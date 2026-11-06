// SPDX-License-Identifier: Apache-2.0

//! Admission by bytes in flight.
//!
//! A request is admitted with the bytes it declares, and its [`Permit`] charges more as copies
//! are made (the body, the tape, the splice). The stop is checked before either bound.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use uaos_contracts::error::{ErrorCode, codes};

use crate::stop::{Stop, StopReason, StopWatch};

/// Admission's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionLimits {
    /// Operations in flight at once.
    pub max_operations: u32,
    /// Bytes in flight at once, across every Operation.
    pub max_bytes: u64,
    /// The `retry-after` an overload refusal carries.
    pub overload_retry_after: Duration,
    /// The `retry-after` a stopped kernel's refusal carries: over 60 s, after which Claude Code
    /// stops retrying.
    pub stopped_retry_after: Duration,
}

impl Default for AdmissionLimits {
    /// `[CONSCIOUS ASSUMPTION]` 64 Operations and 256 MiB. At about four copies of a 1.7 MB body
    /// each, the bytes bound binds first, at about 39 such Operations; smaller bodies reach the
    /// Operations bound. Measured under the overload test and the soak.
    fn default() -> Self {
        Self {
            max_operations: 64,
            max_bytes: 256 * 1024 * 1024,
            overload_retry_after: Duration::from_secs(1),
            stopped_retry_after: Duration::from_secs(120),
        }
    }
}

/// When a refusal during a clean shutdown tells the client to retry: about as long as a restart
/// takes.
pub const DRAINING_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Why admission refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefusalReason {
    /// The kernel is stopped.
    Stopped(StopReason),
    /// The kernel is shutting down cleanly: `RUNTIME_DRAINING`, not `RUNTIME_STOPPED`, because it
    /// is leaving, not halted.
    Draining,
    /// Too many Operations in flight.
    Operations,
    /// Too many bytes in flight.
    Bytes,
    /// The Operation alone needs more bytes than the bound allows, so it can never fit:
    /// `INGRESS_TOO_LARGE`, not retryable, and `retry-after` zero.
    TooLarge,
}

/// A refusal, with the code and `retry-after` the client receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not admitted: {reason:?}; retry after {retry_after:?}")]
pub struct Refusal {
    /// Why.
    pub reason: RefusalReason,
    /// The registered code: `RUNTIME_STOPPED`, `RUNTIME_DRAINING`, `RUNTIME_OVERLOAD` or
    /// `INGRESS_TOO_LARGE`.
    pub code: ErrorCode,
    /// When to retry; zero for a refusal no retry can change.
    pub retry_after: Duration,
}

#[derive(Debug, Default)]
struct Used {
    operations: u32,
    bytes: u64,
}

struct Inner {
    limits: AdmissionLimits,
    stop: Stop,
    /// Set once by [`Admission::drain`], never cleared: a draining kernel only leaves.
    draining: AtomicBool,
    used: Mutex<Used>,
}

impl Inner {
    fn used(&self) -> MutexGuard<'_, Used> {
        // The counters stay consistent under a panic: each update is one assignment.
        self.used.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn stopped(&self) -> Option<Refusal> {
        if !self.stop.is_engaged() {
            return None;
        }
        let reason = self.stop.reason().unwrap_or(StopReason::Unrecognized);
        // `RUNTIME_STOPPED` whatever engaged the stop: the overrun's own code belongs to the stream
        // that overran, not to every request after it.
        Some(Refusal {
            reason: RefusalReason::Stopped(reason),
            code: codes::RUNTIME_STOPPED,
            retry_after: self.limits.stopped_retry_after,
        })
    }

    fn draining(&self) -> Option<Refusal> {
        self.draining.load(Ordering::SeqCst).then_some(Refusal {
            reason: RefusalReason::Draining,
            code: codes::RUNTIME_DRAINING,
            retry_after: DRAINING_RETRY_AFTER,
        })
    }

    fn too_large(&self, bytes: u64) -> Option<Refusal> {
        (bytes > self.limits.max_bytes).then_some(Refusal {
            reason: RefusalReason::TooLarge,
            code: codes::INGRESS_TOO_LARGE,
            retry_after: Duration::ZERO,
        })
    }

    fn overload(&self, reason: RefusalReason) -> Refusal {
        Refusal {
            reason,
            code: codes::RUNTIME_OVERLOAD,
            retry_after: self.limits.overload_retry_after,
        }
    }
}

/// Admission control. Clones share one set of counters.
#[derive(Clone)]
pub struct Admission {
    inner: Arc<Inner>,
}

impl fmt::Debug for Admission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (operations, bytes) = self.in_flight();
        f.debug_struct("Admission")
            .field("limits", &self.inner.limits)
            .field("operations", &operations)
            .field("bytes", &bytes)
            .finish()
    }
}

impl Admission {
    /// Admission under `limits`, refusing everything while `stop` is engaged.
    #[must_use]
    pub fn new(limits: AdmissionLimits, stop: Stop) -> Self {
        Self {
            inner: Arc::new(Inner {
                limits,
                stop,
                draining: AtomicBool::new(false),
                used: Mutex::new(Used::default()),
            }),
        }
    }

    /// Admits one Operation that declares `bytes` in flight.
    ///
    /// # Errors
    /// [`Refusal`]: stopped (checked first); larger than the bytes bound alone, which no retry
    /// changes; or over either bound now.
    pub fn admit(&self, bytes: u64) -> Result<Permit, Refusal> {
        let watch = self.check(bytes)?;
        self.count(bytes, watch)
    }

    /// The checks before the lock: the stop, the drain, the size.
    fn check(&self, bytes: u64) -> Result<StopWatch, Refusal> {
        // Subscribe, then check: a stop engaged after this line reaches the permit's watch, and one
        // engaged before it is refused here.
        let watch = self.inner.stop.watch();
        // The stop first: a stopped kernel says so even while it drains.
        if let Some(refusal) = self.inner.stopped().or_else(|| self.inner.draining()) {
            return Err(refusal);
        }
        if let Some(refusal) = self.inner.too_large(bytes) {
            return Err(refusal);
        }
        Ok(watch)
    }

    /// Counts the Operation under the lock `drain` takes, and hands out its permit.
    fn count(&self, bytes: u64, watch: StopWatch) -> Result<Permit, Refusal> {
        let mut used = self.inner.used();
        // Again under the lock `drain` takes: an Operation is either counted before the shutdown
        // reads `in_flight`, or refused.
        if let Some(refusal) = self.inner.draining() {
            return Err(refusal);
        }
        if used.operations >= self.inner.limits.max_operations {
            return Err(self.inner.overload(RefusalReason::Operations));
        }
        match used.bytes.checked_add(bytes) {
            Some(total) if total <= self.inner.limits.max_bytes => {
                used.operations += 1;
                used.bytes = total;
            }
            _ => return Err(self.inner.overload(RefusalReason::Bytes)),
        }
        drop(used);
        Ok(Permit {
            inner: Arc::clone(&self.inner),
            bytes,
            watch,
        })
    }

    /// Closes admission for a clean shutdown: from now on every new Operation is refused with
    /// `RUNTIME_DRAINING`, and those already admitted continue. It cannot be undone.
    pub fn drain(&self) {
        // Under the lock `admit` counts under, so no Operation is admitted after a count that
        // missed it.
        let _counting = self.inner.used();
        self.inner.draining.store(true, Ordering::SeqCst);
    }

    /// Operations and bytes in flight now.
    #[must_use]
    pub fn in_flight(&self) -> (u32, u64) {
        let used = self.inner.used();
        (used.operations, used.bytes)
    }
}

/// One admitted Operation's share. Dropping it releases both bounds.
pub struct Permit {
    inner: Arc<Inner>,
    bytes: u64,
    watch: StopWatch,
}

impl fmt::Debug for Permit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Permit")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl Permit {
    /// Charges `more` bytes, for a copy the Operation is about to make.
    ///
    /// # Errors
    /// [`Refusal`] if the kernel stopped or the bytes do not fit; nothing is charged.
    pub fn charge(&mut self, more: u64) -> Result<(), Refusal> {
        if let Some(refusal) = self.inner.stopped() {
            return Err(refusal);
        }
        if let Some(refusal) = self.inner.too_large(self.bytes.saturating_add(more)) {
            return Err(refusal);
        }
        let mut used = self.inner.used();
        match used.bytes.checked_add(more) {
            Some(total) if total <= self.inner.limits.max_bytes => {
                used.bytes = total;
                self.bytes += more;
                Ok(())
            }
            _ => Err(self.inner.overload(RefusalReason::Bytes)),
        }
    }

    /// The bytes this Operation holds.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The stop, as this Operation watches it.
    #[must_use]
    pub const fn stop(&self) -> &StopWatch {
        &self.watch
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut used = self.inner.used();
        used.operations = used.operations.saturating_sub(1);
        used.bytes = used.bytes.saturating_sub(self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An Operation checked before the drain and counted after the shutdown read `in_flight` is
    /// refused, so the count misses none. The threaded test in `tests/startup.rs` races the same
    /// window and may not hit it.
    #[test]
    fn an_operation_checked_before_the_drain_is_refused_after_the_count() {
        let admission = Admission::new(AdmissionLimits::default(), Stop::running());
        let watch = admission.check(1).expect("admission is open");
        admission.drain();
        let counted = admission.in_flight().0;
        let admitted = admission.count(1, watch).is_ok();
        assert!(
            !(admitted && counted == 0),
            "an Operation was admitted after the shutdown counted none open"
        );
    }
}
