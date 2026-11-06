// SPDX-License-Identifier: Apache-2.0

//! Real implementations, injected only by the composition root.

pub mod fs;
pub mod keychain;

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use uaos_contracts::time::WallTime;
use uaos_contracts::wire::MonoNanos;

use crate::{Clock, PlatformError, Rng};

/// The operating system's clocks.
#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// Creates a clock whose monotonic origin is now.
    #[must_use]
    #[allow(clippy::disallowed_methods, reason = "uaos-platform is the clock owner")]
    pub fn new() -> Self {
        Self { origin: Instant::now() }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    #[allow(clippy::disallowed_methods, reason = "uaos-platform is the clock owner")]
    fn wall(&self) -> Result<WallTime, PlatformError> {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PlatformError::ClockOutOfRange)?;
        let nanos = i128::try_from(since_epoch.as_nanos()).map_err(|_| PlatformError::ClockOutOfRange)?;
        WallTime::from_unix_nanos(nanos).map_err(|_| PlatformError::ClockOutOfRange)
    }

    fn mono(&self) -> MonoNanos {
        // 2^64 ns is ~584 years of uptime; saturating is unreachable in practice and never wraps.
        MonoNanos(u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX))
    }
}

/// The operating system's cryptographically secure random source.
#[derive(Debug, Default)]
pub struct OsRng;

impl Rng for OsRng {
    #[allow(clippy::disallowed_methods, reason = "uaos-platform is the randomness owner")]
    fn fill(&self, buf: &mut [u8]) -> Result<(), PlatformError> {
        getrandom::fill(buf).map_err(|_| PlatformError::RandomUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdSource;
    use uaos_contracts::id::{EventId, TypedId};

    #[test]
    fn real_sources_produce_v7_ids_and_monotonic_time() {
        let clock = SystemClock::new();
        let a = clock.mono();
        let ids = IdSource::new(SystemClock::new(), OsRng);
        let id: EventId = ids.next().unwrap();
        assert_eq!(id.as_uuid().get_version_num(), 7);
        assert!(clock.mono() >= a);
        assert!(clock.wall().unwrap() > WallTime::UNIX_EPOCH);
    }
}
