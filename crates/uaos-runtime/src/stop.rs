// SPDX-License-Identifier: Apache-2.0

//! The kernel stop, the kill switch.
//!
//! One atomic flag, set before anything else. Admission reads it first, and every admitted
//! Operation holds a [`StopWatch`], so a live relay cuts at its next poll. The stop restricts,
//! so it acts before its record is written and never waits on the state actor; the record
//! ([`Engaged::draft`]) is journaled after, and [`boot_state`] honours it at the next start.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::watch;
use uaos_contracts::event::{Actor, Durability, EnvelopeError, EventEnvelope, InlinePayload, Metadata, types};
use uaos_contracts::id::{CorrelationId, TypedId};
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::wire::ConfigVersion;
use uaos_state::journal::EventDraft;

/// Why the kernel stopped. The code is what the journal records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StopReason {
    /// A human stopped it.
    Operator,
    /// A response's usage passed its reservation mid-stream.
    BudgetOverrun,
    /// The chunk store could not flush the journal's payloads.
    PayloadFlushFailed,
    /// The disk is full.
    DiskFull,
    /// A secret canary appeared where it must never be.
    CanaryHit,
    /// The journal failed in a way no other reason names: a write or a flush failed. A kernel that
    /// cannot journal refuses work.
    JournalFailed,
    /// The ledger's writer failed: a ledger record's fate is unknown, or the ledger task's thread
    /// unwound. No ledger writer means no spend.
    LedgerFailed,
    /// A journaled stop whose reason this build does not know. It still boots stopped.
    Unrecognized,
}

impl StopReason {
    /// Every reason a stop can be engaged with.
    pub const ENGAGEABLE: [Self; 7] = [
        Self::Operator,
        Self::BudgetOverrun,
        Self::PayloadFlushFailed,
        Self::DiskFull,
        Self::CanaryHit,
        Self::JournalFailed,
        Self::LedgerFailed,
    ];

    /// The journaled code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::BudgetOverrun => "budget_overrun",
            Self::PayloadFlushFailed => "payload_flush_failed",
            Self::DiskFull => "disk_full",
            Self::CanaryHit => "canary_hit",
            Self::JournalFailed => "journal_failed",
            Self::LedgerFailed => "ledger_failed",
            Self::Unrecognized => "unrecognized",
        }
    }

    /// The reason a journaled code names; an unknown code is [`StopReason::Unrecognized`].
    #[must_use]
    pub fn from_code(code: &str) -> Self {
        Self::ENGAGEABLE
            .into_iter()
            .find(|r| r.code() == code)
            .unwrap_or(Self::Unrecognized)
    }
}

/// Who engaged a stop, and under which correlation and configuration. The stop record carries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngagedBy {
    /// The system, for the relay and the state actor; a human, for an operator.
    pub actor: Actor,
    /// The Operation's correlation, or the engager's own.
    pub correlation_id: CorrelationId,
    /// The configuration in force for the engager.
    pub config_version: ConfigVersion,
}

/// The current engagement: which one it is, who made it, and which one is journaled.
#[derive(Debug, Clone, Default)]
struct Engagement {
    /// Counts engagements; 0 before the first.
    generation: u64,
    /// `None` for the stop boot read from the journal, whose record already exists.
    by: Option<EngagedBy>,
    /// The latest generation whose record is in the journal.
    recorded: u64,
}

struct Inner {
    engaged: AtomicBool,
    engagement: Mutex<Engagement>,
    reason: watch::Sender<Option<StopReason>>,
}

impl Inner {
    fn engagement(&self) -> MutexGuard<'_, Engagement> {
        // A panic elsewhere must not wedge the stop: the data is a few plain fields.
        self.engagement.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The kernel stop. Clones share one stop.
#[derive(Clone)]
pub struct Stop {
    inner: Arc<Inner>,
}

impl fmt::Debug for Stop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stop").field("reason", &self.reason()).finish()
    }
}

impl Default for Stop {
    fn default() -> Self {
        Self::running()
    }
}

impl Stop {
    /// A kernel that is running.
    #[must_use]
    pub fn running() -> Self {
        Self {
            inner: Arc::new(Inner {
                engaged: AtomicBool::new(false),
                engagement: Mutex::new(Engagement::default()),
                reason: watch::Sender::new(None),
            }),
        }
    }

    /// The stop as the journal left it ([`boot_state`]): a kernel stopped before a restart boots
    /// stopped.
    #[must_use]
    pub fn booted(state: BootState) -> Self {
        let stop = Self::running();
        if let BootState::Stopped(reason) = state {
            let engaged = stop.engage_as(reason, None);
            // Its record is the one boot read.
            stop.recorded(engaged.generation());
        }
        stop
    }

    /// Engages the stop. The flag is set before any watcher is woken, so admission refuses from
    /// this instant, and every live relay cuts at its next poll. The first reason wins; engaging
    /// again changes nothing ([`Engaged::first`] is false). The state actor journals the
    /// engagement, with `by`, through [`Stop::unrecorded`].
    #[must_use = "the state actor journals the stop through `Stop::unrecorded`"]
    pub fn engage(&self, reason: StopReason, by: EngagedBy) -> Engaged {
        self.engage_as(reason, Some(by))
    }

    fn engage_as(&self, reason: StopReason, mut by: Option<EngagedBy>) -> Engaged {
        let mut kept = reason;
        let mut engagement = Engagement::default();
        let first = self.inner.reason.send_if_modified(|current| {
            let mut held = self.inner.engagement();
            if let Some(reason) = *current {
                kept = reason;
                engagement = held.clone();
                false
            } else {
                // The flag first: admission reads it before anything else.
                self.inner.engaged.store(true, Ordering::SeqCst);
                held.generation += 1;
                held.by = by.take();
                engagement = held.clone();
                *current = Some(reason);
                true
            }
        });
        Engaged {
            reason: kept,
            first,
            generation: engagement.generation,
            by: engagement.by,
        }
    }

    /// Whether the stop is engaged.
    #[must_use]
    pub fn is_engaged(&self) -> bool {
        self.inner.engaged.load(Ordering::SeqCst)
    }

    /// The reason the stop holds, if engaged.
    #[must_use]
    pub fn reason(&self) -> Option<StopReason> {
        *self.inner.reason.borrow()
    }

    /// The engaged stop, while its record is not in the journal yet. The state actor journals
    /// [`Engaged::draft`] and then calls [`Stop::recorded`] with its generation; until it does,
    /// this keeps returning the stop, so while the process runs a failed write is retried. A
    /// restart before the record is durable boots running: that is the window states, and DST
    /// bounds it. `None` while running, or once recorded. Whoever engaged the stop need not journal
    /// it, so a relay engages without a journal.
    #[must_use]
    pub fn unrecorded(&self) -> Option<Engaged> {
        let reason = self.reason()?;
        let engagement = self.inner.engagement().clone();
        (engagement.recorded < engagement.generation).then_some(Engaged {
            reason,
            first: true,
            generation: engagement.generation,
            by: engagement.by,
        })
    }

    /// The record of engagement `generation` is in the journal. Marks only that generation, so a
    /// later engagement is not taken for recorded.
    pub fn recorded(&self, generation: u64) {
        let mut engagement = self.inner.engagement();
        if generation == engagement.generation {
            engagement.recorded = generation;
        }
    }

    /// A watch on the stop. Subscribe before checking [`Stop::is_engaged`], and a stop engaged
    /// later is never missed.
    #[must_use]
    pub fn watch(&self) -> StopWatch {
        StopWatch {
            rx: self.inner.reason.subscribe(),
        }
    }
}

/// What [`Stop::engage`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Engaged {
    reason: StopReason,
    first: bool,
    generation: u64,
    by: Option<EngagedBy>,
}

impl Engaged {
    /// The reason the stop holds: the first one engaged.
    #[must_use]
    pub const fn reason(&self) -> StopReason {
        self.reason
    }

    /// Whether this call engaged the stop. Only the first is journaled.
    #[must_use]
    pub const fn first(&self) -> bool {
        self.first
    }

    /// Which engagement this is: it counts from 1.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Who engaged the stop; `None` for the stop boot read from the journal.
    #[must_use]
    pub const fn by(&self) -> Option<&EngagedBy> {
        self.by.as_ref()
    }

    /// The `kernel.stopped` record to journal after the stop took effect: critical, with the
    /// engager as its actor and correlation, and the reason and generation as its inline payload
    /// (`{"reason": "<code>", "generation": "<n>"}`, the count as a decimal string by `wire`'s
    /// rule). The stop boot read is never drafted again; if asked, it is attributed to the system
    /// under an empty correlation.
    ///
    /// # Errors
    /// [`EnvelopeError`] if the inline payload does not fit the envelope's bound (it always
    /// fits: one short code and a number).
    pub fn draft(&self) -> Result<EventDraft, EnvelopeError> {
        let by = self.by.clone().unwrap_or(EngagedBy {
            actor: Actor::System,
            correlation_id: CorrelationId::from_parts(0, [0; 10]),
            config_version: ConfigVersion(0),
        });
        let (actor, correlation_id, config_version) = (by.actor, by.correlation_id, by.config_version);
        Ok(EventDraft {
            session_id: None,
            pocket_id: None,
            operation_id: None,
            request_id: None,
            agent_id: None,
            correlation_id,
            parent_id: None,
            actor,
            event_type: types::KERNEL_STOPPED,
            payload_ref: None,
            payload_inline: Some(InlinePayload::new(serde_json::json!({
                "reason": self.reason.code(),
                "generation": self.generation.to_string(),
            }))?),
            cost_estimate: None,
            compensable: false,
            side_effect_class: SideEffectClass::None,
            risk_tier: RiskTier::MAX,
            durability: Durability::Critical,
            config_version,
            metadata: Metadata::default(),
        })
    }
}

/// A watch on the stop, held by every admitted Operation.
#[derive(Debug, Clone)]
pub struct StopWatch {
    rx: watch::Receiver<Option<StopReason>>,
}

impl StopWatch {
    /// The reason, if the stop is engaged.
    #[must_use]
    pub fn engaged(&self) -> Option<StopReason> {
        *self.rx.borrow()
    }

    /// Resolves at the next change of the stop after the last one this watch saw. If every
    /// [`Stop`] handle is gone, it never resolves.
    pub(crate) async fn changed(&mut self) {
        if self.rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    /// Resolves once the stop is engaged, at once if it already is. If every [`Stop`] handle is
    /// gone, the kernel is gone too, and it never resolves.
    pub async fn stopped(mut self) -> StopReason {
        loop {
            if let Some(reason) = *self.rx.borrow_and_update() {
                return reason;
            }
            if self.rx.changed().await.is_err() {
                return std::future::pending().await;
            }
        }
    }
}

/// How the journal left the stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootState {
    /// No stop, or a resume after the last one.
    Running,
    /// The last record was a stop with this reason.
    Stopped(StopReason),
}

/// Reads the stop from verified journal records, oldest first: the last `kernel.stopped` or
/// `kernel.resumed` decides. A stop whose reason is missing or unknown still stops, and only a
/// human resumes: a `kernel.resumed` from any other actor is ignored.
pub fn boot_state<'a>(records: impl IntoIterator<Item = &'a EventEnvelope>) -> BootState {
    let mut state = BootState::Running;
    for record in records {
        if record.event_type == types::KERNEL_STOPPED {
            let code = record
                .payload_inline
                .as_ref()
                .and_then(|p| p.as_value().get("reason"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            state = BootState::Stopped(StopReason::from_code(code));
        } else if record.event_type == types::KERNEL_RESUMED && record.actor == Actor::Human {
            state = BootState::Running;
        }
    }
    state
}
