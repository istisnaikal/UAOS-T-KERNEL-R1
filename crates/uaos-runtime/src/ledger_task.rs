// SPDX-License-Identifier: Apache-2.0

//! The ledger task.
//!
//! After boot one task owns the [`Ledger`] and writes one ledger record at a time through the
//! state actor: it prepares the write, appends its record (or records), and changes the ledger
//! only after the journal's acknowledgement. A refusal that wrote nothing (`NotQueued`,
//! `StopPending`) withdraws the write and the ledger stays live; anything else abandons it,
//! poisons the ledger, and engages the stop with `ledger_failed`: no ledger writer means no
//! spend. A guard engages the same stop if the task unwinds.
//!
//! - `reserve` journals the intent, which carries its reservation; `allocate` and `transfer`
//!   journal one `budget.entry` per entry (E4b).
//! - `execute` journals `op.executing` between two checks of the stop, and `release` and `settle`
//!   write each close as one record carrying all its entries (E4c).
//! - Closes are the task's (E4d). A token dropped with no close offered is closed by the task as
//!   abandoned, and a close offered by a caller that then stops waiting still lands. A close
//!   refused inside the stop record's pause (`StopPending`) is retried after the pause; one refused
//!   because the state actor has ended (`NotQueued`) is not, and the reservation stays open for the
//!   next boot to settle as estimated.
//!
//! - Shutdown drains the task (E4e). Once admission closes, `reserve` and `execute` are refused
//!   with `RUNTIME_DRAINING` while closes go on; the task ends when every token is closed or the
//!   deadline passes, and says how many reservations it leaves open, stuck items excepted.
//!   `kernel.shutdown` counts them, and the next boot settles them as estimated.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::mpsc::OwnedPermit;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use uaos_contracts::budget::{BudgetTxKind, IdempotencyKey, LedgerDelta, ReasonCode};
use uaos_contracts::error::{ErrorCode, UaosError, codes};
use uaos_contracts::event::{Actor, Durability, EventType, InlinePayload, Metadata, types};
use uaos_contracts::id::{
    AgentId, CorrelationId, EventId, OperationId, PocketId, PoolId, RequestId, ReservationId, SessionId,
};
use uaos_contracts::money::NanoUsd;
use uaos_contracts::operation::{OperationKind, RiskTier, SideEffectClass};
use uaos_contracts::wire::ConfigVersion;
use uaos_egress::EgressError;
use uaos_ledger::inline::{LEDGER_FIELD, STUCK_REPAIR};
use uaos_ledger::{
    Batch, CloseError, Ledger, LedgerError, LedgerState, Repair, RepairOutcome, Reservation, Settlement, Steps,
    StuckItem, StuckKind, Usage, budget_entry_draft,
};
use uaos_state::journal::{Appended, EventDraft, FlushPolicy};

use crate::relay::{RelayEnd, RelayReport};

use crate::state::{StateError, StateHandle};
use crate::stop::{EngagedBy, Stop, StopReason};
use crate::supervisor::{SpawnError, Supervisor};

/// The ledger task's queue, in commands. A full queue makes the caller wait.
pub const DEFAULT_LEDGER_QUEUE: usize = 1_024;

/// The longest upstream name an intent carries: a bounded token, never a URL. A key-shaped name is
/// the configuration's to refuse.
pub const MAX_UPSTREAM_NAME: usize = 64;

/// Whether `name` is an upstream name an intent may carry: one to [`MAX_UPSTREAM_NAME`] ASCII
/// letters, digits, `.`, `_` or `-`. A URL never is (no `:` or `/`), so credentials in one never
/// reach the journal (red line 2; of E4).
#[must_use]
pub fn is_upstream_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_UPSTREAM_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The first wait before a close refused inside the stop record's pause is tried again; it doubles
/// after each refusal, up to [`CLOSE_RETRY_MAX`]. The state actor's own pause starts at 10 ms and
/// doubles up to 5 s, so a retry never waits much past the pause's end.
const CLOSE_RETRY_FIRST: Duration = Duration::from_millis(10);
/// The longest wait between two tries of a close.
const CLOSE_RETRY_MAX: Duration = Duration::from_secs(1);

/// What every record of an Operation carries: its ids, its principal, and what it declared when it
/// was routed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRecord {
    /// The Operation.
    pub operation_id: OperationId,
    /// Its session, if any.
    pub session_id: Option<SessionId>,
    /// Its pocket, if any.
    pub pocket_id: Option<PocketId>,
    /// Its request, if any.
    pub request_id: Option<RequestId>,
    /// Its agent, if any.
    pub agent_id: Option<AgentId>,
    /// Its correlation.
    pub correlation_id: CorrelationId,
    /// The principal of its transitions: each record's actor, and its entries' principal.
    pub actor: Actor,
    /// What it is.
    pub kind: OperationKind,
    /// The configured upstream's name (at most [`MAX_UPSTREAM_NAME`] bytes).
    pub upstream: String,
    /// The effect it declared.
    pub side_effect_class: SideEffectClass,
    /// Whether it declared itself compensable.
    pub compensable: bool,
    /// Its risk tier.
    pub risk_tier: RiskTier,
    /// The configuration snapshot it is pinned to.
    pub config_version: ConfigVersion,
}

/// Who writes a ledger movement that is not an Operation's (an allocation, a transfer), under
/// which key, correlation and configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Movement {
    /// The entries' principal and the records' actor.
    pub principal: Actor,
    /// The caller's idempotency key.
    pub key: IdempotencyKey,
    /// The correlation the records carry.
    pub correlation_id: CorrelationId,
    /// The configuration the records carry.
    pub config_version: ConfigVersion,
}

/// A reservation whose intent the journal acknowledged: the Operation is `Reserved`.
///
/// Its close is the task's. Dropped with no close offered, it is released by the task as abandoned;
/// a close offered through [`LedgerHandle::release`] lands even if the caller stops waiting for it.
#[must_use = "a held reservation is closed as abandoned when dropped"]
#[derive(Debug)]
pub struct Held {
    /// The ledger's token and its slot in the task's queue of owed closes: `None` once the task
    /// has taken them.
    debt: Option<Debt<uaos_ledger::Held>>,
    reservation: ReservationId,
    amount: NanoUsd,
    record: OperationRecord,
    intent: EventId,
    /// The close a caller offered, stored before its call first waits.
    offered: Option<Released>,
}

impl Held {
    /// The reservation.
    #[must_use]
    pub const fn reservation(&self) -> ReservationId {
        self.reservation
    }

    /// The reserved amount.
    #[must_use]
    pub const fn amount(&self) -> NanoUsd {
        self.amount
    }

    /// The Operation's record fields.
    #[must_use]
    pub const fn record(&self) -> &OperationRecord {
        &self.record
    }

    /// The intent's event id: every later record of the Operation links to it (`parent_id`).
    #[must_use]
    pub const fn intent(&self) -> EventId {
        self.intent
    }

    /// The token, its slot, and what its records carry, taken by the task: the token owes
    /// nothing more.
    fn take(mut self) -> Option<(HeldParts, OwnedPermit<Owed>)> {
        let Debt { token, slot } = self.debt.take()?;
        let parts = HeldParts {
            token,
            record: self.record.clone(),
            intent: self.intent,
            offered: self.offered.take(),
        };
        Some((parts, slot))
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(Debt { token, slot }) = self.debt.take() {
            // The slot was reserved when the token was made, so this never waits and never fails
            // for room. A task that has ended cannot close it: the next boot settles it.
            let _queue = slot.send(Owed::Held(HeldParts {
                token,
                record: self.record.clone(),
                intent: self.intent,
                offered: self.offered.take(),
            }));
        }
    }
}

/// A reservation whose `op.executing` the journal acknowledged: the Operation is `Executing`. Only
/// it reaches the door, so every byte that may leave follows `op.executing`.
///
/// Its close is the task's. Dropped with no close offered, it is settled by the task in full, as
/// estimated, since a request may have left; a close offered through [`LedgerHandle::settle`] lands
/// even if the caller stops waiting for it.
#[must_use = "an in-flight reservation is settled in full, as estimated, when dropped"]
#[derive(Debug)]
pub struct InFlight {
    /// The ledger's token and its slot in the task's queue of owed closes: `None` once the task
    /// has taken them.
    debt: Option<Debt<uaos_ledger::InFlight>>,
    reservation: ReservationId,
    amount: NanoUsd,
    record: OperationRecord,
    intent: EventId,
    /// The close a caller offered, stored before its call first waits.
    offered: Option<Settled>,
}

impl InFlight {
    /// The reservation.
    #[must_use]
    pub const fn reservation(&self) -> ReservationId {
        self.reservation
    }

    /// The reserved amount.
    #[must_use]
    pub const fn amount(&self) -> NanoUsd {
        self.amount
    }

    /// The Operation's record fields.
    #[must_use]
    pub const fn record(&self) -> &OperationRecord {
        &self.record
    }

    /// The token, its slot, and what its records carry, taken by the task: the token owes
    /// nothing more.
    fn take(mut self) -> Option<(InFlightParts, OwnedPermit<Owed>)> {
        let Debt { token, slot } = self.debt.take()?;
        let parts = InFlightParts {
            token,
            record: self.record.clone(),
            intent: self.intent,
            offered: self.offered.take(),
        };
        Some((parts, slot))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Some(Debt { token, slot }) = self.debt.take() {
            // The slot was reserved when the token was made, so this never waits and never fails
            // for room. A task that has ended cannot close it: the next boot settles it.
            let _queue = slot.send(Owed::InFlight(InFlightParts {
                token,
                record: self.record.clone(),
                intent: self.intent,
                offered: self.offered.take(),
            }));
        }
    }
}

/// A token the task owes a close for, with the slot its close takes in the task's queue of owed
/// closes if the token is dropped. The slot is reserved when the token is made (at `reserve`;
/// `execute` passes it on), so the queue is bounded by the tokens alive and a drop never waits.
#[derive(Debug)]
struct Debt<S> {
    token: Reservation<S>,
    slot: OwnedPermit<Owed>,
}

/// A `Held` token as the task holds it.
#[derive(Debug)]
struct HeldParts {
    token: Reservation<uaos_ledger::Held>,
    record: OperationRecord,
    intent: EventId,
    offered: Option<Released>,
}

/// An `InFlight` token as the task holds it.
#[derive(Debug)]
struct InFlightParts {
    token: Reservation<uaos_ledger::InFlight>,
    record: OperationRecord,
    intent: EventId,
    offered: Option<Settled>,
}

/// A token dropped before the task took it: its offered close, or none.
#[derive(Debug)]
enum Owed {
    Held(HeldParts),
    InFlight(InFlightParts),
}

/// Why a reservation whose execution never started is released. Each writes `[release]` and
/// `"sent": false`; none can name `op.committed`:
///
/// ```compile_fail
/// let _ = uaos_runtime::Released::Committed;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Released {
    /// The final scan's exit: `op.denied`.
    Denied {
        /// Why.
        reason: ReasonCode,
    },
    /// Any failure between `Reserved` and `execute` (a splice or scan deadline, a module's
    /// fault): `op.failed`.
    Failed {
        /// Why.
        reason: ReasonCode,
    },
    /// The stop was engaged before execution: `op.failed`, `stopped`.
    Stopped,
    /// `op.executing` was refused without being written: `op.failed`, `execute_refused`.
    ExecuteRefused,
}

/// How an execution ended. The task derives the usage, the record and its payload.
#[derive(Debug, Clone)]
pub enum Settled {
    /// The door failed; its own verdict says whether anything may have left.
    DoorFailed(EgressError),
    /// A response arrived, and the relay refused it before relaying (no relay report exists).
    Answered {
        /// The upstream's status.
        upstream_status: u16,
        /// The relay's refusal.
        reason: ReasonCode,
    },
    /// The relay ran.
    RelayEnded {
        /// What it did.
        report: RelayReport,
        /// The upstream's status.
        upstream_status: u16,
    },
}

/// Who applies a stuck item's repair and, for a one-record reservation, the Operation it resolves.
/// Applying a repair needs a human's presence, through an approval channel that is not built yet.
/// Until it exists no code path calls [`LedgerHandle::repair`] outside the tests (red line 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairBy {
    /// The human who applies it: every repair record's actor and every entry's principal.
    pub principal: Actor,
    /// The correlation a two-record or transfer repair's `budget.entry` records carry.
    pub correlation_id: CorrelationId,
    /// The configuration they carry.
    pub config_version: ConfigVersion,
    /// For a stuck one-record reservation: its Operation's record fields and its intent's event
    /// id, as the journal holds them. The task writes the repair as that Operation's resolution
    /// only if the ledger knows the reservation as that Operation's.
    pub resolves: Option<(OperationRecord, EventId)>,
}

/// The reservations a shutdown's drain left open, stuck items excepted: every reservation reserved
/// and not closed when the task ended, whether its token was alive, its close was queued, or the
/// task owed it. `kernel.shutdown`'s `open_operations` adds it to admission's count, and the next
/// boot settles each as estimated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenReservations(pub u32);

/// The task's own channel, read before closes and commands, so a shutdown is seen at once.
#[derive(Debug)]
enum Control {
    Shutdown {
        deadline: Instant,
        reply: oneshot::Sender<OpenReservations>,
    },
}

/// The ledger as the task holds it now (diagnostics and tests).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LedgerSnapshot {
    /// The state.
    pub state: LedgerState,
    /// Whether a write of unknown fate stopped the ledger.
    pub poisoned: bool,
    /// Whether the ledger still refuses new work for its recovery or a stuck item.
    pub needs_recovery: bool,
    /// The task's metrics since it started.
    pub stats: LedgerStats,
}

/// The ledger task's metrics since it started. The queue's depth is [`LedgerHandle::queued`];
/// whether the ledger is poisoned is [`LedgerSnapshot::poisoned`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LedgerStats {
    /// Records journaled and applied, by record type (`op.reserved_intent`, `op.executing`,
    /// `op.committed`, `op.failed`, `op.denied`, `budget.entry`).
    pub records: BTreeMap<String, u64>,
    /// Writes withdrawn after a refusal that wrote nothing: the ledger stayed live.
    pub withdrawn: u64,
    /// Writes abandoned after a refusal of unknown fate: each poisons the ledger and stops the
    /// kernel.
    pub abandoned: u64,
    /// Closes refused inside the stop record's pause and tried again.
    pub retried_closes: u64,
    /// Closes a caller offered and stopped waiting for, which the task took on.
    pub offered_closes: u64,
    /// Closes the task took on as its own: a token dropped with no close offered, or one whose
    /// caller was gone before it was handed out.
    pub owned_closes: u64,
    /// The time from a write's prepare to its apply, the last one, in nanoseconds: the journal's
    /// acknowledgement and the queue hop to the state actor are most of it.
    pub prepare_to_apply_last_nanos: Option<u64>,
    /// The longest such time so far, in nanoseconds.
    pub prepare_to_apply_max_nanos: Option<u64>,
}

impl LedgerStats {
    fn wrote(&mut self, event_type: &EventType) {
        if let Some(count) = self.records.get_mut(event_type.as_str()) {
            *count += 1;
        } else {
            self.records.insert(event_type.as_str().to_owned(), 1);
        }
    }

    fn applied(&mut self, prepared: Instant) {
        let nanos = u64::try_from(prepared.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.prepare_to_apply_last_nanos = Some(nanos);
        self.prepare_to_apply_max_nanos = Some(self.prepare_to_apply_max_nanos.map_or(nanos, |max| max.max(nanos)));
    }
}

/// Why a call to the ledger task failed. Each keeps the code of what refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LedgerCallError {
    /// The ledger refused the write before anything was journaled: the hard cap, a reused
    /// reservation, a ledger that awaits recovery or a repair, or one that is poisoned.
    #[error(transparent)]
    Ledger(LedgerError),
    /// The state actor refused the record without writing it: the write was withdrawn and the
    /// ledger stays live.
    #[error("the record was not written: {0}")]
    Unwritten(StateError),
    /// The record's fate is unknown: the write was abandoned, the ledger is poisoned, and the
    /// stop is engaged with `ledger_failed`.
    #[error("the record's fate is unknown; the ledger stopped: {0}")]
    Abandoned(StateError),
    /// The Operation's record could not be built from what the caller gave; nothing was written.
    #[error("the record could not be built: {0}")]
    Record(&'static str),
    /// The kernel stop is engaged: execution does not start.
    #[error("the kernel is stopped")]
    Stopped,
    /// Shutdown has closed admission: `reserve` and `execute` are refused while closes go on.
    #[error("the kernel is shutting down")]
    Draining,
    /// The task already holds as many live tokens as it allows (its queue capacity): nothing was
    /// reserved or written. Admission's own bound is lower by default, so this is a last guard.
    #[error("the ledger task holds as many reservations as it allows")]
    Overloaded,
    /// The ledger task has ended.
    #[error("the ledger task has ended")]
    Ended,
}

impl LedgerCallError {
    /// The registered code of what refused.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Ledger(error) => error.code(),
            Self::Unwritten(error) | Self::Abandoned(error) => state_code(error),
            Self::Record(_) => codes::BUDGET_LEDGER_INCONSISTENT,
            Self::Stopped => codes::RUNTIME_STOPPED,
            Self::Overloaded => codes::RUNTIME_OVERLOAD,
            Self::Draining => codes::RUNTIME_DRAINING,
            Self::Ended => codes::JOURNAL_WRITE_FAILED,
        }
    }
}

impl LedgerCallError {
    /// The wire error for this refusal: its registered code, the code's localization key as the
    /// user's message, and an agent message naming the Operation and, when there is one, its
    /// reservation. Neither message carries an amount: `Display`, which can (the hard cap's
    /// `LedgerError`), is for the redacted logs only. The agent message says what this refusal
    /// means for the Operation's records, in words true for every call that can meet it. No code's
    /// registered summary is used: a code is shared by calls made before and after the execution,
    /// and `JOURNAL_WRITE_FAILED`'s says "the operation was not started", which is false for a
    /// close (red line 3; of E4). `None` only for a code missing from the registry, which the
    /// registry's own tests rule out.
    #[must_use]
    pub fn to_error(
        &self,
        operation: OperationId,
        reservation: Option<ReservationId>,
        correlation_id: CorrelationId,
    ) -> Option<UaosError> {
        let spec = uaos_contracts::error::spec(self.code())?;
        let mut error = UaosError::from_spec(spec, correlation_id, None);
        let what = match self {
            // The ledger refuses every write once it is poisoned, before writing anything.
            Self::Ledger(LedgerError::Poisoned | LedgerError::Sink(_)) => {
                "The ledger stopped after an earlier write of unknown fate and refuses every write: nothing was \
                 recorded for this step, and the next boot settles a reservation still open as estimated."
            }
            Self::Ledger(LedgerError::Insufficient { .. }) => {
                "The budget pool's hard cap holds: the ledger refused this step before writing anything for it."
            }
            Self::Ledger(_) => "The ledger refused this step before writing anything for it.",
            Self::Unwritten(_) => "The ledger's record was refused before it was written: nothing was recorded.",
            Self::Abandoned(_) => {
                "The ledger's record may or may not have been written, and the ledger stopped: the next boot reads \
                 what landed, and settles a reservation still open as estimated."
            }
            Self::Record(_) => "The ledger's record could not be built: nothing was written.",
            Self::Stopped => "The kernel stop is engaged: the execution did not start.",
            Self::Draining => "The kernel is shutting down: the execution did not start.",
            Self::Overloaded => "The ledger task holds as many reservations as it allows: nothing was reserved.",
            Self::Ended => {
                "The ledger task has ended: whether this step was recorded is unknown, and the next boot settles \
                 an open reservation as estimated."
            }
        };
        error.agent_message = match reservation {
            Some(reservation) => format!("{what} Operation {operation}, reservation {reservation}."),
            None => format!("{what} Operation {operation}."),
        };
        Some(error)
    }
}

/// The journal's own code where the state actor carries it; the writer's failure otherwise.
fn state_code(error: &StateError) -> ErrorCode {
    match error {
        StateError::Journal(error) | StateError::StopPending(error) => error.code(),
        _ => codes::JOURNAL_WRITE_FAILED,
    }
}

/// Whether the state actor's refusal wrote nothing: a command never queued, or one refused because
/// an engaged stop's record has not landed, inside its pause or on a try of it that failed
/// (`StopPending`). Every other error may have written the line.
const fn wrote_nothing(error: &StateError) -> bool {
    matches!(error, StateError::NotQueued | StateError::StopPending(_))
}

enum Command {
    Reserve {
        record: OperationRecord,
        pool: PoolId,
        id: ReservationId,
        amount: NanoUsd,
        reply: oneshot::Sender<Result<Held, LedgerCallError>>,
    },
    Allocate {
        pool: PoolId,
        amount: NanoUsd,
        movement: Movement,
        reply: oneshot::Sender<Result<(), LedgerCallError>>,
    },
    Transfer {
        from: PoolId,
        to: PoolId,
        amount: NanoUsd,
        movement: Movement,
        reply: oneshot::Sender<Result<(), LedgerCallError>>,
    },
    Execute {
        held: Held,
        reply: oneshot::Sender<Result<InFlight, LedgerCallError>>,
    },
    /// The close is offered on the token.
    Release {
        held: Held,
        reply: oneshot::Sender<Result<Appended, LedgerCallError>>,
    },
    /// The close is offered on the token.
    Settle {
        in_flight: InFlight,
        reply: oneshot::Sender<Result<(Settlement, Appended), LedgerCallError>>,
    },
    Repair {
        item: StuckItem,
        repair: Repair,
        by: Box<RepairBy>,
        reply: oneshot::Sender<Result<(), LedgerCallError>>,
    },
    Snapshot(oneshot::Sender<LedgerSnapshot>),
}

/// Where the runtime's ledger writes go once boot has finished. Clones share one queue.
#[derive(Debug, Clone)]
pub struct LedgerHandle {
    commands: mpsc::Sender<Command>,
    control: mpsc::Sender<Control>,
    /// Set when shutdown closes admission: `reserve` and `execute` are refused.
    draining: Arc<AtomicBool>,
    /// The shutdown's deadline, seen by the task at once, even by a close it is retrying.
    deadline: Arc<watch::Sender<Option<Instant>>>,
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Reserve { .. } => "Reserve",
            Self::Allocate { .. } => "Allocate",
            Self::Transfer { .. } => "Transfer",
            Self::Execute { .. } => "Execute",
            Self::Release { .. } => "Release",
            Self::Settle { .. } => "Settle",
            Self::Repair { .. } => "Repair",
            Self::Snapshot(_) => "Snapshot",
        })
    }
}

impl LedgerHandle {
    /// Reserves `amount` of `pool` for the Operation and journals its intent, which carries the
    /// reservation. The token is returned only after the intent's acknowledgement.
    ///
    /// # Errors
    /// [`LedgerCallError`]: the hard cap and every other refusal, with its code.
    pub async fn reserve(
        &self,
        record: OperationRecord,
        pool: PoolId,
        id: ReservationId,
        amount: NanoUsd,
    ) -> Result<Held, LedgerCallError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Reserve {
            record,
            pool,
            id,
            amount,
            reply,
        })
        .await?;
        answer.await.map_err(|_| LedgerCallError::Ended)?
    }

    /// Adds `amount` to `pool`, creating it on first use: one `budget.entry` record.
    ///
    /// # Errors
    /// [`LedgerCallError`].
    pub async fn allocate(&self, pool: PoolId, amount: NanoUsd, movement: Movement) -> Result<(), LedgerCallError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Allocate {
            pool,
            amount,
            movement,
            reply,
        })
        .await?;
        answer.await.map_err(|_| LedgerCallError::Ended)?
    }

    /// Moves `amount` from `from` to `to`: a `transfer_out` and its `transfer_in`, two
    /// `budget.entry` records, applied record by record.
    ///
    /// # Errors
    /// [`LedgerCallError`].
    pub async fn transfer(
        &self,
        from: PoolId,
        to: PoolId,
        amount: NanoUsd,
        movement: Movement,
    ) -> Result<(), LedgerCallError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Transfer {
            from,
            to,
            amount,
            movement,
            reply,
        })
        .await?;
        answer.await.map_err(|_| LedgerCallError::Ended)?
    }

    /// Starts execution: journals `op.executing` and returns the in-flight token only after its
    /// acknowledgement, with the stop checked on both sides of the record. Under the stop the
    /// reservation is released (or, after the record, settled at 0) and the call refused.
    ///
    /// # Errors
    /// [`LedgerCallError::Stopped`] under the stop; otherwise as the write failed.
    pub async fn execute(&self, held: Held) -> Result<InFlight, LedgerCallError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Execute { held, reply }).await?;
        answer.await.map_err(|_| LedgerCallError::Ended)?
    }

    /// Releases a reservation whose execution never started, in its Operation's closing record.
    ///
    /// A plain function: the close is offered on the token before the future is returned, so it is
    /// the task's from then on and lands even if the future is never polled or is dropped while it
    /// waits. The future only reports it.
    ///
    /// # Errors
    /// As the write failed.
    pub fn release(
        &self,
        mut held: Held,
        released: Released,
    ) -> impl Future<Output = Result<Appended, LedgerCallError>> + Send + 'static {
        held.offered = Some(released);
        let commands = self.commands.clone();
        async move {
            let (reply, answer) = oneshot::channel();
            commands
                .send(Command::Release { held, reply })
                .await
                .map_err(|_| LedgerCallError::Ended)?;
            answer.await.map_err(|_| LedgerCallError::Ended)?
        }
    }

    /// Settles an execution in its Operation's closing record, as §8 maps `settled`.
    ///
    /// A plain function: the close is offered on the token before the future is returned, so it is
    /// the task's from then on and lands with this usage even if the future is never polled or is
    /// dropped while it waits. The future only reports it.
    ///
    /// # Errors
    /// As the write failed.
    pub fn settle(
        &self,
        mut in_flight: InFlight,
        settled: Settled,
    ) -> impl Future<Output = Result<(Settlement, Appended), LedgerCallError>> + Send + 'static {
        in_flight.offered = Some(settled);
        let commands = self.commands.clone();
        async move {
            let (reply, answer) = oneshot::channel();
            commands
                .send(Command::Settle { in_flight, reply })
                .await
                .map_err(|_| LedgerCallError::Ended)?;
            answer.await.map_err(|_| LedgerCallError::Ended)?
        }
    }

    /// Applies a stuck item's repair: for a one-record reservation, the Operation's resolution
    /// record (`op.committed` or `op.failed`, reason `stuck_repair`, no `sent` field), written by
    /// the human who applies it; for a two-record reservation or a transfer, `budget.entry`
    /// records. Applied after the acknowledgement, it removes the item from the stuck set, and the
    /// last one lets the ledger accept new work. For tests only, until the approval channel a
    /// human's presence needs is built.
    ///
    /// # Errors
    /// [`LedgerError::NotStuck`] for an item the ledger does not hold as stuck, a one-record
    /// repair without its own Operation's record, and every refusal a write can meet.
    pub async fn repair(&self, item: StuckItem, repair: Repair, by: RepairBy) -> Result<(), LedgerCallError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Repair {
            item,
            repair,
            by: Box::new(by),
            reply,
        })
        .await?;
        answer.await.map_err(|_| LedgerCallError::Ended)?
    }

    /// Commands waiting in the task's queue now.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.commands.max_capacity() - self.commands.capacity()
    }

    /// Shutdown has closed admission: from now on `reserve` and `execute` are refused with
    /// `RUNTIME_DRAINING`, and closes go on.
    pub fn drain(&self) {
        self.draining.store(true, Ordering::Release);
    }

    /// Ends the task: it drains, performing closes until every token is closed or `deadline`
    /// passes, whichever comes first, then ends and says how many reservations it leaves open,
    /// stuck items excepted. A close still queued, or still retrying a `StopPending` refusal, at
    /// the deadline is not performed; its reservation is counted. Only the first call is served: a
    /// later one gets [`LedgerCallError::Ended`] when the task ends.
    ///
    /// # Errors
    /// [`LedgerCallError::Ended`] if the task had already ended.
    pub async fn shutdown(&self, deadline: Instant) -> Result<OpenReservations, LedgerCallError> {
        self.drain();
        let (reply, answer) = oneshot::channel();
        // The message goes first, with the deadline and the answer's channel: whenever the task
        // sees the deadline, its answer is already queued.
        self.control
            .send(Control::Shutdown { deadline, reply })
            .await
            .map_err(|_| LedgerCallError::Ended)?;
        // Then the shared deadline, for a close the task is retrying in the stop record's pause,
        // which reads no message until it ends (of E4).
        self.deadline.send_if_modified(|current| match current {
            Some(earlier) if *earlier <= deadline => false,
            _ => {
                *current = Some(deadline);
                true
            }
        });
        answer.await.map_err(|_| LedgerCallError::Ended)
    }

    /// The ledger as the task holds it now, after every write queued before this call.
    ///
    /// # Errors
    /// [`LedgerCallError::Ended`] once the task has ended.
    pub async fn snapshot(&self) -> Result<LedgerSnapshot, LedgerCallError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Snapshot(reply)).await?;
        answer.await.map_err(|_| LedgerCallError::Ended)
    }

    async fn send(&self, command: Command) -> Result<(), LedgerCallError> {
        self.commands.send(command).await.map_err(|_| LedgerCallError::Ended)
    }
}

/// Starts the ledger task on `supervisor`, with a queue of `capacity` commands. It owns `ledger`
/// from now on, appends through `state`, and engages `stop` as `by` when it fails.
///
/// # Errors
/// [`SpawnError`] if the supervisor refuses the task.
pub fn start_ledger_task(
    supervisor: &Supervisor,
    ledger: Ledger,
    state: StateHandle,
    stop: Stop,
    by: EngagedBy,
    capacity: usize,
) -> Result<(LedgerHandle, JoinHandle<()>), SpawnError> {
    // At least one, and no more than a bounded channel holds (of E4).
    let capacity = capacity.clamp(1, tokio::sync::Semaphore::MAX_PERMITS);
    let (commands, receiver) = mpsc::channel(capacity);
    // One slot per live token, reserved when the token is made.
    let (owed, debts) = mpsc::channel(capacity);
    let (control, orders) = mpsc::channel(1);
    let draining = Arc::new(AtomicBool::new(false));
    let (deadline, deadline_seen) = watch::channel(None);
    let task = Task {
        ledger,
        state,
        stop,
        by,
        durability: "balanced",
        owed,
        stats: LedgerStats::default(),
        draining: Arc::clone(&draining),
        deadline: deadline_seen,
        poison_engaged: false,
        told: None,
    };
    let joined = supervisor.spawn(task.run(receiver, debts, orders))?;
    Ok((
        LedgerHandle {
            commands,
            control,
            draining,
            deadline: Arc::new(deadline),
        },
        joined,
    ))
}

/// Engages the stop with `ledger_failed` if the task unwinds, as the state actor's guard does with
/// `journal_failed`. A normal end engages nothing.
struct EndGuard(Option<(Stop, EngagedBy)>);

impl Drop for EndGuard {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Some((stop, by)) = self.0.take()
        {
            let _engaged = stop.engage(StopReason::LedgerFailed, by);
        }
    }
}

struct Task {
    ledger: Ledger,
    state: StateHandle,
    stop: Stop,
    by: EngagedBy,
    /// The journal's flush policy, as an intent records it.
    durability: &'static str,
    /// The queue of owed closes: every token it makes reserves a slot here.
    owed: mpsc::Sender<Owed>,
    /// Its metrics.
    stats: LedgerStats,
    /// Set by [`LedgerHandle::drain`]: `reserve` and `execute` are refused.
    draining: Arc<AtomicBool>,
    /// The shutdown's deadline, once it is asked for: the drain ends at it, and a close retrying
    /// in the stop record's pause gives up at it.
    deadline: watch::Receiver<Option<Instant>>,
    /// Whether the stop was engaged for the ledger's poison.
    poison_engaged: bool,
    /// The deadline the shutdown's message carried, once it is read.
    told: Option<Instant>,
}

impl Task {
    async fn run(
        mut self,
        mut commands: mpsc::Receiver<Command>,
        mut debts: mpsc::Receiver<Owed>,
        mut control: mpsc::Receiver<Control>,
    ) {
        let _guard = EndGuard(Some((self.stop.clone(), self.by.clone())));
        match self.state.flush_policy().await {
            Ok(FlushPolicy::Strict) => self.durability = "strict",
            Ok(FlushPolicy::Balanced { .. }) => self.durability = "balanced",
            // No journal to write to: no ledger writer, so no spend. Nothing was abandoned.
            Err(_) => {
                self.stop_ledger();
                return;
            }
        }
        let mut commands_open = true;
        let mut asked: Option<oneshot::Sender<OpenReservations>> = None;
        loop {
            let deadline = self.shutdown_deadline();
            if let Some(deadline) = deadline
                && (self.live_tokens() == 0 || Instant::now() >= deadline)
            {
                break;
            }
            if !commands_open && deadline.is_none() {
                // Every handle is gone. The closes already owed are performed; a token dropped
                // from now on finds the task ended, and the next boot settles its reservation.
                while let Ok(debt) = debts.try_recv() {
                    self.owe(debt).await;
                }
                break;
            }
            tokio::select! {
                // A shutdown is seen before anything queued: the drain ends at its deadline.
                biased;
                Some(Control::Shutdown { deadline, reply }) = control.recv(), if asked.is_none() => {
                    self.draining.store(true, Ordering::Release);
                    self.told = Some(deadline);
                    asked = Some(reply);
                }
                // A close owed for a dropped token goes first among the work: it frees a
                // reservation.
                Some(debt) = debts.recv() => {
                    self.owe(debt).await;
                    self.stop_if_poisoned();
                }
                command = commands.recv(), if commands_open => match command {
                    Some(command) => {
                        self.serve(command).await;
                        self.stop_if_poisoned();
                    }
                    None => commands_open = false,
                },
                () = until(deadline), if deadline.is_some() => {}
            }
        }
        // The deadline can be seen before the shutdown's message is read: it was queued first.
        if asked.is_none()
            && let Ok(Control::Shutdown { reply, .. }) = control.try_recv()
        {
            asked = Some(reply);
        }
        if let Some(reply) = asked {
            let _unanswered = reply.send(self.open_reservations());
        }
    }

    /// Tokens alive, and closes owed and not yet performed: each holds a slot.
    fn live_tokens(&self) -> usize {
        self.owed.max_capacity() - self.owed.capacity()
    }

    /// The reservations still open, stuck items excepted: a stuck reservation stays open from boot
    /// to boot until repaired, and `kernel.booted` already counts it.
    fn open_reservations(&self) -> OpenReservations {
        let state = self.ledger.state();
        let stuck = self
            .ledger
            .stuck()
            .iter()
            .filter(|item| matches!(item.kind, StuckKind::Reservation(id) if state.is_open(id)))
            .count();
        let open = state.open_reservations().saturating_sub(stuck);
        OpenReservations(u32::try_from(open).unwrap_or(u32::MAX))
    }

    /// Whether the drain's deadline has passed: a close refused inside the stop record's pause is
    /// not tried again after it.
    fn past_deadline(&self) -> bool {
        self.shutdown_deadline()
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// The shutdown's deadline, if one is asked for.
    fn shutdown_deadline(&self) -> Option<Instant> {
        match (self.told, *self.deadline.borrow()) {
            (Some(told), Some(shared)) => Some(told.min(shared)),
            (told, shared) => told.or(shared),
        }
    }

    /// Waits `pause` before a close is tried again, or less: up to the shutdown's deadline, and no
    /// longer once a deadline is asked for, so a drain never waits on a retry's pause.
    async fn wait_to_retry(&self, pause: Duration) {
        let mut changes = self.deadline.clone();
        let mut wake = Instant::now() + pause;
        if let Some(deadline) = *changes.borrow_and_update() {
            wake = wake.min(deadline);
        }
        tokio::select! {
            () = tokio::time::sleep_until(wake) => {}
            Ok(()) = changes.changed() => {}
        }
    }

    /// A poison the ledger raised itself, in an `apply`, engages the stop as the task's own poisons
    /// do: no ledger writer means no spend.
    fn stop_if_poisoned(&mut self) {
        if self.ledger.is_poisoned() && !self.poison_engaged {
            self.poison_engaged = true;
            let _engaged = self.stop.engage(StopReason::LedgerFailed, self.by.clone());
        }
    }

    /// Poisons the ledger and engages the stop: a write's fate is unknown.
    fn fail(&mut self) {
        self.stats.abandoned += 1;
        self.stop_ledger();
    }

    /// Poisons the ledger and engages the stop with `ledger_failed`.
    fn stop_ledger(&mut self) {
        self.poison_engaged = true;
        self.ledger.poison();
        let _engaged = self.stop.engage(StopReason::LedgerFailed, self.by.clone());
    }

    /// Ends a batch after its append failed: withdrawn when the refusal wrote nothing and no
    /// record of the batch landed; abandoned otherwise, which poisons and stops.
    fn failed<T: uaos_ledger::Closes>(&mut self, batch: Batch<T>, landed: usize, error: StateError) -> LedgerCallError {
        if landed == 0 && wrote_nothing(&error) {
            self.stats.withdrawn += 1;
            let _token = self.ledger.withdraw(batch);
            return LedgerCallError::Unwritten(error);
        }
        self.ledger.abandon(batch);
        self.fail();
        LedgerCallError::Abandoned(error)
    }

    async fn serve(&mut self, command: Command) {
        // A caller that stopped waiting dropped its slot; the write landed or not either way.
        match command {
            Command::Reserve {
                record,
                pool,
                id,
                amount,
                reply,
            } => {
                let reserved = if self.draining.load(Ordering::Acquire) {
                    Err(LedgerCallError::Draining)
                } else {
                    self.reserve(record, pool, id, amount).await
                };
                let _unanswered = reply.send(reserved);
            }
            Command::Allocate {
                pool,
                amount,
                movement,
                reply,
            } => {
                let prepared = self
                    .ledger
                    .prepare_allocate(pool, amount, &movement.principal, movement.key.clone());
                let done = match prepared {
                    Ok(batch) => {
                        self.steps(batch, movement.correlation_id, movement.config_version)
                            .await
                    }
                    Err(error) => Err(LedgerCallError::Ledger(error)),
                };
                let _unanswered = reply.send(done);
            }
            Command::Transfer {
                from,
                to,
                amount,
                movement,
                reply,
            } => {
                let prepared =
                    self.ledger
                        .prepare_transfer(from, to, amount, &movement.principal, movement.key.clone());
                let done = match prepared {
                    Ok(batch) => {
                        self.steps(batch, movement.correlation_id, movement.config_version)
                            .await
                    }
                    Err(error) => Err(LedgerCallError::Ledger(error)),
                };
                let _unanswered = reply.send(done);
            }
            Command::Execute { held, reply } => self.serve_execute(held, reply).await,
            Command::Release { held, reply } => {
                let released = match held.take() {
                    Some((held, _slot)) => self.release_offered(held).await,
                    None => Err(LedgerCallError::Record("a token without its reservation")),
                };
                // A caller gone after queueing its close: the task performed it for them.
                if reply.send(released).is_err() {
                    self.stats.offered_closes += 1;
                }
            }
            Command::Settle { in_flight, reply } => {
                let settled = match in_flight.take() {
                    Some((in_flight, _slot)) => self.settle_offered(in_flight).await,
                    None => Err(LedgerCallError::Record("a token without its reservation")),
                };
                // A caller gone after queueing its close: the task performed it for them.
                if reply.send(settled).is_err() {
                    self.stats.offered_closes += 1;
                }
            }
            Command::Repair {
                item,
                repair,
                by,
                reply,
            } => {
                let _unanswered = reply.send(self.repair(&item, repair, *by).await);
            }
            Command::Snapshot(reply) => {
                let _unanswered = reply.send(LedgerSnapshot {
                    state: self.ledger.state().clone(),
                    poisoned: self.ledger.is_poisoned(),
                    needs_recovery: self.ledger.needs_recovery(),
                    stats: self.stats.clone(),
                });
            }
        }
    }

    /// The intent: prepared, journaled, and applied after its acknowledgement.
    async fn reserve(
        &mut self,
        record: OperationRecord,
        pool: PoolId,
        id: ReservationId,
        amount: NanoUsd,
    ) -> Result<Held, LedgerCallError> {
        if record.upstream.len() > MAX_UPSTREAM_NAME {
            return Err(LedgerCallError::Record("the upstream name is longer than 64 bytes"));
        }
        if !is_upstream_name(&record.upstream) {
            return Err(LedgerCallError::Record(
                "the upstream name is not a token of letters, digits, '.', '_' or '-'",
            ));
        }
        // The slot its close takes if the token is dropped, before anything is written.
        let Ok(slot) = self.owed.clone().try_reserve_owned() else {
            return Err(LedgerCallError::Overloaded);
        };
        let prepared = Instant::now();
        let batch = self
            .ledger
            .prepare_reserve(pool, id, amount, &record.actor)
            .map_err(LedgerCallError::Ledger)?;
        let draft = batch
            .delta()
            .ok()
            .and_then(|delta| intent_draft(&record, &delta, amount, self.durability));
        let Some(draft) = draft else {
            self.ledger.withdraw(batch);
            return Err(LedgerCallError::Record("the intent does not fit its record"));
        };
        match self.state.append(draft).await {
            Ok(appended) => {
                let token = self.ledger.apply(batch);
                self.stats.wrote(&types::OP_RESERVED_INTENT);
                self.stats.applied(prepared);
                // A caller gone when the intent lands drops this token: the task releases it.
                Ok(Held {
                    reservation: token.id(),
                    amount: token.amount(),
                    debt: Some(Debt { token, slot }),
                    record,
                    intent: appended.id,
                    offered: None,
                })
            }
            Err(error) => Err(self.failed(batch, 0, error)),
        }
    }

    /// A write journaled as one `budget.entry` record per entry, applied record by record.
    async fn steps<T: Steps>(
        &mut self,
        mut batch: Batch<T>,
        correlation_id: CorrelationId,
        config_version: ConfigVersion,
    ) -> Result<T::Output, LedgerCallError> {
        let prepared = Instant::now();
        // Every record is built before the first is written: a refusal here wrote nothing (of E4).
        let drafts: Result<Vec<EventDraft>, _> = batch
            .entries()
            .iter()
            .map(|tx| budget_entry_draft(tx, correlation_id, None, config_version))
            .collect();
        let Ok(drafts) = drafts else {
            self.ledger.withdraw(batch);
            return Err(LedgerCallError::Record("an entry does not fit its record"));
        };
        for (landed, draft) in drafts.into_iter().enumerate() {
            match self.state.append(draft).await {
                Ok(_) => {
                    self.ledger.apply_step(&mut batch);
                    self.stats.wrote(&types::BUDGET_ENTRY);
                }
                Err(error) => return Err(self.failed(batch, landed, error)),
            }
        }
        let output = self.ledger.apply(batch);
        self.stats.applied(prepared);
        Ok(output)
    }
}

impl Task {
    /// `execute`, answered; under shutdown, refused.
    async fn serve_execute(&mut self, held: Held, reply: oneshot::Sender<Result<InFlight, LedgerCallError>>) {
        let started = match held.take() {
            // Shutdown refuses a new execution; the reservation is released, never sent, with the
            // drain as its reason. The refusal is the drain's whatever the release met.
            Some((held, _slot)) if self.draining.load(Ordering::Acquire) => {
                let _released = self.release_as(held, types::OP_FAILED, "draining").await;
                Err(LedgerCallError::Draining)
            }
            Some((held, slot)) => self.execute(held, slot).await,
            None => Err(LedgerCallError::Record("a token without its reservation")),
        };
        // A caller gone before the acknowledgement: the token never left the task, so it never
        // reached the door.
        if let Err(Ok(orphan)) = reply.send(started)
            && let Some((orphan, _slot)) = orphan.take()
        {
            self.stats.owned_closes += 1;
            let _closed = self.settle_unsent(orphan, "abandoned", true).await;
        }
    }

    /// A stuck item's repair. The ledger, not the caller, says whether the item is a one-record
    /// reservation: its repair is then its Operation's resolution record, which the record pass
    /// reads only after the entry-less `op.indeterminate` that left it stuck; a two-record
    /// reservation's or a transfer's is `budget.entry` records.
    async fn repair(&mut self, item: &StuckItem, repair: Repair, by: RepairBy) -> Result<(), LedgerCallError> {
        let resolves = self.ledger.resolution_of(item);
        let (event_type, resolution) = match &repair {
            Repair::Settle {
                outcome: RepairOutcome::Committed,
                ..
            } => (types::OP_COMMITTED, "settled"),
            Repair::Settle {
                outcome: RepairOutcome::Failed,
                ..
            } => (types::OP_FAILED, "settled"),
            Repair::Release | Repair::CompleteTransfer | Repair::ReturnTransfer => (types::OP_FAILED, "released"),
        };
        let prepared = Instant::now();
        let batch = self
            .ledger
            .prepare_repair(item, repair, &by.principal)
            .map_err(LedgerCallError::Ledger)?;
        let Some(operation) = resolves else {
            return self.steps(batch, by.correlation_id, by.config_version).await;
        };
        let Some((mut record, intent)) = by.resolves.filter(|(record, _)| record.operation_id == operation) else {
            self.ledger.withdraw(batch);
            return Err(LedgerCallError::Record(
                "a one-record repair resolves the Operation its reservation belongs to",
            ));
        };
        // The human's repair after a crash proves nothing about what left: no `sent` field.
        record.actor = by.principal;
        let fields = serde_json::json!({"reason": STUCK_REPAIR, "resolution": resolution});
        let overrun = batch.entries().iter().any(|tx| tx.kind == BudgetTxKind::Adjust);
        let draft = batch
            .delta()
            .ok()
            .and_then(|delta| closing_draft(&record, intent, event_type.clone(), fields, &delta, overrun));
        let Some(draft) = draft else {
            self.ledger.withdraw(batch);
            return Err(LedgerCallError::Record("a repair does not fit its record"));
        };
        match self.state.append(draft).await {
            Ok(_) => {
                self.ledger.apply(batch);
                self.stats.wrote(&event_type);
                self.stats.applied(prepared);
                Ok(())
            }
            // Refused unwritten, the human may try again; of unknown fate, the ledger stops.
            Err(refused) => Err(self.failed(batch, 0, refused)),
        }
    }
}

/// How a close's one record ended.
enum Closed<O, S> {
    /// Journaled, then applied.
    Done(O, Appended),
    /// Refused inside the stop record's pause and withdrawn: the token, to try again, and the
    /// refusal.
    Retry(Reservation<S>, StateError),
    /// Refused or failed otherwise.
    Failed(LedgerCallError),
}

/// A close the ledger refused before anything was journaled. The token goes with it: the
/// reservation stays open, and the next boot settles it as estimated.
fn close_refused<S>(error: CloseError<S>) -> LedgerCallError {
    match error {
        CloseError::Rejected { error, .. } | CloseError::Failed(error) => LedgerCallError::Ledger(error),
    }
}

impl Task {
    /// The stop, `op.executing`, the stop again; only then the in-flight token.
    async fn execute(&mut self, held: HeldParts, slot: OwnedPermit<Owed>) -> Result<InFlight, LedgerCallError> {
        if self.stop.is_engaged() {
            // The refusal is the stop's whatever the release met.
            let _released = self.release(held, &Released::Stopped).await;
            return Err(LedgerCallError::Stopped);
        }
        match self.state.append(executing_draft(&held.record, held.intent)).await {
            Ok(_) => {
                self.stats.wrote(&types::OP_EXECUTING);
                let HeldParts {
                    token, record, intent, ..
                } = held;
                let in_flight = InFlightParts {
                    token: token.begin(),
                    record,
                    intent,
                    offered: None,
                };
                if self.stop.is_engaged() {
                    // The token never left the task: nothing was sent.
                    let _closed = self.settle_unsent(in_flight, "stopped", false).await;
                    return Err(LedgerCallError::Stopped);
                }
                Ok(InFlight {
                    reservation: in_flight.token.id(),
                    amount: in_flight.token.amount(),
                    debt: Some(Debt {
                        token: in_flight.token,
                        slot,
                    }),
                    record: in_flight.record,
                    intent: in_flight.intent,
                    offered: None,
                })
            }
            Err(error) if wrote_nothing(&error) => {
                self.stats.withdrawn += 1;
                // A stop engaged meanwhile is the refusal's cause: refused as the stop, released as
                // stopped, whatever the release meets (of E4).
                if self.stop.is_engaged() {
                    let _released = self.release(held, &Released::Stopped).await;
                    return Err(LedgerCallError::Stopped);
                }
                Err(self
                    .release(held, &Released::ExecuteRefused)
                    .await
                    .err()
                    .unwrap_or(LedgerCallError::Unwritten(error)))
            }
            Err(error) => {
                // The fate of `op.executing` is unknown: the ledger stops, and the reservation stays
                // open for the next boot to settle as estimated.
                self.fail();
                drop(held);
                Err(LedgerCallError::Abandoned(error))
            }
        }
    }

    /// A token dropped before the task took it: the close its caller offered, or the task's own.
    /// Nobody waits on it: it lands in the journal, or the reservation stays open for the next boot
    /// to settle as estimated.
    async fn owe(&mut self, debt: Owed) {
        let offered = match &debt {
            Owed::Held(held) => held.offered.is_some(),
            Owed::InFlight(in_flight) => in_flight.offered.is_some(),
        };
        if offered {
            self.stats.offered_closes += 1;
        } else {
            self.stats.owned_closes += 1;
        }
        let _closed = match debt {
            Owed::Held(held) => self.release_offered(held).await.map(drop),
            Owed::InFlight(in_flight) => self.settle_offered(in_flight).await.map(drop),
        };
    }

    /// The release offered on a `Held` token. With none offered the close is the task's:
    /// `abandoned`, never sent, since a `Held` token never reached the door.
    async fn release_offered(&mut self, mut held: HeldParts) -> Result<Appended, LedgerCallError> {
        if let Some(released) = held.offered.take() {
            return self.release(held, &released).await;
        }
        held.record.actor = Actor::System;
        self.release_as(held, types::OP_FAILED, "abandoned").await
    }

    /// The settlement offered on an `InFlight` token. With none offered the close is the task's:
    /// the token reached its caller and may have reached the door, so it settles in full, as
    /// estimated.
    async fn settle_offered(
        &mut self,
        mut in_flight: InFlightParts,
    ) -> Result<(Settlement, Appended), LedgerCallError> {
        let (usage, event_type, fields) = if let Some(settled) = in_flight.offered.take() {
            settlement_of(settled, in_flight.token.amount())
        } else {
            in_flight.record.actor = Actor::System;
            let fields =
                serde_json::json!({"reason": "abandoned", "usage_final": false, "may_have_taken_effect": true});
            (Usage::Unknown, types::OP_FAILED, fields)
        };
        self.settle(in_flight, usage, event_type, fields).await
    }

    /// A settlement at 0 for a token that never left the task, so never reached the door: under a
    /// stop seen after `op.executing`, or for a caller of `execute` gone before its answer, which
    /// the task closes as its own.
    async fn settle_unsent(
        &mut self,
        mut in_flight: InFlightParts,
        reason: &str,
        own: bool,
    ) -> Result<(Settlement, Appended), LedgerCallError> {
        if own {
            in_flight.record.actor = Actor::System;
        }
        let unsent = Usage::Reported(NanoUsd::ZERO);
        let fields = serde_json::json!({"reason": reason, "sent": false});
        self.settle(in_flight, unsent, types::OP_FAILED, fields).await
    }

    /// The reservation's `[release]`, in the Operation's closing record, `"sent": false`.
    async fn release(&mut self, held: HeldParts, released: &Released) -> Result<Appended, LedgerCallError> {
        let (event_type, reason) = match released {
            Released::Denied { reason } => (types::OP_DENIED, reason.as_str()),
            Released::Failed { reason } => (types::OP_FAILED, reason.as_str()),
            Released::Stopped => (types::OP_FAILED, "stopped"),
            Released::ExecuteRefused => (types::OP_FAILED, "execute_refused"),
        };
        self.release_as(held, event_type, reason).await
    }

    /// A release written as `event_type` with `reason`, tried again after a refusal inside the stop
    /// record's pause.
    async fn release_as(
        &mut self,
        held: HeldParts,
        event_type: EventType,
        reason: &str,
    ) -> Result<Appended, LedgerCallError> {
        let fields = serde_json::json!({"reason": reason, "sent": false});
        let HeldParts {
            mut token,
            record,
            intent,
            ..
        } = held;
        let mut pause = CLOSE_RETRY_FIRST;
        let mut retried = false;
        loop {
            let prepared = Instant::now();
            let batch = self
                .ledger
                .prepare_release(token, &record.actor)
                .map_err(close_refused)?;
            // Past the drain's deadline a close refused in the pause is not performed: the
            // reservation stays open, counted, for the next boot to settle.
            match self
                .close(batch, &record, intent, event_type.clone(), fields.clone())
                .await
            {
                Closed::Done((), appended) => {
                    self.stats.wrote(&event_type);
                    self.stats.applied(prepared);
                    return Ok(appended);
                }
                Closed::Retry(_, refused) if self.past_deadline() => {
                    return Err(LedgerCallError::Unwritten(refused));
                }
                Closed::Retry(again, _) => token = again,
                Closed::Failed(error) => return Err(error),
            }
            if !retried {
                retried = true;
                self.stats.retried_closes += 1;
            }
            self.wait_to_retry(pause).await;
            pause = pause.saturating_mul(2).min(CLOSE_RETRY_MAX);
        }
    }

    /// The settlement, in the Operation's closing record, tried again after a refusal inside the
    /// stop record's pause.
    async fn settle(
        &mut self,
        in_flight: InFlightParts,
        usage: Usage,
        event_type: EventType,
        fields: Value,
    ) -> Result<(Settlement, Appended), LedgerCallError> {
        let InFlightParts {
            mut token,
            record,
            intent,
            ..
        } = in_flight;
        let mut pause = CLOSE_RETRY_FIRST;
        let mut retried = false;
        loop {
            let prepared = Instant::now();
            let batch = self
                .ledger
                .prepare_settle(token, usage, &record.actor)
                .map_err(close_refused)?;
            // Past the drain's deadline a close refused in the pause is not performed: the
            // reservation stays open, counted, for the next boot to settle.
            match self
                .close(batch, &record, intent, event_type.clone(), fields.clone())
                .await
            {
                Closed::Done(settlement, appended) => {
                    self.stats.wrote(&event_type);
                    self.stats.applied(prepared);
                    return Ok((settlement, appended));
                }
                Closed::Retry(_, refused) if self.past_deadline() => {
                    return Err(LedgerCallError::Unwritten(refused));
                }
                Closed::Retry(again, _) => token = again,
                Closed::Failed(error) => return Err(error),
            }
            if !retried {
                retried = true;
                self.stats.retried_closes += 1;
            }
            self.wait_to_retry(pause).await;
            pause = pause.saturating_mul(2).min(CLOSE_RETRY_MAX);
        }
    }

    /// Journals a close's one record and applies it after the acknowledgement. A refusal inside the
    /// stop record's pause hands the token back to try again; `NotQueued` does not, since the state
    /// actor has ended and no retry can land.
    async fn close<T, S>(
        &mut self,
        batch: Batch<T>,
        record: &OperationRecord,
        intent: EventId,
        event_type: EventType,
        fields: Value,
    ) -> Closed<T::Output, S>
    where
        T: uaos_ledger::Closes<Withdrawn = Option<Reservation<S>>>,
    {
        let overrun = batch.entries().iter().any(|tx| tx.kind == BudgetTxKind::Adjust);
        let draft = batch
            .delta()
            .ok()
            .and_then(|delta| closing_draft(record, intent, event_type, fields, &delta, overrun));
        let Some(draft) = draft else {
            let _token = self.ledger.withdraw(batch);
            return Closed::Failed(LedgerCallError::Record("a close does not fit its record"));
        };
        match self.state.append(draft).await {
            Ok(appended) => Closed::Done(self.ledger.apply(batch), appended),
            Err(error @ StateError::StopPending(_)) => match self.ledger.withdraw(batch) {
                Some(token) => {
                    self.stats.withdrawn += 1;
                    Closed::Retry(token, error)
                }
                None => Closed::Failed(LedgerCallError::Unwritten(error)),
            },
            Err(error) => Closed::Failed(self.failed(batch, 0, error)),
        }
    }
}

/// What a settlement charges, which record closes the Operation, and why (E13). A relay's report is
/// read against `reserved`, the token's own amount, whatever ceiling it metered against: a running
/// cost below the reservation is never taken as the spend (of E4).
fn settlement_of(settled: Settled, reserved: NanoUsd) -> (Usage, EventType, Value) {
    let maybe = |reason: &str, usage_final: bool| serde_json::json!({"reason": reason, "usage_final": usage_final, "may_have_taken_effect": true});
    match settled {
        // Nothing left: a settlement of 0 returns the whole reservation.
        Settled::DoorFailed(error) if !error.may_have_sent() => (
            Usage::Reported(NanoUsd::ZERO),
            types::OP_FAILED,
            serde_json::json!({"reason": error.kind(), "sent": false}),
        ),
        Settled::DoorFailed(error) => (Usage::Unknown, types::OP_FAILED, maybe(error.kind(), false)),
        Settled::Answered { reason, .. } => (Usage::Unknown, types::OP_FAILED, maybe(reason.as_str(), false)),
        Settled::RelayEnded {
            mut report,
            upstream_status,
        } => {
            report.ceiling = reserved;
            let usage = report.settlement();
            match report.end {
                // A relay that completed at a cost of 0 is committed; it never writes `sent`.
                RelayEnd::Completed if (200..300).contains(&upstream_status) => (
                    usage,
                    types::OP_COMMITTED,
                    serde_json::json!({"reason": "completed", "usage_final": report.usage_final}),
                ),
                RelayEnd::Completed => (usage, types::OP_FAILED, maybe("upstream_status", report.usage_final)),
                RelayEnd::Cut(cut) => (usage, types::OP_FAILED, maybe(cut.code(), report.usage_final)),
                RelayEnd::ClientGone => (usage, types::OP_FAILED, maybe("client_gone", report.usage_final)),
            }
        }
    }
}

/// `op.executing`: no entries, linked to the intent.
fn executing_draft(record: &OperationRecord, intent: EventId) -> EventDraft {
    EventDraft {
        parent_id: Some(intent),
        event_type: types::OP_EXECUTING,
        payload_inline: None,
        cost_estimate: None,
        ..record_draft(record)
    }
}

/// An Operation's closing record: its entries and its payload, linked to the intent, at the highest
/// tier when it charges an overrun.
fn closing_draft(
    record: &OperationRecord,
    intent: EventId,
    event_type: EventType,
    fields: Value,
    delta: &LedgerDelta,
    overrun: bool,
) -> Option<EventDraft> {
    let mut payload = fields;
    payload
        .as_object_mut()?
        .insert(LEDGER_FIELD.to_owned(), serde_json::to_value(delta).ok()?);
    Some(EventDraft {
        parent_id: Some(intent),
        event_type,
        payload_inline: Some(InlinePayload::new(payload).ok()?),
        cost_estimate: None,
        risk_tier: if overrun { RiskTier::MAX } else { record.risk_tier },
        ..record_draft(record)
    })
}

/// The envelope fields every record of the Operation carries.
fn record_draft(record: &OperationRecord) -> EventDraft {
    EventDraft {
        session_id: record.session_id,
        pocket_id: record.pocket_id,
        operation_id: Some(record.operation_id),
        request_id: record.request_id,
        agent_id: record.agent_id,
        correlation_id: record.correlation_id,
        parent_id: None,
        actor: record.actor.clone(),
        event_type: types::OP_RESERVED_INTENT,
        payload_ref: None,
        payload_inline: None,
        cost_estimate: None,
        compensable: record.compensable,
        side_effect_class: record.side_effect_class,
        risk_tier: record.risk_tier,
        durability: Durability::Critical,
        config_version: record.config_version,
        metadata: Metadata::default(),
    }
}

/// `op.reserved_intent`, carrying the reservation.
fn intent_draft(
    record: &OperationRecord,
    delta: &LedgerDelta,
    amount: NanoUsd,
    durability: &str,
) -> Option<EventDraft> {
    let mut payload = serde_json::json!({
        "kind": record.kind,
        "upstream": record.upstream,
        "durability": durability,
    });
    payload
        .as_object_mut()?
        .insert(LEDGER_FIELD.to_owned(), serde_json::to_value(delta).ok()?);
    Some(EventDraft {
        session_id: record.session_id,
        pocket_id: record.pocket_id,
        operation_id: Some(record.operation_id),
        request_id: record.request_id,
        agent_id: record.agent_id,
        correlation_id: record.correlation_id,
        parent_id: None,
        actor: record.actor.clone(),
        event_type: types::OP_RESERVED_INTENT,
        payload_ref: None,
        payload_inline: Some(InlinePayload::new(payload).ok()?),
        cost_estimate: Some(amount),
        compensable: record.compensable,
        side_effect_class: record.side_effect_class,
        risk_tier: record.risk_tier,
        durability: Durability::Critical,
        config_version: record.config_version,
        metadata: Metadata::default(),
    })
}

/// Waits until `deadline`, or forever without one.
async fn until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use uaos_contracts::id::TypedId;
    use uaos_state::journal::JournalError;

    use super::*;

    /// A ledger task that unwinds leaves no ledger writer, so its guard engages the stop with
    /// `ledger_failed`; a normal end engages nothing.
    #[test]
    fn a_task_that_unwinds_engages_the_stop() {
        let by = EngagedBy {
            actor: Actor::System,
            correlation_id: CorrelationId::from_parts(9, [9; 10]),
            config_version: ConfigVersion(1),
        };
        let stop = Stop::running();
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            let _guard = EndGuard(Some((stop.clone(), by.clone())));
            std::panic::resume_unwind(Box::new("seeded"));
        }));
        assert!(unwound.is_err());
        assert_eq!(
            stop.reason(),
            Some(StopReason::LedgerFailed),
            "a ledger task that unwound left the kernel running"
        );

        let stop = Stop::running();
        drop(EndGuard(Some((stop.clone(), by))));
        assert!(
            !stop.is_engaged(),
            "a ledger task that ended normally stopped the kernel"
        );
    }

    /// The shutdown's message carries its deadline, so a task that reads the message before the
    /// shared deadline is set still ends at it. The race is made certain here: the message is sent
    /// alone, and the shared deadline never is.
    #[tokio::test]
    async fn a_shutdown_message_alone_carries_its_deadline() {
        use std::path::Path;
        use uaos_platform::sim::fs::SimFs;
        use uaos_platform::sim::{SimClock, SimRng};
        use uaos_platform::{Clock, Rng};
        use uaos_state::journal::Journal;

        use crate::state::{DEFAULT_QUEUE_CAPACITY, StateCore, start_state_actor, state_queue};
        use crate::supervisor::SupervisorLimits;

        let fs = Arc::new(SimFs::new());
        let clock: Arc<dyn Clock> = Arc::new(SimClock::new(
            uaos_contracts::time::WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
        ));
        let rng: Arc<dyn Rng> = Arc::new(SimRng::new(3));
        let dir = Path::new("/data");
        uaos_platform::fs::Fs::create_dir_all(fs.as_ref(), dir).unwrap();
        let journal = Journal::open(fs, clock, rng, dir, FlushPolicy::Strict).unwrap();
        let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default());
        let (state, queue) = state_queue(DEFAULT_QUEUE_CAPACITY);
        let _actor = start_state_actor(&supervisor, StateCore::new(journal), queue).unwrap();
        let by = EngagedBy {
            actor: Actor::System,
            correlation_id: CorrelationId::from_parts(9, [9; 10]),
            config_version: ConfigVersion(1),
        };
        let (ledger, _task) = start_ledger_task(&supervisor, Ledger::default(), state, Stop::running(), by, 8).unwrap();
        let pool = PoolId::from_parts(1, [1; 10]);
        let funds = Movement {
            principal: Actor::System,
            key: IdempotencyKey::new("fund").unwrap(),
            correlation_id: CorrelationId::from_parts(1, [1; 10]),
            config_version: ConfigVersion(1),
        };
        ledger.allocate(pool, NanoUsd::new(1_000), funds).await.unwrap();
        let record = OperationRecord {
            operation_id: OperationId::from_parts(1, [3; 10]),
            session_id: None,
            pocket_id: None,
            request_id: None,
            agent_id: None,
            correlation_id: CorrelationId::from_parts(2, [4; 10]),
            actor: Actor::System,
            kind: OperationKind::ModelCall,
            upstream: "primary".to_owned(),
            side_effect_class: SideEffectClass::External,
            compensable: false,
            risk_tier: RiskTier::new(1).unwrap(),
            config_version: ConfigVersion(1),
        };
        // A live token: the drain waits for it until the deadline.
        let held = ledger
            .reserve(record, pool, ReservationId::from_parts(1, [2; 10]), NanoUsd::new(100))
            .await
            .unwrap();
        let (reply, answer) = oneshot::channel();
        let deadline = Instant::now() + Duration::from_millis(100);
        ledger
            .control
            .send(Control::Shutdown { deadline, reply })
            .await
            .unwrap();
        let answered = tokio::time::timeout(Duration::from_secs(5), answer).await;
        assert_eq!(
            answered.map(Result::ok),
            Ok(Some(OpenReservations(1))),
            "a task that read the shutdown's message before its shared deadline never ended"
        );
        drop(held);
    }

    /// A relay's end decides the closing record and its reason; a completed relay is committed only
    /// with a 2xx status, and its report is read against the reservation, whatever ceiling it
    /// metered against.
    #[test]
    fn a_relays_end_decides_its_closing_record() {
        let reserved = NanoUsd::new(100);
        let ended = |end: RelayEnd, upstream_status: u16| {
            let report = RelayReport {
                end,
                forwarded_bytes: 0,
                segments: 0,
                usage: Vec::new(),
                cost: Some(NanoUsd::new(60)),
                usage_final: true,
                ceiling: reserved,
            };
            let (usage, event_type, fields) = settlement_of(
                Settled::RelayEnded {
                    report,
                    upstream_status,
                },
                reserved,
            );
            (usage, event_type, fields["reason"].as_str().unwrap().to_owned())
        };
        let committed = (
            Usage::Reported(NanoUsd::new(60)),
            types::OP_COMMITTED,
            "completed".to_owned(),
        );
        assert_eq!(ended(RelayEnd::Completed, 200), committed);
        assert_eq!(ended(RelayEnd::Completed, 299), committed);
        for status in [199, 300, 404, 500, 503] {
            assert_eq!(
                ended(RelayEnd::Completed, status),
                (
                    Usage::Reported(NanoUsd::new(60)),
                    types::OP_FAILED,
                    "upstream_status".to_owned()
                ),
                "a completed relay with status {status} was committed"
            );
        }
        assert_eq!(
            ended(RelayEnd::ClientGone, 200),
            (
                Usage::Reported(NanoUsd::new(60)),
                types::OP_FAILED,
                "client_gone".to_owned()
            ),
            "a relay whose client went away was not closed as client_gone"
        );
        assert_eq!(
            ended(RelayEnd::Cut(crate::relay::CutReason::Unpriced), 200),
            (
                Usage::Reported(NanoUsd::new(60)),
                types::OP_FAILED,
                crate::relay::CutReason::Unpriced.code().to_owned()
            )
        );
        // A running cost past the relay's own ceiling but below the reservation is a lower bound,
        // not the spend: the reservation settles in full, estimated.
        let report = RelayReport {
            end: RelayEnd::ClientGone,
            forwarded_bytes: 0,
            segments: 0,
            usage: Vec::new(),
            cost: Some(NanoUsd::new(60)),
            usage_final: false,
            ceiling: NanoUsd::new(50),
        };
        let (usage, _, _) = settlement_of(
            Settled::RelayEnded {
                report,
                upstream_status: 200,
            },
            reserved,
        );
        assert_eq!(
            usage,
            Usage::Unknown,
            "a running cost below the reservation was taken as the spend"
        );
    }

    /// Only a command never queued and a refusal inside the stop record's pause wrote nothing;
    /// every other error, a journal that stays healthy included, may have written.
    #[test]
    fn only_refusals_that_wrote_nothing_withdraw() {
        assert!(wrote_nothing(&StateError::NotQueued));
        assert!(wrote_nothing(&StateError::StopPending(JournalError::LineTooLarge)));
        for error in [
            StateError::Closed,
            StateError::Journal(JournalError::LineTooLarge),
            StateError::Journal(JournalError::Encoding("x".to_owned())),
            StateError::StopRecord,
            StateError::ShutdownRecord,
        ] {
            assert!(!wrote_nothing(&error), "{error:?} was read as unwritten");
        }
    }
}
