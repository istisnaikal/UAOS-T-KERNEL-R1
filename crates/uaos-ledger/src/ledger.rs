// SPDX-License-Identifier: Apache-2.0

//! The ledger writer: turns budget operations into recorded entries.
//!
//! Every write has two phases (intent contract). `prepare_*` computes the write's entries against
//! the state, runs every check, and changes nothing: it returns a [`Batch`]. The caller journals
//! the batch's entries (an Operation's record carries them as a compact delta, [`Batch::delta`])
//! and only after the journal's acknowledgement does [`Ledger::apply`] change the state, so a
//! reservation is durable before the Operation it pays for can execute. A refusal that wrote
//! nothing [`Ledger::withdraw`]s the batch and hands its token back; an error whose fate is unknown
//! [`Ledger::abandon`]s it, and the ledger refuses all work until it is rebuilt from the journal:
//! the record may or may not have landed, and guessing would let memory and truth diverge. One
//! batch is outstanding at a time.
//!
//! The synchronous [`LedgerSink`] methods (`allocate`, `reserve`, `release`, `settle`,
//! `transfer`, `recover`) are the same batches, recorded entry by entry through the sink.
//!
//! Reservations are typestate tokens. A [`Reservation<Held>`] may be released; once execution
//! starts, [`Reservation::begin`] turns it into a [`Reservation<InFlight>`], which can only be
//! settled — money that may already have been spent can never be released. Tokens are not
//! `Clone`, so a reservation cannot be settled twice in-process, and the state refuses a second
//! closing entry anyway. A closing call that is refused before anything is recorded hands the
//! token back ([`CloseError::Rejected`]).
//!
//! A token that is dropped leaves its reservation open and held: the money stays unavailable
//! until the next start. A ledger rebuilt from the journal ([`Ledger::replay`]) refuses new work
//! until [`Ledger::recover`] has closed what the previous run left open: unsettled reservations
//! are settled at the full reserved amount, marked `estimated`, never released. What recovery
//! cannot close is a [`StuckItem`]; the ledger keeps refusing new work until a human repairs every
//! one ([`Ledger::prepare_repair`]).
//!
//! Limitation stated plainly: the journal does not yet record *when* execution began, so a replayed
//! ledger cannot tell a held reservation from an in-flight one. That is why recovery never
//! releases. The runtime journals the start of execution in P3.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use uaos_contracts::budget::{BudgetTx, BudgetTxKind, BudgetTxSchema, IdempotencyKey, ReasonCode};
use uaos_contracts::event::Actor;
use uaos_contracts::id::{OperationId, PoolId, ReservationId};
use uaos_contracts::money::NanoUsd;

use crate::inline::{CompactError, LedgerDelta, STUCK_REPAIR, compact};
use crate::plan::RecoveryPlan;
use crate::state::{LedgerError, LedgerState, Undo, transfer_in_key, transfer_return_key};

/// Where entries are recorded durably.
pub trait LedgerSink {
    /// Records one entry; returns only once it is durable to the sink's standard.
    ///
    /// # Errors
    /// A description of the failure; the entry may or may not have been recorded.
    fn record(&mut self, tx: &BudgetTx) -> Result<(), String>;
}

/// An in-memory sink for tests and simulation.
#[derive(Debug, Default)]
pub struct MemorySink {
    /// Entries in recording order.
    pub entries: Vec<BudgetTx>,
    /// When set, the next `record` fails with this message.
    pub fail_next: Option<String>,
}

impl LedgerSink for MemorySink {
    fn record(&mut self, tx: &BudgetTx) -> Result<(), String> {
        if let Some(message) = self.fail_next.take() {
            return Err(message);
        }
        self.entries.push(tx.clone());
        Ok(())
    }
}

/// Marker: reserved, execution not started; may be released.
#[derive(Debug)]
pub struct Held;
/// Marker: execution started; can only be settled.
#[derive(Debug)]
pub struct InFlight;

/// A reservation token. Not `Clone`: it is consumed by exactly one closing operation.
#[must_use = "an unclosed reservation is settled conservatively at full cost by recovery"]
#[derive(Debug)]
pub struct Reservation<S> {
    id: ReservationId,
    pool: PoolId,
    amount: NanoUsd,
    state: PhantomData<S>,
}

impl<S> Reservation<S> {
    /// The reservation identifier.
    #[must_use]
    pub fn id(&self) -> ReservationId {
        self.id
    }

    /// The reserved amount.
    #[must_use]
    pub fn amount(&self) -> NanoUsd {
        self.amount
    }
}

impl Reservation<Held> {
    /// Marks execution as started. From here on the reservation can only be settled.
    pub fn begin(self) -> Reservation<InFlight> {
        Reservation {
            id: self.id,
            pool: self.pool,
            amount: self.amount,
            state: PhantomData,
        }
    }
}

/// What the provider (or tool) reported as the actual cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    /// Actual cost is known.
    Reported(NanoUsd),
    /// No usage was reported (aborted stream, crash): settle at the reserved amount, estimated.
    Unknown,
}

/// The result of settling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settlement {
    /// Amount recorded as spent.
    pub spent: NanoUsd,
    /// Amount returned to the pool.
    pub released: NanoUsd,
    /// Amount charged beyond the reservation (an S1 condition: the estimate was too low).
    pub overrun: NanoUsd,
    /// Whether the spend is an estimate.
    pub estimated: bool,
}

/// What [`Ledger::recover`] did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Recovery {
    /// Open reservations settled at their full reserved amount (estimated).
    pub settled_estimated: usize,
    /// Partially settled reservations completed (remainder released or overrun charged).
    pub completed: usize,
    /// Transfers whose second half was recorded.
    pub transfers_completed: usize,
    /// Items that could not be closed, with the reason (an S2 condition). While any remain, the
    /// ledger keeps refusing new work.
    pub stuck: Vec<String>,
    /// The same items, typed: what a repair names.
    pub stuck_items: Vec<StuckItem>,
}

/// A closing call (`release`, `settle`) that failed.
#[derive(Debug)]
pub enum CloseError<S> {
    /// Refused before anything was recorded: the token is handed back and may be used again.
    Rejected {
        /// Why.
        error: LedgerError,
        /// The unused token.
        reservation: Reservation<S>,
    },
    /// Failed after recording started; the token is gone.
    Failed(LedgerError),
}

impl<S> CloseError<S> {
    /// The underlying error.
    #[must_use]
    pub fn error(&self) -> &LedgerError {
        match self {
            Self::Rejected { error, .. } | Self::Failed(error) => error,
        }
    }
}

impl<S: fmt::Debug> fmt::Display for CloseError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.error(), f)
    }
}

impl<S: fmt::Debug> std::error::Error for CloseError<S> {}

impl<S> From<CloseError<S>> for LedgerError {
    fn from(e: CloseError<S>) -> Self {
        match e {
            CloseError::Rejected { error, .. } | CloseError::Failed(error) => error,
        }
    }
}

/// The ledger: state plus the rules for producing entries.
#[derive(Debug, Default)]
pub struct Ledger {
    state: LedgerState,
    poisoned: bool,
    /// Whether new work is accepted, or the ledger waits for its recovery or its repairs.
    phase: Phase,
    /// A batch is prepared and not yet applied, withdrawn or abandoned.
    batch_outstanding: bool,
    /// What recovery could not close, until a human repairs it.
    stuck: Vec<StuckItem>,
    /// For each stuck one-record reservation, the Operation whose intent established it: its repair
    /// is that Operation's resolution record.
    resolves: BTreeMap<ReservationId, OperationId>,
    /// While a rehearsal runs: what each applied entry changed, to put back afterwards.
    undo_log: Option<Vec<Undo>>,
}

/// Where a ledger stands between its rebuild and new work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Phase {
    /// New work is accepted.
    #[default]
    Live,
    /// Rebuilt from the journal; `recover` has not run.
    Replayed,
    /// Recovered, with items stuck: new work waits until a human repairs every one.
    Stuck,
}

/// Suffixes and prefixes the ledger derives keys with. Caller keys may not use them, so a
/// caller can never collide with an entry the ledger writes for itself.
const DERIVED_SUFFIXES: [&str; 9] = [
    ":in",
    ":return",
    ":reserve",
    ":release",
    ":settle",
    ":overrun",
    ":repair_release",
    ":repair_settle",
    ":repair_overrun",
];
const DERIVED_PREFIX: &str = "rsv_";

fn caller_key(key: IdempotencyKey) -> Result<IdempotencyKey, LedgerError> {
    let k = key.as_str();
    if k.starts_with(DERIVED_PREFIX) || DERIVED_SUFFIXES.iter().any(|s| k.ends_with(s)) {
        Err(LedgerError::KeyReserved(k.to_owned()))
    } else {
        Ok(key)
    }
}

fn key(text: String) -> Result<IdempotencyKey, LedgerError> {
    IdempotencyKey::new(text).map_err(LedgerError::Invalid)
}

fn reason(code: &str) -> Result<ReasonCode, LedgerError> {
    ReasonCode::new(code).map_err(LedgerError::Invalid)
}

/// An entry ready to record, or the one an idempotent retry already recorded.
enum Prepared {
    New(BudgetTx),
    Recorded,
}

/// What a settlement charges: reported usage, or the reserved amount marked estimated.
fn actual_spend(already_settled: Option<NanoUsd>, usage: Usage, reserved: NanoUsd) -> (NanoUsd, bool) {
    match (already_settled, usage) {
        (Some(actual), _) | (None, Usage::Reported(actual)) => (actual, false),
        (None, Usage::Unknown) => (reserved, true),
    }
}

fn settle_draft(
    id: ReservationId,
    pool: PoolId,
    reserved: NanoUsd,
    actual: NanoUsd,
    estimated: bool,
) -> Result<Draft, LedgerError> {
    Ok(Draft {
        key: key(format!("{id}:settle"))?,
        pool,
        kind: BudgetTxKind::Settle,
        amount: actual,
        reason: if estimated { "settle_estimated" } else { "settle" },
        reservation: Some(id),
        counterparty: None,
        settled: actual == reserved,
        estimated,
    })
}

/// Fields of an entry that vary by operation.
struct Draft {
    key: IdempotencyKey,
    pool: PoolId,
    kind: BudgetTxKind,
    amount: NanoUsd,
    reason: &'static str,
    reservation: Option<ReservationId>,
    counterparty: Option<PoolId>,
    settled: bool,
    estimated: bool,
}

/// An item recovery could not close: it keeps the ledger refusing new work until a human repairs
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StuckItem {
    /// What is stuck.
    pub kind: StuckKind,
    /// Why recovery could not close it: a reason code, never free text, never an amount.
    pub reason: ReasonCode,
}

/// What a [`StuckItem`] names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StuckKind {
    /// A reservation still open.
    Reservation(ReservationId),
    /// A transfer whose second half is not recorded, by its `transfer_out` key.
    Transfer(IdempotencyKey),
}

impl fmt::Display for StuckItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            StuckKind::Reservation(id) => write!(f, "reservation {id}: {}", self.reason.as_str()),
            StuckKind::Transfer(key) => write!(f, "transfer {}: {}", key.as_str(), self.reason.as_str()),
        }
    }
}

/// How a human repairs a stuck item. Every entry carries reason `stuck_repair` and a key of its
/// own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repair {
    /// Settle a stuck reservation at `amount`: `[settle]`, or with the remainder's release or the
    /// overrun's adjust. `outcome` is the record a one-record Operation's resolution is.
    Settle {
        /// The spend the human records.
        amount: NanoUsd,
        /// `op.committed` or `op.failed` for a one-record Operation.
        outcome: RepairOutcome,
    },
    /// Release what a stuck reservation still holds.
    Release,
    /// Record the `transfer_in` recovery would have written (`<out>:in`).
    CompleteTransfer,
    /// Return a stuck transfer to its source (`<out>:return`).
    ReturnTransfer,
}

/// The resolution record a one-record Operation's repair is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairOutcome {
    /// `op.committed` (`ResolveCommitted`).
    Committed,
    /// `op.failed` (`ResolveFailed`).
    Failed,
}

/// One ledger write, prepared and not applied: its entries were computed against the state and
/// checked, and nothing changed. The caller journals them, then [`Ledger::apply`]s the batch after
/// the acknowledgement, [`Ledger::withdraw`]s it after a refusal that wrote nothing, or
/// [`Ledger::abandon`]s it when the fate is unknown. While a batch is outstanding the ledger
/// prepares nothing else; dropping one without ending it leaves the ledger refusing work.
#[must_use = "a batch must be applied, withdrawn or abandoned; the ledger prepares nothing else until then"]
#[derive(Debug)]
pub struct Batch<T> {
    entries: Vec<BudgetTx>,
    applied: usize,
    then: T,
}

impl<T> Batch<T> {
    /// The entries, in the order they apply: one `budget.entry` record each, for a write that is
    /// not an Operation's.
    #[must_use]
    pub fn entries(&self) -> &[BudgetTx] {
        &self.entries
    }

    /// The compact delta an Operation's record carries: the only way entries leave the ledger for
    /// an Operation record.
    ///
    /// # Errors
    /// [`CompactError`] if the entries cannot travel as a delta (an empty batch, a write that is
    /// not an Operation's).
    pub fn delta(&self) -> Result<LedgerDelta, CompactError> {
        let actor = self
            .entries
            .first()
            .map(|tx| tx.principal.clone())
            .ok_or(CompactError::Count)?;
        compact(&self.entries, &actor)
    }
}

/// What a batch gives back when applied or withdrawn.
pub trait Closes: sealed::Sealed {
    /// What [`Ledger::apply`] returns.
    type Output;
    /// What [`Ledger::withdraw`] returns.
    type Withdrawn;
    #[doc(hidden)]
    fn output(self) -> Self::Output;
    #[doc(hidden)]
    fn withdrawn(self) -> Self::Withdrawn;
    #[doc(hidden)]
    fn repaired(&self) -> Option<&StuckItem> {
        None
    }
}

/// A batch journaled as several records, one `budget.entry` per entry: applied record by record
/// with [`Ledger::apply_step`].
pub trait Steps: Closes {}

mod sealed {
    pub trait Sealed {}
}

/// A reservation, prepared: [`Ledger::apply`] gives its token.
#[derive(Debug)]
pub struct Reserve(Reservation<Held>);
/// A release, prepared: withdrawn, it gives the token back (none for recovery's).
#[derive(Debug)]
pub struct Release(Option<Reservation<Held>>);
/// A settlement, prepared: applied, it gives the [`Settlement`]; withdrawn, the token back.
#[derive(Debug)]
pub struct Settle {
    token: Option<Reservation<InFlight>>,
    settlement: Settlement,
}
/// An allocation, prepared.
#[derive(Debug)]
pub struct Allocate;
/// A transfer, prepared: two records.
#[derive(Debug)]
pub struct Transfer;
/// A repair, prepared: applied, its item leaves the stuck set.
#[derive(Debug)]
pub struct Repaired(StuckItem);
/// Recovery's own closes, recorded through the sink at boot.
#[derive(Debug)]
struct Recovered;

impl sealed::Sealed for Reserve {}
impl sealed::Sealed for Release {}
impl sealed::Sealed for Settle {}
impl sealed::Sealed for Allocate {}
impl sealed::Sealed for Transfer {}
impl sealed::Sealed for Repaired {}
impl sealed::Sealed for Recovered {}

impl Closes for Reserve {
    type Output = Reservation<Held>;
    type Withdrawn = ();
    fn output(self) -> Self::Output {
        self.0
    }
    fn withdrawn(self) {}
}

impl Closes for Release {
    type Output = ();
    type Withdrawn = Option<Reservation<Held>>;
    fn output(self) {}
    fn withdrawn(self) -> Self::Withdrawn {
        self.0
    }
}

impl Closes for Settle {
    type Output = Settlement;
    type Withdrawn = Option<Reservation<InFlight>>;
    fn output(self) -> Self::Output {
        self.settlement
    }
    fn withdrawn(self) -> Self::Withdrawn {
        self.token
    }
}

impl Closes for Allocate {
    type Output = ();
    type Withdrawn = ();
    fn output(self) {}
    fn withdrawn(self) {}
}

impl Closes for Transfer {
    type Output = ();
    type Withdrawn = ();
    fn output(self) {}
    fn withdrawn(self) {}
}

impl Closes for Repaired {
    type Output = ();
    type Withdrawn = ();
    fn output(self) {}
    fn withdrawn(self) {}
    fn repaired(&self) -> Option<&StuckItem> {
        Some(&self.0)
    }
}

impl Closes for Recovered {
    type Output = ();
    type Withdrawn = ();
    fn output(self) {}
    fn withdrawn(self) {}
}

impl Steps for Allocate {}
impl Steps for Transfer {}
impl Steps for Repaired {}

/// Whether a settlement's entries are the ledger's own or a repair's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Keys {
    Own,
    Repair,
}

impl Keys {
    const fn suffix(self, own: &'static str, repair: &'static str) -> &'static str {
        match self {
            Self::Own => own,
            Self::Repair => repair,
        }
    }

    const fn reason(self, own: &'static str) -> &'static str {
        match self {
            Self::Own => own,
            Self::Repair => STUCK_REPAIR,
        }
    }
}

/// A settlement's drafts, and what it charges (the ledger's sequence: `[settle]`, then the
/// remainder's release or the overrun's adjust).
fn settlement_drafts(
    id: ReservationId,
    pool: PoolId,
    reserved: NanoUsd,
    already_settled: Option<NanoUsd>,
    usage: Usage,
    keys: Keys,
) -> Result<(Vec<Draft>, Settlement), LedgerError> {
    let (actual, estimated) = actual_spend(already_settled, usage, reserved);
    let mut drafts = Vec::with_capacity(2);
    if already_settled.is_none() {
        let mut d = settle_draft(id, pool, reserved, actual, estimated)?;
        if keys == Keys::Repair {
            d.key = key(format!("{id}:repair_settle"))?;
            d.reason = STUCK_REPAIR;
        }
        drafts.push(d);
    }
    let mut out = Settlement {
        spent: actual,
        released: NanoUsd::ZERO,
        overrun: NanoUsd::ZERO,
        estimated,
    };
    if actual < reserved {
        let remainder = reserved.checked_sub(actual).ok_or(LedgerError::Overflow)?;
        drafts.push(Draft {
            key: key(format!("{id}:{}", keys.suffix("release", "repair_release")))?,
            pool,
            kind: BudgetTxKind::Release,
            amount: remainder,
            reason: keys.reason("release_remainder"),
            reservation: Some(id),
            counterparty: None,
            settled: true,
            estimated: false,
        });
        out.released = remainder;
    } else if actual > reserved {
        let overrun = actual.checked_sub(reserved).ok_or(LedgerError::Overflow)?;
        drafts.push(Draft {
            key: key(format!("{id}:{}", keys.suffix("overrun", "repair_overrun")))?,
            pool,
            kind: BudgetTxKind::Adjust,
            amount: NanoUsd::ZERO.checked_sub(overrun).ok_or(LedgerError::Overflow)?,
            reason: keys.reason("overrun"),
            reservation: Some(id),
            counterparty: None,
            settled: true,
            estimated: false,
        });
        out.overrun = overrun;
    }
    Ok((drafts, out))
}

fn release_draft(id: ReservationId, pool: PoolId, amount: NanoUsd, keys: Keys) -> Result<Draft, LedgerError> {
    Ok(Draft {
        key: key(format!("{id}:{}", keys.suffix("release", "repair_release")))?,
        pool,
        kind: BudgetTxKind::Release,
        amount,
        reason: keys.reason("release"),
        reservation: Some(id),
        counterparty: None,
        settled: true,
        estimated: false,
    })
}

impl Ledger {
    /// Rebuilds a ledger from recorded entries (the journal's `budget.entry` records).
    ///
    /// # Errors
    /// The first entry that does not apply; the history is inconsistent at that point.
    pub fn replay<'a>(entries: impl IntoIterator<Item = &'a BudgetTx>) -> Result<Self, LedgerError> {
        let mut state = LedgerState::default();
        for tx in entries {
            state.apply(tx)?;
        }
        Ok(Self {
            state,
            phase: Phase::Replayed,
            ..Self::default()
        })
    }

    /// Whether the ledger was rebuilt and still has to run [`Ledger::recover`], or recovery left
    /// an item stuck that no repair has closed yet: new work is refused until it is `false`.
    #[must_use]
    pub fn needs_recovery(&self) -> bool {
        self.phase != Phase::Live
    }

    /// The items recovery could not close, in the order it met them.
    #[must_use]
    pub fn stuck(&self) -> &[StuckItem] {
        &self.stuck
    }

    /// The Operation a stuck one-record reservation belongs to: its repair is journaled as that
    /// Operation's resolution record, never as `budget.entry` records. `None` for a two-record
    /// reservation, a transfer, or an item that is not stuck.
    #[must_use]
    pub fn resolution_of(&self, item: &StuckItem) -> Option<OperationId> {
        // By kind, as `prepare_repair` and `stuck_resolved` match: a listing taken at another time
        // may give the same item another reason (of E4).
        match item.kind {
            StuckKind::Reservation(id) if self.stuck.iter().any(|stuck| stuck.kind == item.kind) => {
                self.resolves.get(&id).copied()
            }
            _ => None,
        }
    }

    /// New work is refused while poisoned, and on a rebuilt ledger until recovery has run and no
    /// item is stuck: a replayed ledger may still hold an overrun or a half transfer the cap check
    /// must not miss.
    fn ensure_live(&self) -> Result<(), LedgerError> {
        if self.poisoned {
            Err(LedgerError::Poisoned)
        } else if self.phase != Phase::Live {
            Err(LedgerError::RecoveryRequired)
        } else {
            Ok(())
        }
    }

    /// Boot's token-less closes exist only between replay and recovery.
    fn ensure_unrecovered(&self) -> Result<(), LedgerError> {
        if self.phase == Phase::Replayed {
            Ok(())
        } else {
            Err(LedgerError::NotReplayed)
        }
    }

    /// Runs `f` on this ledger, then puts back everything it changed: every entry applied, the
    /// phase, the stuck set, the poison and the outstanding batch. The recovery plan rehearses boot
    /// this way, without copying the replayed state.
    pub(crate) fn rehearse<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        let saved = (
            self.phase,
            self.stuck.clone(),
            self.resolves.clone(),
            self.poisoned,
            self.batch_outstanding,
        );
        let outer = self.undo_log.replace(Vec::new());
        let result = f(self);
        let log = std::mem::replace(&mut self.undo_log, outer).unwrap_or_default();
        for undo in log.into_iter().rev() {
            self.state.undo(undo);
        }
        (
            self.phase,
            self.stuck,
            self.resolves,
            self.poisoned,
            self.batch_outstanding,
        ) = saved;
        result
    }

    /// One batch at a time, and none on a poisoned ledger.
    fn ensure_no_batch(&self) -> Result<(), LedgerError> {
        if self.poisoned {
            Err(LedgerError::Poisoned)
        } else if self.batch_outstanding {
            Err(LedgerError::Pending)
        } else {
            Ok(())
        }
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> &LedgerState {
        &self.state
    }

    /// Whether a recording failure has stopped the ledger until it is rebuilt.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Stops the ledger until it is rebuilt from the journal: a record without a batch (such as
    /// `op.executing`) met an error whose fate is unknown.
    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Builds the entry for `d` and checks it against the state, recording nothing. For an
    /// idempotent retry it returns the entry recorded before.
    fn prepare(&self, principal: &Actor, d: Draft) -> Result<Prepared, LedgerError> {
        if self.poisoned {
            return Err(LedgerError::Poisoned);
        }
        let reason_code = reason(d.reason)?;
        if let Some(previous) = self.state.entry_for(&d.key) {
            // Idempotent retry: return what was recorded, record nothing new. The same key for
            // anything else (another movement of money, another principal or reason) is a caller
            // bug, never silently absorbed.
            let same = previous.kind == d.kind
                && previous.pool_id == d.pool
                && previous.amount == d.amount
                && previous.reservation_id == d.reservation
                && previous.counterparty_pool == d.counterparty
                && previous.principal == *principal
                && previous.reason_code == reason_code
                && previous.settled == d.settled
                && previous.estimated == d.estimated;
            return if same {
                Ok(Prepared::Recorded)
            } else {
                Err(LedgerError::KeyConflict(d.key.as_str().to_owned()))
            };
        }
        let before = self.state.pool(d.pool).map_or(NanoUsd::ZERO, |p| p.available);
        let mut tx = BudgetTx {
            schema: BudgetTxSchema::V1,
            idempotency_key: d.key,
            pool_id: d.pool,
            principal: principal.clone(),
            session_id: None,
            kind: d.kind,
            amount: d.amount,
            balance_before: before,
            balance_after: before,
            reason_code,
            related_event: None,
            reservation_id: d.reservation,
            counterparty_pool: d.counterparty,
            settled: d.settled,
            estimated: d.estimated,
        };
        tx.balance_after = before.checked_add(tx.effect()?).ok_or(LedgerError::Overflow)?;
        self.state.check(&tx)?;
        Ok(Prepared::New(tx))
    }

    /// The new entries for `drafts`, each computed from the state the one before leaves: applied
    /// tentatively and undone, so the state is as it was whatever happens.
    fn prepare_entries(&mut self, principal: &Actor, drafts: Vec<Draft>) -> Result<Vec<BudgetTx>, LedgerError> {
        let mut undos = Vec::with_capacity(drafts.len());
        let mut entries = Vec::with_capacity(drafts.len());
        let mut failure = None;
        for d in drafts {
            match self.prepare(principal, d) {
                Ok(Prepared::Recorded) => {}
                Ok(Prepared::New(tx)) => match self.state.apply_undoable(&tx) {
                    Ok(undo) => {
                        undos.extend(undo);
                        entries.push(tx);
                    }
                    Err(e) => {
                        failure = Some(e);
                        break;
                    }
                },
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        for undo in undos.into_iter().rev() {
            self.state.undo(undo);
        }
        failure.map_or(Ok(entries), Err)
    }

    /// Prepares a batch: one at a time, none on a poisoned ledger.
    fn batch<T>(&mut self, principal: &Actor, drafts: Vec<Draft>, then: T) -> Result<Batch<T>, (LedgerError, T)> {
        if let Err(e) = self.ensure_no_batch() {
            return Err((e, then));
        }
        match self.prepare_entries(principal, drafts) {
            Ok(entries) => {
                self.batch_outstanding = true;
                Ok(Batch {
                    entries,
                    applied: 0,
                    then,
                })
            }
            Err(e) => Err((e, then)),
        }
    }

    /// Applies one entry the journal acknowledged. If it does not apply, memory no longer matches
    /// the journal: the ledger is poisoned. Unreachable while `prepare` and `apply` share one rule
    /// set.
    fn apply_entry(&mut self, tx: &BudgetTx) {
        let applied = match self.undo_log.as_mut() {
            Some(log) => self.state.apply_undoable(tx).map(|undo| log.extend(undo)),
            None => self.state.apply(tx),
        };
        if applied.is_err() {
            self.poisoned = true;
        }
    }

    /// Applies the batch after its record was acknowledged: every entry not yet applied, in order.
    /// A repair's item leaves the stuck set; when the last does, the ledger accepts new work again.
    pub fn apply<T: Closes>(&mut self, mut batch: Batch<T>) -> T::Output {
        while !self.poisoned && batch.applied < batch.entries.len() {
            let tx = batch.entries[batch.applied].clone();
            self.apply_entry(&tx);
            batch.applied += 1;
        }
        self.batch_outstanding = false;
        if !self.poisoned
            && let Some(item) = batch.then.repaired()
        {
            self.stuck_resolved(item);
        }
        batch.then.output()
    }

    /// Applies the next record of a batch journaled as several (one `budget.entry` per entry),
    /// after that record's acknowledgement. [`Ledger::apply`] ends the batch after the last.
    pub fn apply_step<T: Steps>(&mut self, batch: &mut Batch<T>) {
        if self.poisoned {
            return;
        }
        if let Some(tx) = batch.entries.get(batch.applied).cloned() {
            self.apply_entry(&tx);
            batch.applied += 1;
        }
    }

    /// Ends a batch whose record was refused **without being written** (the state handle's own
    /// verdict): nothing changes, the ledger stays live, and the batch's token comes back.
    ///
    /// Only before the batch's first record was acknowledged: once [`Ledger::apply_step`] has
    /// applied a record, any failure abandons, and a `withdraw` then poisons the ledger as
    /// [`Ledger::abandon`] does (a transfer whose second record is refused after the first
    /// landed). Only a batch of several records can be part applied; theirs give back nothing.
    pub fn withdraw<T: Closes>(&mut self, batch: Batch<T>) -> T::Withdrawn {
        self.batch_outstanding = false;
        if batch.applied > 0 {
            self.poisoned = true;
        }
        batch.then.withdrawn()
    }

    /// Ends a batch whose record's fate is unknown: the ledger is poisoned and refuses all new
    /// work until it is rebuilt from the journal.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "taking the batch by value is the point: it cannot be applied afterwards"
    )]
    pub fn abandon<T>(&mut self, batch: Batch<T>) {
        drop(batch);
        self.batch_outstanding = false;
        self.poisoned = true;
    }

    /// A repair was applied: its item leaves the stuck set, and with the last one the ledger leaves
    /// the replayed state.
    fn stuck_resolved(&mut self, item: &StuckItem) {
        self.stuck.retain(|stuck| stuck.kind != item.kind);
        if self.stuck.is_empty() {
            self.phase = Phase::Live;
        }
    }

    /// Prepares a reservation of `amount` before an Operation executes. The hard cap: refused with
    /// [`LedgerError::Insufficient`] if the pool cannot cover it. A reservation identifier is
    /// single-use ([`LedgerError::ReservationReused`]).
    ///
    /// # Errors
    /// `Pending`, `Insufficient`, `UnknownPool`, `ReservationReused`, or consistency failures.
    pub fn prepare_reserve(
        &mut self,
        pool: PoolId,
        id: ReservationId,
        amount: NanoUsd,
        principal: &Actor,
    ) -> Result<Batch<Reserve>, LedgerError> {
        self.ensure_live()?;
        if self.state.knows_reservation(id) {
            return Err(LedgerError::ReservationReused(id));
        }
        let d = Draft {
            key: key(format!("{id}:reserve"))?,
            pool,
            kind: BudgetTxKind::Reserve,
            amount,
            reason: "reserve",
            reservation: Some(id),
            counterparty: None,
            settled: false,
            estimated: false,
        };
        let token = Reservation {
            id,
            pool,
            amount,
            state: PhantomData,
        };
        self.batch(principal, vec![d], Reserve(token)).map_err(|(e, _)| e)
    }

    /// Prepares the release of a reservation whose execution never started.
    ///
    /// # Errors
    /// [`CloseError::Rejected`], with the token, if it cannot be prepared.
    pub fn prepare_release(
        &mut self,
        reservation: Reservation<Held>,
        principal: &Actor,
    ) -> Result<Batch<Release>, CloseError<Held>> {
        let draft = self
            .ensure_live()
            .and_then(|()| release_draft(reservation.id, reservation.pool, reservation.amount, Keys::Own));
        let d = match draft {
            Ok(d) => d,
            Err(error) => return Err(CloseError::Rejected { error, reservation }),
        };
        self.batch(principal, vec![d], Release(Some(reservation)))
            .map_err(|(error, then)| match then.0 {
                Some(reservation) => CloseError::Rejected { error, reservation },
                None => CloseError::Failed(error),
            })
    }

    /// Prepares the settlement of a reservation whose execution started: the spend, then the
    /// remainder's release or the overrun's adjust.
    ///
    /// # Errors
    /// [`CloseError::Rejected`], with the token, if it cannot be prepared.
    pub fn prepare_settle(
        &mut self,
        reservation: Reservation<InFlight>,
        usage: Usage,
        principal: &Actor,
    ) -> Result<Batch<Settle>, CloseError<InFlight>> {
        let drafts = self.ensure_live().and_then(|()| {
            settlement_drafts(
                reservation.id,
                reservation.pool,
                reservation.amount,
                None,
                usage,
                Keys::Own,
            )
        });
        let (drafts, settlement) = match drafts {
            Ok(d) => d,
            Err(error) => return Err(CloseError::Rejected { error, reservation }),
        };
        let then = Settle {
            token: Some(reservation),
            settlement,
        };
        self.batch(principal, drafts, then)
            .map_err(|(error, then)| match then.token {
                Some(reservation) => CloseError::Rejected { error, reservation },
                None => CloseError::Failed(error),
            })
    }

    /// Boot, before [`Ledger::recover`]: the settlement of an open reservation at its full amount,
    /// estimated, without a token, for the `op.indeterminate` that closes its Operation. Only on a
    /// replayed ledger that has not run its recovery.
    ///
    /// # Errors
    /// `NotReplayed` on a live or recovered ledger, `NotOpen`, `Pending`, or consistency failures.
    pub fn prepare_recovery_settle(&mut self, id: ReservationId) -> Result<Batch<Settle>, LedgerError> {
        self.ensure_unrecovered()?;
        let open = *self.state.open.get(&id).ok_or(LedgerError::NotOpen(id))?;
        let (drafts, settlement) =
            settlement_drafts(id, open.pool, open.reserved, open.settled, Usage::Unknown, Keys::Own)?;
        self.batch(
            &Actor::System,
            drafts,
            Settle {
                token: None,
                settlement,
            },
        )
        .map_err(|(e, _)| e)
    }

    /// Boot, before [`Ledger::recover`]: the release of an open reservation strict mode proves
    /// unsent, without a token. Only on a replayed ledger that has not run its recovery.
    ///
    /// # Errors
    /// `NotReplayed` on a live or recovered ledger, `NotOpen`, `Pending`, or consistency failures.
    pub fn prepare_recovery_release(&mut self, id: ReservationId) -> Result<Batch<Release>, LedgerError> {
        self.ensure_unrecovered()?;
        let open = *self.state.open.get(&id).ok_or(LedgerError::NotOpen(id))?;
        if open.settled.is_some() {
            return Err(LedgerError::Inconsistent(
                "a partly settled reservation is not released",
            ));
        }
        let d = release_draft(id, open.pool, open.reserved, Keys::Own)?;
        self.batch(&Actor::System, vec![d], Release(None)).map_err(|(e, _)| e)
    }

    /// Prepares an allocation (creating the pool on first use): one `budget.entry`.
    ///
    /// # Errors
    /// `Pending`, a reserved key, or consistency failures.
    pub fn prepare_allocate(
        &mut self,
        pool: PoolId,
        amount: NanoUsd,
        principal: &Actor,
        idempotency: IdempotencyKey,
    ) -> Result<Batch<Allocate>, LedgerError> {
        self.ensure_live()?;
        let d = Draft {
            key: caller_key(idempotency)?,
            pool,
            kind: BudgetTxKind::Allocate,
            amount,
            reason: "allocate",
            reservation: None,
            counterparty: None,
            settled: false,
            estimated: false,
        };
        self.batch(principal, vec![d], Allocate).map_err(|(e, _)| e)
    }

    /// Prepares a transfer between pools: a `transfer_out` then its `transfer_in`, two
    /// `budget.entry` records, applied record by record. A transfer whose first half is already
    /// recorded prepares only the second.
    ///
    /// # Errors
    /// `Pending`, `Insufficient` on the source pool, a reserved or conflicting key, or consistency
    /// failures.
    pub fn prepare_transfer(
        &mut self,
        from: PoolId,
        to: PoolId,
        amount: NanoUsd,
        principal: &Actor,
        idempotency: IdempotencyKey,
    ) -> Result<Batch<Transfer>, LedgerError> {
        self.ensure_live()?;
        let idempotency = caller_key(idempotency)?;
        let in_key = transfer_in_key(&idempotency)?;
        // Both keys are checked before the first entry is recorded, so a conflict can never
        // leave money that left one pool without reaching the other.
        if self.state.entry_for(&idempotency).is_none() && self.state.entry_for(&in_key).is_some() {
            return Err(LedgerError::KeyConflict(in_key.as_str().to_owned()));
        }
        let out = Draft {
            key: idempotency,
            pool: from,
            kind: BudgetTxKind::TransferOut,
            amount,
            reason: "transfer",
            reservation: None,
            counterparty: Some(to),
            settled: false,
            estimated: false,
        };
        let incoming = Draft {
            key: in_key,
            pool: to,
            kind: BudgetTxKind::TransferIn,
            amount,
            reason: "transfer",
            reservation: None,
            counterparty: Some(from),
            settled: false,
            estimated: false,
        };
        self.batch(principal, vec![out, incoming], Transfer).map_err(|(e, _)| e)
    }

    /// Prepares a human's repair of a stuck item: only an item recovery left stuck, only by a human
    /// principal (replay refuses a repair entry any other principal signs). Every entry carries
    /// reason `stuck_repair` and its own key. Applying it needs the human's presence, through an
    /// approval channel that is not built yet.
    ///
    /// # Errors
    /// [`LedgerError::NotStuck`] for an item that is not stuck, `Pending`, a repair that does not
    /// fit the item, or consistency failures.
    pub fn prepare_repair(
        &mut self,
        item: &StuckItem,
        repair: Repair,
        principal: &Actor,
    ) -> Result<Batch<Repaired>, LedgerError> {
        self.ensure_no_batch()?;
        if !self.stuck.iter().any(|stuck| stuck.kind == item.kind) {
            return Err(LedgerError::NotStuck);
        }
        let drafts = match (&item.kind, repair) {
            (StuckKind::Reservation(id), Repair::Settle { amount, .. }) => {
                let open = *self.state.open.get(id).ok_or(LedgerError::NotOpen(*id))?;
                if open.settled.is_some_and(|actual| actual != amount) {
                    return Err(LedgerError::Inconsistent(
                        "a partly settled reservation's repair settles at its recorded spend",
                    ));
                }
                settlement_drafts(
                    *id,
                    open.pool,
                    open.reserved,
                    open.settled,
                    Usage::Reported(amount),
                    Keys::Repair,
                )?
                .0
            }
            (StuckKind::Reservation(id), Repair::Release) => {
                let open = *self.state.open.get(id).ok_or(LedgerError::NotOpen(*id))?;
                let remaining = match open.settled {
                    None => open.reserved,
                    Some(actual) if actual < open.reserved => {
                        open.reserved.checked_sub(actual).ok_or(LedgerError::Overflow)?
                    }
                    Some(_) => return Err(LedgerError::Inconsistent("nothing left to release after an overrun")),
                };
                vec![release_draft(*id, open.pool, remaining, Keys::Repair)?]
            }
            (StuckKind::Transfer(out), Repair::CompleteTransfer | Repair::ReturnTransfer) => {
                let pending = *self
                    .state
                    .pending
                    .get(out)
                    .ok_or(LedgerError::Inconsistent("the transfer is not pending"))?;
                let (key, pool, counterparty) = if repair == Repair::CompleteTransfer {
                    (transfer_in_key(out)?, pending.to, pending.from)
                } else {
                    (transfer_return_key(out)?, pending.from, pending.to)
                };
                vec![Draft {
                    key,
                    pool,
                    kind: BudgetTxKind::TransferIn,
                    amount: pending.amount,
                    reason: STUCK_REPAIR,
                    reservation: None,
                    counterparty: Some(counterparty),
                    settled: false,
                    estimated: false,
                }]
            }
            _ => return Err(LedgerError::Inconsistent("the repair does not fit the stuck item")),
        };
        self.batch(principal, drafts, Repaired(item.clone()))
            .map_err(|(e, _)| e)
    }

    /// Records a prepared batch through `sink`, entry by entry, and applies it: the sink-based
    /// path for writes recorded one `budget.entry` at a time. A recording failure poisons.
    fn commit<T: Closes>(&mut self, sink: &mut dyn LedgerSink, mut batch: Batch<T>) -> Result<T::Output, LedgerError> {
        while batch.applied < batch.entries.len() {
            let tx = batch.entries[batch.applied].clone();
            if let Err(e) = sink.record(&tx) {
                self.abandon(batch);
                return Err(LedgerError::Sink(e));
            }
            self.apply_entry(&tx);
            batch.applied += 1;
            if self.poisoned {
                self.abandon(batch);
                return Err(LedgerError::Poisoned);
            }
        }
        Ok(self.apply(batch))
    }

    /// Adds money to a pool (creating it on first use).
    ///
    /// # Errors
    /// Recording or consistency failures.
    pub fn allocate(
        &mut self,
        sink: &mut dyn LedgerSink,
        pool: PoolId,
        amount: NanoUsd,
        principal: &Actor,
        idempotency: IdempotencyKey,
    ) -> Result<(), LedgerError> {
        let batch = self.prepare_allocate(pool, amount, principal, idempotency)?;
        self.commit(sink, batch)
    }

    /// Reserves `amount` before an Operation executes. The hard cap: refused with
    /// [`LedgerError::Insufficient`] if the pool cannot cover it.
    ///
    /// A reservation identifier is single-use: reserving it again is refused with
    /// [`LedgerError::ReservationReused`], so at most one token ever exists per reservation and a
    /// duplicate `Held` token can never release money an `InFlight` one may have spent.
    ///
    /// # Errors
    /// `Insufficient`, `UnknownPool`, `ReservationReused`, recording or consistency failures.
    pub fn reserve(
        &mut self,
        sink: &mut dyn LedgerSink,
        pool: PoolId,
        id: ReservationId,
        amount: NanoUsd,
        principal: &Actor,
    ) -> Result<Reservation<Held>, LedgerError> {
        let batch = self.prepare_reserve(pool, id, amount, principal)?;
        self.commit(sink, batch)
    }

    /// Returns a reservation whose execution never started.
    ///
    /// ```
    /// # use uaos_contracts::{event::Actor, id::{PoolId, ReservationId, TypedId}, money::NanoUsd, budget::IdempotencyKey};
    /// # use uaos_ledger::{Ledger, MemorySink};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let (mut ledger, mut sink) = (Ledger::default(), MemorySink::default());
    /// let pool = PoolId::from_parts(1, [1; 10]);
    /// ledger.allocate(&mut sink, pool, NanoUsd::new(10), &Actor::System, IdempotencyKey::new("fund")?)?;
    /// let held = ledger.reserve(&mut sink, pool, ReservationId::from_parts(1, [2; 10]), NanoUsd::new(5), &Actor::System)?;
    /// ledger.release(&mut sink, held, &Actor::System)?;
    /// # Ok(()) }
    /// ```
    ///
    /// Once execution has begun, the reservation can only be settled; releasing it does not
    /// compile:
    ///
    /// ```compile_fail
    /// # use uaos_contracts::{event::Actor, id::{PoolId, ReservationId, TypedId}, money::NanoUsd, budget::IdempotencyKey};
    /// # use uaos_ledger::{Ledger, MemorySink};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let (mut ledger, mut sink) = (Ledger::default(), MemorySink::default());
    /// let pool = PoolId::from_parts(1, [1; 10]);
    /// ledger.allocate(&mut sink, pool, NanoUsd::new(10), &Actor::System, IdempotencyKey::new("fund")?)?;
    /// let held = ledger.reserve(&mut sink, pool, ReservationId::from_parts(1, [2; 10]), NanoUsd::new(5), &Actor::System)?;
    /// ledger.release(&mut sink, held.begin(), &Actor::System)?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// Recording or consistency failures.
    pub fn release(
        &mut self,
        sink: &mut dyn LedgerSink,
        reservation: Reservation<Held>,
        principal: &Actor,
    ) -> Result<(), CloseError<Held>> {
        let batch = self.prepare_release(reservation, principal)?;
        // From here on the token is in the batch: it can never be released or settled again.
        self.commit(sink, batch).map_err(CloseError::Failed)
    }

    /// Settles a reservation whose execution started: records the spend, then returns the
    /// unused remainder or charges an overrun.
    ///
    /// # Errors
    /// Recording or consistency failures.
    pub fn settle(
        &mut self,
        sink: &mut dyn LedgerSink,
        reservation: Reservation<InFlight>,
        usage: Usage,
        principal: &Actor,
    ) -> Result<Settlement, CloseError<InFlight>> {
        let batch = self.prepare_settle(reservation, usage, principal)?;
        self.commit(sink, batch).map_err(CloseError::Failed)
    }

    /// Moves money between pools: a `TransferOut` then its paired `TransferIn`. If the process
    /// dies in between, [`Ledger::recover`] records the missing half.
    ///
    /// # Errors
    /// `Insufficient` on the source pool, recording or consistency failures.
    pub fn transfer(
        &mut self,
        sink: &mut dyn LedgerSink,
        from: PoolId,
        to: PoolId,
        amount: NanoUsd,
        principal: &Actor,
        idempotency: IdempotencyKey,
    ) -> Result<(), LedgerError> {
        let batch = self.prepare_transfer(from, to, amount, principal, idempotency)?;
        self.commit(sink, batch)
    }

    /// On a ledger rebuilt from the journal, closes what the previous run left open, after boot has
    /// closed each open one-record Operation in its own record: unsettled reservations are settled
    /// at their full reserved amount, marked estimated, and never released; partially settled
    /// reservations get their closing entry; half-recorded transfers are completed. **A reservation
    /// a one-record intent established is never touched**: it closes only in its Operation's
    /// records, so one still open must be a stuck item the plan lists. An item that cannot be
    /// closed is reported in [`Recovery::stuck`] and the others are still processed; the ledger
    /// stays replayed, refusing new work, while the plan or this recovery lists any stuck item.
    /// `RecoveryPlan::default()` is the plan of a journal with no one-record intent.
    ///
    /// Boot-only: in a running process reservations are closed through their tokens, and a
    /// recovery could settle a reservation whose token is still live.
    ///
    /// # Errors
    /// [`LedgerError::NotReplayed`] on a live ledger with open items; `Pending`;
    /// [`LedgerError::Inconsistent`], before anything is recorded, for a one-record reservation
    /// still open that the plan does not list as stuck; recording failures (the ledger is then
    /// poisoned).
    pub fn recover(
        &mut self,
        sink: &mut dyn LedgerSink,
        principal: &Actor,
        plan: &RecoveryPlan,
    ) -> Result<Recovery, LedgerError> {
        self.ensure_no_batch()?;
        let nothing_open = self.state.open.is_empty() && self.state.pending.is_empty();
        if self.phase == Phase::Live && !nothing_open {
            return Err(LedgerError::NotReplayed);
        }
        let unclosed = self
            .state
            .open
            .keys()
            .any(|id| plan.is_one_record(*id) && !plan.lists_stuck(&StuckKind::Reservation(*id)));
        if unclosed {
            return Err(LedgerError::Inconsistent(
                "a one-record Operation is still open: boot closes it in its own record first",
            ));
        }
        let mut report = Recovery::default();
        let open: Vec<_> = self
            .state
            .open
            .iter()
            .filter(|(id, _)| !plan.is_one_record(**id))
            .map(|(id, o)| (*id, *o))
            .collect();
        for (id, o) in open {
            let result = settlement_drafts(id, o.pool, o.reserved, o.settled, Usage::Unknown, Keys::Own)
                .and_then(|(drafts, _)| self.record_now(sink, principal, drafts));
            match result {
                Ok(()) if o.settled.is_some() => report.completed += 1,
                Ok(()) => report.settled_estimated += 1,
                Err(e) => report.stuck_on(StuckKind::Reservation(id), &format!("reservation {id}"), e)?,
            }
        }
        let pending: Vec<_> = self.state.pending.iter().map(|(k, p)| (k.clone(), *p)).collect();
        for (out_key, p) in pending {
            let result = transfer_in_key(&out_key).and_then(|in_key| {
                let d = Draft {
                    key: in_key,
                    pool: p.to,
                    kind: BudgetTxKind::TransferIn,
                    amount: p.amount,
                    reason: "transfer_recovered",
                    reservation: None,
                    counterparty: Some(p.from),
                    settled: false,
                    estimated: false,
                };
                self.record_now(sink, principal, vec![d])
            });
            match result {
                Ok(()) => report.transfers_completed += 1,
                Err(e) => report.stuck_on(
                    StuckKind::Transfer(out_key.clone()),
                    &format!("transfer {}", out_key.as_str()),
                    e,
                )?,
            }
        }
        self.stuck = plan.one_record_stuck().to_vec();
        self.resolves = self
            .stuck
            .iter()
            .filter_map(|item| match item.kind {
                StuckKind::Reservation(id) => plan.operation_of(id).map(|operation| (id, operation)),
                StuckKind::Transfer(_) => None,
            })
            .collect();
        self.stuck.extend(report.stuck_items.iter().cloned());
        self.phase = if self.stuck.is_empty() {
            Phase::Live
        } else {
            Phase::Stuck
        };
        Ok(report)
    }

    /// Prepares `drafts`, records them through `sink` and applies them, in recovery (no batch is
    /// left outstanding).
    fn record_now(
        &mut self,
        sink: &mut dyn LedgerSink,
        principal: &Actor,
        drafts: Vec<Draft>,
    ) -> Result<(), LedgerError> {
        let batch = self.batch(principal, drafts, Recovered).map_err(|(e, _)| e)?;
        self.commit(sink, batch)
    }
}

impl Recovery {
    /// Records a stuck item, or passes on a recording failure, which stops recovery.
    fn stuck_on(&mut self, kind: StuckKind, what: &str, e: LedgerError) -> Result<(), LedgerError> {
        match e {
            LedgerError::Sink(_) | LedgerError::Poisoned => Err(e),
            other => {
                self.stuck.push(format!("{what}: {other}"));
                self.stuck_items.push(StuckItem {
                    kind,
                    reason: ReasonCode::new(other.reason_code()).map_err(LedgerError::Invalid)?,
                });
                Ok(())
            }
        }
    }
}
