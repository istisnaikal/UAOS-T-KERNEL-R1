// SPDX-License-Identifier: Apache-2.0

//! The ledger writer: turns budget operations into recorded entries.
//!
//! Every entry is recorded through a [`LedgerSink`] (normally the journal) **before** the
//! in-memory state changes, so a reservation is durable before the Operation it pays for can
//! execute. If recording fails, the ledger refuses further work until it is rebuilt from the
//! journal: the entry may or may not have reached the journal, and guessing would let memory and
//! truth diverge.
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
//! are settled at the full reserved amount, marked `estimated`, never released.
//!
//! Limitation stated plainly: the journal does not yet record *when* execution began, so a replayed
//! ledger cannot tell a held reservation from an in-flight one. That is why recovery never
//! releases. The runtime journals the start of execution in P3.

use std::fmt;
use std::marker::PhantomData;

use uaos_contracts::budget::{BudgetTx, BudgetTxKind, BudgetTxSchema, IdempotencyKey, ReasonCode};
use uaos_contracts::event::Actor;
use uaos_contracts::id::{PoolId, ReservationId};
use uaos_contracts::money::NanoUsd;

use crate::state::{LedgerError, LedgerState, transfer_in_key};

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
    /// Rebuilt from the journal and not yet recovered.
    replayed: bool,
}

/// Suffixes and prefixes the ledger derives keys with. Caller keys may not use them, so a
/// caller can never collide with an entry the ledger writes for itself.
const DERIVED_SUFFIXES: [&str; 5] = [":in", ":reserve", ":release", ":settle", ":overrun"];
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
    Recorded(BudgetTx),
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
            poisoned: false,
            replayed: true,
        })
    }

    /// Whether the ledger was rebuilt and still has to run [`Ledger::recover`].
    #[must_use]
    pub fn needs_recovery(&self) -> bool {
        self.replayed
    }

    /// New work is refused while poisoned, and on a rebuilt ledger until recovery has run: a
    /// replayed ledger may still hold an overrun or a half transfer the cap check must not miss.
    fn ensure_live(&self) -> Result<(), LedgerError> {
        if self.poisoned {
            Err(LedgerError::Poisoned)
        } else if self.replayed {
            Err(LedgerError::RecoveryRequired)
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
                Ok(Prepared::Recorded(previous.clone()))
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

    fn record(&mut self, sink: &mut dyn LedgerSink, principal: &Actor, d: Draft) -> Result<BudgetTx, LedgerError> {
        match self.prepare(principal, d)? {
            Prepared::Recorded(tx) => Ok(tx),
            Prepared::New(tx) => self.commit(sink, tx),
        }
    }

    /// Records a prepared entry, then applies it. A recording failure poisons the ledger.
    fn commit(&mut self, sink: &mut dyn LedgerSink, tx: BudgetTx) -> Result<BudgetTx, LedgerError> {
        if let Err(e) = sink.record(&tx) {
            self.poisoned = true;
            return Err(LedgerError::Sink(e));
        }
        if let Err(e) = self.state.apply(&tx) {
            // Unreachable while `check` and `apply` share one rule set; if they ever diverge,
            // memory no longer matches what was recorded.
            self.poisoned = true;
            return Err(e);
        }
        Ok(tx)
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
        self.record(sink, principal, d).map(|_| ())
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
        let tx = self.record(sink, principal, d)?;
        Ok(Reservation {
            id,
            pool: tx.pool_id,
            amount: tx.amount,
            state: PhantomData,
        })
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
    #[allow(
        clippy::needless_pass_by_value,
        reason = "taking the token by value is the point: the caller cannot use it again"
    )]
    pub fn release(
        &mut self,
        sink: &mut dyn LedgerSink,
        reservation: Reservation<Held>,
        principal: &Actor,
    ) -> Result<(), CloseError<Held>> {
        let prepared = self.ensure_live().and_then(|()| {
            let id = reservation.id;
            let d = Draft {
                key: key(format!("{id}:release"))?,
                pool: reservation.pool,
                kind: BudgetTxKind::Release,
                amount: reservation.amount,
                reason: "release",
                reservation: Some(id),
                counterparty: None,
                settled: true,
                estimated: false,
            };
            self.prepare(principal, d)
        });
        let prepared = match prepared {
            Ok(p) => p,
            Err(error) => return Err(CloseError::Rejected { error, reservation }),
        };
        // From here on the token is consumed: it can never be released or settled again.
        drop(reservation);
        match prepared {
            Prepared::Recorded(_) => Ok(()),
            Prepared::New(tx) => self.commit(sink, tx).map(|_| ()).map_err(CloseError::Failed),
        }
    }

    /// Settles a reservation whose execution started: records the spend, then returns the
    /// unused remainder or charges an overrun.
    ///
    /// # Errors
    /// Recording or consistency failures.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "taking the token by value is the point: the caller cannot use it again"
    )]
    pub fn settle(
        &mut self,
        sink: &mut dyn LedgerSink,
        reservation: Reservation<InFlight>,
        usage: Usage,
        principal: &Actor,
    ) -> Result<Settlement, CloseError<InFlight>> {
        // Everything that can refuse the first entry is checked before the token is consumed.
        let precheck = self.ensure_live().and_then(|()| {
            let (actual, estimated) = actual_spend(None, usage, reservation.amount);
            let d = settle_draft(reservation.id, reservation.pool, reservation.amount, actual, estimated)?;
            self.prepare(principal, d).map(|_| ())
        });
        if let Err(error) = precheck {
            return Err(CloseError::Rejected { error, reservation });
        }
        let Reservation { id, pool, amount, .. } = reservation;
        self.settle_open(sink, id, pool, amount, None, usage, principal)
            .map_err(CloseError::Failed)
    }

    #[allow(clippy::too_many_arguments, reason = "internal: one call site per recovery path")]
    fn settle_open(
        &mut self,
        sink: &mut dyn LedgerSink,
        id: ReservationId,
        pool: PoolId,
        reserved: NanoUsd,
        already_settled: Option<NanoUsd>,
        usage: Usage,
        principal: &Actor,
    ) -> Result<Settlement, LedgerError> {
        let (actual, estimated) = actual_spend(already_settled, usage, reserved);
        if already_settled.is_none() {
            let d = settle_draft(id, pool, reserved, actual, estimated)?;
            self.record(sink, principal, d)?;
        }
        let mut out = Settlement {
            spent: actual,
            released: NanoUsd::ZERO,
            overrun: NanoUsd::ZERO,
            estimated,
        };
        if actual < reserved {
            let remainder = reserved.checked_sub(actual).ok_or(LedgerError::Overflow)?;
            let d = Draft {
                key: key(format!("{id}:release"))?,
                pool,
                kind: BudgetTxKind::Release,
                amount: remainder,
                reason: "release_remainder",
                reservation: Some(id),
                counterparty: None,
                settled: true,
                estimated: false,
            };
            self.record(sink, principal, d)?;
            out.released = remainder;
        } else if actual > reserved {
            let overrun = actual.checked_sub(reserved).ok_or(LedgerError::Overflow)?;
            let d = Draft {
                key: key(format!("{id}:overrun"))?,
                pool,
                kind: BudgetTxKind::Adjust,
                amount: NanoUsd::ZERO.checked_sub(overrun).ok_or(LedgerError::Overflow)?,
                reason: "overrun",
                reservation: Some(id),
                counterparty: None,
                settled: true,
                estimated: false,
            };
            self.record(sink, principal, d)?;
            out.overrun = overrun;
        }
        Ok(out)
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
        self.record(sink, principal, out)?;
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
        self.record(sink, principal, incoming).map(|_| ())
    }

    /// On a ledger rebuilt from the journal, closes everything the previous run left open:
    /// unsettled reservations are settled at their full reserved amount, marked estimated, and
    /// never released; partially settled reservations get their closing entry; half-recorded
    /// transfers are completed. An item that cannot be closed is reported in [`Recovery::stuck`]
    /// and the others are still processed; the ledger then keeps refusing new work.
    ///
    /// Boot-only: in a running process reservations are closed through their tokens, and a
    /// recovery could settle a reservation whose token is still live.
    ///
    /// # Errors
    /// [`LedgerError::NotReplayed`] on a live ledger with open items; recording failures (the
    /// ledger is then poisoned).
    pub fn recover(&mut self, sink: &mut dyn LedgerSink, principal: &Actor) -> Result<Recovery, LedgerError> {
        if self.poisoned {
            return Err(LedgerError::Poisoned);
        }
        let nothing_open = self.state.open.is_empty() && self.state.pending.is_empty();
        if !self.replayed && !nothing_open {
            return Err(LedgerError::NotReplayed);
        }
        let mut report = Recovery::default();
        let mut stuck = |what: String, e: LedgerError| -> Result<(), LedgerError> {
            match e {
                LedgerError::Sink(_) | LedgerError::Poisoned => Err(e),
                other => {
                    report.stuck.push(format!("{what}: {other}"));
                    Ok(())
                }
            }
        };
        let open: Vec<_> = self.state.open.iter().map(|(id, o)| (*id, *o)).collect();
        for (id, o) in open {
            match self.settle_open(sink, id, o.pool, o.reserved, o.settled, Usage::Unknown, principal) {
                Ok(_) if o.settled.is_some() => report.completed += 1,
                Ok(_) => report.settled_estimated += 1,
                Err(e) => stuck(format!("reservation {id}"), e)?,
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
                self.record(sink, principal, d)
            });
            match result {
                Ok(_) => report.transfers_completed += 1,
                Err(e) => stuck(format!("transfer {}", out_key.as_str()), e)?,
            }
        }
        if report.stuck.is_empty() {
            self.replayed = false;
        }
        Ok(report)
    }
}
