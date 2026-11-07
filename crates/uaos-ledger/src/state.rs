// SPDX-License-Identifier: Apache-2.0

//! The ledger as a pure state machine: entries in, balances out.
//!
//! Every entry is checked against the current state before it applies: the pool balance it was
//! computed from, the reservation lifecycle, transfer pairing and idempotency. Replaying a
//! journal therefore either reproduces the exact state or reports exactly where the history is
//! inconsistent; it never "repairs" silently.
//!
//! Reservation lifecycle (one reservation, at most three entries):
//!
//! ```text
//! Reserve(R)                       available -= R          (refused if available < R: hard cap)
//! ├─ Release(R, settled)           available += R          (only before execution started)
//! └─ Settle(A, settled = A == R)   spent += A
//!    ├─ A < R → Release(R - A, settled)   available += R - A
//!    └─ A > R → Adjust(-(A - R), settled) available -= A - R   (overrun: S1, recorded truthfully)
//! ```

use std::collections::{BTreeMap, BTreeSet};

use uaos_contracts::budget::{BudgetTx, BudgetTxError, BudgetTxKind, IdempotencyKey};
use uaos_contracts::event::Actor;
use uaos_contracts::id::{PoolId, ReservationId};
use uaos_contracts::money::NanoUsd;

use crate::inline::STUCK_REPAIR;

/// Balances of one pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PoolState {
    /// Money that can still be reserved.
    pub available: NanoUsd,
    /// Money held by open reservations.
    pub held: NanoUsd,
    /// Money recorded as spent.
    pub spent: NanoUsd,
}

/// An open reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OpenReservation {
    pub(crate) pool: PoolId,
    pub(crate) reserved: NanoUsd,
    /// Actual spend recorded by a `Settle` that still awaits its closing entry.
    pub(crate) settled: Option<NanoUsd>,
}

/// A transfer whose `TransferOut` is recorded but whose `TransferIn` is not (yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingTransfer {
    pub(crate) from: PoolId,
    pub(crate) to: PoolId,
    pub(crate) amount: NanoUsd,
}

/// Why an entry cannot apply.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    /// The pool cannot cover the amount: the hard cap holds.
    #[error("pool {pool} has {available} nUSD available, {requested} requested")]
    Insufficient {
        /// Pool.
        pool: PoolId,
        /// Available amount.
        available: NanoUsd,
        /// Requested amount.
        requested: NanoUsd,
    },
    /// The pool has never been allocated money.
    #[error("unknown pool {0}")]
    UnknownPool(PoolId),
    /// The reservation is not open (never existed, or already closed).
    #[error("reservation {0} is not open")]
    NotOpen(ReservationId),
    /// A reservation identifier was used twice.
    #[error("reservation {0} already exists")]
    ReservationReused(ReservationId),
    /// An idempotency key was reused for a different entry.
    #[error("idempotency key {0:?} was already used for a different entry")]
    KeyConflict(String),
    /// A caller-supplied idempotency key uses a form the ledger derives for itself.
    #[error(
        "idempotency key {0:?} uses a reserved form (rsv_… or a :in, :return, :reserve, :release, :settle, :overrun, :repair_release, :repair_settle, :repair_overrun suffix)"
    )]
    KeyReserved(String),
    /// The ledger was rebuilt from the journal and must recover before it accepts new work.
    #[error("the ledger must run recovery before it accepts new work")]
    RecoveryRequired,
    /// Recovery runs once, on a ledger rebuilt from the journal. In a running process,
    /// reservations are closed through their tokens.
    #[error("recovery runs only on a ledger rebuilt from the journal")]
    NotReplayed,
    /// The entry was computed from a different balance than the pool holds.
    #[error("entry balance_before does not match the pool's available balance")]
    BalanceMismatch,
    /// The entry is not internally consistent.
    #[error("invalid entry: {0}")]
    Invalid(#[from] BudgetTxError),
    /// The entry does not fit the reservation or transfer it refers to.
    #[error("entry does not fit the ledger state: {0}")]
    Inconsistent(&'static str),
    /// Arithmetic overflow.
    #[error("amount overflow")]
    Overflow,
    /// Recording the entry failed; the in-memory ledger must be rebuilt from the journal.
    #[error("recording failed ({0}); the ledger must be rebuilt from the journal")]
    Sink(String),
    /// A previous recording failed; operations are refused until the ledger is rebuilt.
    #[error("the ledger is poisoned by an earlier recording failure; rebuild it from the journal")]
    Poisoned,
    /// A batch is outstanding: one write at a time. An ordering defect in the caller.
    #[error("a batch is outstanding; apply, withdraw or abandon it first")]
    Pending,
    /// A repair names an item recovery did not leave stuck.
    #[error("the item is not stuck")]
    NotStuck,
}

impl LedgerError {
    /// Registered error code.
    #[must_use]
    pub fn code(&self) -> uaos_contracts::error::ErrorCode {
        use uaos_contracts::error::codes;
        match self {
            Self::Insufficient { .. } => codes::BUDGET_HARD_STOP,
            Self::Sink(_) | Self::Poisoned => codes::JOURNAL_WRITE_FAILED,
            Self::KeyConflict(_) | Self::KeyReserved(_) => codes::BUDGET_KEY_CONFLICT,
            Self::RecoveryRequired => codes::BUDGET_RECOVERY_REQUIRED,
            Self::UnknownPool(_)
            | Self::NotOpen(_)
            | Self::ReservationReused(_)
            | Self::BalanceMismatch
            | Self::Invalid(_)
            | Self::Inconsistent(_)
            | Self::Overflow
            | Self::NotReplayed
            | Self::Pending
            | Self::NotStuck => codes::BUDGET_LEDGER_INCONSISTENT,
        }
    }

    /// A reason code for a stuck item: why recovery could not close it. Never free text, never an
    /// amount or an id.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Insufficient { .. } => "insufficient",
            Self::UnknownPool(_) => "unknown_pool",
            Self::NotOpen(_) => "not_open",
            Self::ReservationReused(_) => "reservation_reused",
            Self::KeyConflict(_) => "key_conflict",
            Self::KeyReserved(_) => "key_reserved",
            Self::BalanceMismatch => "balance_mismatch",
            Self::Invalid(_) => "invalid_entry",
            Self::Inconsistent(_) => "inconsistent",
            Self::Overflow => "overflow",
            Self::RecoveryRequired | Self::NotReplayed | Self::Pending | Self::NotStuck => "ledger_state",
            Self::Sink(_) | Self::Poisoned => "journal",
        }
    }
}

/// What [`LedgerState::apply_undoable`] changed, to put back with [`LedgerState::undo`]. The
/// ledger prepares a transition's entries by applying them one after another and undoing them,
/// so each entry is computed from the state the one before leaves, and nothing stays changed.
#[derive(Debug)]
pub(crate) struct Undo {
    key: IdempotencyKey,
    pool_id: PoolId,
    pool_before: Option<PoolState>,
    commit: UndoCommit,
}

#[derive(Debug)]
enum UndoCommit {
    None,
    /// The reservation's previous entry in `open`, if any.
    Open(ReservationId, Option<OpenReservation>),
    /// The reservation removed from `open`, and whether `closed` already held it.
    Close(ReservationId, Option<OpenReservation>, bool),
    Pending(IdempotencyKey),
    Unpend(IdempotencyKey, PendingTransfer),
}

fn add(a: NanoUsd, b: NanoUsd) -> Result<NanoUsd, LedgerError> {
    a.checked_add(b).ok_or(LedgerError::Overflow)
}

fn sub(a: NanoUsd, b: NanoUsd) -> Result<NanoUsd, LedgerError> {
    a.checked_sub(b).ok_or(LedgerError::Overflow)
}

/// The complete ledger state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LedgerState {
    pools: BTreeMap<PoolId, PoolState>,
    pub(crate) open: BTreeMap<ReservationId, OpenReservation>,
    closed: BTreeSet<ReservationId>,
    pub(crate) pending: BTreeMap<IdempotencyKey, PendingTransfer>,
    applied: BTreeMap<IdempotencyKey, BudgetTx>,
}

impl LedgerState {
    /// Balances of a pool.
    #[must_use]
    pub fn pool(&self, id: PoolId) -> Option<PoolState> {
        self.pools.get(&id).copied()
    }

    /// Every pool and its balances.
    pub fn pools(&self) -> impl Iterator<Item = (PoolId, PoolState)> + '_ {
        self.pools.iter().map(|(k, v)| (*k, *v))
    }

    /// Number of open reservations.
    #[must_use]
    pub fn open_reservations(&self) -> usize {
        self.open.len()
    }

    /// Whether `id` is reserved and not closed.
    #[must_use]
    pub fn is_open(&self, id: ReservationId) -> bool {
        self.open.contains_key(&id)
    }

    /// Whether `id` was ever reserved (open or closed).
    pub(crate) fn knows_reservation(&self, id: ReservationId) -> bool {
        self.open.contains_key(&id) || self.closed.contains(&id)
    }

    /// Number of transfers whose second half is not recorded.
    #[must_use]
    pub fn pending_transfers(&self) -> usize {
        self.pending.len()
    }

    /// Money already spent beyond reservations in `pool` whose closing overrun entry is not
    /// recorded yet. It counts against the cap: a new hold may not use it.
    fn owed(&self, pool: PoolId) -> Result<NanoUsd, LedgerError> {
        self.open
            .values()
            .filter(|o| o.pool == pool)
            .try_fold(NanoUsd::ZERO, |acc, o| match o.settled {
                Some(actual) if actual > o.reserved => add(acc, sub(actual, o.reserved)?),
                _ => Ok(acc),
            })
    }

    /// The cap check for entries that take money out of `available`.
    fn ensure_affordable(&self, pool_id: PoolId, pool: &PoolState, amount: NanoUsd) -> Result<(), LedgerError> {
        let usable = sub(pool.available, self.owed(pool_id)?)?;
        if usable < amount {
            return Err(LedgerError::Insufficient {
                pool: pool_id,
                available: usable,
                requested: amount,
            });
        }
        Ok(())
    }

    /// The entry previously recorded under `key`, if any.
    #[must_use]
    pub fn entry_for(&self, key: &IdempotencyKey) -> Option<&BudgetTx> {
        self.applied.get(key)
    }

    /// Checks whether `tx` may apply, without changing anything.
    ///
    /// # Errors
    /// The first rule `tx` breaks.
    pub fn check(&self, tx: &BudgetTx) -> Result<(), LedgerError> {
        if let Some(previous) = self.applied.get(&tx.idempotency_key) {
            return if previous == tx {
                Ok(())
            } else {
                Err(LedgerError::KeyConflict(tx.idempotency_key.as_str().to_owned()))
            };
        }
        self.validate_entry(tx)?;
        let (pool, _commit) = self.plan(tx)?;
        if pool.available == tx.balance_after {
            Ok(())
        } else {
            Err(LedgerError::Inconsistent(
                "balance_after does not match the applied effect",
            ))
        }
    }

    /// Applies one entry. A replay of an identical entry under the same idempotency key is a
    /// no-op; any other reuse of the key is an error.
    ///
    /// Check-then-commit: every rule is evaluated against local copies first, so a rejected
    /// entry leaves the state untouched without copying the whole ledger.
    ///
    /// # Errors
    /// The first rule the entry breaks; the state is unchanged on error.
    pub fn apply(&mut self, tx: &BudgetTx) -> Result<(), LedgerError> {
        self.apply_keeping(tx, false).map(|_| ())
    }

    /// [`Self::apply`], returning what to put back to undo it (`None` for an idempotent no-op).
    pub(crate) fn apply_undoable(&mut self, tx: &BudgetTx) -> Result<Option<Undo>, LedgerError> {
        self.apply_keeping(tx, true)
    }

    /// Applies `tx`; with `keep`, returns what to put back to undo it. Replay keeps nothing.
    fn apply_keeping(&mut self, tx: &BudgetTx, keep: bool) -> Result<Option<Undo>, LedgerError> {
        if let Some(previous) = self.applied.get(&tx.idempotency_key) {
            return if previous == tx {
                Ok(None)
            } else {
                Err(LedgerError::KeyConflict(tx.idempotency_key.as_str().to_owned()))
            };
        }
        self.validate_entry(tx)?;
        let (pool, commit) = self.plan(tx)?;
        if pool.available != tx.balance_after {
            return Err(LedgerError::Inconsistent(
                "balance_after does not match the applied effect",
            ));
        }
        let pool_before = self.pools.insert(tx.pool_id, pool);
        let undo_commit = match commit {
            Commit::None => UndoCommit::None,
            Commit::Open(id, open) => UndoCommit::Open(id, self.open.insert(id, open)),
            Commit::Close(id) => {
                let removed = self.open.remove(&id);
                let known = !self.closed.insert(id);
                UndoCommit::Close(id, removed, known)
            }
            Commit::Pending(key, pending) => {
                self.pending.insert(key.clone(), pending);
                UndoCommit::Pending(key)
            }
            // `plan` found the pending transfer, so it is there; nothing after the pool's change
            // may fail.
            Commit::Unpend(key) => match self.pending.remove(&key) {
                Some(removed) => UndoCommit::Unpend(key, removed),
                None => UndoCommit::None,
            },
        };
        self.applied.insert(tx.idempotency_key.clone(), tx.clone());
        Ok(keep.then(|| Undo {
            key: tx.idempotency_key.clone(),
            pool_id: tx.pool_id,
            pool_before,
            commit: undo_commit,
        }))
    }

    /// Puts back what one [`Self::apply_undoable`] changed. Undo in reverse order of applying.
    pub(crate) fn undo(&mut self, undo: Undo) {
        self.applied.remove(&undo.key);
        match undo.commit {
            UndoCommit::None => {}
            UndoCommit::Open(id, previous) => match previous {
                Some(open) => {
                    self.open.insert(id, open);
                }
                None => {
                    self.open.remove(&id);
                }
            },
            UndoCommit::Close(id, removed, known) => {
                if let Some(open) = removed {
                    self.open.insert(id, open);
                }
                if !known {
                    self.closed.remove(&id);
                }
            }
            UndoCommit::Pending(key) => {
                self.pending.remove(&key);
            }
            UndoCommit::Unpend(key, pending) => {
                self.pending.insert(key, pending);
            }
        }
        match undo.pool_before {
            Some(pool) => {
                self.pools.insert(undo.pool_id, pool);
            }
            None => {
                self.pools.remove(&undo.pool_id);
            }
        }
    }

    /// The contract's per-entry rules. A hold that would leave the balance negative is reported
    /// as the ledger reports its cap ([`LedgerError::Insufficient`], with the usable balance).
    fn validate_entry(&self, tx: &BudgetTx) -> Result<(), LedgerError> {
        if tx.reason_code.as_str() == STUCK_REPAIR && tx.principal != Actor::Human {
            return Err(LedgerError::Inconsistent("a repair's entries need a human principal"));
        }
        match tx.validate() {
            Err(BudgetTxError::CapExceeded(kind)) => {
                self.plan(tx)?;
                Err(LedgerError::Invalid(BudgetTxError::CapExceeded(kind)))
            }
            other => other.map_err(LedgerError::Invalid),
        }
    }

    /// Computes the pool's new balances and the bookkeeping change, without mutating anything.
    #[allow(
        clippy::too_many_lines,
        reason = "one arm per entry kind keeps every money rule in a single auditable place"
    )]
    fn plan(&self, tx: &BudgetTx) -> Result<(PoolState, Commit), LedgerError> {
        use BudgetTxKind as K;
        // Only an allocation creates a pool; a transfer cannot conjure one into existence.
        if tx.kind != K::Allocate && !self.pools.contains_key(&tx.pool_id) {
            return Err(LedgerError::UnknownPool(tx.pool_id));
        }
        let mut pool = self.pools.get(&tx.pool_id).copied().unwrap_or_default();
        if tx.balance_before != pool.available {
            return Err(LedgerError::BalanceMismatch);
        }
        let amount = tx.amount;
        let reservation = || {
            tx.reservation_id
                .ok_or(LedgerError::Inconsistent("entry without reservation"))
        };
        let commit = match tx.kind {
            K::Allocate => {
                pool.available = add(pool.available, amount)?;
                Commit::None
            }
            // Nothing produces refunds yet. Accepting them on replay would let a crafted journal
            // create money without an audit trail; they arrive with their producer.
            K::Refund => return Err(LedgerError::Inconsistent("refunds have no producer yet")),
            K::Reserve => {
                let id = reservation()?;
                if self.open.contains_key(&id) || self.closed.contains(&id) {
                    return Err(LedgerError::ReservationReused(id));
                }
                self.ensure_affordable(tx.pool_id, &pool, amount)?;
                pool.available = sub(pool.available, amount)?;
                pool.held = add(pool.held, amount)?;
                Commit::Open(
                    id,
                    OpenReservation {
                        pool: tx.pool_id,
                        reserved: amount,
                        settled: None,
                    },
                )
            }
            K::Settle => {
                let id = reservation()?;
                let open = *self.open.get(&id).ok_or(LedgerError::NotOpen(id))?;
                if open.pool != tx.pool_id || open.settled.is_some() {
                    return Err(LedgerError::Inconsistent("settle does not match its reservation"));
                }
                if tx.settled != (amount == open.reserved) {
                    return Err(LedgerError::Inconsistent(
                        "settle closes the reservation exactly when actual equals reserved",
                    ));
                }
                pool.spent = add(pool.spent, amount)?;
                pool.held = sub(pool.held, amount.min(open.reserved))?;
                if tx.settled {
                    Commit::Close(id)
                } else {
                    Commit::Open(
                        id,
                        OpenReservation {
                            settled: Some(amount),
                            ..open
                        },
                    )
                }
            }
            K::Release => {
                let id = reservation()?;
                let open = *self.open.get(&id).ok_or(LedgerError::NotOpen(id))?;
                let remaining = match open.settled {
                    None => open.reserved,
                    Some(actual) if actual < open.reserved => sub(open.reserved, actual)?,
                    Some(_) => return Err(LedgerError::Inconsistent("nothing left to release after an overrun")),
                };
                if open.pool != tx.pool_id || amount != remaining || !tx.settled {
                    return Err(LedgerError::Inconsistent(
                        "release must return exactly the remaining hold and close",
                    ));
                }
                pool.available = add(pool.available, amount)?;
                pool.held = sub(pool.held, amount)?;
                Commit::Close(id)
            }
            K::Adjust => {
                let commit = if let Some(id) = tx.reservation_id {
                    let open = *self.open.get(&id).ok_or(LedgerError::NotOpen(id))?;
                    let overrun = match open.settled {
                        Some(actual) if actual > open.reserved => sub(actual, open.reserved)?,
                        _ => {
                            return Err(LedgerError::Inconsistent(
                                "adjust on a reservation must record an overrun",
                            ));
                        }
                    };
                    if open.pool != tx.pool_id || amount != sub(NanoUsd::ZERO, overrun)? || !tx.settled {
                        return Err(LedgerError::Inconsistent(
                            "overrun adjust must charge exactly the excess and close",
                        ));
                    }
                    Commit::Close(id)
                } else {
                    // Same as refunds: no producer yet, so replay refuses it.
                    return Err(LedgerError::Inconsistent(
                        "adjustments outside an overrun have no producer yet",
                    ));
                };
                pool.available = add(pool.available, amount)?;
                commit
            }
            K::TransferOut => {
                let to = tx
                    .counterparty_pool
                    .ok_or(LedgerError::Inconsistent("transfer without counterparty"))?;
                if to == tx.pool_id {
                    return Err(LedgerError::Inconsistent("transfer to the same pool"));
                }
                if !self.pools.contains_key(&to) {
                    return Err(LedgerError::UnknownPool(to));
                }
                self.ensure_affordable(tx.pool_id, &pool, amount)?;
                pool.available = sub(pool.available, amount)?;
                Commit::Pending(
                    tx.idempotency_key.clone(),
                    PendingTransfer {
                        from: tx.pool_id,
                        to,
                        amount,
                    },
                )
            }
            K::TransferIn => {
                let counterparty = tx
                    .counterparty_pool
                    .ok_or(LedgerError::Inconsistent("transfer without counterparty"))?;
                let (out_key, returned) = if let Some(out) = transfer_out_key(&tx.idempotency_key) {
                    (out, false)
                } else if let Some(out) = returned_out_key(&tx.idempotency_key) {
                    (out, true)
                } else {
                    return Err(LedgerError::Inconsistent(
                        "transfer_in key must be <transfer_out key>:in or :return",
                    ));
                };
                let pending = self
                    .pending
                    .get(&out_key)
                    .copied()
                    .ok_or(LedgerError::Inconsistent("transfer_in without transfer_out"))?;
                // `:in` completes the transfer into its destination; `:return`, a stuck transfer's
                // repair, closes it back into its source.
                let (into, from) = if returned {
                    (pending.from, pending.to)
                } else {
                    (pending.to, pending.from)
                };
                if returned && tx.reason_code.as_str() != STUCK_REPAIR {
                    return Err(LedgerError::Inconsistent("only a repair returns a transfer"));
                }
                if from != counterparty || into != tx.pool_id || pending.amount != amount {
                    return Err(LedgerError::Inconsistent("transfer_in does not match its transfer_out"));
                }
                pool.available = add(pool.available, amount)?;
                Commit::Unpend(out_key)
            }
        };
        Ok((pool, commit))
    }
}

/// The bookkeeping change an entry makes besides pool balances.
enum Commit {
    None,
    Open(ReservationId, OpenReservation),
    Close(ReservationId),
    Pending(IdempotencyKey, PendingTransfer),
    Unpend(IdempotencyKey),
}

/// Idempotency key of the `TransferIn` paired with a `TransferOut` key.
pub(crate) fn transfer_in_key(out: &IdempotencyKey) -> Result<IdempotencyKey, LedgerError> {
    IdempotencyKey::new(format!("{}:in", out.as_str())).map_err(LedgerError::Invalid)
}

fn transfer_out_key(in_key: &IdempotencyKey) -> Option<IdempotencyKey> {
    in_key
        .as_str()
        .strip_suffix(":in")
        .and_then(|k| IdempotencyKey::new(k).ok())
}

/// Idempotency key of the `TransferIn` that returns a stuck transfer to its source.
pub(crate) fn transfer_return_key(out: &IdempotencyKey) -> Result<IdempotencyKey, LedgerError> {
    IdempotencyKey::new(format!("{}:return", out.as_str())).map_err(LedgerError::Invalid)
}

fn returned_out_key(key: &IdempotencyKey) -> Option<IdempotencyKey> {
    key.as_str()
        .strip_suffix(":return")
        .and_then(|k| IdempotencyKey::new(k).ok())
}
