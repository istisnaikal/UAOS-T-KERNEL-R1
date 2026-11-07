// SPDX-License-Identifier: Apache-2.0

//! The recovery plan: what boot closes and what stays stuck, from the journal alone (intent
//! contract).
//!
//! [`recovery_plan`] reads the journal, replays its entries, and rehearses boot on the replayed
//! ledger: each open one-record Operation's settlement at the full reservation, in the order its
//! intent was journaled, then [`Ledger::recover`] for what is left. Everything the rehearsal
//! applied is then undone, and it writes nothing.
//! Boot executes the plan; [`stuck_items`] returns the plan's stuck items, so what boot counts
//! and what `status` lists cannot disagree.

use std::collections::BTreeMap;

use uaos_contracts::budget::ReasonCode;
use uaos_contracts::error::ErrorCode;
use uaos_contracts::event::Actor;
use uaos_contracts::id::{OperationId, ReservationId};
use uaos_state::journal::VerifiedRecord;

use crate::inline::{self, OneRecordOperation, Outcome, ReadError};
use crate::ledger::{Ledger, MemorySink, StuckItem, StuckKind};
use crate::state::LedgerError;

/// The reason of a one-record reservation left stuck by an earlier boot whose settlement the ledger
/// would accept now: it still waits for its repair, since its Operation already has its outcome.
pub const AWAITING_REPAIR: &str = "awaiting_repair";

/// An open one-record Operation: an intent and no outcome. Boot closes it in its own
/// `op.indeterminate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenOperation {
    /// The Operation.
    pub operation: OperationId,
    /// The reservation its intent established.
    pub reservation: ReservationId,
    /// The intent's sequence number: boot closes open Operations in this order.
    pub intent_seq: u64,
    /// Whether the journal holds the Operation's `op.executing` (`executing_recorded`).
    pub executing_recorded: bool,
    /// Whether the ledger accepts the settlement: when it does not, boot journals the
    /// `op.indeterminate` without entries and the reservation is a stuck item.
    pub settles: bool,
}

/// What boot closes and what stays stuck. Made only by [`recovery_plan`]; `RecoveryPlan::default()`
/// is the plan of a journal with no one-record intent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryPlan {
    open: Vec<OpenOperation>,
    /// Every one-record reservation, and the Operation whose intent established it.
    one_record: BTreeMap<ReservationId, OperationId>,
    one_record_stuck: Vec<StuckItem>,
    recover_stuck: Vec<StuckItem>,
}

impl RecoveryPlan {
    /// The open one-record Operations, in the order their intents were journaled.
    #[must_use]
    pub fn open(&self) -> &[OpenOperation] {
        &self.open
    }

    /// Whether a one-record intent established `reservation`: recovery never touches it.
    #[must_use]
    pub fn is_one_record(&self, reservation: ReservationId) -> bool {
        self.one_record.contains_key(&reservation)
    }

    /// The Operation whose one-record intent established `reservation`; `None` for a two-record
    /// reservation. A stuck one-record reservation's repair is that Operation's resolution.
    #[must_use]
    pub fn operation_of(&self, reservation: ReservationId) -> Option<OperationId> {
        self.one_record.get(&reservation).copied()
    }

    /// The stuck one-record reservations, in intent order: those an earlier boot left stuck and
    /// those whose settlement this boot's will be refused.
    #[must_use]
    pub fn one_record_stuck(&self) -> &[StuckItem] {
        &self.one_record_stuck
    }

    /// Every stuck item: the one-record reservations, then what [`Ledger::recover`] cannot close
    /// (two-record reservations, then transfers).
    pub fn stuck(&self) -> impl Iterator<Item = &StuckItem> {
        self.one_record_stuck.iter().chain(&self.recover_stuck)
    }

    /// Whether the plan lists `kind` as stuck.
    #[must_use]
    pub fn lists_stuck(&self, kind: &StuckKind) -> bool {
        self.stuck().any(|item| item.kind == *kind)
    }

    /// How many reservations are stuck (`kernel.booted`'s `stuck_reservations`).
    #[must_use]
    pub fn stuck_reservations(&self) -> usize {
        self.stuck()
            .filter(|item| matches!(item.kind, StuckKind::Reservation(_)))
            .count()
    }

    /// How many transfers are stuck (`kernel.booted`'s `stuck_transfers`).
    #[must_use]
    pub fn stuck_transfers(&self) -> usize {
        self.stuck()
            .filter(|item| matches!(item.kind, StuckKind::Transfer(_)))
            .count()
    }
}

/// Why a journal has no recovery plan.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    /// The journal's ledger entries do not read.
    #[error(transparent)]
    Read(#[from] ReadError),
    /// The entries do not replay, or the rehearsal of boot found an inconsistency.
    #[error(transparent)]
    Ledger(#[from] LedgerError),
}

impl PlanError {
    /// The error's code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Read(e) => e.code(),
            Self::Ledger(e) => e.code(),
        }
    }
}

/// The recovery plan of a journal's verified records. Pure: it writes nothing.
///
/// # Errors
/// [`PlanError`] for a journal whose entries do not read or replay; boot refuses it the same way.
pub fn recovery_plan(records: &[VerifiedRecord]) -> Result<RecoveryPlan, PlanError> {
    replay_with_plan(records).map(|(_, plan)| plan)
}

/// The stuck items of a journal's verified records: the plan's, listed on demand. Writes nothing.
///
/// # Errors
/// As [`recovery_plan`].
pub fn stuck_items(records: &[VerifiedRecord]) -> Result<Vec<StuckItem>, PlanError> {
    recovery_plan(records).map(|plan| plan.stuck().cloned().collect())
}

/// The replayed ledger and its recovery plan, from one read of the journal: boot's step 3.
///
/// # Errors
/// As [`recovery_plan`].
pub fn replay_with_plan(records: &[VerifiedRecord]) -> Result<(Ledger, RecoveryPlan), PlanError> {
    let read = inline::read_journal(records)?;
    let mut ledger = Ledger::replay(&read.entries)?;
    // Rehearsed on the replayed ledger itself, which comes back as it was.
    let plan = ledger.rehearse(|rehearsal| rehearse(rehearsal, &read.one_record))?;
    Ok((ledger, plan))
}

/// Boot on `rehearsal`: each open one-record Operation's settlement, in intent order, then
/// `recover`. The plan is what it closed and what it could not.
fn rehearse(rehearsal: &mut Ledger, one_record: &[OneRecordOperation]) -> Result<RecoveryPlan, PlanError> {
    let mut plan = RecoveryPlan {
        one_record: one_record.iter().map(|op| (op.reservation, op.operation)).collect(),
        ..RecoveryPlan::default()
    };
    for op in one_record {
        match op.outcome {
            Outcome::Closed => {}
            // Boot settles it in its `op.indeterminate`, then applies it: the next Operation's
            // settlement is prepared against the state this one leaves.
            Outcome::Pending => {
                let settles = match rehearsal.prepare_recovery_settle(op.reservation) {
                    Ok(batch) => {
                        rehearsal.apply(batch);
                        true
                    }
                    Err(refused) => {
                        plan.one_record_stuck
                            .push(stuck(StuckKind::Reservation(op.reservation), refused.reason_code())?);
                        false
                    }
                };
                plan.open.push(OpenOperation {
                    operation: op.operation,
                    reservation: op.reservation,
                    intent_seq: op.intent_seq,
                    executing_recorded: op.executing_recorded,
                    settles,
                });
            }
            // An earlier boot journaled its `op.indeterminate` without entries: still stuck, with
            // the reason the ledger gives today.
            Outcome::Stuck => {
                let reason = match rehearsal.prepare_recovery_settle(op.reservation) {
                    Ok(batch) => {
                        rehearsal.withdraw(batch);
                        AWAITING_REPAIR
                    }
                    Err(refused) => refused.reason_code(),
                };
                plan.one_record_stuck
                    .push(stuck(StuckKind::Reservation(op.reservation), reason)?);
            }
        }
    }
    let recovery = rehearsal.recover(&mut MemorySink::default(), &Actor::System, &plan)?;
    plan.recover_stuck = recovery.stuck_items;
    Ok(plan)
}

fn stuck(kind: StuckKind, reason: &str) -> Result<StuckItem, LedgerError> {
    Ok(StuckItem {
        kind,
        reason: ReasonCode::new(reason).map_err(LedgerError::Invalid)?,
    })
}
