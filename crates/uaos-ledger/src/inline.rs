// SPDX-License-Identifier: Apache-2.0

//! The compact ledger delta an Operation's record carries, and the reader of a journal's ledger
//! entries (intent contract).
//!
//! Every Operation transition that moves money is one record: its entries travel inline, under the
//! payload's `ledger` field, as a [`LedgerDelta`]. [`compact`] makes a delta from the entries the
//! ledger prepared, and refuses entries its expansion would not reproduce exactly; [`expand`] turns
//! a delta back into `uaos.budget_tx/1` entries; [`read_entries`] reads every ledger entry of a
//! journal. It checks each record against the contract's rules first (the record pass), and returns
//! the entries in journal order, and within a record in entry order (the entry pass). Nothing here
//! writes: a refusal leaves the journal as it is.

use std::collections::BTreeMap;

use serde::Deserialize as _;
use serde_json::Value;
use uaos_contracts::budget::{BudgetTx, BudgetTxKind, BudgetTxSchema, IdempotencyKey};
pub use uaos_contracts::budget::{DeltaEntry, LEDGER_DELTA_VERSION, LedgerDelta};
use uaos_contracts::error::{ErrorCode, codes};
use uaos_contracts::event::{Actor, EventEnvelope, EventType, types};
use uaos_contracts::id::{OperationId, PoolId, ReservationId};
use uaos_contracts::money::NanoUsd;
use uaos_contracts::operation::{Operation, OperationKind, OperationState, Transition};
use uaos_state::journal::VerifiedRecord;

/// The inline payload field that carries a [`LedgerDelta`].
pub const LEDGER_FIELD: &str = "ledger";

/// The reason every entry of a stuck item's repair carries.
pub const STUCK_REPAIR: &str = "stuck_repair";

/// Why [`compact`] refused. Nothing was journaled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CompactError {
    /// A delta holds one or two entries.
    #[error("a ledger delta holds one or two entries")]
    Count,
    /// An entry of a kind an Operation's record does not carry (`allocate`, a transfer, a refund).
    #[error("an entry's kind does not belong in an Operation's record")]
    Kind,
    /// The entries do not name one pool and one reservation.
    #[error("the entries do not share one pool and one reservation")]
    Binding,
    /// Expanding the delta would not give back the entries exactly: a field the delta leaves out
    /// does not follow the record (its principal, a session, a key the ledger did not derive).
    #[error("expanding the delta would not reproduce the entries exactly")]
    NotReproducible,
}

/// Why [`expand`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExpandError {
    /// An entry of a kind an Operation's record does not carry.
    #[error("an entry's kind does not belong in an Operation's record")]
    Kind,
    /// The derived idempotency key is not a valid key.
    #[error("the entry's derived key is not a valid key")]
    Key,
}

/// Makes the delta for `entries`, the ledger's entries for one Operation transition, journaled in a
/// record whose actor is `actor`.
///
/// # Errors
/// [`CompactError`] if the entries cannot travel as a delta that expands back to them exactly.
pub fn compact(entries: &[BudgetTx], actor: &Actor) -> Result<LedgerDelta, CompactError> {
    let [first, ..] = entries else {
        return Err(CompactError::Count);
    };
    if entries.len() > 2 {
        return Err(CompactError::Count);
    }
    let reservation = first.reservation_id.ok_or(CompactError::Binding)?;
    let pool = first.pool_id;
    let mut compacted = Vec::with_capacity(entries.len());
    for tx in entries {
        if tx.pool_id != pool || tx.reservation_id != Some(reservation) {
            return Err(CompactError::Binding);
        }
        if !carried(tx.kind) {
            return Err(CompactError::Kind);
        }
        compacted.push(DeltaEntry {
            kind: tx.kind,
            amount: tx.amount,
            before: tx.balance_before,
            after: tx.balance_after,
            reason: tx.reason_code.clone(),
            settled: tx.settled,
            estimated: tx.estimated,
        });
    }
    let delta = LedgerDelta {
        v: LEDGER_DELTA_VERSION,
        pool,
        reservation,
        entries: compacted,
    };
    match expand(&delta, actor) {
        Ok(expanded) if expanded == entries => Ok(delta),
        _ => Err(CompactError::NotReproducible),
    }
}

/// The `uaos.budget_tx/1` entries a delta stands for, in a record whose actor is `actor` ('s
/// table).
///
/// # Errors
/// [`ExpandError`] for an entry kind an Operation's record does not carry, or a key that cannot be
/// derived.
pub fn expand(delta: &LedgerDelta, actor: &Actor) -> Result<Vec<BudgetTx>, ExpandError> {
    delta
        .entries
        .iter()
        .map(|entry| {
            let suffix = derived_suffix(entry).ok_or(ExpandError::Kind)?;
            let key = IdempotencyKey::new(format!("{}:{suffix}", delta.reservation)).map_err(|_| ExpandError::Key)?;
            Ok(BudgetTx {
                schema: BudgetTxSchema::V1,
                idempotency_key: key,
                pool_id: delta.pool,
                principal: actor.clone(),
                session_id: None,
                kind: entry.kind,
                amount: entry.amount,
                balance_before: entry.before,
                balance_after: entry.after,
                reason_code: entry.reason.clone(),
                related_event: None,
                reservation_id: Some(delta.reservation),
                counterparty_pool: None,
                settled: entry.settled,
                estimated: entry.estimated,
            })
        })
        .collect()
}

/// Whether an Operation's record may carry an entry of this kind.
const fn carried(kind: BudgetTxKind) -> bool {
    matches!(
        kind,
        BudgetTxKind::Reserve | BudgetTxKind::Settle | BudgetTxKind::Release | BudgetTxKind::Adjust
    )
}

/// The ledger's derived key suffix for an entry: the ledger's own (`reserve`, `settle`, `release`,
/// `overrun`), or a repair's (`repair_settle`, `repair_release`, `repair_overrun`).
fn derived_suffix(entry: &DeltaEntry) -> Option<&'static str> {
    let repair = entry.reason.as_str() == STUCK_REPAIR;
    Some(match (entry.kind, repair) {
        (BudgetTxKind::Reserve, false) => "reserve",
        (BudgetTxKind::Settle, false) => "settle",
        (BudgetTxKind::Release, false) => "release",
        (BudgetTxKind::Adjust, false) => "overrun",
        (BudgetTxKind::Settle, true) => "repair_settle",
        (BudgetTxKind::Release, true) => "repair_release",
        (BudgetTxKind::Adjust, true) => "repair_overrun",
        _ => return None,
    })
}

/// Why the journal's ledger entries cannot be read. Nothing was written. The message names the
/// record's sequence number and the rule, never an amount or an id.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    /// A record this kernel cannot read, perhaps written by a newer one (E7):
    /// `BUDGET_ENTRIES_UNREADABLE`.
    #[error("record {seq}: {why}")]
    Unreadable {
        /// The record's sequence number.
        seq: u64,
        /// The rule it breaks.
        why: &'static str,
    },
    /// A record that breaks the contract's rules for entries: `BUDGET_LEDGER_INCONSISTENT`.
    #[error("record {seq}: {why}")]
    Inconsistent {
        /// The record's sequence number.
        seq: u64,
        /// The rule it breaks.
        why: &'static str,
    },
}

impl ReadError {
    /// The registered error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Unreadable { .. } => codes::BUDGET_ENTRIES_UNREADABLE,
            Self::Inconsistent { .. } => codes::BUDGET_LEDGER_INCONSISTENT,
        }
    }

    /// The sequence number of the record refused.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        match self {
            Self::Unreadable { seq, .. } | Self::Inconsistent { seq, .. } => *seq,
        }
    }
}

const fn inconsistent<T>(seq: u64, why: &'static str) -> Result<T, ReadError> {
    Err(ReadError::Inconsistent { seq, why })
}

const fn unreadable<T>(seq: u64, why: &'static str) -> Result<T, ReadError> {
    Err(ReadError::Unreadable { seq, why })
}

/// Reads every ledger entry of a journal's verified records, oldest first: the record pass, then
/// the entries in journal order. `budget.entry` records give one entry each, as before; an
/// Operation's record with a `ledger` delta gives its expanded entries.
///
/// # Errors
/// [`ReadError`] for the first record that breaks a rule of §3.3 or §5.2, or whose entries do not
/// decode.
pub fn read_entries(records: &[VerifiedRecord]) -> Result<Vec<BudgetTx>, ReadError> {
    read_journal(records).map(|read| read.entries)
}

/// One Operation whose one-record intent established a reservation, as its records leave it: what
/// the recovery plan needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OneRecordOperation {
    pub(crate) operation: OperationId,
    pub(crate) reservation: ReservationId,
    /// The intent's sequence number.
    pub(crate) intent_seq: u64,
    /// The journal holds the Operation's `op.executing`.
    pub(crate) executing_recorded: bool,
    pub(crate) outcome: Outcome,
}

/// A journal's ledger entries, and its one-record Operations in the order their intents were
/// journaled.
#[derive(Debug)]
pub(crate) struct JournalRead {
    pub(crate) entries: Vec<BudgetTx>,
    pub(crate) one_record: Vec<OneRecordOperation>,
}

/// [`read_entries`], with what the record pass learned of each one-record Operation.
pub(crate) fn read_journal(records: &[VerifiedRecord]) -> Result<JournalRead, ReadError> {
    let mut reader = Reader::default();
    for record in records {
        reader.record(&record.envelope)?;
    }
    reader.finish()
}

/// What the record pass knows of one Operation's history.
#[derive(Debug, Default)]
struct Track {
    history: History,
    /// A record of the Operation's lifecycle came before any intent.
    seen_record: bool,
    /// The one-record history's state, from `Proposed` through `Operation::apply`.
    state: Option<Operation>,
    /// The intent's sequence number, pool, reservation and reserved amount.
    intent_seq: u64,
    pool: Option<PoolId>,
    reservation: Option<ReservationId>,
    reserved: NanoUsd,
    /// The one-record history holds `op.executing`.
    executing: bool,
    outcome: Outcome,
}

/// Where the Operation's reservation stands after its records so far.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// No outcome yet: the reservation is open.
    #[default]
    Pending,
    /// The first outcome was an `op.indeterminate` without entries: a stuck item, still open.
    Stuck,
    /// The reservation is closed.
    Closed,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum History {
    #[default]
    NoIntent,
    TwoRecord,
    OneRecord,
}

#[derive(Debug, Default)]
struct Reader {
    ops: BTreeMap<OperationId, Track>,
    /// Each reservation a one-record intent established, and its Operation.
    owners: BTreeMap<ReservationId, OperationId>,
    /// Each reservation a `budget.entry` names, with the first such record's sequence number.
    named_by_entries: BTreeMap<ReservationId, u64>,
    entries: Vec<BudgetTx>,
}

/// The kernel's Operation lifecycle types.
const OP_TYPES: [&EventType; 7] = [
    &types::OP_RESERVED_INTENT,
    &types::OP_EXECUTING,
    &types::OP_DENIED,
    &types::OP_APPROVAL_REQUIRED,
    &types::OP_FAILED,
    &types::OP_COMMITTED,
    &types::OP_INDETERMINATE,
];

impl Reader {
    fn record(&mut self, envelope: &EventEnvelope) -> Result<(), ReadError> {
        let seq = envelope.seq.0;
        let ledger = envelope
            .payload_inline
            .as_ref()
            .and_then(|payload| payload.as_value().get(LEDGER_FIELD));
        if envelope.event_type == types::BUDGET_ENTRY {
            if ledger.is_some() {
                return inconsistent(seq, "a budget.entry carries a ledger delta");
            }
            let tx = budget_entry(envelope)?;
            if let Some(reservation) = tx.reservation_id {
                self.named_by_entries.entry(reservation).or_insert(seq);
            }
            self.entries.push(tx);
            return Ok(());
        }
        if OP_TYPES.contains(&&envelope.event_type) {
            return self.operation_record(envelope, ledger);
        }
        if types::ALL.contains(&&envelope.event_type) {
            if ledger.is_some() {
                return inconsistent(seq, "a ledger delta on a record type that carries none");
            }
            return Ok(());
        }
        // An unknown type: every domain but `module.` is the kernel's (E7).
        let module = envelope.event_type.as_str().starts_with("module.");
        if ledger.is_some() && !module {
            return unreadable(seq, "a record of an unknown type carries a ledger delta");
        }
        Ok(())
    }

    fn operation_record(&mut self, envelope: &EventEnvelope, ledger: Option<&Value>) -> Result<(), ReadError> {
        let seq = envelope.seq.0;
        let Some(operation) = envelope.operation_id else {
            if ledger.is_some() {
                return inconsistent(seq, "a ledger delta on a record without an Operation");
            }
            return Ok(());
        };
        let delta = ledger.map(|value| parse_delta(seq, value)).transpose()?;
        let track = self.ops.entry(operation).or_default();
        let expanded = if envelope.event_type == types::OP_RESERVED_INTENT {
            intent(seq, envelope, operation, track, delta.as_ref(), &mut self.owners)?
        } else {
            step(seq, envelope, track, delta.as_ref())?
        };
        self.entries.extend(expanded);
        Ok(())
    }

    fn finish(self) -> Result<JournalRead, ReadError> {
        // A `budget.entry` never names a one-record reservation: report the earliest.
        let conflict = self
            .named_by_entries
            .iter()
            .filter(|(reservation, _)| self.owners.contains_key(reservation))
            .map(|(_, seq)| *seq)
            .min();
        if let Some(seq) = conflict {
            return inconsistent(
                seq,
                "a budget.entry names a reservation a one-record intent established",
            );
        }
        let mut one_record: Vec<_> = self
            .ops
            .iter()
            .filter(|(_, track)| track.history == History::OneRecord)
            .filter_map(|(operation, track)| {
                track.reservation.map(|reservation| OneRecordOperation {
                    operation: *operation,
                    reservation,
                    intent_seq: track.intent_seq,
                    executing_recorded: track.executing,
                    outcome: track.outcome,
                })
            })
            .collect();
        one_record.sort_by_key(|op| op.intent_seq);
        Ok(JournalRead {
            entries: self.entries,
            one_record,
        })
    }
}

/// A `budget.entry` record's one entry.
fn budget_entry(envelope: &EventEnvelope) -> Result<BudgetTx, ReadError> {
    let seq = envelope.seq.0;
    let Some(payload) = envelope.payload_inline.as_ref() else {
        return inconsistent(seq, "a budget.entry has no payload");
    };
    BudgetTx::deserialize(payload.as_value())
        .or_else(|_| inconsistent(seq, "a budget.entry's payload is not a valid entry"))
}

/// The fields a delta and its entries may have in version 1.
const DELTA_FIELDS: [&str; 4] = ["v", "pool", "reservation", "entries"];
const ENTRY_FIELDS: [&str; 7] = ["kind", "amount", "before", "after", "reason", "settled", "estimated"];

/// Parses a delta: what a newer writer could have added is unreadable (E7); what does not parse as
/// version 1 is inconsistent.
fn parse_delta(seq: u64, value: &Value) -> Result<LedgerDelta, ReadError> {
    // The common case first, read from the borrowed payload (the reader runs over every record at
    // boot): a delta of this version that parses. Only one that does not parse is examined for
    // why: a newer writer's version, field or kind is unreadable (E7), anything else inconsistent.
    let delta = match LedgerDelta::deserialize(value) {
        Ok(delta) if delta.v == LEDGER_DELTA_VERSION => delta,
        Ok(_) => return unreadable(seq, "a ledger delta of a version this kernel does not read"),
        Err(_) => return Err(why_unparsed(seq, value)),
    };
    if delta.entries.is_empty() || delta.entries.len() > 2 {
        return inconsistent(seq, "a ledger delta holds one or two entries");
    }
    if delta.entries.iter().any(|entry| !carried(entry.kind)) {
        return inconsistent(seq, "a ledger entry of a kind an Operation's record does not carry");
    }
    Ok(delta)
}

/// Why a delta does not parse: a version, field or entry kind this kernel does not know is
/// unreadable; anything else is inconsistent.
fn why_unparsed(seq: u64, value: &Value) -> ReadError {
    match newer_writer(seq, value) {
        Err(refused) => refused,
        Ok(()) => ReadError::Inconsistent {
            seq,
            why: "a ledger delta does not parse",
        },
    }
}

/// Refuses what only a newer writer writes (unreadable), or a delta without its shape
/// (inconsistent); accepts what this kernel knows.
fn newer_writer(seq: u64, value: &Value) -> Result<(), ReadError> {
    let Some(object) = value.as_object() else {
        return inconsistent(seq, "a ledger delta is not an object");
    };
    match object.get("v").map(Value::as_u64) {
        Some(Some(v)) if v == u64::from(LEDGER_DELTA_VERSION) => {}
        Some(Some(_)) => return unreadable(seq, "a ledger delta of a version this kernel does not read"),
        _ => return inconsistent(seq, "a ledger delta without a valid version"),
    }
    if object.keys().any(|key| !DELTA_FIELDS.contains(&key.as_str())) {
        return unreadable(seq, "a ledger delta has a field this kernel does not know");
    }
    for entry in object.get("entries").and_then(Value::as_array).into_iter().flatten() {
        let Some(entry) = entry.as_object() else { continue };
        if entry.keys().any(|key| !ENTRY_FIELDS.contains(&key.as_str())) {
            return unreadable(seq, "a ledger entry has a field this kernel does not know");
        }
        if let Some(kind) = entry.get("kind").filter(|kind| kind.is_string())
            && BudgetTxKind::deserialize(kind).is_err()
        {
            return unreadable(seq, "a ledger entry of a kind this kernel does not know");
        }
    }
    Ok(())
}

fn expand_at(seq: u64, delta: &LedgerDelta, actor: &Actor) -> Result<Vec<BudgetTx>, ReadError> {
    expand(delta, actor).or_else(|_| inconsistent(seq, "a ledger entry's key cannot be derived"))
}

/// Whether the entries are one release of the whole reservation's remainder.
fn is_release(entries: &[DeltaEntry]) -> bool {
    matches!(entries, [release] if release.kind == BudgetTxKind::Release)
}

/// The ledger's settlement sequence: `[settle]`, `[settle, release]` or `[settle, adjust]`.
fn is_settlement(entries: &[DeltaEntry]) -> bool {
    match entries {
        [settle] => settle.kind == BudgetTxKind::Settle,
        [settle, rest] => {
            settle.kind == BudgetTxKind::Settle && matches!(rest.kind, BudgetTxKind::Release | BudgetTxKind::Adjust)
        }
        _ => false,
    }
}

/// An `op.reserved_intent`.
fn intent(
    seq: u64,
    envelope: &EventEnvelope,
    operation: OperationId,
    track: &mut Track,
    delta: Option<&LedgerDelta>,
    owners: &mut BTreeMap<ReservationId, OperationId>,
) -> Result<Vec<BudgetTx>, ReadError> {
    let Some(delta) = delta else {
        return match track.history {
            // In a one-record history an intent is `Authorize` from a later state: refused.
            History::OneRecord => inconsistent(seq, "an intent its Operation's state does not allow"),
            // The two-record form, read as today: a second intent keeps the first.
            History::NoIntent | History::TwoRecord => {
                track.history = History::TwoRecord;
                Ok(Vec::new())
            }
        };
    };
    match track.history {
        History::OneRecord => return inconsistent(seq, "an Operation has a second one-record intent"),
        History::TwoRecord => return inconsistent(seq, "a one-record intent follows a two-record one"),
        History::NoIntent if track.seen_record => {
            return inconsistent(seq, "a one-record intent is not its Operation's first record");
        }
        History::NoIntent => {}
    }
    let [reserve] = delta.entries.as_slice() else {
        return inconsistent(seq, "an intent's entries are not one reserve");
    };
    if reserve.kind != BudgetTxKind::Reserve {
        return inconsistent(seq, "an intent's entries are not one reserve");
    }
    if owners.contains_key(&delta.reservation) {
        return inconsistent(seq, "an intent names another Operation's reservation");
    }
    let proposed = Operation::propose(
        operation,
        OperationKind::ModelCall,
        envelope.side_effect_class,
        envelope.compensable,
        envelope.risk_tier,
    );
    let reserved = proposed
        .apply(Transition::Authorize)
        .and_then(|op| op.apply(Transition::Reserve))
        .or_else(|_| inconsistent(seq, "an intent its Operation's state does not allow"))?;
    owners.insert(delta.reservation, operation);
    *track = Track {
        history: History::OneRecord,
        state: Some(reserved),
        intent_seq: seq,
        pool: Some(delta.pool),
        reservation: Some(delta.reservation),
        reserved: reserve.amount,
        ..Track::default()
    };
    expand_at(seq, delta, &envelope.actor)
}

/// Any other lifecycle record of an Operation ('s table and rules).
fn step(
    seq: u64,
    envelope: &EventEnvelope,
    track: &mut Track,
    delta: Option<&LedgerDelta>,
) -> Result<Vec<BudgetTx>, ReadError> {
    let Some(state) = track.state.filter(|_| track.history == History::OneRecord) else {
        // No intent, or a two-record one: read as today, with no entries.
        if delta.is_some() {
            return inconsistent(seq, "a ledger delta on an Operation without a one-record intent");
        }
        track.seen_record = true;
        return Ok(Vec::new());
    };
    let kind = &envelope.event_type;
    let before = state.state;
    let transition = if *kind == types::OP_EXECUTING {
        Transition::Execute
    } else if *kind == types::OP_DENIED {
        Transition::Deny
    } else if *kind == types::OP_APPROVAL_REQUIRED {
        Transition::RequireApproval
    } else if *kind == types::OP_FAILED {
        if before == OperationState::Indeterminate {
            Transition::ResolveFailed
        } else {
            Transition::Fail
        }
    } else if *kind == types::OP_COMMITTED {
        if before == OperationState::Indeterminate {
            Transition::ResolveCommitted
        } else {
            Transition::Commit
        }
    } else {
        Transition::CrashRecovered
    };
    let after = state
        .apply(transition)
        .or_else(|_| inconsistent(seq, "a step its Operation's state does not allow"))?;
    track.state = Some(after);
    track.executing |= *kind == types::OP_EXECUTING;
    if *kind == types::OP_EXECUTING || *kind == types::OP_APPROVAL_REQUIRED {
        if delta.is_some() {
            return inconsistent(seq, "a ledger delta on a record type that carries none");
        }
        return Ok(Vec::new());
    }
    if let Some(delta) = delta
        && (Some(delta.pool) != track.pool || Some(delta.reservation) != track.reservation)
    {
        return inconsistent(seq, "a closing record names a reservation its intent did not establish");
    }
    if track.outcome == Outcome::Pending {
        first_outcome(seq, envelope, track, delta, before)
    } else {
        resolution(seq, envelope, track, delta)
    }
}

/// The Operation's first outcome: it closes the reservation and carries the closing entries, or is
/// an `op.indeterminate` without entries, a stuck item (rules).
fn first_outcome(
    seq: u64,
    envelope: &EventEnvelope,
    track: &mut Track,
    delta: Option<&LedgerDelta>,
    before: OperationState,
) -> Result<Vec<BudgetTx>, ReadError> {
    let kind = &envelope.event_type;
    let Some(delta) = delta else {
        if *kind == types::OP_INDETERMINATE {
            track.outcome = Outcome::Stuck;
            return Ok(Vec::new());
        }
        return inconsistent(
            seq,
            "a first outcome after a one-record intent carries no closing entries",
        );
    };
    // A repair resolves a stuck item: it follows the entry-less `op.indeterminate` that left the
    // item stuck, never an Operation that was not.
    if delta.entries.iter().any(|entry| entry.reason.as_str() == STUCK_REPAIR) {
        return inconsistent(seq, "a repair without the entry-less op.indeterminate it resolves");
    }
    let fits = if *kind == types::OP_INDETERMINATE {
        // Boot's recovery: the full reservation, estimated.
        matches!(delta.entries.as_slice(), [settle] if settle.kind == BudgetTxKind::Settle
            && settle.estimated && settle.amount == track.reserved)
    } else if *kind == types::OP_DENIED || (*kind == types::OP_FAILED && before == OperationState::Reserved) {
        is_release(&delta.entries)
    } else {
        // `op.failed` after `op.executing`, or `op.committed`.
        is_settlement(&delta.entries)
    };
    if !fits {
        return inconsistent(seq, "a closing record's entries do not fit its place");
    }
    track.outcome = Outcome::Closed;
    expand_at(seq, delta, &envelope.actor)
}

/// A later outcome, a resolution after `op.indeterminate`: without entries, unless it repairs the
/// stuck item an entry-less `op.indeterminate` left.
fn resolution(
    seq: u64,
    envelope: &EventEnvelope,
    track: &mut Track,
    delta: Option<&LedgerDelta>,
) -> Result<Vec<BudgetTx>, ReadError> {
    let Some(delta) = delta else {
        return Ok(Vec::new());
    };
    if track.outcome != Outcome::Stuck {
        return inconsistent(seq, "a record after its Operation's outcome carries entries");
    }
    if delta.entries.iter().any(|entry| entry.reason.as_str() != STUCK_REPAIR) {
        return inconsistent(seq, "a resolution's entries are not a repair's");
    }
    let fits = is_settlement(&delta.entries) || (envelope.event_type == types::OP_FAILED && is_release(&delta.entries));
    if !fits {
        return inconsistent(seq, "a closing record's entries do not fit its place");
    }
    track.outcome = Outcome::Closed;
    expand_at(seq, delta, &envelope.actor)
}
