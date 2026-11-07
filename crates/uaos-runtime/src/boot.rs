// SPDX-License-Identifier: Apache-2.0

//! Boot recovery.
//!
//! After the journal has opened and repaired its tail, [`boot`] rebuilds what the runtime holds in
//! memory from the verified records, closes what a crash left open, and explains the boot in one
//! `kernel.booted` record:
//! 1. records that are not the journal's, or a configuration older than the journal's last, are
//!    refused, before anything is written;
//! 2. the stop is restored;
//! 3. The ledger is replayed; each open one-record Operation closes in its own `op.indeterminate`,
//!    with its reservation settled at the full amount (intent contract); then recovery closes what
//!    is left. Money that may be spent is settled, never released.
//! 4. every other open intent becomes `Indeterminate`, once: neither success nor failure is
//!    assumed;
//! 5. the boot is journaled with its counts, and with how the run before it ended: a clean
//!    shutdown, a crash, or unknown.
//!
//! A crash between any two appends converges on the next boot without duplicates.

use std::collections::{BTreeMap, BTreeSet};

use uaos_contracts::budget::LedgerDelta;
use uaos_contracts::error::{ErrorCode, codes};
use uaos_contracts::event::{
    Actor, Durability, EnvelopeError, EventEnvelope, EventType, InlinePayload, Metadata, types,
};
use uaos_contracts::id::{CorrelationId, OperationId};
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::wire::{ConfigVersion, Seq};
use uaos_ledger::inline::LEDGER_FIELD;
use uaos_ledger::{
    JournalSink, Ledger, LedgerError, OpenOperation, PlanError, ReadError, StuckItem, StuckKind, replay_with_plan,
};
use uaos_state::journal::{EventDraft, Journal, JournalError, OpenEvidence, VerifiedRecord};

use crate::config::ConfigSnapshot;
use crate::stop::{BootState, Stop, boot_state};

/// The reason an intent with no outcome is made indeterminate.
pub const CRASH_RECOVERY: &str = "crash_recovery";

/// How the run before a boot ended, as the journal tells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LastEnd {
    /// The last boot could journal a clean shutdown (`shutdown_record`), the previous runs'
    /// records end with its `kernel.shutdown`, and the clean end's seal names that record.
    Clean,
    /// The last boot could journal a clean shutdown, and the previous runs' records do not end
    /// with one a seal names: that run, or a boot after it that wrote no `kernel.booted`, ended
    /// without it, or its shutdown failed to flush.
    Crashed,
    /// No boot record says a shutdown would have been journaled: an empty journal, or one
    /// written before shutdown records existed. Never read as clean.
    Unknown,
}

impl LastEnd {
    /// The value the `kernel.booted` payload carries: `clean`, `crash` or `unknown`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Crashed => "crash",
            Self::Unknown => "unknown",
        }
    }
}

/// What a boot did: counts and versions, as the `kernel.booted` record carries them, and in
/// memory only, why ledger items stayed stuck.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootReport {
    /// Verified records read.
    pub records: u64,
    /// The stop as the journal left it.
    pub stop: BootState,
    /// Operations whose intent had no outcome, now `Indeterminate`, in journal order.
    pub indeterminate: Vec<OperationId>,
    /// Of those, the one-record Operations whose own `op.indeterminate` settled their reservation
    /// at its full amount, estimated.
    pub indeterminate_settled: usize,
    /// Open reservations of the two-record form settled at their full amount, estimated, by
    /// `budget.entry` records under boot's correlation.
    pub settled_estimated: usize,
    /// Partly settled reservations completed.
    pub completed: usize,
    /// Transfers whose second half was recorded.
    pub transfers_completed: usize,
    /// The items recovery could not close, each with the reason code saying why: one-record
    /// reservations, then what the ledger's recovery could not close. While any remain, the ledger
    /// refuses new work (`BUDGET_RECOVERY_REQUIRED`). Not journaled: the record counts them, by
    /// kind.
    pub stuck: Vec<StuckItem>,
    /// How the run before this boot ended.
    pub last_end: LastEnd,
    /// The kernel boots running after a crash: a stop engaged just before it may not have been
    /// journaled. The evidence is a missing `kernel.shutdown` after a boot that would have written
    /// one; on a journal older than shutdown records, work left open or an interrupted boot's
    /// `op.indeterminate`. A clean shutdown flushed every record before its own, an engaged stop's
    /// included; one that counted Operations still open let them run past its record, so it still
    /// says so.
    pub stop_may_be_lost: bool,
    /// The configuration version the kernel boots with.
    pub config_version: ConfigVersion,
}

/// A booted kernel's state.
#[derive(Debug)]
pub struct Booted {
    /// The stop, as the journal left it.
    pub stop: Stop,
    /// The ledger, replayed and recovered.
    pub ledger: Ledger,
    /// What the boot did.
    pub report: BootReport,
}

/// Why boot refused or failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BootError {
    /// The records are not the whole journal, from its genesis to its head: boot would journal
    /// against records that are not the journal's, and a retry with the same records would repeat
    /// its writes. Nothing was written.
    #[error(
        "the records are not the whole journal from its genesis to its head, one record after \
         another (they end before {records_end}; the journal's next is {journal_next})"
    )]
    StaleRecords {
        /// The sequence number after the last record handed to boot.
        records_end: Seq,
        /// The journal's next sequence number.
        journal_next: Seq,
    },
    /// The configuration is older than the last one the journal records. Nothing was written.
    #[error("the configuration (version {configured}) is older than the journal's last ({journaled})")]
    ConfigDrift {
        /// The highest version a record carries.
        journaled: ConfigVersion,
        /// The version the process starts with.
        configured: ConfigVersion,
    },
    /// The journal's ledger entries cannot be read: a record breaks the runtime intent contract's
    /// rules, or this kernel cannot read it. Nothing was written.
    #[error("the journal's budget entries cannot be read: {0}")]
    LedgerEntries(#[source] ReadError),
    /// The ledger's entries do not replay, or its recovery failed other than at the journal.
    #[error("the budget ledger could not be rebuilt: {0}")]
    Ledger(#[source] LedgerError),
    /// The journal refused a recovery record. The next boot resumes where this one stopped.
    #[error("the journal refused a recovery record: {0}")]
    Journal(#[from] JournalError),
    /// A recovery record does not fit the envelope's bounds.
    #[error("a recovery record does not fit the envelope: {0}")]
    Envelope(#[from] EnvelopeError),
}

impl BootError {
    /// The registered error code. A journal failure keeps the journal's own code wherever it lands,
    /// in the ledger's recovery or in boot's own records; anything else the ledger reports is an
    /// inconsistent ledger.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::StaleRecords { .. } => codes::RUNTIME_BOOT_RECORDS_STALE,
            Self::ConfigDrift { .. } => codes::CONFIG_DRIFT,
            Self::LedgerEntries(error) => error.code(),
            Self::Ledger(_) => codes::BUDGET_LEDGER_INCONSISTENT,
            Self::Journal(error) => error.code(),
            Self::Envelope(_) => codes::JOURNAL_WRITE_FAILED,
        }
    }
}

/// Recovers a kernel from its journal. `records` are the journal's verified records, oldest first,
/// read after it opened; `evidence` is what the open found about the previous run's end
/// ([`Journal::open_with_payloads`]; `OpenEvidence::default()` when nothing is known, and then no
/// shutdown reads as clean); `config` is the snapshot the process starts with; the recovery records
/// carry `correlation`.
///
/// # Errors
/// [`BootError::StaleRecords`] and [`BootError::ConfigDrift`] before anything is written; otherwise
/// a ledger or journal failure, after which the next boot resumes.
pub fn boot(
    journal: &mut Journal,
    records: &[VerifiedRecord],
    evidence: OpenEvidence,
    config: &ConfigSnapshot,
    correlation: CorrelationId,
) -> Result<Booted, BootError> {
    // 0. The records are the whole journal: from its genesis to its head. A journal never drops
    // a verified record, so an empty slice means an empty journal.
    let records_end = records
        .last()
        .map_or(Seq(0), |last| Seq(last.envelope.seq.0.saturating_add(1)));
    let ends_at_head = records.last().map_or(journal.next_seq() == Seq(0), |last| {
        records_end == journal.next_seq() && last.hash == journal.head()
    });
    let from_genesis = records.first().is_none_or(|first| first.envelope.seq == Seq(0));
    // One after another, by sequence and chain link: no gap, no record twice.
    let contiguous = records
        .iter()
        .zip(records.iter().skip(1))
        .all(|(a, b)| b.envelope.seq.0 == a.envelope.seq.0.saturating_add(1) && b.envelope.prev_hash == a.hash);
    if !(ends_at_head && from_genesis && contiguous) {
        return Err(BootError::StaleRecords {
            records_end,
            journal_next: journal.next_seq(),
        });
    }

    // 1. Drift, before anything is written.
    if let Some(journaled) = records.iter().map(|r| r.envelope.config_version).max()
        && journaled > config.version()
    {
        return Err(BootError::ConfigDrift {
            journaled,
            configured: config.version(),
        });
    }

    // 2. The stop. A stopped kernel boots stopped; recovery still closes the journal honestly.
    let stop_state = boot_state(records.iter().map(|r| &r.envelope));
    let stop = Stop::booted(stop_state);

    // 3. The ledger: replayed; open one-record Operations closed in their own records; then
    // Recovered (a replayed ledger always runs its recovery). Open reservations settle at their
    // full amount, estimated, and are never released: their Operations may have spent them. The
    // plan says what boot closes and what stays stuck.
    let (mut ledger, plan) = replay_with_plan(records).map_err(|error| match error {
        PlanError::Read(error) => BootError::LedgerEntries(error),
        PlanError::Ledger(error) => BootError::Ledger(error),
    })?;
    let intents = open_intents(records);
    let one_record: BTreeSet<OperationId> = plan.open().iter().map(|open| open.operation).collect();
    let indeterminate_settled =
        close_one_record_operations(journal, &mut ledger, records, &intents, plan.open(), config.version())?;
    let recovery = {
        let mut sink = JournalSink::new(journal, correlation, None, config.version());
        match ledger.recover(&mut sink, &Actor::System, &plan) {
            Ok(recovery) => recovery,
            // A journal failure keeps the journal's own code, as it does at boot's own records.
            Err(error) => return Err(sink.take_refusal().map_or(BootError::Ledger(error), BootError::Journal)),
        }
    };

    // 4. Every other intent with no outcome, the two-record form's, becomes indeterminate, once,
    // with the effect it declared.
    for intent in intents.iter().filter(|intent| {
        intent
            .operation_id
            .is_none_or(|operation| !one_record.contains(&operation))
    }) {
        if carries_ledger(intent) {
            // A one-record intent the plan does not list as open: the reader and boot disagree.
            return Err(BootError::Ledger(LedgerError::Inconsistent(
                "a one-record intent is open and the recovery plan does not list it",
            )));
        }
        journal.append(indeterminate_draft(intent, config.version())?)?;
    }

    // 5. The boot, explained.
    // Evidence of a crash: work left open, or an interrupted boot's `op.indeterminate` with no
    // `kernel.booted` after it. A stuck item is not: it stays from boot to boot.
    let last_boot = records
        .iter()
        .rposition(|r| r.envelope.event_type == types::KERNEL_BOOTED);
    let interrupted = records
        .iter()
        .skip(last_boot.map_or(0, |at| at + 1))
        .any(|r| r.envelope.event_type == types::OP_INDETERMINATE);
    let crashed = interrupted
        || !intents.is_empty()
        || recovery.settled_estimated + recovery.completed + recovery.transfers_completed > 0;
    let stuck = ledger.stuck().to_vec();
    let (last_end, open_at_shutdown) = last_end(records, last_boot, evidence);
    let stop_may_be_lost = stop_state == BootState::Running
        && match last_end {
            LastEnd::Clean => open_at_shutdown,
            LastEnd::Crashed => true,
            LastEnd::Unknown => crashed,
        };
    let report = BootReport {
        records: u64::try_from(records.len()).unwrap_or(u64::MAX),
        stop: stop_state,
        indeterminate: intents.iter().filter_map(|intent| intent.operation_id).collect(),
        indeterminate_settled,
        settled_estimated: recovery.settled_estimated,
        completed: recovery.completed,
        transfers_completed: recovery.transfers_completed,
        stuck,
        last_end,
        stop_may_be_lost,
        config_version: config.version(),
    };
    journal.append(booted_draft(&report, BootCounts::of(&report), correlation)?)?;
    Ok(Booted { stop, ledger, report })
}

/// How the run before this boot ended, and whether a clean shutdown counted Operations still open.
/// Clean takes three things:
/// - the last boot set `shutdown_record`;
/// - the previous runs' records end with `kernel.shutdown`. The open's own records (a loss it
///   reported) are left out: they follow that end, whatever it was. Any other record after the
///   shutdown was written by a later process that ended before its own `kernel.booted`, an
///   interrupted boot;
/// - a seal names that very record ([`OpenEvidence::sealed`]). Only a clean shutdown writes a seal,
///   after its flush succeeded, and the next run removes it before it admits work. A shutdown whose
///   flush failed may still be in the file, handed to the OS but never confirmed; that is a crash,
///   and the stop the failure engaged may be lost.
fn last_end(records: &[VerifiedRecord], last_boot: Option<usize>, evidence: OpenEvidence) -> (LastEnd, bool) {
    let Some(boot) = last_boot.and_then(|at| records.get(at)) else {
        return (LastEnd::Unknown, false);
    };
    let capable = boot
        .envelope
        .payload_inline
        .as_ref()
        .and_then(|payload| payload.as_value().get("shutdown_record"))
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    if !capable {
        return (LastEnd::Unknown, false);
    }
    let after = last_boot.map_or(0, |at| at + 1);
    let previous = records
        .iter()
        .take_while(|r| evidence.own_from.is_none_or(|own| r.envelope.seq < own));
    match previous.skip(after).last() {
        Some(last)
            if last.envelope.event_type == types::KERNEL_SHUTDOWN && evidence.sealed == Some(last.envelope.seq) =>
        {
            let open = last
                .envelope
                .payload_inline
                .as_ref()
                .and_then(|payload| payload.as_value().get("open_operations"))
                .and_then(serde_json::Value::as_str);
            // An unreadable count is read as work left open: never clean by default.
            (LastEnd::Clean, open != Some("0"))
        }
        _ => (LastEnd::Crashed, false),
    }
}

/// The event types after which an Operation has an outcome, or needs a human: terminal for boot.
const OUTCOMES: [&EventType; 5] = [
    &types::OP_COMMITTED,
    &types::OP_FAILED,
    &types::OP_DENIED,
    &types::OP_APPROVAL_REQUIRED,
    &types::OP_INDETERMINATE,
];

/// What the records say of one Operation.
enum Seen<'r> {
    /// An intent with no outcome yet: where it was first journaled, and that first intent.
    Open { at: usize, intent: &'r EventEnvelope },
    /// An outcome or a human's decision: terminal for boot, whatever a later record says.
    Closed,
}

/// The first intent of each Operation that has no outcome, in the order those intents were
/// journaled. Once an Operation is closed, a later intent does not reopen it:
/// only an inconsistent journal holds one, and reopening would make a committed Operation
/// indeterminate.
fn open_intents(records: &[VerifiedRecord]) -> Vec<&EventEnvelope> {
    let mut seen: BTreeMap<OperationId, Seen<'_>> = BTreeMap::new();
    for (at, record) in records.iter().enumerate() {
        let envelope = &record.envelope;
        let Some(operation) = envelope.operation_id else {
            continue;
        };
        if envelope.event_type == types::OP_RESERVED_INTENT {
            seen.entry(operation).or_insert(Seen::Open { at, intent: envelope });
        } else if OUTCOMES.contains(&&envelope.event_type) {
            seen.insert(operation, Seen::Closed);
        }
    }
    let mut open: Vec<(usize, &EventEnvelope)> = seen
        .into_values()
        .filter_map(|seen| match seen {
            Seen::Open { at, intent } => Some((at, intent)),
            Seen::Closed => None,
        })
        .collect();
    open.sort_unstable_by_key(|(at, _)| *at);
    open.into_iter().map(|(_, intent)| intent).collect()
}

/// Whether an intent is the one-record form's: its reserve travels inside it.
fn carries_ledger(intent: &EventEnvelope) -> bool {
    intent
        .payload_inline
        .as_ref()
        .is_some_and(|payload| payload.as_value().get(LEDGER_FIELD).is_some())
}

/// Closes each open one-record Operation the plan lists, in intent order, in its own record.
/// Returns how many records settled their reservation.
fn close_one_record_operations(
    journal: &mut Journal,
    ledger: &mut Ledger,
    records: &[VerifiedRecord],
    intents: &[&EventEnvelope],
    open_operations: &[OpenOperation],
    config_version: ConfigVersion,
) -> Result<usize, BootError> {
    let mut indeterminate_settled = 0;
    for open in open_operations {
        // The plan and the intents agree on what is open: an Operation with an outcome is never
        // recovered again (idempotence).
        if !intents.iter().any(|intent| intent.operation_id == Some(open.operation)) {
            return Err(BootError::Ledger(LedgerError::Inconsistent(
                "the recovery plan lists an Operation open that has an outcome",
            )));
        }
        let intent = usize::try_from(open.intent_seq)
            .ok()
            .and_then(|at| records.get(at))
            .map(|record| &record.envelope)
            .filter(|intent| intent.operation_id == Some(open.operation))
            .ok_or(BootError::Ledger(LedgerError::Inconsistent(
                "an open one-record Operation's intent is not where the plan says",
            )))?;
        if close_one_record(journal, ledger, intent, open, config_version)? {
            indeterminate_settled += 1;
        }
    }
    Ok(indeterminate_settled)
}

/// Closes an open one-record Operation in its own `op.indeterminate`. Its reservation's settlement
/// at the full amount, estimated, is prepared before the record and applied only after the journal
/// acknowledges it. When the ledger refuses that settlement, the record carries no entries and the
/// reservation is a stuck item. Returns whether the record settled the reservation.
fn close_one_record(
    journal: &mut Journal,
    ledger: &mut Ledger,
    intent: &EventEnvelope,
    open: &OpenOperation,
    config_version: ConfigVersion,
) -> Result<bool, BootError> {
    if !open.settles {
        journal.append(one_record_draft(intent, open, None, config_version)?)?;
        return Ok(false);
    }
    let batch = ledger
        .prepare_recovery_settle(open.reservation)
        .map_err(BootError::Ledger)?;
    let appended = batch
        .delta()
        .map_err(|_| BootError::Ledger(LedgerError::Inconsistent("a recovery settlement does not fit a delta")))
        .and_then(|delta| one_record_draft(intent, open, Some(&delta), config_version))
        .and_then(|draft| journal.append(draft).map_err(BootError::from));
    match appended {
        Ok(_) => {
            let _settled = ledger.apply(batch);
            Ok(true)
        }
        Err(error) => {
            // The record was refused, or its fate is unknown: the ledger stops, and the next boot
            // reads the journal again and closes the Operation once (idempotence).
            ledger.abandon(batch);
            Err(error)
        }
    }
}

/// A one-record Operation's `op.indeterminate`: the two-record form's record, which says whether
/// the journal holds the Operation's `op.executing` (`executing_recorded`) and carries the
/// settlement, when there is one.
fn one_record_draft(
    intent: &EventEnvelope,
    open: &OpenOperation,
    delta: Option<&LedgerDelta>,
    config_version: ConfigVersion,
) -> Result<EventDraft, BootError> {
    let mut payload = serde_json::json!({
        "reason": CRASH_RECOVERY,
        "may_have_taken_effect": true,
        "executing_recorded": open.executing_recorded,
    });
    if let (Some(delta), Some(fields)) = (delta, payload.as_object_mut()) {
        let delta = serde_json::to_value(delta)
            .map_err(|_| BootError::Ledger(LedgerError::Inconsistent("a recovery settlement does not serialize")))?;
        fields.insert(LEDGER_FIELD.to_owned(), delta);
    }
    Ok(EventDraft {
        payload_inline: Some(InlinePayload::new(payload)?),
        ..indeterminate_draft(intent, config_version)?
    })
}

/// `op.indeterminate` for an intent with no outcome (`Transition::CrashRecovered`). It is the
/// Operation's record: it carries the intent's ids and correlation, links to the intent, keeps the
/// effect the intent declared, and says the effect may have happened. The request may have reached
/// the provider, and neither success nor failure is assumed (red line 3).
fn indeterminate_draft(intent: &EventEnvelope, config_version: ConfigVersion) -> Result<EventDraft, EnvelopeError> {
    Ok(EventDraft {
        session_id: intent.session_id,
        pocket_id: intent.pocket_id,
        operation_id: intent.operation_id,
        request_id: intent.request_id,
        agent_id: intent.agent_id,
        correlation_id: intent.correlation_id,
        parent_id: Some(intent.id),
        actor: Actor::System,
        event_type: types::OP_INDETERMINATE,
        payload_ref: None,
        payload_inline: Some(InlinePayload::new(serde_json::json!({
            "reason": CRASH_RECOVERY,
            "may_have_taken_effect": true,
        }))?),
        cost_estimate: None,
        compensable: false,
        side_effect_class: intent.side_effect_class,
        // The Operation's own tier, as the envelope defines it; the record surfaces by its type and
        // by the boot record's tier.
        risk_tier: intent.risk_tier,
        durability: Durability::Critical,
        config_version,
        metadata: Metadata::default(),
    })
}

/// The counts `kernel.booted` carries: what recovery closed in the Operations' own records
/// (`indeterminate_settled`) and in boot's (`settled_estimated`, `completed`,
/// `transfers_completed`), and what it could not (`stuck`, by kind).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BootCounts {
    records: u64,
    indeterminate: u64,
    indeterminate_settled: u64,
    settled_estimated: u64,
    completed: u64,
    transfers_completed: u64,
    stuck: u64,
    stuck_reservations: u64,
    stuck_transfers: u64,
}

impl BootCounts {
    fn of(report: &BootReport) -> Self {
        let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        let kind = |reservation: bool| {
            count(
                report
                    .stuck
                    .iter()
                    .filter(|item| matches!(item.kind, StuckKind::Reservation(_)) == reservation)
                    .count(),
            )
        };
        Self {
            records: report.records,
            indeterminate: count(report.indeterminate.len()),
            indeterminate_settled: count(report.indeterminate_settled),
            settled_estimated: count(report.settled_estimated),
            completed: count(report.completed),
            transfers_completed: count(report.transfers_completed),
            stuck: count(report.stuck.len()),
            stuck_reservations: kind(true),
            stuck_transfers: kind(false),
        }
    }

    /// Whether recovery closed or left anything.
    const fn any_recovered(&self) -> bool {
        self.indeterminate != 0
            || self.indeterminate_settled != 0
            || self.settled_estimated != 0
            || self.completed != 0
            || self.transfers_completed != 0
            || self.stuck != 0
    }
}

/// `kernel.booted`, with the boot's counts as canonical decimal strings (`wire`'s rule). A boot
/// that closed anything, follows a crash, or says a stop may have been lost, surfaces at the
/// highest risk tier; a clean boot is routine. `shutdown_record: true` says this run journals a
/// clean shutdown, so the next boot can tell one from a crash.
fn booted_draft(
    report: &BootReport,
    counts: BootCounts,
    correlation: CorrelationId,
) -> Result<EventDraft, EnvelopeError> {
    let recovered = counts.any_recovered() || report.last_end == LastEnd::Crashed || report.stop_may_be_lost;
    let payload = serde_json::json!({
            "records": counts.records.to_string(),
            "indeterminate": counts.indeterminate.to_string(),
            "indeterminate_settled": counts.indeterminate_settled.to_string(),
            "settled_estimated": counts.settled_estimated.to_string(),
            "completed": counts.completed.to_string(),
            "transfers_completed": counts.transfers_completed.to_string(),
            "stuck": counts.stuck.to_string(),
            "stuck_reservations": counts.stuck_reservations.to_string(),
            "stuck_transfers": counts.stuck_transfers.to_string(),
            "stopped": report.stop != BootState::Running,
            "stop_may_be_lost": report.stop_may_be_lost,
            "config_version": report.config_version.0.to_string(),
            "shutdown_record": true,
            "last_end": report.last_end.as_str(),
    });
    Ok(EventDraft {
        session_id: None,
        pocket_id: None,
        operation_id: None,
        request_id: None,
        agent_id: None,
        correlation_id: correlation,
        parent_id: None,
        actor: Actor::System,
        event_type: types::KERNEL_BOOTED,
        payload_ref: None,
        payload_inline: Some(InlinePayload::new(payload)?),
        cost_estimate: None,
        compensable: false,
        side_effect_class: SideEffectClass::None,
        risk_tier: if recovered { RiskTier::MAX } else { RiskTier::MIN },
        durability: Durability::Critical,
        config_version: report.config_version,
        metadata: Metadata::default(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test: a failed fixture fails the test")]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use uaos_contracts::budget::{IdempotencyKey, ReasonCode};
    use uaos_contracts::id::TypedId;
    use uaos_contracts::limits::MAX_INLINE_PAYLOAD;
    use uaos_contracts::time::WallTime;
    use uaos_platform::fs::Fs as _;
    use uaos_platform::sim::fs::SimFs;
    use uaos_platform::sim::{SimClock, SimRng};
    use uaos_state::journal::FlushPolicy;

    use super::*;

    fn report(stuck: Vec<StuckItem>) -> BootReport {
        BootReport {
            records: 1,
            stop: BootState::Running,
            indeterminate: Vec::new(),
            indeterminate_settled: 0,
            settled_estimated: 0,
            completed: 0,
            transfers_completed: 0,
            stuck,
            last_end: LastEnd::Unknown,
            stop_may_be_lost: false,
            config_version: ConfigVersion(1),
        }
    }

    #[test]
    fn a_boot_that_leaves_an_item_stuck_counts_it_and_surfaces() {
        // A stuck item is counted in the boot record and makes it surface, though it is no evidence
        // of a crash by itself. Counted by kind.
        let report = report(vec![StuckItem {
            kind: StuckKind::Transfer(IdempotencyKey::new("t").unwrap()),
            reason: ReasonCode::new("key_conflict").unwrap(),
        }]);
        let draft = booted_draft(&report, BootCounts::of(&report), CorrelationId::from_parts(1, [1; 10])).unwrap();
        let payload = draft.payload_inline.as_ref().unwrap().as_value();
        assert_eq!(
            (
                &payload["stuck"],
                &payload["stuck_transfers"],
                &payload["stuck_reservations"]
            ),
            (
                &serde_json::json!("1"),
                &serde_json::json!("1"),
                &serde_json::json!("0")
            ),
            "the boot record hid a stuck item"
        );
        assert_eq!(
            draft.risk_tier,
            RiskTier::MAX,
            "a boot that left an item stuck was journaled as routine"
        );
    }

    #[test]
    fn the_boot_record_fits_with_every_count_at_its_extreme() {
        // The boot record is built and journaled with every count at its 64-bit extreme, so its
        // size is checked, not estimated. The longest flags: `false` for both booleans and
        // `unknown` for the end.
        let report = BootReport {
            config_version: ConfigVersion(u64::MAX),
            ..report(Vec::new())
        };
        let counts = BootCounts {
            records: u64::MAX,
            indeterminate: u64::MAX,
            indeterminate_settled: u64::MAX,
            settled_estimated: u64::MAX,
            completed: u64::MAX,
            transfers_completed: u64::MAX,
            stuck: u64::MAX,
            stuck_reservations: u64::MAX,
            stuck_transfers: u64::MAX,
        };
        let draft = booted_draft(&report, counts, CorrelationId::from_parts(1, [1; 10])).unwrap();
        let payload = serde_json::to_vec(draft.payload_inline.as_ref().unwrap().as_value()).unwrap();
        assert!(
            u64::try_from(payload.len()).unwrap() <= MAX_INLINE_PAYLOAD.0,
            "the boot record at its extremes is {} bytes",
            payload.len()
        );
        // Journaled as boot journals it.
        let fs = SimFs::new();
        fs.create_dir_all(Path::new("/data")).unwrap();
        let mut journal = Journal::open(
            Arc::new(fs),
            Arc::new(SimClock::new(
                WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
            )),
            Arc::new(SimRng::new(1)),
            Path::new("/data"),
            FlushPolicy::Strict,
        )
        .unwrap();
        journal
            .append(draft)
            .expect("the boot record at its extremes was not journaled");
    }
}
