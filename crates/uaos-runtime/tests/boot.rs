// SPDX-License-Identifier: Apache-2.0

//! Boot recovery, on a simulated disk: drift, the stop, the ledger, open intents, the boot record,
//! and convergence after a crash at every append of a boot.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use uaos_contracts::budget::LedgerDelta;
use uaos_contracts::budget::{BudgetTx, BudgetTxKind, BudgetTxSchema, IdempotencyKey, ReasonCode};
use uaos_contracts::event::{Actor, Durability, EventEnvelope, EventType, InlinePayload, Metadata, types};
use uaos_contracts::id::{
    AgentId, CorrelationId, EventId, OperationId, PocketId, PoolId, RequestId, ReservationId, SessionId, TypedId,
};
use uaos_contracts::money::NanoUsd;
use uaos_contracts::operation::{OperationKind, RiskTier, SideEffectClass};
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::{ConfigVersion, Seq};
use uaos_ledger::inline::LEDGER_FIELD;
use uaos_ledger::{
    JournalSink, Ledger, LedgerSink, Repair, RepairOutcome, StuckItem, StuckKind, Usage, entries_from_journal,
};
use uaos_platform::fs::Fs;
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, Rng};
use uaos_runtime::{
    Admission, AdmissionLimits, BootError, BootState, Booted, CRASH_RECOVERY, ConfigSnapshot, DEFAULT_LEDGER_QUEUE,
    DEFAULT_QUEUE_CAPACITY, EngagedBy, LastEnd, LedgerCallError, LedgerHandle, LocaleTag, OperationRecord, RepairBy,
    StateActor, StateCore, StateHandle, Stop, StopReason, Supervisor, SupervisorLimits, boot, shut_down,
    start_ledger_task, start_state_actor, state_queue,
};
use uaos_state::journal::{EventDraft, FlushPolicy, JOURNAL_DIR, Journal, OpenEvidence, read_verified};

const DATA: &str = "/data";
const POOL_FUNDS: i64 = 10_000;
const RESERVED: i64 = 300;

fn pool() -> PoolId {
    PoolId::from_parts(1, [1; 10])
}

fn op(n: u8) -> OperationId {
    OperationId::from_parts(u64::from(n) + 1, [n; 10])
}

fn correlation() -> CorrelationId {
    CorrelationId::from_parts(9, [9; 10])
}

fn config(version: u64) -> ConfigSnapshot {
    ConfigSnapshot::new(ConfigVersion(version), LocaleTag::new("en").unwrap())
}

/// A journal on a simulated disk.
struct World {
    fs: SimFs,
    clock: Arc<SimClock>,
    rng: Arc<SimRng>,
    data: PathBuf,
}

impl World {
    fn new() -> Self {
        let fs = SimFs::new();
        fs.create_dir_all(Path::new(DATA)).unwrap();
        Self {
            fs,
            clock: Arc::new(SimClock::new(
                WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
            )),
            rng: Arc::new(SimRng::new(11)),
            data: PathBuf::from(DATA),
        }
    }

    fn open(&self) -> Journal {
        let clock: Arc<dyn Clock> = self.clock.clone();
        let rng: Arc<dyn Rng> = self.rng.clone();
        Journal::open(Arc::new(self.fs.clone()), clock, rng, &self.data, FlushPolicy::Strict).unwrap()
    }

    fn records(&self) -> Vec<uaos_state::journal::VerifiedRecord> {
        read_verified(&self.fs, &self.data.join(JOURNAL_DIR)).unwrap().0
    }

    fn envelopes(&self) -> Vec<EventEnvelope> {
        self.records().into_iter().map(|r| r.envelope).collect()
    }

    /// Ends the run that booted last cleanly, as the state actor journals it: `kernel.shutdown`,
    /// with nothing left open. Without it, a boot after a boot that set `shutdown_record` reads a
    /// crash.
    fn shut_down_cleanly(&self) {
        let mut journal = self.open();
        journal
            .append(EventDraft {
                operation_id: None,
                event_type: types::KERNEL_SHUTDOWN,
                payload_inline: Some(
                    InlinePayload::new(serde_json::json!({"clean": true, "open_operations": "0"})).unwrap(),
                ),
                side_effect_class: SideEffectClass::None,
                risk_tier: RiskTier::MIN,
                ..op_event(op(0), types::KERNEL_SHUTDOWN, 1)
            })
            .unwrap();
        let _sealed = journal.seal().unwrap();
    }

    /// Opens the journal and boots under `config`.
    fn boot(&self, config: &ConfigSnapshot) -> Result<Booted, BootError> {
        self.boot_with(config, FlushPolicy::Strict)
    }

    /// Opens the journal under `policy` and boots under `config`.
    fn boot_with(&self, config: &ConfigSnapshot, policy: FlushPolicy) -> Result<Booted, BootError> {
        let clock: Arc<dyn Clock> = self.clock.clone();
        let rng: Arc<dyn Rng> = self.rng.clone();
        let opened = Journal::open_verified(Arc::new(self.fs.clone()), clock, rng, &self.data, policy).unwrap();
        let mut journal = opened.journal;
        boot(&mut journal, &opened.records, opened.evidence, config, correlation())
    }

    /// The OS writes back `num`/`den` of each journal file's unflushed bytes on its own.
    fn write_back_part(&self, num: usize, den: usize) {
        for file in self.fs.list_dir(&self.data.join(JOURNAL_DIR)).unwrap() {
            self.fs.write_back_part(&file, num, den);
        }
    }
}

fn op_event(operation: OperationId, event_type: EventType, version: u64) -> EventDraft {
    EventDraft {
        session_id: None,
        pocket_id: None,
        operation_id: Some(operation),
        request_id: None,
        agent_id: None,
        correlation_id: correlation(),
        parent_id: None,
        actor: Actor::System,
        event_type,
        payload_ref: None,
        payload_inline: None,
        cost_estimate: None,
        compensable: false,
        side_effect_class: SideEffectClass::External,
        risk_tier: RiskTier::new(1).unwrap(),
        durability: Durability::Critical,
        config_version: ConfigVersion(version),
        metadata: Metadata::default(),
    }
}

/// How an Operation's story ended before the crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// Intent recorded, nothing after: the crash interrupted it.
    Open,
    Committed,
    Failed,
    /// A previous boot already made it indeterminate.
    AlreadyIndeterminate,
    /// Refused before it ran: the reservation released, the Operation denied.
    Denied,
    /// The crash fell between the reserve entry and the intent: a reservation no intent names.
    ReservedOnly,
    /// One-record intent, nothing after: the crash interrupted it.
    OneOpen,
    /// One-record intent and `op.executing`, nothing after.
    OneExecuting,
    /// One-record intent, `op.executing`, then `op.committed` with its settlement.
    OneCommitted,
    /// One-record intent, then `op.failed` releasing the reservation, never sent.
    OneReleased,
    /// One-record intent closed by an earlier boot's `op.indeterminate`, with its settlement.
    OneAlreadyIndeterminate,
}

impl Fate {
    const fn one_record(self) -> bool {
        matches!(
            self,
            Self::OneOpen | Self::OneExecuting | Self::OneCommitted | Self::OneReleased | Self::OneAlreadyIndeterminate
        )
    }

    /// An intent with no outcome: boot makes it indeterminate.
    const fn open(self) -> bool {
        matches!(self, Self::Open | Self::OneOpen | Self::OneExecuting)
    }
}

/// An Operation record carrying `fields` and a ledger delta.
fn with_delta(draft: EventDraft, fields: serde_json::Value, delta: &LedgerDelta) -> EventDraft {
    let mut payload = fields;
    payload
        .as_object_mut()
        .unwrap()
        .insert(LEDGER_FIELD.to_owned(), serde_json::to_value(delta).unwrap());
    EventDraft {
        payload_inline: Some(InlinePayload::new(payload).unwrap()),
        ..draft
    }
}

/// A one-record Operation, as the ledger task will write it (E4): each transition one record, its
/// entries prepared before it and applied after its acknowledgement.
fn one_record(
    journal: &mut Journal,
    ledger: &mut Ledger,
    operation: OperationId,
    id: ReservationId,
    fate: Fate,
    version: u64,
) {
    // Every id the Operation's records carry: its intent's.
    let event = |event_type| EventDraft {
        session_id: Some(SessionId::from_parts(2, [2; 10])),
        pocket_id: Some(PocketId::from_parts(3, [3; 10])),
        request_id: Some(RequestId::from_parts(4, [4; 10])),
        agent_id: Some(AgentId::from_parts(5, [5; 10])),
        correlation_id: CorrelationId::from_parts(6, [6; 10]),
        risk_tier: RiskTier::new(2).unwrap(),
        ..op_event(operation, event_type, version)
    };
    let batch = ledger
        .prepare_reserve(pool(), id, NanoUsd::new(RESERVED), &Actor::System)
        .unwrap();
    let intent = serde_json::json!({"kind": "model_call", "upstream": "primary", "durability": "balanced"});
    journal
        .append(with_delta(
            event(types::OP_RESERVED_INTENT),
            intent,
            &batch.delta().unwrap(),
        ))
        .unwrap();
    let held = ledger.apply(batch);
    if matches!(fate, Fate::OneOpen) {
        drop(held);
        return;
    }
    if matches!(fate, Fate::OneReleased) {
        let batch = ledger.prepare_release(held, &Actor::System).unwrap();
        let fields = serde_json::json!({"reason": "stopped", "sent": false});
        journal
            .append(with_delta(event(types::OP_FAILED), fields, &batch.delta().unwrap()))
            .unwrap();
        ledger.apply(batch);
        return;
    }
    let executing = matches!(fate, Fate::OneExecuting | Fate::OneCommitted);
    if executing {
        journal.append(event(types::OP_EXECUTING)).unwrap();
    }
    match fate {
        Fate::OneCommitted => {
            let batch = ledger
                .prepare_settle(
                    held.begin(),
                    Usage::Reported(NanoUsd::new(RESERVED - 100)),
                    &Actor::System,
                )
                .unwrap();
            let fields = serde_json::json!({"reason": "completed", "usage_final": true});
            journal
                .append(with_delta(event(types::OP_COMMITTED), fields, &batch.delta().unwrap()))
                .unwrap();
            let _settled = ledger.apply(batch);
        }
        Fate::OneAlreadyIndeterminate => {
            // An earlier, complete boot: the full reservation settled, estimated, in the record.
            let batch = ledger
                .prepare_settle(held.begin(), Usage::Unknown, &Actor::System)
                .unwrap();
            let fields = serde_json::json!({
                "reason": CRASH_RECOVERY, "may_have_taken_effect": true, "executing_recorded": false,
            });
            journal
                .append(with_delta(
                    event(types::OP_INDETERMINATE),
                    fields,
                    &batch.delta().unwrap(),
                ))
                .unwrap();
            let _settled = ledger.apply(batch);
            journal.append(earlier_boot(version)).unwrap();
        }
        _ => drop(held.begin()),
    }
}

/// Writes a journal in which each Operation reserved `RESERVED` and then met its fate. An open
/// Operation's reservation stays open, as a crash leaves it.
fn build(world: &World, fates: &[Fate], version: u64) {
    let mut journal = world.open();
    let mut ledger = Ledger::default();
    {
        let mut sink = JournalSink::new(&mut journal, correlation(), None, ConfigVersion(version));
        ledger
            .allocate(
                &mut sink,
                pool(),
                NanoUsd::new(POOL_FUNDS),
                &Actor::System,
                IdempotencyKey::new("fund").unwrap(),
            )
            .unwrap();
    }
    for (n, fate) in fates.iter().enumerate() {
        let operation = op(u8::try_from(n).unwrap());
        if fate.one_record() {
            let id = ReservationId::from_parts(u64::try_from(n).unwrap() + 1, [7; 10]);
            one_record(&mut journal, &mut ledger, operation, id, *fate, version);
            continue;
        }
        let held = {
            let mut sink = JournalSink::new(&mut journal, correlation(), Some(operation), ConfigVersion(version));
            ledger
                .reserve(
                    &mut sink,
                    pool(),
                    ReservationId::from_parts(u64::try_from(n).unwrap() + 1, [7; 10]),
                    NanoUsd::new(RESERVED),
                    &Actor::System,
                )
                .unwrap()
        };
        if *fate == Fate::ReservedOnly {
            drop(held);
            continue;
        }
        journal
            .append(op_event(operation, types::OP_RESERVED_INTENT, version))
            .unwrap();
        match fate {
            Fate::Open | Fate::ReservedOnly => drop(held.begin()),
            Fate::OneOpen
            | Fate::OneExecuting
            | Fate::OneCommitted
            | Fate::OneReleased
            | Fate::OneAlreadyIndeterminate => unreachable!("one-record fates are written above"),
            Fate::Denied => {
                let mut sink = JournalSink::new(&mut journal, correlation(), Some(operation), ConfigVersion(version));
                ledger.release(&mut sink, held, &Actor::System).unwrap();
                journal.append(op_event(operation, types::OP_DENIED, version)).unwrap();
            }
            Fate::Committed | Fate::Failed | Fate::AlreadyIndeterminate => {
                let mut sink = JournalSink::new(&mut journal, correlation(), Some(operation), ConfigVersion(version));
                ledger
                    .settle(
                        &mut sink,
                        held.begin(),
                        Usage::Reported(NanoUsd::new(RESERVED)),
                        &Actor::System,
                    )
                    .unwrap();
                let outcome = match fate {
                    Fate::Committed => types::OP_COMMITTED,
                    Fate::Failed => types::OP_FAILED,
                    _ => types::OP_INDETERMINATE,
                };
                journal.append(op_event(operation, outcome, version)).unwrap();
                if *fate == Fate::AlreadyIndeterminate {
                    // That earlier boot completed: it is no interrupted boot.
                    journal.append(earlier_boot(version)).unwrap();
                }
            }
        }
    }
    // The process dies here: the open reservations and intents stay open.
    drop(journal);
    world.fs.crash();
}

/// A `kernel.booted` an earlier, complete boot journaled.
fn earlier_boot(version: u64) -> EventDraft {
    EventDraft {
        operation_id: None,
        side_effect_class: SideEffectClass::None,
        ..op_event(op(0), types::KERNEL_BOOTED, version)
    }
}

fn count(envelopes: &[EventEnvelope], event_type: &EventType, operation: OperationId) -> usize {
    envelopes
        .iter()
        .filter(|e| e.event_type == *event_type && e.operation_id == Some(operation))
        .count()
}

// ── Drift ───────────────────────────────────────────────────────────────────────

#[test]
fn an_older_configuration_is_refused_before_anything_is_written() {
    let world = World::new();
    build(&world, &[Fate::Open], 5);
    let before = world.records().len();
    let refused = world.boot(&config(4));
    assert!(
        matches!(
            refused,
            Err(BootError::ConfigDrift {
                journaled: ConfigVersion(5),
                configured: ConfigVersion(4)
            })
        ),
        "a configuration older than the journal booted"
    );
    assert_eq!(refused.unwrap_err().code(), uaos_contracts::error::codes::CONFIG_DRIFT);
    world.fs.crash();
    assert_eq!(
        world.records().len(),
        before,
        "boot wrote before refusing a drifted configuration"
    );
    for version in [5, 6] {
        world.fs.crash();
        assert!(world.boot(&config(version)).is_ok(), "version {version}");
    }
}

// ── Intents ─────────────────────────────────────────────────────────────────────

#[test]
fn open_intents_become_indeterminate_once() {
    let world = World::new();
    build(
        &world,
        &[
            Fate::Open,
            Fate::Committed,
            Fate::Failed,
            Fate::AlreadyIndeterminate,
            Fate::Open,
            Fate::Denied,
        ],
        1,
    );
    let booted = world.boot(&config(1)).unwrap();
    assert_eq!(
        booted.report.indeterminate,
        vec![op(0), op(4)],
        "an open intent was not made indeterminate, or a closed one was"
    );
    let envelopes = world.envelopes();
    for (n, expected) in [(0, 1), (1, 0), (2, 0), (3, 1), (4, 1), (5, 0)] {
        assert_eq!(
            count(&envelopes, &types::OP_INDETERMINATE, op(n)),
            expected,
            "operation {n}"
        );
    }
    let made = envelopes
        .iter()
        .find(|e| e.event_type == types::OP_INDETERMINATE && e.operation_id == Some(op(0)))
        .unwrap();
    // The record carries the effect the intent declared, and says it may have happened.
    assert_eq!(
        made.side_effect_class,
        SideEffectClass::External,
        "the indeterminate record hid the intent's effect"
    );
    let payload = made.payload_inline.as_ref().unwrap().as_value();
    assert_eq!(payload["reason"], serde_json::json!(CRASH_RECOVERY));
    assert_eq!(
        payload["may_have_taken_effect"],
        serde_json::json!(true),
        "the indeterminate record does not say the effect may have happened"
    );
    // A second boot finds nothing open.
    drop(booted);
    world.fs.crash();
    let again = world.boot(&config(1)).unwrap();
    assert!(
        again.report.indeterminate.is_empty(),
        "an intent was made indeterminate twice"
    );
    assert_eq!(count(&world.envelopes(), &types::OP_INDETERMINATE, op(0)), 1);
}

// ── The ledger ──────────────────────────────────────────────────────────────────

#[test]
fn an_open_reservation_settles_in_full_and_is_never_released() {
    let world = World::new();
    build(&world, &[Fate::Open, Fate::Committed], 1);
    let booted = world.boot(&config(1)).unwrap();
    assert_eq!(booted.report.settled_estimated, 1, "boot left an open reservation open");
    assert!(booted.report.stuck.is_empty(), "recovery left an item stuck");
    // Settled as estimated, not as a reported cost.
    let estimated = entries_from_journal(&world.records())
        .unwrap()
        .iter()
        .filter(|tx| tx.kind == BudgetTxKind::Settle && tx.estimated)
        .count();
    assert_eq!(estimated, 1, "the open reservation was not settled as estimated");
    let state = booted.ledger.state().pool(pool()).unwrap();
    assert_eq!(
        (state.available, state.held, state.spent),
        (
            NanoUsd::new(POOL_FUNDS - 2 * RESERVED),
            NanoUsd::new(0),
            NanoUsd::new(2 * RESERVED)
        ),
        "boot released money an Operation may have spent"
    );
}

// ── The stop ────────────────────────────────────────────────────────────────────

#[test]
fn a_journaled_stop_boots_stopped_and_recovery_still_runs() {
    let world = World::new();
    build(&world, &[Fate::Open], 1);
    {
        let mut journal = world.open();
        let stop = Stop::running();
        let by = EngagedBy {
            actor: Actor::Human,
            correlation_id: correlation(),
            config_version: ConfigVersion(1),
        };
        let _engaged = stop.engage(StopReason::Operator, by);
        let record = stop.unrecorded().unwrap().draft().unwrap();
        journal.append(record).unwrap();
    }
    world.fs.crash();
    let booted = world.boot(&config(1)).unwrap();
    assert!(booted.stop.is_engaged(), "a journaled stop did not boot stopped");
    assert_eq!(
        booted.report.stop,
        BootState::Stopped(StopReason::Operator),
        "the report hides the stop"
    );
    assert_eq!(
        booted.report.indeterminate,
        vec![op(0)],
        "a stopped kernel skipped recovery"
    );
    assert_eq!(
        booted.report.settled_estimated, 1,
        "a stopped kernel left its ledger open"
    );
    assert!(!booted.report.stop_may_be_lost, "a journaled stop was called lost");
    let envelopes = world.envelopes();
    let record = envelopes.iter().find(|e| e.event_type == types::KERNEL_BOOTED).unwrap();
    assert_eq!(
        record.payload_inline.as_ref().unwrap().as_value()["stopped"],
        serde_json::json!(true),
        "a stopped boot was journaled as running"
    );
}

#[test]
fn a_boot_after_a_crash_says_a_stop_may_be_lost() {
    // Booting running with work left open, a stop engaged just before the crash may not have been
    // journaled.
    let world = World::new();
    build(&world, &[Fate::Open], 1);
    let booted = world.boot(&config(1)).unwrap();
    assert!(
        booted.report.stop_may_be_lost,
        "a crash that may have lost a stop was not said so"
    );
    drop(booted);
    // The run after that boot ends cleanly.
    world.shut_down_cleanly();
    world.fs.crash();
    let clean = world.boot(&config(1)).unwrap();
    assert!(
        !clean.report.stop_may_be_lost,
        "a boot with nothing open claimed a lost stop"
    );
    // A crash between a reserve and its intent leaves only the ledger's work.
    let world = World::new();
    build(&world, &[Fate::ReservedOnly], 1);
    let booted = world.boot(&config(1)).unwrap();
    assert!(booted.report.indeterminate.is_empty());
    assert!(
        booted.report.stop_may_be_lost,
        "a crash that may have lost a stop was not said so"
    );
}

// ── The boot record ─────────────────────────────────────────────────────────────

#[test]
fn every_boot_is_explained_once() {
    let world = World::new();
    build(&world, &[Fate::Open, Fate::Committed], 3);
    let read = world.records().len();
    let booted = world.boot(&config(3)).unwrap();
    let envelopes = world.envelopes();
    let booted_records: Vec<&EventEnvelope> = envelopes
        .iter()
        .filter(|e| e.event_type == types::KERNEL_BOOTED)
        .collect();
    assert_eq!(booted_records.len(), 1, "a boot went unexplained");
    let payload = booted_records[0].payload_inline.as_ref().unwrap().as_value();
    // Against what the fixture holds, not the report itself; 64-bit counters as canonical decimal
    // strings.
    for (field, value) in [
        ("records", serde_json::json!(read.to_string())),
        ("indeterminate", serde_json::json!("1")),
        ("settled_estimated", serde_json::json!("1")),
        ("completed", serde_json::json!("0")),
        ("transfers_completed", serde_json::json!("0")),
        ("stuck", serde_json::json!("0")),
        ("stopped", serde_json::json!(false)),
        ("stop_may_be_lost", serde_json::json!(true)),
        ("config_version", serde_json::json!("3")),
    ] {
        assert_eq!(payload[field], value, "the boot record miscounts {field}");
    }
    assert_eq!(booted.report.records, u64::try_from(read).unwrap());
}

// ── Refusals and failures (the error codes) ──────────────────────────────────────

#[test]
fn records_that_are_not_the_journals_are_refused_before_anything_is_written() {
    // A retry with the records of an earlier attempt would repeat its writes.
    let world = World::new();
    build(&world, &[Fate::Open], 1);
    let mut journal = world.open();
    let records = world.records();
    assert!(
        boot(
            &mut journal,
            &records,
            OpenEvidence::default(),
            &config(1),
            correlation()
        )
        .is_ok()
    );
    let after = world.records().len();
    let retried = boot(
        &mut journal,
        &records,
        OpenEvidence::default(),
        &config(1),
        correlation(),
    );
    assert!(
        matches!(retried, Err(BootError::StaleRecords { .. })),
        "boot wrote over records that are not the journal's"
    );
    assert_eq!(
        retried.err().unwrap().code(),
        uaos_contracts::error::codes::RUNTIME_BOOT_RECORDS_STALE
    );
    // No records, a suffix of them, or another journal's are not this one's.
    let records = world.records();
    let other = World::new();
    build(&other, &[Fate::Open, Fate::Committed], 1);
    let foreign = other.records();
    // A gap, or a record twice, between a genuine first and last.
    let gapped: Vec<_> = records
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, r)| r.clone())
        .collect();
    let mut doubled = records.clone();
    doubled.insert(1, records[1].clone());
    for (case, slice) in [
        ("empty", &records[..0]),
        ("a suffix", &records[1..]),
        ("another journal's", &foreign[..records.len().min(foreign.len())]),
        ("a gap", gapped.as_slice()),
        ("a record twice", doubled.as_slice()),
    ] {
        assert!(
            matches!(
                boot(&mut journal, slice, OpenEvidence::default(), &config(1), correlation()),
                Err(BootError::StaleRecords { .. })
            ),
            "boot accepted records that are not the journal's: {case}"
        );
    }
    assert_eq!(world.records().len(), after, "a refused boot wrote");
}

#[test]
fn a_full_disk_reads_the_same_wherever_boot_meets_it() {
    // A full disk is the journal's failure, with the journal's own code, during the ledger's
    // recovery as at boot's own records.
    let disk_full = |world: &World| {
        let mut journal = world.open();
        let records = world.records();
        world.fs.set_capacity(Some(0));
        boot(
            &mut journal,
            &records,
            OpenEvidence::default(),
            &config(1),
            correlation(),
        )
        .err()
        .unwrap()
    };
    // During the ledger's recovery: an open reservation is its first write.
    let world = World::new();
    build(&world, &[Fate::Open], 1);
    let during_recovery = disk_full(&world);
    assert!(
        matches!(during_recovery, BootError::Journal(_))
            && during_recovery.code() == uaos_contracts::error::codes::JOURNAL_DISK_FULL,
        "a journal failure during recovery lost its code: {during_recovery}"
    );
    // At an open intent, with nothing for the ledger to recover.
    let world = World::new();
    build(&world, &[Fate::Committed], 1);
    {
        let mut journal = world.open();
        journal.append(op_event(op(9), types::OP_RESERVED_INTENT, 1)).unwrap();
    }
    world.fs.crash();
    let at_intent = disk_full(&world);
    assert_eq!(
        at_intent.code(),
        during_recovery.code(),
        "one full disk read as two codes"
    );
}

// ── Convergence ──────────────────────────────.

/// How many `op.indeterminate` each Operation has, read from the records alone: a boot that
/// recovered an Operation twice leaves a journal whose entries the reader then refuses, so this
/// is checked before anything reads the entries.
fn indeterminate_counts(world: &World) -> BTreeMap<OperationId, usize> {
    let mut counts = BTreeMap::new();
    for envelope in world.envelopes() {
        if envelope.event_type == types::OP_INDETERMINATE
            && let Some(operation) = envelope.operation_id
        {
            *counts.entry(operation).or_insert(0) += 1;
        }
    }
    counts
}

/// What boot leaves: the pool's balances and, per Operation, how many `op.indeterminate` the
/// journal holds.
fn outcome(world: &World) -> ((NanoUsd, NanoUsd, NanoUsd), BTreeMap<OperationId, usize>) {
    let records = world.records();
    let entries = entries_from_journal(&records).unwrap();
    // Replay absorbs an identical entry under the same key, so count them.
    let mut keys: BTreeMap<&IdempotencyKey, usize> = BTreeMap::new();
    for tx in &entries {
        *keys.entry(&tx.idempotency_key).or_insert(0) += 1;
    }
    assert!(keys.values().all(|n| *n == 1), "a ledger entry was journaled twice");
    let ledger = Ledger::replay(&entries).unwrap();
    let state = ledger.state().pool(pool()).unwrap();
    ((state.available, state.held, state.spent), indeterminate_counts(world))
}

fn fates() -> impl Strategy<Value = Vec<Fate>> {
    prop::collection::vec(
        prop::sample::select(vec![
            Fate::Open,
            Fate::Committed,
            Fate::Failed,
            Fate::AlreadyIndeterminate,
            Fate::Denied,
            Fate::ReservedOnly,
            Fate::OneOpen,
            Fate::OneExecuting,
            Fate::OneCommitted,
            Fate::OneReleased,
            Fate::OneAlreadyIndeterminate,
        ]),
        1..7,
    )
}

/// The draft a record was appended from.
fn draft_of(envelope: &EventEnvelope) -> EventDraft {
    EventDraft {
        session_id: envelope.session_id,
        pocket_id: envelope.pocket_id,
        operation_id: envelope.operation_id,
        request_id: envelope.request_id,
        agent_id: envelope.agent_id,
        correlation_id: envelope.correlation_id,
        parent_id: envelope.parent_id,
        actor: envelope.actor.clone(),
        event_type: envelope.event_type.clone(),
        payload_ref: envelope.payload_ref,
        payload_inline: envelope.payload_inline.clone(),
        cost_estimate: envelope.cost_estimate,
        compensable: envelope.compensable,
        side_effect_class: envelope.side_effect_class,
        risk_tier: envelope.risk_tier,
        durability: envelope.durability,
        config_version: envelope.config_version,
        metadata: envelope.metadata.clone(),
    }
}

/// What an uncut boot of `fates` leaves, the records it appended, and whether it said a stop may
/// have been lost.
struct Reference {
    expected: ((NanoUsd, NanoUsd, NanoUsd), BTreeMap<OperationId, usize>),
    appended: Vec<EventEnvelope>,
    says_lost: bool,
}

fn reference(fates: &[Fate]) -> Result<Reference, TestCaseError> {
    let world = World::new();
    build(&world, fates, 1);
    let before = world.records().len();
    let first = world.boot(&config(1));
    prop_assert!(first.is_ok(), "an uncut boot failed: {:?}", first.err());
    let says_lost = first.unwrap().report.stop_may_be_lost;
    world.fs.crash();
    let counts = indeterminate_counts(&world);
    prop_assert!(
        counts.values().all(|n| *n == 1),
        "an Operation was recovered twice by an uncut boot: {:?}",
        counts
    );
    let expected = outcome(&world);
    let appended = world.envelopes().split_off(before);
    prop_assert_eq!(
        appended.last().map(|e| e.event_type.clone()),
        Some(types::KERNEL_BOOTED),
        "a boot did not end with its record"
    );
    Ok(Reference {
        expected,
        appended,
        says_lost,
    })
}

/// The next complete boot after an interrupted one, of which `kept` appends survived, converges on
/// what the uncut boot left.
fn converges(world: &World, fates: &[Fate], reference: &Reference, kept: usize) -> Result<(), TestCaseError> {
    let booted = world.boot(&config(1));
    prop_assert!(
        booted.is_ok(),
        "the boot after a crash at append {} failed: {:?}",
        kept,
        booted.as_ref().err()
    );
    let report = booted.unwrap().report;
    world.fs.crash();
    let counts = indeterminate_counts(world);
    prop_assert!(
        counts.values().all(|n| *n == 1),
        "an Operation was recovered twice after a crash at append {}: {:?}",
        kept,
        counts
    );
    prop_assert!(report.stuck.is_empty(), "recovery left an item stuck");
    prop_assert_eq!(
        outcome(world),
        reference.expected.clone(),
        "a crash during boot did not converge"
    );
    // The first complete boot after a crash says what an uncut boot says, even when the interrupted
    // boot closed everything. A cut after recovering only reservations no intent named leaves no
    // evidence: the residual states, which a one-record history does not leave.
    let last_ledger = reference
        .appended
        .iter()
        .rposition(|e| e.event_type == types::BUDGET_ENTRY);
    let residual = !fates.iter().any(|fate| fate.open())
        && fates.contains(&Fate::ReservedOnly)
        && last_ledger.is_some_and(|last| kept > last);
    if kept < reference.appended.len() && !residual {
        prop_assert_eq!(
            report.stop_may_be_lost,
            reference.says_lost,
            "an interrupted boot hid a lost stop"
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// For random journals in both forms, a boot cut after its n-th append, for every n, then a
    /// full boot, leaves what a boot with no cut leaves: the same balances, every open intent
    /// indeterminate, and no Operation recovered twice. The cut journal holds exactly the first n
    /// records a real boot appended, which is what a crash between two appends leaves (an
    /// acknowledged append survives a crash, and open cuts a torn one).
    #[test]
    fn a_crash_during_boot_converges(fates in fates()) {
        let reference = reference(&fates)?;
        for n in 0..=reference.appended.len() {
            let world = World::new();
            build(&world, &fates, 1);
            {
                let mut journal = world.open();
                for envelope in &reference.appended[..n] {
                    journal.append(draft_of(envelope)).unwrap();
                }
            }
            world.fs.crash();
            converges(&world, &fates, &reference, n)?;
        }
    }

    /// Power loss during boot. Boot runs under the default balanced flush policy, the OS writes
    /// back a part of its unflushed bytes (none, a quarter, a half, three quarters, all), and the
    /// machine loses power: the journal keeps its durable prefix, which may end inside a record.
    /// The next boot converges as after a cut.
    #[test]
    fn a_power_loss_during_boot_converges(fates in fates()) {
        let reference = reference(&fates)?;
        for quarters in 0..=4 {
            let world = World::new();
            build(&world, &fates, 1);
            let before = world.records().len();
            prop_assert!(world.boot_with(&config(1), FlushPolicy::default()).is_ok());
            world.write_back_part(quarters, 4);
            world.fs.power_loss();
            let kept = world.records().len().saturating_sub(before);
            prop_assert!(kept <= reference.appended.len());
            converges(&world, &fates, &reference, kept)?;
        }
    }
}

// ── What the records carry ───────────────────────────────────────────

#[test]
fn a_closed_operation_stays_closed_and_its_first_intent_speaks() {
    // An intent after an outcome does not reopen the Operation. An open Operation's record carries
    // its first intent's effect.
    let world = World::new();
    build(&world, &[Fate::Committed], 1);
    {
        let mut journal = world.open();
        journal.append(op_event(op(0), types::OP_RESERVED_INTENT, 1)).unwrap();
        journal.append(op_event(op(7), types::OP_RESERVED_INTENT, 1)).unwrap();
        let quieter = EventDraft {
            side_effect_class: SideEffectClass::None,
            ..op_event(op(7), types::OP_RESERVED_INTENT, 1)
        };
        journal.append(quieter).unwrap();
    }
    world.fs.crash();
    let booted = world.boot(&config(1)).unwrap();
    assert_eq!(
        booted.report.indeterminate,
        vec![op(7)],
        "a closed Operation was reopened"
    );
    let made = world
        .envelopes()
        .into_iter()
        .find(|e| e.event_type == types::OP_INDETERMINATE && e.operation_id == Some(op(7)))
        .unwrap();
    assert_eq!(
        made.side_effect_class,
        SideEffectClass::External,
        "the indeterminate record did not carry the first intent's effect"
    );
}

#[test]
fn a_boot_after_complete_boots_claims_no_lost_stop() {
    // The evidence of an interrupted boot is read after the last boot record, not the first.
    // Since S8 a clean shutdown decides the last case; `an_old_journal_is_unknown` (startup)
    // tells the last boot record from the first.
    let world = World::new();
    build(&world, &[Fate::Open], 1);
    assert!(world.boot(&config(1)).unwrap().report.stop_may_be_lost);
    world.fs.crash();
    {
        let mut journal = world.open();
        journal.append(op_event(op(8), types::OP_RESERVED_INTENT, 1)).unwrap();
    }
    world.fs.crash();
    assert!(world.boot(&config(1)).unwrap().report.stop_may_be_lost);
    world.shut_down_cleanly();
    world.fs.crash();
    assert!(
        !world.boot(&config(1)).unwrap().report.stop_may_be_lost,
        "a clean boot after complete boots claimed a lost stop"
    );
}

#[test]
fn recovery_records_carry_the_operations_ids_and_honest_flags() {
    // The indeterminate record carries the intent's correlation and links to it, is not
    // compensable, and is critical. Recovery settles as the system. The boot record is critical,
    // surfaces when it recovered, and is routine when nothing was open.
    let world = World::new();
    build(&world, &[Fate::Open], 1);
    let mut journal = world.open();
    let records = world.records();
    let boot_correlation = CorrelationId::from_parts(5, [5; 10]);
    let booted = boot(
        &mut journal,
        &records,
        OpenEvidence::default(),
        &config(1),
        boot_correlation,
    )
    .unwrap();
    drop(journal);
    let envelopes = world.envelopes();
    let intent = envelopes
        .iter()
        .find(|e| e.event_type == types::OP_RESERVED_INTENT)
        .unwrap();
    let made = envelopes
        .iter()
        .find(|e| e.event_type == types::OP_INDETERMINATE)
        .unwrap();
    assert_eq!(
        made.parent_id,
        Some(intent.id),
        "the indeterminate record lost its intent"
    );
    assert_eq!(
        made.correlation_id, intent.correlation_id,
        "the indeterminate record lost the Operation's correlation"
    );
    assert!(
        !made.compensable && made.durability == Durability::Critical,
        "the indeterminate record claims what it cannot"
    );
    let settle = entries_from_journal(&world.records())
        .unwrap()
        .into_iter()
        .find(|tx| tx.kind == BudgetTxKind::Settle && tx.estimated)
        .unwrap();
    assert_eq!(settle.principal, Actor::System, "recovery settled as someone else");
    let first = envelopes.iter().find(|e| e.event_type == types::KERNEL_BOOTED).unwrap();
    assert_eq!(
        (first.durability, first.risk_tier, first.correlation_id),
        (Durability::Critical, RiskTier::MAX, boot_correlation),
        "a recovering boot was journaled as routine"
    );
    drop(booted);
    world.shut_down_cleanly();
    world.fs.crash();
    assert!(world.boot(&config(1)).is_ok());
    let clean = world
        .envelopes()
        .into_iter()
        .rev()
        .find(|e| e.event_type == types::KERNEL_BOOTED)
        .unwrap();
    assert_eq!(
        clean.risk_tier,
        RiskTier::MIN,
        "a clean boot was journaled as a recovery"
    );
}

#[test]
fn the_indeterminate_record_carries_the_intents_ids() {
    // Every id the intent carries is the Operation's, and its record keeps them.
    let world = World::new();
    build(&world, &[Fate::Committed], 1);
    let intent = EventDraft {
        session_id: Some(SessionId::from_parts(2, [2; 10])),
        pocket_id: Some(PocketId::from_parts(3, [3; 10])),
        request_id: Some(RequestId::from_parts(4, [4; 10])),
        agent_id: Some(AgentId::from_parts(5, [5; 10])),
        risk_tier: RiskTier::new(2).unwrap(),
        ..op_event(op(6), types::OP_RESERVED_INTENT, 1)
    };
    {
        let mut journal = world.open();
        journal.append(intent).unwrap();
    }
    world.fs.crash();
    assert!(world.boot(&config(1)).is_ok());
    let envelopes = world.envelopes();
    let of = |event_type: &EventType| {
        envelopes
            .iter()
            .find(|e| e.event_type == *event_type && e.operation_id == Some(op(6)))
            .unwrap()
    };
    let (written, made) = (of(&types::OP_RESERVED_INTENT), of(&types::OP_INDETERMINATE));
    assert_eq!(
        (
            made.session_id,
            made.pocket_id,
            made.request_id,
            made.agent_id,
            made.risk_tier
        ),
        (
            written.session_id,
            written.pocket_id,
            written.request_id,
            written.agent_id,
            written.risk_tier
        ),
        "the indeterminate record dropped the Operation's ids"
    );
    assert!(made.session_id.is_some() && made.agent_id.is_some());
}

/// The open says which records are its own and which record a clean end's seal names. Its own
/// records after a sealed shutdown leave the end clean.
#[test]
fn only_a_proven_shutdown_is_clean_and_the_opens_own_records_do_not_count() {
    let world = World::new();
    assert!(world.boot(&config(1)).is_ok());
    world.shut_down_cleanly();
    // A record the next open appends itself after the shutdown, as it does a loss it reports.
    // Boot tells the open's own records by sequence number, whatever their type.
    let mut journal = world.open();
    let own = journal.append(op_event(op(9), types::OP_COMMITTED, 1)).unwrap().seq;
    drop(journal);
    let records = world.records();
    let shutdown = records
        .iter()
        .rfind(|r| r.envelope.event_type == types::KERNEL_SHUTDOWN)
        .unwrap()
        .envelope
        .seq;
    let run = |evidence: OpenEvidence| {
        let world_records = world.records();
        let mut journal = world.open();
        let report = boot(&mut journal, &world_records, evidence, &config(1), correlation())
            .unwrap()
            .report;
        drop(journal);
        world.fs.crash();
        report.last_end
    };
    let proven = OpenEvidence {
        sealed: Some(shutdown),
        own_from: Some(own),
    };
    assert_eq!(
        run(proven),
        LastEnd::Clean,
        "the open's own record after a durable shutdown made the end a crash"
    );
}

#[test]
fn a_seal_naming_another_record_is_a_crash() {
    let world = World::new();
    assert!(world.boot(&config(1)).is_ok());
    world.shut_down_cleanly();
    let records = world.records();
    let shutdown = records.last().unwrap().envelope.seq;
    let mut journal = world.open();
    let report = boot(
        &mut journal,
        &records,
        OpenEvidence {
            sealed: Some(Seq(shutdown.0 - 1)),
            own_from: None,
        },
        &config(1),
        correlation(),
    )
    .unwrap()
    .report;
    assert_eq!(
        report.last_end,
        LastEnd::Crashed,
        "a shutdown no seal names was read as clean"
    );
}

// ── One-record recovery ──────────────.

/// The reservation `build` names for its `n`-th Operation.
fn reservation(n: u8) -> ReservationId {
    ReservationId::from_parts(u64::from(n) + 1, [7; 10])
}

#[test]
fn an_open_one_record_operation_recovers_in_its_own_record() {
    let world = World::new();
    build(&world, &[Fate::OneOpen, Fate::OneExecuting], 1);
    let before = world.records().len();
    let booted = world.boot(&config(1)).unwrap();
    let envelopes = world.envelopes();
    let appended = &envelopes[before..];
    assert!(
        appended.iter().all(|e| e.event_type != types::BUDGET_ENTRY),
        "a one-record recovery entry was journaled under boot's correlation"
    );
    for (n, executing) in [(0, false), (1, true)] {
        let operation = op(n);
        let intent = envelopes
            .iter()
            .find(|e| e.event_type == types::OP_RESERVED_INTENT && e.operation_id == Some(operation))
            .unwrap();
        let made: Vec<_> = appended
            .iter()
            .filter(|e| e.event_type == types::OP_INDETERMINATE && e.operation_id == Some(operation))
            .collect();
        assert_eq!(made.len(), 1, "Operation {n} was not recovered once");
        let made = made[0];
        assert_eq!(
            (
                made.parent_id,
                made.correlation_id,
                made.session_id,
                made.pocket_id,
                made.request_id,
                made.agent_id,
                made.risk_tier,
                made.side_effect_class,
            ),
            (
                Some(intent.id),
                intent.correlation_id,
                intent.session_id,
                intent.pocket_id,
                intent.request_id,
                intent.agent_id,
                intent.risk_tier,
                intent.side_effect_class,
            ),
            "a recovery record is not attributed to its Operation"
        );
        assert!(made.session_id.is_some() && made.correlation_id != correlation());
        let payload = made.payload_inline.as_ref().unwrap().as_value();
        assert_eq!(
            payload["executing_recorded"],
            serde_json::json!(executing),
            "the recovery record hides the Operation's op.executing"
        );
        assert_eq!(
            (&payload["reason"], &payload["may_have_taken_effect"]),
            (&serde_json::json!(CRASH_RECOVERY), &serde_json::json!(true))
        );
        let delta: LedgerDelta = serde_json::from_value(payload[LEDGER_FIELD].clone()).unwrap();
        assert_eq!(delta.reservation, reservation(n));
        assert_eq!(
            delta
                .entries
                .iter()
                .map(|entry| (entry.kind, entry.amount, entry.estimated))
                .collect::<Vec<_>>(),
            [(BudgetTxKind::Settle, NanoUsd::new(RESERVED), true)],
            "the reservation was not settled in full, estimated, in its Operation's record"
        );
    }
    let report = &booted.report;
    assert_eq!(report.indeterminate, [op(0), op(1)]);
    assert_eq!((report.indeterminate_settled, report.settled_estimated), (2, 0));
    let record = appended.last().unwrap().payload_inline.as_ref().unwrap().as_value();
    assert_eq!(
        (&record["indeterminate_settled"], &record["settled_estimated"]),
        (&serde_json::json!("2"), &serde_json::json!("0"))
    );
    assert!(!booted.ledger.needs_recovery());
    assert_eq!(booted.ledger.state().open_reservations(), 0);
}

/// A crafted `budget.entry` on pool 9: an allocation of 0 under `key`, so the recovery entry that
/// needs that key is refused (a stuck item), or the transfer `t` from the main pool, whose own
/// `transfer_in` never landed.
fn crafted(
    key: &str,
    kind: BudgetTxKind,
    pool_id: PoolId,
    amount: i64,
    before: i64,
    counterparty: Option<PoolId>,
) -> BudgetTx {
    BudgetTx {
        schema: BudgetTxSchema::V1,
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        pool_id,
        principal: Actor::System,
        session_id: None,
        kind,
        amount: NanoUsd::new(amount),
        balance_before: NanoUsd::new(before),
        balance_after: NanoUsd::new(
            before
                - if kind == BudgetTxKind::TransferOut {
                    amount
                } else {
                    -amount
                },
        ),
        reason_code: ReasonCode::new(if kind == BudgetTxKind::TransferOut {
            "transfer"
        } else {
            "allocate"
        })
        .unwrap(),
        related_event: None,
        reservation_id: None,
        counterparty_pool: counterparty,
        settled: false,
        estimated: false,
    }
}

#[test]
fn stuck_items_are_counted_by_kind_on_this_boot_and_the_next() {
    let world = World::new();
    // A one-record and a two-record Operation left open, each with its settlement's key taken,
    // and a transfer whose second half's key is taken.
    build(&world, &[Fate::OneOpen, Fate::Open], 1);
    let available = Ledger::replay(&entries_from_journal(&world.records()).unwrap())
        .unwrap()
        .state()
        .pool(pool())
        .unwrap()
        .available
        .get();
    {
        let mut journal = world.open();
        let mut sink = JournalSink::new(&mut journal, correlation(), None, ConfigVersion(1));
        let side = PoolId::from_parts(9, [9; 10]);
        for key in [
            format!("{}:settle", reservation(0)),
            format!("{}:settle", reservation(1)),
            "t:in".to_owned(),
        ] {
            sink.record(&crafted(&key, BudgetTxKind::Allocate, side, 0, 0, None))
                .unwrap();
        }
        sink.record(&crafted(
            "t",
            BudgetTxKind::TransferOut,
            pool(),
            10,
            available,
            Some(side),
        ))
        .unwrap();
    }
    world.fs.crash();
    let counts = |booted: &Booted| {
        let record = world.envelopes().last().unwrap().payload_inline.clone().unwrap();
        let record = record.as_value();
        (
            booted.report.stuck.len(),
            record["stuck"].clone(),
            record["stuck_reservations"].clone(),
            record["stuck_transfers"].clone(),
        )
    };
    let expected = (
        3,
        serde_json::json!("3"),
        serde_json::json!("2"),
        serde_json::json!("1"),
    );
    let first = world.boot(&config(1)).unwrap();
    assert_eq!(counts(&first), expected, "the first boot miscounted the stuck items");
    assert!(first.ledger.needs_recovery(), "the ledger went live with items stuck");
    world.fs.crash();
    let next = world.boot(&config(1)).unwrap();
    assert_eq!(
        counts(&next),
        expected,
        "the next boot counted the stuck items differently"
    );
    assert_eq!(next.report.stuck, first.report.stuck);
    assert!(next.ledger.needs_recovery(), "the ledger went live with items stuck");
}

/// A stuck reservation stays open from boot to boot until repaired, and `kernel.booted` already
/// counts it, so a clean shutdown whose only open reservation is a stuck item counts 0, and the
/// next boot does not say a stop may have been lost.
#[tokio::test]
#[allow(
    clippy::disallowed_methods,
    reason = "joining the actor's thread blocks: the test waits for it off the runtime's threads"
)]
async fn a_clean_shutdown_does_not_count_a_stuck_item() {
    let world = World::new();
    // A one-record Operation left open, its settlement's key taken: boot leaves it stuck.
    let (journal, booted) = left_stuck(&world, &[Fate::OneOpen]);
    assert_eq!(booted.report.stuck.len(), 1);

    // The run: the state actor, the ledger task holding the stuck item, admission; then a clean
    // shutdown.
    let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default());
    let (state, queue) = state_queue(DEFAULT_QUEUE_CAPACITY);
    let actor = start_state_actor(&supervisor, StateCore::new(journal), queue).unwrap();
    let by = EngagedBy {
        actor: Actor::Human,
        correlation_id: correlation(),
        config_version: ConfigVersion(1),
    };
    let (ledger, _task) = start_ledger_task(
        &supervisor,
        booted.ledger,
        state.clone(),
        booted.stop.clone(),
        by.clone(),
        DEFAULT_LEDGER_QUEUE,
    )
    .unwrap();
    let admission = Admission::new(AdmissionLimits::default(), booted.stop.clone());
    shut_down(&admission, &state, Some(&ledger), by, Duration::from_secs(1))
        .await
        .unwrap();
    drop((ledger, state));
    tokio::task::spawn_blocking(move || actor.join().unwrap())
        .await
        .unwrap();

    let shutdown = world
        .envelopes()
        .into_iter()
        .rev()
        .find(|e| e.event_type == types::KERNEL_SHUTDOWN)
        .unwrap();
    assert_eq!(
        shutdown.payload_inline.unwrap().as_value()["open_operations"],
        "0",
        "a stuck item was counted as work left open"
    );
    let next = world.boot(&config(1)).unwrap();
    assert_eq!(next.report.last_end, LastEnd::Clean);
    assert!(
        !next.report.stop_may_be_lost,
        "a stuck item made the next boot say a stop may have been lost"
    );
    assert_eq!(next.report.stuck, booted.report.stuck);
}

/// Each Operation of `fates` left open with its settlement's key taken, then booted: boot leaves
/// each reservation stuck. Returns the booted journal, ready for the run after the boot.
fn left_stuck(world: &World, fates: &[Fate]) -> (Journal, Booted) {
    build(world, fates, 1);
    {
        let mut journal = world.open();
        let mut sink = JournalSink::new(&mut journal, correlation(), None, ConfigVersion(1));
        let side = PoolId::from_parts(9, [9; 10]);
        for n in 0..fates.len() {
            let key = format!("{}:settle", reservation(u8::try_from(n).unwrap()));
            sink.record(&crafted(&key, BudgetTxKind::Allocate, side, 0, 0, None))
                .unwrap();
        }
    }
    world.fs.crash();
    let clock: Arc<dyn Clock> = world.clock.clone();
    let rng: Arc<dyn Rng> = world.rng.clone();
    let opened =
        Journal::open_verified(Arc::new(world.fs.clone()), clock, rng, &world.data, FlushPolicy::Strict).unwrap();
    let mut journal = opened.journal;
    let booted = boot(
        &mut journal,
        &opened.records,
        opened.evidence,
        &config(1),
        correlation(),
    )
    .unwrap();
    (journal, booted)
}

/// The journal after the repairs: Operations 0 to 2 (one-record) each have one resolution
/// record, written by the human, reason `stuck_repair`, no `sent`, of the type its repair
/// names (0 settled and committed, 1 settled and failed, 2 released); Operation 3 (two-record) is
/// released in `budget.entry` records. Every repair entry reads, with its reason and principal.
fn assert_repaired(world: &World) {
    let envelopes = world.envelopes();
    for (n, event_type, resolution) in [
        (0, types::OP_COMMITTED, "settled"),
        (1, types::OP_FAILED, "settled"),
        (2, types::OP_FAILED, "released"),
    ] {
        let resolutions: Vec<_> = envelopes
            .iter()
            .filter(|e| {
                e.operation_id == Some(op(n)) && [types::OP_COMMITTED, types::OP_FAILED].contains(&e.event_type)
            })
            .collect();
        assert_eq!(resolutions.len(), 1, "the repair is not the Operation's one resolution");
        let found = resolutions[0];
        assert_eq!(
            found.event_type, event_type,
            "a repair's outcome wrote the wrong record type"
        );
        let payload = found.payload_inline.as_ref().unwrap().as_value();
        assert_eq!(
            (payload["reason"].clone(), payload["resolution"].clone()),
            (serde_json::json!("stuck_repair"), serde_json::json!(resolution))
        );
        assert!(payload.get("sent").is_none(), "a repair wrote `sent`");
        assert_eq!(found.actor, Actor::Human);
    }
    let entries = entries_from_journal(&world.records()).unwrap();
    let repaired = |n: u8, kind: BudgetTxKind| {
        entries.iter().any(|tx| {
            tx.reservation_id == Some(reservation(n))
                && tx.kind == kind
                && tx.reason_code.as_str() == "stuck_repair"
                && tx.principal == Actor::Human
        })
    };
    for n in [0, 1] {
        assert!(repaired(n, BudgetTxKind::Settle) && repaired(n, BudgetTxKind::Release));
    }
    assert!(repaired(2, BudgetTxKind::Release) && repaired(3, BudgetTxKind::Release));
}

/// Operation `n`'s record fields and its intent's event id, as the journal holds them.
fn resolution(world: &World, n: u8) -> (OperationRecord, EventId) {
    let intent = world
        .envelopes()
        .into_iter()
        .find(|e| e.event_type == types::OP_RESERVED_INTENT && e.operation_id == Some(op(n)))
        .unwrap();
    (operation_record(&intent), intent.id)
}

/// The run after a boot: the state actor on `journal` and the ledger task holding `ledger`.
fn run_after_boot(
    journal: Journal,
    ledger: Ledger,
    stop: &Stop,
) -> (Supervisor, StateHandle, StateActor, LedgerHandle, EngagedBy) {
    let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default());
    let (state, queue) = state_queue(DEFAULT_QUEUE_CAPACITY);
    let actor = start_state_actor(&supervisor, StateCore::new(journal), queue).unwrap();
    let engaged_by = EngagedBy {
        actor: Actor::Human,
        correlation_id: correlation(),
        config_version: ConfigVersion(1),
    };
    let (ledger, _task) = start_ledger_task(
        &supervisor,
        ledger,
        state.clone(),
        stop.clone(),
        engaged_by.clone(),
        DEFAULT_LEDGER_QUEUE,
    )
    .unwrap();
    (supervisor, state, actor, ledger, engaged_by)
}

/// An Operation's record fields, as its intent holds them.
fn operation_record(intent: &EventEnvelope) -> OperationRecord {
    let payload = intent.payload_inline.as_ref().unwrap().as_value();
    OperationRecord {
        operation_id: intent.operation_id.unwrap(),
        session_id: intent.session_id,
        pocket_id: intent.pocket_id,
        request_id: intent.request_id,
        agent_id: intent.agent_id,
        correlation_id: intent.correlation_id,
        actor: intent.actor.clone(),
        kind: serde_json::from_value::<OperationKind>(payload["kind"].clone()).unwrap(),
        upstream: payload["upstream"].as_str().unwrap().to_owned(),
        side_effect_class: intent.side_effect_class,
        compensable: intent.compensable,
        risk_tier: intent.risk_tier,
        config_version: intent.config_version,
    }
}

/// row 18 (the task's side): a stuck item's repair through the ledger task. A one-record
/// reservation's is its Operation's resolution record, after the entry-less `op.indeterminate` that
/// left it stuck: `op.committed` or `op.failed` for a settlement by its outcome, `op.failed` for a
/// release, each with reason `stuck_repair`, actor `human`, and no `sent`. Named with another
/// Operation's record it is refused and writes nothing. A two-record reservation's is
/// `budget.entry` records. Once the last is repaired the ledger accepts new work, the journal
/// reads, and the next boot finds nothing stuck.
#[tokio::test]
#[allow(
    clippy::disallowed_methods,
    reason = "joining the actor's thread blocks: the test waits for it off the runtime's threads"
)]
async fn a_repair_through_the_ledger_task_resolves_its_stuck_item() {
    let world = World::new();
    // Three one-record Operations and a two-record one, each left stuck.
    let fates = [Fate::OneOpen, Fate::OneOpen, Fate::OneOpen, Fate::Open];
    let (journal, booted) = left_stuck(&world, &fates);
    let item = |n: u8| {
        booted
            .report
            .stuck
            .iter()
            .find(|item| item.kind == StuckKind::Reservation(reservation(n)))
            .cloned()
            .unwrap()
    };
    let items = [item(0), item(1), item(2), item(3)];
    let stop = booted.stop.clone();
    let (_supervisor, state, actor, ledger, engaged_by) = run_after_boot(journal, booted.ledger, &stop);
    let by = |resolves| RepairBy {
        principal: Actor::Human,
        correlation_id: correlation(),
        config_version: ConfigVersion(1),
        resolves,
    };
    let settle = |outcome| Repair::Settle {
        amount: NanoUsd::new(40),
        outcome,
    };
    // Named with another Operation's record, a one-record repair is refused and writes nothing.
    let (record, intent) = resolution(&world, 0);
    let mut other = record.clone();
    other.operation_id = op(1);
    let refused = ledger
        .repair(
            items[0].clone(),
            settle(RepairOutcome::Committed),
            by(Some((other, intent))),
        )
        .await
        .unwrap_err();
    assert!(matches!(refused, LedgerCallError::Record(_)), "{refused:?}");
    // The ledger, not the item's reason, says which form a repair takes: a listing taken at another
    // time may give the same item another reason (of E4).
    let relisted = StuckItem {
        kind: items[0].kind.clone(),
        reason: ReasonCode::new("awaiting_repair").unwrap(),
    };
    ledger
        .repair(relisted, settle(RepairOutcome::Committed), by(Some((record, intent))))
        .await
        .unwrap();
    let failed = settle(RepairOutcome::Failed);
    ledger
        .repair(items[1].clone(), failed, by(Some(resolution(&world, 1))))
        .await
        .unwrap();
    ledger
        .repair(items[2].clone(), Repair::Release, by(Some(resolution(&world, 2))))
        .await
        .unwrap();
    ledger
        .repair(items[3].clone(), Repair::Release, by(None))
        .await
        .unwrap();
    let snapshot = ledger.snapshot().await.unwrap();
    assert!(
        !snapshot.needs_recovery,
        "the last repair left the ledger refusing new work"
    );
    let admission = Admission::new(AdmissionLimits::default(), stop.clone());
    shut_down(&admission, &state, Some(&ledger), engaged_by, Duration::from_secs(1))
        .await
        .unwrap();
    drop((ledger, state));
    tokio::task::spawn_blocking(move || actor.join().unwrap())
        .await
        .unwrap();

    assert_repaired(&world);
    let next = world.boot(&config(1)).unwrap();
    assert!(
        next.report.stuck.is_empty(),
        "a repaired item was stuck on the next boot"
    );
    assert_eq!(next.report.last_end, LastEnd::Clean);
    assert!(!next.ledger.needs_recovery());
}
