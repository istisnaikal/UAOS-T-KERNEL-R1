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

use proptest::prelude::*;
use uaos_contracts::budget::{BudgetTxKind, IdempotencyKey};
use uaos_contracts::event::{Actor, Durability, EventEnvelope, EventType, InlinePayload, Metadata, types};
use uaos_contracts::id::{
    AgentId, CorrelationId, OperationId, PocketId, PoolId, RequestId, ReservationId, SessionId, TypedId,
};
use uaos_contracts::money::NanoUsd;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::{ConfigVersion, Seq};
use uaos_ledger::{JournalSink, Ledger, Usage, entries_from_journal};
use uaos_platform::fs::Fs;
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, Rng};
use uaos_runtime::{
    BootError, BootState, Booted, CRASH_RECOVERY, ConfigSnapshot, EngagedBy, LastEnd, LocaleTag, Stop, StopReason, boot,
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
        let clock: Arc<dyn Clock> = self.clock.clone();
        let rng: Arc<dyn Rng> = self.rng.clone();
        let opened =
            Journal::open_verified(Arc::new(self.fs.clone()), clock, rng, &self.data, FlushPolicy::Strict).unwrap();
        let mut journal = opened.journal;
        boot(&mut journal, &opened.records, opened.evidence, config, correlation())
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

// ── Convergence ────────────────────────────────────────────────────────────────────────

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
    let mut indeterminate = BTreeMap::new();
    for record in &records {
        if record.envelope.event_type == types::OP_INDETERMINATE
            && let Some(operation) = record.envelope.operation_id
        {
            *indeterminate.entry(operation).or_insert(0) += 1;
        }
    }
    ((state.available, state.held, state.spent), indeterminate)
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
        ]),
        1..6,
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// For random journals, a boot cut after its n-th append, for every n, then a full boot,
    /// leaves what a boot with no cut leaves: the same balances, every open intent
    /// indeterminate, and no Operation indeterminate twice. The cut journal holds exactly the
    /// first n records a real boot appended, which is what a crash between two appends leaves
    /// (an acknowledged append survives a crash, and open cuts a torn one).
    #[test]
    fn a_crash_during_boot_converges(fates in fates()) {
        let reference = World::new();
        build(&reference, &fates, 1);
        let before = reference.records().len();
        let first = reference.boot(&config(1));
        prop_assert!(first.is_ok());
        let says_lost = first.unwrap().report.stop_may_be_lost;
        reference.fs.crash();
        let expected = outcome(&reference);
        prop_assert!(
            expected.1.values().all(|n| *n == 1),
            "a boot made an Operation indeterminate twice"
        );
        let appended = reference.envelopes().split_off(before);
        let last_ledger = appended.iter().rposition(|e| e.event_type == types::BUDGET_ENTRY);
        prop_assert_eq!(
            appended.last().map(|e| e.event_type.clone()),
            Some(types::KERNEL_BOOTED),
            "a boot did not end with its record"
        );

        for n in 0..=appended.len() {
            let world = World::new();
            build(&world, &fates, 1);
            {
                let mut journal = world.open();
                for envelope in &appended[..n] {
                    journal.append(draft_of(envelope)).unwrap();
                }
            }
            world.fs.crash();
            let booted = world.boot(&config(1));
            prop_assert!(booted.is_ok(), "the boot after a crash at append {} failed", n);
            let report = booted.unwrap().report;
            prop_assert!(report.stuck.is_empty(), "recovery left an item stuck");
            world.fs.crash();
            prop_assert_eq!(outcome(&world), expected.clone(), "a crash during boot did not converge");
            // The first complete boot after a crash says what an uncut boot says, even when the
            // interrupted boot closed everything. A cut after recovering a reservation no intent
            // named leaves no evidence: the residual §2 step 5 states, which one-record intent
            // removes.
            let residual = !fates.contains(&Fate::Open)
                && fates.contains(&Fate::ReservedOnly)
                && last_ledger.is_some_and(|last| n > last);
            if n < appended.len() && !residual {
                prop_assert_eq!(report.stop_may_be_lost, says_lost, "an interrupted boot hid a lost stop");
            }
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
