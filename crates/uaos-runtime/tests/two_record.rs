// SPDX-License-Identifier: Apache-2.0

//! The two-record form still boots (intent contract). A journal written by the writer every kernel
//! before used, two records per intent and no `ledger` delta anywhere, is committed as bytes under
//! `tests/fixtures/two-record/`. It holds a committed Operation with no `op.executing` before its
//! commit, an open Operation with a second intent, and a denied one. Booted. Boot's record gained
//! fields in slice E3 (`indeterminate_settled`, `stuck_reservations`, `stuck_transfers`): only
//! `kernel.booted` changed, and only by those counts, which are 0 here.
//!
//! `cargo test -p uaos-runtime --test two_record -- --ignored` rewrites the fixture with the
//! writer of the day; it is run once, when the fixture is made, never to make a test pass.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::json;
use uaos_contracts::budget::IdempotencyKey;
use uaos_contracts::event::{Actor, Durability, EventEnvelope, EventType, Metadata, types};
use uaos_contracts::id::{CorrelationId, OperationId, PoolId, ReservationId, TypedId};
use uaos_contracts::money::NanoUsd;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::ConfigVersion;
use uaos_ledger::{Held, JournalSink, Ledger, Reservation, Usage, entries_from_journal};
use uaos_platform::fs::Fs;
use uaos_platform::real::fs::OsFs;
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, Rng};
use uaos_runtime::{ConfigSnapshot, LastEnd, LocaleTag, boot};
use uaos_state::journal::{EventDraft, FlushPolicy, JOURNAL_DIR, Journal, read_verified};

const DATA: &str = "/data";

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/two-record")
}

fn op(n: u8) -> OperationId {
    OperationId::from_parts(u64::from(n), [n; 10])
}

fn rsv(n: u8) -> ReservationId {
    ReservationId::from_parts(u64::from(n), [n; 10])
}

fn pool() -> PoolId {
    PoolId::from_parts(1, [1; 10])
}

fn correlation() -> CorrelationId {
    CorrelationId::from_parts(9, [9; 10])
}

struct World {
    fs: SimFs,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
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
            rng: Arc::new(SimRng::new(23)),
        }
    }

    fn open(&self) -> Journal {
        Journal::open(
            Arc::new(self.fs.clone()),
            self.clock.clone(),
            self.rng.clone(),
            Path::new(DATA),
            FlushPolicy::Strict,
        )
        .unwrap()
    }

    fn envelopes(&self) -> Vec<EventEnvelope> {
        read_verified(&self.fs, &Path::new(DATA).join(JOURNAL_DIR))
            .unwrap()
            .0
            .into_iter()
            .map(|r| r.envelope)
            .collect()
    }
}

fn op_event(operation: OperationId, event_type: EventType) -> EventDraft {
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
        config_version: ConfigVersion(1),
        metadata: Metadata::default(),
    }
}

/// The reserve `budget.entry`, the first of the two records.
fn reserve(journal: &mut Journal, ledger: &mut Ledger, operation: OperationId, id: ReservationId) -> Reservation<Held> {
    let mut sink = JournalSink::new(journal, correlation(), Some(operation), ConfigVersion(1));
    ledger
        .reserve(&mut sink, pool(), id, NanoUsd::new(300), &Actor::System)
        .unwrap()
}

/// The journal in the two-record form, as the writer before left it.
fn write_two_record_journal(world: &World) {
    let mut journal = world.open();
    let mut ledger = Ledger::default();
    {
        let mut sink = JournalSink::new(&mut journal, correlation(), None, ConfigVersion(1));
        ledger
            .allocate(
                &mut sink,
                pool(),
                NanoUsd::new(10_000),
                &Actor::System,
                IdempotencyKey::new("fund").unwrap(),
            )
            .unwrap();
    }
    // 1: committed, with no `op.executing` before the commit: two-record journals have none.
    let held = reserve(&mut journal, &mut ledger, op(1), rsv(1));
    journal.append(op_event(op(1), types::OP_RESERVED_INTENT)).unwrap();
    {
        let mut sink = JournalSink::new(&mut journal, correlation(), Some(op(1)), ConfigVersion(1));
        ledger
            .settle(
                &mut sink,
                held.begin(),
                Usage::Reported(NanoUsd::new(200)),
                &Actor::System,
            )
            .unwrap();
    }
    journal.append(op_event(op(1), types::OP_COMMITTED)).unwrap();
    // 2: open, with a second intent; boot reads the first.
    let held = reserve(&mut journal, &mut ledger, op(2), rsv(2));
    journal.append(op_event(op(2), types::OP_RESERVED_INTENT)).unwrap();
    journal
        .append(EventDraft {
            side_effect_class: SideEffectClass::None,
            ..op_event(op(2), types::OP_RESERVED_INTENT)
        })
        .unwrap();
    drop(held.begin());
    // 3: denied: the reservation released, then `op.denied`.
    let held = reserve(&mut journal, &mut ledger, op(3), rsv(3));
    journal.append(op_event(op(3), types::OP_RESERVED_INTENT)).unwrap();
    {
        let mut sink = JournalSink::new(&mut journal, correlation(), Some(op(3)), ConfigVersion(1));
        ledger.release(&mut sink, held, &Actor::System).unwrap();
    }
    journal.append(op_event(op(3), types::OP_DENIED)).unwrap();
}

/// Copies every file under `from_root` to the same relative path under `to_root`.
fn copy_tree(from: &dyn Fs, from_root: &Path, to: &dyn Fs, to_root: &Path) {
    to.create_dir_all(to_root).unwrap();
    let mut entries = from.list_dir(from_root).unwrap();
    entries.sort();
    for entry in entries {
        let name = entry.file_name().unwrap();
        if from.list_dir(&entry).is_ok() {
            copy_tree(from, &entry, to, &to_root.join(name));
        } else {
            to.write_atomic(&to_root.join(name), &from.read(&entry).unwrap())
                .unwrap();
        }
    }
}

#[test]
#[ignore = "rewrites the committed fixture; run once, when the fixture is made"]
fn regenerate_the_two_record_fixture() {
    let world = World::new();
    write_two_record_journal(&world);
    copy_tree(
        &world.fs,
        &Path::new(DATA).join(JOURNAL_DIR),
        &OsFs,
        &fixture().join(JOURNAL_DIR),
    );
}

#[test]
fn the_two_record_fixture_boots_as_it_did() {
    let world = World::new();
    copy_tree(
        &OsFs,
        &fixture().join(JOURNAL_DIR),
        &world.fs,
        &Path::new(DATA).join(JOURNAL_DIR),
    );
    let before = world.envelopes();
    // The reader reads its entries as before: the allocate; 1's reserve, settle and the
    // remainder's release; 2's reserve; 3's reserve and release.
    let records = read_verified(&world.fs, &Path::new(DATA).join(JOURNAL_DIR)).unwrap().0;
    let entries = entries_from_journal(&records).expect("the two-record fixture's entries are no longer read");
    assert_eq!(
        entries.len(),
        7,
        "the two-record fixture's entries were read differently"
    );

    let opened = Journal::open_verified(
        Arc::new(world.fs.clone()),
        world.clock.clone(),
        world.rng.clone(),
        Path::new(DATA),
        FlushPolicy::Strict,
    )
    .unwrap();
    let mut journal = opened.journal;
    let config = ConfigSnapshot::new(ConfigVersion(1), LocaleTag::new("en").unwrap());
    let booted = boot(&mut journal, &opened.records, opened.evidence, &config, correlation())
        .expect("the two-record fixture no longer boots");
    drop(journal);

    // The counts.
    let report = &booted.report;
    assert_eq!(
        report.records,
        u64::try_from(before.len()).unwrap(),
        "boot read another number of records"
    );
    assert_eq!(
        report.indeterminate,
        vec![op(2)],
        "the open Operation was not made indeterminate alone"
    );
    assert_eq!(
        (
            report.settled_estimated,
            report.completed,
            report.transfers_completed,
            report.stuck.len()
        ),
        (1, 0, 0, 0),
        "recovery closed something else"
    );
    assert_eq!(report.last_end, LastEnd::Unknown);
    assert!(
        report.stop_may_be_lost,
        "open work in an unknown end no longer says a stop may be lost"
    );

    assert_written_as_before(&world.envelopes()[before.len()..], before.len());
}

/// The open reservation settled in full, estimated, under boot's correlation; the open Operation's
/// `op.indeterminate` with its first intent's effect; then `kernel.booted`.
fn assert_written_as_before(records_written: &[EventEnvelope], records_read: usize) {
    let written: Vec<_> = records_written
        .iter()
        .map(|e| {
            (
                e.event_type.as_str().to_owned(),
                e.operation_id,
                e.side_effect_class,
                e.payload_inline.as_ref().map(|p| p.as_value().clone()),
            )
        })
        .collect();
    assert_eq!(written.len(), 3, "boot wrote another number of records: {written:?}");
    assert_eq!(written[0].0, "budget.entry");
    let settle = written[0].3.as_ref().unwrap();
    assert_eq!(
        (
            settle["kind"].as_str(),
            settle["amount"].as_str(),
            settle["estimated"].as_bool()
        ),
        (Some("settle"), Some("300"), Some(true)),
        "the open reservation was not settled in full, estimated"
    );
    assert_eq!(
        (written[1].0.as_str(), written[1].1, written[1].2),
        ("op.indeterminate", Some(op(2)), SideEffectClass::External),
        "the open Operation's record changed"
    );
    assert_eq!(
        written[1].3,
        Some(json!({"reason": "crash_recovery", "may_have_taken_effect": true}))
    );
    assert_eq!(written[2].0, "kernel.booted");
    assert_eq!(
        written[2].3,
        Some(json!({
            "records": records_read.to_string(),
            "indeterminate": "1",
            "indeterminate_settled": "0",
            "settled_estimated": "1",
            "completed": "0",
            "transfers_completed": "0",
            "stuck": "0",
            "stuck_reservations": "0",
            "stuck_transfers": "0",
            "stopped": false,
            "stop_may_be_lost": true,
            "config_version": "1",
            "shutdown_record": true,
            "last_end": "unknown",
        })),
        "kernel.booted changed"
    );
}
