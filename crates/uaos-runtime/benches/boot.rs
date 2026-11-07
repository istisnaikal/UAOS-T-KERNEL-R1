// SPDX-License-Identifier: Apache-2.0

//! Boot time against the number of records after a crash.
//!
//! Run: `cargo bench -p uaos-runtime --bench boot`. For each size it writes a journal on the real
//! filesystem (`OsFs`, the system clock, OS randomness) under the default flush policy. In it every
//! Operation reserved, journaled its intent, settled and committed, except one in a hundred, which
//! the crash left open. The journal is then dropped without a final flush, as a kill leaves it.
//! Each round boots a fresh copy of that directory and times three phases apart: the journal's own
//! open, the read of its verified records, and `uaos_runtime::boot`. It prints the median and the
//! maximum of each. Each size is written in both forms (intent contract): the two-record form (four
//! records per Operation, its money in `budget.entry` records) and the one-record form (intent,
//! `op.executing` and `op.committed`, each carrying its entries). At equal Operation counts the
//! one-record form's whole boot must not be slower; its records hold a third more Operations, so
//! give it three quarters of the two-record form's records to compare (for example 50,000 and
//! 37,313). `UAOS_BENCH_FORM` (`two` or `one`) runs one form, `UAOS_BENCH_RECORDS` overrides the
//! sizes (comma-separated) and `UAOS_BENCH_ENV` labels the environment. Dependency-free on purpose
//! (`harness = false`); nothing leaves the machine.

#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::disallowed_methods,
    reason = "benchmark binary: measures wall time, copies its fixture with std::fs and prints results"
)]

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use uaos_contracts::budget::IdempotencyKey;
use uaos_contracts::budget::LedgerDelta;
use uaos_contracts::event::InlinePayload;
use uaos_contracts::event::{Actor, Durability, EventType, Metadata, types};
use uaos_contracts::id::{CorrelationId, OperationId, PoolId, ReservationId, TypedId};
use uaos_contracts::money::NanoUsd;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::wire::ConfigVersion;
use uaos_ledger::inline::LEDGER_FIELD;
use uaos_ledger::{JournalSink, Ledger, LedgerSink, Usage};
use uaos_platform::fs::Fs;
use uaos_platform::real::fs::OsFs;
use uaos_platform::real::{OsRng, SystemClock};
use uaos_platform::{Clock, Rng};
use uaos_runtime::{ConfigSnapshot, LocaleTag, boot};
use uaos_state::journal::{EventDraft, FlushPolicy, JOURNAL_DIR, Journal, OpenEvidence, read_verified};

const SIZES: [usize; 4] = [1_000, 5_000, 10_000, 50_000];
const ROUNDS: usize = 3;
const RESERVED: i64 = 300;
/// One Operation in this many is left open by the crash.
const OPEN_EVERY: usize = 100;
const VERSION: ConfigVersion = ConfigVersion(1);

fn correlation() -> CorrelationId {
    CorrelationId::from_parts(9, [9; 10])
}

fn open(dir: &Path) -> Journal {
    let fs: Arc<dyn Fs> = Arc::new(OsFs);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let rng: Arc<dyn Rng> = Arc::new(OsRng);
    Journal::open(fs, clock, rng, dir, FlushPolicy::default()).unwrap()
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
        config_version: VERSION,
        metadata: Metadata::default(),
    }
}

/// How the journal records an Operation's money (intent contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// `budget.entry` records beside the Operation's records, four per Operation.
    TwoRecord,
    /// Each transition one record carrying its entries: intent, `op.executing`, outcome.
    OneRecord,
}

impl Form {
    const fn label(self) -> &'static str {
        match self {
            Self::TwoRecord => "two",
            Self::OneRecord => "one",
        }
    }
}

/// `UAOS_BENCH_FORM`: `two`, `one`, or both (the default).
fn forms() -> Vec<Form> {
    match std::env::var("UAOS_BENCH_FORM").as_deref() {
        Ok("two") => vec![Form::TwoRecord],
        Ok("one") => vec![Form::OneRecord],
        _ => vec![Form::TwoRecord, Form::OneRecord],
    }
}

/// An Operation record carrying `fields` and its transition's entries.
fn with_ledger(draft: EventDraft, fields: serde_json::Value, delta: &LedgerDelta) -> EventDraft {
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

/// Writes about `records` records in the one-record form, as the ledger task will (E4): intent,
/// `op.executing`, `op.committed`, each with its entries. Returns the Operations left open.
fn write_crashed_one_record_journal(dir: &Path, records: usize) -> usize {
    let mut journal = open(dir);
    let mut ledger = Ledger::default();
    let pool = PoolId::from_parts(1, [1; 10]);
    let operations = records / 3;
    let funds = NanoUsd::new(RESERVED * i64::try_from(operations).unwrap());
    let mut batch = ledger
        .prepare_allocate(pool, funds, &Actor::System, IdempotencyKey::new("fund").unwrap())
        .unwrap();
    JournalSink::new(&mut journal, correlation(), None, VERSION)
        .record(&batch.entries()[0])
        .unwrap();
    ledger.apply_step(&mut batch);
    ledger.apply(batch);
    let mut left_open = 0;
    for n in 0..operations {
        let id = u64::try_from(n).unwrap() + 1;
        let operation = OperationId::from_parts(id, [3; 10]);
        let batch = ledger
            .prepare_reserve(
                pool,
                ReservationId::from_parts(id, [7; 10]),
                NanoUsd::new(RESERVED),
                &Actor::System,
            )
            .unwrap();
        let intent = serde_json::json!({"kind": "model_call", "upstream": "primary", "durability": "balanced"});
        journal
            .append(with_ledger(
                op_event(operation, types::OP_RESERVED_INTENT),
                intent,
                &batch.delta().unwrap(),
            ))
            .unwrap();
        let held = ledger.apply(batch);
        journal.append(op_event(operation, types::OP_EXECUTING)).unwrap();
        if n % OPEN_EVERY == OPEN_EVERY - 1 {
            drop(held.begin());
            left_open += 1;
            continue;
        }
        let batch = ledger
            .prepare_settle(held.begin(), Usage::Reported(NanoUsd::new(RESERVED)), &Actor::System)
            .unwrap();
        let fields = serde_json::json!({"reason": "completed", "usage_final": true});
        journal
            .append(with_ledger(
                op_event(operation, types::OP_COMMITTED),
                fields,
                &batch.delta().unwrap(),
            ))
            .unwrap();
        let _settled = ledger.apply(batch);
    }
    drop(journal);
    left_open
}

/// Writes about `records` records to a journal in `dir` and drops it without a final flush.
/// Returns the number of Operations the crash left open.
fn write_crashed_journal(dir: &Path, records: usize) -> usize {
    let mut journal = open(dir);
    let mut ledger = Ledger::default();
    let pool = PoolId::from_parts(1, [1; 10]);
    let operations = records / 4;
    let funds = NanoUsd::new(RESERVED * i64::try_from(operations).unwrap());
    {
        let mut sink = JournalSink::new(&mut journal, correlation(), None, VERSION);
        ledger
            .allocate(
                &mut sink,
                pool,
                funds,
                &Actor::System,
                IdempotencyKey::new("fund").unwrap(),
            )
            .unwrap();
    }
    let mut left_open = 0;
    for n in 0..operations {
        let id = u64::try_from(n).unwrap() + 1;
        let operation = OperationId::from_parts(id, [3; 10]);
        let held = {
            let mut sink = JournalSink::new(&mut journal, correlation(), Some(operation), VERSION);
            ledger
                .reserve(
                    &mut sink,
                    pool,
                    ReservationId::from_parts(id, [7; 10]),
                    NanoUsd::new(RESERVED),
                    &Actor::System,
                )
                .unwrap()
        };
        journal.append(op_event(operation, types::OP_RESERVED_INTENT)).unwrap();
        if n % OPEN_EVERY == OPEN_EVERY - 1 {
            drop(held.begin());
            left_open += 1;
            continue;
        }
        let mut sink = JournalSink::new(&mut journal, correlation(), Some(operation), VERSION);
        ledger
            .settle(
                &mut sink,
                held.begin(),
                Usage::Reported(NanoUsd::new(RESERVED)),
                &Actor::System,
            )
            .unwrap();
        journal.append(op_event(operation, types::OP_COMMITTED)).unwrap();
    }
    drop(journal);
    left_open
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

fn summary(mut samples: Vec<Duration>) -> String {
    samples.sort_unstable();
    let median = samples[samples.len() / 2];
    let max = samples[samples.len() - 1];
    format!("{:>9.1} {:>9.1}", ms(median), ms(max))
}

fn sizes() -> Vec<usize> {
    std::env::var("UAOS_BENCH_RECORDS").map_or_else(
        |_| SIZES.to_vec(),
        |v| v.split(',').map(|s| s.trim().parse().unwrap()).collect(),
    )
}

fn main() {
    let env = std::env::var("UAOS_BENCH_ENV").unwrap_or_else(|_| "unlabelled".to_owned());
    let root = std::env::temp_dir().join(format!("uaos-boot-bench-{}", std::process::id()));
    let config = ConfigSnapshot::new(VERSION, LocaleTag::new("en").unwrap());
    println!("boot after a crash, env {env}, {ROUNDS} rounds; times in ms (median, max)");
    println!(
        "{:>4} {:>8} {:>9} | {:>9} {:>9} | {:>9} {:>9} | {:>9} {:>9} | {:>9} {:>9}",
        "form", "records", "open ops", "open", "max", "read", "max", "boot", "max", "total", "max"
    );
    for (size, form) in sizes()
        .into_iter()
        .flat_map(|size| forms().into_iter().map(move |form| (size, form)))
    {
        let fixture = root.join(format!("fixture-{size}-{}", form.label()));
        let left_open = match form {
            Form::TwoRecord => write_crashed_journal(&fixture, size),
            Form::OneRecord => write_crashed_one_record_journal(&fixture, size),
        };
        let records = read_verified(&OsFs, &fixture.join(JOURNAL_DIR)).unwrap().0.len();
        let (mut opens, mut reads, mut boots, mut totals) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for round in 0..ROUNDS {
            let dir = root.join(format!("run-{size}-{}-{round}", form.label()));
            copy_dir(&fixture, &dir);
            let start = Instant::now();
            let mut journal = open(&dir);
            let opened = Instant::now();
            let verified = read_verified(&OsFs, &dir.join(JOURNAL_DIR)).unwrap().0;
            let read = Instant::now();
            let booted = boot(&mut journal, &verified, OpenEvidence::default(), &config, correlation()).unwrap();
            let done = Instant::now();
            assert_eq!(
                booted.report.indeterminate.len(),
                left_open,
                "boot missed an open intent"
            );
            let settled = match form {
                Form::TwoRecord => booted.report.settled_estimated,
                Form::OneRecord => booted.report.indeterminate_settled,
            };
            assert_eq!(settled, left_open, "boot missed an open reservation");
            opens.push(opened - start);
            reads.push(read - opened);
            boots.push(done - read);
            totals.push(done - start);
            drop(journal);
            std::fs::remove_dir_all(&dir).unwrap();
        }
        println!(
            "{:>4} {records:>8} {left_open:>9} | {} | {} | {} | {}",
            form.label(),
            summary(opens),
            summary(reads),
            summary(boots),
            summary(totals)
        );
    }
    std::fs::remove_dir_all(&root).unwrap();
}
