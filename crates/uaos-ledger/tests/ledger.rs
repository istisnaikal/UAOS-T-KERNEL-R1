// SPDX-License-Identifier: Apache-2.0

//! Ledger proofs: gate `budget-concurrency`, behavior `budget-double-spend` (P2).
//!
//! Scenario tests pin down every money rule. The deterministic simulation at the end drives
//! random interleavings of agents that reserve, begin, release, settle (under, exact, over,
//! unknown) and transfer, with injected recording failures (before and after the write) and
//! crashes. It checks every step against an independent model and the recorded entries:
//!
//! * the ledger's balances equal the model's, and every refusal is the one the model predicts;
//! * conservation: per pool, `available + held + spent` equals what was funded into it;
//! * hard cap: no reservation or transfer was accepted beyond the available balance, so only a
//!   recorded overrun can take a pool below zero;
//! * a reservation identifier is never reserved twice (double spend);
//! * replaying the recorded entries reproduces the live ledger exactly;
//! * after recovery, every reservation is closed exactly once, and every reservation whose
//!   execution began was settled, never released.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use uaos_contracts::budget::{BudgetTx, BudgetTxKind, IdempotencyKey};
use uaos_contracts::error::codes;
use uaos_contracts::event::{Actor, Durability, InlinePayload, Metadata, types};
use uaos_contracts::id::{CorrelationId, PoolId, ReservationId, TypedId};
use uaos_contracts::limits::Millis;
use uaos_contracts::money::NanoUsd;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::ConfigVersion;
use uaos_ledger::{
    Held, InFlight, JournalSink, Ledger, LedgerError, LedgerSink, LedgerState, MemorySink, Recovery, Reservation,
    Settlement, Usage, entries_from_journal,
};
use uaos_platform::fs::Fs;
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, Rng};
use uaos_state::journal::{EventDraft, FlushPolicy, JOURNAL_DIR, Journal, read_verified};

fn pool(n: usize) -> PoolId {
    PoolId::from_parts(1, [u8::try_from(n).unwrap() + 1; 10])
}

fn rid(n: u64) -> ReservationId {
    ReservationId::from_parts(n, [0xA5; 10])
}

fn usd(n: i64) -> NanoUsd {
    NanoUsd::new(n)
}

fn key(s: &str) -> IdempotencyKey {
    IdempotencyKey::new(s).unwrap()
}

fn sys() -> Actor {
    Actor::System
}

/// A ledger with one pool funded with `amount`.
fn funded(amount: i64) -> (Ledger, MemorySink) {
    let mut ledger = Ledger::default();
    let mut sink = MemorySink::default();
    ledger
        .allocate(&mut sink, pool(0), usd(amount), &sys(), key("fund"))
        .unwrap();
    (ledger, sink)
}

fn balances(ledger: &Ledger, p: usize) -> (i64, i64, i64) {
    let s = ledger.state().pool(pool(p)).unwrap();
    (s.available.get(), s.held.get(), s.spent.get())
}

fn kinds(sink: &MemorySink) -> Vec<BudgetTxKind> {
    sink.entries.iter().map(|tx| tx.kind).collect()
}

// ---------------------------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------------------------

#[test]
fn hard_cap_refuses_before_anything_is_recorded() {
    let (mut ledger, mut sink) = funded(100);
    let first = ledger.reserve(&mut sink, pool(0), rid(1), usd(60), &sys()).unwrap();
    let refused = ledger.reserve(&mut sink, pool(0), rid(2), usd(50), &sys()).unwrap_err();
    assert_eq!(
        refused,
        LedgerError::Insufficient {
            pool: pool(0),
            available: usd(40),
            requested: usd(50)
        },
        "hard cap breached: a reservation beyond the available balance was accepted"
    );
    assert_eq!(refused.code(), codes::BUDGET_HARD_STOP);
    assert_eq!(sink.entries.len(), 2, "a refusal records nothing");
    // Exactly the available balance is still reservable.
    let rest = ledger.reserve(&mut sink, pool(0), rid(3), usd(40), &sys()).unwrap();
    assert_eq!(balances(&ledger, 0), (0, 100, 0));
    ledger.release(&mut sink, first, &sys()).unwrap();
    ledger.release(&mut sink, rest, &sys()).unwrap();
    assert_eq!(balances(&ledger, 0), (100, 0, 0));
}

#[test]
fn reservations_need_an_allocated_pool() {
    let mut ledger = Ledger::default();
    let mut sink = MemorySink::default();
    assert_eq!(
        ledger.reserve(&mut sink, pool(0), rid(1), usd(0), &sys()).unwrap_err(),
        LedgerError::UnknownPool(pool(0))
    );
    assert!(sink.entries.is_empty());
}

#[test]
fn release_returns_the_whole_hold() {
    let (mut ledger, mut sink) = funded(100);
    let held = ledger.reserve(&mut sink, pool(0), rid(1), usd(30), &sys()).unwrap();
    assert_eq!(balances(&ledger, 0), (70, 30, 0));
    ledger.release(&mut sink, held, &sys()).unwrap();
    assert_eq!(balances(&ledger, 0), (100, 0, 0));
    assert_eq!(ledger.state().open_reservations(), 0);
    let release = sink.entries.last().unwrap();
    assert_eq!(
        (release.kind, release.amount, release.settled),
        (BudgetTxKind::Release, usd(30), true)
    );
}

#[test]
fn settlement_under_exact_and_over() {
    // Under: the unused remainder returns to the pool.
    let (mut ledger, mut sink) = funded(100);
    let held = ledger.reserve(&mut sink, pool(0), rid(1), usd(30), &sys()).unwrap();
    let s = ledger
        .settle(&mut sink, held.begin(), Usage::Reported(usd(20)), &sys())
        .unwrap();
    assert_eq!(
        s,
        Settlement {
            spent: usd(20),
            released: usd(10),
            overrun: usd(0),
            estimated: false
        }
    );
    assert_eq!(balances(&ledger, 0), (80, 0, 20));
    assert_eq!(
        kinds(&sink),
        [
            BudgetTxKind::Allocate,
            BudgetTxKind::Reserve,
            BudgetTxKind::Settle,
            BudgetTxKind::Release
        ]
    );

    // Exact: one closing entry.
    let (mut ledger, mut sink) = funded(100);
    let held = ledger.reserve(&mut sink, pool(0), rid(1), usd(30), &sys()).unwrap();
    ledger
        .settle(&mut sink, held.begin(), Usage::Reported(usd(30)), &sys())
        .unwrap();
    assert_eq!(balances(&ledger, 0), (70, 0, 30));
    assert_eq!(sink.entries.len(), 3);
    assert!(sink.entries[2].settled);

    // Over: the excess is charged truthfully and reported (an S1 condition upstream).
    let (mut ledger, mut sink) = funded(100);
    let held = ledger.reserve(&mut sink, pool(0), rid(1), usd(30), &sys()).unwrap();
    let s = ledger
        .settle(&mut sink, held.begin(), Usage::Reported(usd(45)), &sys())
        .unwrap();
    assert_eq!((s.spent, s.released, s.overrun), (usd(45), usd(0), usd(15)));
    assert_eq!(balances(&ledger, 0), (55, 0, 45));
    let adjust = sink.entries.last().unwrap();
    assert_eq!(
        (adjust.kind, adjust.amount, adjust.settled),
        (BudgetTxKind::Adjust, usd(-15), true)
    );
}

#[test]
fn overrun_beyond_the_pool_is_recorded_and_blocks_new_reservations() {
    let (mut ledger, mut sink) = funded(30);
    let held = ledger.reserve(&mut sink, pool(0), rid(1), usd(30), &sys()).unwrap();
    let s = ledger
        .settle(&mut sink, held.begin(), Usage::Reported(usd(50)), &sys())
        .unwrap();
    assert_eq!(s.overrun, usd(20));
    assert_eq!(balances(&ledger, 0), (-20, 0, 50), "the debt is recorded, not hidden");
    assert!(matches!(
        ledger.reserve(&mut sink, pool(0), rid(2), usd(0), &sys()),
        Err(LedgerError::Insufficient { .. })
    ));
}

#[test]
fn unknown_usage_settles_at_full_cost_estimated() {
    let (mut ledger, mut sink) = funded(100);
    let held = ledger.reserve(&mut sink, pool(0), rid(1), usd(30), &sys()).unwrap();
    let s = ledger.settle(&mut sink, held.begin(), Usage::Unknown, &sys()).unwrap();
    assert_eq!(
        s,
        Settlement {
            spent: usd(30),
            released: usd(0),
            overrun: usd(0),
            estimated: true
        }
    );
    let settle = sink.entries.last().unwrap();
    assert!(settle.estimated && settle.settled);
    assert_eq!(settle.reason_code.as_str(), "settle_estimated");
}

/// Behavior `budget-double-spend`: a reservation identifier pays for exactly one Operation.
#[test]
fn a_reservation_cannot_be_spent_twice() {
    let (mut ledger, mut sink) = funded(100);
    let held = ledger.reserve(&mut sink, pool(0), rid(1), usd(30), &sys()).unwrap();
    let in_flight = held.begin();
    // While in flight, re-reserving the same identifier cannot mint a second (releasable) token.
    assert_eq!(
        ledger.reserve(&mut sink, pool(0), rid(1), usd(30), &sys()).unwrap_err(),
        LedgerError::ReservationReused(rid(1))
    );
    ledger
        .settle(&mut sink, in_flight, Usage::Reported(usd(30)), &sys())
        .unwrap();
    // After it closed, neither.
    assert_eq!(
        ledger.reserve(&mut sink, pool(0), rid(1), usd(30), &sys()).unwrap_err(),
        LedgerError::ReservationReused(rid(1))
    );
    assert_eq!(sink.entries.len(), 3);

    // The state machine refuses forged entries as well: a second closing entry, and the same
    // reservation reserved again under a fresh idempotency key.
    let mut state = LedgerState::default();
    for tx in &sink.entries {
        state.apply(tx).unwrap();
    }
    let available = state.pool(pool(0)).unwrap().available;
    let mut second_close = sink.entries[2].clone();
    second_close.idempotency_key = key("forged-close");
    assert_eq!(state.apply(&second_close), Err(LedgerError::NotOpen(rid(1))));
    let mut second_reserve = sink.entries[1].clone();
    second_reserve.idempotency_key = key("forged-reserve");
    second_reserve.balance_before = available;
    second_reserve.balance_after = available.checked_sub(second_reserve.amount).unwrap();
    assert_eq!(
        state.apply(&second_reserve),
        Err(LedgerError::ReservationReused(rid(1)))
    );
}

#[test]
fn idempotent_retries_record_nothing_new_and_conflicts_are_refused() {
    let (mut ledger, mut sink) = funded(100);
    ledger
        .allocate(&mut sink, pool(0), usd(100), &sys(), key("fund"))
        .unwrap();
    assert_eq!(sink.entries.len(), 1, "same key, same allocation: recorded once");
    assert_eq!(
        ledger
            .allocate(&mut sink, pool(0), usd(5), &sys(), key("fund"))
            .unwrap_err(),
        LedgerError::KeyConflict("fund".to_owned())
    );
    ledger
        .allocate(&mut sink, pool(1), usd(0), &sys(), key("open1"))
        .unwrap();
    ledger
        .transfer(&mut sink, pool(0), pool(1), usd(40), &sys(), key("move"))
        .unwrap();
    ledger
        .transfer(&mut sink, pool(0), pool(1), usd(40), &sys(), key("move"))
        .unwrap();
    assert_eq!(sink.entries.len(), 4, "a retried transfer moves money once");
    assert_eq!(balances(&ledger, 0).0, 60);
    assert_eq!(balances(&ledger, 1).0, 40);
    assert!(matches!(
        ledger.transfer(&mut sink, pool(0), pool(1), usd(1), &sys(), key("move")),
        Err(LedgerError::KeyConflict(_))
    ));
}

/// A sink that records the entry and then reports failure: the ambiguous case.
#[derive(Debug, Default)]
struct WrittenButFailed {
    entries: Vec<BudgetTx>,
    fail: bool,
}

impl LedgerSink for WrittenButFailed {
    fn record(&mut self, tx: &BudgetTx) -> Result<(), String> {
        self.entries.push(tx.clone());
        if self.fail {
            self.fail = false;
            return Err("disk said no after writing".to_owned());
        }
        Ok(())
    }
}

#[test]
fn a_recording_failure_poisons_until_rebuilt() {
    // Not written: nothing changes, and the rebuilt ledger agrees.
    let (mut ledger, mut sink) = funded(100);
    sink.fail_next = Some("disk full".to_owned());
    assert_eq!(
        ledger.reserve(&mut sink, pool(0), rid(1), usd(30), &sys()).unwrap_err(),
        LedgerError::Sink("disk full".to_owned())
    );
    assert!(ledger.is_poisoned());
    assert_eq!(
        ledger
            .allocate(&mut sink, pool(0), usd(1), &sys(), key("more"))
            .unwrap_err(),
        LedgerError::Poisoned
    );
    let rebuilt = Ledger::replay(&sink.entries).unwrap();
    assert_eq!(rebuilt.state(), ledger.state());

    // Written, then reported as failed: the journal is the truth. The rebuilt ledger holds the
    // reservation the caller never received, and recovery settles it conservatively.
    let mut ledger = Ledger::default();
    let mut sink = WrittenButFailed::default();
    ledger
        .allocate(&mut sink, pool(0), usd(100), &sys(), key("fund"))
        .unwrap();
    sink.fail = true;
    assert!(matches!(
        ledger.reserve(&mut sink, pool(0), rid(1), usd(30), &sys()),
        Err(LedgerError::Sink(_))
    ));
    let mut rebuilt = Ledger::replay(&sink.entries).unwrap();
    assert_eq!(rebuilt.state().open_reservations(), 1);
    let report = rebuilt.recover(&mut sink, &sys()).unwrap();
    assert_eq!(report.settled_estimated, 1);
    assert_eq!(balances(&rebuilt, 0), (70, 0, 30));
}

#[test]
fn transfers_move_money_and_recovery_completes_a_half_recorded_one() {
    let (mut ledger, mut sink) = funded(100);
    ledger
        .allocate(&mut sink, pool(1), usd(0), &sys(), key("open1"))
        .unwrap();
    ledger
        .transfer(&mut sink, pool(0), pool(1), usd(25), &sys(), key("t1"))
        .unwrap();
    assert_eq!((balances(&ledger, 0).0, balances(&ledger, 1).0), (75, 25));
    let pair: Vec<_> = sink.entries[2..]
        .iter()
        .map(|tx| (tx.kind, tx.counterparty_pool))
        .collect();
    assert_eq!(
        pair,
        [
            (BudgetTxKind::TransferOut, Some(pool(1))),
            (BudgetTxKind::TransferIn, Some(pool(0)))
        ]
    );

    // Crash between the halves: the out half is recorded, the in half is not.
    let mut half = sink.entries.clone();
    let mut out = half[2].clone();
    out.idempotency_key = key("t2");
    out.balance_before = usd(75);
    out.balance_after = usd(50);
    half.push(out);
    let mut rebuilt = Ledger::replay(&half).unwrap();
    assert_eq!(rebuilt.state().pending_transfers(), 1);
    let mut sink = MemorySink {
        entries: half,
        fail_next: None,
    };
    let report = rebuilt.recover(&mut sink, &sys()).unwrap();
    assert_eq!(report.transfers_completed, 1);
    assert_eq!((balances(&rebuilt, 0).0, balances(&rebuilt, 1).0), (50, 50));
    let completed = sink.entries.last().unwrap();
    assert_eq!(completed.idempotency_key.as_str(), "t2:in");
    assert_eq!(completed.reason_code.as_str(), "transfer_recovered");
}

#[test]
fn transfer_rules() {
    let (mut ledger, mut sink) = funded(10);
    ledger
        .allocate(&mut sink, pool(1), usd(0), &sys(), key("open1"))
        .unwrap();
    assert!(matches!(
        ledger.transfer(&mut sink, pool(0), pool(0), usd(1), &sys(), key("self")),
        Err(LedgerError::Invalid(_))
    ));
    assert_eq!(
        ledger
            .transfer(&mut sink, pool(0), pool(3), usd(1), &sys(), key("conjure"))
            .unwrap_err(),
        LedgerError::UnknownPool(pool(3)),
        "a transfer cannot create a pool"
    );
    assert!(matches!(
        ledger.transfer(&mut sink, pool(0), pool(1), usd(11), &sys(), key("big")),
        Err(LedgerError::Insufficient { .. })
    ));
    assert_eq!(
        ledger
            .transfer(&mut sink, pool(2), pool(0), usd(1), &sys(), key("ghost"))
            .unwrap_err(),
        LedgerError::UnknownPool(pool(2))
    );
    assert_eq!(sink.entries.len(), 2);
}

#[test]
fn recovery_settles_open_reservations_and_never_releases_them() {
    let (mut ledger, mut sink) = funded(100);
    let held = ledger.reserve(&mut sink, pool(0), rid(1), usd(10), &sys()).unwrap();
    let in_flight = ledger
        .reserve(&mut sink, pool(0), rid(2), usd(20), &sys())
        .unwrap()
        .begin();
    // The process dies holding both tokens.
    drop((held, in_flight));
    let mut rebuilt = Ledger::replay(&sink.entries).unwrap();
    let report = rebuilt.recover(&mut sink, &sys()).unwrap();
    assert_eq!(
        report,
        Recovery {
            settled_estimated: 2,
            completed: 0,
            transfers_completed: 0,
            stuck: Vec::new(),
        }
    );
    assert_eq!(balances(&rebuilt, 0), (70, 0, 30));
    assert!(
        sink.entries[3..]
            .iter()
            .all(|tx| tx.kind == BudgetTxKind::Settle && tx.estimated),
        "recovery settles; it never releases money that may have been spent"
    );
    // Recovery is idempotent.
    let again = rebuilt.recover(&mut sink, &sys()).unwrap();
    assert_eq!(again, Recovery::default());
}

#[test]
fn recovery_completes_a_partial_settlement_with_the_reported_amount() {
    let (mut ledger, mut sink) = funded(100);
    let in_flight = ledger
        .reserve(&mut sink, pool(0), rid(1), usd(30), &sys())
        .unwrap()
        .begin();
    let mut sink = FailAt {
        inner: sink,
        countdown: Some(1),
    };
    assert!(matches!(
        ledger
            .settle(&mut sink, in_flight, Usage::Reported(usd(12)), &sys())
            .map_err(LedgerError::from),
        Err(LedgerError::Sink(_))
    ));
    let mut rebuilt = Ledger::replay(&sink.inner.entries).unwrap();
    let report = rebuilt.recover(&mut sink, &sys()).unwrap();
    assert_eq!(report.completed, 1);
    assert_eq!(
        balances(&rebuilt, 0),
        (88, 0, 12),
        "the reported spend stands; the rest returns"
    );
}

/// Fails the record after `countdown` successful ones.
#[derive(Debug)]
struct FailAt {
    inner: MemorySink,
    countdown: Option<usize>,
}

impl LedgerSink for FailAt {
    fn record(&mut self, tx: &BudgetTx) -> Result<(), String> {
        match self.countdown {
            Some(0) => {
                self.countdown = None;
                Err("injected".to_owned())
            }
            Some(n) => {
                self.countdown = Some(n - 1);
                self.inner.record(tx)
            }
            None => self.inner.record(tx),
        }
    }
}

#[test]
fn replay_refuses_an_inconsistent_history() {
    let (mut ledger, mut sink) = funded(100);
    let held = ledger.reserve(&mut sink, pool(0), rid(1), usd(30), &sys()).unwrap();
    ledger
        .settle(&mut sink, held.begin(), Usage::Reported(usd(10)), &sys())
        .unwrap();

    let mut missing_reserve = sink.entries.clone();
    missing_reserve.remove(1);
    assert!(Ledger::replay(&missing_reserve).is_err());

    let mut inflated = sink.entries.clone();
    inflated[0].amount = usd(1_000);
    inflated[0].balance_after = usd(1_000);
    assert_eq!(Ledger::replay(&inflated).unwrap_err(), LedgerError::BalanceMismatch);

    let mut reordered = sink.entries.clone();
    reordered.swap(2, 3);
    assert!(Ledger::replay(&reordered).is_err());
}

// ---------------------------------------------------------------------------------------------
// Real threads contending for one pool
// ---------------------------------------------------------------------------------------------

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "contended threads on real OS threads are the point of this test (std::thread::scope)"
)]
fn threads_contending_for_one_pool_never_overspend() {
    const THREADS: u64 = 8;
    const ROUNDS: u64 = 200;
    const FUNDS: i64 = 10_000;
    let shared = Mutex::new(funded(FUNDS));
    let refusals = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let (shared, refusals) = (&shared, &refusals);
            s.spawn(move || {
                for i in 0..ROUNDS {
                    let id = rid(t * ROUNDS + i + 1);
                    let amount = usd(i64::try_from(10 + (t * 7 + i * 13) % 90).unwrap());
                    let reserved = {
                        let mut guard = shared.lock().unwrap();
                        let (ledger, sink) = &mut *guard;
                        ledger.reserve(sink, pool(0), id, amount, &sys())
                    };
                    match reserved {
                        Ok(held) => {
                            let in_flight = held.begin();
                            std::thread::yield_now(); // the "provider call", outside the lock
                            let usage = if i % 3 == 0 {
                                Usage::Unknown
                            } else {
                                Usage::Reported(usd(amount.get() / 2))
                            };
                            let mut guard = shared.lock().unwrap();
                            let (ledger, sink) = &mut *guard;
                            ledger.settle(sink, in_flight, usage, &sys()).unwrap();
                        }
                        Err(LedgerError::Insufficient { .. }) => {
                            refusals.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => panic!("unexpected ledger error: {e}"),
                    }
                }
            });
        }
    });
    let (ledger, sink) = shared.into_inner().unwrap();
    assert!(
        refusals.into_inner() > 0,
        "the cap was never reached; the test proves nothing"
    );
    let (available, held, spent) = balances(&ledger, 0);
    assert_eq!(available + held + spent, FUNDS, "conservation");
    assert_eq!(held, 0);
    assert!(
        available >= 0 && spent <= FUNDS,
        "hard cap breached: overspend under contention"
    );
    assert!(
        sink.entries
            .iter()
            .filter(|tx| tx.kind == BudgetTxKind::Reserve)
            .all(|tx| tx.balance_before >= tx.amount),
        "hard cap breached: a reservation exceeded the available balance"
    );
    assert_eq!(Ledger::replay(&sink.entries).unwrap().state(), ledger.state());
}

// ---------------------------------------------------------------------------------------------
// Journal round trip
// ---------------------------------------------------------------------------------------------

struct JournalWorld {
    fs: SimFs,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
}

impl JournalWorld {
    fn new() -> Self {
        let fs = SimFs::new();
        fs.create_dir_all(Path::new("/data")).unwrap();
        Self {
            fs,
            clock: Arc::new(SimClock::new(
                WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
            )),
            rng: Arc::new(SimRng::new(7)),
        }
    }

    fn open(&self) -> Journal {
        Journal::open(
            Arc::new(self.fs.clone()),
            self.clock.clone(),
            self.rng.clone(),
            Path::new("/data"),
            FlushPolicy::Balanced { window: Millis(60_000) },
        )
        .unwrap()
    }

    fn entries(&self) -> Result<Vec<BudgetTx>, String> {
        let (records, _) = read_verified(&self.fs, &Path::new("/data").join(JOURNAL_DIR)).unwrap();
        entries_from_journal(&records)
    }
}

fn journal_sink(journal: &mut Journal) -> JournalSink<'_> {
    JournalSink::new(journal, CorrelationId::from_parts(1, [3; 10]), None, ConfigVersion(1))
}

#[test]
fn journal_entries_survive_a_crash_and_replay_to_the_live_ledger() {
    let world = JournalWorld::new();
    let mut journal = world.open();
    let mut ledger = Ledger::default();
    let live = {
        let mut sink = journal_sink(&mut journal);
        ledger
            .allocate(&mut sink, pool(0), usd(100), &sys(), key("fund"))
            .unwrap();
        let held = ledger.reserve(&mut sink, pool(0), rid(1), usd(40), &sys()).unwrap();
        ledger
            .settle(&mut sink, held.begin(), Usage::Reported(usd(25)), &sys())
            .unwrap();
        ledger
            .allocate(&mut sink, pool(1), usd(0), &sys(), key("open1"))
            .unwrap();
        ledger
            .transfer(&mut sink, pool(0), pool(1), usd(10), &sys(), key("move"))
            .unwrap();
        // Left open when the process dies.
        let _in_flight = ledger
            .reserve(&mut sink, pool(0), rid(2), usd(5), &sys())
            .unwrap()
            .begin();
        ledger.state().clone()
    };
    world.fs.crash();
    drop(journal);

    let mut journal = world.open();
    let entries = world.entries().unwrap();
    assert_eq!(entries.len(), 8);
    let mut rebuilt = Ledger::replay(&entries).unwrap();
    assert_eq!(rebuilt.state(), &live, "every critical entry survived the crash");
    let report = rebuilt.recover(&mut journal_sink(&mut journal), &sys()).unwrap();
    assert_eq!(report.settled_estimated, 1);
    assert_eq!(balances(&rebuilt, 0), (60, 0, 30));
    // Recovery's own entries are journaled too.
    assert_eq!(
        Ledger::replay(&world.entries().unwrap()).unwrap().state(),
        rebuilt.state()
    );
}

#[test]
fn journal_reader_ignores_other_events_and_refuses_malformed_entries() {
    let world = JournalWorld::new();
    let mut journal = world.open();
    let draft = |event_type, payload: Option<serde_json::Value>| EventDraft {
        session_id: None,
        pocket_id: None,
        operation_id: None,
        request_id: None,
        agent_id: None,
        correlation_id: CorrelationId::from_parts(1, [4; 10]),
        parent_id: None,
        actor: sys(),
        event_type,
        payload_ref: None,
        payload_inline: payload.map(|p| InlinePayload::new(p).unwrap()),
        cost_estimate: None,
        compensable: false,
        side_effect_class: SideEffectClass::None,
        risk_tier: RiskTier::new(0).unwrap(),
        durability: Durability::Critical,
        config_version: ConfigVersion(1),
        metadata: Metadata::default(),
    };
    journal.append(draft(types::OP_COMMITTED, None)).unwrap();
    assert!(world.entries().unwrap().is_empty());
    journal
        .append(draft(
            types::BUDGET_ENTRY,
            Some(serde_json::json!({ "not": "an entry" })),
        ))
        .unwrap();
    let error = world.entries().unwrap_err();
    assert!(error.contains("malformed"), "{error}");
}

// ---------------------------------------------------------------------------------------------
// Deterministic simulation against a model
// ---------------------------------------------------------------------------------------------

const POOLS: usize = 3;
const AGENTS: usize = 4;

#[derive(Debug, Clone, Copy)]
enum Spend {
    /// Percent of the reservation, below 100.
    Under(i64),
    Exact,
    /// Amount beyond the reservation.
    Over(i64),
    Unknown,
}

#[derive(Debug, Clone)]
enum Op {
    Allocate {
        pool: usize,
        amount: i64,
    },
    Reserve {
        agent: usize,
        pool: usize,
        amount: i64,
    },
    Begin {
        agent: usize,
        slot: usize,
    },
    Release {
        agent: usize,
        slot: usize,
    },
    Settle {
        agent: usize,
        slot: usize,
        spend: Spend,
    },
    Transfer {
        from: usize,
        to: usize,
        amount: i64,
    },
    /// Reserve an identifier that was already reserved: the double-spend attempt.
    Reuse {
        slot: usize,
    },
    /// The next operation's recording fails after `skip` successful records, before or after
    /// writing the failing entry.
    Arm {
        skip: usize,
        after_write: bool,
    },
    Crash,
}

fn spend() -> impl Strategy<Value = Spend> {
    prop_oneof![
        (0..100_i64).prop_map(Spend::Under),
        Just(Spend::Exact),
        (1..300_i64).prop_map(Spend::Over),
        Just(Spend::Unknown),
    ]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..POOLS, 0..2_000_i64).prop_map(|(pool, amount)| Op::Allocate { pool, amount }),
        8 => (0..AGENTS, 0..POOLS, 0..800_i64).prop_map(|(agent, pool, amount)| Op::Reserve { agent, pool, amount }),
        5 => (0..AGENTS, any::<usize>()).prop_map(|(agent, slot)| Op::Begin { agent, slot }),
        2 => (0..AGENTS, any::<usize>()).prop_map(|(agent, slot)| Op::Release { agent, slot }),
        5 => (0..AGENTS, any::<usize>(), spend()).prop_map(|(agent, slot, spend)| Op::Settle { agent, slot, spend }),
        2 => (0..POOLS, 1..POOLS, 0..1_000_i64)
            .prop_map(|(from, d, amount)| Op::Transfer { from, to: (from + d) % POOLS, amount }),
        1 => any::<usize>().prop_map(|slot| Op::Reuse { slot }),
        1 => (0..2_usize, any::<bool>()).prop_map(|(skip, after_write)| Op::Arm { skip, after_write }),
        1 => Just(Op::Crash),
    ]
}

#[derive(Debug, Clone, Copy)]
struct Arm {
    skip: usize,
    after_write: bool,
}

/// How many entries survive when an operation that records `records` entries runs under `arm`;
/// `None` when the operation completes without a failure.
fn surviving(arm: Option<Arm>, records: usize) -> Option<usize> {
    arm.filter(|a| records > a.skip)
        .map(|a| a.skip + usize::from(a.after_write))
}

#[derive(Debug, Default)]
struct SimSink {
    entries: Vec<BudgetTx>,
    arm: Option<Arm>,
}

impl LedgerSink for SimSink {
    fn record(&mut self, tx: &BudgetTx) -> Result<(), String> {
        match &mut self.arm {
            Some(a) if a.skip > 0 => a.skip -= 1,
            Some(a) => {
                let after_write = a.after_write;
                self.arm = None;
                if after_write {
                    self.entries.push(tx.clone());
                }
                return Err("injected recording failure".to_owned());
            }
            None => {}
        }
        self.entries.push(tx.clone());
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Bal {
    available: i64,
    held: i64,
    spent: i64,
}

#[derive(Debug, Default)]
struct Sim {
    ledger: Ledger,
    sink: SimSink,
    held: [Vec<Reservation<Held>>; AGENTS],
    in_flight: [Vec<Reservation<InFlight>>; AGENTS],
    // The model.
    pools: [Option<Bal>; POOLS],
    open: BTreeMap<ReservationId, (usize, i64)>,
    reserved: Vec<(ReservationId, usize, i64)>,
    begun: BTreeSet<ReservationId>,
    armed: Option<Arm>,
    partial_settles: usize,
    partial_transfers: usize,
    next: u64,
    // Running totals over the recorded entries.
    seen: usize,
    funded: [i64; POOLS],
    overrun: [i64; POOLS],
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "a `map_err` adapter receives the error by value"
)]
fn unexpected(e: LedgerError) -> TestCaseError {
    TestCaseError::fail(format!("unexpected ledger error: {e}"))
}

fn index(id: PoolId) -> usize {
    (0..POOLS).find(|&p| pool(p) == id).unwrap()
}

impl Sim {
    fn fresh(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    fn bal(&mut self, p: usize) -> &mut Bal {
        self.pools[p].get_or_insert_default()
    }

    fn hold(&mut self, p: usize, id: ReservationId, amount: i64) {
        let b = self.bal(p);
        b.available -= amount;
        b.held += amount;
        self.open.insert(id, (p, amount));
        self.reserved.push((id, p, amount));
    }

    fn released(&mut self, id: ReservationId) {
        let (p, amount) = self.open.remove(&id).unwrap();
        let b = self.bal(p);
        b.available += amount;
        b.held -= amount;
    }

    fn settled(&mut self, id: ReservationId, actual: i64) {
        let (p, amount) = self.open.remove(&id).unwrap();
        let b = self.bal(p);
        b.held -= amount;
        b.spent += actual;
        b.available += amount - actual;
    }

    fn moved(&mut self, from: usize, to: usize, amount: i64) {
        self.bal(from).available -= amount;
        self.bal(to).available += amount;
    }

    /// Runs one operation; returns whether it was expected to poison the ledger.
    #[allow(
        clippy::too_many_lines,
        reason = "one arm per simulated operation, side by side with its model"
    )]
    fn run(&mut self, op: &Op, arm: Option<Arm>) -> Result<bool, TestCaseError> {
        let mut poisons = false;
        match *op {
            Op::Arm { .. } | Op::Crash => unreachable!("handled by step"),
            Op::Allocate { pool: p, amount } => {
                let k = key(&format!("alloc-{}", self.fresh()));
                let r = self.ledger.allocate(&mut self.sink, pool(p), usd(amount), &sys(), k);
                match surviving(arm, 1) {
                    None => {
                        r.map_err(unexpected)?;
                        self.bal(p).available += amount;
                    }
                    Some(kept) => {
                        prop_assert!(matches!(r, Err(LedgerError::Sink(_))));
                        poisons = true;
                        if kept >= 1 {
                            self.bal(p).available += amount;
                        }
                    }
                }
            }
            Op::Reserve { agent, pool: p, amount } => {
                let id = rid(self.fresh());
                let r = self.ledger.reserve(&mut self.sink, pool(p), id, usd(amount), &sys());
                match self.pools[p] {
                    None => prop_assert_eq!(r.err(), Some(LedgerError::UnknownPool(pool(p)))),
                    Some(b) if b.available < amount => prop_assert_eq!(
                        r.err(),
                        Some(LedgerError::Insufficient {
                            pool: pool(p),
                            available: usd(b.available),
                            requested: usd(amount)
                        }),
                        "hard cap breached: the model refuses this reservation"
                    ),
                    Some(_) => match surviving(arm, 1) {
                        None => {
                            let held = r.map_err(unexpected)?;
                            prop_assert_eq!((held.id(), held.amount()), (id, usd(amount)));
                            self.held[agent].push(held);
                            self.hold(p, id, amount);
                        }
                        Some(kept) => {
                            prop_assert!(matches!(r, Err(LedgerError::Sink(_))));
                            poisons = true;
                            if kept >= 1 {
                                self.hold(p, id, amount);
                            }
                        }
                    },
                }
            }
            Op::Begin { agent, slot } => {
                if !self.held[agent].is_empty() {
                    let held = self.held[agent].remove(slot % self.held[agent].len());
                    self.begun.insert(held.id());
                    self.in_flight[agent].push(held.begin());
                }
            }
            Op::Release { agent, slot } => {
                if !self.held[agent].is_empty() {
                    let held = self.held[agent].remove(slot % self.held[agent].len());
                    let id = held.id();
                    let r = self.ledger.release(&mut self.sink, held, &sys());
                    match surviving(arm, 1) {
                        None => {
                            r.map_err(|e| unexpected(e.into()))?;
                            self.released(id);
                        }
                        Some(kept) => {
                            prop_assert!(matches!(r.map_err(LedgerError::from), Err(LedgerError::Sink(_))));
                            poisons = true;
                            if kept >= 1 {
                                self.released(id);
                            }
                        }
                    }
                }
            }
            Op::Settle { agent, slot, spend } => {
                if !self.in_flight[agent].is_empty() {
                    let token = self.in_flight[agent].remove(slot % self.in_flight[agent].len());
                    let id = token.id();
                    let amount = token.amount().get();
                    let (usage, actual) = match spend {
                        Spend::Under(pct) => {
                            let a = amount * pct / 100;
                            (Usage::Reported(usd(a)), a)
                        }
                        Spend::Exact => (Usage::Reported(usd(amount)), amount),
                        Spend::Over(extra) => (Usage::Reported(usd(amount + extra)), amount + extra),
                        Spend::Unknown => (Usage::Unknown, amount),
                    };
                    let records = if actual == amount { 1 } else { 2 };
                    let r = self.ledger.settle(&mut self.sink, token, usage, &sys());
                    match surviving(arm, records) {
                        None => {
                            let s = r.map_err(|e| unexpected(e.into()))?;
                            prop_assert_eq!(
                                s,
                                Settlement {
                                    spent: usd(actual),
                                    released: usd((amount - actual).max(0)),
                                    overrun: usd((actual - amount).max(0)),
                                    estimated: matches!(spend, Spend::Unknown),
                                }
                            );
                            self.settled(id, actual);
                        }
                        Some(kept) => {
                            prop_assert!(matches!(r.map_err(LedgerError::from), Err(LedgerError::Sink(_))));
                            poisons = true;
                            if kept >= 1 {
                                // The recorded Settle carries the actual spend; recovery closes it.
                                self.settled(id, actual);
                                if records == 2 && kept == 1 {
                                    self.partial_settles += 1;
                                }
                            }
                        }
                    }
                }
            }
            Op::Transfer { from, to, amount } => {
                let k = key(&format!("move-{}", self.fresh()));
                let r = self
                    .ledger
                    .transfer(&mut self.sink, pool(from), pool(to), usd(amount), &sys(), k);
                match self.pools[from] {
                    None => prop_assert_eq!(r.err(), Some(LedgerError::UnknownPool(pool(from)))),
                    // A transfer cannot create its destination.
                    Some(_) if self.pools[to].is_none() => {
                        prop_assert_eq!(r.err(), Some(LedgerError::UnknownPool(pool(to))));
                    }
                    Some(b) if b.available < amount => prop_assert_eq!(
                        r.err(),
                        Some(LedgerError::Insufficient {
                            pool: pool(from),
                            available: usd(b.available),
                            requested: usd(amount)
                        })
                    ),
                    Some(_) => match surviving(arm, 2) {
                        None => {
                            r.map_err(unexpected)?;
                            self.moved(from, to, amount);
                        }
                        Some(kept) => {
                            prop_assert!(matches!(r, Err(LedgerError::Sink(_))));
                            poisons = true;
                            if kept >= 1 {
                                self.moved(from, to, amount);
                                if kept == 1 {
                                    self.partial_transfers += 1;
                                }
                            }
                        }
                    },
                }
            }
            Op::Reuse { slot } => {
                if !self.reserved.is_empty() {
                    let (id, p, amount) = self.reserved[slot % self.reserved.len()];
                    let before = self.sink.entries.len();
                    let r = self.ledger.reserve(&mut self.sink, pool(p), id, usd(amount), &sys());
                    prop_assert_eq!(r.err(), Some(LedgerError::ReservationReused(id)), "double spend");
                    prop_assert_eq!(self.sink.entries.len(), before);
                }
            }
        }
        Ok(poisons)
    }

    fn step(&mut self, op: &Op) -> Result<(), TestCaseError> {
        match *op {
            Op::Arm { skip, after_write } => {
                self.armed = Some(Arm { skip, after_write });
                return Ok(());
            }
            Op::Crash => {
                self.armed = None;
                self.restart(true)?;
            }
            _ => {
                let arm = self.armed.take();
                self.sink.arm = arm;
                let poisons = self.run(op, arm)?;
                self.sink.arm = None;
                prop_assert_eq!(self.ledger.is_poisoned(), poisons);
                if poisons {
                    // The daemon's response to a recording failure: rebuild from the journal.
                    self.restart(false)?;
                }
            }
        }
        self.check()
    }

    /// The process dies (or rebuilds after a recording failure): tokens are gone, the ledger is
    /// replayed from the recorded entries and recovery runs.
    fn restart(&mut self, compare_live: bool) -> Result<(), TestCaseError> {
        for tokens in &mut self.held {
            tokens.clear();
        }
        for tokens in &mut self.in_flight {
            tokens.clear();
        }
        let rebuilt = Ledger::replay(&self.sink.entries).map_err(unexpected)?;
        if compare_live {
            prop_assert_eq!(
                rebuilt.state(),
                self.ledger.state(),
                "replay must reproduce the live ledger"
            );
        }
        self.ledger = rebuilt;
        let report = self.ledger.recover(&mut self.sink, &sys()).map_err(unexpected)?;
        let expected = Recovery {
            settled_estimated: self.open.len(),
            completed: std::mem::take(&mut self.partial_settles),
            transfers_completed: std::mem::take(&mut self.partial_transfers),
            stuck: Vec::new(),
        };
        for (_, (p, amount)) in std::mem::take(&mut self.open) {
            let b = self.bal(p);
            b.held -= amount;
            b.spent += amount;
        }
        prop_assert_eq!(report, expected);
        prop_assert_eq!(self.ledger.state().pending_transfers(), 0);
        Ok(())
    }

    fn check(&mut self) -> Result<(), TestCaseError> {
        for tx in &self.sink.entries[self.seen..] {
            let p = index(tx.pool_id);
            match tx.kind {
                BudgetTxKind::Allocate | BudgetTxKind::Refund | BudgetTxKind::TransferIn => {
                    self.funded[p] += tx.amount.get();
                }
                BudgetTxKind::TransferOut => {
                    prop_assert!(
                        tx.balance_before >= tx.amount,
                        "hard cap breached: transfer beyond available"
                    );
                    self.funded[p] -= tx.amount.get();
                }
                BudgetTxKind::Reserve => {
                    prop_assert!(
                        tx.balance_before >= tx.amount,
                        "hard cap breached: reservation beyond available"
                    );
                }
                BudgetTxKind::Adjust => self.overrun[p] -= tx.amount.get(),
                BudgetTxKind::Settle | BudgetTxKind::Release => {}
            }
        }
        self.seen = self.sink.entries.len();
        let state = self.ledger.state();
        for p in 0..POOLS {
            let got = state
                .pool(pool(p))
                .map(|s| (s.available.get(), s.held.get(), s.spent.get()));
            prop_assert_eq!(
                got,
                self.pools[p].map(|b| (b.available, b.held, b.spent)),
                "pool {} vs model",
                p
            );
            if let Some((available, held, spent)) = got {
                prop_assert_eq!(available + held + spent, self.funded[p], "conservation in pool {}", p);
                prop_assert!(
                    available + self.overrun[p] >= 0,
                    "hard cap breached: pool {} is below zero beyond recorded overruns",
                    p
                );
            }
        }
        prop_assert_eq!(state.open_reservations(), self.open.len());
        Ok(())
    }

    /// After a final restart: every reservation closed exactly once; begun ones were settled.
    fn check_closure(&self) -> Result<(), TestCaseError> {
        #[derive(Default)]
        struct Life {
            reserves: usize,
            settles: usize,
            releases: usize,
            adjusts: usize,
            closings: usize,
        }
        let mut lives: BTreeMap<ReservationId, Life> = BTreeMap::new();
        for tx in &self.sink.entries {
            let Some(id) = tx.reservation_id else { continue };
            let life = lives.entry(id).or_default();
            match tx.kind {
                BudgetTxKind::Reserve => life.reserves += 1,
                BudgetTxKind::Settle => life.settles += 1,
                BudgetTxKind::Release => life.releases += 1,
                BudgetTxKind::Adjust => life.adjusts += 1,
                _ => {}
            }
            life.closings += usize::from(tx.settled);
        }
        for (id, life) in &lives {
            prop_assert_eq!(life.reserves, 1, "{} reserved more than once", id);
            prop_assert_eq!(life.closings, 1, "{} closed {} times", id, life.closings);
            prop_assert!(life.settles <= 1 && life.releases <= 1 && life.adjusts <= 1);
        }
        for id in &self.begun {
            if let Some(life) = lives.get(id) {
                prop_assert_eq!(
                    life.settles,
                    1,
                    "in-flight reservation {} was released, not settled",
                    id
                );
            }
        }
        Ok(())
    }
}

/// Scenarios per run: 256 on every merge; nightly sets `UAOS_SIM_CASES` (100k).
#[allow(clippy::disallowed_methods, reason = "test configuration knob, read once")]
fn sim_cases() -> u32 {
    std::env::var("UAOS_SIM_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: sim_cases(), ..ProptestConfig::default() })]

    #[test]
    fn simulation(ops in prop::collection::vec(op(), 1..150)) {
        let mut sim = Sim::default();
        for op in &ops {
            sim.step(op)?;
        }
        sim.step(&Op::Crash)?;
        prop_assert_eq!(sim.ledger.state().open_reservations(), 0);
        sim.check_closure()?;
    }
}

// ---------------------------------------------------------------------------------------------
// Regression tests
// ---------------------------------------------------------------------------------------------

/// Fund 100, reserve 30, settle 80 (overrun 50) and fail the closing overrun entry: the journal
/// holds the Settle but not the Adjust.
fn unclosed_overrun() -> Vec<BudgetTx> {
    let (mut ledger, inner) = funded(100);
    let mut sink = FailAt { inner, countdown: None };
    let in_flight = ledger
        .reserve(&mut sink, pool(0), rid(1), usd(30), &sys())
        .unwrap()
        .begin();
    sink.countdown = Some(1); // the Settle is recorded, the overrun Adjust fails
    assert!(
        ledger
            .settle(&mut sink, in_flight, Usage::Reported(usd(80)), &sys())
            .is_err()
    );
    sink.inner.entries
}

#[test]
fn a_rebuilt_ledger_refuses_new_work_until_recovered() {
    let entries = unclosed_overrun();
    let mut rebuilt = Ledger::replay(&entries).unwrap();
    assert!(rebuilt.needs_recovery());
    let mut sink = MemorySink {
        entries: entries.clone(),
        fail_next: None,
    };
    assert_eq!(
        rebuilt
            .reserve(&mut sink, pool(0), rid(2), usd(70), &sys())
            .unwrap_err(),
        LedgerError::RecoveryRequired
    );
    assert_eq!(
        rebuilt
            .allocate(&mut sink, pool(0), usd(1), &sys(), key("more"))
            .unwrap_err(),
        LedgerError::RecoveryRequired
    );
    // The unclosed overrun counts against the cap even before recovery closes it.
    let mut crafted = sink.entries.last().unwrap().clone();
    crafted.idempotency_key = key("crafted");
    crafted.kind = BudgetTxKind::Reserve;
    crafted.reservation_id = Some(rid(9));
    crafted.amount = usd(70);
    crafted.balance_before = usd(70);
    crafted.balance_after = usd(0);
    crafted.settled = false;
    crafted.estimated = false;
    assert!(matches!(
        rebuilt.state().check(&crafted),
        Err(LedgerError::Insufficient { .. })
    ));

    let report = rebuilt.recover(&mut sink, &sys()).unwrap();
    assert_eq!(report.completed, 1);
    assert!(!rebuilt.needs_recovery());
    assert_eq!(balances(&rebuilt, 0), (20, 0, 80), "the overrun is charged");
    assert!(matches!(
        rebuilt.reserve(&mut sink, pool(0), rid(2), usd(70), &sys()),
        Err(LedgerError::Insufficient { .. })
    ));
    let _held = rebuilt.reserve(&mut sink, pool(0), rid(3), usd(20), &sys()).unwrap();
}

#[test]
fn caller_keys_cannot_collide_with_derived_keys() {
    let (mut ledger, mut sink) = funded(100);
    ledger
        .allocate(&mut sink, pool(1), usd(0), &sys(), key("open1"))
        .unwrap();
    for reserved in [
        "move:in",
        "rsv_anything",
        "x:reserve",
        "x:release",
        "x:settle",
        "x:overrun",
    ] {
        assert_eq!(
            ledger
                .allocate(&mut sink, pool(0), usd(1), &sys(), key(reserved))
                .unwrap_err()
                .code(),
            codes::BUDGET_KEY_CONFLICT,
            "{reserved}"
        );
        assert!(matches!(
            ledger.transfer(&mut sink, pool(0), pool(1), usd(1), &sys(), key(reserved)),
            Err(LedgerError::KeyReserved(_))
        ));
    }
    assert_eq!(sink.entries.len(), 2, "nothing was recorded");
}

#[test]
fn recovery_reports_a_stuck_item_and_still_closes_the_rest() {
    // One bad item must not block recovery of everything else.
    let (mut ledger, mut sink) = funded(100);
    ledger
        .allocate(&mut sink, pool(1), usd(0), &sys(), key("open1"))
        .unwrap();
    ledger
        .transfer(&mut sink, pool(0), pool(1), usd(10), &sys(), key("t"))
        .unwrap();
    let _open = ledger.reserve(&mut sink, pool(0), rid(1), usd(5), &sys()).unwrap();
    // A crafted journal: drop the transfer's second half, and make its key collide.
    let mut entries = sink.entries.clone();
    let transfer_in = entries.remove(3);
    let mut collider = entries[1].clone();
    collider.idempotency_key = transfer_in.idempotency_key.clone();
    collider.amount = usd(0);
    collider.balance_before = usd(0);
    collider.balance_after = usd(0);
    entries.insert(2, collider);
    let mut rebuilt = Ledger::replay(&entries).unwrap();
    let mut sink = MemorySink {
        entries,
        fail_next: None,
    };
    let report = rebuilt.recover(&mut sink, &sys()).unwrap();
    assert_eq!(report.settled_estimated, 1, "the open reservation was still closed");
    assert_eq!(report.stuck.len(), 1, "{:?}", report.stuck);
    assert!(
        rebuilt.needs_recovery(),
        "a stuck item keeps the ledger closed for new work"
    );
}

#[test]
fn recovery_is_boot_only_and_rejected_closes_hand_the_token_back() {
    let (mut ledger, mut sink) = funded(100);
    let held = ledger.reserve(&mut sink, pool(0), rid(1), usd(30), &sys()).unwrap();
    assert_eq!(
        ledger.recover(&mut sink, &sys()).unwrap_err(),
        LedgerError::NotReplayed,
        "recovery must not settle a reservation whose token is still live"
    );
    let in_flight = held.begin();
    let token = match ledger.settle(&mut sink, in_flight, Usage::Reported(usd(-5)), &sys()) {
        Err(uaos_ledger::CloseError::Rejected { reservation, .. }) => reservation,
        other => panic!("expected the token back, got {other:?}"),
    };
    let s = ledger
        .settle(&mut sink, token, Usage::Reported(usd(30)), &sys())
        .unwrap();
    assert_eq!(s.spent, usd(30));

    let held = ledger.reserve(&mut sink, pool(0), rid(2), usd(10), &sys()).unwrap();
    sink.fail_next = Some("disk full".to_owned());
    assert!(
        ledger
            .allocate(&mut sink, pool(0), usd(1), &sys(), key("poison"))
            .is_err()
    );
    assert!(ledger.is_poisoned());
    assert!(matches!(
        ledger.release(&mut sink, held, &sys()),
        Err(uaos_ledger::CloseError::Rejected {
            error: LedgerError::Poisoned,
            ..
        })
    ));
}

#[test]
fn replay_enforces_every_reservation_and_transfer_rule() {
    // The four rules that seeded mutants showed no test exercised.
    let (mut ledger, inner) = funded(100);
    let mut sink = FailAt { inner, countdown: None };
    ledger
        .allocate(&mut sink, pool(1), usd(5), &sys(), key("open1"))
        .unwrap();
    let in_flight = ledger
        .reserve(&mut sink, pool(0), rid(1), usd(30), &sys())
        .unwrap()
        .begin();
    sink.countdown = Some(1); // the Settle (12 of 30) is recorded, its Release is not
    assert!(
        ledger
            .settle(&mut sink, in_flight, Usage::Reported(usd(12)), &sys())
            .is_err()
    );
    let base = sink.inner.entries.clone();
    let settle = base.last().unwrap().clone();
    assert_eq!(settle.kind, BudgetTxKind::Settle);

    // (1) A second Settle on a partly settled reservation.
    let mut twice = base.clone();
    let mut again = settle.clone();
    again.idempotency_key = key("again");
    twice.push(again);
    assert!(Ledger::replay(&twice).is_err(), "second settle accepted");

    // (2) A Settle against another pool.
    let mut other_pool = base[..base.len() - 1].to_vec();
    let mut wrong = settle.clone();
    wrong.pool_id = pool(1);
    wrong.balance_before = usd(5);
    wrong.balance_after = usd(5);
    other_pool.push(wrong);
    assert!(
        Ledger::replay(&other_pool).is_err(),
        "settle against another pool accepted"
    );

    // (3) A TransferIn whose amount differs from its TransferOut.
    let (mut l2, mut s2) = funded(100);
    l2.allocate(&mut s2, pool(1), usd(0), &sys(), key("open1")).unwrap();
    l2.transfer(&mut s2, pool(0), pool(1), usd(10), &sys(), key("t"))
        .unwrap();
    let mut inflated = s2.entries.clone();
    let transfer_in = inflated.last_mut().unwrap();
    transfer_in.amount = usd(11);
    transfer_in.balance_after = usd(11);
    assert!(
        Ledger::replay(&inflated).is_err(),
        "transfer_in creating money accepted"
    );

    // (4) A Release that does not close its reservation.
    let (mut l3, mut s3) = funded(100);
    let held = l3.reserve(&mut s3, pool(0), rid(1), usd(30), &sys()).unwrap();
    l3.release(&mut s3, held, &sys()).unwrap();
    let mut open_release = s3.entries.clone();
    open_release.last_mut().unwrap().settled = false;
    assert!(
        Ledger::replay(&open_release).is_err(),
        "release without settled accepted"
    );
}

#[test]
fn replay_refuses_money_without_a_producer() {
    let (_, sink) = funded(100);
    let fund = sink.entries[0].clone();
    let mut refund = fund.clone();
    refund.idempotency_key = key("refund");
    refund.kind = BudgetTxKind::Refund;
    refund.balance_before = usd(100);
    refund.balance_after = usd(200);
    assert!(Ledger::replay(&[fund.clone(), refund]).is_err());
    let mut adjust = fund.clone();
    adjust.idempotency_key = key("adjust");
    adjust.kind = BudgetTxKind::Adjust;
    adjust.balance_before = usd(100);
    adjust.balance_after = usd(200);
    assert!(Ledger::replay(&[fund, adjust]).is_err());
}

#[test]
fn a_retry_must_match_every_field_and_errors_have_their_own_codes() {
    let (mut ledger, mut sink) = funded(100);
    let other = Actor::Module {
        name: uaos_contracts::event::ModuleName::new("mod-x").unwrap(),
    };
    let err = ledger
        .allocate(&mut sink, pool(0), usd(100), &other, key("fund"))
        .unwrap_err();
    assert_eq!(
        err,
        LedgerError::KeyConflict("fund".to_owned()),
        "another principal is not a retry"
    );
    assert_eq!(err.code(), codes::BUDGET_KEY_CONFLICT);
    assert_eq!(LedgerError::Inconsistent("x").code(), codes::BUDGET_LEDGER_INCONSISTENT);
    assert_eq!(LedgerError::RecoveryRequired.code(), codes::BUDGET_RECOVERY_REQUIRED);
    assert_eq!(
        LedgerError::Insufficient {
            pool: pool(0),
            available: usd(0),
            requested: usd(1)
        }
        .code(),
        codes::BUDGET_HARD_STOP
    );
}

#[test]
fn an_overrun_is_journaled_at_the_highest_risk_tier() {
    // An overrun is an S1 condition, not routine bookkeeping.
    let world = JournalWorld::new();
    let mut journal = world.open();
    let mut ledger = Ledger::default();
    {
        let mut sink = journal_sink(&mut journal);
        ledger
            .allocate(&mut sink, pool(0), usd(100), &sys(), key("fund"))
            .unwrap();
        let held = ledger.reserve(&mut sink, pool(0), rid(1), usd(10), &sys()).unwrap();
        let s = ledger
            .settle(&mut sink, held.begin(), Usage::Reported(usd(25)), &sys())
            .unwrap();
        assert_eq!(s.overrun, usd(15));
    }
    let (records, _) = read_verified(&world.fs, &Path::new("/data").join(JOURNAL_DIR)).unwrap();
    let tiers: Vec<_> = records
        .iter()
        .filter(|r| r.envelope.event_type == types::BUDGET_ENTRY)
        .map(|r| r.envelope.risk_tier)
        .collect();
    assert_eq!(tiers.last(), Some(&RiskTier::MAX));
    assert!(tiers[..tiers.len() - 1].iter().all(|t| *t != RiskTier::MAX));
}
