// SPDX-License-Identifier: Apache-2.0

//! The one-record intent's E2 slice (intent contract): the two-phase ledger, the recovery plan and
//! its stuck items, and repairs. 7 (the ledger), 8 (the ledger's side), 9, 17 (the plan and going
//! live) and 18 (the ledger). Each test that guards a rule names it in its failure message, which
//! its seeded violation in `xtask negative` expects.
//!
//! Boot does not close open one-record Operations yet (E3): [`boot`] here does what the plan says
//! boot will, so the plan's rehearsal and its execution can be compared.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use serde_json::{Value, json};
use uaos_contracts::budget::{BudgetTx, BudgetTxKind, BudgetTxSchema, IdempotencyKey, LedgerDelta, ReasonCode};
use uaos_contracts::digest::Sha256Digest;
use uaos_contracts::event::{Actor, Durability, EventEnvelope, EventSchema, EventType, InlinePayload, Metadata, types};
use uaos_contracts::id::{CorrelationId, CredentialId, EventId, OperationId, PoolId, ReservationId, TypedId};
use uaos_contracts::money::NanoUsd;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::time::{EventTime, WallTime};
use uaos_contracts::wire::{ConfigVersion, MonoNanos, Seq};
use uaos_ledger::inline::{LEDGER_FIELD, expand};
use uaos_ledger::{
    AWAITING_REPAIR, Batch, CloseError, Held, Ledger, LedgerError, MemorySink, RecoveryPlan, Repair, RepairOutcome,
    Reservation, StuckItem, StuckKind, Usage, entries_from_journal, recovery_plan, replay_with_plan, stuck_items,
};
use uaos_state::journal::VerifiedRecord;

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

fn pool(n: u8) -> PoolId {
    PoolId::from_parts(3, [n; 10])
}

fn rid(n: u8) -> ReservationId {
    ReservationId::from_parts(2, [n; 10])
}

fn op(n: u8) -> OperationId {
    OperationId::from_parts(1, [n; 10])
}

fn usd(n: i64) -> NanoUsd {
    NanoUsd::new(n)
}

fn key(text: &str) -> IdempotencyKey {
    IdempotencyKey::new(text).unwrap()
}

fn agent() -> Actor {
    Actor::Agent {
        credential: CredentialId::from_parts(4, [7; 10]),
    }
}

fn reason(code: &str) -> ReasonCode {
    ReasonCode::new(code).unwrap()
}

fn stuck_reservation(n: u8, code: &str) -> StuckItem {
    StuckItem {
        kind: StuckKind::Reservation(rid(n)),
        reason: reason(code),
    }
}

fn stuck_transfer(out: &str, code: &str) -> StuckItem {
    StuckItem {
        kind: StuckKind::Transfer(key(out)),
        reason: reason(code),
    }
}

/// A live ledger with `amount` allocated to each pool.
fn funded(pools: &[(u8, i64)]) -> Ledger {
    let mut ledger = Ledger::default();
    for (n, amount) in pools {
        let batch = ledger
            .prepare_allocate(pool(*n), usd(*amount), &Actor::System, key(&format!("fund{n}")))
            .unwrap();
        ledger.apply(batch);
    }
    ledger
}

fn reserve(ledger: &mut Ledger, n: u8, p: u8, amount: i64) -> Reservation<Held> {
    let batch = ledger.prepare_reserve(pool(p), rid(n), usd(amount), &agent()).unwrap();
    ledger.apply(batch)
}

fn with_ledger(fields: Value, delta: &LedgerDelta) -> Value {
    let mut payload = fields;
    payload
        .as_object_mut()
        .unwrap()
        .insert(LEDGER_FIELD.to_owned(), serde_json::to_value(delta).unwrap());
    payload
}

/// A journal built record by record, and the ledger that wrote its entries (the previous run).
struct Book {
    records: Vec<VerifiedRecord>,
    writer: Ledger,
}

impl Book {
    fn new() -> Self {
        Self {
            records: Vec::new(),
            writer: Ledger::default(),
        }
    }

    fn push(&mut self, event_type: EventType, operation: Option<OperationId>, actor: &Actor, payload: Option<Value>) {
        let seq = u64::try_from(self.records.len()).unwrap();
        let envelope = EventEnvelope {
            schema: EventSchema::V1,
            id: EventId::from_parts(1_760_000_000_000 + seq, [1; 10]),
            seq: Seq(seq),
            ts: EventTime {
                wall: WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
                mono_ns: MonoNanos(seq),
            },
            session_id: None,
            pocket_id: None,
            operation_id: operation,
            request_id: None,
            agent_id: None,
            correlation_id: CorrelationId::from_parts(5, [5; 10]),
            parent_id: None,
            actor: actor.clone(),
            event_type,
            payload_ref: None,
            payload_inline: payload.map(|p| InlinePayload::new(p).unwrap()),
            cost_estimate: None,
            compensable: false,
            side_effect_class: SideEffectClass::External,
            risk_tier: RiskTier::new(1).unwrap(),
            durability: Durability::Critical,
            config_version: ConfigVersion(1),
            prev_hash: Sha256Digest::from_bytes([0; 32]),
            metadata: Metadata::default(),
        };
        self.records.push(VerifiedRecord {
            envelope,
            hash: Sha256Digest::from_bytes([0; 32]),
        });
    }

    /// One `budget.entry` record per entry, its actor the entry's principal.
    fn budget_entries(&mut self, entries: &[BudgetTx]) {
        for tx in entries {
            let payload = serde_json::to_value(tx).unwrap();
            self.push(types::BUDGET_ENTRY, None, &tx.principal.clone(), Some(payload));
        }
    }

    fn allocate(&mut self, p: u8, amount: i64) {
        let mut batch = self
            .writer
            .prepare_allocate(pool(p), usd(amount), &Actor::System, key(&format!("fund{p}")))
            .unwrap();
        self.budget_entries(batch.entries());
        self.writer.apply_step(&mut batch);
        self.writer.apply(batch);
    }

    /// A crafted `budget.entry`: an allocation of 0 to pool 9 under `taken`, a key the ledger
    /// derives for itself, so the recovery entry that needs that key is refused (a stuck item).
    fn collide(&mut self, taken: &str) {
        let tx = BudgetTx {
            schema: BudgetTxSchema::V1,
            idempotency_key: key(taken),
            pool_id: pool(9),
            principal: Actor::System,
            session_id: None,
            kind: BudgetTxKind::Allocate,
            amount: usd(0),
            balance_before: usd(0),
            balance_after: usd(0),
            reason_code: reason("allocate"),
            related_event: None,
            reservation_id: None,
            counterparty_pool: None,
            settled: false,
            estimated: false,
        };
        self.budget_entries(&[tx]);
    }

    /// A crafted allocation to pool `p`, whose journaled balance is `before`.
    fn top_up(&mut self, p: u8, before: i64, amount: i64) {
        let tx = BudgetTx {
            schema: BudgetTxSchema::V1,
            idempotency_key: key(&format!("top{p}")),
            pool_id: pool(p),
            principal: Actor::System,
            session_id: None,
            kind: BudgetTxKind::Allocate,
            amount: usd(amount),
            balance_before: usd(before),
            balance_after: usd(before + amount),
            reason_code: reason("allocate"),
            related_event: None,
            reservation_id: None,
            counterparty_pool: None,
            settled: false,
            estimated: false,
        };
        self.budget_entries(&[tx]);
    }

    /// A one-record intent: the reserve inside `op.reserved_intent`.
    fn one_record(&mut self, o: u8, r: u8, p: u8, amount: i64) -> Reservation<Held> {
        let batch = self
            .writer
            .prepare_reserve(pool(p), rid(r), usd(amount), &agent())
            .unwrap();
        let payload = with_ledger(
            json!({"kind": "model_call", "upstream": "primary", "durability": "balanced"}),
            &batch.delta().unwrap(),
        );
        self.push(types::OP_RESERVED_INTENT, Some(op(o)), &agent(), Some(payload));
        self.writer.apply(batch)
    }

    /// A two-record intent: the reserve's `budget.entry`, then `op.reserved_intent` without one.
    fn two_record(&mut self, o: u8, r: u8, p: u8, amount: i64) {
        let batch = self
            .writer
            .prepare_reserve(pool(p), rid(r), usd(amount), &agent())
            .unwrap();
        self.budget_entries(batch.entries());
        self.push(
            types::OP_RESERVED_INTENT,
            Some(op(o)),
            &agent(),
            Some(json!({"kind": "model_call", "upstream": "primary"})),
        );
        drop(self.writer.apply(batch));
    }

    /// A transfer whose `transfer_out` landed and whose `transfer_in` did not. The writer applies
    /// both, so later writes through it must not touch `to`.
    fn half_transfer(&mut self, from: u8, to: u8, amount: i64, out: &str) {
        let batch = self
            .writer
            .prepare_transfer(pool(from), pool(to), usd(amount), &Actor::System, key(out))
            .unwrap();
        self.budget_entries(&batch.entries()[..1]);
        self.writer.apply(batch);
    }

    /// Boot's `op.indeterminate`, with the settlement it closes, or without entries (a stuck item).
    fn indeterminate(&mut self, operation: OperationId, delta: Option<&LedgerDelta>) {
        let fields = json!({"reason": "crash_recovery", "may_have_taken_effect": true, "executing_recorded": false});
        let payload = match delta {
            Some(delta) => with_ledger(fields, delta),
            None => fields,
        };
        self.push(types::OP_INDETERMINATE, Some(operation), &Actor::System, Some(payload));
    }

    /// A repair's resolution of a one-record Operation (E12).
    fn resolution(&mut self, event_type: EventType, operation: OperationId, delta: &LedgerDelta) {
        let payload = with_ledger(json!({"reason": "stuck_repair", "resolution": "settled"}), delta);
        self.push(event_type, Some(operation), &Actor::Human, Some(payload));
    }

    fn replayed(&self) -> Ledger {
        Ledger::replay(&entries_from_journal(&self.records).unwrap()).unwrap()
    }
}

/// What boot does with the plan (E3 builds it into boot): each open one-record Operation closes in
/// its own `op.indeterminate`, with its settlement or, refused, without entries; then `recover`
/// closes the rest through `budget.entry` records. Returns the ledger and what `recover` wrote.
fn boot(book: &mut Book) -> (Ledger, RecoveryPlan, Vec<BudgetTx>) {
    let (mut ledger, plan) = replay_with_plan(&book.records).unwrap();
    for open in plan.open() {
        if open.settles {
            let batch = ledger.prepare_recovery_settle(open.reservation).unwrap();
            book.indeterminate(open.operation, Some(&batch.delta().unwrap()));
            let _settled = ledger.apply(batch);
        } else {
            book.indeterminate(open.operation, None);
        }
    }
    let mut sink = MemorySink::default();
    ledger.recover(&mut sink, &Actor::System, &plan).unwrap();
    book.budget_entries(&sink.entries);
    (ledger, plan, sink.entries)
}

// `expand(compact(e)) == e` for every entry `prepare_*` produces for an Operation
// ---------------------------------------------------------------------------------------------

/// The batch's delta expands back to its entries exactly, and survives the wire.
fn survives<T>(batch: &Batch<T>) -> Result<(), TestCaseError> {
    let delta = batch
        .delta()
        .map_err(|e| TestCaseError::fail(format!("a prepared entry does not survive the delta: {e}")))?;
    let actor = &batch.entries()[0].principal;
    prop_assert_eq!(
        expand(&delta, actor).unwrap(),
        batch.entries(),
        "a prepared entry does not survive the delta"
    );
    let wire: LedgerDelta = serde_json::from_value(serde_json::to_value(&delta).unwrap()).unwrap();
    prop_assert_eq!(wire, delta, "a prepared entry does not survive the delta");
    Ok(())
}

/// How the Operation's reservation closes.
#[derive(Debug, Clone, Copy)]
enum Close {
    Release,
    Settle(i64),
    SettleUnknown,
    RecoverySettle,
    RecoveryRelease,
    RepairSettle(i64, RepairOutcome),
    RepairRelease,
}

fn amount() -> impl Strategy<Value = i64> {
    prop_oneof![Just(0_i64), Just(1), Just(i64::MAX - 1), Just(i64::MAX), 0..=i64::MAX]
}

fn close() -> impl Strategy<Value = Close> {
    let outcome = prop_oneof![Just(RepairOutcome::Committed), Just(RepairOutcome::Failed)];
    prop_oneof![
        Just(Close::Release),
        amount().prop_map(Close::Settle),
        Just(Close::SettleUnknown),
        Just(Close::RecoverySettle),
        Just(Close::RecoveryRelease),
        (amount(), outcome).prop_map(|(spent, outcome)| Close::RepairSettle(spent, outcome)),
        Just(Close::RepairRelease),
    ]
}

/// Reserves `reserved` of `funds` in a one-record intent, then prepares `close`; checks every
/// batch that prepares. Returns whether the close prepared.
fn operation_survives(funds: i64, reserved: i64, close: Close) -> Result<bool, TestCaseError> {
    let mut book = Book::new();
    book.allocate(1, funds);
    let batch = book
        .writer
        .prepare_reserve(pool(1), rid(1), usd(reserved), &agent())
        .unwrap();
    survives(&batch)?;
    let payload = with_ledger(json!({"kind": "model_call"}), &batch.delta().unwrap());
    book.push(types::OP_RESERVED_INTENT, Some(op(1)), &agent(), Some(payload));
    let held = book.writer.apply(batch);
    let prepared = match close {
        Close::Release => book.writer.prepare_release(held, &agent()).map(|b| survives(&b)).ok(),
        Close::Settle(spent) => book
            .writer
            .prepare_settle(held.begin(), Usage::Reported(usd(spent)), &agent())
            .map(|b| survives(&b))
            .ok(),
        Close::SettleUnknown => book
            .writer
            .prepare_settle(held.begin(), Usage::Unknown, &agent())
            .map(|b| survives(&b))
            .ok(),
        Close::RecoverySettle => book
            .replayed()
            .prepare_recovery_settle(rid(1))
            .map(|b| survives(&b))
            .ok(),
        Close::RecoveryRelease => book
            .replayed()
            .prepare_recovery_release(rid(1))
            .map(|b| survives(&b))
            .ok(),
        Close::RepairSettle(..) | Close::RepairRelease => {
            drop(held);
            book.indeterminate(op(1), None);
            let (mut ledger, plan, _) = boot(&mut book);
            let item = plan.stuck().next().unwrap().clone();
            let repair = match close {
                Close::RepairSettle(spent, outcome) => Repair::Settle {
                    amount: usd(spent),
                    outcome,
                },
                _ => Repair::Release,
            };
            ledger
                .prepare_repair(&item, repair, &Actor::Human)
                .map(|b| survives(&b))
                .ok()
        }
    };
    prepared.transpose().map(|p| p.is_some())
}

proptest! {
    #[test]
    fn every_entry_prepared_for_an_operation_survives_the_delta(
        funds in amount(),
        reserved in amount(),
        close in close(),
    ) {
        operation_survives(funds, reserved.min(funds), close)?;
    }
}

#[test]
fn the_extremes_prepare_and_survive_the_delta() {
    // Every amount at its 64-bit extreme: each close prepares, so the property above covers it.
    let max = i64::MAX;
    for (funds, reserved, close) in [
        (max, max, Close::Release),
        (max, max, Close::Settle(0)),
        (max, max, Close::Settle(max)),
        (max, 0, Close::Settle(max)),
        (max, max, Close::SettleUnknown),
        (max, max, Close::RecoverySettle),
        (max, max, Close::RecoveryRelease),
        (max, max, Close::RepairSettle(0, RepairOutcome::Failed)),
        (max, 0, Close::RepairSettle(max, RepairOutcome::Committed)),
        (max, max, Close::RepairRelease),
    ] {
        assert!(
            operation_survives(funds, reserved, close).unwrap(),
            "{close:?} at the extremes did not prepare"
        );
    }
}

// State only after the acknowledgement
// ---------------------------------------------------------------------------------------------

#[test]
fn a_prepared_batch_changes_nothing_until_it_is_applied() {
    let mut ledger = funded(&[(1, 100), (2, 0)]);
    let before = ledger.state().clone();
    let batch = ledger.prepare_reserve(pool(1), rid(1), usd(30), &agent()).unwrap();
    assert_eq!(ledger.state(), &before, "the ledger changed before the acknowledgement");
    let held = ledger.apply(batch);
    assert_ne!(ledger.state(), &before, "an applied batch changed nothing");

    let before = ledger.state().clone();
    let batch = ledger
        .prepare_transfer(pool(1), pool(2), usd(10), &agent(), key("t"))
        .unwrap();
    assert_eq!(ledger.state(), &before, "the ledger changed before the acknowledgement");
    ledger.apply(batch);

    // A settlement with an overrun, two entries: prepared, then its record's fate is unknown.
    let before = ledger.state().clone();
    let batch = ledger
        .prepare_settle(held.begin(), Usage::Reported(usd(50)), &agent())
        .unwrap();
    assert_eq!(batch.entries().len(), 2);
    assert_eq!(ledger.state(), &before, "the ledger changed before the acknowledgement");
    ledger.abandon(batch);
    assert_eq!(ledger.state(), &before, "an abandoned batch changed the state");
    assert!(ledger.is_poisoned(), "an abandoned batch left the ledger live");
    assert_eq!(
        ledger
            .prepare_allocate(pool(1), usd(1), &Actor::System, key("more"))
            .unwrap_err(),
        LedgerError::Poisoned,
        "a poisoned ledger prepared new work"
    );
}

#[test]
fn boot_and_repair_batches_change_nothing_until_applied() {
    let mut book = Book::new();
    book.allocate(1, 100);
    drop(book.one_record(1, 1, 1, 30));
    let mut ledger = book.replayed();
    let before = ledger.state().clone();
    let batch = ledger.prepare_recovery_settle(rid(1)).unwrap();
    assert_eq!(ledger.state(), &before, "the ledger changed before the acknowledgement");
    ledger.abandon(batch);
    assert_eq!(ledger.state(), &before, "an abandoned batch changed the state");

    book.indeterminate(op(1), None);
    let (mut ledger, plan, _) = boot(&mut book);
    let before = ledger.state().clone();
    let item = plan.stuck().next().unwrap().clone();
    let batch = ledger.prepare_repair(&item, Repair::Release, &Actor::Human).unwrap();
    assert_eq!(ledger.state(), &before, "the ledger changed before the acknowledgement");
    ledger.withdraw(batch);
    assert_eq!(ledger.stuck(), [item], "a withdrawn repair closed its item");
}

#[test]
fn poison_stops_the_ledger_for_a_record_without_a_batch() {
    // `op.executing` carries no batch: an error of unknown fate there poisons the ledger.
    let mut ledger = funded(&[(1, 100)]);
    let held = reserve(&mut ledger, 1, 1, 10);
    ledger.poison();
    assert!(ledger.is_poisoned());
    match ledger.prepare_release(held, &agent()) {
        Err(CloseError::Rejected { error, .. }) => assert_eq!(error, LedgerError::Poisoned),
        other => panic!("a poisoned ledger prepared a close: {other:?}"),
    }
}

// A refusal that wrote nothing does not poison; anything else does
// ---------------------------------------------------------------------------------------------

#[test]
fn a_refusal_that_wrote_nothing_withdraws_and_the_ledger_stays_live() {
    let mut ledger = funded(&[(1, 100)]);
    let held = reserve(&mut ledger, 1, 1, 30);
    let before = ledger.state().clone();
    let batch = ledger.prepare_release(held, &agent()).unwrap();
    let held = ledger
        .withdraw(batch)
        .expect("a withdrawn release gives its token back");
    assert!(
        !ledger.is_poisoned(),
        "a refusal that wrote nothing poisoned the ledger"
    );
    assert_eq!(ledger.state(), &before, "a withdrawn batch changed the state");
    // The token comes back, and the close is retried with it.
    let batch = ledger
        .prepare_settle(held.begin(), Usage::Reported(usd(10)), &agent())
        .unwrap();
    let in_flight = ledger
        .withdraw(batch)
        .expect("a withdrawn settlement gives its token back");
    assert!(
        !ledger.is_poisoned(),
        "a refusal that wrote nothing poisoned the ledger"
    );
    let batch = ledger
        .prepare_settle(in_flight, Usage::Reported(usd(10)), &agent())
        .unwrap();
    let settlement = ledger.apply(batch);
    assert_eq!((settlement.spent, settlement.released), (usd(10), usd(20)));
    assert_eq!(ledger.state().open_reservations(), 0);
}

#[test]
fn a_batch_part_journaled_cannot_be_withdrawn() {
    // A transfer whose second record is refused after the first landed: the ledger is poisoned.
    let mut ledger = funded(&[(1, 100), (2, 0)]);
    let mut batch = ledger
        .prepare_transfer(pool(1), pool(2), usd(10), &agent(), key("t"))
        .unwrap();
    ledger.apply_step(&mut batch);
    ledger.withdraw(batch);
    assert!(
        ledger.is_poisoned(),
        "a withdraw after a record landed left the ledger live"
    );
    assert_eq!(
        ledger
            .prepare_allocate(pool(1), usd(1), &Actor::System, key("more"))
            .unwrap_err(),
        LedgerError::Poisoned
    );
}

#[test]
fn several_records_apply_record_by_record() {
    let mut ledger = funded(&[(1, 100), (2, 0)]);
    let mut batch = ledger
        .prepare_transfer(pool(1), pool(2), usd(10), &agent(), key("t"))
        .unwrap();
    ledger.apply_step(&mut batch);
    assert_eq!(
        ledger.state().pending_transfers(),
        1,
        "the first record's entry was not applied"
    );
    ledger.apply_step(&mut batch);
    ledger.apply(batch);
    assert_eq!(ledger.state().pending_transfers(), 0);
    assert_eq!(ledger.state().pool(pool(2)).unwrap().available, usd(10));
}

// One batch at a time
// ---------------------------------------------------------------------------------------------

#[test]
fn one_batch_at_a_time() {
    let mut ledger = funded(&[(1, 100), (2, 0)]);
    let held = reserve(&mut ledger, 1, 1, 10);
    let in_flight = reserve(&mut ledger, 2, 1, 10).begin();
    let first = ledger
        .prepare_allocate(pool(1), usd(1), &Actor::System, key("a"))
        .unwrap();
    let second = "a second batch was prepared while one was outstanding";
    assert!(
        matches!(
            ledger.prepare_reserve(pool(1), rid(3), usd(1), &agent()),
            Err(LedgerError::Pending)
        ),
        "{second}"
    );
    assert!(
        matches!(
            ledger.prepare_allocate(pool(1), usd(1), &Actor::System, key("b")),
            Err(LedgerError::Pending)
        ),
        "{second}"
    );
    assert!(
        matches!(
            ledger.prepare_transfer(pool(1), pool(2), usd(1), &agent(), key("t")),
            Err(LedgerError::Pending)
        ),
        "{second}"
    );
    let held = match ledger.prepare_release(held, &agent()) {
        Err(CloseError::Rejected { error, reservation }) => {
            assert_eq!(error, LedgerError::Pending, "{second}");
            reservation
        }
        other => panic!("{second}: {other:?}"),
    };
    let in_flight = match ledger.prepare_settle(in_flight, Usage::Unknown, &agent()) {
        Err(CloseError::Rejected { error, reservation }) => {
            assert_eq!(error, LedgerError::Pending, "{second}");
            reservation
        }
        other => panic!("{second}: {other:?}"),
    };
    ledger.apply(first);
    let batch = ledger.prepare_release(held, &agent()).unwrap();
    ledger.apply(batch);
    let batch = ledger.prepare_settle(in_flight, Usage::Unknown, &agent()).unwrap();
    let _settled = ledger.apply(batch);
}

#[test]
fn one_batch_at_a_time_at_boot() {
    let mut book = Book::new();
    book.allocate(1, 100);
    drop(book.one_record(1, 1, 1, 10));
    drop(book.one_record(2, 2, 1, 10));
    let (mut ledger, plan) = replay_with_plan(&book.records).unwrap();
    let first = ledger.prepare_recovery_settle(rid(1)).unwrap();
    let second = "a second batch was prepared while one was outstanding";
    assert!(
        matches!(ledger.prepare_recovery_settle(rid(2)), Err(LedgerError::Pending)),
        "{second}"
    );
    assert!(
        matches!(ledger.prepare_recovery_release(rid(2)), Err(LedgerError::Pending)),
        "{second}"
    );
    assert!(
        matches!(
            ledger.recover(&mut MemorySink::default(), &Actor::System, &plan),
            Err(LedgerError::Pending)
        ),
        "{second}"
    );
    let _settled = ledger.apply(first);
}

// Stuck items counted, listed, and holding the ledger
// ---------------------------------------------------------------------------------------------

/// A journal whose recovery leaves one item of each kind stuck: a one-record reservation whose
/// settlement the ledger refuses, one an earlier boot left stuck, a two-record reservation, and a
/// transfer. Operation 1 is open and settles.
fn stuck_journal() -> Book {
    let mut book = Book::new();
    book.allocate(1, 1000);
    book.allocate(2, 0);
    drop(book.one_record(1, 1, 1, 100));
    drop(book.one_record(2, 2, 1, 100));
    book.collide(&format!("{}:settle", rid(2)));
    drop(book.one_record(4, 4, 1, 100));
    book.indeterminate(op(4), None);
    book.two_record(3, 3, 1, 100);
    book.collide(&format!("{}:settle", rid(3)));
    book.half_transfer(1, 2, 10, "t");
    book.collide("t:in");
    book
}

fn expected_stuck() -> Vec<StuckItem> {
    vec![
        stuck_reservation(2, "key_conflict"),
        stuck_reservation(4, AWAITING_REPAIR),
        stuck_reservation(3, "key_conflict"),
        stuck_transfer("t", "key_conflict"),
    ]
}

#[test]
fn the_plan_counts_each_stuck_item_once_on_this_boot_and_the_next() {
    let mut book = stuck_journal();
    let plan = recovery_plan(&book.records).unwrap();
    assert_eq!(
        plan.stuck().cloned().collect::<Vec<_>>(),
        expected_stuck(),
        "the plan miscounted the stuck items on the first boot"
    );
    assert_eq!((plan.stuck_reservations(), plan.stuck_transfers()), (3, 1));
    let open: Vec<_> = plan.open().iter().map(|o| (o.operation, o.settles)).collect();
    assert_eq!(open, [(op(1), true), (op(2), false)], "the plan's open Operations");

    let records = book.records.len();
    assert_eq!(
        stuck_items(&book.records).unwrap(),
        expected_stuck(),
        "stuck_items lists other items than the plan"
    );
    assert_eq!(book.records.len(), records, "listing stuck items wrote a record");

    // The boot that writes the entry-less `op.indeterminate`, and the next, count the same.
    let (_, _, written) = boot(&mut book);
    assert!(written.is_empty(), "recovery closed a stuck item: {written:?}");
    let next = recovery_plan(&book.records).unwrap();
    assert_eq!(
        next.stuck().cloned().collect::<Vec<_>>(),
        expected_stuck(),
        "the plan miscounted the stuck items on the next boot"
    );
    assert!(next.open().is_empty(), "a closed Operation is still open");
}

#[test]
fn recover_never_writes_for_a_one_record_reservation() {
    let mut book = Book::new();
    book.allocate(1, 1000);
    drop(book.one_record(1, 1, 1, 100));
    drop(book.one_record(2, 2, 1, 100));
    book.indeterminate(op(2), None);
    book.two_record(3, 3, 1, 100);

    // Before boot closes Operation 1 in its own record, `recover` refuses and writes nothing.
    let (mut ledger, plan) = replay_with_plan(&book.records).unwrap();
    let mut sink = MemorySink::default();
    assert!(matches!(
        ledger.recover(&mut sink, &Actor::System, &plan),
        Err(LedgerError::Inconsistent(_))
    ));
    assert!(sink.entries.is_empty(), "a refused recovery wrote {:?}", sink.entries);

    let (_, plan, written) = boot(&mut book);
    assert!(
        written
            .iter()
            .all(|tx| tx.reservation_id.is_none_or(|r| !plan.is_one_record(r))),
        "recover wrote a budget.entry for a one-record reservation: {written:?}"
    );
    assert_eq!(
        written
            .iter()
            .map(|tx| (tx.reservation_id, tx.kind, tx.estimated))
            .collect::<Vec<_>>(),
        [(Some(rid(3)), BudgetTxKind::Settle, true)],
        "the two-record reservation was not settled in full, estimated"
    );
    // The journal boot leaves reads, and replays to the same ledger.
    assert_eq!(book.replayed().state().open_reservations(), 1);
}

#[test]
fn a_stuck_one_record_reservation_holds_the_ledger() {
    let mut book = Book::new();
    book.allocate(1, 1000);
    drop(book.one_record(1, 1, 1, 100));
    book.indeterminate(op(1), None);
    let (mut ledger, plan, _) = boot(&mut book);
    assert_eq!(
        plan.stuck().cloned().collect::<Vec<_>>(),
        [stuck_reservation(1, AWAITING_REPAIR)]
    );
    assert!(
        ledger.needs_recovery(),
        "the ledger went live with a one-record item stuck"
    );
    assert!(
        matches!(
            ledger.prepare_allocate(pool(1), usd(1), &Actor::System, key("more")),
            Err(LedgerError::RecoveryRequired)
        ),
        "the ledger went live with a one-record item stuck"
    );
    // The human's repair, the Operation's resolution: the last item closes and the ledger is live.
    let batch = ledger
        .prepare_repair(&stuck_reservation(1, AWAITING_REPAIR), Repair::Release, &Actor::Human)
        .unwrap();
    book.resolution(types::OP_FAILED, op(1), &batch.delta().unwrap());
    ledger.apply(batch);
    assert!(
        !ledger.needs_recovery(),
        "the last repair left the ledger refusing work"
    );
    let batch = ledger
        .prepare_allocate(pool(1), usd(1), &Actor::System, key("more"))
        .unwrap();
    ledger.apply(batch);
    assert_eq!(book.replayed().state().open_reservations(), 0);
}

// A repair needs a stuck item, and replays with its own keys
// ---------------------------------------------------------------------------------------------

#[test]
fn a_repair_needs_a_stuck_item() {
    let not_stuck = "a repair was prepared for an item that is not stuck";
    // A live reservation, whose token is still held.
    let mut ledger = funded(&[(1, 100)]);
    let _held = reserve(&mut ledger, 1, 1, 30);
    let live = stuck_reservation(1, "key_conflict");
    assert!(
        matches!(
            ledger.prepare_repair(&live, Repair::Release, &Actor::Human),
            Err(LedgerError::NotStuck)
        ),
        "{not_stuck}"
    );
    // A recovered ledger with a stuck item: another open item, and a transfer it never left
    // stuck, are refused; so is a repair signed by anyone but a human.
    let mut book = stuck_journal();
    let (mut ledger, _, _) = boot(&mut book);
    for item in [
        stuck_reservation(1, "key_conflict"),
        stuck_transfer("u", "key_conflict"),
    ] {
        assert!(
            matches!(
                ledger.prepare_repair(&item, Repair::Release, &Actor::Human),
                Err(LedgerError::NotStuck)
            ),
            "{not_stuck}"
        );
    }
    for principal in [Actor::System, agent()] {
        assert!(
            matches!(
                ledger.prepare_repair(&stuck_reservation(3, "key_conflict"), Repair::Release, &principal),
                Err(LedgerError::Inconsistent(_))
            ),
            "a repair signed by {principal:?} was prepared"
        );
    }
    // A repair that does not fit its item.
    assert!(matches!(
        ledger.prepare_repair(&stuck_transfer("t", "key_conflict"), Repair::Release, &Actor::Human),
        Err(LedgerError::Inconsistent(_))
    ));
    assert!(ledger.needs_recovery());
}

/// A journal with a stuck item for every repair: two-record reservations 1, 2, 3 and 6, one-record
/// reservations 4 and 5 left stuck by an earlier boot, a transfer `back` stuck by a key, and a
/// transfer `over` whose destination would overflow until reservation 6's overrun is charged.
fn repair_journal() -> Book {
    let mut book = Book::new();
    book.allocate(1, 1000);
    book.allocate(2, 1000);
    book.allocate(3, 1000);
    for n in [1, 2, 3] {
        book.two_record(n, n, 1, 100);
        book.collide(&format!("{}:settle", rid(n)));
    }
    for n in [4, 5] {
        drop(book.one_record(n, n, 3, 100));
        book.indeterminate(op(n), None);
    }
    book.two_record(6, 6, 2, 100);
    book.collide(&format!("{}:settle", rid(6)));
    book.half_transfer(1, 3, 10, "back");
    book.collide("back:in");
    book.half_transfer(1, 2, 50, "over");
    book.top_up(2, 900, i64::MAX - 920);
    book
}

fn keys(entries: &[BudgetTx]) -> Vec<String> {
    entries
        .iter()
        .map(|tx| tx.idempotency_key.as_str().to_owned())
        .collect()
}

#[test]
fn each_repair_replays_with_its_own_keys() {
    let own = "a repair's entries do not carry their own keys";
    let mut book = repair_journal();
    let (mut ledger, plan, written) = boot(&mut book);
    assert!(written.is_empty(), "recovery closed a stuck item: {written:?}");
    let over = stuck_transfer("over", "overflow");
    assert_eq!(
        plan.stuck().cloned().collect::<Vec<_>>(),
        [
            stuck_reservation(4, AWAITING_REPAIR),
            stuck_reservation(5, AWAITING_REPAIR),
            stuck_reservation(1, "key_conflict"),
            stuck_reservation(2, "key_conflict"),
            stuck_reservation(3, "key_conflict"),
            stuck_reservation(6, "key_conflict"),
            stuck_transfer("back", "key_conflict"),
            over.clone(),
        ]
    );
    // Until reservation 6's overrun is charged, the transfer's destination would overflow.
    assert_eq!(
        ledger
            .prepare_repair(&over, Repair::CompleteTransfer, &Actor::Human)
            .unwrap_err(),
        LedgerError::Overflow
    );

    // Two-record repairs: `budget.entry` records, one per entry, applied record by record.
    let two_record = [
        (
            stuck_reservation(1, "key_conflict"),
            settle(60),
            vec!["repair_settle", "repair_release"],
        ),
        (
            stuck_reservation(2, "key_conflict"),
            Repair::Release,
            vec!["repair_release"],
        ),
        (stuck_reservation(3, "key_conflict"), settle(100), vec!["repair_settle"]),
        (
            stuck_reservation(6, "key_conflict"),
            settle(150),
            vec!["repair_settle", "repair_overrun"],
        ),
    ];
    for (item, repair, suffixes) in two_record {
        let StuckKind::Reservation(id) = item.kind else {
            unreachable!()
        };
        let expected: Vec<_> = suffixes.iter().map(|s| format!("{id}:{s}")).collect();
        repair_by_records(&mut ledger, &mut book, &item, repair, &expected);
    }
    // One-record repairs: the Operation's resolution carries the delta.
    for (n, repair, record, suffixes) in [
        (
            4,
            settle_as(70, RepairOutcome::Failed),
            types::OP_FAILED,
            vec!["repair_settle", "repair_release"],
        ),
        (5, Repair::Release, types::OP_FAILED, vec!["repair_release"]),
    ] {
        let batch = ledger
            .prepare_repair(&stuck_reservation(n, AWAITING_REPAIR), repair, &Actor::Human)
            .expect(own);
        let expected: Vec<_> = suffixes.iter().map(|s| format!("{}:{s}", rid(n))).collect();
        assert_eq!(keys(batch.entries()), expected, "{own}");
        book.resolution(record, op(n), &batch.delta().expect(own));
        ledger.apply(batch);
    }
    // Transfers: `<out>:return` back into the source, `<out>:in` into the destination.
    for (item, repair, expected) in [
        (
            stuck_transfer("back", "key_conflict"),
            Repair::ReturnTransfer,
            "back:return",
        ),
        (over, Repair::CompleteTransfer, "over:in"),
    ] {
        repair_by_records(&mut ledger, &mut book, &item, repair, &[expected.to_owned()]);
    }

    assert!(ledger.stuck().is_empty());
    assert!(
        !ledger.needs_recovery(),
        "the last repair left the ledger refusing work"
    );
    assert_eq!(
        book.replayed().state(),
        ledger.state(),
        "the repaired journal does not replay to the repaired ledger"
    );
    let back = book.replayed().state().pool(pool(1)).unwrap().available;
    assert_eq!(
        back,
        usd(1000 - 300 + 40 + 100 - 50),
        "the returned transfer did not credit its source"
    );
}

/// A repair journaled as `budget.entry` records, one per entry, applied record by record; its
/// keys are `expected`.
fn repair_by_records(ledger: &mut Ledger, book: &mut Book, item: &StuckItem, repair: Repair, expected: &[String]) {
    let own = "a repair's entries do not carry their own keys";
    let mut batch = ledger.prepare_repair(item, repair, &Actor::Human).expect(own);
    assert_eq!(keys(batch.entries()), expected, "{own}");
    book.budget_entries(batch.entries());
    for _ in 0..batch.entries().len() {
        ledger.apply_step(&mut batch);
    }
    ledger.apply(batch);
}

fn settle(amount: i64) -> Repair {
    settle_as(amount, RepairOutcome::Committed)
}

fn settle_as(amount: i64, outcome: RepairOutcome) -> Repair {
    Repair::Settle {
        amount: usd(amount),
        outcome,
    }
}

#[test]
fn replay_accepts_a_repair_only_as_a_human_close() {
    let mut book = repair_journal();
    let (mut ledger, _, _) = boot(&mut book);
    let batch = ledger
        .prepare_repair(
            &stuck_transfer("back", "key_conflict"),
            Repair::ReturnTransfer,
            &Actor::Human,
        )
        .unwrap();
    let repair = batch.entries()[0].clone();
    ledger.withdraw(batch);
    let mut entries = entries_from_journal(&book.records).unwrap();
    entries.push(repair.clone());
    Ledger::replay(&entries).expect("a human's return replays");

    // Signed by the system, or a return with another reason: refused on replay.
    let mut system = repair.clone();
    system.principal = Actor::System;
    let mut ordinary = repair;
    ordinary.reason_code = reason("transfer_recovered");
    for crafted in [system, ordinary] {
        let mut entries = entries_from_journal(&book.records).unwrap();
        entries.push(crafted.clone());
        assert!(
            matches!(Ledger::replay(&entries), Err(LedgerError::Inconsistent(_))),
            "replay accepted {crafted:?}"
        );
    }
}

#[test]
fn the_rehearsal_leaves_the_replayed_ledger_as_it_was() {
    // The plan rehearses boot on the replayed ledger itself and undoes it: boot then gets the
    // ledger a plain replay builds, not one already recovered.
    let book = stuck_journal();
    let (mut ledger, plan) = replay_with_plan(&book.records).unwrap();
    let fresh = book.replayed();
    assert_eq!(
        ledger.state(),
        fresh.state(),
        "the rehearsal changed the replayed ledger"
    );
    assert!(ledger.needs_recovery() && ledger.stuck().is_empty() && !ledger.is_poisoned());
    assert_eq!(plan.open().len(), 2);
    let batch = ledger
        .prepare_recovery_settle(rid(1))
        .expect("the rehearsal left the ledger recovered");
    let _settled = ledger.apply(batch);
}
