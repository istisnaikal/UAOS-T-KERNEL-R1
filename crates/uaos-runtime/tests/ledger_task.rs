// SPDX-License-Identifier: Apache-2.0

//! The ledger task (intent contract), slice E4b: §10 rows 1 (no reservation without its intent), 7
//! (the task: state only after the acknowledgement), 8 (the handle's side: a refusal that wrote
//! nothing withdraws, anything else abandons and stops), 10 (no double spend, every write ordered)
//! and 11 (`Held` only after the intent). Each test that guards a rule names it in its failure
//! message, which its seeded violation in `xtask negative` expects.
//!
//! The ledger task gets a stop of its own here, so that what it engages is not hidden behind the
//! state actor's engagement of the same failure; in the kernel the two share one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::time::Instant;

use uaos_contracts::budget::{BudgetTxKind, DeltaEntry, IdempotencyKey, LedgerDelta, ReasonCode};
use uaos_contracts::error::codes;
use uaos_contracts::event::{Actor, Durability, EventType, InlinePayload, Metadata, types};
use uaos_contracts::id::{CorrelationId, OperationId, PoolId, ReservationId, TypedId};
use uaos_contracts::money::NanoUsd;
use uaos_contracts::operation::{OperationKind, RiskTier, SideEffectClass};
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::ConfigVersion;
use uaos_egress::addr::Blocked;
use uaos_egress::{EgressError, UpstreamError};
use uaos_ledger::{Ledger, LedgerError, entries_from_journal};
use uaos_platform::fs::{AppendFile, Fs, FsError, LockGuard};
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, Rng};
use uaos_runtime::{
    Admission, AdmissionLimits, Booted, ConfigSnapshot, CutReason, DEFAULT_LEDGER_QUEUE, DEFAULT_QUEUE_CAPACITY,
    EngagedBy, LastEnd, LedgerCallError, LedgerHandle, LocaleTag, Movement, OpenReservations, OperationRecord,
    RelayEnd, RelayReport, Released, Settled, ShutdownReason, StateActor, StateCore, StateError, StateHandle, Stop,
    StopReason, Supervisor, SupervisorLimits, boot, shut_down, start_ledger_task, start_state_actor, state_queue,
};
use uaos_state::journal::{EventDraft, FlushPolicy, JOURNAL_DIR, Journal, VerifiedRecord, read_verified};

const DATA: &str = "/data";
const FUNDS: i64 = 1_000;

fn pool(n: u8) -> PoolId {
    PoolId::from_parts(1, [n; 10])
}

fn rid(n: u32) -> ReservationId {
    ReservationId::from_parts(u64::from(n) + 1, [7; 10])
}

fn op(n: u32) -> OperationId {
    OperationId::from_parts(u64::from(n) + 1, [3; 10])
}

fn correlation() -> CorrelationId {
    CorrelationId::from_parts(9, [9; 10])
}

fn by() -> EngagedBy {
    EngagedBy {
        actor: Actor::System,
        correlation_id: correlation(),
        config_version: ConfigVersion(1),
    }
}

fn record(n: u32) -> OperationRecord {
    OperationRecord {
        operation_id: op(n),
        session_id: None,
        pocket_id: None,
        request_id: None,
        agent_id: None,
        correlation_id: CorrelationId::from_parts(u64::from(n) + 20, [4; 10]),
        actor: Actor::System,
        kind: OperationKind::ModelCall,
        upstream: "primary".to_owned(),
        side_effect_class: SideEffectClass::External,
        compensable: false,
        risk_tier: RiskTier::new(1).unwrap(),
        config_version: ConfigVersion(1),
    }
}

fn movement(key: &str) -> Movement {
    Movement {
        principal: Actor::System,
        key: IdempotencyKey::new(key).unwrap(),
        correlation_id: correlation(),
        config_version: ConfigVersion(1),
    }
}

/// A kernel's journal writer and ledger task on a simulated disk.
struct World {
    fs: SimFs,
    data: PathBuf,
    state: StateHandle,
    ledger: LedgerHandle,
    /// The ledger task's own stop.
    stop: Stop,
    supervisor: Supervisor,
    actor: Option<StateActor>,
    /// The journal's and the actor's clock: it stands still unless a test moves it.
    clock: Arc<SimClock>,
}

/// How a world is built.
#[derive(Debug, Clone, Copy)]
struct Setup {
    /// The ledger task's queue, and the tokens it lets live at once.
    capacity: usize,
    /// Whether the state actor journals the ledger task's stop, as the kernel's one stop.
    shared_stop: bool,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_LEDGER_QUEUE,
            shared_stop: false,
        }
    }
}

impl World {
    async fn start() -> Self {
        let fs = SimFs::new();
        Self::start_on(fs.clone(), Arc::new(fs)).await
    }

    /// A world whose journal writes through `disk`, a view of `fs`.
    async fn start_on(fs: SimFs, disk: Arc<dyn Fs>) -> Self {
        Self::build(fs, disk, Setup::default()).await
    }

    async fn build(fs: SimFs, disk: Arc<dyn Fs>, setup: Setup) -> Self {
        fs.create_dir_all(Path::new(DATA)).unwrap();
        let clock = fresh_clock();
        // A kernel's run: the journal is booted first, so its end can be read as clean.
        let dyn_clock: Arc<dyn Clock> = clock.clone();
        let rng: Arc<dyn Rng> = Arc::new(SimRng::new(5));
        let opened = Journal::open_verified(disk, dyn_clock, rng, Path::new(DATA), FlushPolicy::Strict).unwrap();
        let mut journal = opened.journal;
        let config = ConfigSnapshot::new(ConfigVersion(1), LocaleTag::new("en").unwrap());
        let booted = boot(
            &mut journal,
            &opened.records,
            opened.evidence,
            &config,
            by().correlation_id,
        )
        .unwrap();
        let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default());
        let (state, queue) = state_queue(DEFAULT_QUEUE_CAPACITY);
        let stop = Stop::running();
        let core = StateCore::new(journal);
        // The kernel's one stop, which the actor journals, or the ledger task's alone.
        let core = if setup.shared_stop {
            core.with_stop(stop.clone(), by())
        } else {
            core
        };
        let actor = start_state_actor(&supervisor, core, queue).unwrap();
        let (ledger, _task) = start_ledger_task(
            &supervisor,
            booted.ledger,
            state.clone(),
            stop.clone(),
            by(),
            setup.capacity,
        )
        .unwrap();
        ledger
            .allocate(pool(1), NanoUsd::new(FUNDS), movement("fund1"))
            .await
            .unwrap();
        ledger
            .allocate(pool(2), NanoUsd::new(0), movement("fund2"))
            .await
            .unwrap();
        Self {
            fs,
            data: PathBuf::from(DATA),
            state,
            ledger,
            stop,
            supervisor,
            actor: Some(actor),
            clock,
        }
    }

    fn records(&self) -> Vec<VerifiedRecord> {
        read_verified(&self.fs, &self.data.join(JOURNAL_DIR)).unwrap().0
    }

    /// Ends the world as a process does: the handles go, the ledger task ends, then the actor.
    #[allow(
        clippy::disallowed_methods,
        reason = "joining the actor's thread blocks: the test waits for it off the runtime's threads"
    )]
    async fn end(mut self) -> SimFs {
        let actor = self.actor.take().unwrap();
        let Self { fs, state, ledger, .. } = self;
        drop((state, ledger));
        tokio::task::spawn_blocking(move || actor.join().unwrap())
            .await
            .unwrap();
        fs
    }
}

fn fresh_clock() -> Arc<SimClock> {
    Arc::new(SimClock::new(
        WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
    ))
}

fn open_journal(disk: Arc<dyn Fs>, clock: Arc<SimClock>) -> Journal {
    let clock: Arc<dyn Clock> = clock;
    let rng: Arc<dyn Rng> = Arc::new(SimRng::new(5));
    Journal::open(disk, clock, rng, Path::new(DATA), FlushPolicy::Strict).unwrap()
}

/// Polls a future once, as a caller does before it stops waiting.
fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

// `Held` only after the intent, state only after the acknowledgement ────────

#[tokio::test]
async fn a_reservation_is_held_only_after_its_intent_lands() {
    let world = World::start().await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let records = world.records();
    let intent = records.last().unwrap();
    assert_eq!(
        (
            intent.envelope.event_type.clone(),
            intent.envelope.operation_id,
            intent.envelope.id
        ),
        (types::OP_RESERVED_INTENT, Some(op(1)), held.intent()),
        "the reservation was not journaled in its intent"
    );
    let snapshot = world.ledger.snapshot().await.unwrap();
    assert_eq!(snapshot.state.open_reservations(), 1);

    // The disk fills: the next intent's fate is unknown.
    world.fs.set_capacity(Some(0));
    let refused = world
        .ledger
        .reserve(record(2), pool(1), rid(2), NanoUsd::new(100))
        .await;
    let Err(error) = refused else {
        panic!("a reservation was handed out without its intent's acknowledgement");
    };
    assert!(matches!(error, LedgerCallError::Abandoned(_)), "{error:?}");
    assert_eq!(error.code(), codes::JOURNAL_DISK_FULL, "the journal's code was lost");
    let after = world.ledger.snapshot().await.unwrap();
    assert_eq!(
        after.state, snapshot.state,
        "the ledger changed before the intent's acknowledgement"
    );
    assert!(after.poisoned, "a write of unknown fate left the ledger live");
    assert_eq!((after.stats.withdrawn, after.stats.abandoned), (0, 1));
    assert_eq!(
        world.stop.reason(),
        Some(StopReason::LedgerFailed),
        "an abandoned write did not stop the kernel"
    );
    // Poisoned, it refuses all new work.
    world.fs.set_capacity(None);
    let poisoned = world
        .ledger
        .reserve(record(3), pool(1), rid(3), NanoUsd::new(1))
        .await
        .unwrap_err();
    assert_eq!(poisoned.code(), codes::JOURNAL_WRITE_FAILED);
    drop(held);
}

// The handle's side: a refusal that wrote nothing withdraws ────────────────────────────

#[tokio::test]
#[allow(
    clippy::disallowed_methods,
    reason = "joining the actor's thread blocks: the test waits for it off the runtime's threads"
)]
async fn a_refusal_that_wrote_nothing_leaves_the_ledger_live() {
    let mut world = World::start().await;
    let before = world.ledger.snapshot().await.unwrap();
    world.state.shutdown(ShutdownReason::new(by(), 0)).await.unwrap();
    // Once the actor's thread has ended, no command can be queued: nothing is written.
    let actor = world.actor.take().unwrap();
    tokio::task::spawn_blocking(move || actor.join().unwrap())
        .await
        .unwrap();
    let refused = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap_err();
    assert_eq!(refused, LedgerCallError::Unwritten(StateError::NotQueued));
    let moved = world
        .ledger
        .transfer(pool(1), pool(2), NanoUsd::new(5), movement("t"))
        .await
        .unwrap_err();
    assert_eq!(moved, LedgerCallError::Unwritten(StateError::NotQueued));
    let after = world.ledger.snapshot().await.unwrap();
    assert!(
        !after.poisoned,
        "a refusal that wrote nothing poisoned the task's ledger"
    );
    assert_eq!(after.state, before.state);
    assert_eq!(
        world.stop.reason(),
        None,
        "a refusal that wrote nothing stopped the kernel"
    );
}

// No double spend, every write ordered, no reservation apart from its intent ─

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writes_never_overspend_and_the_journal_is_the_ledger() {
    let world = World::start().await;
    let mut calls = Vec::new();
    for n in 0..40_u32 {
        let ledger = world.ledger.clone();
        let call = world.supervisor.spawn(async move {
            match n % 4 {
                0 => ledger
                    .transfer(pool(1), pool(2), NanoUsd::new(7), movement(&format!("t{n}")))
                    .await
                    .map(|()| None),
                1 => ledger
                    .allocate(pool(2), NanoUsd::new(3), movement(&format!("a{n}")))
                    .await
                    .map(|()| None),
                // The tokens are kept: a dropped one is released by the task.
                _ => ledger
                    .reserve(record(n), pool(1), rid(n), NanoUsd::new(90))
                    .await
                    .map(Some),
            }
        });
        calls.push(call.unwrap());
    }
    let mut capped = 0;
    let mut held = Vec::new();
    for call in calls {
        match call.await.unwrap() {
            Ok(token) => held.extend(token),
            Err(error) if error.code() == codes::BUDGET_HARD_STOP => capped += 1,
            Err(error) => panic!("an unexpected refusal: {error:?}"),
        }
    }
    let snapshot = world.ledger.snapshot().await.unwrap();
    let main = snapshot.state.pool(pool(1)).unwrap();
    assert!(capped > 0, "the cap was never reached; the test proves nothing");
    assert!(main.available.get() >= 0, "the pool was overspent: {main:?}");
    assert_eq!(snapshot.state.open_reservations(), 20 - capped);

    // Every reserve travels inside its Operation's intent, never apart from it.
    let records = world.records();
    let apart = records
        .iter()
        .filter(|r| r.envelope.event_type == types::BUDGET_ENTRY)
        .any(|r| {
            r.envelope
                .payload_inline
                .as_ref()
                .is_some_and(|p| p.as_value()["kind"] == serde_json::json!(BudgetTxKind::Reserve))
        });
    assert!(!apart, "a reservation was recorded apart from its intent");
    // The journal, read and replayed, is the task's ledger.
    let entries = entries_from_journal(&records).expect("the journal's order is not the ledger's");
    let replayed = Ledger::replay(&entries).expect("the journal's order is not the ledger's");
    assert_eq!(
        replayed.state(),
        &snapshot.state,
        "the journal's order is not the ledger's"
    );
    assert_eq!(held.len(), 20 - capped);
}

// ── Slice E4c: `execute` and the typed closes (4, 11, 12, 22) ─────────────────────────

fn report(end: RelayEnd, cost: Option<i64>, usage_final: bool, ceiling: i64) -> RelayReport {
    RelayReport {
        end,
        forwarded_bytes: 0,
        segments: 0,
        usage: Vec::new(),
        cost: cost.map(NanoUsd::new),
        usage_final,
        ceiling: NanoUsd::new(ceiling),
    }
}

/// An Operation's closing record: its type, payload and entries (kind, amount, estimated), and
/// its risk tier.
fn closing(
    world: &World,
    operation: OperationId,
) -> (EventType, serde_json::Value, Vec<(BudgetTxKind, i64, bool)>, RiskTier) {
    let record = closing_record(world, operation);
    let payload = record.envelope.payload_inline.as_ref().unwrap().as_value().clone();
    let delta: LedgerDelta = serde_json::from_value(payload["ledger"].clone()).unwrap();
    let entries = delta
        .entries
        .iter()
        .map(|e| (e.kind, e.amount.get(), e.estimated))
        .collect();
    (
        record.envelope.event_type.clone(),
        payload,
        entries,
        record.envelope.risk_tier,
    )
}

/// An Operation's closing record.
fn closing_record(world: &World, operation: OperationId) -> VerifiedRecord {
    world
        .records()
        .into_iter()
        .rev()
        .find(|r| {
            r.envelope.operation_id == Some(operation)
                && [types::OP_COMMITTED, types::OP_FAILED, types::OP_DENIED].contains(&r.envelope.event_type)
        })
        .expect("the Operation has no closing record")
}

/// No `budget.entry` carries a settlement's entry: every close is one record.
fn settlements_in_one_record(world: &World) -> bool {
    !world
        .records()
        .iter()
        .filter(|r| r.envelope.event_type == types::BUDGET_ENTRY)
        .any(|r| {
            let kind = &r.envelope.payload_inline.as_ref().unwrap().as_value()["kind"];
            [BudgetTxKind::Settle, BudgetTxKind::Release, BudgetTxKind::Adjust]
                .iter()
                .any(|k| *kind == serde_json::json!(k))
        })
}

#[tokio::test]
async fn execution_starts_only_after_its_record_and_settles_in_one_record() {
    let world = World::start().await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let intent = held.intent();
    let in_flight = world.ledger.execute(held).await.unwrap();
    let executing = world
        .records()
        .iter()
        .any(|r| r.envelope.event_type == types::OP_EXECUTING && r.envelope.parent_id == Some(intent));
    assert!(executing, "an InFlight token exists before its op.executing landed");
    let ended = report(RelayEnd::Completed, Some(60), true, 100);
    let (settlement, _) = world
        .ledger
        .settle(
            in_flight,
            Settled::RelayEnded {
                report: ended,
                upstream_status: 200,
            },
        )
        .await
        .unwrap();
    assert_eq!((settlement.spent.get(), settlement.released.get()), (60, 40));
    let (event_type, payload, entries, _) = closing(&world, op(1));
    assert_eq!(event_type, types::OP_COMMITTED);
    assert_eq!(payload["reason"], "completed");
    assert_eq!(
        entries,
        [(BudgetTxKind::Settle, 60, false), (BudgetTxKind::Release, 40, false)]
    );
    assert!(
        settlements_in_one_record(&world),
        "a settlement was split across records"
    );
    let snapshot = world.ledger.snapshot().await.unwrap();
    assert_eq!(snapshot.state.open_reservations(), 0);
    // What the task wrote, by record type (the world's two allocations included).
    let stats = snapshot.stats;
    assert_eq!(
        (
            stats.records["op.reserved_intent"],
            stats.records["op.executing"],
            stats.records["op.committed"],
            stats.records["budget.entry"]
        ),
        (1, 1, 1, 2),
        "the task miscounted what it wrote"
    );
    assert!(stats.prepare_to_apply_last_nanos.is_some());
    assert!(stats.prepare_to_apply_max_nanos >= stats.prepare_to_apply_last_nanos);
}

#[tokio::test]
async fn under_the_stop_execution_does_not_start() {
    let world = World::start().await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let _engaged = world.stop.engage(StopReason::Operator, by());
    let refused = world.ledger.execute(held).await.unwrap_err();
    assert_eq!(refused.code(), codes::RUNTIME_STOPPED);
    let (event_type, payload, entries, _) = closing(&world, op(1));
    assert_eq!(
        (event_type, payload["reason"].clone(), payload["sent"].clone()),
        (types::OP_FAILED, serde_json::json!("stopped"), serde_json::json!(false))
    );
    assert_eq!(entries, [(BudgetTxKind::Release, 100, false)]);
    assert!(
        !world
            .records()
            .iter()
            .any(|r| r.envelope.event_type == types::OP_EXECUTING)
    );
}

#[tokio::test]
async fn an_executing_record_of_unknown_fate_keeps_the_reservation_open() {
    let world = World::start().await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    world.fs.set_capacity(Some(0));
    let refused = world.ledger.execute(held).await.unwrap_err();
    assert!(matches!(refused, LedgerCallError::Abandoned(_)), "{refused:?}");
    let snapshot = world.ledger.snapshot().await.unwrap();
    assert_eq!(
        snapshot.state.open_reservations(),
        1,
        "an op.executing of unknown fate released its reservation"
    );
    assert!(snapshot.poisoned);
    assert_eq!(world.stop.reason(), Some(StopReason::LedgerFailed));
}

/// An `op.executing` refused unwritten returns the refusal and leaves the ledger live. With the
/// state actor ended its release cannot land either (`NotQueued`), so the reservation stays open
/// for the next boot to settle; nothing is poisoned and nothing stops.
#[tokio::test]
#[allow(
    clippy::disallowed_methods,
    reason = "joining the actor's thread blocks: the test waits for it off the runtime's threads"
)]
async fn a_refused_execute_returns_the_refusal_and_leaves_the_ledger_live() {
    let mut world = World::start().await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    world.state.shutdown(ShutdownReason::new(by(), 0)).await.unwrap();
    let actor = world.actor.take().unwrap();
    tokio::task::spawn_blocking(move || actor.join().unwrap())
        .await
        .unwrap();
    let refused = world.ledger.execute(held).await.unwrap_err();
    assert_eq!(refused, LedgerCallError::Unwritten(StateError::NotQueued));
    let snapshot = world.ledger.snapshot().await.unwrap();
    assert!(!snapshot.poisoned, "a refusal that wrote nothing poisoned the ledger");
    assert_eq!(
        world.stop.reason(),
        None,
        "a refusal that wrote nothing stopped the kernel"
    );
    assert_eq!(snapshot.state.open_reservations(), 1);
    // Withdrawn twice: the unwritten `op.executing`, then its release, refused too.
    assert_eq!((snapshot.stats.withdrawn, snapshot.stats.abandoned), (2, 0));
    assert!(
        !world
            .records()
            .iter()
            .any(|r| r.envelope.event_type == types::OP_EXECUTING)
    );
}

#[tokio::test]
async fn the_doors_verdict_decides_how_the_reservation_closes() {
    let world = World::start().await;
    // The contract's table: whether each failure may have sent, fixed here, not read from the door,
    // so a misclassified variant fails this test.
    let verdicts = [
        (EgressError::Blocked(Blocked::Loopback), false),
        (EgressError::Unreachable("x"), false),
        (EgressError::Timeout, false),
        (EgressError::Limits("x"), false),
        (
            EgressError::CircuitOpen {
                retry_after: Duration::from_secs(1),
            },
            false,
        ),
        (EgressError::Refused("x"), false),
        (EgressError::Upstream(UpstreamError::Port), false),
        (EgressError::Tls("x"), false),
        (EgressError::Interrupted("x"), true),
        (EgressError::Unusable("x"), true),
        (EgressError::AlreadySent, true),
    ];
    for (n, (error, may_have_sent)) in verdicts.into_iter().enumerate() {
        let n = u32::try_from(n).unwrap();
        let held = world
            .ledger
            .reserve(record(n), pool(1), rid(n), NanoUsd::new(100))
            .await
            .unwrap();
        let in_flight = world.ledger.execute(held).await.unwrap();
        let kind = error.kind();
        let already = error == EgressError::AlreadySent;
        world
            .ledger
            .settle(in_flight, Settled::DoorFailed(error))
            .await
            .unwrap();
        let (event_type, payload, entries, _) = closing(&world, op(n));
        assert_eq!(
            (event_type, payload["reason"].clone()),
            (types::OP_FAILED, serde_json::json!(kind))
        );
        if may_have_sent {
            assert_eq!(
                (entries.as_slice(), payload["may_have_taken_effect"].clone()),
                (&[(BudgetTxKind::Settle, 100, true)][..], serde_json::json!(true)),
                "{}",
                if already {
                    "an Operation that already sent was released"
                } else {
                    "a request that may have been sent was released"
                }
            );
        } else {
            assert_eq!(
                (entries.as_slice(), payload["sent"].clone()),
                (
                    &[(BudgetTxKind::Settle, 0, false), (BudgetTxKind::Release, 100, false)][..],
                    serde_json::json!(false)
                ),
                "an unsent request was settled in full"
            );
        }
    }
    // A zero reservation's unsent close is `[settle]`.
    let held = world
        .ledger
        .reserve(record(30), pool(1), rid(30), NanoUsd::ZERO)
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    world
        .ledger
        .settle(in_flight, Settled::DoorFailed(EgressError::Timeout))
        .await
        .unwrap();
    assert_eq!(closing(&world, op(30)).2, [(BudgetTxKind::Settle, 0, false)]);
    assert!(
        settlements_in_one_record(&world),
        "a settlement was split across records"
    );
}

#[tokio::test]
async fn each_typed_close_writes_its_own_record() {
    let world = World::start().await;
    let reason = |code: &str| ReasonCode::new(code).unwrap();
    // A relay completed at a cost of 0 is committed, with no `sent` field (E13).
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    let ended = report(RelayEnd::Completed, Some(0), true, 100);
    world
        .ledger
        .settle(
            in_flight,
            Settled::RelayEnded {
                report: ended,
                upstream_status: 200,
            },
        )
        .await
        .unwrap();
    let (event_type, payload, _, _) = closing(&world, op(1));
    assert_eq!(event_type, types::OP_COMMITTED);
    assert!(payload.get("sent").is_none(), "a completed relay was written as unsent");
    // An answer the relay refused: `op.failed`, with its reason, settled as unknown.
    let held = world
        .ledger
        .reserve(record(2), pool(1), rid(2), NanoUsd::new(100))
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    let answered = Settled::Answered {
        upstream_status: 200,
        reason: reason("compressed"),
    };
    world.ledger.settle(in_flight, answered).await.unwrap();
    let (event_type, payload, entries, _) = closing(&world, op(2));
    assert_eq!(
        (event_type, payload["reason"].clone()),
        (types::OP_FAILED, serde_json::json!("compressed")),
        "an answered Operation was closed as abandoned"
    );
    assert_eq!(entries, [(BudgetTxKind::Settle, 100, true)]);
    // Released before execution: `op.failed` or `op.denied`, `[release]`, never sent.
    for (n, released, expected) in [
        (
            3,
            Released::Failed {
                reason: reason("scan_deadline"),
            },
            (types::OP_FAILED, "scan_deadline"),
        ),
        (
            4,
            Released::Denied {
                reason: reason("final_scan"),
            },
            (types::OP_DENIED, "final_scan"),
        ),
    ] {
        let held = world
            .ledger
            .reserve(record(n), pool(1), rid(n), NanoUsd::new(100))
            .await
            .unwrap();
        world.ledger.release(held, released).await.unwrap();
        let (event_type, payload, entries, _) = closing(&world, op(n));
        assert_eq!(
            (event_type, payload["reason"].clone()),
            (expected.0, serde_json::json!(expected.1))
        );
        assert_eq!(
            (entries.as_slice(), payload["sent"].clone()),
            (&[(BudgetTxKind::Release, 100, false)][..], serde_json::json!(false))
        );
    }
    assert!(
        settlements_in_one_record(&world),
        "a settlement was split across records"
    );
}

/// An overrun charges its adjust in the same record, journaled at the highest tier.
#[tokio::test]
async fn an_overrun_is_charged_in_its_closing_record() {
    let world = World::start().await;
    let held = world
        .ledger
        .reserve(record(5), pool(1), rid(5), NanoUsd::new(100))
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    let cut = report(RelayEnd::Cut(CutReason::BudgetOverrun), Some(150), false, 100);
    world
        .ledger
        .settle(
            in_flight,
            Settled::RelayEnded {
                report: cut,
                upstream_status: 200,
            },
        )
        .await
        .unwrap();
    let (_, payload, entries, tier) = closing(&world, op(5));
    assert_eq!(payload["reason"], "budget_overrun");
    assert_eq!(
        entries,
        [(BudgetTxKind::Settle, 150, false), (BudgetTxKind::Adjust, -50, false)]
    );
    assert_eq!(tier, RiskTier::MAX, "an overrun was journaled as routine");
    assert!(
        settlements_in_one_record(&world),
        "a settlement was split across records"
    );
}

/// The closing records: the largest a settlement writes (an overrun at the 64-bit extremes, the
/// longest cut reason) is built and journaled.
#[tokio::test]
async fn the_largest_closing_record_fits() {
    let world = World::start().await;
    world
        .ledger
        .allocate(pool(3), NanoUsd::new(i64::MAX - 10), movement("fund3"))
        .await
        .unwrap();
    let held = world
        .ledger
        .reserve(record(1), pool(3), rid(1), NanoUsd::new(1))
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    let cut = report(RelayEnd::Cut(CutReason::CostOutOfRange), Some(i64::MAX), false, 1);
    world
        .ledger
        .settle(
            in_flight,
            Settled::RelayEnded {
                report: cut,
                upstream_status: 200,
            },
        )
        .await
        .expect("the largest closing record was not journaled");
    let (_, _, entries, _) = closing(&world, op(1));
    assert_eq!(
        entries,
        [
            (BudgetTxKind::Settle, i64::MAX, false),
            (BudgetTxKind::Adjust, 1 - i64::MAX, false)
        ]
    );
}

// No partial settlement, under a cut at every write ─────────────────────────────────

/// A disk that lets `budget` changes through, then refuses every change, as if the process had
/// died there. The append it dies in first writes `tear` quarters of its bytes: a torn record.
/// Reads still work: they are what the next process sees.
#[derive(Debug, Clone)]
struct Dying {
    inner: SimFs,
    budget: Arc<AtomicUsize>,
    tear: Arc<AtomicUsize>,
    gate: Arc<Mutex<Option<Gate>>>,
}

#[derive(Debug)]
struct DyingFile {
    inner: Box<dyn AppendFile>,
    budget: Arc<AtomicUsize>,
    tear: Arc<AtomicUsize>,
    gate: Arc<Mutex<Option<Gate>>>,
}

/// Holds the next file flush until the test lets it go: the state actor's thread waits inside
/// an append whose acknowledgement the ledger task awaits.
#[derive(Debug)]
struct Gate {
    entered: SyncSender<()>,
    release: Receiver<()>,
}

impl Dying {
    /// A disk that never dies until a test sets its budget.
    fn new(inner: SimFs) -> Self {
        Self {
            inner,
            budget: Arc::new(AtomicUsize::new(usize::MAX)),
            tear: Arc::new(AtomicUsize::new(0)),
            gate: Arc::default(),
        }
    }

    /// Arms the gate for the next flush: the first receiver says the flush has begun, the
    /// sender lets it finish.
    fn arm(&self) -> (Receiver<()>, SyncSender<()>) {
        let (entered, begun) = sync_channel(1);
        let (finish, release) = sync_channel(1);
        *self.gate.lock().unwrap() = Some(Gate { entered, release });
        (begun, finish)
    }
}

/// Spends one change from `budget`, or reports the process dead.
fn spend(budget: &AtomicUsize, op: &'static str) -> Result<(), FsError> {
    budget
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
        .map(|_| ())
        .map_err(|_| FsError::StaleHandle { op })
}

impl AppendFile for DyingFile {
    fn append(&mut self, bytes: &[u8]) -> Result<(), FsError> {
        if let Err(dead) = spend(&self.budget, "append") {
            let torn = bytes.len() * self.tear.swap(0, Ordering::SeqCst) / 4;
            if torn > 0 {
                self.inner.append(&bytes[..torn])?;
            }
            return Err(dead);
        }
        self.inner.append(bytes)
    }
    fn sync_data(&mut self) -> Result<(), FsError> {
        spend(&self.budget, "sync_data")?;
        let armed = self.gate.lock().unwrap().take();
        if let Some(gate) = armed {
            gate.entered.send(()).unwrap();
            gate.release.recv().unwrap();
        }
        self.inner.sync_data()
    }
    fn os_len(&self) -> Result<u64, FsError> {
        self.inner.os_len()
    }
}

impl Fs for Dying {
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        spend(&self.budget, "create_dir_all")?;
        self.inner.create_dir_all(path)
    }
    fn open_append(&self, path: &Path) -> Result<Box<dyn AppendFile>, FsError> {
        spend(&self.budget, "open_append")?;
        Ok(Box::new(DyingFile {
            inner: self.inner.open_append(path)?,
            budget: Arc::clone(&self.budget),
            tear: Arc::clone(&self.tear),
            gate: Arc::clone(&self.gate),
        }))
    }
    fn read(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        self.inner.read(path)
    }
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError> {
        self.inner.list_dir(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        spend(&self.budget, "rename")?;
        self.inner.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        spend(&self.budget, "remove_file")?;
        self.inner.remove_file(path)
    }
    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        spend(&self.budget, "sync_dir")?;
        self.inner.sync_dir(path)
    }
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        spend(&self.budget, "write_atomic")?;
        self.inner.write_atomic(path, bytes)
    }
    fn write_unsynced(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        spend(&self.budget, "write_unsynced")?;
        self.inner.write_unsynced(path, bytes)
    }
    fn sync_file(&self, path: &Path) -> Result<(), FsError> {
        spend(&self.budget, "sync_file")?;
        self.inner.sync_file(path)
    }
    fn try_lock_exclusive(&self, path: &Path) -> Result<Box<dyn LockGuard>, FsError> {
        self.inner.try_lock_exclusive(path)
    }
}

/// `settle` cut at every change it makes to the disk, its record torn at every quarter, then the
/// process dies or the power fails. With a remainder (`[settle, release]`) and with an overrun
/// (`[settle, adjust]`), the next open finds the reservation open, or closed with all its entries;
/// an acknowledged settlement is always closed.
#[tokio::test]
async fn a_settlement_cut_anywhere_is_whole_or_absent() {
    // How many cuts left the reservation open, and how many found it closed.
    let (mut open, mut closed) = (0, 0);
    for (cost, end, last) in [
        (60, RelayEnd::Completed, BudgetTxKind::Release),
        (150, RelayEnd::Cut(CutReason::BudgetOverrun), BudgetTxKind::Adjust),
    ] {
        for (power, tear) in [false, true].into_iter().flat_map(|p| (0..4).map(move |t| (p, t))) {
            for cut in 0_usize.. {
                let fs = SimFs::new();
                let disk = Dying::new(fs.clone());
                let budget = Arc::clone(&disk.budget);
                disk.tear.store(tear, Ordering::SeqCst);
                let world = World::start_on(fs, Arc::new(disk)).await;
                let held = world
                    .ledger
                    .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
                    .await
                    .unwrap();
                let in_flight = world.ledger.execute(held).await.unwrap();
                budget.store(cut, Ordering::SeqCst);
                let ended = Settled::RelayEnded {
                    report: report(end, Some(cost), true, 100),
                    upstream_status: 200,
                };
                let acknowledged = world.ledger.settle(in_flight, ended).await.is_ok();
                let finished = budget.load(Ordering::SeqCst) > 0;
                let fs = world.end().await;
                if power {
                    fs.power_loss();
                } else {
                    fs.crash();
                }
                // The next process opens the journal, cutting a torn tail, and reads its entries.
                drop(open_journal(Arc::new(fs.clone()), fresh_clock()));
                let records = read_verified(&fs, &Path::new(DATA).join(JOURNAL_DIR)).unwrap().0;
                // The reader refuses a settlement's entry outside its closing record.
                let entries = entries_from_journal(&records).unwrap_or_else(|error| {
                    panic!(
                        "the journal does not read after a cut through a settlement, as when a settlement \
                         was split across records: {error:?} (cut {cut}, tear {tear}, power {power})"
                    )
                });
                let kinds: Vec<_> = entries
                    .iter()
                    .filter(|tx| tx.reservation_id == Some(rid(1)))
                    .map(|tx| tx.kind)
                    .collect();
                let whole = kinds == [BudgetTxKind::Reserve, BudgetTxKind::Settle, last];
                assert!(
                    whole || kinds == [BudgetTxKind::Reserve],
                    "a settlement was split across records: {kinds:?} (cut {cut}, tear {tear}, power {power})"
                );
                assert!(
                    whole || !acknowledged,
                    "an acknowledged settlement was lost (cut {cut}, tear {tear}, power {power})"
                );
                if whole {
                    closed += 1;
                } else {
                    open += 1;
                }
                if finished {
                    break;
                }
            }
        }
    }
    assert!(
        open >= 16 && closed >= 16,
        "the cuts missed the settlement's writes: {open} open, {closed} closed"
    );
    eprintln!("row 2: {open} cuts left the reservation open, {closed} found it closed");
}

// ── Slice E4d: closes are the task's ─────────────────────────────────────────

/// A token dropped with no close offered is closed by the task, in one record with actor `system`
/// under the Operation's correlation. A `Held` token never reached the door, so it is released,
/// never sent; an `InFlight` token that reached its caller may have, so it is settled in full, as
/// estimated. A caller of `reserve` gone when the intent lands is a dropped `Held` token.
#[tokio::test]
async fn a_dropped_token_is_closed_by_the_task() {
    let world = World::start().await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    drop(held);
    let held = world
        .ledger
        .reserve(record(2), pool(1), rid(2), NanoUsd::new(100))
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    drop(in_flight);
    {
        let mut reserving = pin!(world.ledger.reserve(record(3), pool(1), rid(3), NanoUsd::new(100)));
        assert!(poll_once(reserving.as_mut()).is_pending());
    }
    let snapshot = world.ledger.snapshot().await.unwrap();
    assert_eq!(
        snapshot.state.open_reservations(),
        0,
        "a dropped token left its reservation open"
    );
    assert_eq!((snapshot.stats.owned_closes, snapshot.stats.offered_closes), (3, 0));
    for n in [1, 3] {
        let (event_type, payload, entries, _) = closing(&world, op(n));
        assert_eq!(
            (event_type, payload["reason"].clone(), payload["sent"].clone()),
            (
                types::OP_FAILED,
                serde_json::json!("abandoned"),
                serde_json::json!(false)
            )
        );
        assert_eq!(entries, [(BudgetTxKind::Release, 100, false)]);
    }
    let (event_type, payload, entries, _) = closing(&world, op(2));
    assert_eq!(
        (
            event_type,
            payload["reason"].clone(),
            payload["usage_final"].clone(),
            payload["may_have_taken_effect"].clone()
        ),
        (
            types::OP_FAILED,
            serde_json::json!("abandoned"),
            serde_json::json!(false),
            serde_json::json!(true)
        )
    );
    assert_eq!(
        entries,
        [(BudgetTxKind::Settle, 100, true)],
        "a dropped in-flight token was closed as never sent"
    );
    for n in [1, 2, 3] {
        let closed = closing_record(&world, op(n));
        assert_eq!(
            (closed.envelope.actor, closed.envelope.correlation_id),
            (Actor::System, record(n).correlation_id),
            "the task's own close is not the system's, under the Operation's correlation"
        );
    }
}

/// A caller of `execute` gone before its answer. The token never left the task, so it never reached
/// the door: it settles at 0, never sent.
#[tokio::test]
async fn an_in_flight_token_whose_caller_is_gone_settles_at_zero() {
    let world = World::start().await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    {
        let mut executing = pin!(world.ledger.execute(held));
        assert!(poll_once(executing.as_mut()).is_pending());
    }
    let snapshot = world.ledger.snapshot().await.unwrap();
    assert_eq!(snapshot.state.open_reservations(), 0);
    assert!(
        world
            .records()
            .iter()
            .any(|r| r.envelope.event_type == types::OP_EXECUTING)
    );
    let (event_type, payload, entries, _) = closing(&world, op(1));
    assert_eq!(
        entries,
        [(BudgetTxKind::Settle, 0, false), (BudgetTxKind::Release, 100, false)],
        "an InFlight token that never left the task was settled in full"
    );
    assert_eq!(
        (event_type, payload["reason"].clone(), payload["sent"].clone()),
        (
            types::OP_FAILED,
            serde_json::json!("abandoned"),
            serde_json::json!(false)
        )
    );
    assert_eq!(closing_record(&world, op(1)).envelope.actor, Actor::System);
    assert_eq!((snapshot.stats.owned_closes, snapshot.stats.offered_closes), (1, 0));
}

/// An overrun `settle` whose caller stops waiting while the task's queue is full still lands, as
/// `[settle, adjust]` at the cost the caller reported.
#[tokio::test]
async fn a_close_offered_by_a_caller_that_stops_waiting_still_lands() {
    let fs = SimFs::new();
    let setup = Setup {
        capacity: 1,
        shared_stop: false,
    };
    let world = World::build(fs.clone(), Arc::new(fs), setup).await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    // The queue holds one command: a snapshot not yet served fills it.
    let mut queued = pin!(world.ledger.snapshot());
    assert!(poll_once(queued.as_mut()).is_pending());
    {
        let cut = report(RelayEnd::Cut(CutReason::BudgetOverrun), Some(150), false, 100);
        let mut settling = pin!(world.ledger.settle(
            in_flight,
            Settled::RelayEnded {
                report: cut,
                upstream_status: 200,
            },
        ));
        assert!(poll_once(settling.as_mut()).is_pending(), "the queue had room");
    }
    queued.await.unwrap();
    let snapshot = world.ledger.snapshot().await.unwrap();
    assert_eq!(snapshot.state.open_reservations(), 0);
    let (_, payload, entries, tier) = closing(&world, op(1));
    assert_eq!(
        entries,
        [(BudgetTxKind::Settle, 150, false), (BudgetTxKind::Adjust, -50, false)],
        "a cancelled caller's close was lost"
    );
    assert_eq!((snapshot.stats.offered_closes, snapshot.stats.owned_closes), (1, 0));
    assert_eq!(
        (payload["reason"].clone(), tier),
        (serde_json::json!("budget_overrun"), RiskTier::MAX)
    );
}

/// A stop engaged while `op.executing` is being journaled. The second check sees it, so the token
/// never leaves the task: it settles at 0, `stopped`, never sent.
#[tokio::test]
async fn a_stop_engaged_while_executing_is_journaled_closes_at_zero() {
    let fs = SimFs::new();
    let disk = Dying::new(fs.clone());
    let gate = disk.clone();
    let world = World::start_on(fs, Arc::new(disk)).await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let (begun, finish) = gate.arm();
    let mut executing = pin!(world.ledger.execute(held));
    assert!(poll_once(executing.as_mut()).is_pending());
    // The task appends `op.executing`; the disk holds its flush.
    while begun.try_recv().is_err() {
        tokio::task::yield_now().await;
    }
    // While `op.executing` is held at its flush, no in-flight token exists.
    assert!(
        poll_once(executing.as_mut()).is_pending(),
        "an InFlight token was handed out before op.executing's acknowledgement"
    );
    let _engaged = world.stop.engage(StopReason::Operator, by());
    finish.send(()).unwrap();
    let Err(refused) = executing.await else {
        panic!("a stop engaged during op.executing's append let execution start");
    };
    assert_eq!(refused.code(), codes::RUNTIME_STOPPED);
    let (event_type, payload, entries, _) = closing(&world, op(1));
    assert_eq!(
        (event_type, payload["reason"].clone(), payload["sent"].clone()),
        (types::OP_FAILED, serde_json::json!("stopped"), serde_json::json!(false))
    );
    assert_eq!(
        entries,
        [(BudgetTxKind::Settle, 0, false), (BudgetTxKind::Release, 100, false)]
    );
}

/// A close refused inside the stop record's pause (`StopPending`) wrote nothing, so the task tries
/// it again after the pause, and the ledger stays live. The test's clock stands still, so the pause
/// lasts until the test moves it.
#[tokio::test]
async fn a_close_refused_inside_the_stop_records_pause_is_retried() {
    let fs = SimFs::new();
    let setup = Setup {
        capacity: DEFAULT_LEDGER_QUEUE,
        shared_stop: true,
    };
    let world = World::build(fs.clone(), Arc::new(fs), setup).await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    // The disk fills and the stop is engaged: the actor's own try of the stop record fails, and
    // its pause begins.
    world.fs.set_capacity(Some(0));
    let _engaged = world.stop.engage(StopReason::Operator, by());
    while world.state.stats().await.unwrap().stop_record_retries == 0 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let ledger = world.ledger.clone();
    let settling = world
        .supervisor
        .spawn(async move {
            ledger
                .settle(in_flight, Settled::DoorFailed(EgressError::Timeout))
                .await
        })
        .unwrap();
    // Refused inside the pause, tried again; then the disk frees and the pause ends.
    tokio::time::sleep(Duration::from_millis(200)).await;
    // While a close retries in the pause, the task serves nothing else. The stop is engaged
    // meanwhile, so no new spend waits on it; the shutdown's deadline bounds it.
    let ledger = world.ledger.clone();
    let looking = world.supervisor.spawn(async move { ledger.snapshot().await }).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !looking.is_finished(),
        "the task served another command while a close was retrying"
    );
    world.fs.set_capacity(None);
    world.clock.advance(10_000_000_000);
    let settled = settling.await.unwrap();
    assert!(
        settled.is_ok(),
        "a close refused inside the pause was not retried: {settled:?}"
    );
    assert!(
        looking.await.unwrap().is_ok(),
        "the waiting command was not served after the pause"
    );
    let snapshot = world.ledger.snapshot().await.unwrap();
    assert!(
        snapshot.stats.retried_closes > 0,
        "the close was never refused inside the pause"
    );
    assert!(!snapshot.poisoned, "a refusal that wrote nothing poisoned the ledger");
    let (_, payload, entries, _) = closing(&world, op(1));
    assert_eq!(
        (entries.as_slice(), payload["sent"].clone()),
        (
            &[(BudgetTxKind::Settle, 0, false), (BudgetTxKind::Release, 100, false)][..],
            serde_json::json!(false)
        )
    );
}

/// Once the state actor has ended (`NotQueued`) no retry can land, so the task does not retry: the
/// close is refused, and the reservation stays open for the next boot.
#[tokio::test]
#[allow(
    clippy::disallowed_methods,
    reason = "joining the actor's thread blocks: the test waits for it off the runtime's threads"
)]
async fn a_close_after_the_state_actor_ended_is_not_retried() {
    let mut world = World::start().await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    world.state.shutdown(ShutdownReason::new(by(), 0)).await.unwrap();
    let actor = world.actor.take().unwrap();
    tokio::task::spawn_blocking(move || actor.join().unwrap())
        .await
        .unwrap();
    let settling = world
        .ledger
        .settle(in_flight, Settled::DoorFailed(EgressError::Timeout));
    let Ok(settled) = tokio::time::timeout(Duration::from_secs(5), settling).await else {
        panic!("a close was retried after the state actor ended");
    };
    assert_eq!(settled.unwrap_err(), LedgerCallError::Unwritten(StateError::NotQueued));
    let snapshot = world.ledger.snapshot().await.unwrap();
    assert_eq!(snapshot.state.open_reservations(), 1);
    assert!(!snapshot.poisoned);
    assert_eq!(snapshot.stats.retried_closes, 0);
}

// ── Slice E4e: shutdown drains the ledger task ──────────────────────────────────────

/// The next process: opens the journal and boots it.
fn boot_again(fs: &SimFs) -> Booted {
    let clock: Arc<dyn Clock> = fresh_clock();
    let rng: Arc<dyn Rng> = Arc::new(SimRng::new(6));
    let opened =
        Journal::open_verified(Arc::new(fs.clone()), clock, rng, Path::new(DATA), FlushPolicy::Strict).unwrap();
    let mut journal = opened.journal;
    let config = ConfigSnapshot::new(ConfigVersion(1), LocaleTag::new("en").unwrap());
    boot(
        &mut journal,
        &opened.records,
        opened.evidence,
        &config,
        by().correlation_id,
    )
    .unwrap()
}

/// Starts `shut_down` with the ledger task, and waits until it has closed admission (and with
/// it, in the same step, the task's `reserve` and `execute`).
async fn start_shutdown(
    world: &World,
    admission: &Admission,
    deadline: Duration,
) -> tokio::task::JoinHandle<Result<uaos_runtime::ShutdownReport, StateError>> {
    let (admitting, state, ledger) = (admission.clone(), world.state.clone(), world.ledger.clone());
    let shutting = world
        .supervisor
        .spawn(async move { shut_down(&admitting, &state, Some(&ledger), by(), deadline).await })
        .unwrap();
    while admission.admit(0).is_ok() {
        tokio::task::yield_now().await;
    }
    shutting
}

/// `kernel.shutdown`'s sequence number and `open_operations`.
fn shutdown_record(world: &World) -> (u64, String) {
    let records = world.records();
    let record = records
        .iter()
        .find(|r| r.envelope.event_type == types::KERNEL_SHUTDOWN)
        .expect("no kernel.shutdown");
    let payload = record.envelope.payload_inline.as_ref().unwrap().as_value();
    (
        record.envelope.seq.0,
        payload["open_operations"].as_str().unwrap().to_owned(),
    )
}

/// Shutdown drains the ledger task before `kernel.shutdown`. While it drains, `reserve` and
/// `execute` are refused with `RUNTIME_DRAINING` and closes go on: an Operation settling and a
/// dropped token both close before the record, which counts nothing open, and the next boot reads a
/// clean end.
#[tokio::test]
#[allow(
    clippy::disallowed_methods,
    reason = "joining the actor's thread blocks: the test waits for it off the runtime's threads"
)]
async fn shutdown_drains_the_ledger_before_its_record() {
    let world = World::start().await;
    let admission = Admission::new(AdmissionLimits::default(), world.stop.clone());
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    let dropped = world
        .ledger
        .reserve(record(2), pool(1), rid(2), NanoUsd::new(100))
        .await
        .unwrap();
    let unstarted = world
        .ledger
        .reserve(record(3), pool(1), rid(3), NanoUsd::new(100))
        .await
        .unwrap();
    let begun = Instant::now();
    let shutting = start_shutdown(&world, &admission, Duration::from_secs(10)).await;

    let reserved = world
        .ledger
        .reserve(record(4), pool(1), rid(4), NanoUsd::new(100))
        .await;
    let executed = world.ledger.execute(unstarted).await;
    drop(dropped);
    let completed = report(RelayEnd::Completed, Some(60), true, 100);
    let settled = world
        .ledger
        .settle(
            in_flight,
            Settled::RelayEnded {
                report: completed,
                upstream_status: 200,
            },
        )
        .await;
    let report = shutting.await.unwrap().unwrap();

    assert_ne!(
        settled.as_ref().err().map(LedgerCallError::code),
        Some(codes::RUNTIME_DRAINING),
        "a close was refused while the ledger drained"
    );
    let (shutdown, open) = shutdown_record(&world);
    assert_eq!(shutdown, report.record.0);
    for n in [1, 2, 3] {
        let closed = world.records().into_iter().find(|r| {
            r.envelope.operation_id == Some(op(n))
                && [types::OP_COMMITTED, types::OP_FAILED].contains(&r.envelope.event_type)
        });
        assert!(
            closed.is_some_and(|r| r.envelope.seq.0 < shutdown),
            "kernel.shutdown was written before the ledger drained"
        );
    }
    // Whichever comes first, every token closed or the deadline.
    assert!(
        begun.elapsed() < Duration::from_secs(5),
        "the drain waited for its deadline though every token was closed"
    );
    assert!(settled.is_ok(), "{settled:?}");
    assert_eq!(
        reserved.err().map(|e| e.code()),
        Some(codes::RUNTIME_DRAINING),
        "a reserve was accepted while the ledger drained"
    );
    assert_eq!(
        executed.err().map(|e| e.code()),
        Some(codes::RUNTIME_DRAINING),
        "an execution started while the ledger drained"
    );
    assert_eq!(closing(&world, op(3)).1["reason"], "draining");
    assert_eq!(closing(&world, op(2)).1["reason"], "abandoned");
    assert_eq!(open, "0", "a drained shutdown counted work left open");

    let fs = world.end().await;
    let booted = boot_again(&fs);
    assert_eq!(booted.report.last_end, LastEnd::Clean);
    assert!(
        !booted.report.stop_may_be_lost,
        "a drained shutdown read as a lost stop"
    );
    assert_eq!(booted.ledger.state().open_reservations(), 0);
}

/// What the drain could not close is counted, from two reads in order. With the order fixed,
/// `open_operations` is exactly admission's count read before the task ends plus the reservations
/// open when it ends:
/// - A, a token alive at the deadline whose caller holds its permit: both reads (2);
/// - B, a cancelled caller's overrun close still queued at the deadline: the ledger's (1);
/// - C, a caller still waiting on its close's reply at the deadline (its flush held past it):
///   admission's (1); its close lands after the deadline, so it is not open at the end;
/// - D, a live token whose caller dropped its permit: the ledger's (1).
///
/// The next boot reads work left open and settles A, B and D as estimated.
#[tokio::test]
#[allow(
    clippy::disallowed_methods,
    reason = "joining the actor's thread blocks: the test waits for it off the runtime's threads"
)]
async fn shutdown_counts_what_the_drain_left_open() {
    let fs = SimFs::new();
    let disk = Dying::new(fs.clone());
    let gate = disk.clone();
    let world = World::start_on(fs, Arc::new(disk)).await;
    let admission = Admission::new(AdmissionLimits::default(), world.stop.clone());
    let mut tokens = Vec::new();
    let mut permits = Vec::new();
    for n in 1..=4 {
        permits.push(admission.admit(0).unwrap());
        let held = world
            .ledger
            .reserve(record(n), pool(1), rid(n), NanoUsd::new(100))
            .await
            .unwrap();
        tokens.push(world.ledger.execute(held).await.unwrap());
    }
    let (live_d, waiting_c, cancelled_b, live_a) = (
        tokens.pop().unwrap(),
        tokens.pop().unwrap(),
        tokens.pop().unwrap(),
        tokens.pop().unwrap(),
    );
    let (permit_d, permit_c, permit_b, permit_a) = (
        permits.pop().unwrap(),
        permits.pop().unwrap(),
        permits.pop().unwrap(),
        permits.pop().unwrap(),
    );
    drop((permit_b, permit_d));
    // C's close: its caller waits for the reply, permit in hand; the disk holds its flush.
    let (begun, finish) = gate.arm();
    let ledger = world.ledger.clone();
    let completed = report(RelayEnd::Completed, Some(60), true, 100);
    let waiting = world
        .supervisor
        .spawn(async move {
            let settled = ledger
                .settle(
                    waiting_c,
                    Settled::RelayEnded {
                        report: completed,
                        upstream_status: 200,
                    },
                )
                .await;
            drop(permit_c);
            settled
        })
        .unwrap();
    while begun.try_recv().is_err() {
        tokio::task::yield_now().await;
    }
    // B's caller offers an overrun close and gives up: the close is queued behind C's.
    let overrun = report(RelayEnd::Cut(CutReason::BudgetOverrun), Some(150), false, 100);
    drop(world.ledger.settle(
        cancelled_b,
        Settled::RelayEnded {
            report: overrun,
            upstream_status: 200,
        },
    ));
    let shutting = start_shutdown(&world, &admission, Duration::from_millis(100)).await;
    // Past the deadline, and past admission's read, the disk lets C's flush finish.
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    finish.send(()).unwrap();
    shutting.await.unwrap().unwrap();
    assert!(waiting.await.unwrap().is_ok());

    let (_, open) = shutdown_record(&world);
    assert_eq!(
        open, "5",
        "kernel.shutdown miscounted the work left open (admission's 2, plus 3 open)"
    );
    drop((live_a, live_d, permit_a));
    let fs = world.end().await;
    let booted = boot_again(&fs);
    assert_eq!(booted.report.last_end, LastEnd::Clean);
    assert!(
        booted.report.stop_may_be_lost,
        "the next boot did not read the work left open"
    );
    assert_eq!(booted.report.indeterminate_settled, 3);
    assert_eq!(booted.ledger.state().open_reservations(), 0);
}

// The reader's side: a repair resolves a stuck item ───────────────────────────────

/// The record pass reads a one-record repair only after the entry-less `op.indeterminate` that left
/// its item stuck. A resolution with `stuck_repair` entries for an Operation that was never stuck
/// is refused, so the journal never reads as repaired what was not stuck (the task itself never
/// writes one: the ledger names the Operation).
#[tokio::test]
async fn a_repair_without_its_stuck_item_is_refused_by_the_reader() {
    let world = World::start().await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let intent = held.intent();
    let _in_flight = world.ledger.execute(held).await.unwrap();
    let delta = LedgerDelta {
        v: 1,
        pool: pool(1),
        reservation: rid(1),
        entries: vec![DeltaEntry {
            kind: BudgetTxKind::Settle,
            amount: NanoUsd::new(100),
            before: NanoUsd::new(FUNDS - 100),
            after: NanoUsd::new(FUNDS - 100),
            reason: ReasonCode::new("stuck_repair").unwrap(),
            settled: true,
            estimated: false,
        }],
    };
    let operation = record(1);
    let payload = serde_json::json!({"reason": "stuck_repair", "resolution": "settled", "ledger": delta});
    world
        .state
        .append(EventDraft {
            session_id: operation.session_id,
            pocket_id: operation.pocket_id,
            operation_id: Some(operation.operation_id),
            request_id: operation.request_id,
            agent_id: operation.agent_id,
            correlation_id: operation.correlation_id,
            parent_id: Some(intent),
            actor: Actor::Human,
            event_type: types::OP_COMMITTED,
            payload_ref: None,
            payload_inline: Some(InlinePayload::new(payload).unwrap()),
            cost_estimate: None,
            compensable: operation.compensable,
            side_effect_class: operation.side_effect_class,
            risk_tier: operation.risk_tier,
            durability: Durability::Critical,
            config_version: operation.config_version,
            metadata: Metadata::default(),
        })
        .await
        .unwrap();
    let Err(refused) = entries_from_journal(&world.records()) else {
        panic!("a repair was read without the stuck item it resolves");
    };
    assert!(
        format!("{refused:?}").contains("a repair without the entry-less op.indeterminate"),
        "{refused:?}"
    );
}

// Fixes and the proofs the review found missing ────────────────────

/// A close already retrying in the stop record's pause when the shutdown begins sees the deadline
/// at once. It is not performed, the drain ends at the deadline, and its reservation is counted.
/// The test's clock stands still, so the pause lasts.
#[tokio::test]
async fn a_close_retrying_when_shutdown_begins_ends_at_the_deadline() {
    let fs = SimFs::new();
    let setup = Setup {
        capacity: DEFAULT_LEDGER_QUEUE,
        shared_stop: true,
    };
    let world = World::build(fs.clone(), Arc::new(fs), setup).await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    world.fs.set_capacity(Some(0));
    let _engaged = world.stop.engage(StopReason::Operator, by());
    while world.state.stats().await.unwrap().stop_record_retries == 0 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let ledger = world.ledger.clone();
    let settling = world
        .supervisor
        .spawn(async move {
            ledger
                .settle(in_flight, Settled::DoorFailed(EgressError::Timeout))
                .await
        })
        .unwrap();
    // The close is retrying inside the pause now: after 1.3 s it is inside a wait of a second
    // (its waits double from 10 ms), which the drain's deadline must cut short.
    tokio::time::sleep(Duration::from_millis(1_300)).await;
    let begun = Instant::now();
    let drained = tokio::time::timeout(
        Duration::from_secs(10),
        world.ledger.shutdown(begun + Duration::from_millis(200)),
    )
    .await;
    let Ok(drained) = drained else {
        panic!("a close retrying in the stop record's pause held the drain past its deadline");
    };
    assert_eq!(drained.unwrap(), OpenReservations(1));
    // The drain answers at its deadline (200 ms), not after the retry's wait of up to a second.
    assert!(
        begun.elapsed() < Duration::from_millis(700),
        "a retry's wait ran past the drain's deadline: {:?}",
        begun.elapsed()
    );
    let settled = settling.await.unwrap();
    assert!(
        matches!(settled, Err(LedgerCallError::Unwritten(StateError::StopPending(_)))),
        "{settled:?}"
    );
}

/// `release` and `settle` offer their close before they return the future, so a close whose future
/// is never polled still lands with the caller's usage. A close whose caller leaves after it was
/// queued lands too. Both count as taken on.
#[tokio::test]
async fn a_close_offered_by_a_future_never_polled_still_lands() {
    let world = World::start().await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    let cut = report(RelayEnd::Cut(CutReason::BudgetOverrun), Some(150), false, 100);
    drop(world.ledger.settle(
        in_flight,
        Settled::RelayEnded {
            report: cut,
            upstream_status: 200,
        },
    ));
    let held = world
        .ledger
        .reserve(record(2), pool(1), rid(2), NanoUsd::new(100))
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    {
        let completed = report(RelayEnd::Completed, Some(60), true, 100);
        let mut settling = pin!(world.ledger.settle(
            in_flight,
            Settled::RelayEnded {
                report: completed,
                upstream_status: 200,
            },
        ));
        assert!(poll_once(settling.as_mut()).is_pending());
    }
    // `release` too: a denial offered on a future never polled lands as `op.denied`.
    let held = world
        .ledger
        .reserve(record(3), pool(1), rid(3), NanoUsd::new(100))
        .await
        .unwrap();
    let denied = Released::Denied {
        reason: ReasonCode::new("final_scan").unwrap(),
    };
    drop(world.ledger.release(held, denied));
    let snapshot = world.ledger.snapshot().await.unwrap();
    assert_eq!(
        closing(&world, op(1)).2,
        [(BudgetTxKind::Settle, 150, false), (BudgetTxKind::Adjust, -50, false)],
        "an offered close was lost because its future was never polled"
    );
    let (event_type, payload, _, _) = closing(&world, op(3));
    assert_eq!(
        (event_type, payload["reason"].clone()),
        (types::OP_DENIED, serde_json::json!("final_scan")),
        "a release offered on a future never polled lost its close"
    );
    assert_eq!(
        closing(&world, op(2)).2,
        [(BudgetTxKind::Settle, 60, false), (BudgetTxKind::Release, 40, false)]
    );
    assert_eq!((snapshot.stats.offered_closes, snapshot.stats.owned_closes), (3, 0));
}

/// A ledger task that cannot answer the shutdown, here because it has already ended, is counted as
/// one open Operation in `kernel.shutdown`, so a boot after it would read work left open.
#[tokio::test]
async fn a_ledger_task_that_cannot_answer_is_counted_as_one() {
    let world = World::start().await;
    let admission = Admission::new(AdmissionLimits::default(), world.stop.clone());
    let ended = world.ledger.shutdown(Instant::now()).await.unwrap();
    assert_eq!(ended, OpenReservations(0));
    shut_down(
        &admission,
        &world.state,
        Some(&world.ledger),
        by(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let (_, open) = shutdown_record(&world);
    assert_eq!(open, "1", "a ledger task that could not answer was counted as nothing");
}

/// A deadline too far to represent waits as long as it can; it never panics.
#[tokio::test]
async fn a_shutdown_with_the_longest_deadline_does_not_panic() {
    let world = World::start().await;
    let admission = Admission::new(AdmissionLimits::default(), world.stop.clone());
    shut_down(&admission, &world.state, Some(&world.ledger), by(), Duration::MAX)
        .await
        .unwrap();
    assert_eq!(shutdown_record(&world).1, "0");
}

/// With every token slot taken, `reserve` is refused as `RUNTIME_OVERLOAD` before anything is
/// written; `queued()` reads the task's queue.
#[tokio::test]
async fn a_reserve_without_a_free_slot_is_refused_unwritten() {
    let fs = SimFs::new();
    let setup = Setup {
        capacity: 1,
        shared_stop: false,
    };
    let world = World::build(fs.clone(), Arc::new(fs), setup).await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let written = world.records().len();
    let refused = world
        .ledger
        .reserve(record(2), pool(1), rid(2), NanoUsd::new(100))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), codes::RUNTIME_OVERLOAD);
    assert_eq!(world.records().len(), written, "a refused reserve wrote its intent");
    assert_eq!(world.ledger.queued(), 0);
    drop(held);
}

/// A refusal's wire error names the Operation and its reservation in the agent message, and carries
/// no amount.
#[tokio::test]
async fn a_refusal_names_its_operation_and_reservation_not_its_amount() {
    let world = World::start().await;
    let refused = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(987_654))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), codes::BUDGET_HARD_STOP);
    let error = refused.to_error(op(1), Some(rid(1)), by().correlation_id).unwrap();
    assert_eq!(error.code, codes::BUDGET_HARD_STOP.to_string());
    assert!(
        error.agent_message.contains(&op(1).to_string()) && error.agent_message.contains(&rid(1).to_string()),
        "{}",
        error.agent_message
    );
    assert!(
        !error.agent_message.contains("987654") && !error.message_key.contains("987654"),
        "an amount reached the wire error: {error:?}"
    );
}

// ── The drain's grace, offered releases and refusals under the stop (E4) ────────────

/// A ledger task that does not answer within the grace past the deadline, here because the state
/// actor holds its write, is counted as one, and the shutdown goes on without it.
#[tokio::test]
async fn a_ledger_task_that_does_not_answer_within_the_grace_is_counted_as_one() {
    let fs = SimFs::new();
    let disk = Dying::new(fs.clone());
    let gate = disk.clone();
    let world = World::start_on(fs, Arc::new(disk)).await;
    let admission = Admission::new(AdmissionLimits::default(), world.stop.clone());
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    // The task's close is held at its flush past the deadline and the grace.
    let (begun, finish) = gate.arm();
    let ledger = world.ledger.clone();
    let settling = world
        .supervisor
        .spawn(async move {
            ledger
                .settle(in_flight, Settled::DoorFailed(EgressError::Timeout))
                .await
        })
        .unwrap();
    while begun.try_recv().is_err() {
        tokio::task::yield_now().await;
    }
    let (admitting, state, ledger) = (admission.clone(), world.state.clone(), world.ledger.clone());
    let shutting = world
        .supervisor
        .spawn(async move { shut_down(&admitting, &state, Some(&ledger), by(), Duration::from_millis(100)).await })
        .unwrap();
    // The grace ends 2.1 s after the shutdown began; the flush is let go after it.
    tokio::time::sleep(uaos_runtime::LEDGER_DRAIN_GRACE + Duration::from_millis(600)).await;
    finish.send(()).unwrap();
    shutting.await.unwrap().unwrap();
    assert!(settling.await.unwrap().is_ok());
    let (_, open) = shutdown_record(&world);
    assert_eq!(
        open, "1",
        "a ledger task that did not answer within the grace was not counted"
    );
}

/// Under the stop, `execute` is refused with `RUNTIME_STOPPED` even when the release that follows
/// cannot land, here because the ledger is poisoned.
#[tokio::test]
async fn under_the_stop_the_refusal_is_the_stops_whatever_the_release_meets() {
    let world = World::start().await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    // A full disk: the next intent's fate is unknown, so the ledger is poisoned and stops.
    world.fs.set_capacity(Some(0));
    let abandoned = world
        .ledger
        .reserve(record(2), pool(1), rid(2), NanoUsd::new(100))
        .await
        .unwrap_err();
    assert!(matches!(abandoned, LedgerCallError::Abandoned(_)), "{abandoned:?}");
    let refused = world.ledger.execute(held).await.unwrap_err();
    assert_eq!(
        refused.code(),
        codes::RUNTIME_STOPPED,
        "an execution under the stop was refused with another code: {refused:?}"
    );
}

// ── Refusal messages, retries, relay ends and upstream names (E4) ──────────────────

/// A close the ledger refuses because an earlier write poisoned it never reads as "the operation
/// was not started": `op.executing` is in the journal, and the request may have reached the
/// upstream (red line 3; of E4).
#[tokio::test]
async fn a_close_refused_by_a_poisoned_ledger_never_reads_as_not_started() {
    let world = World::start().await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    let in_flight = world.ledger.execute(held).await.unwrap();
    // Another write's fate is unknown: the ledger is poisoned.
    world.fs.set_capacity(Some(0));
    let abandoned = world
        .ledger
        .reserve(record(2), pool(1), rid(2), NanoUsd::new(100))
        .await
        .unwrap_err();
    assert!(matches!(abandoned, LedgerCallError::Abandoned(_)), "{abandoned:?}");
    world.fs.set_capacity(None);
    let refused = world
        .ledger
        .settle(in_flight, Settled::DoorFailed(EgressError::Timeout))
        .await
        .unwrap_err();
    assert!(
        matches!(refused, LedgerCallError::Ledger(LedgerError::Poisoned)),
        "{refused:?}"
    );
    let error = refused.to_error(op(1), Some(rid(1)), by().correlation_id).unwrap();
    assert_eq!(error.code, codes::JOURNAL_WRITE_FAILED.to_string());
    assert!(
        !error.agent_message.contains("not started") && error.agent_message.contains("nothing was recorded"),
        "a close refused after the execution read as not started: {}",
        error.agent_message
    );
    assert!(
        error.agent_message.contains(&op(1).to_string()) && error.agent_message.contains(&rid(1).to_string()),
        "{}",
        error.agent_message
    );
}

/// A release refused inside the stop record's pause wrote nothing, so the task tries it again, as
/// it does a settlement, and it lands.
#[tokio::test]
async fn a_release_refused_inside_the_stop_records_pause_is_retried() {
    let fs = SimFs::new();
    let setup = Setup {
        capacity: DEFAULT_LEDGER_QUEUE,
        shared_stop: true,
    };
    let world = World::build(fs.clone(), Arc::new(fs), setup).await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    world.fs.set_capacity(Some(0));
    let _engaged = world.stop.engage(StopReason::Operator, by());
    while world.state.stats().await.unwrap().stop_record_retries == 0 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let denied = Released::Denied {
        reason: ReasonCode::new("final_scan").unwrap(),
    };
    let releasing = world.supervisor.spawn(world.ledger.release(held, denied)).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    world.fs.set_capacity(None);
    world.clock.advance(10_000_000_000);
    let released = releasing.await.unwrap();
    assert!(
        released.is_ok(),
        "a release refused inside the pause was not retried: {released:?}"
    );
    let snapshot = world.ledger.snapshot().await.unwrap();
    assert!(
        snapshot.stats.retried_closes > 0,
        "the release was never refused inside the pause"
    );
    assert!(!snapshot.poisoned, "a refusal that wrote nothing poisoned the ledger");
    let (event_type, payload, entries, _) = closing(&world, op(1));
    assert_eq!(
        (event_type, payload["reason"].clone(), entries.as_slice()),
        (
            types::OP_DENIED,
            serde_json::json!("final_scan"),
            &[(BudgetTxKind::Release, 100, false)][..]
        )
    );
}

/// A critical record of another Operation, appended by the test itself.
fn standalone_draft() -> EventDraft {
    EventDraft {
        session_id: None,
        pocket_id: None,
        operation_id: Some(op(9)),
        request_id: None,
        agent_id: None,
        correlation_id: correlation(),
        parent_id: None,
        actor: Actor::System,
        event_type: types::OP_APPROVAL_REQUIRED,
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

/// A stop engaged after `execute` checked it, while `op.executing` waits in the state actor's
/// queue, makes the actor refuse that record unwritten (`StopPending`). The refusal is the stop's,
/// and the release is `stopped`.
#[tokio::test]
async fn a_stop_engaged_while_op_executing_waits_is_the_refusal() {
    let fs = SimFs::new();
    let disk = Dying::new(fs.clone());
    let gate = disk.clone();
    let setup = Setup {
        capacity: DEFAULT_LEDGER_QUEUE,
        shared_stop: true,
    };
    let world = World::build(fs, Arc::new(disk), setup).await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    // The state actor is held inside another record's flush...
    let (begun, finish) = gate.arm();
    let state = world.state.clone();
    let holding = world
        .supervisor
        .spawn(async move { state.append(standalone_draft()).await })
        .unwrap();
    while begun.try_recv().is_err() {
        assert!(!holding.is_finished(), "the held append ended before its flush began");
        tokio::task::yield_now().await;
    }
    // ...so `op.executing` waits in its queue, after `execute` found the stop not engaged.
    let ledger = world.ledger.clone();
    let executing = world
        .supervisor
        .spawn(async move { ledger.execute(held).await })
        .unwrap();
    while world.state.queued() == 0 {
        tokio::task::yield_now().await;
    }
    // Now the stop is engaged and its record cannot land.
    world.fs.set_capacity(Some(0));
    let _engaged = world.stop.engage(StopReason::Operator, by());
    finish.send(()).unwrap();
    assert!(holding.await.unwrap().is_ok());
    tokio::time::sleep(Duration::from_millis(200)).await;
    world.fs.set_capacity(None);
    world.clock.advance(10_000_000_000);
    let refused = executing.await.unwrap().unwrap_err();
    assert_eq!(
        refused.code(),
        codes::RUNTIME_STOPPED,
        "a refusal caused by the stop was not the stop's: {refused:?}"
    );
    let (event_type, payload, entries, _) = closing(&world, op(1));
    assert_eq!(
        (event_type, payload["reason"].clone(), entries.as_slice()),
        (
            types::OP_FAILED,
            serde_json::json!("stopped"),
            &[(BudgetTxKind::Release, 100, false)][..]
        ),
        "a release caused by the stop was not journaled as stopped"
    );
}

/// During the drain, `execute` is refused with `RUNTIME_DRAINING` even when the release that
/// follows cannot land, here because the ledger is poisoned.
#[tokio::test]
async fn while_draining_the_refusal_is_the_drains_whatever_the_release_meets() {
    let world = World::start().await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    world.fs.set_capacity(Some(0));
    let abandoned = world
        .ledger
        .reserve(record(2), pool(1), rid(2), NanoUsd::new(100))
        .await
        .unwrap_err();
    assert!(matches!(abandoned, LedgerCallError::Abandoned(_)), "{abandoned:?}");
    world.fs.set_capacity(None);
    world.ledger.drain();
    let refused = world.ledger.execute(held).await.unwrap_err();
    assert_eq!(
        refused.code(),
        codes::RUNTIME_DRAINING,
        "an execution refused by the drain was refused with another code: {refused:?}"
    );
}

/// Through the task, a relay that completed with an error status is closed as `op.failed` with
/// `upstream_status`, and one whose client went away with `client_gone`; each charges its reported
/// cost in its one record.
#[tokio::test]
async fn a_relays_end_is_journaled_as_its_closing_record() {
    let world = World::start().await;
    for (n, end, status) in [(1, RelayEnd::Completed, 500), (2, RelayEnd::ClientGone, 200)] {
        let held = world
            .ledger
            .reserve(record(n), pool(1), rid(n), NanoUsd::new(100))
            .await
            .unwrap();
        let in_flight = world.ledger.execute(held).await.unwrap();
        world
            .ledger
            .settle(
                in_flight,
                Settled::RelayEnded {
                    report: report(end, Some(60), true, 100),
                    upstream_status: status,
                },
            )
            .await
            .unwrap();
    }
    for (n, reason) in [(1, "upstream_status"), (2, "client_gone")] {
        let (event_type, payload, entries, _) = closing(&world, op(n));
        assert_eq!(
            (event_type, payload["reason"].clone(), entries.as_slice()),
            (
                types::OP_FAILED,
                serde_json::json!(reason),
                &[(BudgetTxKind::Settle, 60, false), (BudgetTxKind::Release, 40, false)][..]
            ),
            "Operation {n}'s relay end was journaled wrongly"
        );
    }
}

/// An upstream name that is not a token, such as a URL with credentials in it, or one longer than
/// 64 bytes, is refused before anything is written (red line 2; of E4).
#[tokio::test]
async fn an_upstream_name_that_is_not_a_token_is_refused_unwritten() {
    let world = World::start().await;
    let written = world.records().len();
    let too_long = "a".repeat(uaos_runtime::MAX_UPSTREAM_NAME + 1);
    for upstream in [
        "https://user:pw@example.com",
        "",
        "a b",
        "primary/v1",
        too_long.as_str(),
    ] {
        let mut named = record(1);
        named.upstream = upstream.to_owned();
        let refused = world
            .ledger
            .reserve(named, pool(1), rid(1), NanoUsd::new(100))
            .await
            .unwrap_err();
        assert!(
            matches!(refused, LedgerCallError::Record(_)),
            "{upstream:?}: {refused:?}"
        );
    }
    assert_eq!(world.records().len(), written, "a refused upstream name was journaled");
    assert!(uaos_runtime::is_upstream_name("openai-eu.2"));
    assert!(uaos_runtime::is_upstream_name(
        &"a".repeat(uaos_runtime::MAX_UPSTREAM_NAME)
    ));
    assert!(!uaos_runtime::is_upstream_name(&too_long));
}

/// A queue capacity past what a bounded channel holds is clamped, never a panic.
#[tokio::test]
async fn a_queue_capacity_past_a_channels_bound_is_clamped() {
    let fs = SimFs::new();
    let setup = Setup {
        capacity: usize::MAX,
        shared_stop: false,
    };
    let world = World::build(fs.clone(), Arc::new(fs), setup).await;
    let held = world
        .ledger
        .reserve(record(1), pool(1), rid(1), NanoUsd::new(100))
        .await
        .unwrap();
    drop(held);
    let (state, _queue) = state_queue(usize::MAX);
    assert_eq!(state.queued(), 0);
}
