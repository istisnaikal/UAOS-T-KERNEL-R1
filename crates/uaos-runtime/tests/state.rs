// SPDX-License-Identifier: Apache-2.0

//! The state actor and its flush schedule (P1, P2 and P10), and the fixes of the slice-1 review.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "the harness spawns concurrent callers and joins the actor's thread outside the supervisor"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use uaos_contracts::event::{Actor, EventEnvelope, types};
use uaos_contracts::id::{CorrelationId, EventId, TypedId};
use uaos_contracts::limits::Millis;
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::{ConfigVersion, MonoNanos};
use uaos_platform::fs::Fs;
use uaos_platform::real::SystemClock;
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, PlatformError, Rng};
use uaos_runtime::{
    DEFAULT_QUEUE_CAPACITY, EngagedBy, SpawnError, StartRefused, StateCore, StateError, Stop, StopReason, Supervisor,
    SupervisorLimits, start_state_actor, state_queue, stop_reason_for,
};
use uaos_state::journal::{EventDraft, FlushPolicy, JOURNAL_DIR, Journal, JournalHealth, read_verified};

const DATA: &str = "/data";
/// The flush window under test: the default.
const W: Millis = Millis(50);

/// A journal on a simulated disk and clock.
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
            rng: Arc::new(SimRng::new(7)),
            data: PathBuf::from(DATA),
        }
    }

    /// A core on the simulated clock.
    fn core(&self) -> StateCore {
        self.core_on(self.clock.clone(), W)
    }

    /// A core on `clock`, with the flush window `window`.
    fn core_on(&self, clock: Arc<dyn Clock>, window: Millis) -> StateCore {
        let rng: Arc<dyn Rng> = self.rng.clone();
        let journal = Journal::open(
            Arc::new(self.fs.clone()),
            clock,
            rng,
            &self.data,
            FlushPolicy::Balanced { window },
        )
        .unwrap();
        StateCore::new(journal)
    }

    /// The identifiers of the records the next start reads.
    fn durable_ids(&self) -> Vec<EventId> {
        read_verified(&self.fs, &self.data.join(JOURNAL_DIR))
            .unwrap()
            .0
            .into_iter()
            .map(|r| r.envelope.id)
            .collect()
    }
}

/// A critical record: an operator's stop is the simplest draft at hand.
fn record(n: u8) -> EventDraft {
    let stop = Stop::running();
    let by = EngagedBy {
        actor: Actor::System,
        correlation_id: CorrelationId::from_parts(u64::from(n) + 1, [n; 10]),
        config_version: ConfigVersion(1),
    };
    let _engaged = stop.engage(StopReason::Operator, by);
    stop.unrecorded().unwrap().draft().unwrap()
}

/// The gap the schedule closes: the journal alone leaves a quiet journal's last record
/// unflushed past W, so a power loss takes it.
#[test]
fn without_the_schedule_a_quiet_journal_loses_its_last_record() {
    let world = World::new();
    let mut core = world.core();
    let appended = core.append(record(1)).unwrap();
    world.clock.advance(W.as_nanos() * 10);
    world.fs.power_loss();
    assert!(
        !world.durable_ids().contains(&appended.id),
        "the journal flushed a quiet record on its own; the gap this contract closes is gone, \
         so update this test"
    );
}

/// P1: an acknowledged record is flushed within W although no other record follows.
#[test]
fn a_quiet_journal_flushes_within_the_window() {
    let world = World::new();
    let mut core = world.core();
    let appended = core.append(record(1)).unwrap();
    let deadline = core.tick().unwrap();
    assert_eq!(
        deadline,
        world.clock.mono().0 + W.as_nanos(),
        "the deadline is not the acknowledgement plus W"
    );
    world.clock.advance(W.as_nanos());
    assert_eq!(core.tick(), None, "a deadline is still pending after the flush");
    assert_eq!(core.stats().deadline_flushes, 1);
    world.fs.power_loss();
    assert!(
        world.durable_ids().contains(&appended.id),
        "an acknowledged record was lost to a power loss W after its acknowledgement"
    );
}

/// The coordinator's delay is measured from the time a flush was due to the time it started, and
/// the stats carry the journal's health.
#[test]
fn stats_measure_the_flush_delay_and_carry_the_health() {
    let world = World::new();
    let mut core = world.core();
    assert_eq!(core.stats().flush_delay_last_nanos, None);
    core.append(record(1)).unwrap();
    world.clock.advance(W.as_nanos() + 3_000_000);
    assert_eq!(core.tick(), None);
    let stats = core.stats();
    assert_eq!(
        stats.flush_delay_last_nanos,
        Some(3_000_000),
        "the delay is not deadline to flush"
    );
    assert_eq!(stats.flush_delay_max_nanos, Some(3_000_000));
    assert_eq!(stats.health, JournalHealth::Healthy);
    // On time: the last delay is zero and the longest stays.
    core.append(record(2)).unwrap();
    world.clock.advance(W.as_nanos());
    assert_eq!(core.tick(), None);
    let stats = core.stats();
    assert_eq!(stats.flush_delay_last_nanos, Some(0));
    assert_eq!(stats.flush_delay_max_nanos, Some(3_000_000));
    // A flush that fails for good: the health says so.
    core.append(record(3)).unwrap();
    world.fs.fail_next_sync();
    world.fs.set_capacity(Some(0));
    world.clock.advance(W.as_nanos());
    let _retry_at = core.tick();
    let stats = core.stats();
    assert_eq!(stats.failed_flushes, 1);
    assert_ne!(stats.health, JournalHealth::Healthy, "the stats hide a failed journal");
    // The retry is due 50 ms after the failed flush; a retry 2 ms after that is 2 ms late.
    world.clock.advance(52_000_000);
    let _retry_at = core.tick();
    let stats = core.stats();
    assert_eq!(stats.failed_flushes, 2);
    assert_eq!(
        stats.flush_delay_last_nanos,
        Some(2_000_000),
        "a retry's delay is not counted from its retry time"
    );
}

/// P1, measured directly: the age of the oldest waiting record when a flush that covers it
/// starts, whether the journal flushes inside an append, the core flushes at a deadline, or a
/// caller asks.
#[test]
fn stats_measure_the_oldest_record_at_each_flush() {
    let world = World::new();
    let mut core = world.core();
    assert_eq!(core.stats().flush_age_max_nanos, None);
    // Inside an append: the first record waits W + 2 ms, then the next append flushes both.
    core.append(record(1)).unwrap();
    world.clock.advance(W.as_nanos() + 2_000_000);
    core.append(record(2)).unwrap();
    assert!(
        core.flushed_through().is_some(),
        "the journal did not flush inside the append"
    );
    assert_eq!(
        core.stats().flush_age_max_nanos,
        Some(W.as_nanos() + 2_000_000),
        "a flush inside an append was not measured"
    );
    // At a deadline, 5 ms late.
    core.append(record(3)).unwrap();
    world.clock.advance(W.as_nanos() + 5_000_000);
    assert_eq!(core.tick(), None);
    assert_eq!(core.stats().flush_age_max_nanos, Some(W.as_nanos() + 5_000_000));
    // On request, early: the longest stays.
    core.append(record(4)).unwrap();
    world.clock.advance(1_000_000);
    core.sync().unwrap();
    assert_eq!(core.stats().flush_age_max_nanos, Some(W.as_nanos() + 5_000_000));
}

/// The stop record's own flush covers the records waiting before it, so their wait counts toward P1
/// like any other flush's.
#[test]
fn the_stop_records_flush_is_measured() {
    let world = World::new();
    let stop = Stop::running();
    let mut core = world
        .core_on(world.clock.clone(), Millis(60_000))
        .with_stop(stop.clone(), the_actor());
    core.append(record(1)).unwrap();
    world.clock.advance(40_000_000);
    let _engaged = stop.engage(StopReason::Operator, operator());
    let _next = core.tick();
    assert!(stop.unrecorded().is_none());
    assert_eq!(
        core.stats().flush_age_max_nanos,
        Some(40_000_000),
        "the stop record's flush was not measured"
    );
}

/// The queue depth in the stats is what still waited behind the stats command when the actor
/// answered it.
#[tokio::test(flavor = "current_thread")]
async fn stats_count_the_commands_still_queued() {
    let world = World::new();
    let (handle, queue) = state_queue(16);
    let asker = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.stats().await.unwrap() })
    };
    tokio::task::yield_now().await;
    let mut appenders = Vec::new();
    for n in 0..3 {
        let handle = handle.clone();
        appenders.push(tokio::spawn(async move { handle.append(record(n)).await.unwrap() }));
        tokio::task::yield_now().await;
    }
    assert_eq!(handle.queued(), 4);
    let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default());
    let actor = start_state_actor(&supervisor, world.core(), queue).unwrap();
    assert_eq!(
        asker.await.unwrap().queued,
        3,
        "the stats do not count the commands behind them"
    );
    for appender in appenders {
        appender.await.unwrap();
    }
    drop(handle);
    tokio::task::spawn_blocking(move || actor.join().unwrap())
        .await
        .unwrap();
}

/// P2: the appends of a burst within W share the deadline's flush.
#[test]
fn a_burst_shares_one_flush() {
    let world = World::new();
    let mut core = world.core();
    let mut last = None;
    for n in 0..100 {
        last = Some(core.append(record(n)).unwrap());
        world.clock.advance(100_000);
    }
    let last = last.unwrap();
    assert!(
        core.flushed_through().is_none_or(|seq| seq < last.seq),
        "the burst was flushed per append, not shared"
    );
    world.clock.advance(W.as_nanos());
    assert_eq!(core.tick(), None);
    assert_eq!(core.stats().deadline_flushes, 1, "the burst did not share one flush");
    assert_eq!(core.flushed_through(), Some(last.seq));
}

/// The actor's own thread runs the schedule: nothing but the passing of time flushes. The
/// journal runs on the system clock, so the deadline passes only in real time and only the
/// actor's timer can find it. No command reaches the actor while the test waits: any command
/// would wake it and run the schedule. The power loss then shows what is durable.
///
/// The journal also flushes inside an append once W has passed since its last flush, which would
/// make the timer moot. So a record is flushed first, and the record under test follows at once
/// and is checked to be still unflushed; a machine that stalls for W in between is retried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_actor_flushes_a_quiet_journal_on_its_own() {
    let world = World::new();
    let (handle, queue) = state_queue(DEFAULT_QUEUE_CAPACITY);
    let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default());
    let core = world.core_on(Arc::new(SystemClock::new()), W);
    let actor = start_state_actor(&supervisor, core, queue).unwrap();
    let mut pending = None;
    for _attempt in 0..5 {
        handle.append(record(0)).await.unwrap();
        handle.sync().await.unwrap();
        let appended = handle.append(record(1)).await.unwrap();
        if handle.stats().await.unwrap().oldest_unflushed_nanos.is_some() {
            pending = Some(appended);
            break;
        }
    }
    assert!(
        pending.is_some(),
        "every attempt was flushed inside its append; the machine stalls for W"
    );
    let appended = pending.unwrap();
    // Ten windows of real time: the actor's timer fires after one.
    tokio::time::sleep(Duration::from_millis(W.0 * 10)).await;
    world.fs.power_loss();
    assert!(
        world.durable_ids().contains(&appended.id),
        "the actor did not flush a quiet journal on its own"
    );
    drop(handle);
    // The timer flushed everything, so the final flush has nothing left to write.
    let exit = tokio::task::spawn_blocking(move || actor.join().unwrap())
        .await
        .unwrap();
    assert_eq!(exit.final_flush, Ok(()));
    assert_eq!(exit.flushed_through, Some(appended.seq));
}

/// A refused start returns its error and hands the core and the queue back, so a record the
/// journal acknowledged can still be flushed. The actor's timer is dropped on the caller's
/// thread, here a runtime worker, where dropping a runtime the plain way panics.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_start_hands_the_journal_back() {
    let world = World::new();
    let (handle, queue) = state_queue(DEFAULT_QUEUE_CAPACITY);
    let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits { max_tasks: 0 });
    let mut core = world.core_on(world.clock.clone(), Millis(60_000));
    let appended = core.append(record(1)).unwrap();
    let refused = start_state_actor(&supervisor, core, queue).unwrap_err();
    assert_eq!(refused.error, SpawnError::Full);
    assert_eq!(supervisor.refused(), 1);
    let StartRefused { mut core, queue, .. } = *refused;
    core.sync().unwrap();
    world.fs.power_loss();
    assert!(
        world.durable_ids().contains(&appended.id),
        "a refused start lost a record the journal acknowledged"
    );
    drop(queue);
    assert_eq!(handle.append(record(2)).await.unwrap_err(), StateError::NotQueued);
}

/// The operating system can refuse a thread. The refusal is counted, and the core comes back.
/// The test runs itself again in a child process whose threads ask for a petabyte of stack, so
/// the system refuses every new thread; the child runs on its main thread only. Linux only:
/// other systems may answer that request differently.
#[cfg(target_os = "linux")]
#[test]
fn an_os_refusal_is_counted() {
    const CHILD: &str = "UAOS_STATE_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "an_os_refusal_is_counted", "--test-threads=1"])
            .env(CHILD, "1")
            .env("RUST_MIN_STACK", "1125899906842624")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "the child failed: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let world = World::new();
    let supervisor = Supervisor::new(runtime.handle().clone(), SupervisorLimits::default());
    let (_handle, queue) = state_queue(DEFAULT_QUEUE_CAPACITY);
    let refused = start_state_actor(&supervisor, world.core(), queue).unwrap_err();
    assert_eq!(refused.error, SpawnError::Thread);
    assert_eq!(supervisor.refused(), 1, "an OS refusal was not counted");
    assert_eq!(supervisor.live(), 0);
}

/// A clock that moves on by a set step each time it is read, so time passes inside the actor's
/// loop without the test touching it.
#[derive(Debug)]
struct Stepping {
    inner: SimClock,
    step: AtomicU64,
}

impl Clock for Stepping {
    fn wall(&self) -> Result<WallTime, PlatformError> {
        self.inner.wall()
    }

    fn mono(&self) -> MonoNanos {
        let now = self.inner.mono();
        self.inner.advance(self.step.load(Ordering::SeqCst));
        now
    }
}

/// Contract §4: the schedule also runs between queued commands, so a due flush waits at most one
/// command. Six commands wait in the queue; the clock moves W/4 at every read, so the deadline
/// passes in the middle of the drain. No reply may show a record older than W, and the drain
/// must flush.
#[tokio::test(flavor = "current_thread")]
async fn a_due_flush_waits_at_most_one_command() {
    let world = World::new();
    let clock = Arc::new(Stepping {
        inner: SimClock::new(WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap()),
        step: AtomicU64::new(0),
    });
    let mut core = world.core_on(clock.clone(), W);
    core.append(record(1)).unwrap();
    assert!(core.flushed_through().is_none());
    let (handle, queue) = state_queue(16);
    let mut askers = Vec::new();
    for _ in 0..6 {
        let handle = handle.clone();
        askers.push(tokio::spawn(async move { handle.stats().await.unwrap() }));
        tokio::task::yield_now().await;
    }
    assert_eq!(handle.queued(), 6);
    clock.step.store(W.as_nanos() / 4, Ordering::SeqCst);
    let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default());
    let actor = start_state_actor(&supervisor, core, queue).unwrap();
    let mut replies = Vec::new();
    for asker in askers {
        let stats = asker.await.unwrap();
        replies.push((stats.deadline_flushes, stats.oldest_unflushed_nanos));
    }
    assert!(
        replies
            .iter()
            .all(|(_, oldest)| oldest.is_none_or(|age| age <= W.as_nanos())),
        "the drain held a due flush back past the next command: {replies:?}"
    );
    assert_eq!(replies.last(), Some(&(1, None)), "the drain never flushed: {replies:?}");
    drop(handle);
    tokio::task::spawn_blocking(move || actor.join().unwrap())
        .await
        .unwrap();
}

/// The last flush, once every handle is gone, is reported to whoever joins the actor, and its
/// failure is not lost: records acknowledged before it may exist only in memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_final_flush_is_reported() {
    for fails in [false, true] {
        let world = World::new();
        let (handle, queue) = state_queue(DEFAULT_QUEUE_CAPACITY);
        let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default());
        // A window the test never reaches, so only the final flush can flush.
        let core = world.core_on(world.clock.clone(), Millis(60_000));
        let actor = start_state_actor(&supervisor, core, queue).unwrap();
        let appended = handle.append(record(1)).await.unwrap();
        if fails {
            // The flush fails, and a full disk keeps the journal from rewriting the records
            // to a fresh file, as it would after a single failed flush.
            world.fs.fail_next_sync();
            world.fs.set_capacity(Some(0));
        }
        drop(handle);
        let exit = tokio::task::spawn_blocking(move || actor.join().unwrap())
            .await
            .unwrap();
        if fails {
            assert!(
                matches!(exit.final_flush, Err(StateError::Journal(_))),
                "the final flush's failure was not reported: {exit:?}"
            );
            assert_ne!(exit.health, JournalHealth::Healthy);
            assert_eq!(exit.flushed_through, None);
        } else {
            assert_eq!(exit.final_flush, Ok(()));
            assert_eq!(exit.flushed_through, Some(appended.seq));
        }
    }
}

/// P10: a full queue makes callers wait. Nothing is dropped and no caller's records reorder.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_queue_applies_backpressure() {
    let world = World::new();
    let (handle, queue) = state_queue(2);
    let mut callers = Vec::new();
    for caller in 0..8_u8 {
        let handle = handle.clone();
        callers.push(tokio::spawn(async move {
            let mut seqs = Vec::new();
            for n in 0..4_u8 {
                seqs.push(handle.append(record(caller * 4 + n)).await.unwrap().seq);
            }
            seqs
        }));
    }
    // Every caller reaches the queue before the actor starts, so the queue is full.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(handle.queued(), 2, "the queue did not fill before the actor started");
    let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default());
    let actor = start_state_actor(&supervisor, world.core(), queue).unwrap();
    let mut total = 0;
    for caller in callers {
        let seqs = caller.await.unwrap();
        assert!(
            seqs.windows(2).all(|w| w[0] < w[1]),
            "a caller's records were reordered"
        );
        total += seqs.len();
    }
    assert_eq!(total, 32, "a record was dropped");
    assert_eq!(handle.stats().await.unwrap().queued, 0);
    drop(handle);
    tokio::task::spawn_blocking(move || actor.join().unwrap())
        .await
        .unwrap();
}

/// P10 across callers: callers that wait on a full queue are served in the order they arrived.
/// The test's runtime has one thread, so each caller runs, reaches the queue or starts waiting
/// on it, before the next one is spawned.
#[tokio::test(flavor = "current_thread")]
async fn waiting_callers_are_served_in_arrival_order() {
    let world = World::new();
    let (handle, queue) = state_queue(4);
    let mut callers = Vec::new();
    for n in 0..12_u8 {
        let handle = handle.clone();
        callers.push(tokio::spawn(async move { handle.append(record(n)).await.unwrap().seq }));
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }
    assert_eq!(handle.queued(), 4, "the queue did not fill before the actor started");
    let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default());
    let actor = start_state_actor(&supervisor, world.core(), queue).unwrap();
    let mut seqs = Vec::new();
    for caller in callers {
        seqs.push(caller.await.unwrap());
    }
    assert!(
        seqs.windows(2).all(|w| w[0] < w[1]),
        "callers were served out of arrival order: {seqs:?}"
    );
    drop(handle);
    tokio::task::spawn_blocking(move || actor.join().unwrap())
        .await
        .unwrap();
}

/// One thing a caller does between power losses.
#[derive(Debug, Clone)]
enum Step {
    Append,
    /// Time passes, in nanoseconds, while the actor runs its schedule.
    Wait(u64),
    Sync,
}

fn step() -> impl proptest::strategy::Strategy<Value = Step> {
    use proptest::prelude::*;
    prop_oneof![
        4 => Just(Step::Append),
        3 => (0..W.as_nanos() * 2).prop_map(Step::Wait),
        1 => Just(Step::Sync),
    ]
}

/// Runs the core as the actor does for `span` nanoseconds of simulated time: it sleeps until a
/// deadline, wakes `delay` late (the scheduling delay §4 measures), and runs the schedule.
fn run_actor_for(core: &mut StateCore, clock: &SimClock, span: u64, delay: u64) {
    let end = clock.mono().0 + span;
    loop {
        let now = clock.mono().0;
        // The next wake: the deadline the schedule returns, `delay` late. A deadline already
        // passed means the schedule did not flush when due; the actor then looks again a
        // millisecond later (only a broken schedule gets here).
        let wake = match core.tick() {
            Some(due) if due.saturating_add(delay) > now => due.saturating_add(delay),
            Some(_) => now + 1_000_000,
            None => u64::MAX,
        };
        if wake > end {
            clock.advance(end.saturating_sub(now));
            let _next = core.tick();
            return;
        }
        clock.advance(wake - now);
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 256,
        rng_seed: proptest::test_runner::RngSeed::Fixed(0x5541_4f53_5031_504c),
        ..proptest::test_runner::Config::default()
    })]

    /// With the core run as the actor runs it, whatever the traffic and wherever the power fails,
    /// every record acknowledged at least W plus the scheduling delay before the loss survives it.
    /// The records that survive are the first ones acknowledged, in order, with no gap.
    #[test]
    fn acknowledged_records_survive_a_power_loss_past_the_window(
        steps in proptest::collection::vec(step(), 1..60),
        delay in 0..W.as_nanos() / 2,
        cut in 0..W.as_nanos() * 3,
    ) {
        let world = World::new();
        let mut core = world.core();
        let mut acknowledged: Vec<(EventId, u64)> = Vec::new();
        for (n, step) in steps.into_iter().enumerate() {
            match step {
                Step::Append => {
                    let at = world.clock.mono().0;
                    let appended = core.append(record(u8::try_from(n % 256).unwrap())).unwrap();
                    acknowledged.push((appended.id, at));
                }
                Step::Wait(span) => run_actor_for(&mut core, &world.clock, span, delay),
                Step::Sync => core.sync().unwrap(),
            }
        }
        run_actor_for(&mut core, &world.clock, cut, delay);
        let lost_at = world.clock.mono().0;
        world.fs.power_loss();
        let durable = world.durable_ids();
        let in_order: Vec<EventId> = acknowledged.iter().map(|(id, _)| *id).take(durable.len()).collect();
        proptest::prop_assert_eq!(&durable, &in_order, "the records that survived are not a prefix");
        for (id, at) in &acknowledged {
            if at + W.as_nanos() + delay <= lost_at {
                proptest::prop_assert!(
                    durable.contains(id),
                    "a record acknowledged {} ns before the power loss was lost (W + delay = {} ns)",
                    lost_at - at,
                    W.as_nanos() + delay
                );
            }
        }
    }
}

/// An operator, as a human engages the stop.
fn operator() -> EngagedBy {
    EngagedBy {
        actor: Actor::Human,
        correlation_id: CorrelationId::from_parts(7, [7; 10]),
        config_version: ConfigVersion(1),
    }
}

/// The state actor, as it engages the stop for a failing journal.
fn the_actor() -> EngagedBy {
    EngagedBy {
        actor: Actor::System,
        correlation_id: CorrelationId::from_parts(9, [9; 10]),
        config_version: ConfigVersion(1),
    }
}

impl World {
    /// The records a read finds, in order.
    fn durable_records(&self) -> Vec<EventEnvelope> {
        read_verified(&self.fs, &self.data.join(JOURNAL_DIR))
            .unwrap()
            .0
            .into_iter()
            .map(|r| r.envelope)
            .collect()
    }

    /// The entries of the journal's directory: segments, manifest, marker and orphans.
    fn journal_entries(&self) -> usize {
        self.fs.list_dir(&self.data.join(JOURNAL_DIR)).unwrap().len()
    }

    /// The bytes the simulated disk holds under the data directory.
    fn stored(&self) -> u64 {
        let mut total = 0;
        let mut dirs = vec![self.data.clone()];
        while let Some(dir) = dirs.pop() {
            for path in self.fs.list_dir(&dir).unwrap_or_default() {
                match self.fs.read(&path) {
                    Ok(bytes) => total += u64::try_from(bytes.len()).unwrap(),
                    Err(_) => dirs.push(path),
                }
            }
        }
        total
    }

    /// The actors of the records a read finds, in order: what the OS holds, or after a power
    /// loss what was flushed. `record(n)` writes as the system, an operator's stop as a human.
    fn durable_actors(&self) -> Vec<Actor> {
        read_verified(&self.fs, &self.data.join(JOURNAL_DIR))
            .unwrap()
            .0
            .into_iter()
            .map(|r| r.envelope.actor)
            .collect()
    }
}

/// P3: an engaged stop's record goes ahead of every later record, and is flushed at once,
/// whatever the mode: here the window is a minute, so nothing else would flush.
#[test]
fn the_stop_record_goes_first() {
    let world = World::new();
    let stop = Stop::running();
    let mut core = world
        .core_on(world.clock.clone(), Millis(60_000))
        .with_stop(stop.clone(), the_actor());
    core.append(record(1)).unwrap();
    let _engaged = stop.engage(StopReason::Operator, operator());
    core.append(record(2)).unwrap();
    // Before a power loss a read sees what the OS holds: every record, in journal order.
    assert_eq!(
        world.durable_actors(),
        [Actor::System, Actor::Human, Actor::System],
        "the stop record did not go first"
    );
    assert!(stop.unrecorded().is_none(), "the stop was not marked recorded");
    // The record says who engaged the stop, and which engagement.
    let records = world.durable_records();
    let stopped = records.iter().find(|r| r.actor == Actor::Human).unwrap();
    assert_eq!(
        (stopped.correlation_id, stopped.config_version),
        (operator().correlation_id, operator().config_version),
        "the stop record lost who engaged it"
    );
    assert_eq!(
        stopped.payload_inline.as_ref().unwrap().as_value(),
        &serde_json::json!({"reason": "operator", "generation": "1"}),
        "the stop record lost its reason or its generation"
    );
    // After one, what was flushed: the stop's record and the one before it, not the one after.
    world.fs.power_loss();
    assert_eq!(
        world.durable_actors(),
        [Actor::System, Actor::Human],
        "the stop's record was not flushed at once"
    );
}

/// P4: a stop whose record fails stays engaged, the record is tried again with a growing pause,
/// nothing else is written meanwhile, and the record lands once space returns.
#[test]
fn a_full_disk_keeps_the_stop_and_retries() {
    let world = World::new();
    let stop = Stop::running();
    let mut core = world
        .core_on(world.clock.clone(), Millis(60_000))
        .with_stop(stop.clone(), the_actor());
    core.append(record(1)).unwrap();
    world.fs.set_capacity(Some(0));
    let _engaged = stop.engage(StopReason::Operator, operator());
    let _next = core.tick();
    assert!(stop.is_engaged());
    assert!(
        stop.unrecorded().is_some(),
        "a stop whose record failed was taken for recorded"
    );
    assert_eq!(core.stats().stop_record_retries, 1);
    // Nothing else is written while the stop's record cannot land.
    assert!(core.append(record(2)).is_err(), "a record went ahead of the stop's");
    // The schedule waits out the pause before it tries again.
    let tries = core.stats().stop_record_retries;
    let _next = core.tick();
    assert_eq!(
        core.stats().stop_record_retries,
        tries,
        "the schedule retried without a pause"
    );
    world.fs.set_capacity(None);
    world.clock.advance(6_000_000_000);
    let _next = core.tick();
    assert!(
        stop.unrecorded().is_none(),
        "the stop's record did not land once space returned"
    );
    world.fs.power_loss();
    assert!(
        world.durable_actors().contains(&Actor::Human),
        "the stop's record was lost"
    );
}

/// P6: a failing journal engages the stop. Every health has its reason, and a full disk under an
/// append engages the stop as the state actor.
#[test]
fn journal_failures_engage_the_stop() {
    assert_eq!(stop_reason_for(JournalHealth::Healthy), None);
    assert_eq!(stop_reason_for(JournalHealth::DiskFull), Some(StopReason::DiskFull));
    assert_eq!(
        stop_reason_for(JournalHealth::PayloadFlushFailed),
        Some(StopReason::PayloadFlushFailed)
    );
    assert_eq!(
        stop_reason_for(JournalHealth::WriteFailed),
        Some(StopReason::JournalFailed)
    );
    assert_eq!(
        stop_reason_for(JournalHealth::FlushFailed),
        Some(StopReason::JournalFailed)
    );

    let world = World::new();
    let stop = Stop::running();
    let mut core = world.core().with_stop(stop.clone(), the_actor());
    world.fs.set_capacity(Some(0));
    assert!(core.append(record(1)).is_err());
    assert!(stop.is_engaged(), "a failing journal kept admitting");
    assert_eq!(stop.reason(), stop_reason_for(core.health()));
    assert_eq!(stop.unrecorded().unwrap().by(), Some(&the_actor()));

    // So does a flush asked for, which fails and cannot be rewritten.
    let world = World::new();
    let stop = Stop::running();
    let mut core = world.core().with_stop(stop.clone(), the_actor());
    core.append(record(1)).unwrap();
    world.fs.fail_next_sync();
    world.fs.set_capacity(Some(0));
    assert!(core.sync().is_err());
    assert!(stop.is_engaged(), "a failed sync kept the kernel admitting");
    world.fs.set_capacity(None);

    // A flush that fails at its deadline engages the stop as well.
    let world = World::new();
    let stop = Stop::running();
    let mut core = world.core().with_stop(stop.clone(), the_actor());
    core.append(record(1)).unwrap();
    world.fs.fail_next_sync();
    world.fs.set_capacity(Some(0));
    world.clock.advance(W.as_nanos());
    let _next = core.tick();
    assert!(stop.is_engaged(), "a failed flush kept the kernel admitting");
}

/// The actor journals a stop on its own: an engagement wakes it, with no command sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_actor_records_a_stop_on_its_own() {
    let world = World::new();
    let stop = Stop::running();
    let (handle, queue) = state_queue(DEFAULT_QUEUE_CAPACITY);
    let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default());
    let core = world
        .core_on(world.clock.clone(), Millis(60_000))
        .with_stop(stop.clone(), the_actor());
    let actor = start_state_actor(&supervisor, core, queue).unwrap();
    // Let the actor run its first schedule and park on its wait, so only the engagement can
    // wake it.
    let _parked = handle.stats().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _engaged = stop.engage(StopReason::Operator, operator());
    for _ in 0..500 {
        if stop.unrecorded().is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        stop.unrecorded().is_none(),
        "the actor did not record a stop on its own"
    );
    world.fs.power_loss();
    assert_eq!(world.durable_actors(), [Actor::Human]);
    drop(handle);
    tokio::task::spawn_blocking(move || actor.join().unwrap())
        .await
        .unwrap();
}

/// Inside the pause after a failed stop record, an append or a sync is refused with that failure
/// and touches nothing. A recovery on a full disk may leave an empty segment file each time it is
/// tried, so tries are rationed by time, never by traffic.
#[test]
fn appends_inside_the_pause_try_nothing() {
    let world = World::new();
    let stop = Stop::running();
    let mut core = world
        .core_on(world.clock.clone(), Millis(60_000))
        .with_stop(stop.clone(), the_actor());
    core.append(record(1)).unwrap();
    world.fs.set_capacity(Some(0));
    let _engaged = stop.engage(StopReason::Operator, operator());
    // The try touched the journal for the stop's line, not for the command's: the command's line
    // was never written, so the refusal says `StopPending`, which the ledger task reads as a write
    // that wrote nothing (of E4).
    let first_try = core.append(record(2)).unwrap_err();
    assert!(
        matches!(first_try, StateError::StopPending(_)),
        "a command refused because its stop record failed read as a write of unknown fate: {first_try:?}"
    );
    let (entries, tries) = (world.journal_entries(), core.stats().stop_record_retries);
    assert_eq!(tries, 1);
    for n in 0..200_u8 {
        // Inside the pause nothing is tried, and the refusal says so (`StopPending`).
        let refused = core.append(record(n)).unwrap_err();
        assert_eq!(
            core.stats().stop_record_retries,
            tries,
            "an append inside the pause tried the stop record again"
        );
        assert!(
            matches!(refused, StateError::StopPending(_)),
            "a refusal inside the pause did not say it wrote nothing: {refused:?}"
        );
        assert!(matches!(core.sync().unwrap_err(), StateError::StopPending(_)));
    }
    assert_eq!(
        (core.stats().stop_record_retries, world.journal_entries()),
        (tries, entries),
        "an append inside the pause tried the stop record again"
    );
    // Past the pause, one more try.
    world.clock.advance(11_000_000);
    assert!(core.append(record(3)).is_err());
    assert_eq!(core.stats().stop_record_retries, tries + 1);
}

/// The handle says which policy the journal flushes under, which an intent records as its
/// `durability`.
#[tokio::test]
async fn the_handle_says_the_journals_flush_policy() {
    let world = World::new();
    let (handle, queue) = state_queue(DEFAULT_QUEUE_CAPACITY);
    let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default());
    let actor = start_state_actor(&supervisor, world.core_on(world.clock.clone(), Millis(60_000)), queue).unwrap();
    assert_eq!(
        handle.flush_policy().await.unwrap(),
        FlushPolicy::Balanced { window: Millis(60_000) }
    );
    drop(handle);
    tokio::task::spawn_blocking(move || actor.join().unwrap())
        .await
        .unwrap();
}

/// The pause between scheduled tries doubles from 10 ms and stops at 5 s, and only real tries
/// count.
#[test]
fn the_stop_records_pause_doubles_to_five_seconds() {
    let world = World::new();
    let stop = Stop::running();
    let mut core = world
        .core_on(world.clock.clone(), Millis(60_000))
        .with_stop(stop.clone(), the_actor());
    world.fs.set_capacity(Some(0));
    let _engaged = stop.engage(StopReason::Operator, operator());
    let mut pauses = Vec::new();
    for _ in 0..12 {
        let now = world.clock.mono().0;
        let next = core.tick().unwrap();
        pauses.push((next - now) / 1_000_000);
        world.clock.advance(next - now);
    }
    assert_eq!(
        pauses,
        [10, 20, 40, 80, 160, 320, 640, 1280, 2560, 5000, 5000, 5000],
        "the stop record's pauses are not 10 ms doubling to 5 s"
    );
    assert_eq!(core.stats().stop_record_retries, 12);
}

/// When the stop's record fails, the records already in the journal are flushed anyway. They come
/// before the stop's, so the order holds; a flush needs no space.
#[test]
fn a_failing_stop_record_still_flushes_what_came_before() {
    let world = World::new();
    let stop = Stop::running();
    let mut core = world
        .core_on(world.clock.clone(), Millis(60_000))
        .with_stop(stop.clone(), the_actor());
    core.append(record(1)).unwrap();
    world.fs.set_capacity(Some(0));
    let _engaged = stop.engage(StopReason::Operator, operator());
    assert!(core.sync().is_err());
    world.fs.power_loss();
    assert_eq!(
        world.durable_actors(),
        [Actor::System],
        "a failing stop record kept the records before it from being flushed"
    );
}

/// A stop record appended whose flush failed is flushed by the next try, never appended a second
/// time. A failed flush keeps the bytes in the cache, and the rewrite that would save them finds no
/// space until the space returns.
#[test]
fn a_stop_record_is_journaled_once() {
    // How many bytes the stop's record takes, on an identical world.
    let probe = World::new();
    let stop = Stop::running();
    let mut core = probe
        .core_on(probe.clock.clone(), Millis(60_000))
        .with_stop(stop.clone(), the_actor());
    core.append(record(1)).unwrap();
    core.sync().unwrap();
    let before = probe.stored();
    let _engaged = stop.engage(StopReason::Operator, operator());
    let _next = core.tick();
    let line = probe.stored() - before;

    let world = World::new();
    let stop = Stop::running();
    let mut core = world
        .core_on(world.clock.clone(), Millis(60_000))
        .with_stop(stop.clone(), the_actor());
    core.append(record(1)).unwrap();
    core.sync().unwrap();
    world.fs.set_failed_sync_keeps_cache(true);
    world.fs.set_capacity(Some(world.stored() + line + line / 2));
    world.fs.fail_next_sync();
    let _engaged = stop.engage(StopReason::Operator, operator());
    let _next = core.tick();
    assert!(stop.unrecorded().is_some(), "the scenario's first try did not fail");
    world.fs.set_capacity(None);
    world.clock.advance(6_000_000_000);
    let _next = core.tick();
    assert!(stop.unrecorded().is_none(), "the stop's record did not land");
    let stops = world
        .durable_records()
        .iter()
        .filter(|r| r.event_type == types::KERNEL_STOPPED && r.actor == Actor::Human)
        .count();
    assert_eq!(stops, 1, "one engagement was journaled twice");
}

/// A random source that fails once told to.
#[derive(Debug)]
struct Failing {
    inner: SimRng,
    fail: AtomicBool,
}

impl Rng for Failing {
    fn fill(&self, buf: &mut [u8]) -> Result<(), PlatformError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(PlatformError::RandomUnavailable);
        }
        self.inner.fill(buf)
    }
}

/// A failure of the platform under the journal leaves it healthy, but no record can be written, so
/// the kernel cannot journal and the stop engages.
#[test]
fn a_platform_failure_engages_the_stop() {
    let world = World::new();
    let rng = Arc::new(Failing {
        inner: SimRng::new(3),
        fail: AtomicBool::new(false),
    });
    let journal = Journal::open(
        Arc::new(world.fs.clone()),
        world.clock.clone(),
        rng.clone(),
        &world.data,
        FlushPolicy::Balanced { window: W },
    )
    .unwrap();
    let stop = Stop::running();
    let mut core = StateCore::new(journal).with_stop(stop.clone(), the_actor());
    rng.fail.store(true, Ordering::SeqCst);
    assert!(core.append(record(1)).is_err());
    assert_eq!(core.health(), JournalHealth::Healthy);
    assert_eq!(
        stop.reason(),
        Some(StopReason::JournalFailed),
        "a kernel that could not journal kept admitting"
    );
}

/// A stop record that failed is tried again by the actor's own schedule: once space returns it
/// lands with no command sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_stop_record_lands_on_its_own_once_space_returns() {
    let world = World::new();
    let stop = Stop::running();
    let (handle, queue) = state_queue(DEFAULT_QUEUE_CAPACITY);
    let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default());
    let core = world
        .core_on(Arc::new(SystemClock::new()), Millis(60_000))
        .with_stop(stop.clone(), the_actor());
    let actor = start_state_actor(&supervisor, core, queue).unwrap();
    let _parked = handle.stats().await.unwrap();
    world.fs.set_capacity(Some(0));
    let _engaged = stop.engage(StopReason::Operator, operator());
    for _ in 0..500 {
        if handle_tries(&handle).await > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(handle_tries(&handle).await > 0, "the first try never ran");
    world.fs.set_capacity(None);
    for _ in 0..1_000 {
        if stop.unrecorded().is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        stop.unrecorded().is_none(),
        "a failed stop record did not land on its own once space returned"
    );
    drop(handle);
    tokio::task::spawn_blocking(move || actor.join().unwrap())
        .await
        .unwrap();
}

/// The failed stop-record tries so far, read through the handle (a command, but only before space
/// returns: after it, nothing is sent).
async fn handle_tries(handle: &uaos_runtime::StateHandle) -> u64 {
    handle.stats().await.unwrap().stop_record_retries
}

/// The flush inside the stop record's own append (due once W has passed since the last flush) fails
/// after the line is written. The append returns an error, but the record is in the journal; the
/// next try flushes it and never appends it again.
#[test]
fn a_stop_record_whose_inline_flush_failed_is_journaled_once() {
    let window = Millis(60_000);
    // How many bytes the stop's record takes, on an identical world.
    let probe = World::new();
    let stop = Stop::running();
    let mut core = probe
        .core_on(probe.clock.clone(), window)
        .with_stop(stop.clone(), the_actor());
    core.append(record(1)).unwrap();
    core.sync().unwrap();
    probe.clock.advance(window.as_nanos() + 1);
    let before = probe.stored();
    let _engaged = stop.engage(StopReason::Operator, operator());
    let _next = core.tick();
    let line = probe.stored() - before;

    let world = World::new();
    let stop = Stop::running();
    let mut core = world
        .core_on(world.clock.clone(), window)
        .with_stop(stop.clone(), the_actor());
    core.append(record(1)).unwrap();
    core.sync().unwrap();
    // The window passes with nothing to flush, so the stop's append flushes inline.
    world.clock.advance(window.as_nanos() + 1);
    world.fs.set_failed_sync_keeps_cache(true);
    world.fs.set_capacity(Some(world.stored() + line + line / 2));
    world.fs.fail_next_sync();
    let _engaged = stop.engage(StopReason::Operator, operator());
    let _next = core.tick();
    assert!(stop.unrecorded().is_some(), "the scenario's first try did not fail");
    world.fs.set_capacity(None);
    world.clock.advance(6_000_000_000);
    let _next = core.tick();
    assert!(stop.unrecorded().is_none(), "the stop's record did not land");
    let stops = world
        .durable_records()
        .iter()
        .filter(|r| r.event_type == types::KERNEL_STOPPED && r.actor == Actor::Human)
        .count();
    assert_eq!(stops, 1, "an engagement whose inline flush failed was journaled twice");
}

/// An append whose try of the stop record fails, here on a full disk, is refused with
/// `StopPending`, and its own line is not among the journal's records. The command's line is
/// appended only after the stop record lands, so this holds for every way that try can fail (a
/// failed flush is recovered in place, so a full disk is the failure a test can reach).
#[test]
fn a_command_refused_for_its_stop_record_is_not_written() {
    let world = World::new();
    let stop = Stop::running();
    let mut core = world
        .core_on(world.clock.clone(), Millis(60_000))
        .with_stop(stop.clone(), the_actor());
    core.append(record(1)).unwrap();
    let _engaged = stop.engage(StopReason::Operator, operator());
    world.fs.set_capacity(Some(0));
    let refused = core.append(record(2)).unwrap_err();
    assert!(
        matches!(refused, StateError::StopPending(_)),
        "a command refused because its stop record failed read as a write of unknown fate: {refused:?}"
    );
    let refused_line = record(2).correlation_id;
    let written = read_verified(&world.fs, &world.data.join(JOURNAL_DIR)).unwrap().0;
    assert!(
        !written.iter().any(|r| r.envelope.correlation_id == refused_line),
        "a refused command's line was written"
    );
}
