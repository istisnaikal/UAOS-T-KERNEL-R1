// SPDX-License-Identifier: Apache-2.0

//! The state actor's cost and its flush schedule's delay.
//!
//! Run: `cargo bench -p uaos-runtime --bench state_actor`. Everything runs on the real file
//! system (`OsFs`, under the system's temporary directory), the system clock and OS randomness.
//! Three parts:
//!
//! 1. **Overhead.** The same appends, timed one by one: straight into a `Journal`, then through
//!    a `StateHandle` from one caller that awaits each answer. The flush window is a minute, so
//!    no flush falls inside either run: the budget excludes the flush itself.
//! 2. **Delay when idle.** Two appends, then nothing for three windows (no command reaches the
//!    actor, as in a quiet period), then the stats: the delay from the deadline to the flush the
//!    actor's timer started, and the oldest record's age at that flush. The second append is
//!    there because the journal flushes the first one after a quiet period on its own; each
//!    round checks that the actor's timer flushed once.
//! 3. **Under load.** Concurrent callers append without pause for a while. The journal's own
//!    rule then flushes inside appends, and the actor flushes at a deadline only when a gap
//!    opens. Printed: the longest delay of any deadline flush, and P1 measured directly: the
//!    oldest record's age when any flush that covered it started (`flush_age_max_nanos`).
//! 4. **The ledger task**. Operations reserved, executed and settled one at a time through the
//!    ledger task: `reserve` and `execute` timed from the call to the token, beside a bare append
//!    through the actor timed in the same loop. Each pays one append; what the task adds over it is
//!    one queue hop and the ledger's own work, which the policy and routing budget bounds (≤ 1 ms
//!    excluding I/O).
//!
//! `UAOS_BENCH_ENV` labels the environment. Dependency-free on purpose (`harness = false`); nothing
//! leaves the machine.

#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::disallowed_methods,
    reason = "benchmark binary: measures wall time, makes its directories with std::fs and prints results"
)]

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use uaos_contracts::budget::IdempotencyKey;
use uaos_contracts::event::{Actor, Durability, Metadata, types};
use uaos_contracts::id::{CorrelationId, OperationId, PoolId, ReservationId, TypedId};
use uaos_contracts::limits::Millis;
use uaos_contracts::money::NanoUsd;
use uaos_contracts::operation::{OperationKind, RiskTier, SideEffectClass};
use uaos_contracts::wire::ConfigVersion;
use uaos_egress::EgressError;
use uaos_ledger::Ledger;
use uaos_platform::fs::Fs;
use uaos_platform::real::fs::OsFs;
use uaos_platform::real::{OsRng, SystemClock};
use uaos_platform::{Clock, Rng};
use uaos_runtime::{
    DEFAULT_LEDGER_QUEUE, EngagedBy, Movement, OperationRecord, Settled, StateCore, StateHandle, Stop, Supervisor,
    SupervisorLimits, start_ledger_task, start_state_actor, state_queue,
};
use uaos_state::journal::{EventDraft, FlushPolicy, Journal};

/// Appends timed in each run of part 1.
const APPENDS: usize = 5_000;
/// The default flush window.
const W: Millis = Millis(50);
/// A window no part-1 run reaches.
const LAZY: Millis = Millis(60_000);
const IDLE_ROUNDS: usize = 100;
/// Operations timed in part 4.
const OPERATIONS: usize = 5_000;
/// Callers and duration of part 3.
const LOADED_CALLERS: usize = 256;
const LOADED_FOR: Duration = Duration::from_secs(3);

fn open(dir: &Path, window: Millis) -> Journal {
    std::fs::create_dir_all(dir).unwrap();
    let fs: Arc<dyn Fs> = Arc::new(OsFs);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let rng: Arc<dyn Rng> = Arc::new(OsRng);
    Journal::open(fs, clock, rng, dir, FlushPolicy::Balanced { window }).unwrap()
}

fn draft(n: u64) -> EventDraft {
    EventDraft {
        session_id: None,
        pocket_id: None,
        operation_id: None,
        request_id: None,
        agent_id: None,
        correlation_id: CorrelationId::from_parts(n, [5; 10]),
        parent_id: None,
        actor: Actor::System,
        event_type: types::OP_RESERVED_INTENT,
        payload_ref: None,
        payload_inline: None,
        cost_estimate: None,
        compensable: false,
        side_effect_class: SideEffectClass::External,
        risk_tier: RiskTier::MAX,
        durability: Durability::Critical,
        config_version: ConfigVersion(1),
        metadata: Metadata::default(),
    }
}

fn index(n: usize) -> u64 {
    u64::try_from(n).unwrap()
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000_000.0
}

fn ms_of_nanos(n: u64) -> f64 {
    Duration::from_nanos(n).as_secs_f64() * 1_000.0
}

/// The sample at quantile `q` (0 to 1) of sorted `samples`.
fn quantile<T: Copy>(samples: &[T], q: f64) -> T {
    let last = samples.len() - 1;
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::as_conversions,
        reason = "an index into a short sorted sample"
    )]
    let at = ((last as f64) * q).round() as usize;
    samples[at.min(last)]
}

fn start(runtime: &tokio::runtime::Runtime, journal: Journal) -> (StateHandle, uaos_runtime::StateActor) {
    let (handle, queue) = state_queue(uaos_runtime::DEFAULT_QUEUE_CAPACITY);
    let supervisor = Supervisor::new(runtime.handle().clone(), SupervisorLimits::default());
    let actor = start_state_actor(&supervisor, StateCore::new(journal), queue).unwrap();
    (handle, actor)
}

fn overhead(root: &Path, runtime: &tokio::runtime::Runtime) {
    let mut journal = open(&root.join("direct"), LAZY);
    let mut direct = Vec::with_capacity(APPENDS);
    for n in 0..APPENDS {
        let record = draft(index(n));
        let t = Instant::now();
        journal.append(record).unwrap();
        direct.push(t.elapsed());
    }
    journal.sync().unwrap();
    drop(journal);

    let (handle, actor) = start(runtime, open(&root.join("actor"), LAZY));
    let through = runtime.block_on(async {
        let mut through = Vec::with_capacity(APPENDS);
        for n in 0..APPENDS {
            let record = draft(index(n));
            let t = Instant::now();
            handle.append(record).await.unwrap();
            through.push(t.elapsed());
        }
        through
    });
    drop(handle);
    assert_eq!(actor.join().unwrap().final_flush, Ok(()));

    direct.sort_unstable();
    let mut through = through;
    through.sort_unstable();
    println!("1. overhead: {APPENDS} appends each, no flush inside; µs (p50, p95, p99, max)");
    for (name, samples) in [("direct", &direct), ("actor", &through)] {
        println!(
            "   {name:<7} {:>8.1} {:>8.1} {:>8.1} {:>8.1}",
            us(quantile(samples, 0.50)),
            us(quantile(samples, 0.95)),
            us(quantile(samples, 0.99)),
            us(quantile(samples, 1.0)),
        );
    }
    println!(
        "   added at p95: {:.1} µs (budget 100 µs)",
        us(quantile(&through, 0.95)) - us(quantile(&direct, 0.95))
    );
}

fn idle_delay(root: &Path, runtime: &tokio::runtime::Runtime) {
    let (handle, actor) = start(runtime, open(&root.join("idle"), W));
    let (delays, ages) = runtime.block_on(async {
        let (mut delays, mut ages) = (Vec::new(), Vec::new());
        for n in 0..IDLE_ROUNDS {
            // After a quiet period the journal's own rule flushes the first append itself, so
            // a second append follows at once: it is not due under that rule, and only the
            // actor's timer can flush it.
            handle.append(draft(index(2 * n))).await.unwrap();
            handle.append(draft(index(2 * n + 1))).await.unwrap();
            // Nothing reaches the actor for three windows.
            tokio::time::sleep(Duration::from_millis(W.0 * 3)).await;
            let stats = handle.stats().await.unwrap();
            assert_eq!(stats.oldest_unflushed_nanos, None, "the record was not flushed");
            assert_eq!(
                stats.deadline_flushes,
                index(n + 1),
                "a round was flushed by something other than the actor's timer"
            );
            let delay = stats.flush_delay_last_nanos.unwrap();
            delays.push(delay);
            // The age at the flush: the window, plus the delay.
            ages.push(W.as_nanos() + delay);
        }
        (delays, ages)
    });
    drop(handle);
    assert_eq!(actor.join().unwrap().final_flush, Ok(()));
    let (mut delays, mut ages) = (delays, ages);
    delays.sort_unstable();
    ages.sort_unstable();
    println!(
        "2. delay when idle: {IDLE_ROUNDS} quiet rounds, W = {} ms; ms (p50, p99, max)",
        W.0
    );
    println!(
        "   deadline to flush   {:>8.3} {:>8.3} {:>8.3}",
        ms_of_nanos(quantile(&delays, 0.50)),
        ms_of_nanos(quantile(&delays, 0.99)),
        ms_of_nanos(quantile(&delays, 1.0)),
    );
    println!(
        "   age at the flush    {:>8.3} {:>8.3} {:>8.3}",
        ms_of_nanos(quantile(&ages, 0.50)),
        ms_of_nanos(quantile(&ages, 0.99)),
        ms_of_nanos(quantile(&ages, 1.0)),
    );
}

fn loaded_delay(root: &Path, runtime: &tokio::runtime::Runtime) {
    let (handle, actor) = start(runtime, open(&root.join("loaded"), W));
    let (appends, stats) = runtime.block_on(async {
        let until = Instant::now() + LOADED_FOR;
        let mut callers = Vec::new();
        for caller in 0..LOADED_CALLERS {
            let handle = handle.clone();
            callers.push(tokio::spawn(async move {
                let mut n = 0_u64;
                while Instant::now() < until {
                    handle.append(draft(index(caller) << 32 | n)).await.unwrap();
                    n += 1;
                }
                n
            }));
        }
        let mut appends = 0;
        for caller in callers {
            appends += caller.await.unwrap();
        }
        (appends, handle.stats().await.unwrap())
    });
    drop(handle);
    assert_eq!(actor.join().unwrap().final_flush, Ok(()));
    println!(
        "3. under load: {LOADED_CALLERS} callers for {} s, {appends} appends, {} deadline flushes \
         (the journal's own rule inside append flushed the rest)",
        LOADED_FOR.as_secs(),
        stats.deadline_flushes
    );
    println!(
        "   longest deadline to flush: {}; oldest record at any flush (P1): {}",
        stats
            .flush_delay_max_nanos
            .map_or("none".to_owned(), |n| format!("{:.3} ms", ms_of_nanos(n))),
        stats
            .flush_age_max_nanos
            .map_or("none".to_owned(), |n| format!("{:.3} ms", ms_of_nanos(n))),
    );
}

fn operation(n: usize) -> OperationRecord {
    OperationRecord {
        operation_id: OperationId::from_parts(index(n) + 1, [3; 10]),
        session_id: None,
        pocket_id: None,
        request_id: None,
        agent_id: None,
        correlation_id: CorrelationId::from_parts(index(n), [6; 10]),
        actor: Actor::System,
        kind: OperationKind::ModelCall,
        upstream: "bench".to_owned(),
        side_effect_class: SideEffectClass::External,
        compensable: false,
        risk_tier: RiskTier::MIN,
        config_version: ConfigVersion(1),
    }
}

fn ledger_task(root: &Path, runtime: &tokio::runtime::Runtime) {
    let (handle, actor) = start(runtime, open(&root.join("ledger"), LAZY));
    let supervisor = Supervisor::new(runtime.handle().clone(), SupervisorLimits::default());
    let correlation_id = CorrelationId::from_parts(1, [7; 10]);
    let by = EngagedBy {
        actor: Actor::System,
        correlation_id,
        config_version: ConfigVersion(1),
    };
    let (mut reserves, mut executes, mut appends) = runtime.block_on(async {
        let (ledger, _task) = start_ledger_task(
            &supervisor,
            Ledger::default(),
            handle.clone(),
            Stop::running(),
            by,
            DEFAULT_LEDGER_QUEUE,
        )
        .unwrap();
        let pool = PoolId::from_parts(1, [1; 10]);
        let funds = Movement {
            principal: Actor::System,
            key: IdempotencyKey::new("fund").unwrap(),
            correlation_id,
            config_version: ConfigVersion(1),
        };
        ledger.allocate(pool, NanoUsd::new(1 << 40), funds).await.unwrap();
        let mut samples = (
            Vec::with_capacity(OPERATIONS),
            Vec::with_capacity(OPERATIONS),
            Vec::with_capacity(OPERATIONS),
        );
        for n in 0..OPERATIONS {
            let id = ReservationId::from_parts(index(n) + 1, [2; 10]);
            let t = Instant::now();
            let held = ledger.reserve(operation(n), pool, id, NanoUsd::new(100)).await.unwrap();
            samples.0.push(t.elapsed());
            let t = Instant::now();
            let in_flight = ledger.execute(held).await.unwrap();
            samples.1.push(t.elapsed());
            let unsent = Settled::DoorFailed(EgressError::Timeout);
            ledger.settle(in_flight, unsent).await.unwrap();
            let t = Instant::now();
            handle.append(draft(index(n))).await.unwrap();
            samples.2.push(t.elapsed());
        }
        samples
    });
    drop(handle);
    assert_eq!(actor.join().unwrap().final_flush, Ok(()));
    reserves.sort_unstable();
    executes.sort_unstable();
    appends.sort_unstable();
    println!("4. ledger task: {OPERATIONS} Operations, one at a time, no flush inside; µs (p50, p99, max)");
    for (name, samples) in [("reserve", &reserves), ("execute", &executes), ("append", &appends)] {
        println!(
            "   {name:<7} {:>8.1} {:>8.1} {:>8.1}",
            us(quantile(samples, 0.50)),
            us(quantile(samples, 0.99)),
            us(quantile(samples, 1.0)),
        );
    }
    println!(
        "   added over one append at p99: reserve {:.1} µs, execute {:.1} µs \
         (policy and routing budget: p99 ≤ 1 ms excluding I/O)",
        us(quantile(&reserves, 0.99)) - us(quantile(&appends, 0.99)),
        us(quantile(&executes, 0.99)) - us(quantile(&appends, 0.99)),
    );
}

fn main() {
    let env = std::env::var("UAOS_BENCH_ENV").unwrap_or_else(|_| "unlabelled".to_owned());
    let root = std::env::temp_dir().join(format!("uaos-state-actor-bench-{}", std::process::id()));
    let workers = std::thread::available_parallelism().map_or(2, std::num::NonZero::get);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_time()
        .build()
        .unwrap();
    println!("state actor, env {env}, {workers} runtime workers");
    overhead(&root, &runtime);
    idle_delay(&root, &runtime);
    loaded_delay(&root, &runtime);
    ledger_task(&root, &runtime);
    std::fs::remove_dir_all(&root).unwrap();
}
