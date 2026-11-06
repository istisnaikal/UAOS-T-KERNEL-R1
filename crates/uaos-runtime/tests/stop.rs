// SPDX-License-Identifier: Apache-2.0

//! The stop, admission, the configuration snapshot, declared pricing and the supervisor.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use uaos_contracts::error::codes;
use uaos_contracts::event::{Actor, EventEnvelope, InlinePayload, types};
use uaos_contracts::id::{CorrelationId, TypedId};
use uaos_contracts::money::NanoUsd;
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::ConfigVersion;
use uaos_module_api::Code;
use uaos_platform::fs::Fs;
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, Rng};
use uaos_runtime::{
    Admission, AdmissionLimits, BootState, ConfigCell, ConfigError, ConfigSnapshot, DeclaredPrice, EngagedBy,
    LocaleTag, MAX_LOCALE_TAG, Price, PriceError, RefusalReason, SpawnError, Stop, StopReason, Supervisor,
    SupervisorLimits, boot_state,
};
use uaos_state::journal::{EventDraft, FlushPolicy, JOURNAL_DIR, Journal, read_verified};

const MIB: u64 = 1024 * 1024;
const DATA: &str = "/data";

fn limits(max_operations: u32, max_bytes: u64) -> AdmissionLimits {
    AdmissionLimits {
        max_operations,
        max_bytes,
        ..AdmissionLimits::default()
    }
}

// ── The stop ───────────────────────────────────────────────────────────────────────────

#[test]
fn a_stopped_kernel_admits_nothing() {
    let stop = Stop::running();
    let admission = Admission::new(AdmissionLimits::default(), stop.clone());
    let mut live = admission.admit(MIB).unwrap();
    let _engaged = stop.engage(StopReason::Operator, by());
    let refused = admission.admit(0);
    assert!(refused.is_err(), "a stopped kernel admitted an Operation");
    let refusal = refused.unwrap_err();
    assert_eq!(refusal.reason, RefusalReason::Stopped(StopReason::Operator));
    assert_eq!(refusal.code, codes::RUNTIME_STOPPED);
    assert!(refusal.retry_after > Duration::from_secs(60), "Claude Code would retry");
    assert!(live.charge(1).is_err(), "a stopped kernel let an Operation grow");
}

#[test]
fn every_stopped_refusal_says_stopped() {
    // The overrun's own S1 code belongs to the stream that overran, not to every request refused
    // after it.
    for reason in StopReason::ENGAGEABLE {
        let stop = Stop::running();
        let _engaged = stop.engage(reason, by());
        let refusal = Admission::new(AdmissionLimits::default(), stop).admit(0).unwrap_err();
        assert_eq!(refusal.reason, RefusalReason::Stopped(reason));
        assert_eq!(
            refusal.code,
            codes::RUNTIME_STOPPED,
            "a stopped kernel's refusal carried another code"
        );
    }
}

#[test]
fn the_first_reason_wins() {
    let stop = Stop::running();
    let first = stop.engage(StopReason::Operator, by());
    let second = stop.engage(StopReason::DiskFull, by());
    assert!(first.first() && !second.first());
    assert_eq!(second.reason(), StopReason::Operator);
    assert_eq!(stop.reason(), Some(StopReason::Operator));
    assert!(stop.is_engaged());
}

#[tokio::test]
async fn a_stop_reaches_every_live_permit() {
    let stop = Stop::running();
    let admission = Admission::new(AdmissionLimits::default(), stop.clone());
    let permits: Vec<_> = (0..3).map(|_| admission.admit(1).unwrap()).collect();
    // The watch is polled, and waiting, before the stop engages.
    let waiting = tokio::time::timeout(Duration::from_secs(5), permits[0].stop().clone().stopped());
    let (reached, ()) = tokio::join!(waiting, async {
        tokio::task::yield_now().await;
        let _engaged = stop.engage(StopReason::CanaryHit, by());
    });
    for permit in &permits {
        assert_eq!(permit.stop().engaged(), Some(StopReason::CanaryHit));
    }
    assert_eq!(
        reached.ok(),
        Some(StopReason::CanaryHit),
        "a waiting watch missed the stop"
    );
}

#[test]
fn the_record_is_handed_out_until_it_is_journaled() {
    let stop = Stop::running();
    stop.recorded(0);
    assert!(stop.unrecorded().is_none(), "a running kernel had a stop to record");
    let _engaged = stop.engage(StopReason::DiskFull, by());
    assert_eq!(stop.unrecorded().map(|e| e.reason()), Some(StopReason::DiskFull));
    // A write that failed leaves the record to hand out again.
    assert!(
        stop.unrecorded().is_some(),
        "a stop's record was handed out once and could be lost"
    );
    stop.recorded(stop.unrecorded().unwrap().generation());
    assert!(stop.unrecorded().is_none(), "a journaled stop was handed out again");
}

/// S5's mechanism, proven before resume exists: marking another generation recorded leaves the
/// current engagement unrecorded, so a second engagement is journaled again however late the first
/// one's record lands.
#[test]
fn a_stale_generation_does_not_mark_the_stop_recorded() {
    let stop = Stop::running();
    let _engaged = stop.engage(StopReason::Operator, by());
    let generation = stop.unrecorded().unwrap().generation();
    assert_eq!(generation, 1);
    stop.recorded(0);
    stop.recorded(generation + 1);
    assert!(
        stop.unrecorded().is_some(),
        "another generation's record marked this engagement recorded"
    );
    stop.recorded(generation);
    assert!(stop.unrecorded().is_none());
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
            rng: Arc::new(SimRng::new(7)),
            data: PathBuf::from(DATA),
        }
    }

    fn append(&self, drafts: Vec<EventDraft>) {
        let clock: Arc<dyn Clock> = self.clock.clone();
        let rng: Arc<dyn Rng> = self.rng.clone();
        let mut journal =
            Journal::open(Arc::new(self.fs.clone()), clock, rng, &self.data, FlushPolicy::Strict).unwrap();
        for draft in drafts {
            journal.append(draft).unwrap();
        }
    }

    /// What the next start reads.
    fn records(&self) -> Vec<EventEnvelope> {
        read_verified(&self.fs, &self.data.join(JOURNAL_DIR))
            .unwrap()
            .0
            .into_iter()
            .map(|r| r.envelope)
            .collect()
    }
}

/// The system, as the relay and the state actor engage the stop.
fn by() -> EngagedBy {
    EngagedBy {
        actor: Actor::System,
        correlation_id: CorrelationId::from_parts(1, [7; 10]),
        config_version: ConfigVersion(1),
    }
}

fn stop_record(reason: StopReason) -> EventDraft {
    let stop = Stop::running();
    let _engaged = stop.engage(reason, by());
    stop.unrecorded().unwrap().draft().unwrap()
}

#[test]
fn a_journaled_stop_survives_a_restart() {
    let world = World::new();
    world.append(vec![stop_record(StopReason::BudgetOverrun)]);
    let state = boot_state(&world.records());
    assert_eq!(
        state,
        BootState::Stopped(StopReason::BudgetOverrun),
        "a journaled stop did not survive a restart"
    );
    let stop = Stop::booted(state);
    assert!(stop.is_engaged());
    assert!(stop.unrecorded().is_none(), "boot journaled its stop again");
    assert!(Admission::new(AdmissionLimits::default(), stop).admit(0).is_err());
}

#[test]
fn an_unknown_stop_reason_still_boots_stopped_and_a_resume_boots_running() {
    let world = World::new();
    let mut future = stop_record(StopReason::Operator);
    future.payload_inline = Some(InlinePayload::new(serde_json::json!({ "reason": "from_a_later_build" })).unwrap());
    let mut bare = stop_record(StopReason::Operator);
    bare.payload_inline = None;
    world.append(vec![future]);
    assert_eq!(
        boot_state(&world.records()),
        BootState::Stopped(StopReason::Unrecognized)
    );
    let mut by_the_kernel = stop_record(StopReason::Operator);
    by_the_kernel.event_type = types::KERNEL_RESUMED;
    by_the_kernel.payload_inline = None;
    let mut by_a_human = by_the_kernel.clone();
    by_a_human.actor = Actor::Human;
    world.append(vec![by_the_kernel]);
    assert_eq!(
        boot_state(&world.records()),
        BootState::Stopped(StopReason::Unrecognized),
        "a resume by a non-human actor booted the kernel running"
    );
    world.append(vec![by_a_human]);
    assert_eq!(boot_state(&world.records()), BootState::Running);
    world.append(vec![bare]);
    assert_eq!(
        boot_state(&world.records()),
        BootState::Stopped(StopReason::Unrecognized)
    );
}

// ── Admission ──────────────────────────────────────────────────────────────────────────

#[test]
fn admission_counts_bytes_in_flight() {
    let admission = Admission::new(limits(64, 10 * MIB), Stop::running());
    let first = admission.admit(6 * MIB).unwrap();
    let second = admission.admit(6 * MIB);
    assert_eq!(
        second.map(|_| ()).map_err(|r| r.reason),
        Err(RefusalReason::Bytes),
        "admission counted requests, not bytes"
    );
    let third = admission.admit(4 * MIB).unwrap();
    assert_eq!(admission.in_flight(), (2, 10 * MIB));
    drop((first, third));
    assert_eq!(admission.in_flight(), (0, 0));
}

#[test]
fn a_permit_grows_only_inside_the_bound() {
    let admission = Admission::new(limits(64, 10 * MIB), Stop::running());
    let mut permit = admission.admit(4 * MIB).unwrap();
    let other = admission.admit(4 * MIB).unwrap();
    permit.charge(MIB).unwrap();
    let refused = permit.charge(2 * MIB).unwrap_err();
    assert_eq!(refused.reason, RefusalReason::Bytes);
    assert_eq!(refused.code, codes::RUNTIME_OVERLOAD);
    assert_eq!(permit.bytes(), 5 * MIB, "a refused charge was charged");
    assert_eq!(admission.in_flight(), (2, 9 * MIB));
    let alone = permit.charge(6 * MIB).unwrap_err();
    assert_eq!(
        alone.reason,
        RefusalReason::TooLarge,
        "a charge that can never fit was told to retry"
    );
    drop((permit, other));
    assert_eq!(admission.in_flight(), (0, 0), "a dropped permit kept its bytes");
}

#[test]
fn a_request_that_can_never_fit_is_not_told_to_retry() {
    // Past the bytes bound on its own, a request is refused for good.
    let admission = Admission::new(limits(64, 10 * MIB), Stop::running());
    let refusal = admission.admit(11 * MIB).unwrap_err();
    assert_eq!(
        (refusal.reason, refusal.code, refusal.retry_after),
        (RefusalReason::TooLarge, codes::INGRESS_TOO_LARGE, Duration::ZERO),
        "a request that can never fit was told to retry"
    );
    assert_eq!(admission.in_flight(), (0, 0));
}

#[test]
fn admission_bounds_operations_too() {
    let admission = Admission::new(limits(2, u64::MAX), Stop::running());
    let held = (admission.admit(0).unwrap(), admission.admit(0).unwrap());
    let refusal = admission.admit(0).unwrap_err();
    assert_eq!(refusal.reason, RefusalReason::Operations);
    assert_eq!(refusal.retry_after, Duration::from_secs(1));
    drop(held);
    assert!(admission.admit(u64::MAX).is_ok());
}

// ── The configuration snapshot ─────────────────────────────────────────────────────────

fn snapshot(version: u64, locale: &str) -> ConfigSnapshot {
    ConfigSnapshot::new(ConfigVersion(version), LocaleTag::new(locale).unwrap())
}

#[test]
fn a_pin_survives_a_publish_and_versions_only_grow() {
    let cell = ConfigCell::new(snapshot(1, "en"));
    let pinned = cell.pin();
    cell.publish(snapshot(2, "tr")).unwrap();
    assert_eq!(pinned.locale().as_str(), "en", "a publish changed a pinned snapshot");
    assert_eq!(cell.pin().locale().as_str(), "tr");
    assert_eq!(
        cell.publish(snapshot(2, "de")),
        Err(ConfigError::NotNewer {
            current: ConfigVersion(2),
            offered: ConfigVersion(2)
        })
    );
    assert!(cell.publish(snapshot(1, "de")).is_err());
    assert_eq!(cell.pin().version(), ConfigVersion(2));
}

#[test]
fn locale_tags_are_opaque_and_well_formed() {
    for good in [
        "en",
        "tr",
        "de",
        "fr",
        "es",
        "it",
        "ar",
        "en-US",
        "zh-Hant-TW",
        "es-419",
        "EN-us",
        "ast",
    ] {
        let tag = LocaleTag::new(good);
        assert_eq!(tag.map(|t| t.as_str().to_owned()), Ok(good.to_owned()), "{good}");
    }
    let long = "a".repeat(MAX_LOCALE_TAG + 1);
    for bad in [
        "",
        "e",
        "en_US",
        "en-",
        "-en",
        "en--US",
        "1en",
        "en-123456789",
        "en US",
        "tr-\u{131}",
        &long,
    ] {
        assert!(LocaleTag::new(bad).is_err(), "{bad}");
    }
}

// ── Declared pricing ───────────────────────────────────────────────────────────────────

fn code(s: &str) -> Code {
    Code::new(s).unwrap()
}

#[test]
fn a_declared_price_costs_each_dimension() {
    let price = DeclaredPrice::new([
        (code("input_tokens"), NanoUsd::new(100)),
        (code("output_tokens"), NanoUsd::new(1_000)),
    ])
    .unwrap();
    let usage = [(code("input_tokens"), 50), (code("output_tokens"), 100)];
    assert_eq!(price.cost(&usage), Ok(NanoUsd::new(105_000)));
    assert_eq!(price.cost(&[(code("cache_read"), 1)]), Err(PriceError::Unpriced));
    assert_eq!(
        price.cost(&[(code("output_tokens"), u64::MAX)]),
        Err(PriceError::Overflow)
    );
    let half = u64::try_from(i64::MAX / 1_000).unwrap();
    assert_eq!(
        price.cost(&[(code("output_tokens"), half), (code("input_tokens"), half)]),
        Err(PriceError::Overflow)
    );
    // A free dimension is free whatever its count.
    let free = DeclaredPrice::new([
        (code("cache_read"), NanoUsd::ZERO),
        (code("output_tokens"), NanoUsd::new(1)),
    ])
    .unwrap();
    assert_eq!(
        free.cost(&[(code("cache_read"), u64::MAX), (code("output_tokens"), 2)]),
        Ok(NanoUsd::new(2))
    );
}

#[test]
fn a_declared_price_refuses_negative_and_repeated_prices() {
    assert_eq!(
        DeclaredPrice::new([(code("output_tokens"), NanoUsd::new(-1))]),
        Err(PriceError::Invalid)
    );
    assert_eq!(
        DeclaredPrice::new([
            (code("output_tokens"), NanoUsd::new(1)),
            (code("output_tokens"), NanoUsd::new(2))
        ]),
        Err(PriceError::Invalid)
    );
}

// ── The supervisor ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_supervisor_refuses_past_its_bound_and_frees_finished_slots() {
    let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits { max_tasks: 2 });
    let (release, wait) = tokio::sync::oneshot::channel::<()>();
    let held = supervisor
        .spawn(async move {
            let _released = wait.await;
        })
        .unwrap();
    let quick = supervisor.spawn(async { 7 }).unwrap();
    assert_eq!(quick.await.unwrap(), 7);
    // The finished task's slot frees as its future is dropped.
    tokio::time::timeout(Duration::from_secs(5), async {
        while supervisor.live() > 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let again = supervisor.spawn(async {}).unwrap();
    again.await.unwrap();
    let (block, never) = tokio::sync::oneshot::channel::<()>();
    let second = supervisor
        .spawn(async move {
            let _never = never.await;
        })
        .unwrap();
    assert_eq!(supervisor.spawn(async {}).err(), Some(SpawnError::Full));
    assert_eq!(supervisor.refused(), 1);
    release.send(()).unwrap();
    block.send(()).unwrap();
    held.await.unwrap();
    second.await.unwrap();
}

#[tokio::test]
async fn the_supervisor_runs_hyper_executor_tasks() {
    use hyper::rt::Executor as _;
    let supervisor = Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default());
    let (done, ran) = tokio::sync::oneshot::channel();
    supervisor.execute(async move {
        let _sent = done.send(());
    });
    assert!(
        tokio::time::timeout(Duration::from_secs(5), ran).await.is_ok(),
        "the executor did not run the task"
    );
}
