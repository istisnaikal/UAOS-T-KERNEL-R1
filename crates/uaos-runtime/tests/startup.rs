// SPDX-License-Identifier: Apache-2.0

//! The startup sequence and the clean shutdown: P7 and P8. Everything runs on a simulated disk and
//! clock; the actor runs on its own thread as it does in a kernel.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test: a failed fixture fails the test"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;

use uaos_contracts::error::codes;
use uaos_contracts::event::{Actor, Durability, EventEnvelope, EventType, InlinePayload, Metadata, types};
use uaos_contracts::id::{CorrelationId, OperationId, PocketId, TypedId};
use uaos_contracts::limits::Millis;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::ConfigVersion;
use uaos_platform::fs::{AppendFile, Fs, FsError, LockGuard};
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, Rng};
use uaos_runtime::{
    Admission, AdmissionLimits, BootState, ConfigSnapshot, DEFAULT_QUEUE_CAPACITY, EngagedBy, JournalSource, LastEnd,
    LocaleTag, RefusalReason, Started, StateError, Stop, StopReason, Supervisor, SupervisorLimits, shut_down,
    start_kernel,
};
use uaos_state::chunks::ChunkStore;
use uaos_state::chunks::keyring::MemoryKeyring;
use uaos_state::journal::{EventDraft, FlushPolicy, JOURNAL_DIR, Journal, SEAL_FILE, read_verified};

const DATA: &str = "/data";
/// A window no test reaches: only the shutdown's own flushes and explicit syncs flush.
const LAZY: Millis = Millis(60_000);

/// A kernel's data directory on a simulated disk and clock.
struct World {
    fs: SimFs,
    clock: Arc<SimClock>,
    rng: Arc<SimRng>,
    keys: Arc<MemoryKeyring>,
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
            keys: Arc::new(MemoryKeyring::new(Arc::new(SimRng::new(12)))),
        }
    }

    /// The journal and its chunk store, on `fs`.
    fn source(&self, fs: Arc<dyn Fs>) -> JournalSource {
        let rng: Arc<dyn Rng> = self.rng.clone();
        let store = ChunkStore::open(Arc::clone(&fs), Arc::clone(&rng), self.keys.clone(), Path::new(DATA)).unwrap();
        let clock: Arc<dyn Clock> = self.clock.clone();
        JournalSource::new(
            fs,
            clock,
            rng,
            PathBuf::from(DATA),
            FlushPolicy::Balanced { window: LAZY },
            Arc::new(store),
        )
    }

    fn start(&self, supervisor: &Supervisor) -> Started {
        start_kernel(
            self.source(Arc::new(self.fs.clone())),
            &config(),
            correlation(),
            supervisor,
            DEFAULT_QUEUE_CAPACITY,
        )
        .unwrap()
    }

    /// The journal opened directly, as a process older than shutdown records, or one that
    /// crashed in its boot, would write it.
    fn open_directly(&self) -> Journal {
        let source = self.source(Arc::new(self.fs.clone()));
        Journal::open_with_payloads(
            source.fs,
            source.clock,
            source.rng,
            &source.data_dir,
            source.flush,
            source.payloads,
        )
        .unwrap()
        .journal
    }

    /// The records a read finds now.
    fn records(&self) -> Vec<EventEnvelope> {
        read_verified(&self.fs, &Path::new(DATA).join(JOURNAL_DIR))
            .unwrap()
            .0
            .into_iter()
            .map(|r| r.envelope)
            .collect()
    }
}

fn config() -> ConfigSnapshot {
    ConfigSnapshot::new(ConfigVersion(1), LocaleTag::new("en").unwrap())
}

fn correlation() -> CorrelationId {
    CorrelationId::from_parts(3, [3; 10])
}

fn supervisor() -> Supervisor {
    Supervisor::new(tokio::runtime::Handle::current(), SupervisorLimits::default())
}

/// An operator, as a human asks for the shutdown.
fn operator() -> EngagedBy {
    EngagedBy {
        actor: Actor::Human,
        correlation_id: CorrelationId::from_parts(7, [7; 10]),
        config_version: ConfigVersion(1),
    }
}

/// A record of `event_type`, as the system writes it.
fn draft(event_type: EventType, operation: Option<OperationId>, payload: Option<serde_json::Value>) -> EventDraft {
    EventDraft {
        session_id: None,
        pocket_id: None,
        operation_id: operation,
        request_id: None,
        agent_id: None,
        correlation_id: correlation(),
        parent_id: None,
        actor: Actor::System,
        event_type,
        payload_ref: None,
        payload_inline: payload.map(|p| InlinePayload::new(p).unwrap()),
        cost_estimate: None,
        compensable: false,
        side_effect_class: SideEffectClass::None,
        risk_tier: RiskTier::MIN,
        durability: Durability::Critical,
        config_version: ConfigVersion(1),
        metadata: Metadata::default(),
    }
}

fn payload(record: &EventEnvelope) -> &serde_json::Value {
    record.payload_inline.as_ref().unwrap().as_value()
}

/// The last `kernel.booted` record.
fn last_boot(records: &[EventEnvelope]) -> &EventEnvelope {
    records
        .iter()
        .rfind(|r| r.event_type == types::KERNEL_BOOTED)
        .expect("no boot record")
}

/// P7: a clean shutdown closes admission, waits for the Operation still running, writes and
/// flushes `kernel.shutdown`, and ends the actor. The next boot runs, says the last run ended
/// clean, and says no stop was lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clean_shutdown_boots_running() {
    let world = World::new();
    let supervisor = supervisor();
    let first = world.start(&supervisor);
    assert_eq!(
        first.report.last_end,
        LastEnd::Unknown,
        "an empty journal was read as more than unknown"
    );
    assert_eq!(
        payload(last_boot(&world.records()))["shutdown_record"],
        serde_json::json!(true),
        "the boot record does not say this run journals its shutdown"
    );

    // An Operation is running when the shutdown begins; it appends its record 30 ms later and
    // ends.
    let admission = Admission::new(AdmissionLimits::default(), first.stop.clone());
    let permit = admission.admit(1).unwrap();
    let state = first.state.clone();
    let operation = supervisor
        .spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            let appended = state
                .append(draft(
                    types::OP_COMMITTED,
                    Some(OperationId::from_parts(1, [1; 10])),
                    None,
                ))
                .await;
            drop(permit);
            appended
        })
        .unwrap();
    let (report, refused) = tokio::join!(
        shut_down(&admission, &first.state, None, operator(), Duration::from_secs(10)),
        async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            admission.admit(1).err()
        }
    );
    let report = report.unwrap();
    let refused = refused.expect("admission stayed open during the shutdown");
    assert_eq!(refused.reason, RefusalReason::Draining);
    assert_eq!(refused.code, codes::RUNTIME_DRAINING);
    let records = world.records();
    let last = records.last().unwrap();
    assert_eq!(last.event_type, types::KERNEL_SHUTDOWN);
    assert_eq!(last.seq, report.record);
    assert_eq!(
        payload(last),
        &serde_json::json!({"clean": true, "open_operations": "0"}),
        "the shutdown record went ahead of an Operation still running"
    );
    assert_eq!(
        last.actor,
        Actor::Human,
        "the shutdown was not journaled as the one who asked"
    );
    assert_eq!(last.risk_tier, RiskTier::MIN);
    let finished = operation.await.unwrap().unwrap();
    assert!(
        finished.seq < report.record,
        "the Operation's record came after the shutdown's"
    );
    assert_eq!(
        report.flushed_through,
        Some(report.record),
        "the shutdown record was not flushed"
    );
    // After its shutdown the actor serves nothing: a command is refused, before it is queued
    // (`NotQueued`) or after, when it was queued as the actor ended (`Closed`); either way it is
    // never written. Checked before the join, so a regression fails here instead of hanging there
    // (of E4).
    let refused = first.state.append(draft(types::OP_COMMITTED, None, None)).await;
    assert!(
        matches!(refused, Err(StateError::NotQueued | StateError::Closed)),
        "the actor kept serving after its shutdown: {refused:?}"
    );
    let exit = first.actor.join().unwrap();
    assert_eq!(exit.flushed_through, Some(report.record));

    // The shutdown record survives a power loss, and the next boot runs.
    world.fs.power_loss();
    the_next_boot_runs_clean(&world, &supervisor);
}

/// After a clean shutdown and a power loss, the shutdown record is still there, and the next
/// boot runs, reads the end as clean, says no stop was lost, and does not surface.
fn the_next_boot_runs_clean(world: &World, supervisor: &Supervisor) {
    assert_eq!(world.records().last().unwrap().event_type, types::KERNEL_SHUTDOWN);
    let second = world.start(supervisor);
    assert_eq!(
        second.report.stop,
        BootState::Running,
        "a clean shutdown booted stopped"
    );
    assert!(!second.stop.is_engaged());
    assert_eq!(
        second.report.last_end,
        LastEnd::Clean,
        "a durable shutdown was not read as clean"
    );
    assert!(!second.report.stop_may_be_lost, "a clean shutdown was read as a crash");
    let booted = world.records();
    let booted = last_boot(&booted);
    assert_eq!(payload(booted)["last_end"], serde_json::json!("clean"));
    assert_eq!(
        booted.risk_tier,
        RiskTier::MIN,
        "a boot after a clean shutdown surfaced"
    );
    drop(second.state);
    second.actor.join().unwrap();
}

/// P7: once a boot has said it journals its shutdown, a journal that does not end with one is a
/// crash, even with nothing left open; a stop engaged before it may have been lost. A record
/// after the shutdown, which only a boot interrupted before its own record leaves, is a crash
/// too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_after_a_shutdown_capable_boot_is_evidence() {
    let world = World::new();
    let supervisor = supervisor();
    let first = world.start(&supervisor);
    first
        .state
        .append(draft(types::OP_COMMITTED, None, None))
        .await
        .unwrap();
    first.state.sync().await.unwrap();
    // The process dies without a shutdown: nothing is open, so the old evidence sees nothing.
    drop(first.state);
    first.actor.join().unwrap();
    world.fs.crash();

    let second = world.start(&supervisor);
    assert_eq!(second.report.last_end, LastEnd::Crashed);
    assert!(
        second.report.stop_may_be_lost,
        "a crash with nothing open was read as a clean exit"
    );
    let records = world.records();
    let booted = last_boot(&records);
    assert_eq!(payload(booted)["last_end"], serde_json::json!("crash"));
    assert_eq!(payload(booted)["stop_may_be_lost"], serde_json::json!(true));
    assert_eq!(booted.risk_tier, RiskTier::MAX, "a boot after a crash did not surface");

    // A clean shutdown, then a record after it: a later boot ended before its own record.
    let admission = Admission::new(AdmissionLimits::default(), second.stop.clone());
    shut_down(&admission, &second.state, None, operator(), Duration::from_secs(10))
        .await
        .unwrap();
    second.actor.join().unwrap();
    let mut journal = world.open_directly();
    journal
        .append(draft(
            types::OP_INDETERMINATE,
            Some(OperationId::from_parts(2, [2; 10])),
            None,
        ))
        .unwrap();
    journal.sync().unwrap();
    drop(journal);

    let third = world.start(&supervisor);
    assert_eq!(third.report.stop, BootState::Running);
    assert_eq!(
        third.report.last_end,
        LastEnd::Crashed,
        "a shutdown followed by an interrupted boot was read as clean"
    );
    assert!(third.report.stop_may_be_lost);
    drop(third.state);
    third.actor.join().unwrap();
}

/// P7: a journal written before shutdown records existed is "unknown", never clean, and a
/// missing shutdown on it is no evidence of a crash: no false crash on the first boot after the
/// upgrade. Work left open stays evidence, as before. After the upgrade, the last boot record
/// decides: the first crash of the upgraded kernel is evidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_old_journal_is_unknown() {
    let world = World::new();
    // An older kernel booted (its record has no `shutdown_record`), wrote, and exited.
    let mut journal = world.open_directly();
    let old_boot = serde_json::json!({
        "records": "0", "indeterminate": "0", "settled_estimated": "0", "completed": "0",
        "transfers_completed": "0", "stuck": "0", "stopped": false, "stop_may_be_lost": false,
        "config_version": "1",
    });
    journal
        .append(draft(types::KERNEL_BOOTED, None, Some(old_boot)))
        .unwrap();
    journal.append(draft(types::OP_COMMITTED, None, None)).unwrap();
    journal.sync().unwrap();
    drop(journal);

    let supervisor = supervisor();
    let first = world.start(&supervisor);
    assert_eq!(
        first.report.last_end,
        LastEnd::Unknown,
        "a missing shutdown on an old journal was trusted as evidence"
    );
    assert!(
        !first.report.stop_may_be_lost,
        "a missing shutdown on an old journal was read as a crash"
    );
    let records = world.records();
    assert_eq!(payload(last_boot(&records))["last_end"], serde_json::json!("unknown"));
    // The upgraded kernel now crashes with nothing open. Its own boot record, the last one, said
    // it journals its shutdown; the older one before it did not. The last boot decides.
    drop(first.state);
    first.actor.join().unwrap();
    world.fs.crash();
    let second = world.start(&supervisor);
    assert_eq!(
        second.report.last_end,
        LastEnd::Crashed,
        "the end of the run was read from an older boot than the last"
    );
    assert!(second.report.stop_may_be_lost);
    drop(second.state);
    second.actor.join().unwrap();
}

/// P7: an Operation still open at the deadline is counted in the shutdown record, which then
/// surfaces, and the next boot says a stop may have been lost: the Operation ran past the record.
/// Cutting it as a stop does lands with the pipeline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn work_left_open_at_the_deadline_is_counted() {
    let world = World::new();
    let supervisor = supervisor();
    let first = world.start(&supervisor);
    let admission = Admission::new(AdmissionLimits::default(), first.stop.clone());
    let permit = admission.admit(1).unwrap();
    let report = shut_down(&admission, &first.state, None, operator(), Duration::from_millis(20))
        .await
        .unwrap();
    let records = world.records();
    let last = records.last().unwrap();
    assert_eq!(last.seq, report.record);
    assert_eq!(payload(last)["open_operations"], serde_json::json!("1"));
    assert_eq!(
        last.risk_tier,
        RiskTier::MAX,
        "work left open at the shutdown did not surface"
    );
    drop(permit);
    first.actor.join().unwrap();

    let second = world.start(&supervisor);
    assert_eq!(second.report.last_end, LastEnd::Clean);
    assert!(
        second.report.stop_may_be_lost,
        "work that ran past the shutdown record was read as a clean end"
    );
    drop(second.state);
    second.actor.join().unwrap();
}

/// The actor keeps the stop boot restored, and records nothing twice: a stop the journal left
/// engaged is already journaled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_booted_stop_is_not_journaled_again() {
    let world = World::new();
    let supervisor = supervisor();
    let first = world.start(&supervisor);
    let _engaged = first.stop.engage(StopReason::Operator, operator());
    first.state.sync().await.unwrap();
    let stopped = |records: &[EventEnvelope]| records.iter().filter(|r| r.event_type == types::KERNEL_STOPPED).count();
    assert_eq!(stopped(&world.records()), 1, "the engaged stop was not journaled");
    let admission = Admission::new(AdmissionLimits::default(), first.stop.clone());
    shut_down(&admission, &first.state, None, operator(), Duration::from_secs(10))
        .await
        .unwrap();
    first.actor.join().unwrap();

    let second = world.start(&supervisor);
    assert_eq!(second.report.stop, BootState::Stopped(StopReason::Operator));
    assert!(second.stop.is_engaged());
    second
        .state
        .append(draft(types::OP_COMMITTED, None, None))
        .await
        .unwrap();
    let admission = Admission::new(AdmissionLimits::default(), second.stop.clone());
    shut_down(&admission, &second.state, None, operator(), Duration::from_secs(10))
        .await
        .unwrap();
    second.actor.join().unwrap();
    assert_eq!(stopped(&world.records()), 1, "a booted stop was journaled again");
}

/// A file system that counts the reads of journal segments.
#[derive(Debug, Clone)]
struct Counting {
    inner: SimFs,
    segment_reads: Arc<AtomicUsize>,
}

impl Fs for Counting {
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        self.inner.create_dir_all(path)
    }
    fn open_append(&self, path: &Path) -> Result<Box<dyn AppendFile>, FsError> {
        self.inner.open_append(path)
    }
    fn read(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        let segment = path.parent().and_then(Path::file_name) == Some(JOURNAL_DIR.as_ref())
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("seg-"));
        if segment {
            self.segment_reads.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.read(path)
    }
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError> {
        self.inner.list_dir(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        self.inner.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        self.inner.remove_file(path)
    }
    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        self.inner.sync_dir(path)
    }
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        self.inner.write_atomic(path, bytes)
    }
    fn write_unsynced(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        self.inner.write_unsynced(path, bytes)
    }
    fn sync_file(&self, path: &Path) -> Result<(), FsError> {
        self.inner.sync_file(path)
    }
    fn try_lock_exclusive(&self, path: &Path) -> Result<Box<dyn LockGuard>, FsError> {
        self.inner.try_lock_exclusive(path)
    }
}

/// A data directory whose journal holds a few records over two runs, the second cut by a crash
/// with records the OS holds unflushed: the open then also recovers a tail. Built the same way
/// every time.
fn populated() -> World {
    let world = World::new();
    for run in 0..2_u64 {
        let mut journal = world.open_directly();
        for n in 0..3_u64 {
            journal
                .append(draft(
                    types::OP_COMMITTED,
                    Some(OperationId::from_parts(run * 10 + n + 1, [4; 10])),
                    None,
                ))
                .unwrap();
        }
        if run == 0 {
            journal.sync().unwrap();
        }
        drop(journal);
        world.fs.crash();
    }
    world
}

/// P8: startup reads the journal once. It reads the segments exactly as often as opening the
/// journal alone does on the same directory: boot reads nothing again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_reads_the_journal_once() {
    let counted = |world: &World| Counting {
        inner: world.fs.clone(),
        segment_reads: Arc::new(AtomicUsize::new(0)),
    };

    let alone = populated();
    let fs = counted(&alone);
    let source = alone.source(Arc::new(fs.clone()));
    let opened = Journal::open_with_payloads(
        source.fs,
        source.clock,
        source.rng,
        &source.data_dir,
        source.flush,
        source.payloads,
    )
    .unwrap();
    let by_the_open = fs.segment_reads.load(Ordering::SeqCst);
    assert!(by_the_open > 0, "the open read no segment");
    assert_eq!(
        opened.records.len(),
        6,
        "the open handed back other records than the journal holds"
    );
    drop(opened);

    let started = populated();
    let fs = counted(&started);
    let kernel = start_kernel(
        started.source(Arc::new(fs.clone())),
        &config(),
        correlation(),
        &supervisor(),
        DEFAULT_QUEUE_CAPACITY,
    )
    .unwrap();
    assert_eq!(
        fs.segment_reads.load(Ordering::SeqCst),
        by_the_open,
        "startup read the journal again after its open"
    );
    assert_eq!(
        kernel.report.records, 6,
        "boot did not see every record the open verified"
    );
    drop(kernel.state);
    kernel.actor.join().unwrap();
}

/// A file system whose flushes fail while `fail` is set; appended bytes still reach the
/// simulated OS, as after a writeback error on Linux.
#[derive(Debug, Clone)]
struct Flaky {
    inner: SimFs,
    fail: Arc<AtomicBool>,
}

#[derive(Debug)]
struct FlakyFile {
    inner: Box<dyn AppendFile>,
    fail: Arc<AtomicBool>,
}

impl AppendFile for FlakyFile {
    fn append(&mut self, bytes: &[u8]) -> Result<(), FsError> {
        self.inner.append(bytes)
    }
    fn sync_data(&mut self) -> Result<(), FsError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(FsError::SyncFailed { op: "sync_data" });
        }
        self.inner.sync_data()
    }
    fn os_len(&self) -> Result<u64, FsError> {
        self.inner.os_len()
    }
}

impl Flaky {
    fn failing(&self) -> Result<(), FsError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(FsError::SyncFailed { op: "sync" });
        }
        Ok(())
    }
}

impl Fs for Flaky {
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        self.inner.create_dir_all(path)
    }
    fn open_append(&self, path: &Path) -> Result<Box<dyn AppendFile>, FsError> {
        Ok(Box::new(FlakyFile {
            inner: self.inner.open_append(path)?,
            fail: Arc::clone(&self.fail),
        }))
    }
    fn read(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        self.inner.read(path)
    }
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError> {
        self.inner.list_dir(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        self.inner.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        self.inner.remove_file(path)
    }
    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        self.failing()?;
        self.inner.sync_dir(path)
    }
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        self.failing()?;
        self.inner.write_atomic(path, bytes)
    }
    fn write_unsynced(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        self.inner.write_unsynced(path, bytes)
    }
    fn sync_file(&self, path: &Path) -> Result<(), FsError> {
        self.failing()?;
        self.inner.sync_file(path)
    }
    fn try_lock_exclusive(&self, path: &Path) -> Result<Box<dyn LockGuard>, FsError> {
        self.inner.try_lock_exclusive(path)
    }
}

/// A shutdown whose record reached the OS but whose flush failed is not clean. The failing journal
/// engaged the stop, which could not be recorded; the process exits, and the OS still holds the
/// `kernel.shutdown` line. The next boot must read a crash and say a stop may have been lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shutdown_that_failed_to_flush_is_a_crash() {
    let world = World::new();
    let supervisor = supervisor();
    let fail = Arc::new(AtomicBool::new(false));
    let flaky = Flaky {
        inner: world.fs.clone(),
        fail: Arc::clone(&fail),
    };
    let first = start_kernel(
        world.source(Arc::new(flaky)),
        &config(),
        correlation(),
        &supervisor,
        DEFAULT_QUEUE_CAPACITY,
    )
    .unwrap();
    first.state.sync().await.unwrap();
    fail.store(true, Ordering::SeqCst);
    let admission = Admission::new(AdmissionLimits::default(), first.stop.clone());
    let failed = shut_down(&admission, &first.state, None, operator(), Duration::from_secs(1)).await;
    assert!(failed.is_err(), "the scenario's shutdown did not fail");
    assert!(first.stop.is_engaged() && first.stop.unrecorded().is_some());
    // The caller exits, as §6 step 3 allows; the process dies, and the OS keeps its bytes.
    drop(first.state);
    let _exit = first.actor.join().unwrap();
    fail.store(false, Ordering::SeqCst);
    world.fs.crash();
    assert_eq!(
        world.records().last().unwrap().event_type,
        types::KERNEL_SHUTDOWN,
        "the scenario left no shutdown record in the file"
    );

    let second = world.start(&supervisor);
    assert_eq!(
        second.report.last_end,
        LastEnd::Crashed,
        "a shutdown that failed to flush was read as clean"
    );
    assert!(second.report.stop_may_be_lost);
    drop(second.state);
    second.actor.join().unwrap();
}

/// A payload lost between runs, behind a sealed shutdown, leaves the end clean: the seal moved the
/// marker past it, so the next open checks no payload there and writes no record of its own. The
/// rule that the open's own records do not decide the end is proven at boot's level
/// (`only_a_proven_shutdown_is_clean_and_the_opens_own_records_do_not_count`); an open writes such
/// records after a seal only if the marker was held back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_payload_lost_behind_the_seal_leaves_the_end_clean() {
    let world = World::new();
    let supervisor = supervisor();
    let source = world.source(Arc::new(world.fs.clone()));
    let store = Arc::clone(&source.payloads);
    let first = start_kernel(source, &config(), correlation(), &supervisor, DEFAULT_QUEUE_CAPACITY).unwrap();
    let pocket = PocketId::from_parts(5, [5; 10]);
    let chunk = store.put(pocket, b"payload").unwrap();
    let mut with_payload = draft(types::OP_COMMITTED, None, None);
    with_payload.pocket_id = Some(pocket);
    with_payload.payload_ref = Some(chunk);
    first.state.append(with_payload).await.unwrap();
    let admission = Admission::new(AdmissionLimits::default(), first.stop.clone());
    shut_down(&admission, &first.state, None, operator(), Duration::from_secs(1))
        .await
        .unwrap();
    first.actor.join().unwrap();
    drop(store);
    let mut dirs = vec![PathBuf::from(DATA).join("chunks")];
    while let Some(dir) = dirs.pop() {
        for path in world.fs.list_dir(&dir).unwrap_or_default() {
            if path.extension().and_then(|e| e.to_str()) == Some("chunk") {
                world.fs.remove_file(&path).unwrap();
            } else if world.fs.read(&path).is_err() {
                dirs.push(path);
            }
        }
    }
    world.fs.crash();
    let second = world.start(&supervisor);
    assert_eq!(
        second.report.last_end,
        LastEnd::Clean,
        "a payload lost behind the seal made a clean end read as a crash"
    );
    assert!(
        !world.records().iter().any(|r| r.event_type == types::CHUNK_LOST),
        "the open checked a payload the seal's marker covered"
    );
    drop(second.state);
    second.actor.join().unwrap();
}

/// Once the shutdown has counted the Operations in flight, none is admitted that the count missed:
/// an Operation is either counted or refused.
#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the race needs a second thread outside the supervisor"
)]
fn no_operation_slips_past_the_drain_count() {
    let mut slipped = 0_u32;
    for _ in 0..20_000 {
        let admission = Admission::new(AdmissionLimits::default(), Stop::running());
        let counted = Arc::new(AtomicU32::new(u32::MAX));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let racer = {
            let admission = admission.clone();
            let counted = Arc::clone(&counted);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                admission.admit(1).is_ok_and(|permit| {
                    std::thread::yield_now();
                    let seen = counted.load(Ordering::SeqCst);
                    drop(permit);
                    seen == 0
                })
            })
        };
        barrier.wait();
        admission.drain();
        counted.store(admission.in_flight().0, Ordering::SeqCst);
        if racer.join().unwrap() {
            slipped += 1;
        }
    }
    assert_eq!(
        slipped, 0,
        "an Operation was admitted after the shutdown counted none open"
    );
}

/// Starts a kernel on `world`'s data directory whose flushes fail once `fail` is set, and has it
/// shut down while they fail: the shutdown record reaches the OS, its flush fails, and the stop
/// the failure engaged is never recorded. The process then dies.
async fn a_failed_shutdown(world: &World, supervisor: &Supervisor) {
    let fail = Arc::new(AtomicBool::new(false));
    let flaky = Flaky {
        inner: world.fs.clone(),
        fail: Arc::clone(&fail),
    };
    let first = start_kernel(
        world.source(Arc::new(flaky)),
        &config(),
        correlation(),
        supervisor,
        DEFAULT_QUEUE_CAPACITY,
    )
    .unwrap();
    first.state.sync().await.unwrap();
    fail.store(true, Ordering::SeqCst);
    let admission = Admission::new(AdmissionLimits::default(), first.stop.clone());
    let failed = shut_down(&admission, &first.state, None, operator(), Duration::from_secs(1)).await;
    assert!(failed.is_err(), "the scenario's shutdown did not fail");
    assert!(first.stop.is_engaged() && first.stop.unrecorded().is_some());
    drop(first.state);
    let _exit = first.actor.join().unwrap();
    fail.store(false, Ordering::SeqCst);
    world.fs.crash();
}

/// A later process that opens the journal and ends before its own `kernel.booted` (its boot
/// refused, or killed after the open) moves the `FLUSHED` marker onto the failed shutdown's record.
/// That must not prove the shutdown: only a seal does, and no open writes one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_intervening_open_does_not_prove_a_failed_shutdown() {
    for refused in [true, false] {
        let world = World::new();
        let supervisor = supervisor();
        a_failed_shutdown(&world, &supervisor).await;
        if refused {
            let drift = start_kernel(
                world.source(Arc::new(world.fs.clone())),
                &ConfigSnapshot::new(ConfigVersion(0), LocaleTag::new("en").unwrap()),
                correlation(),
                &supervisor,
                DEFAULT_QUEUE_CAPACITY,
            );
            assert!(drift.is_err(), "the scenario's second start was not refused");
        } else {
            drop(world.open_directly());
        }
        world.fs.crash();
        let third = world.start(&supervisor);
        assert_eq!(
            third.report.last_end,
            LastEnd::Crashed,
            "an open after a failed shutdown made it read as clean"
        );
        assert!(third.report.stop_may_be_lost);
        drop(third.state);
        third.actor.join().unwrap();
    }
}

/// The seal goes before anything can run. A run that starts after a clean end and then loses its
/// records to a power loss (its `kernel.booted` was never flushed) must not read as that clean
/// end: whatever it did, a stop included, may be lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_whose_records_were_lost_is_not_read_as_clean() {
    let world = World::new();
    let supervisor = supervisor();
    let first = world.start(&supervisor);
    let admission = Admission::new(AdmissionLimits::default(), first.stop.clone());
    shut_down(&admission, &first.state, None, operator(), Duration::from_secs(1))
        .await
        .unwrap();
    first.actor.join().unwrap();

    // The next run boots on a disk whose flushes then fail, so its boot record is never
    // flushed, and the power fails.
    let fail = Arc::new(AtomicBool::new(false));
    let flaky = Flaky {
        inner: world.fs.clone(),
        fail: Arc::clone(&fail),
    };
    let second = start_kernel(
        world.source(Arc::new(flaky)),
        &config(),
        correlation(),
        &supervisor,
        DEFAULT_QUEUE_CAPACITY,
    )
    .unwrap();
    assert_eq!(second.report.last_end, LastEnd::Clean);
    fail.store(true, Ordering::SeqCst);
    drop(second.state);
    let _exit = second.actor.join().unwrap();
    world.fs.power_loss();
    assert_eq!(
        world.records().last().unwrap().event_type,
        types::KERNEL_SHUTDOWN,
        "the scenario's second run left a record behind"
    );

    let third = world.start(&supervisor);
    assert_eq!(
        third.report.last_end,
        LastEnd::Crashed,
        "a run whose records were lost read as the clean end before it"
    );
    assert!(third.report.stop_may_be_lost);
    drop(third.state);
    third.actor.join().unwrap();
}

/// A file system that lets `budget` changes through, then refuses every change, as if the
/// process had died there. Reads still work: they are what the next process sees.
#[derive(Debug, Clone)]
struct Dying {
    inner: SimFs,
    budget: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct DyingFile {
    inner: Box<dyn AppendFile>,
    budget: Arc<AtomicUsize>,
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
        spend(&self.budget, "append")?;
        self.inner.append(bytes)
    }
    fn sync_data(&mut self) -> Result<(), FsError> {
        spend(&self.budget, "sync_data")?;
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

/// `start_kernel` cut at every change it makes to the disk, across the open, boot's records and the
/// seal's removal, then a crash or a power loss. No cut leaves a false clean end:
/// - a start that got its actor running, or left any record of its own behind, reads as a
///   crash;
/// - a start that failed before the actor, and left no record of its own, reads clean exactly
///   when the seal survived (honest: nothing ran);
/// - and the next start always succeeds, so every cut converges.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_cut_anywhere_never_reads_a_false_clean_end() {
    let seal = Path::new(DATA).join(JOURNAL_DIR).join(SEAL_FILE);
    // The case the seal's removal exists for: the actor ran, its records were lost to the power
    // loss, and only the removed seal keeps the next boot from reading the clean end before it.
    let mut lost_run = false;
    for power in [false, true] {
        for cut in 0_usize.. {
            let world = World::new();
            let supervisor = supervisor();
            let first = world.start(&supervisor);
            let admission = Admission::new(AdmissionLimits::default(), first.stop.clone());
            shut_down(&admission, &first.state, None, operator(), Duration::from_secs(1))
                .await
                .unwrap();
            first.actor.join().unwrap();

            // The second start dies after `cut` changes to the disk.
            let budget = Arc::new(AtomicUsize::new(cut));
            let dying: Arc<dyn Fs> = Arc::new(Dying {
                inner: world.fs.clone(),
                budget: Arc::clone(&budget),
            });
            let rng: Arc<dyn Rng> = world.rng.clone();
            let started = ChunkStore::open(
                Arc::clone(&dying),
                Arc::clone(&rng),
                world.keys.clone(),
                Path::new(DATA),
            )
            .ok()
            .and_then(|store| {
                let clock: Arc<dyn Clock> = world.clock.clone();
                let source = JournalSource::new(
                    dying,
                    clock,
                    rng,
                    PathBuf::from(DATA),
                    FlushPolicy::Balanced { window: LAZY },
                    Arc::new(store),
                );
                start_kernel(source, &config(), correlation(), &supervisor, DEFAULT_QUEUE_CAPACITY).ok()
            });
            let ran = started.is_some();
            let finished = budget.load(Ordering::SeqCst) > 0;
            if let Some(second) = started {
                drop(second.state);
                let _exit = second.actor.join().unwrap();
            }
            if power {
                world.fs.power_loss();
            } else {
                world.fs.crash();
            }
            let wrote = world.records().last().unwrap().event_type != types::KERNEL_SHUTDOWN;
            let sealed = world.fs.read(&seal).is_ok();

            lost_run |= power && ran && !wrote;
            let third = world.start(&supervisor);
            let expected = if ran || wrote || !sealed {
                LastEnd::Crashed
            } else {
                LastEnd::Clean
            };
            assert_eq!(
                third.report.last_end, expected,
                "cut after {cut} changes (power loss: {power}; actor ran: {ran}; a record left: {wrote}; seal left: {sealed}) read the wrong end"
            );
            // And it converges: the next clean end reads clean.
            let admission = Admission::new(AdmissionLimits::default(), third.stop.clone());
            shut_down(&admission, &third.state, None, operator(), Duration::from_secs(1))
                .await
                .unwrap();
            third.actor.join().unwrap();
            let fourth = world.start(&supervisor);
            assert_eq!(
                fourth.report.last_end,
                LastEnd::Clean,
                "cut after {cut} changes did not converge"
            );
            drop(fourth.state);
            fourth.actor.join().unwrap();
            if finished {
                assert!(
                    cut >= 5,
                    "the start made only {cut} changes: the cuts covered too little"
                );
                break;
            }
        }
    }
    assert!(lost_run, "no cut reached a run whose records the power loss took");
}
