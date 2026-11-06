// SPDX-License-Identifier: Apache-2.0

//! Journal durability, recovery and integrity, proven under deterministic crash simulation.
//!
//! Scenario tests pin each failure mode down; the property test at the end drives random sequences
//! of appends, flushes, crashes, power losses, failed flushes and disk-full episodes against a
//! model of what was acknowledged, and checks guarantees after every recovery.
//!
//! * after a **process crash**, every acknowledged record is present, unchanged;
//! * after a **power loss**, every acknowledged record up to the flushed boundary is present,
//!   unchanged, and nothing present contradicts an acknowledgement;
//! * the chain always verifies.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use proptest::prelude::*;
use uaos_contracts::digest::Sha256Digest;
use uaos_contracts::event::{Actor, Durability, Metadata, types};
use uaos_contracts::id::{CorrelationId, TypedId};
use uaos_contracts::limits::Millis;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::ConfigVersion;
use uaos_platform::crypto::sha256;
use uaos_platform::fs::Fs;
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, Rng};
use uaos_state::journal::manifest::{Manifest, SegmentStatus};
use uaos_state::journal::{
    EventDraft, FLUSH_MARKER, FlushPolicy, JOURNAL_DIR, Journal, JournalError, JournalHealth, OpenEvidence, SEAL_FILE,
    read_verified, verify,
};

const DATA: &str = "/data";

struct World {
    fs: SimFs,
    clock: Arc<SimClock>,
    rng: Arc<SimRng>,
    data: PathBuf,
}

impl World {
    fn new(seed: u64) -> Self {
        let fs = SimFs::new();
        fs.create_dir_all(Path::new(DATA)).unwrap();
        let clock = Arc::new(SimClock::new(
            WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
        ));
        Self {
            fs,
            clock,
            rng: Arc::new(SimRng::new(seed)),
            data: PathBuf::from(DATA),
        }
    }

    fn open(&self, flush: FlushPolicy) -> Result<Journal, JournalError> {
        let clock: Arc<dyn Clock> = self.clock.clone();
        let rng: Arc<dyn Rng> = self.rng.clone();
        Journal::open(Arc::new(self.fs.clone()), clock, rng, &self.data, flush)
    }

    fn dir(&self) -> PathBuf {
        self.data.join(JOURNAL_DIR)
    }

    fn records(&self) -> Vec<(u64, Sha256Digest)> {
        read_verified(&self.fs, &self.dir())
            .unwrap()
            .0
            .iter()
            .map(|r| (r.envelope.seq.0, r.hash))
            .collect()
    }
}

/// Balanced with a window no test clock reaches unless advanced on purpose.
const LAZY: FlushPolicy = FlushPolicy::Balanced { window: Millis(60_000) };

fn draft(n: u64) -> EventDraft {
    EventDraft {
        session_id: None,
        pocket_id: None,
        operation_id: None,
        request_id: None,
        agent_id: None,
        correlation_id: CorrelationId::from_parts(n, [7; 10]),
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

/// The flush deadline belongs to the oldest record not yet flushed, not to the newest. A later
/// append must not push it back: a record acknowledged at 0 and another at 0.9 W leave the first
/// due at W, not at 1.9 W.
#[test]
fn the_flush_deadline_follows_the_oldest_unflushed_record() {
    let w = World::new(3);
    let window = Millis(50);
    let mut j = w.open(FlushPolicy::Balanced { window }).unwrap();
    assert_eq!(
        j.flush_deadline(),
        None,
        "a journal with nothing unflushed has a deadline"
    );
    let first = w.clock.mono().0;
    j.append(draft(1)).unwrap();
    w.clock.advance(window.as_nanos() * 9 / 10);
    j.append(draft(2)).unwrap();
    assert!(
        j.flushed_through().is_none(),
        "the journal flushed inside the window on its own"
    );
    assert_eq!(
        j.flush_deadline(),
        Some(first + window.as_nanos()),
        "a later append moved the deadline of the oldest unflushed record"
    );
    assert_eq!(j.unflushed_since(), Some(first));
    j.sync().unwrap();
    assert_eq!(j.flush_deadline(), None);
    assert_eq!(j.unflushed_since(), None);
}

#[test]
fn appends_form_a_chain_verifiable_over_exact_bytes() {
    let w = World::new(1);
    let mut j = w.open(LAZY).unwrap();
    let acks: Vec<_> = (0..5).map(|i| j.append(draft(i)).unwrap()).collect();
    assert_eq!(acks.iter().map(|a| a.seq.0).collect::<Vec<_>>(), [0, 1, 2, 3, 4]);

    // Recompute the chain from the raw segment bytes, as an external auditor would.
    let manifest = Manifest::load(&w.fs, &w.dir()).unwrap();
    let raw =
        w.fs.read(&w.dir().join(&manifest.segments.last().unwrap().file))
            .unwrap();
    let lines: Vec<&[u8]> = raw.split_inclusive(|&b| b == b'\n').collect();
    assert_eq!(lines.len(), 5);
    for (line, ack) in lines.iter().zip(&acks) {
        assert_eq!(sha256(line), ack.hash);
    }
    let report = verify(&w.fs, &w.dir()).unwrap();
    assert_eq!((report.records, report.next_seq, report.head), (5, 5, acks[4].hash));
}

#[test]
fn one_daemon_per_data_directory() {
    let w = World::new(2);
    let first = w.open(LAZY).unwrap();
    assert_eq!(w.open(LAZY).unwrap_err(), JournalError::InstanceLocked);
    drop(first);
    assert!(w.open(LAZY).is_ok());
}

#[test]
fn process_crash_loses_no_acknowledged_record() {
    let w = World::new(3);
    let mut j = w.open(LAZY).unwrap();
    let acked: Vec<_> = (0..10).map(|i| j.append(draft(i)).unwrap()).collect();
    assert_eq!(
        j.flushed_through(),
        None,
        "nothing was flushed: only the OS holds the records"
    );
    w.fs.crash();
    drop(j);

    let mut j = w.open(LAZY).unwrap();
    let recovered = w.records();
    assert_eq!(recovered, acked.iter().map(|a| (a.seq.0, a.hash)).collect::<Vec<_>>());
    assert_eq!(
        j.append(draft(99)).unwrap().seq.0,
        10,
        "numbering continues after recovery"
    );
    assert!(verify(&w.fs, &w.dir()).is_ok());
}

#[test]
fn power_loss_keeps_exactly_the_flushed_records() {
    let w = World::new(4);
    let mut j = w.open(LAZY).unwrap();
    for i in 0..3 {
        j.append(draft(i)).unwrap();
    }
    j.sync().unwrap();
    for i in 3..5 {
        j.append(draft(i)).unwrap();
    }
    w.fs.power_loss();
    drop(j);

    let mut j = w.open(LAZY).unwrap();
    assert_eq!(w.records().len(), 3);
    assert_eq!(j.append(draft(9)).unwrap().seq.0, 3);
}

#[test]
fn strict_mode_survives_power_loss_for_every_ack() {
    let w = World::new(5);
    let mut j = w.open(FlushPolicy::Strict).unwrap();
    for i in 0..4 {
        j.append(draft(i)).unwrap();
        assert_eq!(j.flushed_through().map(|s| s.0), Some(i));
    }
    w.fs.power_loss();
    drop(j);
    w.open(FlushPolicy::Strict).unwrap();
    assert_eq!(w.records().len(), 4);
}

#[test]
fn balanced_mode_flushes_once_the_window_elapses() {
    let w = World::new(6);
    let mut j = w.open(FlushPolicy::Balanced { window: Millis(50) }).unwrap();
    j.append(draft(0)).unwrap();
    assert_eq!(j.flushed_through(), None);
    w.clock.advance(Millis(50).as_nanos());
    j.append(draft(1)).unwrap();
    assert_eq!(j.flushed_through().map(|s| s.0), Some(1));
}

#[test]
fn failed_flush_is_recovered_by_rewriting_never_by_retrying() {
    let w = World::new(7);
    let mut j = w.open(LAZY).unwrap();
    j.append(draft(0)).unwrap();
    j.sync().unwrap();
    j.append(draft(1)).unwrap();
    j.append(draft(2)).unwrap();
    w.fs.fail_next_sync(); // drops the OS-held copies of records 1 and 2 from the cache
    j.sync().unwrap();
    assert_eq!(j.flushed_through().map(|s| s.0), Some(2));

    let manifest = Manifest::load(&w.fs, &w.dir()).unwrap();
    let statuses: Vec<_> = manifest.segments.iter().map(|s| s.status).collect();
    assert_eq!(statuses, [SegmentStatus::Suspect, SegmentStatus::Active]);

    w.fs.power_loss();
    drop(j);
    w.open(LAZY).unwrap();
    assert_eq!(w.records().len(), 3, "rewritten records are durable");
}

#[test]
fn failed_flush_without_space_fails_closed_until_recovered() {
    let w = World::new(8);
    let mut j = w.open(LAZY).unwrap();
    j.append(draft(0)).unwrap();
    j.sync().unwrap();
    j.append(draft(1)).unwrap();
    w.fs.fail_next_sync();
    w.fs.set_capacity(Some(0));
    assert!(j.sync().is_err());
    assert_eq!(j.health(), JournalHealth::FlushFailed);
    assert_eq!(j.append(draft(2)).unwrap_err(), JournalError::Stopped);
    assert!(j.recover().is_err(), "still no space: recovery keeps failing closed");
    w.fs.set_capacity(None);
    j.recover().unwrap();
    assert_eq!(
        j.flushed_through().map(|s| s.0),
        Some(1),
        "the memory-only record was rewritten"
    );
    w.fs.power_loss();
    drop(j);
    w.open(LAZY).unwrap();
    assert_eq!(w.records().len(), 2, "both records are durable after recovery");
}

#[test]
fn disk_full_fails_closed_and_recovers_without_a_torn_record() {
    let w = World::new(9);
    let mut j = w.open(LAZY).unwrap();
    j.append(draft(0)).unwrap();
    let used =
        w.fs.os_view(&w.dir().join(&Manifest::load(&w.fs, &w.dir()).unwrap().segments[0].file))
            .unwrap()
            .len();
    // Leave room for only part of the next record: it will be torn.
    w.fs.set_capacity(Some(u64::try_from(used).unwrap() + 4096 + 40));
    let mut outcomes = Vec::new();
    for i in 1..200 {
        match j.append(draft(i)) {
            Ok(_) => outcomes.push(true),
            Err(e) => {
                assert_eq!(e, JournalError::DiskFull);
                break;
            }
        }
    }
    let acked = u64::try_from(outcomes.len()).unwrap() + 1;
    assert_eq!(
        j.append(draft(500)).unwrap_err(),
        JournalError::DiskFull,
        "fails closed until recovered"
    );

    w.fs.set_capacity(None);
    j.recover().unwrap();
    let next = j.append(draft(600)).unwrap();
    assert_eq!(
        next.seq.0, acked,
        "no gap and no reuse: the torn record was never acknowledged"
    );
    let report = verify(&w.fs, &w.dir()).unwrap();
    assert_eq!(report.records, acked + 1);
    assert!(report.ignored_tail_bytes > 0, "the torn bytes are excluded, not parsed");
}

#[test]
fn tampering_with_any_record_but_the_last_is_detected() {
    let w = World::new(10);
    let mut j = w.open(LAZY).unwrap();
    for i in 0..6 {
        j.append(draft(i)).unwrap();
    }
    w.fs.crash();
    drop(j);
    let manifest = Manifest::load(&w.fs, &w.dir()).unwrap();
    let seg = w.dir().join(&manifest.segments.last().unwrap().file);
    let raw = w.fs.read(&seg).unwrap();
    // Flip a byte inside the third record's correlation id (still valid JSON).
    let line_start = raw
        .split_inclusive(|&b| b == b'\n')
        .take(2)
        .map(<[u8]>::len)
        .sum::<usize>();
    let field = b"\"correlation_id\":\"cor_";
    let at = line_start + raw[line_start..].windows(field.len()).position(|w| w == field).unwrap() + field.len() + 30;
    let original = raw[at];
    assert!(w.fs.overwrite_byte(&seg, at, if original == b'0' { b'1' } else { b'0' }));
    assert!(matches!(
        verify(&w.fs, &w.dir()),
        Err(JournalError::ChainBroken { seq: 3, .. })
    ));
    // Opening a broken journal refuses and modifies nothing.
    assert!(matches!(w.open(LAZY), Err(JournalError::ChainBroken { .. })));
}

#[test]
fn missing_manifest_with_existing_segments_is_refused() {
    let w = World::new(11);
    let mut j = w.open(LAZY).unwrap();
    j.append(draft(0)).unwrap();
    w.fs.crash();
    drop(j);
    w.fs.remove_file(&Manifest::path(&w.dir())).unwrap();
    assert!(
        matches!(w.open(LAZY), Err(JournalError::Corrupt(_))),
        "a new history started over a journal whose records lost their manifest"
    );
}

/// What a writer killed inside its first open leaves (the kill harness found it, nightly
/// 39330543607): the first segment created, its directory entry flushed, the manifest never
/// stored. Nothing was written, so the next open sets the file aside and starts.
#[test]
fn a_first_open_killed_before_its_manifest_is_stored_starts_cleanly() {
    let w = World::new(13);
    w.fs.create_dir_all(&w.dir()).unwrap();
    let first = w.dir().join("seg-00000000000000000000-000001.jsonl");
    drop(w.fs.open_append(&first).unwrap());
    let mut j = w
        .open(LAZY)
        .unwrap_or_else(|e| panic!("a crashed first open left the journal unopenable: {e}"));
    j.append(draft(0)).unwrap();
    assert_eq!(w.records().len(), 1);
    let names: Vec<String> =
        w.fs.list_dir(&w.dir())
            .unwrap()
            .iter()
            .filter_map(|p| p.file_name()?.to_str().map(str::to_owned))
            .collect();
    assert!(
        names
            .iter()
            .any(|n| n == "seg-00000000000000000000-000001.jsonl.orphan-g0"),
        "the empty segment was not set aside: {names:?}"
    );
}

/// The usual shape of a real history: opened once before any record (the first segment sealed
/// empty), then records in the next segment. Its manifest lost, it is refused, and nothing is
/// renamed (of the first-open fix).
#[test]
fn a_lost_manifest_behind_an_empty_first_segment_is_refused() {
    let w = World::new(15);
    drop(w.open(LAZY).unwrap());
    w.fs.crash();
    let mut j = w.open(LAZY).unwrap();
    j.append(draft(0)).unwrap();
    j.sync().unwrap();
    drop(j);
    w.fs.crash();
    // The marker check is separate; this test is about the segments.
    w.fs.remove_file(&Manifest::path(&w.dir())).unwrap();
    let _marker_gone = w.fs.remove_file(&w.dir().join(FLUSH_MARKER));
    let names = |w: &World| -> Vec<String> {
        let mut names: Vec<String> =
            w.fs.list_dir(&w.dir())
                .unwrap()
                .iter()
                .filter_map(|p| p.file_name()?.to_str().map(str::to_owned))
                .collect();
        names.sort();
        names
    };
    let before = names(&w);
    assert!(
        matches!(w.open(LAZY), Err(JournalError::Corrupt(_))),
        "a new history started over records behind an empty first segment"
    );
    assert_eq!(names(&w), before, "a refused open renamed files");
}

/// Without a manifest, a marker naming a record proves a history existed: refused.
#[test]
fn a_missing_manifest_with_a_recorded_durable_point_is_refused() {
    let w = World::new(16);
    w.fs.create_dir_all(&w.dir()).unwrap();
    let marker = format!("uaos.flushed/1 4 {}\n", "0".repeat(64));
    w.fs.write_atomic(&w.dir().join(FLUSH_MARKER), marker.as_bytes())
        .unwrap();
    assert!(
        matches!(w.open(LAZY), Err(JournalError::Corrupt(_))),
        "a new history started over a recorded durable point"
    );
}

/// One byte in a segment without a manifest is a history, however torn: refused.
#[test]
fn a_missing_manifest_over_any_byte_is_refused() {
    let w = World::new(14);
    w.fs.create_dir_all(&w.dir()).unwrap();
    let torn = w.dir().join("seg-00000000000000000000-000001.jsonl");
    w.fs.open_append(&torn).unwrap().append(b"{").unwrap();
    assert!(
        matches!(w.open(LAZY), Err(JournalError::Corrupt(_))),
        "a new history started over a segment holding bytes"
    );
}

#[test]
fn orphan_segments_are_quarantined_not_reused() {
    let w = World::new(12);
    let j = w.open(LAZY).unwrap();
    w.fs.crash();
    drop(j);
    let orphan = w.dir().join("seg-00000000000000000000-999999.jsonl");
    w.fs.open_append(&orphan)
        .unwrap()
        .append(b"never acknowledged\n")
        .unwrap();
    w.open(LAZY).unwrap();
    let names: Vec<String> =
        w.fs.list_dir(&w.dir())
            .unwrap()
            .iter()
            .filter_map(|p| p.file_name()?.to_str().map(str::to_owned))
            .collect();
    assert!(
        names
            .iter()
            .any(|n| n.starts_with("seg-00000000000000000000-999999.jsonl.orphan"))
    );
    assert!(verify(&w.fs, &w.dir()).is_ok());
}

#[test]
fn errors_map_to_registered_codes() {
    use uaos_contracts::error::codes;
    assert_eq!(JournalError::InstanceLocked.code(), codes::JOURNAL_INSTANCE_LOCKED);
    assert_eq!(JournalError::DiskFull.code(), codes::JOURNAL_DISK_FULL);
    assert_eq!(JournalError::Stopped.code(), codes::JOURNAL_FSYNC_FAILED);
}

// ── Deterministic simulation ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Op {
    Append,
    Sync,
    AdvanceClock(u64),
    Crash,
    PowerLoss,
    FailNextSync,
    FillDisk(u16),
    FreeDiskAndRecover,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        8 => Just(Op::Append),
        2 => Just(Op::Sync),
        2 => (0u64..80).prop_map(Op::AdvanceClock),
        1 => Just(Op::Crash),
        1 => Just(Op::PowerLoss),
        1 => Just(Op::FailNextSync),
        1 => (0u16..2048).prop_map(Op::FillDisk),
        1 => Just(Op::FreeDiskAndRecover),
    ]
}

/// Reopens after a crash or power loss and checks the guarantees against the model.
fn reopen_and_check(
    w: &World,
    policy: FlushPolicy,
    acked: &mut BTreeMap<u64, Sha256Digest>,
    must_survive_through: Option<u64>,
) -> Result<Journal, TestCaseError> {
    w.fs.set_capacity(None);
    // A flush fault injected before the crash may fire during startup. Opening must then fail
    // closed (never start non-durably) AND leave the journal recoverable: the retry must succeed.
    let j = match w.open(policy) {
        Ok(j) => j,
        Err(JournalError::Storage(_) | JournalError::Stopped) => w
            .open(policy)
            .map_err(|e| TestCaseError::fail(format!("journal unrecoverable after a failed open: {e}")))?,
        Err(e) => return Err(TestCaseError::fail(format!("reopen failed: {e}"))),
    };
    let present: BTreeMap<u64, Sha256Digest> = w.records().into_iter().collect();
    for (seq, hash) in acked.iter() {
        match present.get(seq) {
            Some(h) => prop_assert_eq!(h, hash, "record {} changed", seq),
            None => prop_assert!(
                must_survive_through.is_none_or(|limit| *seq > limit),
                "acknowledged record {} lost (guaranteed through {:?})",
                seq,
                must_survive_through
            ),
        }
    }
    // Records beyond the recovered head are gone; their numbers will be reused.
    let next = j.next_seq().0;
    acked.retain(|seq, _| *seq < next);
    Ok(j)
}

/// What a process crash must preserve: every acknowledged record, except while a failed flush
/// could not be rewritten — then only flushed records (the rest exist only in memory).
fn crash_guarantee(j: &Journal, acked: &BTreeMap<u64, Sha256Digest>) -> Option<u64> {
    if j.health() == JournalHealth::FlushFailed {
        j.flushed_through().map(|s| s.0)
    } else {
        acked.keys().next_back().copied()
    }
}

fn run_simulation(seed: u64, policy: FlushPolicy, ops: &[Op]) -> Result<(), TestCaseError> {
    let w = World::new(seed);
    let mut j = w.open(policy).unwrap();
    let mut acked: BTreeMap<u64, Sha256Digest> = BTreeMap::new();
    for (n, op) in ops.iter().enumerate() {
        match op {
            Op::Append => {
                if let Ok(a) = j.append(draft(u64::try_from(n).unwrap())) {
                    acked.insert(a.seq.0, a.hash);
                }
            }
            Op::Sync => {
                let _outcome = j.sync();
            }
            Op::AdvanceClock(ms) => w.clock.advance(Millis(*ms).as_nanos()),
            Op::Crash => {
                let guaranteed = crash_guarantee(&j, &acked);
                w.fs.crash();
                drop(j);
                j = reopen_and_check(&w, policy, &mut acked, guaranteed)?;
            }
            Op::PowerLoss => {
                let durable = j.flushed_through().map(|s| s.0);
                w.fs.power_loss();
                drop(j);
                j = reopen_and_check(&w, policy, &mut acked, durable)?;
            }
            Op::FailNextSync => w.fs.fail_next_sync(),
            Op::FillDisk(slack) => {
                let used: usize =
                    w.fs.list_dir(&w.dir())
                        .unwrap()
                        .iter()
                        .filter_map(|p| w.fs.os_view(p))
                        .map(|v| v.len())
                        .sum();
                w.fs.set_capacity(Some(u64::try_from(used).unwrap() + u64::from(*slack)));
            }
            Op::FreeDiskAndRecover => {
                w.fs.set_capacity(None);
                let _outcome = j.recover();
            }
        }
    }
    // Final check: a crash now must lose nothing guaranteed.
    let guaranteed = crash_guarantee(&j, &acked);
    w.fs.crash();
    drop(j);
    let _j = reopen_and_check(&w, policy, &mut acked, guaranteed)?;
    prop_assert!(verify(&w.fs, &w.dir()).is_ok());
    Ok(())
}

/// Scenarios per simulation: 256 on every merge; nightly runs set `UAOS_SIM_CASES` (deep seed
/// sweeps nightly).
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
    fn simulation_balanced(seed in any::<u64>(), ops in prop::collection::vec(op(), 1..120)) {
        run_simulation(seed, FlushPolicy::Balanced { window: Millis(50) }, &ops)?;
    }

    #[test]
    fn simulation_strict(seed in any::<u64>(), ops in prop::collection::vec(op(), 1..120)) {
        run_simulation(seed, FlushPolicy::Strict, &ops)?;
    }
}

impl World {
    /// What the next open reports about a clean end's seal.
    fn sealed(&self) -> OpenEvidence {
        let clock: Arc<dyn Clock> = self.clock.clone();
        let rng: Arc<dyn Rng> = self.rng.clone();
        let opened = Journal::open_verified(Arc::new(self.fs.clone()), clock, rng, &self.data, LAZY).unwrap();
        opened.evidence
    }
}

/// The seal: a sealed journal reports the record the seal names; a seal that names a record with
/// another hash, a record that does not exist, or that is torn, reports nothing.
#[test]
fn only_a_seal_naming_a_record_with_its_hash_counts() {
    let w = World::new(21);
    let mut j = w.open(LAZY).unwrap();
    j.append(draft(1)).unwrap();
    let last = j.append(draft(2)).unwrap();
    assert_eq!(j.seal().unwrap(), last.seq);
    drop(j);
    w.fs.crash();
    assert_eq!(w.sealed().sealed, Some(last.seq));
    // The next open reported it; the file is unchanged, so each variant below is read afresh.
    let path = w.dir().join(SEAL_FILE);
    let good = String::from_utf8(w.fs.read(&path).unwrap()).unwrap();
    let other_hash = format!("uaos.sealed/1 {} {}\n", last.seq.0, sha256(b"another record"));
    let missing = good.replacen(&format!(" {} ", last.seq.0), " 99 ", 1);
    let torn = good.trim_end().to_owned();
    for (case, text) in [
        ("another hash", other_hash),
        ("a missing record", missing),
        ("a torn file", torn),
    ] {
        w.fs.write_atomic(&path, text.as_bytes()).unwrap();
        assert_eq!(w.sealed().sealed, None, "a seal naming {case} was trusted");
    }
}

/// A seal whose write failed after its rename (the directory flush failed) is removed again, so a
/// shutdown that reported failure leaves no seal.
#[test]
fn a_seal_whose_write_failed_is_removed() {
    let w = World::new(22);
    let mut j = w.open(LAZY).unwrap();
    j.append(draft(1)).unwrap();
    j.sync().unwrap();
    // The seal's temporary flushes; the directory flush after the rename fails.
    w.fs.fail_sync_after(1);
    assert!(j.seal().is_err(), "the scenario's seal did not fail");
    drop(j);
    w.fs.crash();
    assert_eq!(w.sealed().sealed, None, "a seal whose write failed was left behind");
}

/// A journal with nothing flushed has no record to seal.
#[test]
fn an_empty_journal_cannot_be_sealed() {
    let w = World::new(23);
    let mut j = w.open(LAZY).unwrap();
    assert_eq!(j.seal(), Err(JournalError::Stopped));
}
