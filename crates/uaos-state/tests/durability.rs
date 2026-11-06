// SPDX-License-Identifier: Apache-2.0

//! Chunk payloads join the journal's durability classes, under deterministic crash simulation, plus
//! a chunk race and earlier findings, each as a regression test.
//!
//! Guarantees checked:
//! * **payload before record:** a record that references a chunk not yet stored is refused;
//! * after a **process crash**, every acknowledged record is present and its payload readable,
//!   unless a failed flush dropped it and the loss was journaled;
//! * after a **power loss**, every record up to the flushed boundary is present and its payload
//!   readable, unless that loss was already journaled;
//! * **never silent:** a surviving record whose payload is unreadable has a `chunk.lost` record,
//!   or a later `chunk.shredded` record names its chunk.
//!
//! The simulated disk runs in two modes: a failed flush either drops the unflushed bytes, or
//! (`set_failed_sync_keeps_cache`) keeps serving them while never making them durable, as Linux
//! does after a writeback error.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::disallowed_methods,
    reason = "test harness: fixtures and checks abort on failure; race tests need real threads and time"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use proptest::prelude::*;
use uaos_contracts::digest::ChunkRef;
use uaos_contracts::event::{Actor, Durability, Metadata, types};
use uaos_contracts::id::{AgentId, CorrelationId, PocketId, TypedId};
use uaos_contracts::limits::Millis;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::{ConfigVersion, Seq};
use uaos_platform::fs::{AppendFile, Fs, FsError, LockGuard};
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, Rng};
use uaos_state::chunks::keyring::{KekVersion, KeyringError, MemoryKeyring, PocketKeyring};
use uaos_state::chunks::{
    CHUNKS_DIR, ChunkDurability, ChunkError, ChunkStore, LossCause, MAX_PENDING, MAX_UNFINISHED_SHREDS, QUARANTINE_DIR,
};
use uaos_state::journal::{
    CHUNK_METADATA_KEY, EventDraft, FLUSH_MARKER, FlushPolicy, JOURNAL_DIR, Journal, JournalError, JournalHealth,
    MAX_LOST_LISTED, RECORD_SEQ_METADATA_KEY, VerifiedRecord, read_verified,
};

const DATA: &str = "/data";
/// A window longer than any test, so only explicit `sync` calls flush.
const NEVER: FlushPolicy = FlushPolicy::Balanced {
    window: Millis(u64::MAX / 2),
};

// ── A simulated disk with switches ─────────────────────────────────────────────────────────

/// Holds the first matching operation until released.
#[derive(Debug, Default)]
struct Gate {
    armed: AtomicBool,
    held: AtomicBool,
    open: Mutex<bool>,
    opened: Condvar,
}

impl Gate {
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
    fn hold_if_armed(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.held.store(true, Ordering::SeqCst);
            let mut open = self.open.lock().unwrap();
            while !*open {
                open = self.opened.wait(open).unwrap();
            }
        }
    }
    /// Waits until the gated operation is held; panics if it never runs, so a test cannot hang.
    fn wait_held(&self) {
        for _ in 0..10_000 {
            if self.held.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("the gated operation never ran");
    }
    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.opened.notify_all();
    }
    /// Releases after `ms` from another thread, so a test cannot deadlock on its own gate.
    fn release_after(self: &Arc<Self>, ms: u64) -> std::thread::JoinHandle<()> {
        let gate = Arc::clone(self);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(ms));
            gate.release();
        })
    }
}

#[derive(Debug, Clone)]
struct FaultFs {
    sim: SimFs,
    /// Segment appends let through before the next one fails with `NoSpace`, once.
    segment_append_fault: Arc<Mutex<Option<u32>>>,
    /// The first key-file write.
    key_write: Arc<Gate>,
    /// The first key-file rename (quarantine).
    key_rename: Arc<Gate>,
    /// The next key-file rename fails, once.
    fail_key_rename: Arc<AtomicBool>,
    /// The next key-file removal fails, once.
    fail_key_remove: Arc<AtomicBool>,
    /// The next loss-marker write fails with `NoSpace`, once.
    fail_marker: Arc<AtomicBool>,
    /// The first directory flush that fails, held after failing and before it returns.
    dir_sync_fail: Arc<Gate>,
    /// The first segment append, held before it runs.
    segment_append: Arc<Gate>,
}

#[derive(Debug)]
struct FaultAppend {
    inner: Box<dyn AppendFile>,
    segment: bool,
    fault: Arc<Mutex<Option<u32>>>,
    gate: Arc<Gate>,
}

impl AppendFile for FaultAppend {
    fn append(&mut self, bytes: &[u8]) -> Result<(), FsError> {
        if self.segment {
            self.gate.hold_if_armed();
            let mut fault = self.fault.lock().unwrap();
            match *fault {
                Some(0) => {
                    *fault = None;
                    // As `write_all` on ENOSPC: part of the line reaches the file before the
                    // failure.
                    let _partial = self.inner.append(bytes.get(..bytes.len() / 2).unwrap_or_default());
                    return Err(FsError::NoSpace { op: "append" });
                }
                Some(n) => *fault = Some(n - 1),
                None => {}
            }
        }
        self.inner.append(bytes)
    }
    fn sync_data(&mut self) -> Result<(), FsError> {
        self.inner.sync_data()
    }
    fn os_len(&self) -> Result<u64, FsError> {
        self.inner.os_len()
    }
}

fn injected(op: &'static str) -> FsError {
    FsError::Io {
        op,
        kind: "injected".to_owned(),
    }
}

fn is_key(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("key")
}

impl FaultFs {
    /// Lets `n` segment appends through, then fails the next with `NoSpace`.
    fn fail_segment_append_after(&self, n: u32) {
        *self.segment_append_fault.lock().unwrap() = Some(n);
    }

    fn clear_append_fault(&self) {
        *self.segment_append_fault.lock().unwrap() = None;
    }

    fn append_fault_pending(&self) -> bool {
        self.segment_append_fault.lock().unwrap().is_some()
    }
}

impl Fs for FaultFs {
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        self.sim.create_dir_all(path)
    }
    fn open_append(&self, path: &Path) -> Result<Box<dyn AppendFile>, FsError> {
        Ok(Box::new(FaultAppend {
            inner: self.sim.open_append(path)?,
            segment: path.extension().and_then(|e| e.to_str()) == Some("jsonl"),
            fault: Arc::clone(&self.segment_append_fault),
            gate: Arc::clone(&self.segment_append),
        }))
    }
    fn read(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        self.sim.read(path)
    }
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError> {
        self.sim.list_dir(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        if is_key(from) {
            self.key_rename.hold_if_armed();
            if self.fail_key_rename.swap(false, Ordering::SeqCst) {
                return Err(injected("rename"));
            }
        }
        self.sim.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        if is_key(path) && self.fail_key_remove.swap(false, Ordering::SeqCst) {
            return Err(injected("remove"));
        }
        self.sim.remove_file(path)
    }
    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        let result = self.sim.sync_dir(path);
        if result.is_err() {
            self.dir_sync_fail.hold_if_armed();
        }
        result
    }
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        if is_key(path) {
            self.key_write.hold_if_armed();
        }
        self.sim.write_atomic(path, bytes)
    }
    fn write_unsynced(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        if is_key(path) {
            self.key_write.hold_if_armed();
        }
        if path.extension().and_then(|e| e.to_str()) == Some("lost") && self.fail_marker.swap(false, Ordering::SeqCst) {
            return Err(FsError::NoSpace { op: "write_unsynced" });
        }
        self.sim.write_unsynced(path, bytes)
    }
    fn sync_file(&self, path: &Path) -> Result<(), FsError> {
        self.sim.sync_file(path)
    }
    fn try_lock_exclusive(&self, path: &Path) -> Result<Box<dyn LockGuard>, FsError> {
        self.sim.try_lock_exclusive(path)
    }
}

/// What a journal shows: see [`World::survey`].
type Survey = (
    Vec<(u64, PocketId, ChunkRef)>,
    BTreeSet<u64>,
    Vec<(PocketId, String, u64)>,
);

struct World {
    sim: SimFs,
    fs: FaultFs,
    clock: Arc<SimClock>,
    rng: Arc<SimRng>,
    /// Survives simulated crashes, like an OS keychain.
    keys: Arc<MemoryKeyring>,
    data: PathBuf,
}

impl World {
    fn new(seed: u64) -> Self {
        let sim = SimFs::new();
        sim.create_dir_all(Path::new(DATA)).unwrap();
        let rng = Arc::new(SimRng::new(seed));
        Self {
            fs: FaultFs {
                sim: sim.clone(),
                segment_append_fault: Arc::new(Mutex::new(None)),
                key_write: Arc::new(Gate::default()),
                key_rename: Arc::new(Gate::default()),
                fail_key_rename: Arc::new(AtomicBool::new(false)),
                fail_key_remove: Arc::new(AtomicBool::new(false)),
                fail_marker: Arc::new(AtomicBool::new(false)),
                dir_sync_fail: Arc::new(Gate::default()),
                segment_append: Arc::new(Gate::default()),
            },
            sim,
            clock: Arc::new(SimClock::new(
                WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
            )),
            keys: Arc::new(MemoryKeyring::new(rng.clone())),
            rng,
            data: PathBuf::from(DATA),
        }
    }

    fn try_store(&self, durability: ChunkDurability) -> Result<Arc<ChunkStore>, ChunkError> {
        let rng: Arc<dyn Rng> = self.rng.clone();
        let keys: Arc<dyn PocketKeyring> = self.keys.clone();
        ChunkStore::open_with(Arc::new(self.fs.clone()), rng, keys, &self.data, durability).map(Arc::new)
    }

    fn store(&self) -> Arc<ChunkStore> {
        self.try_store(ChunkDurability::Balanced).unwrap()
    }

    fn open(&self, store: &Arc<ChunkStore>) -> Result<Journal, JournalError> {
        self.open_with(store, NEVER)
    }

    fn open_with(&self, store: &Arc<ChunkStore>, flush: FlushPolicy) -> Result<Journal, JournalError> {
        let clock: Arc<dyn Clock> = self.clock.clone();
        let rng: Arc<dyn Rng> = self.rng.clone();
        Journal::open_with_payloads(
            Arc::new(self.fs.clone()),
            clock,
            rng,
            &self.data,
            flush,
            Arc::clone(store),
        )
        .map(|opened| opened.journal)
    }

    /// Simulates the process dying and starting again: a crash, then a fresh store and journal.
    fn restart(&self, power: bool) -> (Arc<ChunkStore>, Journal) {
        self.sim.fail_sync_after(u32::MAX);
        if power {
            self.sim.power_loss();
        } else {
            self.sim.crash();
        }
        let store = self.store();
        let journal = self.open(&store).unwrap();
        (store, journal)
    }

    /// Records with a payload, record seqs named by `chunk.lost`, and (pocket, chunk, seq) of
    /// every `chunk.shredded` record.
    fn survey(&self) -> Survey {
        let (records, _) = read_verified(&self.sim, &self.data.join(JOURNAL_DIR)).unwrap();
        let (mut with_payload, mut reported, mut shreds) = (Vec::new(), BTreeSet::new(), Vec::new());
        for r in records {
            let e = r.envelope;
            if e.event_type == types::CHUNK_LOST {
                reported.insert(e.metadata.as_map()[RECORD_SEQ_METADATA_KEY].parse::<u64>().unwrap());
            } else if e.event_type == types::CHUNK_SHREDDED {
                shreds.push((
                    e.pocket_id.unwrap(),
                    e.metadata.as_map()[CHUNK_METADATA_KEY].clone(),
                    e.seq.0,
                ));
            } else if let (Some(p), Some(c)) = (e.pocket_id, e.payload_ref) {
                with_payload.push((e.seq.0, p, c));
            }
        }
        (with_payload, reported, shreds)
    }

    /// Every surviving record's payload is readable, reported lost, or shredded after it.
    fn assert_never_silent(&self, store: &ChunkStore, what: &str) {
        let (records, reported, shreds) = self.survey();
        for (seq, p, c) in &records {
            let shredded = shreds
                .iter()
                .any(|(sp, sc, ss)| sp == p && *sc == c.to_string() && ss > seq);
            assert!(
                store.get(*p, *c).is_ok() || reported.contains(seq) || shredded,
                "{what}: record {seq} has an unreadable payload and no chunk.lost record"
            );
        }
    }

    fn quarantined(&self) -> usize {
        self.sim
            .list_dir(
                &self
                    .data
                    .join(CHUNKS_DIR)
                    .join(pocket().to_string())
                    .join(QUARANTINE_DIR),
            )
            .map_or(0, |v| {
                v.iter()
                    .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("chunk" | "key")))
                    .count()
            })
    }
}

fn pocket() -> PocketId {
    PocketId::from_parts(7, [7; 10])
}

fn draft(pocket: Option<PocketId>, chunk: Option<ChunkRef>, n: u64) -> EventDraft {
    let mut random = [0u8; 10];
    random[..8].copy_from_slice(&n.to_le_bytes());
    EventDraft {
        session_id: None,
        pocket_id: pocket,
        operation_id: None,
        request_id: None,
        agent_id: None,
        correlation_id: CorrelationId::from_parts(n, random),
        parent_id: None,
        actor: Actor::System,
        event_type: types::OP_RESERVED_INTENT,
        payload_ref: chunk,
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

fn shredded_record(chunk: ChunkRef, n: u64) -> EventDraft {
    let mut d = draft(Some(pocket()), None, n);
    d.event_type = types::CHUNK_SHREDDED;
    d.side_effect_class = SideEffectClass::LocalIrreversible;
    d.metadata = Metadata::new(
        [(CHUNK_METADATA_KEY.to_owned(), chunk.to_string())]
            .into_iter()
            .collect(),
    )
    .unwrap();
    d
}

fn content(n: u64) -> Vec<u8> {
    format!("payload {n} ").repeat(32).into_bytes()
}

/// Stores a payload and appends a record that references it.
fn write(store: &ChunkStore, journal: &mut Journal, n: u64) -> (u64, ChunkRef) {
    let chunk = store.put(pocket(), &content(n)).unwrap();
    let seq = journal.append(draft(Some(pocket()), Some(chunk), n)).unwrap().seq.0;
    (seq, chunk)
}

// ── Scenarios ──────────────────────────────────────────────────────────────────────────────

#[test]
fn a_record_cannot_reference_a_chunk_that_is_not_stored() {
    let w = World::new(1);
    let store = w.store();
    let mut journal = w.open(&store).unwrap();
    let body = content(1);
    let chunk = store.reference(pocket(), &body).unwrap();

    assert_eq!(
        journal.append(draft(Some(pocket()), Some(chunk), 1)),
        Err(JournalError::PayloadNotStored),
        "payload before record: a record referencing an unwritten chunk was acknowledged"
    );
    assert_eq!(
        journal.append(draft(None, Some(chunk), 1)),
        Err(JournalError::PayloadNotStored),
        "a payload without its pocket cannot be checked and must be refused"
    );
    store.put(pocket(), &body).unwrap();
    journal.append(draft(Some(pocket()), Some(chunk), 1)).unwrap();
}

#[test]
fn balanced_chunks_become_durable_with_the_records_that_reference_them() {
    let w = World::new(2);
    let store = w.store();
    let mut journal = w.open(&store).unwrap();
    let (seq, chunk) = write(&store, &mut journal, 1);
    assert_eq!(store.pending_len(), 1, "a balanced put is not flushed by itself");
    journal.sync().unwrap();
    assert_eq!(store.pending_len(), 0, "the journal's flush flushes the payloads first");
    assert_eq!(journal.flushed_through().unwrap().0, seq);
    drop(journal);
    drop(store);

    let (store, journal) = w.restart(true);
    assert!(journal.lost_payloads().is_empty());
    assert!(w.survey().0.iter().any(|(s, _, _)| *s == seq));
    assert_eq!(store.get(pocket(), chunk).unwrap(), content(1));
}

#[test]
fn unflushed_payloads_lost_to_power_are_never_silent() {
    let w = World::new(3);
    let store = w.store();
    let mut journal = w.open(&store).unwrap();
    write(&store, &mut journal, 1);
    journal.sync().unwrap();
    write(&store, &mut journal, 2); // with the OS only
    drop(journal);
    drop(store);
    let (store, _journal) = w.restart(true);
    w.assert_never_silent(&store, "power loss");
}

/// Whatever flush fails, in either cache mode, and whenever the power goes, a record at or before
/// the flushed boundary has a readable payload.
#[test]
fn a_flushed_record_never_references_an_unreadable_payload() {
    for keep_cache in [false, true] {
        for k in 0..14 {
            let w = World::new(100 + u64::from(k));
            w.sim.set_failed_sync_keeps_cache(keep_cache);
            let store = w.store();
            let mut journal = w.open(&store).unwrap();
            for n in 0..3 {
                write(&store, &mut journal, n);
            }
            w.sim.fail_sync_after(k);
            // Whether this flush fails depends on `k`; the guarantee must hold either way.
            let _outcome = journal.sync();
            let flushed = journal.flushed_through().map(|s| s.0);
            drop(journal);
            drop(store);
            let (store, _journal) = w.restart(true);
            let (records, reported, _) = w.survey();
            for (seq, p, c) in records {
                let readable = store.get(p, c).is_ok();
                if flushed.is_some_and(|f| seq <= f) {
                    assert!(
                        readable,
                        "fault after {k} flushes (cache kept: {keep_cache}): flushed record {seq} lost its payload"
                    );
                }
                assert!(
                    readable || reported.contains(&seq),
                    "record {seq} lost its payload silently"
                );
            }
        }
    }
}

#[test]
fn a_failed_payload_flush_stops_the_writer_until_recovery_reports_the_loss() {
    let w = World::new(4);
    let store = w.store();
    let mut journal = w.open(&store).unwrap();
    let (seq, _) = write(&store, &mut journal, 1);
    w.sim.fail_next_sync(); // the chunk's data file: the OS drops its unflushed pages
    assert_eq!(journal.sync(), Err(JournalError::PayloadFlushFailed));
    assert_eq!(journal.health(), JournalHealth::PayloadFlushFailed);
    assert_eq!(
        journal.append(draft(None, None, 2)),
        Err(JournalError::PayloadFlushFailed)
    );
    assert_eq!(
        store.put(pocket(), &content(3)),
        Err(ChunkError::FlushFailed),
        "the store is poisoned"
    );

    journal.recover().unwrap();
    assert_eq!(journal.health(), JournalHealth::Healthy);
    assert_eq!(journal.lost_payloads().len(), 1);
    assert_eq!(journal.lost_payloads()[0].record_seq.0, seq);
    assert!(
        w.quarantined() > 0,
        "the unreadable chunk is kept in quarantine, not deleted"
    );
    drop(journal);
    assert!(w.survey().1.contains(&seq), "the loss is journaled as chunk.lost");
}

/// A `chunk.lost` record carries the agent of the record whose payload it reports, so per-agent
/// attribution survives a loss.
#[test]
fn a_lost_payload_record_names_the_agent_of_the_record_it_reports() {
    let w = World::new(4);
    let store = w.store();
    let mut journal = w.open(&store).unwrap();
    let agent = AgentId::from_parts(9, [9; 10]);
    let chunk = store.put(pocket(), &content(1)).unwrap();
    let mut referencing = draft(Some(pocket()), Some(chunk), 1);
    referencing.agent_id = Some(agent);
    let seq = journal.append(referencing).unwrap().seq.0;
    w.sim.fail_next_sync();
    assert_eq!(journal.sync(), Err(JournalError::PayloadFlushFailed));
    journal.recover().unwrap();
    drop(journal);
    let (records, _) = read_verified(&w.sim, &w.data.join(JOURNAL_DIR)).unwrap();
    let lost: Vec<_> = records
        .iter()
        .map(|r| &r.envelope)
        .filter(|e| e.event_type == types::CHUNK_LOST)
        .collect();
    assert_eq!(lost.len(), 1);
    assert_eq!(lost[0].metadata.as_map()[RECORD_SEQ_METADATA_KEY], seq.to_string());
    assert_eq!(lost[0].agent_id, Some(agent), "a lost-payload record dropped the agent");
}

#[test]
fn rotation_rewraps_are_durable_in_balanced_mode() {
    let w = World::new(5);
    let store = w.store();
    let keep = store.put(pocket(), &content(1)).unwrap();
    let doomed = store.put(pocket(), &content(2)).unwrap();
    store.sync_pending().unwrap();
    store.shred(pocket(), doomed).unwrap(); // rotates the KEK, re-wraps `keep`, retires the old KEK
    drop(store);
    w.sim.power_loss();
    let store = w.store();
    assert_eq!(
        store.get(pocket(), keep).unwrap(),
        content(1),
        "an unflushed re-wrap would leave a key only the destroyed KEK opens"
    );
}

#[test]
fn a_chunk_left_torn_by_a_power_loss_is_rewritten_not_trusted() {
    let w = World::new(6);
    let store = w.store();
    let chunk = store.put(pocket(), &content(1)).unwrap();
    // Make the directory entries durable but not the file contents: both files come back empty.
    w.sim
        .sync_dir(&w.data.join(CHUNKS_DIR).join(pocket().to_string()).join("data"))
        .unwrap();
    w.sim
        .sync_dir(&w.data.join(CHUNKS_DIR).join(pocket().to_string()).join("keys"))
        .unwrap();
    drop(store);
    w.sim.power_loss();
    let store = w.store();
    assert!(store.get(pocket(), chunk).is_err());
    assert!(!store.is_stored(pocket(), chunk).unwrap());
    assert_eq!(store.put(pocket(), &content(1)).unwrap(), chunk);
    assert_eq!(store.get(pocket(), chunk).unwrap(), content(1));
}

/// (P8's half in this crate): `open_with_payloads` hands back the whole journal, oldest first, the
/// loss record it appended itself included, so boot reads nothing again.
#[test]
fn an_open_returns_the_whole_journal_with_the_records_it_appended() {
    let w = World::new(13);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    write(&store, &mut j, 0);
    j.sync().unwrap();
    write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    drop(j);
    drop(store);
    w.sim.crash();

    let store = w.store();
    let clock: Arc<dyn Clock> = w.clock.clone();
    let rng: Arc<dyn Rng> = w.rng.clone();
    let opened =
        Journal::open_with_payloads(Arc::new(w.fs.clone()), clock, rng, &w.data, NEVER, Arc::clone(&store)).unwrap();
    let (journal, records) = (opened.journal, opened.records);
    // The loss record is the open's own, and the evidence says where those begin.
    let lost = records
        .iter()
        .find(|r| r.envelope.event_type == types::CHUNK_LOST)
        .map(|r| r.envelope.seq);
    assert_eq!(
        opened.evidence.own_from, lost,
        "the open did not say where its own records begin"
    );
    let (read, _) = read_verified(&w.sim, &w.data.join(JOURNAL_DIR)).unwrap();
    let ids = |records: &[VerifiedRecord]| records.iter().map(|r| (r.envelope.seq, r.hash)).collect::<Vec<_>>();
    assert!(
        records.iter().any(|r| r.envelope.event_type == types::CHUNK_LOST),
        "the scenario reported no loss at open"
    );
    assert_eq!(
        ids(&records),
        ids(&read),
        "the open handed back other records than the journal holds"
    );
    assert_eq!(records.last().map(|r| r.hash), Some(journal.head()));
}

/// If reporting a loss fails during open, the marker has not moved, so the next open checks the
/// same tail and reports it.
#[test]
fn h1_open_reports_a_loss_before_its_marker_moves() {
    let w = World::new(11);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    drop(j);
    drop(store);
    w.sim.crash();

    // The open copies the previous run's record to a fresh segment, then appends chunk.lost:
    // the second segment append fails.
    w.fs.fail_segment_append_after(1);
    let store = w.store();
    let first = w.open(&store);
    assert!(first.is_err(), "the chunk.lost append failed, so open fails: {first:?}");
    drop(first);
    drop(store);

    let (store, _j) = w.restart(false);
    w.assert_never_silent(&store, "h1");
}

/// An open that found a loss and failed to journal it leaves no record durable ahead of its loss
/// record, even if the power goes before the next open.
#[test]
fn h1_a_failed_open_leaves_no_record_durable_before_its_loss_record() {
    let w = World::new(25);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _) = write(&store, &mut j, 1);
    w.sim.fail_next_sync(); // the chunk's data file: the OS drops its unflushed pages
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    drop(j);
    drop(store);
    w.sim.crash();
    // The open finds the loss, copies the record, and fails to append its chunk.lost record.
    w.fs.fail_segment_append_after(1);
    let store = w.store();
    assert!(w.open(&store).is_err());
    drop(store);
    w.sim.power_loss();
    let (records, reported, _) = w.survey();
    assert!(
        !records.iter().any(|(s, _, _)| *s == seq) || reported.contains(&seq),
        "the record became durable before its loss record"
    );
}

/// A loss found by recovery survives a failed report and every other recovery branch.
#[test]
fn h2_a_loss_survives_a_failed_report_and_other_recover_branches() {
    let w = World::new(12);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));

    w.fs.fail_segment_append_after(0);
    assert!(j.recover().is_err(), "the chunk.lost append fails");
    assert_eq!(j.health(), JournalHealth::DiskFull);
    j.recover().unwrap(); // the disk-full branch must report what is still unreported
    assert_eq!(j.lost_payloads().len(), 1);
    write(&store, &mut j, 2);
    j.sync().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "h2");
}

/// A flush that fails in the store, outside the journal, poisons the store, so the next journal
/// flush stops instead of marking records durable over dropped content.
#[test]
fn h3_a_store_flush_failure_stops_the_journal() {
    let w = World::new(13);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, chunk) = write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert!(store.sync_pending().is_err());
    assert_eq!(
        j.sync(),
        Err(JournalError::PayloadFlushFailed),
        "the journal saw the store's failure"
    );
    assert!(j.flushed_through().is_none_or(|f| f.0 < seq));
    assert!(
        store.is_stored(pocket(), chunk).is_err(),
        "a poisoned store does not vouch from memory"
    );
    j.recover().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "h3");
}

/// After a writeback error the cache still serves the bytes and a second flush of the same file
/// "succeeds" without making them durable. Recovery must rewrite, not re-flush.
#[test]
fn h4_recovery_rewrites_content_instead_of_reflushing_the_failed_file() {
    let w = World::new(16);
    w.sim.set_failed_sync_keeps_cache(true);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, chunk) = write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    j.recover().unwrap();
    assert!(
        j.lost_payloads().is_empty(),
        "the cached bytes were readable, so nothing is lost"
    );
    assert!(j.flushed_through().is_some_and(|f| f.0 >= seq));
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    assert_eq!(
        store.get(pocket(), chunk).ok(),
        Some(content(1)),
        "a flushed record's payload was re-flushed in place and lost to the power cut"
    );
}

/// A lost chunk is quarantined under its slot, so a concurrent put of the same content cannot have
/// its fresh pair moved away underneath it. The race is reachable at open, while the previous run's
/// tail is checked; during runtime recovery the store is poisoned and refuses puts outright
/// (`a_failed_payload_flush_stops_the_writer_until_recovery_reports_the_loss`).
#[test]
fn m2_a_quarantine_and_a_concurrent_put_of_the_same_chunk_never_lose_it() {
    let w = World::new(14);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    w.sim.fail_next_sync(); // the chunk's data file: the OS drops its unflushed pages
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    drop(j);
    drop(store);
    w.sim.crash(); // the record is still with the OS; its payload is not

    let store = w.store();
    w.fs.key_rename.arm(); // the quarantine of the lost chunk stops at its key file
    let rename = Arc::clone(&w.fs.key_rename);
    let b = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            rename.wait_held();
            store.put(pocket(), &content(1))
        })
    };
    let releaser = w.fs.key_rename.release_after(300);
    let mut j = w.open(&store).unwrap();
    releaser.join().unwrap();
    assert_eq!(
        b.join().unwrap().unwrap(),
        x,
        "the put waited for the quarantine, then wrote a fresh pair"
    );
    assert_eq!(
        j.lost_payloads().len(),
        1,
        "the earlier record's payload was lost and is reported"
    );
    j.append(draft(Some(pocket()), Some(x), 2)).unwrap();
    j.sync().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "m2");
    assert_eq!(
        store.get(pocket(), x).ok(),
        Some(content(1)),
        "the fresh pair was moved into quarantine"
    );
}

/// A put that is wrapping its key cannot race a shred into wrapping under a KEK the shred destroys.
#[test]
fn m3_a_put_racing_a_shred_in_the_same_pocket_stays_readable() {
    for durability in [ChunkDurability::Balanced, ChunkDurability::Strict] {
        let w = World::new(15);
        let store = w.try_store(durability).unwrap();
        let other = store.put(pocket(), &content(9)).unwrap();
        store.sync_pending().unwrap();
        w.fs.key_write.arm();
        let a = {
            let store = Arc::clone(&store);
            std::thread::spawn(move || store.put(pocket(), &content(1)))
        };
        w.fs.key_write.wait_held(); // A holds the current KEK and has not written its key file
        let s = {
            let store = Arc::clone(&store);
            std::thread::spawn(move || store.shred(pocket(), other))
        };
        std::thread::sleep(Duration::from_millis(200));
        w.fs.key_write.release();
        let z = a.join().unwrap().unwrap();
        s.join().unwrap().unwrap();
        assert!(store.is_stored(pocket(), z).unwrap());
        assert_eq!(
            store.get(pocket(), z).ok(),
            Some(content(1)),
            "{durability:?}: the put's key file was wrapped under a destroyed KEK"
        );
    }
}

/// Recovery quarantines unreadable chunks instead of deleting them, and a keyring that cannot
/// produce a KEK is a failure that touches nothing.
#[test]
fn m5_keyring_failures_fail_closed_without_touching_chunks() {
    let w = World::new(17);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, chunk) = write(&store, &mut j, 1);
    drop(j);
    drop(store);
    w.sim.crash();
    // The keychain lost every KEK version (a reset, or a moved data directory).
    w.keys.retire_keks_before(pocket(), KekVersion(1_000)).unwrap();
    let store = w.store();
    let opened = w.open(&store);
    assert!(
        matches!(opened, Err(JournalError::Payload(ChunkError::Keyring(_)))),
        "missing keys are not a payload loss: {opened:?}"
    );
    assert_eq!(w.quarantined(), 0, "nothing was moved or deleted");
    let name = chunk.to_string();
    let key_file = format!("{}.key", name.strip_prefix("hmac-sha256:").unwrap());
    let key_files = w
        .sim
        .list_dir(&w.data.join(CHUNKS_DIR).join(pocket().to_string()).join("keys"))
        .unwrap();
    assert!(
        key_files
            .iter()
            .any(|p| p.file_name().unwrap().to_string_lossy() == key_file),
        "the key file is where it was"
    );
}

/// One chunk store per data directory.
#[test]
fn l2_one_chunk_store_per_data_directory() {
    let w = World::new(18);
    let _first = w.store();
    assert_eq!(
        w.try_store(ChunkDurability::Balanced).err(),
        Some(ChunkError::InstanceLocked)
    );
}

/// A journal that has coordinated a chunk store cannot be opened without it.
#[test]
fn l3_a_coordinated_journal_refuses_to_open_without_its_store() {
    let w = World::new(19);
    let store = w.store();
    let j = w.open(&store).unwrap();
    drop(j);
    w.sim.crash();
    let clock: Arc<dyn Clock> = w.clock.clone();
    let rng: Arc<dyn Rng> = w.rng.clone();
    let plain = Journal::open(Arc::new(w.fs.clone()), clock, rng, &w.data, NEVER);
    assert_eq!(
        plain.err(),
        Some(JournalError::PayloadsRequired),
        "a coordinated journal opened without its store"
    );
}

/// Chunk records name their chunk in metadata, and a shred after a record is not a loss.
#[test]
fn l5_chunk_records_name_their_chunk_and_a_shred_is_not_a_loss() {
    let w = World::new(20);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, chunk) = write(&store, &mut j, 1);
    let mut wrong = shredded_record(chunk, 2);
    wrong.payload_ref = Some(chunk);
    assert!(matches!(j.append(wrong), Err(JournalError::InvalidRecord(_))));
    // Through the journal: the record is durable before the content goes.
    j.shred(shredded_record(chunk, 3)).unwrap().finish().unwrap();
    drop(j);
    drop(store);
    let (store, j) = w.restart(true);
    assert!(j.lost_payloads().is_empty(), "a shredded payload was reported lost");
    w.assert_never_silent(&store, "l5");
}

// ── Found by the crash schedules ───────────────────

/// N1: a chunk already on disk from an earlier process is replaced only by a flushed write. An
/// unflushed replacement, once its process died, would be made durable empty by the next
/// directory flush, under a record that was durable before.
#[test]
fn n1_a_rewrite_of_a_chunk_from_an_earlier_process_is_flushed() {
    let w = World::new(21);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, x) = write(&store, &mut j, 1);
    w.clock.advance(1_100_000_000);
    j.sync().unwrap(); // the marker now names the record: no later open checks its payload
    drop(j);
    drop(store);
    w.sim.crash();
    // A process that did not write the content stores it again, then dies before any flush.
    let store = w.store();
    assert_eq!(store.put(pocket(), &content(1)).unwrap(), x);
    drop(store);
    // The next process flushes the pocket's directories, then the power goes.
    let (store, mut j) = w.restart(false);
    write(&store, &mut j, 2);
    j.sync().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    assert!(w.survey().0.iter().any(|(s, _, _)| *s == seq));
    assert_eq!(
        store.get(pocket(), x).ok(),
        Some(content(1)),
        "a durable payload was replaced by an unflushed copy"
    );
}

/// N2: a rewrite keeps the pair's data key, so a failure between the data-file and key-file
/// writes leaves the old key file opening the new data file.
#[test]
fn n2_a_rewrite_that_fails_between_its_two_files_leaves_a_readable_pair() {
    let w = World::new(22);
    let store = w.store();
    let x = store.put(pocket(), &content(1)).unwrap();
    store.sync_pending().unwrap();
    drop(store);
    w.sim.crash();
    let store = w.store();
    store.put(pocket(), &content(2)).unwrap(); // the pocket's directories are prepared
    // A flushed write is two flushes (file, directory): the data file's succeed, the key
    // file's first one fails.
    w.sim.fail_sync_after(2);
    assert!(store.put(pocket(), &content(1)).is_err());
    w.sim.fail_sync_after(u32::MAX);
    assert_eq!(
        store.get(pocket(), x).ok(),
        Some(content(1)),
        "new data was left paired with a key file that was never written"
    );
    drop(store);
    w.sim.power_loss();
    let store = w.store();
    assert_eq!(
        store.get(pocket(), x).ok(),
        Some(content(1)),
        "new data was left paired with a key file that was never written"
    );
}

/// N3: while a found loss waits to be journaled (the disk filled while it was reported), the
/// writer refuses records and flushes, so no record becomes durable before its loss record.
#[test]
fn n3_a_loss_waiting_to_be_journaled_holds_back_every_flush() {
    let w = World::new(23);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _) = write(&store, &mut j, 1);
    w.sim.fail_next_sync(); // the chunk's data file: the OS drops its unflushed pages
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    w.fs.fail_segment_append_after(0);
    assert!(
        j.recover().is_err(),
        "the loss was found; its record could not be appended"
    );
    assert_eq!(
        j.sync(),
        Err(JournalError::DiskFull),
        "a flush ran while a loss waited to be journaled"
    );
    assert!(
        j.flushed_through().is_none_or(|f| f.0 < seq),
        "the record became durable before its loss record"
    );
    assert_eq!(j.append(draft(None, None, 2)), Err(JournalError::DiskFull));
    j.recover().unwrap();
    assert!(j.flushed_through().is_some_and(|f| f.0 > seq));
    drop(j);
    drop(store);
    let (_store, _j) = w.restart(true);
    assert!(w.survey().1.contains(&seq), "the loss is journaled and durable");
}

/// N4: open never flushes the previous run's segment again. After a failed flush, a second
/// flush of the same file can report success without writing anything (cache kept), and a
/// failing one drops what the OS held (cache dropped). Whatever flush fails during an open,
/// the previous run's records survive the next open and a power loss after it.
#[test]
fn n4_open_copies_the_previous_runs_records_instead_of_flushing_their_file_again() {
    for keep_cache in [false, true] {
        for k in 0..6 {
            let w = World::new(24);
            w.sim.set_failed_sync_keeps_cache(keep_cache);
            let plain = || {
                let clock: Arc<dyn Clock> = w.clock.clone();
                let rng: Arc<dyn Rng> = w.rng.clone();
                Journal::open(Arc::new(w.fs.clone()), clock, rng, &w.data, NEVER)
            };
            let mut j = plain().unwrap();
            for n in 0..3 {
                j.append(draft(None, None, n)).unwrap(); // with the OS only
            }
            drop(j);
            w.sim.crash();
            w.sim.fail_sync_after(k);
            // Whether this open fails depends on `k`; the records must survive either way.
            drop(plain());
            w.sim.fail_sync_after(u32::MAX);
            w.sim.crash();
            drop(plain().unwrap());
            w.sim.power_loss();
            let records = read_verified(&w.sim, &w.data.join(JOURNAL_DIR))
                .unwrap_or_else(|e| panic!("cache kept: {keep_cache}, fault after {k}: {e}"))
                .0;
            assert_eq!(
                records.len(),
                3,
                "cache kept: {keep_cache}, fault after {k}: the previous run's records were lost"
            );
        }
    }
}

// ── Regression tests, part two ──────────────────────────────────────

/// Stops all I/O right after the `n`th successful MANIFEST write: the machine dies at that
/// instant. Used to cut an open between its manifest write and whatever follows.
#[derive(Debug, Clone)]
struct DieFs {
    inner: FaultFs,
    manifests_left: Arc<Mutex<u32>>,
    dead: Arc<AtomicBool>,
}

#[derive(Debug)]
struct DieAppend {
    inner: Box<dyn AppendFile>,
    dead: Arc<AtomicBool>,
}

impl AppendFile for DieAppend {
    fn append(&mut self, bytes: &[u8]) -> Result<(), FsError> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(injected("dead"));
        }
        self.inner.append(bytes)
    }
    fn sync_data(&mut self) -> Result<(), FsError> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(injected("dead"));
        }
        self.inner.sync_data()
    }
    fn os_len(&self) -> Result<u64, FsError> {
        self.inner.os_len()
    }
}

impl DieFs {
    fn new(inner: FaultFs, manifests: u32) -> Self {
        Self {
            inner,
            manifests_left: Arc::new(Mutex::new(manifests)),
            dead: Arc::new(AtomicBool::new(false)),
        }
    }
    fn alive(&self) -> Result<(), FsError> {
        if self.dead.load(Ordering::SeqCst) {
            Err(injected("dead"))
        } else {
            Ok(())
        }
    }
}

impl Fs for DieFs {
    fn create_dir_all(&self, p: &Path) -> Result<(), FsError> {
        self.alive()?;
        self.inner.create_dir_all(p)
    }
    fn open_append(&self, p: &Path) -> Result<Box<dyn AppendFile>, FsError> {
        self.alive()?;
        Ok(Box::new(DieAppend {
            inner: self.inner.open_append(p)?,
            dead: Arc::clone(&self.dead),
        }))
    }
    fn read(&self, p: &Path) -> Result<Vec<u8>, FsError> {
        self.alive()?;
        self.inner.read(p)
    }
    fn list_dir(&self, p: &Path) -> Result<Vec<PathBuf>, FsError> {
        self.alive()?;
        self.inner.list_dir(p)
    }
    fn rename(&self, a: &Path, b: &Path) -> Result<(), FsError> {
        self.alive()?;
        self.inner.rename(a, b)
    }
    fn remove_file(&self, p: &Path) -> Result<(), FsError> {
        self.alive()?;
        self.inner.remove_file(p)
    }
    fn sync_dir(&self, p: &Path) -> Result<(), FsError> {
        self.alive()?;
        self.inner.sync_dir(p)
    }
    fn write_atomic(&self, p: &Path, b: &[u8]) -> Result<(), FsError> {
        self.alive()?;
        let written = self.inner.write_atomic(p, b);
        if written.is_ok() && p.file_name().and_then(|n| n.to_str()) == Some("MANIFEST") {
            let mut left = self.manifests_left.lock().unwrap();
            if *left == 0 {
                self.dead.store(true, Ordering::SeqCst);
            } else {
                *left -= 1;
            }
        }
        written
    }
    fn write_unsynced(&self, p: &Path, b: &[u8]) -> Result<(), FsError> {
        self.alive()?;
        self.inner.write_unsynced(p, b)
    }
    fn sync_file(&self, p: &Path) -> Result<(), FsError> {
        self.alive()?;
        self.inner.sync_file(p)
    }
    fn try_lock_exclusive(&self, p: &Path) -> Result<Box<dyn LockGuard>, FsError> {
        self.alive()?;
        self.inner.try_lock_exclusive(p)
    }
}

/// The previous run flushed three records with its marker lagging, then crashed. The next open dies
/// right after its first manifest write and the power goes: the records it had acknowledged as
/// durable must survive.
#[test]
fn r2_h1_a_power_loss_during_open_keeps_what_the_previous_run_flushed() {
    let w = World::new(900);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    for n in 0..3 {
        write(&store, &mut j, n);
    }
    j.sync().unwrap();
    let flushed = j.flushed_through().unwrap().0;
    drop(j);
    drop(store);
    w.sim.crash();

    let store = w.store();
    let die = DieFs::new(w.fs.clone(), 0);
    let clock: Arc<dyn Clock> = w.clock.clone();
    let rng: Arc<dyn Rng> = w.rng.clone();
    let opened = Journal::open_with_payloads(Arc::new(die.clone()), clock, rng, &w.data, NEVER, Arc::clone(&store));
    assert!(die.dead.load(Ordering::SeqCst), "the open stored a manifest");
    assert!(opened.is_err());
    drop(opened);
    drop(store);
    w.sim.power_loss();
    let (_store, _j) = w.restart(false);
    let present: BTreeSet<u64> = w.survey().0.iter().map(|r| r.0).collect();
    assert!(
        (0..=flushed).all(|s| present.contains(&s)),
        "records flushed and acknowledged by the previous run vanished: present {present:?}"
    );
}

/// Whatever flush or append fails during the open, and whether a crash or a power loss follows, the
/// records the previous run flushed survive.
#[test]
fn r2_h1_a_failed_open_keeps_what_the_previous_run_flushed() {
    let mut failures = Vec::new();
    for power in [false, true] {
        for keep_cache in [false, true] {
            for k in 0..30u32 {
                let w = World::new(901);
                w.sim.set_failed_sync_keeps_cache(keep_cache);
                let store = w.store();
                let mut j = w.open(&store).unwrap();
                for n in 0..3 {
                    write(&store, &mut j, n);
                }
                j.sync().unwrap();
                let flushed = j.flushed_through().unwrap().0;
                drop(j);
                drop(store);
                w.sim.crash();
                w.fs.fail_segment_append_after(1);
                w.sim.fail_sync_after(k);
                let store = w.store();
                let first = w.open(&store);
                let failed = first.is_err();
                drop(first);
                drop(store);
                w.fs.clear_append_fault();
                let (_s, _j) = w.restart(power);
                let present: BTreeSet<u64> = w.survey().0.iter().map(|r| r.0).collect();
                if !(0..=flushed).all(|s| present.contains(&s)) {
                    failures.push(format!(
                        "power {power}, cache kept {keep_cache}, fault after {k}, open failed {failed}: present {present:?}"
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "flushed records lost:\n{}", failures.join("\n"));
}

/// A store poisoned before the journal attached is recovered at open, and the marker is still
/// written, so the journal cannot then be opened without its store.
#[test]
fn r2_l1_a_store_poisoned_before_the_journal_attached_is_recovered_at_open() {
    let w = World::new(902);
    let store = w.store();
    store.put(pocket(), &content(1)).unwrap();
    w.sim.fail_next_sync();
    assert!(store.sync_pending().is_err());
    let j = w.open(&store).unwrap();
    assert_eq!(j.health(), JournalHealth::Healthy);
    assert!(!store.is_poisoned(), "open left the store poisoned");
    drop(j);
    drop(store);
    w.sim.crash();
    let clock: Arc<dyn Clock> = w.clock.clone();
    let rng: Arc<dyn Rng> = w.rng.clone();
    let plain = Journal::open(Arc::new(w.fs.clone()), clock, rng, &w.data, NEVER);
    assert_eq!(
        plain.err(),
        Some(JournalError::PayloadsRequired),
        "a coordinated journal opened without its store"
    );
}

/// Recovery from a full disk while a loss waits to be journaled moves the
/// unflushed records without flushing them, so a power loss cannot leave a record durable
/// ahead of its loss record.
#[test]
fn r2_m1_disk_full_recovery_never_flushes_a_record_before_its_loss_record() {
    let w = World::new(903);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _) = write(&store, &mut j, 1);
    w.sim.fail_next_sync(); // the chunk's data file: the OS drops its unflushed pages
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    w.fs.fail_segment_append_after(0);
    assert!(j.recover().is_err(), "the loss record could not be appended");
    // The next recovery moves the records, then its loss-record append fails again.
    w.fs.fail_segment_append_after(1);
    assert!(j.recover().is_err());
    drop(j);
    drop(store);
    w.sim.power_loss();
    let (records, reported, _) = w.survey();
    assert!(
        !records.iter().any(|(s, _, _)| *s == seq) || reported.contains(&seq),
        "the record became durable before its loss record"
    );
}

/// The same after a failed relocation (`FlushFailed`): retrying it does not
/// flush the records ahead of their loss record either.
#[test]
fn r2_m1_a_failed_relocation_never_flushes_a_record_before_its_loss_record() {
    let w = World::new(904);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _) = write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    w.fs.fail_segment_append_after(0);
    assert!(j.recover().is_err(), "the loss record could not be appended");
    w.fs.fail_segment_append_after(0); // the relocation's own append fails
    assert!(j.recover().is_err());
    assert_eq!(j.health(), JournalHealth::FlushFailed);
    w.fs.fail_segment_append_after(1); // the relocation succeeds, the loss record fails again
    assert!(j.recover().is_err());
    drop(j);
    drop(store);
    w.sim.power_loss();
    let (records, reported, _) = w.survey();
    assert!(
        !records.iter().any(|(s, _, _)| *s == seq) || reported.contains(&seq),
        "the record became durable before its loss record"
    );
}

/// A pair left unflushed by an earlier process is rewritten, flushed,
/// before a record may reference it, so a power loss after the marker passed the record
/// cannot take the payload.
#[test]
fn r2_m1_is_stored_rewrites_an_earlier_processs_unflushed_pair() {
    let w = World::new(905);
    let store = w.store();
    let x = store.put(pocket(), &content(1)).unwrap(); // never flushed, no record
    drop(store);
    w.sim.crash();
    let (store, mut j) = w.restart(false);
    j.append(draft(Some(pocket()), Some(x), 1)).unwrap();
    w.clock.advance(1_100_000_000);
    j.sync().unwrap(); // the marker now passes the record
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    assert!(
        store.get(pocket(), x).is_ok() || w.survey().1.contains(&0),
        "a record became durable over a payload only an earlier process had written"
    );
}

/// A pending chunk whose files vanished is a flush failure, never success.
#[test]
fn r2_m1_a_pending_file_removed_underneath_is_a_flush_failure() {
    let w = World::new(906);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, x) = write(&store, &mut j, 1);
    let name = x.to_string();
    let key_file = w
        .data
        .join(CHUNKS_DIR)
        .join(pocket().to_string())
        .join("keys")
        .join(format!("{}.key", name.strip_prefix("hmac-sha256:").unwrap()));
    w.sim.remove_file(&key_file).unwrap();
    assert_eq!(
        j.sync(),
        Err(JournalError::PayloadFlushFailed),
        "a flush succeeded although a pending payload's file was gone"
    );
    j.recover().unwrap();
    assert_eq!(j.lost_payloads().len(), 1);
    assert_eq!(j.lost_payloads()[0].record_seq.0, seq);
}

/// A loss found by recovery survives a failed quarantine and is reported
/// by the next recovery.
#[test]
fn r2_m1_a_failed_quarantine_never_drops_a_loss() {
    let w = World::new(907);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _) = write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    w.fs.fail_key_rename.store(true, Ordering::SeqCst); // the quarantine fails
    assert!(j.recover().is_err());
    j.recover().unwrap();
    assert_eq!(
        j.lost_payloads().iter().map(|l| l.record_seq.0).collect::<Vec<_>>(),
        vec![seq],
        "the loss was dropped by the failed quarantine"
    );
}

/// In balanced mode a failed directory flush poisons the store.
#[test]
fn r2_l2_a_failed_directory_flush_poisons_a_balanced_store() {
    let w = World::new(908);
    let store = w.store();
    let keep = store.put(pocket(), &content(1)).unwrap();
    let doomed = store.put(pocket(), &content(2)).unwrap();
    store.sync_pending().unwrap();
    let _pending = store.put(pocket(), &content(3)).unwrap();
    w.sim.fail_next_sync(); // the shred's first directory flush
    assert!(store.shred(pocket(), doomed).is_err());
    assert!(store.is_poisoned(), "a failed directory flush did not poison the store");
    assert_eq!(store.put(pocket(), &content(4)), Err(ChunkError::FlushFailed));
    assert!(store.get(pocket(), keep).is_ok());
}

/// Puts past the pending bound are refused, and a journal flush clears it.
#[test]
fn r2_l5_pending_full_is_refused_and_cleared_by_a_flush() {
    let w = World::new(909);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let base = 1_000_000u64;
    for n in 0..u64::try_from(MAX_PENDING).unwrap() {
        store.put(pocket(), &content(base + n)).unwrap();
    }
    assert_eq!(store.put(pocket(), &content(1)), Err(ChunkError::PendingFull));
    j.append(draft(None, None, 1)).unwrap();
    j.sync().unwrap();
    assert_eq!(store.pending_len(), 0);
    store.put(pocket(), &content(1)).unwrap();
}

/// A shred whose record is durable but whose files a crash left behind is completed when the
/// journal opens; without that, the store's startup re-wraps the leftover key and the content
/// stays readable (pre-existing).
#[test]
fn a_shred_interrupted_after_its_record_is_completed_at_open() {
    let w = World::new(910);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    let (_, y) = write(&store, &mut j, 2);
    j.sync().unwrap();
    w.fs.fail_key_remove.store(true, Ordering::SeqCst);
    assert!(
        matches!(j.shred(shredded_record(x, 3)), Err(JournalError::Payload(_))),
        "the record is durable and the KEK rotated, then the removal failed"
    );
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    assert_eq!(
        store.get(pocket(), x).err(),
        Some(ChunkError::Unavailable),
        "content whose shred was journaled is still readable"
    );
    assert_eq!(store.get(pocket(), y).ok(), Some(content(2)));
    w.assert_never_silent(&store, "interrupted shred");
}

/// A shred is completed at open only once its record is durable. Here the record was with the
/// OS only, the open fails before its flush, and the power goes: the record is gone, so the
/// content it named must still be there (found by the crash schedules).
#[test]
fn r2_a_shred_is_completed_only_once_its_record_is_durable() {
    let w = World::new(911);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    j.sync().unwrap();
    record_shred_unflushed(&w, &store, &mut j, x, 2); // with the OS only; the shred never ran
    drop(j);
    drop(store);
    w.sim.crash();
    w.fs.fail_segment_append_after(0); // the open's copy of the shred record fails
    let store = w.store();
    assert!(w.open(&store).is_err());
    drop(store);
    w.sim.power_loss(); // the shred record is gone
    let store = w.store();
    assert_eq!(
        store.get(pocket(), x).ok(),
        Some(content(1)),
        "a shred ran on a record a power loss took away"
    );
}

/// Fails every MANIFEST write while armed; everything else passes through.
#[derive(Debug, Clone)]
struct NoManifestFs {
    inner: FaultFs,
    armed: Arc<AtomicBool>,
}

impl Fs for NoManifestFs {
    fn create_dir_all(&self, p: &Path) -> Result<(), FsError> {
        self.inner.create_dir_all(p)
    }
    fn open_append(&self, p: &Path) -> Result<Box<dyn AppendFile>, FsError> {
        self.inner.open_append(p)
    }
    fn read(&self, p: &Path) -> Result<Vec<u8>, FsError> {
        self.inner.read(p)
    }
    fn list_dir(&self, p: &Path) -> Result<Vec<PathBuf>, FsError> {
        self.inner.list_dir(p)
    }
    fn rename(&self, a: &Path, b: &Path) -> Result<(), FsError> {
        self.inner.rename(a, b)
    }
    fn remove_file(&self, p: &Path) -> Result<(), FsError> {
        self.inner.remove_file(p)
    }
    fn sync_dir(&self, p: &Path) -> Result<(), FsError> {
        self.inner.sync_dir(p)
    }
    fn write_atomic(&self, p: &Path, b: &[u8]) -> Result<(), FsError> {
        if self.armed.load(Ordering::SeqCst) && p.file_name().and_then(|n| n.to_str()) == Some("MANIFEST") {
            return Err(injected("manifest"));
        }
        self.inner.write_atomic(p, b)
    }
    fn write_unsynced(&self, p: &Path, b: &[u8]) -> Result<(), FsError> {
        self.inner.write_unsynced(p, b)
    }
    fn sync_file(&self, p: &Path) -> Result<(), FsError> {
        self.inner.sync_file(p)
    }
    fn try_lock_exclusive(&self, p: &Path) -> Result<Box<dyn LockGuard>, FsError> {
        self.inner.try_lock_exclusive(p)
    }
}

/// A record appended after a shred that references the shredded content is refused until the
/// content is stored again; a coordinated store refuses a direct shred.
#[test]
fn r3_h1_after_a_shred_a_record_needs_its_content_stored_again() {
    let w = World::new(950);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    j.sync().unwrap();
    assert_eq!(
        store.shred(pocket(), x).err(),
        Some(ChunkError::ShredThroughJournal),
        "a coordinated store shredded without its journal"
    );
    j.shred(shredded_record(x, 2)).unwrap().finish().unwrap();
    assert_eq!(
        j.append(draft(Some(pocket()), Some(x), 3)).err(),
        Some(JournalError::PayloadNotStored),
        "a record referenced content shredded before it"
    );
    assert_eq!(store.put(pocket(), &content(1)).unwrap(), x);
    let again = j.append(draft(Some(pocket()), Some(x), 4)).unwrap().seq.0;
    w.clock.advance(1_100_000_000);
    j.sync().unwrap(); // the marker passes the new record
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "r3 h1");
    assert!(w.survey().0.iter().any(|(s, _, _)| *s == again));
    assert_eq!(store.get(pocket(), x).ok(), Some(content(1)));
}

/// Reopening a journal with no new records does not copy its segment again and again; disk use
/// stays flat.
#[test]
fn r3_m1_restarts_do_not_grow_the_journal() {
    let w = World::new(951);
    let plain = || {
        let clock: Arc<dyn Clock> = w.clock.clone();
        let rng: Arc<dyn Rng> = w.rng.clone();
        Journal::open(Arc::new(w.fs.clone()), clock, rng, &w.data, NEVER)
    };
    let mut j = plain().unwrap();
    for n in 0..2000 {
        j.append(draft(None, None, n)).unwrap();
    }
    j.sync().unwrap();
    drop(j);
    let dir = w.data.join(JOURNAL_DIR);
    let bytes = || -> usize {
        w.sim
            .list_dir(&dir)
            .unwrap()
            .iter()
            .filter(|p| p.to_string_lossy().contains("seg-"))
            .filter_map(|p| w.sim.os_view(p))
            .map(|v| v.len())
            .sum()
    };
    let before = bytes();
    for _ in 0..5 {
        w.sim.crash();
        drop(plain().unwrap());
    }
    let after = bytes();
    assert!(
        after <= before + before / 10,
        "segment bytes grew from {before} to {after} over five restarts with no new record"
    );
}

/// Files moved into quarantine survive a power loss.
#[test]
fn r3_l1_quarantined_files_survive_a_power_loss() {
    let w = World::new(952);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    j.recover().unwrap();
    let quarantined = w.quarantined();
    assert!(quarantined > 0);
    write(&store, &mut j, 2);
    j.sync().unwrap(); // flushes the pocket's data and key directories
    drop(j);
    drop(store);
    w.sim.power_loss();
    assert_eq!(
        w.quarantined(),
        quarantined,
        "quarantined files were lost to a power loss"
    );
}

/// At open, shreds run only after the manifest naming the copied records is durable. Here that
/// manifest write fails, then the power goes.
#[test]
fn r3_m2_shreds_at_open_wait_for_the_manifest() {
    let w = World::new(953);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    w.clock.advance(1_100_000_000);
    j.sync().unwrap(); // the marker now names the record
    record_shred_unflushed(&w, &store, &mut j, x, 2); // with the OS only; the shred never ran
    drop(j);
    drop(store);
    w.sim.crash();
    let store = w.store();
    let failing = NoManifestFs {
        inner: w.fs.clone(),
        armed: Arc::new(AtomicBool::new(true)),
    };
    let clock: Arc<dyn Clock> = w.clock.clone();
    let rng: Arc<dyn Rng> = w.rng.clone();
    let opened = Journal::open_with_payloads(Arc::new(failing), clock, rng, &w.data, NEVER, Arc::clone(&store));
    assert!(opened.is_err());
    drop(opened);
    drop(store);
    w.sim.power_loss();
    let (store, _j) = w.restart(false);
    w.assert_never_silent(&store, "r3 m2");
    assert_eq!(
        store.get(pocket(), x).ok(),
        Some(content(1)),
        "a shred ran before the manifest naming its record was durable"
    );
}

/// After a keychain reset a put in the pocket fails closed instead of creating a fresh KEK under
/// which every existing key file would look tampered with.
#[test]
fn r3_l2_a_put_after_a_keychain_reset_fails_closed() {
    let w = World::new(954);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    write(&store, &mut j, 1);
    drop(j);
    drop(store);
    w.sim.crash();
    w.keys.retire_keks_before(pocket(), KekVersion(1_000)).unwrap();
    let store = w.store();
    assert!(w.open(&store).is_err(), "open fails closed");
    assert!(
        matches!(store.put(pocket(), &content(2)), Err(ChunkError::Keyring(_))),
        "a put created a fresh KEK over existing key files"
    );
    assert!(w.open(&store).is_err());
    assert_eq!(w.quarantined(), 0, "missing keys were treated as a loss");
}

/// A shred completed at open that fails midway is finished by the next open, even after its key
/// file is already gone.
#[test]
fn r3_l3_a_shred_failing_midway_at_open_is_finished_by_the_next() {
    let mut hits = Vec::new();
    for k in 0..40u32 {
        let w = World::new(955);
        let store = w.store();
        let mut j = w.open(&store).unwrap();
        let (_, x) = write(&store, &mut j, 1);
        write(&store, &mut j, 2);
        j.sync().unwrap();
        // Write-ahead: the record is durable and the KEK rotated; then the shred stops before
        // removing anything, and the process dies.
        w.fs.fail_key_remove.store(true, Ordering::SeqCst);
        assert!(matches!(j.shred(shredded_record(x, 3)), Err(JournalError::Payload(_))));
        drop(j);
        drop(store);
        w.sim.crash();
        let store = w.store();
        w.sim.fail_sync_after(k);
        let first = w.open(&store);
        w.sim.fail_sync_after(u32::MAX);
        if first.is_ok() {
            continue;
        }
        drop(first);
        let Ok(_j) = w.open(&store) else { continue };
        let versions = w.keys.kek_versions(pocket()).unwrap();
        let readable = store.get(pocket(), x).is_ok();
        if versions.len() > 1 || readable {
            hits.push(format!("fault after {k}: versions {versions:?}, readable {readable}"));
        }
    }
    assert!(
        hits.is_empty(),
        "a retried open left a shred unfinished:\n{}",
        hits.join("\n")
    );
}

/// A marker a plain journal wrote says nothing about payloads, so the first open with a store still
/// checks the whole journal.
#[test]
fn r4_m1_a_plain_journals_marker_does_not_skip_the_payload_check() {
    let w = World::new(960);
    let plain = || {
        let clock: Arc<dyn Clock> = w.clock.clone();
        let rng: Arc<dyn Rng> = w.rng.clone();
        Journal::open(Arc::new(w.fs.clone()), clock, rng, &w.data, NEVER)
    };
    let strict = w.try_store(ChunkDurability::Strict).unwrap();
    let mut j = plain().unwrap();
    let x = strict.put(pocket(), &content(1)).unwrap();
    j.append(draft(Some(pocket()), Some(x), 1)).unwrap();
    let never_stored = strict.reference(pocket(), &content(2)).unwrap();
    let unchecked = j.append(draft(Some(pocket()), Some(never_stored), 2)).unwrap().seq.0;
    j.sync().unwrap();
    drop(j);
    drop(plain().unwrap()); // a plain reopen writes a marker naming the last record
    drop(strict);
    w.sim.crash();
    let store = w.store();
    let _j = w.open(&store).unwrap();
    assert!(
        w.survey().1.contains(&unchecked),
        "the first open with a store trusted a plain journal's marker"
    );
    w.assert_never_silent(&store, "r4 m1");
}

/// A shred through the journal leaves the re-wrap of the pocket's other keys until the writer is
/// free; the old KEK lives until then, and dropping the remainder finishes it too.
#[test]
fn r4_m2_the_rewrap_runs_after_the_writer_is_free() {
    let w = World::new(961);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let chunks: Vec<ChunkRef> = (0..20).map(|n| write(&store, &mut j, n).1).collect();
    j.sync().unwrap();
    let rewrap = j.shred(shredded_record(chunks[0], 100)).unwrap();
    write(&store, &mut j, 101); // the writer takes records while the re-wrap is still to run
    assert_eq!(
        w.keys.kek_versions(pocket()).unwrap().len(),
        2,
        "the shred re-wrapped the pocket while it held the writer"
    );
    let report = rewrap.finish().unwrap();
    assert!(report.removed);
    assert_eq!(
        report.rewrapped, 20,
        "the 19 older keys and the one written since the rotation"
    );
    assert_eq!(w.keys.kek_versions(pocket()).unwrap().len(), 1);
    drop(j.shred(shredded_record(chunks[1], 102)).unwrap());
    assert_eq!(
        w.keys.kek_versions(pocket()).unwrap().len(),
        1,
        "a dropped re-wrap left the old KEK alive"
    );
    for c in &chunks[2..] {
        assert!(store.get(pocket(), *c).is_ok());
    }
    j.sync().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "r4 m2");
    assert_eq!(store.get(pocket(), chunks[0]).err(), Some(ChunkError::Unavailable));
}

/// A put whose write overlaps a failed directory flush is not acknowledged, even when a recovery
/// cleared the poisoning before it joined the pending set; the next recovery rewrites it.
#[test]
fn r4_l1_a_put_spanning_a_failed_directory_flush_is_recovered_with_it() {
    let w = World::new(962);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    write(&store, &mut j, 1);
    w.fs.key_write.arm();
    let t = {
        let s = Arc::clone(&store);
        std::thread::spawn(move || s.put(pocket(), &content(2)))
    };
    w.fs.key_write.wait_held(); // its data file is written, its key file not yet
    w.sim.fail_sync_after(2); // both files of chunk 1 flush, then the data-directory flush fails
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    j.recover().unwrap();
    assert!(!store.is_poisoned());
    w.fs.key_write.release();
    assert_eq!(
        t.join().unwrap().err(),
        Some(ChunkError::FlushFailed),
        "a put spanning the failed flush was acknowledged after recovery missed it"
    );
    assert!(store.is_poisoned(), "the put left no recovery to include it");
    j.recover().unwrap();
    let y = write(&store, &mut j, 2).1;
    j.sync().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "r4 l1");
    assert_eq!(store.get(pocket(), y).ok(), Some(content(2)));
}

/// A keyring whose next rotation fails, once.
#[derive(Debug)]
struct FailRotate {
    inner: Arc<MemoryKeyring>,
    fail: AtomicBool,
}

impl PocketKeyring for FailRotate {
    fn cas_key(&self, p: PocketId) -> Result<Arc<uaos_platform::crypto::SecretKey>, KeyringError> {
        self.inner.cas_key(p)
    }
    fn current_kek(&self, p: PocketId) -> Result<(KekVersion, Arc<uaos_platform::crypto::SecretKey>), KeyringError> {
        self.inner.current_kek(p)
    }
    fn kek(&self, p: PocketId, v: KekVersion) -> Result<Arc<uaos_platform::crypto::SecretKey>, KeyringError> {
        self.inner.kek(p, v)
    }
    fn rotate_kek(&self, p: PocketId) -> Result<KekVersion, KeyringError> {
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(KeyringError::Unavailable("injected".to_owned()));
        }
        self.inner.rotate_kek(p)
    }
    fn retire_keks_before(&self, p: PocketId, v: KekVersion) -> Result<(), KeyringError> {
        self.inner.retire_keks_before(p, v)
    }
    fn kek_versions(&self, p: PocketId) -> Result<Vec<KekVersion>, KeyringError> {
        self.inner.kek_versions(p)
    }
}

/// Whichever step of a shred fails after its record is durable (here the KEK rotation, then a file
/// removal), the store neither vouches for the content nor serves it until it is stored again, and
/// the next open completes the shred.
#[test]
fn r4_l2_a_failed_shred_never_vouches_for_its_content() {
    for rotation_fails in [true, false] {
        let w = World::new(963);
        let keys = Arc::new(FailRotate {
            inner: Arc::clone(&w.keys),
            fail: AtomicBool::new(false),
        });
        let rng: Arc<dyn Rng> = w.rng.clone();
        let k: Arc<dyn PocketKeyring> = keys.clone();
        let store = Arc::new(
            ChunkStore::open_with(Arc::new(w.fs.clone()), rng, k, &w.data, ChunkDurability::Balanced).unwrap(),
        );
        let mut j = w.open(&store).unwrap();
        let (_, x) = write(&store, &mut j, 1);
        let (_, kept) = write(&store, &mut j, 2);
        j.sync().unwrap();
        if rotation_fails {
            keys.fail.store(true, Ordering::SeqCst);
        } else {
            w.fs.fail_key_remove.store(true, Ordering::SeqCst);
        }
        assert!(matches!(j.shred(shredded_record(x, 3)), Err(JournalError::Payload(_))));
        assert_eq!(
            j.append(draft(Some(pocket()), Some(x), 4)).err(),
            Some(JournalError::PayloadNotStored),
            "rotation fails {rotation_fails}: a record referenced content whose shred is recorded"
        );
        assert_eq!(store.get(pocket(), x).err(), Some(ChunkError::Unavailable));
        assert!(store.get(pocket(), kept).is_ok());
        j.sync().unwrap();
        drop(j);
        drop(store);
        let (store, _j) = w.restart(true);
        w.assert_never_silent(&store, "r4 l2");
        assert_eq!(store.get(pocket(), x).err(), Some(ChunkError::Unavailable));
        assert_eq!(w.keys.kek_versions(pocket()).unwrap().len(), 1);
    }
}

/// Storing the content again after a failed shred makes it referenceable.
#[test]
fn r4_l2_storing_the_content_again_lifts_the_refusal() {
    let w = World::new(964);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    j.sync().unwrap();
    w.fs.fail_key_remove.store(true, Ordering::SeqCst);
    assert!(j.shred(shredded_record(x, 2)).is_err());
    assert_eq!(store.put(pocket(), &content(1)).unwrap(), x);
    assert_eq!(
        store.pending_len(),
        0,
        "a put wrote a fresh pair with the journal over the pair a failed shred left"
    );
    let again = j.append(draft(Some(pocket()), Some(x), 3)).unwrap().seq.0;
    w.clock.advance(1_100_000_000);
    j.sync().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "r4 l2 again");
    assert!(w.survey().0.iter().any(|(s, _, _)| *s == again));
    assert_eq!(store.get(pocket(), x).ok(), Some(content(1)));
}

/// A keyring that counts how often it is asked for a pocket's KEK versions.
#[derive(Debug)]
struct CountVersions {
    inner: Arc<MemoryKeyring>,
    calls: AtomicUsize,
}

impl PocketKeyring for CountVersions {
    fn cas_key(&self, p: PocketId) -> Result<Arc<uaos_platform::crypto::SecretKey>, KeyringError> {
        self.inner.cas_key(p)
    }
    fn current_kek(&self, p: PocketId) -> Result<(KekVersion, Arc<uaos_platform::crypto::SecretKey>), KeyringError> {
        self.inner.current_kek(p)
    }
    fn kek(&self, p: PocketId, v: KekVersion) -> Result<Arc<uaos_platform::crypto::SecretKey>, KeyringError> {
        self.inner.kek(p, v)
    }
    fn rotate_kek(&self, p: PocketId) -> Result<KekVersion, KeyringError> {
        self.inner.rotate_kek(p)
    }
    fn retire_keks_before(&self, p: PocketId, v: KekVersion) -> Result<(), KeyringError> {
        self.inner.retire_keks_before(p, v)
    }
    fn kek_versions(&self, p: PocketId) -> Result<Vec<KekVersion>, KeyringError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.kek_versions(p)
    }
}

/// Open asks the keychain for a pocket's KEK versions once, however many shreds the journal records
/// in it.
#[test]
fn r4_l3_open_asks_the_keychain_once_per_pocket() {
    let w = World::new(965);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let chunks: Vec<ChunkRef> = (0..10).map(|n| write(&store, &mut j, n).1).collect();
    j.sync().unwrap();
    for (n, c) in (100..).zip(&chunks) {
        j.shred(shredded_record(*c, n)).unwrap().finish().unwrap();
    }
    drop(j);
    drop(store);
    w.sim.crash();
    let keys = Arc::new(CountVersions {
        inner: Arc::clone(&w.keys),
        calls: AtomicUsize::new(0),
    });
    let rng: Arc<dyn Rng> = w.rng.clone();
    let k: Arc<dyn PocketKeyring> = keys.clone();
    let store =
        Arc::new(ChunkStore::open_with(Arc::new(w.fs.clone()), rng, k, &w.data, ChunkDurability::Balanced).unwrap());
    keys.calls.store(0, Ordering::SeqCst);
    let _j = w.open(&store).unwrap();
    assert_eq!(
        keys.calls.load(Ordering::SeqCst),
        1,
        "open asked the keychain once per recorded shred"
    );
}

/// The first open with a store fails after writing `PAYLOADS` (here, a full disk while it journals
/// the loss it found). The plain journal's marker must still not be trusted by the next open, in
/// the same process or after a crash.
#[test]
fn r5_m1_a_failed_first_open_with_a_store_does_not_trust_the_plain_marker() {
    for crash_between in [false, true] {
        let w = World::new(970);
        let plain = || {
            let clock: Arc<dyn Clock> = w.clock.clone();
            let rng: Arc<dyn Rng> = w.rng.clone();
            Journal::open(Arc::new(w.fs.clone()), clock, rng, &w.data, NEVER)
        };
        let strict = w.try_store(ChunkDurability::Strict).unwrap();
        let mut j = plain().unwrap();
        let x = strict.put(pocket(), &content(1)).unwrap();
        j.append(draft(Some(pocket()), Some(x), 1)).unwrap();
        let never_stored = strict.reference(pocket(), &content(2)).unwrap();
        let unchecked = j.append(draft(Some(pocket()), Some(never_stored), 2)).unwrap().seq.0;
        j.sync().unwrap();
        drop(j);
        drop(plain().unwrap()); // the plain marker now names `unchecked`
        drop(strict);
        w.sim.crash();
        let mut store = w.store();
        w.fs.fail_segment_append_after(0); // the chunk.lost append of the first open with a store
        assert!(w.open(&store).is_err(), "the first open with a store should fail here");
        w.fs.clear_append_fault();
        if crash_between {
            drop(store);
            w.sim.crash();
            store = w.store();
        }
        let j = w.open(&store).unwrap();
        assert!(
            w.survey().1.contains(&unchecked),
            "crash between {crash_between}: after a failed first open, the plain marker was trusted"
        );
        drop(j);
        drop(store);
        let (store, _j) = w.restart(true);
        w.assert_never_silent(&store, "r5 m1");
    }
}

/// A journal flush is not acknowledged across a failed flushed write elsewhere in the store (here a
/// re-wrap's `keys/` flush on another thread, which may have dropped the pending chunk's entry);
/// the next recovery rewrites the pending chunk.
#[test]
fn r5_m2_a_flush_is_not_acknowledged_across_a_failed_rewrap() {
    let w = World::new(973);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let chunks: Vec<ChunkRef> = (0..4).map(|n| write(&store, &mut j, n).1).collect();
    j.sync().unwrap();
    let rewrap = j.shred(shredded_record(chunks[0], 100)).unwrap();
    let pending = write(&store, &mut j, 101).1; // pending in the same pocket, its record unflushed
    assert_eq!(store.pending_len(), 1);
    w.fs.key_write.arm();
    let rewrapping = std::thread::spawn(move || rewrap.finish());
    w.fs.key_write.wait_held(); // the re-wrap holds the stripe and the flush window
    w.sim.fail_sync_after(1); // the re-wrap's file flush passes, its keys/ flush fails
    let synced = std::thread::scope(|s| {
        let t = s.spawn(|| j.sync());
        std::thread::sleep(Duration::from_millis(100));
        w.fs.key_write.release();
        t.join().unwrap()
    });
    let finished = rewrapping.join().unwrap();
    w.sim.fail_sync_after(u32::MAX);
    assert!(finished.is_err(), "the re-wrap's flush was meant to fail");
    assert_eq!(
        synced,
        Err(JournalError::PayloadFlushFailed),
        "a journal flush was acknowledged across a failed flush of the same directory"
    );
    assert_eq!(store.pending_len(), 1, "the batch was dropped from the pending set");
    j.recover().unwrap();
    j.sync().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "r5 m2");
    assert_eq!(store.get(pocket(), pending).ok(), Some(content(101)));
}

/// A put whose own write fails does not lift a failed shred's refusal.
#[test]
fn r5_l1_a_failed_put_keeps_a_failed_shred_refused() {
    let w = World::new(971);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    j.sync().unwrap();
    w.fs.fail_key_remove.store(true, Ordering::SeqCst);
    assert!(j.shred(shredded_record(x, 2)).is_err());
    w.sim.fail_sync_after(0); // the put's flushed rewrite fails
    assert!(store.put(pocket(), &content(1)).is_err());
    w.sim.fail_sync_after(u32::MAX);
    j.recover().unwrap();
    assert_eq!(
        store.get(pocket(), x).err(),
        Some(ChunkError::Unavailable),
        "a failed put lifted the refusal of a failed shred"
    );
    assert_eq!(
        j.append(draft(Some(pocket()), Some(x), 3)).err(),
        Some(JournalError::PayloadNotStored),
        "a failed put lifted the refusal of a failed shred"
    );
    j.sync().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "r5 l1 put");
    assert_eq!(store.get(pocket(), x).err(), Some(ChunkError::Unavailable));
}

/// A shred whose own flush fails marks the chunk anyway; once `recover` makes the shred record
/// durable, no record can reference the content and the next open completes it.
#[test]
fn r5_l1_a_shred_whose_flush_failed_stays_refused() {
    let w = World::new(972);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    j.sync().unwrap();
    w.fs.fail_segment_append_after(1); // the shred record passes, the rewrite's copy fails
    w.sim.fail_sync_after(0); // the segment flush fails
    assert!(j.shred(shredded_record(x, 2)).is_err());
    w.fs.clear_append_fault();
    w.sim.fail_sync_after(u32::MAX);
    j.recover().unwrap(); // the shred record is now durable
    assert!(w.survey().2.iter().any(|(_, c, _)| *c == x.to_string()));
    assert_eq!(
        j.append(draft(Some(pocket()), Some(x), 3)).err(),
        Some(JournalError::PayloadNotStored),
        "a record referenced content whose shred record is durable"
    );
    j.sync().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "r5 l1 flush");
    assert_eq!(store.get(pocket(), x).err(), Some(ChunkError::Unavailable));
}

/// A re-wrap whose `keys/` flush fails leaves its new key file visible but not durable; a later
/// re-wrap must not skip it as already current and retire the old KEK, or a power loss leaves a key
/// file only the retired KEK opens.
#[test]
fn r5_a_failed_rewrap_never_leaves_a_key_only_a_retired_kek_opens() {
    let mut hits = Vec::new();
    for k in 0..8u32 {
        let w = World::new(975);
        let store = w.store();
        let mut j = w.open(&store).unwrap();
        let chunks: Vec<ChunkRef> = (1..=3).map(|n| write(&store, &mut j, n).1).collect();
        let first = j.shred(shredded_record(chunks[1], 10)).unwrap();
        let second = j.shred(shredded_record(chunks[1], 11)).unwrap();
        w.sim.fail_sync_after(k);
        let failed = first.finish().is_err();
        w.sim.fail_sync_after(u32::MAX);
        let _outcome = second.finish();
        drop(j);
        drop(store);
        w.sim.power_loss();
        let store = w.store();
        match w.open(&store) {
            Ok(_j) => {
                for (n, c) in [(1, chunks[0]), (3, chunks[2])] {
                    if store.get(pocket(), c).ok() != Some(content(n)) {
                        hits.push(format!(
                            "fault after {k} (re-wrap failed: {failed}): payload {n} unreadable"
                        ));
                    }
                }
            }
            Err(e) => hits.push(format!(
                "fault after {k} (re-wrap failed: {failed}): open failed: {e:?}"
            )),
        }
    }
    assert!(
        hits.is_empty(),
        "a re-wrap retired a KEK a durable key file still needed:
{}",
        hits.join(
            "
"
        )
    );
}

/// A direct `sync_pending` whose own directory flush fails poisons the store inside the flush
/// window, so a concurrent journal flush cannot acknowledge its batch in between.
#[test]
fn r6_l1_a_failed_direct_store_flush_is_seen_by_a_concurrent_journal_flush() {
    let w = World::new(980);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    write(&store, &mut j, 1);
    assert_eq!(store.pending_len(), 1);
    w.fs.dir_sync_fail.arm();
    w.sim.fail_sync_after(2); // the direct flush's two file flushes pass, its data/ flush fails
    let direct = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || store.sync_pending())
    };
    w.fs.dir_sync_fail.wait_held(); // failed in the OS, not yet back in the store
    let synced = std::thread::scope(|s| {
        let t = s.spawn(|| j.sync());
        std::thread::sleep(Duration::from_millis(100));
        w.fs.dir_sync_fail.release();
        t.join().unwrap()
    });
    assert!(direct.join().unwrap().is_err());
    assert!(store.is_poisoned());
    assert_eq!(
        synced,
        Err(JournalError::PayloadFlushFailed),
        "a journal flush was acknowledged across a failed flush of the same directory"
    );
    assert_eq!(store.pending_len(), 1, "the batch was dropped from the pending set");
}

/// A put of the same content while `Journal::shred` runs lifts the mark; if the shred's flush then
/// fails, the chunk is refused again, since the record can still become durable.
#[test]
fn r6_l2_a_put_during_a_shred_whose_flush_fails_does_not_lift_the_refusal() {
    let w = World::new(981);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    j.sync().unwrap();
    w.fs.fail_segment_append_after(1); // the shred record passes, the rewrite's copy fails
    w.sim.fail_sync_after(0); // the segment flush fails
    w.fs.segment_append.arm(); // holds the shred record's append, after `begin_shred`
    let shred = std::thread::scope(|s| {
        let t = s.spawn(|| j.shred(shredded_record(x, 2)).map(drop));
        w.fs.segment_append.wait_held();
        assert_eq!(store.put(pocket(), &content(1)).unwrap(), x); // another request, same content
        w.fs.segment_append.release();
        t.join().unwrap()
    });
    assert!(shred.is_err());
    w.fs.clear_append_fault();
    w.sim.fail_sync_after(u32::MAX);
    j.recover().unwrap(); // the shred record is now durable
    assert!(w.survey().2.iter().any(|(_, c, _)| *c == x.to_string()));
    assert_eq!(
        j.append(draft(Some(pocket()), Some(x), 3)).err(),
        Some(JournalError::PayloadNotStored),
        "a record referenced content whose shred record is durable"
    );
}

/// A shred refused before its record is written (here a malformed record) leaves the content as it
/// was.
#[test]
fn r6_l3_a_shred_refused_before_its_record_leaves_the_content_alone() {
    let w = World::new(982);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    j.sync().unwrap();
    let mut bad = shredded_record(x, 2);
    bad.payload_ref = Some(x);
    assert!(matches!(j.shred(bad), Err(JournalError::InvalidRecord(_))));
    assert!(w.survey().2.is_empty(), "no shred record exists");
    assert_eq!(
        store.get(pocket(), x).ok(),
        Some(content(1)),
        "content with no shred record is refused"
    );
    j.append(draft(Some(pocket()), Some(x), 3)).unwrap();
}

/// Shreds refused by a stopped writer (a full disk) leave no mark behind, so the backlog holds only
/// shreds whose record exists.
#[test]
fn r6_l3_a_disk_full_episode_leaves_no_shred_backlog() {
    let w = World::new(983);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 0);
    j.sync().unwrap();
    w.fs.fail_segment_append_after(0);
    assert_eq!(
        j.append(draft(Some(pocket()), None, 99)).err(),
        Some(JournalError::DiskFull)
    );
    for n in 1..=u64::try_from(MAX_UNFINISHED_SHREDS).unwrap() {
        let r = store.reference(pocket(), &content(n)).unwrap();
        assert_eq!(j.shred(shredded_record(r, n)).err(), Some(JournalError::DiskFull));
    }
    j.recover().unwrap();
    assert!(w.survey().2.is_empty(), "no shred record exists");
    assert!(
        j.shred(shredded_record(x, 0)).map(drop).is_ok(),
        "a healthy journal refused a shred: the backlog held shreds that never reached their record"
    );
}

/// A keyring whose first `kek` lookup, once armed, is held before it runs.
#[derive(Debug)]
struct GateKek {
    inner: Arc<MemoryKeyring>,
    gate: Arc<Gate>,
}

impl PocketKeyring for GateKek {
    fn cas_key(&self, p: PocketId) -> Result<Arc<uaos_platform::crypto::SecretKey>, KeyringError> {
        self.inner.cas_key(p)
    }
    fn current_kek(&self, p: PocketId) -> Result<(KekVersion, Arc<uaos_platform::crypto::SecretKey>), KeyringError> {
        self.inner.current_kek(p)
    }
    fn kek(&self, p: PocketId, v: KekVersion) -> Result<Arc<uaos_platform::crypto::SecretKey>, KeyringError> {
        self.gate.hold_if_armed();
        self.inner.kek(p, v)
    }
    fn rotate_kek(&self, p: PocketId) -> Result<KekVersion, KeyringError> {
        self.inner.rotate_kek(p)
    }
    fn retire_keks_before(&self, p: PocketId, v: KekVersion) -> Result<(), KeyringError> {
        self.inner.retire_keks_before(p, v)
    }
    fn kek_versions(&self, p: PocketId) -> Result<Vec<KekVersion>, KeyringError> {
        self.inner.kek_versions(p)
    }
}

/// A put that reads back stored content holds the stripe, so a re-wrap finishing meanwhile waits
/// for it instead of retiring the KEK it is unwrapping with.
#[test]
fn r6_l4_a_put_reading_back_content_is_not_failed_by_a_finishing_rewrap() {
    let w = World::new(984);
    {
        let store = w.store();
        let mut j = w.open(&store).unwrap();
        write(&store, &mut j, 1);
        write(&store, &mut j, 2);
        w.clock.advance(1_100_000_000);
        j.sync().unwrap(); // the marker passes both records, so the next open leaves them unread
    }
    w.sim.crash();
    let gate = Arc::new(Gate::default());
    let keys: Arc<dyn PocketKeyring> = Arc::new(GateKek {
        inner: Arc::clone(&w.keys),
        gate: Arc::clone(&gate),
    });
    let rng: Arc<dyn Rng> = w.rng.clone();
    let store =
        Arc::new(ChunkStore::open_with(Arc::new(w.fs.clone()), rng, keys, &w.data, ChunkDurability::Balanced).unwrap());
    let mut j = w.open(&store).unwrap();
    let b = store.reference(pocket(), &content(2)).unwrap();
    let rewrap = j.shred(shredded_record(b, 10)).unwrap();
    gate.arm();
    let put = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || store.put(pocket(), &content(1)))
    };
    gate.wait_held(); // the put has read the key file of content 1 (version 1)
    let rewrapping = std::thread::spawn(move || rewrap.finish());
    std::thread::sleep(Duration::from_millis(300)); // a re-wrap that does not wait finishes now
    gate.release();
    assert_eq!(
        put.join().unwrap().err(),
        None,
        "a put of stored content failed because a re-wrap finished while it read the pair"
    );
    assert!(rewrapping.join().unwrap().is_ok());
}

/// Under the default flush policy the shred record's own append runs the due flush; when that flush
/// fails after the record was written, the chunk stays refused, since `recover` makes the record
/// durable.
#[test]
fn r7_m1_a_shred_whose_flush_inside_append_fails_stays_refused() {
    let w = World::new(7001);
    let store = w.store();
    let mut j = w.open_with(&store, FlushPolicy::default()).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    j.sync().unwrap();
    w.clock.advance(100_000_000); // 100 ms: the next append finds the 50 ms window due
    w.fs.fail_segment_append_after(1); // the shred record passes, the rewrite's copy fails
    w.sim.fail_sync_after(0); // the segment flush inside append fails
    assert!(j.shred(shredded_record(x, 2)).is_err());
    w.fs.clear_append_fault();
    w.sim.fail_sync_after(u32::MAX);
    j.recover().unwrap();
    assert!(
        w.survey().2.iter().any(|(_, c, _)| *c == x.to_string()),
        "the shred record is durable"
    );
    assert_eq!(
        j.append(draft(Some(pocket()), Some(x), 3)).err(),
        Some(JournalError::PayloadNotStored),
        "a record referenced content whose shred record is durable"
    );
    j.sync().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "r7 m1");
    assert_eq!(store.get(pocket(), x).err(), Some(ChunkError::Unavailable));
}

/// The same through a failed payload flush inside the append (strict policy).
#[test]
fn r7_m1_a_shred_whose_payload_flush_inside_append_fails_stays_refused() {
    let w = World::new(7002);
    let store = w.store();
    let mut j = w.open_with(&store, FlushPolicy::Strict).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    let _pending = store.put(pocket(), &content(9)).unwrap(); // no record yet
    assert_eq!(store.pending_len(), 1);
    w.sim.fail_sync_after(0); // the pending chunk's flush inside the append's sync fails
    assert!(j.shred(shredded_record(x, 2)).is_err());
    w.sim.fail_sync_after(u32::MAX);
    j.recover().unwrap();
    assert!(w.survey().2.iter().any(|(_, c, _)| *c == x.to_string()));
    assert_eq!(
        j.append(draft(Some(pocket()), Some(x), 3)).err(),
        Some(JournalError::PayloadNotStored),
        "a record referenced content whose shred record is durable"
    );
}

/// Shreds left unfinished by failures are bounded; past the bound a shred is refused before its
/// record, and retrying them clears the backlog.
#[test]
fn r5_l3_unfinished_shreds_are_bounded() {
    let w = World::new(974);
    let keys = Arc::new(FailRotate {
        inner: Arc::clone(&w.keys),
        fail: AtomicBool::new(false),
    });
    let rng: Arc<dyn Rng> = w.rng.clone();
    let k: Arc<dyn PocketKeyring> = keys.clone();
    let store =
        Arc::new(ChunkStore::open_with(Arc::new(w.fs.clone()), rng, k, &w.data, ChunkDurability::Balanced).unwrap());
    let mut j = w.open(&store).unwrap();
    write(&store, &mut j, 0);
    j.sync().unwrap();
    let refs: Vec<ChunkRef> = (1..=u64::try_from(MAX_UNFINISHED_SHREDS).unwrap() + 1)
        .map(|n| store.reference(pocket(), &content(n)).unwrap())
        .collect();
    for (n, r) in (1..).zip(&refs[..MAX_UNFINISHED_SHREDS]) {
        keys.fail.store(true, Ordering::SeqCst);
        assert!(j.shred(shredded_record(*r, n)).is_err());
    }
    let over = refs[MAX_UNFINISHED_SHREDS];
    assert_eq!(
        j.shred(shredded_record(over, 0)).err(),
        Some(JournalError::Payload(ChunkError::ShredBacklog)),
        "unfinished shreds grew past their bound"
    );
    j.shred(shredded_record(refs[0], 1)).unwrap().finish().unwrap(); // a retry clears its entry
    j.shred(shredded_record(over, 0)).unwrap().finish().unwrap();
}

/// A `chunk.shredded` record that reaches the OS but not the disk, its shred never run.
/// `Journal::append` refuses the record on a coordinated journal, so tests reach this state through
/// the shred: an unrelated put is pending, its flush fails first, and the journal stops before it
/// flushes the segment.
fn record_shred_unflushed(w: &World, store: &ChunkStore, j: &mut Journal, chunk: ChunkRef, n: u64) {
    store.put(pocket(), &content(n + 100)).unwrap();
    w.sim.fail_next_sync();
    let before = j.next_seq().0;
    assert_eq!(
        j.shred(shredded_record(chunk, n)).err(),
        Some(JournalError::PayloadFlushFailed),
        "the store's flush did not fail first"
    );
    assert!(j.next_seq().0 > before, "the shred record was not written");
    w.sim.fail_sync_after(u32::MAX);
}

/// With a store attached, `chunk.shredded` goes only through `Journal::shred` and `chunk.lost`
/// comes only from the journal's own loss reporting. A shred record appended directly recorded a
/// shred that never marked or removed the content (the next open shredded it, and a record after it
/// needed no put); a forged `chunk.lost` excluded a healthy record from every later payload check.
#[test]
fn r9_l1_kernel_records_cannot_be_appended_directly() {
    let w = World::new(9001);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, x) = write(&store, &mut j, 1);
    j.sync().unwrap();
    let before = j.next_seq().0;
    assert!(
        matches!(j.append(shredded_record(x, 2)), Err(JournalError::InvalidRecord(_))),
        "a chunk.shredded record was appended directly"
    );
    let mut lost = draft(Some(pocket()), None, 3);
    lost.event_type = types::CHUNK_LOST;
    lost.metadata = Metadata::new(
        [
            (CHUNK_METADATA_KEY.to_owned(), x.to_string()),
            (RECORD_SEQ_METADATA_KEY.to_owned(), seq.to_string()),
        ]
        .into_iter()
        .collect(),
    )
    .unwrap();
    assert!(
        matches!(j.append(lost), Err(JournalError::InvalidRecord(_))),
        "a chunk.lost record was appended directly"
    );
    assert_eq!(j.next_seq().0, before, "a kernel record was written");
    // A record referencing the content still needs nothing more: no shred was recorded.
    j.append(draft(Some(pocket()), Some(x), 4)).unwrap();
    j.sync().unwrap();
    drop(j);
    drop(store);
    let (store, j) = w.restart(true);
    assert_eq!(
        store.get(pocket(), x).ok(),
        Some(content(1)),
        "content no shred removed is gone"
    );
    assert!(j.lost_payloads().is_empty());
    let (_, reported, shreds) = w.survey();
    assert!(reported.is_empty() && shreds.is_empty(), "a kernel record was written");
}

/// A coordinated store's recovery and losses go through its journal. A caller that took the store's
/// losses, or recovered it itself, let the records referencing a lost payload become durable with
/// no `chunk.lost` record.
#[test]
fn r10_l1_a_coordinated_stores_losses_go_through_its_journal() {
    // A caller tries to take the losses after a failed payload flush.
    let w = World::new(1010);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, x) = write(&store, &mut j, 1); // pending, unflushed
    w.sim.fail_next_sync(); // the payload flush fails; the unflushed bytes are dropped
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    assert_eq!(
        store.recover_pending(),
        Err(ChunkError::LossesThroughJournal),
        "a caller recovered a coordinated store"
    );
    assert_eq!(store.take_lost().err(), Some(ChunkError::LossesThroughJournal));
    assert_eq!(
        store.verify_and_sync(&[(pocket(), x)]),
        Err(ChunkError::LossesThroughJournal)
    );
    w.clock.advance(1_100_000_000); // the marker may move on the next flush
    j.recover().unwrap();
    assert_eq!(j.lost_payloads().len(), 1, "the journal did not report the loss");
    assert!(w.survey().1.contains(&seq));
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "r10 l1, taken");

    // A caller's own flush fails and poisons the store; the journal's next flush refuses, and
    // its recovery reports the loss first.
    let w = World::new(1011);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _x) = write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert!(store.sync_pending().is_err());
    assert_eq!(store.recover_pending(), Err(ChunkError::LossesThroughJournal));
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    j.recover().unwrap();
    assert!(
        w.survey().1.contains(&seq),
        "record {seq} became durable before its loss record"
    );
    assert_eq!(
        j.flushed_through().map(|s| s.0),
        Some(seq + 1),
        "the loss record is flushed with it"
    );
}

/// With the writer out of space and the store poisoned by a failed flush of its own, `recover`
/// rotated the segment, returned `Ok` and left the store refusing every put until a later flush
/// failed and a second recovery ran.
#[test]
fn r10_a_recovery_out_of_space_also_recovers_a_poisoned_store() {
    let w = World::new(1013);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    write(&store, &mut j, 1);
    j.sync().unwrap();
    w.fs.fail_segment_append_after(0);
    assert_eq!(
        j.append(draft(Some(pocket()), None, 2)).err(),
        Some(JournalError::DiskFull)
    );
    store.put(pocket(), &content(3)).unwrap(); // pending
    w.sim.fail_next_sync();
    assert!(store.sync_pending().is_err(), "the store's flush did not fail");
    j.recover().unwrap();
    assert!(!store.is_poisoned(), "the store stayed poisoned after an Ok recovery");
    assert_eq!(j.health(), JournalHealth::Healthy);
    store.put(pocket(), &content(4)).unwrap();
}

/// An append that runs out of space leaves half its line in the segment and the writer `DiskFull`.
/// A payload flush failure then replaced `DiskFull` with `PayloadFlushFailed`, which `recover`
/// cleared without leaving the torn segment: later records, the loss record among them, were
/// appended after the torn bytes, and the journal no longer opened. Both ways in: a caller's flush,
/// and a recovery whose own rotation fails.
#[test]
fn r11_h1_a_payload_failure_never_hides_a_torn_segment() {
    for recover_twice in [false, true] {
        let w = World::new(1101);
        let store = w.store();
        let mut j = w.open(&store).unwrap();
        write(&store, &mut j, 1);
        j.sync().unwrap();
        write(&store, &mut j, 2); // unflushed, its payload pending
        w.fs.fail_segment_append_after(0); // the next append writes half its line, then fails
        assert_eq!(
            j.append(draft(Some(pocket()), None, 3)).err(),
            Some(JournalError::DiskFull)
        );
        w.sim.fail_next_sync(); // the store's next flush fails
        if recover_twice {
            assert!(j.recover().is_err(), "the rotation's payload flush did not fail");
        } else {
            assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
        }
        assert_eq!(
            j.health(),
            JournalHealth::DiskFull,
            "a payload failure hid the torn segment"
        );
        j.recover().unwrap();
        let after = j.append(draft(Some(pocket()), None, 4)).unwrap().seq.0;
        j.sync().unwrap();
        drop(j);
        drop(store);
        let (store, j) = w.restart(false); // fails if a record follows torn bytes
        assert!(j.next_seq().0 > after, "the record after the recovery is gone");
        w.assert_never_silent(&store, "r11 h1");
    }
}

/// A loss still waiting to be journaled was queued again when the same content was stored and lost
/// once more before the report succeeded, so one record got two `chunk.lost` records.
#[test]
fn r11_l1_a_loss_is_queued_once() {
    let w = World::new(1103);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, x) = write(&store, &mut j, 1); // unflushed, its payload pending
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed)); // the payload is dropped
    w.fs.fail_segment_append_after(0); // the loss record's append fails
    assert_eq!(j.recover().err(), Some(JournalError::DiskFull));
    // The store still takes puts while the journal refuses records.
    assert_eq!(store.put(pocket(), &content(1)).unwrap(), x);
    w.sim.fail_next_sync();
    assert!(store.sync_pending().is_err()); // lost again
    j.recover().unwrap();
    let (records, _) = read_verified(&w.sim, &w.data.join(JOURNAL_DIR)).unwrap();
    let reports = records
        .iter()
        .filter(|r| r.envelope.event_type == types::CHUNK_LOST)
        .filter(|r| r.envelope.metadata.as_map().get(RECORD_SEQ_METADATA_KEY) == Some(&seq.to_string()))
        .count();
    assert_eq!(reports, 1, "record {seq} has {reports} chunk.lost records");
}

/// Content whose loss was journaled read back as `Unavailable`, whose message says "never stored or
/// shredded"; it reads back as lost (`STORE_PAYLOAD_LOST`), also after a restart.
#[test]
fn r12_l3_lost_content_reads_back_as_lost() {
    let w = World::new(1201);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, x) = write(&store, &mut j, 1); // unflushed, its payload pending
    w.sim.fail_next_sync(); // the payload's bytes are dropped
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    j.recover().unwrap();
    assert!(w.survey().1.contains(&seq), "the loss was not journaled");
    assert_eq!(
        store.get(pocket(), x),
        Err(ChunkError::Lost),
        "lost content read back as never stored or shredded"
    );
    drop(j);
    drop(store);
    let (store, _j) = w.restart(false);
    assert_eq!(store.get(pocket(), x), Err(ChunkError::Lost));
    assert_eq!(
        ChunkError::Lost.code(),
        uaos_contracts::error::codes::STORE_PAYLOAD_LOST
    );
    // Stored again, it reads back.
    store.put(pocket(), &content(1)).unwrap();
    assert_eq!(store.get(pocket(), x).ok(), Some(content(1)));
}

/// An open that finds one lost chunk referenced by more records than it lists journals a loss for
/// every one and lists the latest `MAX_LOST_LISTED`.
#[test]
fn r10_l2_every_loss_at_open_is_journaled_and_the_list_is_bounded() {
    let w = World::new(1012);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let n = u64::try_from(MAX_LOST_LISTED).unwrap() + 100;
    let x = store.put(pocket(), &content(1)).unwrap();
    for i in 0..n {
        j.append(draft(Some(pocket()), Some(x), i)).unwrap();
    }
    j.sync().unwrap();
    drop(j);
    drop(store);
    w.sim.crash();
    let name = x.to_string()["hmac-sha256:".len()..].to_owned();
    let data = w.data.join(CHUNKS_DIR).join(pocket().to_string()).join("data");
    w.sim.remove_file(&data.join(format!("{name}.chunk"))).unwrap();
    let store = w.store();
    let j = w.open(&store).unwrap();
    assert_eq!(j.lost_payloads().len(), MAX_LOST_LISTED);
    assert_eq!(
        j.lost_payloads().last().map(|l| l.record_seq.0),
        Some(n - 1),
        "not the latest"
    );
    assert_eq!(
        w.survey().1.len(),
        usize::try_from(n).unwrap(),
        "a referencing record has no loss record"
    );
}

/// Files with extension `ext` in `dir`.
fn files_in(w: &World, dir: &Path, ext: &str) -> Vec<PathBuf> {
    w.sim
        .list_dir(dir)
        .map(|v| {
            v.into_iter()
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some(ext))
                .collect()
        })
        .unwrap_or_default()
}

/// The OS writes something back on its own, in no order across files: 0, the segments and their
/// directory; 1, the chunk directories' entries only; 2, segments and key files; 3, segments and
/// data files; 4, part of the segments; 5, the segments and part of the chunk files with their
/// entries; 6, part of both.
fn write_back(w: &World, kind: u8) {
    let journal = w.data.join(JOURNAL_DIR);
    let pocket_dir = w.data.join(CHUNKS_DIR).join(pocket().to_string());
    if kind >= 4 {
        let (num, den) = (1 + usize::from(kind) % 3, 4);
        for p in files_in(w, &journal, "jsonl") {
            if kind == 5 {
                w.sim.write_back(&p);
            } else {
                w.sim.write_back_part(&p, num, den);
            }
        }
        w.sim.write_back_dir(&journal);
        if kind >= 5 {
            for (dir, ext) in [("data", "chunk"), ("keys", "key")] {
                for p in files_in(w, &pocket_dir.join(dir), ext) {
                    w.sim.write_back_part(&p, num, den);
                }
                w.sim.write_back_dir(&pocket_dir.join(dir));
            }
        }
        return;
    }
    if kind != 1 {
        for p in files_in(w, &journal, "jsonl") {
            w.sim.write_back(&p);
        }
        w.sim.write_back_dir(&journal);
    }
    if kind >= 1 {
        for dir in ["data", "keys", QUARANTINE_DIR] {
            w.sim.write_back_dir(&pocket_dir.join(dir));
        }
        w.sim.write_back_dir(&pocket_dir);
    }
    let files = match kind {
        2 => files_in(w, &pocket_dir.join("keys"), "key"),
        3 => files_in(w, &pocket_dir.join("data"), "chunk"),
        _ => Vec::new(),
    };
    for p in files {
        w.sim.write_back(&p);
    }
}

/// The OS wrote back the record, the key file whole and three quarters of the data file, then the
/// power went: the payload is unauthentic.
fn torn_payload_on_disk(w: &World) {
    let pocket_dir = w.data.join(CHUNKS_DIR).join(pocket().to_string());
    write_back(w, 0);
    for p in files_in(w, &pocket_dir.join("keys"), "key") {
        w.sim.write_back(&p);
    }
    for p in files_in(w, &pocket_dir.join("data"), "chunk") {
        w.sim.write_back_part(&p, 3, 4);
    }
    for dir in ["data", "keys"] {
        w.sim.write_back_dir(&pocket_dir.join(dir));
    }
    w.sim.write_back_dir(&pocket_dir);
}

/// A record the OS wrote back without its whole payload is found at open, its payload unauthentic,
/// and journaled as lost. Skipping that cause lost the payload silently, and no schedule could see
/// it: the simulator never wrote anything back on its own.
#[test]
fn r13_l1_an_unauthentic_payload_found_at_open_is_journaled() {
    let w = World::new(1304);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _x) = write(&store, &mut j, 1); // record and payload with the OS, nothing flushed
    torn_payload_on_disk(&w);
    drop(j);
    drop(store);
    let (store, j) = w.restart(true);
    assert!(
        w.survey().1.contains(&seq),
        "record {seq} survived without its payload and with no chunk.lost record"
    );
    assert_eq!(j.lost_payloads().first().map(|l| l.cause), Some(LossCause::Unauthentic));
    w.assert_never_silent(&store, "r13 l1, open");
}

/// A payload whose flush failed after the OS wrote part of it back is found unauthentic by recovery
/// and journaled as lost.
#[test]
fn r13_l1_an_unauthentic_payload_found_in_recovery_is_journaled() {
    let w = World::new(1305);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _x) = write(&store, &mut j, 1); // its payload pending
    let pocket_dir = w.data.join(CHUNKS_DIR).join(pocket().to_string());
    for p in files_in(&w, &pocket_dir.join("data"), "chunk") {
        w.sim.write_back_part(&p, 3, 4);
    }
    w.sim.fail_next_sync(); // the data file's flush fails, dropping what was not written back
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    j.recover().unwrap();
    assert!(
        w.survey().1.contains(&seq),
        "record {seq} became durable without its payload and with no chunk.lost record"
    );
    assert_eq!(j.lost_payloads().first().map(|l| l.cause), Some(LossCause::Unauthentic));
}

/// The most likely power-loss loss, a record the OS wrote back whose payload never reached the
/// disk, left no file to set aside and read back as never stored or shredded.
#[test]
fn r13_l2_a_missing_payload_reads_back_as_lost() {
    let w = World::new(1301);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, x) = write(&store, &mut j, 1);
    write_back(&w, 0); // the segment only
    drop(j);
    drop(store);
    let (store, j) = w.restart(true);
    assert!(w.survey().1.contains(&seq), "the loss was not journaled");
    assert_eq!(j.lost_payloads().first().map(|l| l.cause), Some(LossCause::Missing));
    assert_eq!(
        store.get(pocket(), x),
        Err(ChunkError::Lost),
        "a journaled loss reads back as never stored or shredded"
    );
}

/// Content lost once, stored again and then shredded on purpose reads back as shredded, not lost;
/// content lost before any record referenced it reads back as lost with a message that claims no
/// `chunk.lost` record.
#[test]
fn r13_l3_lost_then_shredded_reads_back_as_shredded() {
    let w = World::new(1302);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    j.recover().unwrap();
    assert_eq!(store.get(pocket(), x), Err(ChunkError::Lost));
    store.put(pocket(), &content(1)).unwrap();
    j.append(draft(Some(pocket()), Some(x), 2)).unwrap();
    j.sync().unwrap();
    j.shred(shredded_record(x, 3)).unwrap().finish().unwrap();
    assert_eq!(
        store.get(pocket(), x),
        Err(ChunkError::Unavailable),
        "deliberately shredded content reads back as lost"
    );

    let w = World::new(1303);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let y = store.put(pocket(), &content(2)).unwrap(); // no record references it
    j.append(draft(Some(pocket()), None, 1)).unwrap();
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    j.recover().unwrap();
    assert_eq!(store.get(pocket(), y), Err(ChunkError::Lost));
    assert!(w.survey().1.is_empty());
    assert!(
        !ChunkError::Lost.to_string().contains("chunk.lost record"),
        "the message claims a loss record that does not exist"
    );
}

/// A shred of content still pending whose own record flush fails on that content's data file after
/// the OS wrote part of it back. Recovery finds the payload unauthentic, quarantines it and makes
/// the shred record durable; the open must still complete the shred, or the pocket's KEK is never
/// rotated and the quarantined key file still opens the content's data key.
#[test]
fn r14_m1_a_shred_whose_payload_was_quarantined_is_completed() {
    let w = World::new(1405);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_seq, x) = write(&store, &mut j, 1); // payload pending, record unflushed
    let pocket_dir = w.data.join(CHUNKS_DIR).join(pocket().to_string());
    for p in files_in(&w, &pocket_dir.join("data"), "chunk") {
        w.sim.write_back_part(&p, 3, 4);
    }
    let v0 = w.keys.kek_versions(pocket()).unwrap().into_iter().max();
    w.sim.fail_next_sync(); // the shred record's flush fails on the payload's data file
    assert!(j.shred(shredded_record(x, 2)).is_err());
    j.recover().unwrap();
    assert!(!w.survey().2.is_empty(), "the shred record is durable");
    assert!(w.quarantined() >= 1, "the payload's files sit in quarantine");
    drop(j);
    drop(store);
    let (store, _j) = w.restart(false);
    let v1 = w.keys.kek_versions(pocket()).unwrap().into_iter().max();
    assert!(
        v1 > v0,
        "a durable shred record, yet the pocket's KEK ({v0:?}) was never rotated"
    );
    assert_eq!(w.keys.kek_versions(pocket()).unwrap().len(), 1);
    assert_eq!(
        store.get(pocket(), x),
        Err(ChunkError::Unavailable),
        "shredded content reads back as lost"
    );
}

/// A shred of content lost once and stored again, whose quarantine flush (its last) fails before
/// the power goes: the pair's removal is durable, the marker's removal is not. The open completes
/// the shred again, so the content reads back as shredded.
#[test]
fn r14_l1_a_shred_cut_before_its_quarantine_flush_reads_back_as_shredded() {
    let w = World::new(1402);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    j.recover().unwrap();
    assert_eq!(store.get(pocket(), x), Err(ChunkError::Lost));
    store.put(pocket(), &content(1)).unwrap();
    j.append(draft(Some(pocket()), Some(x), 2)).unwrap();
    j.sync().unwrap();
    // Flushes: the shred record's segment (1), keys/ (2), data/ (3); quarantine/ (4) fails.
    w.sim.fail_sync_after(3);
    assert!(j.shred(shredded_record(x, 3)).is_err());
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    assert!(!w.survey().2.is_empty(), "the shred record is durable");
    assert_eq!(
        store.get(pocket(), x),
        Err(ChunkError::Unavailable),
        "deliberately shredded content reads back as lost after a power loss"
    );
}

/// A store poisoned when the journal reopens with it: recovery at open finds the payload
/// unauthentic and quarantines it, then the check of the previous run's records finds the chunk
/// absent. The loss reported is the one the bytes showed.
#[test]
fn r14_l2_the_cause_the_bytes_showed_is_the_cause_reported() {
    let w = World::new(1401);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _x) = write(&store, &mut j, 1);
    let pocket_dir = w.data.join(CHUNKS_DIR).join(pocket().to_string());
    for p in files_in(&w, &pocket_dir.join("data"), "chunk") {
        w.sim.write_back_part(&p, 3, 4);
    }
    w.sim.fail_next_sync(); // only the written-back three quarters remain
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    drop(j); // closed without recovering; the store stays poisoned
    let j = w.open(&store).unwrap();
    let causes: Vec<LossCause> = j
        .lost_payloads()
        .iter()
        .filter(|l| l.record_seq.0 == seq)
        .map(|l| l.cause)
        .collect();
    assert_eq!(causes, vec![LossCause::Unauthentic], "cause reported for record {seq}");
}

/// The disk is full when recovery writes a loss's marker. Nothing is set aside then; the next
/// recovery finds the chunk again, writes the marker and reports the loss.
#[test]
fn r14_l3_a_full_disk_while_marking_a_loss_leaves_it_to_the_next_recovery() {
    let w = World::new(1403);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, x) = write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    w.fs.fail_marker.store(true, Ordering::SeqCst);
    assert!(j.recover().is_err(), "the marker write did not fail");
    j.recover().unwrap();
    assert!(w.survey().1.contains(&seq), "the loss was not journaled");
    assert_eq!(
        store.get(pocket(), x),
        Err(ChunkError::Lost),
        "a journaled loss reads back as never stored or shredded"
    );
}

// ── Random crash schedules ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Op {
    /// Store a new payload and append a record that references it.
    Write,
    /// Append a record that references an earlier payload again.
    Repeat(usize),
    /// Shred an earlier payload and journal it.
    Shred(usize),
    Sync,
    /// Let `n` flushes succeed, then fail the next.
    FailSyncAfter(u32),
    /// The next segment append fails with `NoSpace`.
    FailAppend,
    /// Advance the clock past the marker interval.
    Tick,
    /// Finish the re-wraps shreds left pending.
    FinishRewraps,
    Crash,
    PowerLoss,
    Recover,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => Just(Op::Write),
        2 => (0usize..64).prop_map(Op::Repeat),
        1 => (0usize..64).prop_map(Op::Shred),
        3 => Just(Op::Sync),
        2 => (0u32..4).prop_map(Op::FailSyncAfter),
        1 => Just(Op::FailAppend),
        1 => Just(Op::Tick),
        1 => Just(Op::FinishRewraps),
        1 => Just(Op::Crash),
        1 => Just(Op::PowerLoss),
        2 => Just(Op::Recover),
    ]
}

/// `os_holds_unflushed`: whether records after the flushed boundary were with the OS when the
/// process died; not after a failed segment flush whose rewrite also failed (`FlushFailed`: those
/// records lived only in memory). `reported_before`: losses already journaled.
fn check(
    w: &World,
    store: &ChunkStore,
    acked: &BTreeMap<u64, u64>,
    flushed: Option<u64>,
    power: bool,
    os_holds_unflushed: bool,
    reported_before: &BTreeSet<u64>,
) {
    w.assert_never_silent(store, "schedule");
    let (records, _, shreds) = w.survey();
    let present: BTreeMap<u64, ChunkRef> = records.iter().map(|(s, _, c)| (*s, *c)).collect();
    for seq in acked.keys() {
        let flushed_here = flushed.is_some_and(|f| *seq <= f);
        if !(flushed_here || (!power && os_holds_unflushed)) {
            continue;
        }
        let chunk = present
            .get(seq)
            .unwrap_or_else(|| panic!("acknowledged record {seq} is gone"));
        let shredded = shreds.iter().any(|(_, sc, ss)| *sc == chunk.to_string() && ss > seq);
        if power && !reported_before.contains(seq) && !shredded {
            assert!(
                store.get(pocket(), *chunk).is_ok(),
                "flushed record {seq} lost its payload"
            );
        }
    }
}

/// After a process crash: every acknowledged record that survived keeps a readable payload unless a
/// failed flush may have dropped it (one armed while the record was not yet flushed, and only when
/// a failed flush drops the unflushed bytes) or a later shred removed it. A reported loss alone
/// does not excuse it, so a store that loses or discards payloads and reports every loss still
/// fails.
fn check_crash_payloads(w: &World, store: &ChunkStore, acked: &BTreeMap<u64, u64>, exposed: &BTreeSet<u64>) {
    let (records, _, shreds) = w.survey();
    for (seq, _, chunk) in &records {
        if !acked.contains_key(seq) || exposed.contains(seq) {
            continue;
        }
        let shredded = shreds.iter().any(|(_, sc, ss)| *sc == chunk.to_string() && ss > seq);
        assert!(
            shredded || store.get(pocket(), *chunk).is_ok(),
            "record {seq} lost its payload to a process crash, though no failed flush could have dropped it"
        );
    }
}

/// A recovery with no fault armed succeeds and leaves neither the journal nor the store refusing
/// work, and the journal then takes a record, flushes it and still reads back whole: no record
/// lands after a torn line.
fn check_clean_recovery(
    w: &World,
    outcome: &Result<(), JournalError>,
    journal: &mut Journal,
    store: &ChunkStore,
) -> Result<(), TestCaseError> {
    prop_assert!(outcome.is_ok(), "a recovery with no fault armed failed: {:?}", outcome);
    prop_assert_eq!(journal.health(), JournalHealth::Healthy);
    prop_assert!(!store.is_poisoned(), "the store stayed poisoned after a clean recovery");
    let appended = journal.append(draft(Some(pocket()), None, 0));
    prop_assert!(
        appended.is_ok(),
        "a clean recovery left the journal refusing records: {:?}",
        appended
    );
    let synced = journal.sync();
    prop_assert!(
        synced.is_ok(),
        "a clean recovery left the journal unable to flush: {:?}",
        synced
    );
    let read = read_verified(&w.sim, &w.data.join(JOURNAL_DIR));
    prop_assert!(
        read.is_ok(),
        "the journal no longer reads back after a clean recovery: {:?}",
        read.err()
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn payload_durability_under_random_crash_schedules(
        seed in any::<u64>(),
        keep_cache in any::<bool>(),
        policy in 0u8..3,
        ops in prop::collection::vec(op(), 1..80),
        writebacks in prop::collection::vec((0usize..80, 0u8..7), 0..6),
    ) {
        let w = World::new(seed);
        w.sim.set_failed_sync_keeps_cache(keep_cache);
        // Appends flush on their own under the strict policy and a window that falls due (a tick
        // passes it), as in production; the long window leaves every flush to `Op::Sync`.
        let flush = match policy {
            0 => NEVER,
            1 => FlushPolicy::Strict,
            _ => FlushPolicy::Balanced { window: Millis(1_000) },
        };
        let mut store = w.store();
        let mut journal = w.open_with(&store, flush).unwrap();
        let mut contents: Vec<u64> = Vec::new();
        let mut acked: BTreeMap<u64, u64> = BTreeMap::new();
        let mut next = 0u64;
        let mut rewraps = Vec::new();
        // Acknowledged records whose payload a flush failure armed since their acknowledgement may
        // have dropped: only these may lose it to a process crash.
        let mut exposed: BTreeSet<u64> = BTreeSet::new();
        for (idx, op) in ops.into_iter().enumerate() {
            for &(at, kind) in &writebacks {
                if at == idx {
                    write_back(&w, kind);
                }
            }
            match op {
                Op::Write | Op::Repeat(_) => {
                    let n = match op {
                        Op::Repeat(i) if !contents.is_empty() => contents[i % contents.len()],
                        _ => { next += 1; contents.push(next); next }
                    };
                    let Ok(chunk) = store.put(pocket(), &content(n)) else { continue };
                    if let Ok(a) = journal.append(draft(Some(pocket()), Some(chunk), n)) {
                        acked.insert(a.seq.0, n);
                        if !keep_cache && w.sim.sync_fault_pending() {
                            exposed.insert(a.seq.0);
                        }
                    }
                }
                Op::Shred(i) if !contents.is_empty() => {
                    let n = contents[i % contents.len()];
                    let Ok(chunk) = store.reference(pocket(), &content(n)) else { continue };
                    // Through the journal: the shred runs only once its record is durable. A shred
                    // that fails after its record is completed when the journal next opens. Its
                    // re-wrap stays pending until a later operation.
                    if let Ok(rewrap) = journal.shred(shredded_record(chunk, n)) {
                        rewraps.push(rewrap);
                    }
                }
                Op::Shred(_) => {}
                // Failures are part of the schedule; the checks after each crash judge the outcome.
                Op::Sync => { let _outcome = journal.sync(); }
                Op::FailSyncAfter(n) => {
                    w.sim.fail_sync_after(n);
                    // A failed flush drops only unflushed bytes, and none when the cache keeps
                    // them: records already flushed cannot lose their payload.
                    if !keep_cache {
                        let flushed = journal.flushed_through().map(|s| s.0);
                        exposed.extend(acked.keys().copied().filter(|s| flushed.is_none_or(|f| *s > f)));
                    }
                }
                Op::FailAppend => w.fs.fail_segment_append_after(0),
                Op::Tick => w.clock.advance(1_100_000_000),
                Op::FinishRewraps => {
                    for rewrap in rewraps.drain(..) {
                        let _outcome = rewrap.finish();
                    }
                }
                Op::Recover => {
                    let clean = !w.sim.sync_fault_pending() && !w.fs.append_fault_pending();
                    let outcome = journal.recover();
                    if clean {
                        check_clean_recovery(&w, &outcome, &mut journal, &store)?;
                    }
                }
                Op::Crash | Op::PowerLoss => {
                    let power = matches!(op, Op::PowerLoss);
                    let flushed = journal.flushed_through().map(|s| s.0);
                    let os_holds_unflushed = journal.health() != JournalHealth::FlushFailed;
                    let (_, reported_before, _) = w.survey();
                    // The process dies with its re-wraps unfinished: nothing runs their `Drop`.
                    rewraps.drain(..).for_each(std::mem::forget);
                    drop(journal);
                    drop(store);
                    let mut durable_reported = BTreeSet::new();
                    if power {
                        w.sim.power_loss();
                        durable_reported = w.survey().1;
                    } else {
                        w.sim.crash();
                    }
                    // Faults armed before the crash may still hit this open; then open again.
                    // A failed open must not cost anything the OS held (it copies the previous
                    // run's records instead of flushing their file again).
                    // The store's own open can fail too (it finishes an interrupted rotation).
                    // After a failed open, the machine either crashes or loses power (alternating
                    // by schedule); after a power loss only flushed records are owed.
                    let reopen = |w: &World| -> Option<(Arc<ChunkStore>, Journal)> {
                        let s = w.try_store(ChunkDurability::Balanced).ok()?;
                        let j = w.open_with(&s, flush).ok()?;
                        Some((s, j))
                    };
                    let mut lost_power = power;
                    let clean = !w.sim.sync_fault_pending() && !w.fs.append_fault_pending();
                    (store, journal) = if let Some(pair) = reopen(&w) {
                        pair
                    } else {
                        // Only an armed fault may fail an open.
                        prop_assert!(!clean, "an open with no fault armed failed");
                        w.sim.clear_sync_fault();
                        w.fs.clear_append_fault();
                        if acked.len().is_multiple_of(2) {
                            w.sim.power_loss();
                            durable_reported = w.survey().1;
                            lost_power = true;
                        } else {
                            w.sim.crash();
                        }
                        reopen(&w).unwrap()
                    };
                    // After a power loss, only a loss record that survived it excuses a payload.
                    let reported = if lost_power { &durable_reported } else { &reported_before };
                    check(&w, &store, &acked, flushed, lost_power, os_holds_unflushed, reported);
                    if !lost_power {
                        check_crash_payloads(&w, &store, &acked, &exposed);
                    }
                    let (records, _, _) = w.survey();
                    let present: BTreeSet<u64> = records.iter().map(|(s, _, _)| *s).collect();
                    acked.retain(|s, _| present.contains(s));
                    exposed.retain(|s| acked.contains_key(s));
                    // After a power loss the OS may have written a record back without its payload;
                    // the open reports that loss, and later crashes must not count it against the
                    // store.
                    if lost_power {
                        let (_, reported, _) = w.survey();
                        exposed.extend(reported.into_iter().filter(|s| acked.contains_key(s)));
                    }
                    // An open verifies every surviving record's payload and makes it durable, so a
                    // record whose payload reads back and no `chunk.lost` names is safe from any
                    // later failed flush.
                    let (records, reported, _) = w.survey();
                    for (seq, _, chunk) in &records {
                        if !reported.contains(seq) && store.get(pocket(), *chunk).is_ok() {
                            exposed.remove(seq);
                        }
                    }
                }
            }
        }
    }
}

// ── Shred schedules: refusal and completion oracles ──────────

#[derive(Debug, Clone)]
/// The shred schedule's operations: those of [`Op`], plus a record that references an earlier
/// payload without storing it again.
enum ShredOp {
    Write,
    Repeat(usize),
    /// Append a record that references an earlier payload without storing it again.
    RepeatNoPut(usize),
    Shred(usize),
    Sync,
    FailSyncAfter(u32),
    FailAppend,
    Tick,
    FinishRewraps,
    Crash,
    PowerLoss,
    Recover,
}

fn shred_op() -> impl Strategy<Value = ShredOp> {
    prop_oneof![
        6 => Just(ShredOp::Write),
        2 => (0usize..64).prop_map(ShredOp::Repeat),
        3 => (0usize..64).prop_map(ShredOp::RepeatNoPut),
        2 => (0usize..64).prop_map(ShredOp::Shred),
        3 => Just(ShredOp::Sync),
        2 => (0u32..4).prop_map(ShredOp::FailSyncAfter),
        1 => Just(ShredOp::FailAppend),
        1 => Just(ShredOp::Tick),
        1 => Just(ShredOp::FinishRewraps),
        1 => Just(ShredOp::Crash),
        1 => Just(ShredOp::PowerLoss),
        2 => Just(ShredOp::Recover),
    ]
}

/// After a successful open: every `chunk.shredded` record not followed by a record that
/// references the chunk again leaves the content unreadable, and the pocket has one KEK version.
fn check_shreds_complete(w: &World, store: &ChunkStore, what: &str) {
    let (records, _, shreds) = w.survey();
    for (pocket, chunk, sseq) in &shreds {
        let later_use = records
            .iter()
            .any(|(seq, p, c)| p == pocket && c.to_string() == *chunk && seq > sseq);
        if later_use {
            continue;
        }
        let r: ChunkRef = chunk.parse().unwrap();
        assert!(
            store.get(*pocket, r).is_err(),
            "{what}: shred record {sseq} is durable, no record uses the chunk again, yet it is readable"
        );
        // No copy of its data key can still be unwrapped: no key file of the chunk, in `keys/` or
        // set aside in quarantine, is wrapped under a KEK version still alive. "One version alive"
        // also holds for a KEK never rotated. A key file starts with "UAOSKEY1" and its KEK version
        // (u32 little-endian).
        let alive = w.keys.kek_versions(*pocket).unwrap();
        let name = chunk.trim_start_matches("hmac-sha256:");
        let pocket_dir = w.data.join(CHUNKS_DIR).join(pocket.to_string());
        for dir in ["keys", QUARANTINE_DIR] {
            for file in files_in(w, &pocket_dir.join(dir), "key") {
                let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or_default();
                if !file_name.starts_with(&format!("{name}.")) {
                    continue;
                }
                let bytes = w.sim.read(&file).unwrap_or_default();
                let Some(version) = bytes.get(8..12).and_then(|b| <[u8; 4]>::try_from(b).ok()) else {
                    continue;
                };
                assert!(
                    !alive.contains(&KekVersion(u32::from_le_bytes(version))),
                    "{what}: shred record {sseq} is durable, yet {file_name} is wrapped under a KEK still alive"
                );
            }
        }
    }
    let versions = w.keys.kek_versions(pocket()).unwrap();
    assert!(
        versions.len() <= 1,
        "{what}: {} KEK versions alive after open",
        versions.len()
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn shred_refusal_and_completion_under_random_crash_schedules(
        seed in any::<u64>(),
        keep_cache in any::<bool>(),
        policy in 0u8..3,
        ops in prop::collection::vec(shred_op(), 1..100),
        writebacks in prop::collection::vec((0usize..100, 0u8..7), 0..6),
    ) {
        let w = World::new(seed);
        w.sim.set_failed_sync_keeps_cache(keep_cache);
        let flush = match policy {
            0 => NEVER,
            1 => FlushPolicy::Strict,
            _ => FlushPolicy::Balanced { window: Millis(1_000) },
        };
        let mut store = w.store();
        let mut journal = w.open_with(&store, flush).unwrap();
        let mut contents: Vec<u64> = Vec::new();
        let mut acked: BTreeMap<u64, u64> = BTreeMap::new();
        let mut next = 0u64;
        let mut rewraps = Vec::new();
        // Acknowledged records whose payload a flush failure armed since their acknowledgement may
        // have dropped: only these may lose it to a process crash.
        let mut exposed: BTreeSet<u64> = BTreeSet::new();
        // In this process: the op index of the latest shred of content n whose record was
        // written, and of the latest successful put of content n. A record referencing n written
        // after such a shred needs a put in between.
        let mut shred_written: BTreeMap<u64, usize> = BTreeMap::new();
        let mut last_put: BTreeMap<u64, usize> = BTreeMap::new();
        for (idx, op) in ops.into_iter().enumerate() {
            for &(at, kind) in &writebacks {
                if at == idx {
                    write_back(&w, kind);
                }
            }
            match op {
                ShredOp::Write | ShredOp::Repeat(_) => {
                    let n = match op {
                        ShredOp::Repeat(i) if !contents.is_empty() => contents[i % contents.len()],
                        _ => { next += 1; contents.push(next); next }
                    };
                    let Ok(chunk) = store.put(pocket(), &content(n)) else { continue };
                    last_put.insert(n, idx);
                    if let Ok(a) = journal.append(draft(Some(pocket()), Some(chunk), n)) {
                        acked.insert(a.seq.0, n);
                        if !keep_cache && w.sim.sync_fault_pending() {
                            exposed.insert(a.seq.0);
                        }
                    }
                }
                ShredOp::RepeatNoPut(i) if !contents.is_empty() => {
                    let n = contents[i % contents.len()];
                    let Ok(chunk) = store.reference(pocket(), &content(n)) else { continue };
                    let before = journal.next_seq().0;
                    let res = journal.append(draft(Some(pocket()), Some(chunk), n));
                    let written = journal.next_seq().0 > before;
                    if let Ok(a) = &res {
                        acked.insert(a.seq.0, n);
                        if !keep_cache && w.sim.sync_fault_pending() {
                            exposed.insert(a.seq.0);
                        }
                    }
                    if written && let Some(s) = shred_written.get(&n) {
                        let reput = last_put.get(&n).is_some_and(|p| p > s);
                        prop_assert!(
                            reput,
                            "op {}: a record referencing content {} was written after a written shred record (op {}) with no put since",
                            idx, n, s
                        );
                    }
                }
                ShredOp::Shred(i) if !contents.is_empty() => {
                    let n = contents[i % contents.len()];
                    let Ok(chunk) = store.reference(pocket(), &content(n)) else { continue };
                    let before = journal.next_seq().0;
                    let res = journal.shred(shredded_record(chunk, n));
                    if journal.next_seq().0 > before {
                        shred_written.insert(n, idx);
                    }
                    if let Ok(rewrap) = res {
                        rewraps.push(rewrap);
                    }
                }
                ShredOp::RepeatNoPut(_) | ShredOp::Shred(_) => {}
                ShredOp::Sync => { let _outcome = journal.sync(); }
                ShredOp::FailSyncAfter(n) => {
                    w.sim.fail_sync_after(n);
                    // A failed flush drops only unflushed bytes, and none when the cache keeps
                    // them: records already flushed cannot lose their payload.
                    if !keep_cache {
                        let flushed = journal.flushed_through().map(|s| s.0);
                        exposed.extend(acked.keys().copied().filter(|s| flushed.is_none_or(|f| *s > f)));
                    }
                }
                ShredOp::FailAppend => w.fs.fail_segment_append_after(0),
                ShredOp::Tick => w.clock.advance(1_100_000_000),
                ShredOp::FinishRewraps => {
                    for rewrap in rewraps.drain(..) {
                        let _outcome = rewrap.finish();
                    }
                }
                ShredOp::Recover => {
                    let clean = !w.sim.sync_fault_pending() && !w.fs.append_fault_pending();
                    let outcome = journal.recover();
                    if clean {
                        check_clean_recovery(&w, &outcome, &mut journal, &store)?;
                    }
                }
                ShredOp::Crash | ShredOp::PowerLoss => {
                    let power = matches!(op, ShredOp::PowerLoss);
                    let flushed = journal.flushed_through().map(|s| s.0);
                    let os_holds_unflushed = journal.health() != JournalHealth::FlushFailed;
                    let (_, reported_before, _) = w.survey();
                    rewraps.drain(..).for_each(std::mem::forget);
                    drop(journal);
                    drop(store);
                    let mut durable_reported = BTreeSet::new();
                    if power {
                        w.sim.power_loss();
                        durable_reported = w.survey().1;
                    } else {
                        w.sim.crash();
                    }
                    let reopen = |w: &World| -> Option<(Arc<ChunkStore>, Journal)> {
                        let s = w.try_store(ChunkDurability::Balanced).ok()?;
                        let j = w.open_with(&s, flush).ok()?;
                        Some((s, j))
                    };
                    let mut lost_power = power;
                    let clean = !w.sim.sync_fault_pending() && !w.fs.append_fault_pending();
                    (store, journal) = if let Some(pair) = reopen(&w) {
                        pair
                    } else {
                        // Only an armed fault may fail an open.
                        prop_assert!(!clean, "an open with no fault armed failed");
                        w.sim.clear_sync_fault();
                        w.fs.clear_append_fault();
                        if acked.len().is_multiple_of(2) {
                            w.sim.power_loss();
                            durable_reported = w.survey().1;
                            lost_power = true;
                        } else {
                            w.sim.crash();
                        }
                        reopen(&w).unwrap()
                    };
                    // After a power loss, only a loss record that survived it excuses a payload.
                    let reported = if lost_power { &durable_reported } else { &reported_before };
                    check(&w, &store, &acked, flushed, lost_power, os_holds_unflushed, reported);
                    if !lost_power {
                        check_crash_payloads(&w, &store, &acked, &exposed);
                    }
                    check_shreds_complete(&w, &store, "shred schedule");
                    let (records, _, _) = w.survey();
                    let present: BTreeSet<u64> = records.iter().map(|(s, _, _)| *s).collect();
                    acked.retain(|s, _| present.contains(s));
                    exposed.retain(|s| acked.contains_key(s));
                    // After a power loss the OS may have written a record back without its payload;
                    // the open reports that loss, and later crashes must not count it against the
                    // store.
                    if lost_power {
                        let (_, reported, _) = w.survey();
                        exposed.extend(reported.into_iter().filter(|s| acked.contains_key(s)));
                    }
                    // An open verifies every surviving record's payload and makes it durable, so a
                    // record whose payload reads back and no `chunk.lost` names is safe from any
                    // later failed flush.
                    let (records, reported, _) = w.survey();
                    for (seq, _, chunk) in &records {
                        if !reported.contains(seq) && store.get(pocket(), *chunk).is_ok() {
                            exposed.remove(seq);
                        }
                    }
                    shred_written.clear();
                    last_put.clear();
                }
            }
        }
    }
}

// ── S-6: two writers of one chunk ──────────────────────────────────────────────────────────

#[test]
fn concurrent_puts_of_one_chunk_never_pair_data_with_the_wrong_key() {
    for durability in [ChunkDurability::Balanced, ChunkDurability::Strict] {
        let w = World::new(9);
        let store = w.try_store(durability).unwrap();
        let body = content(42);
        w.fs.key_write.arm();

        // Writer A stores its data file, then is held before its key file.
        let a = {
            let (store, body) = (Arc::clone(&store), body.clone());
            std::thread::spawn(move || store.put(pocket(), &body))
        };
        w.fs.key_write.wait_held();
        // Writer B arrives for the same content. Without one writer per chunk it would replace
        // A's data file and write its own key, and A's late key would then open nothing.
        let b = {
            let (store, body) = (Arc::clone(&store), body.clone());
            std::thread::spawn(move || store.put(pocket(), &body))
        };
        for _ in 0..50 {
            if b.is_finished() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        w.fs.key_write.release();
        let chunk = a.join().unwrap().unwrap();
        assert_eq!(b.join().unwrap().unwrap(), chunk);
        assert_eq!(
            store.get(pocket(), chunk).ok(),
            Some(body),
            "{durability:?}: two writers of one chunk left a data file paired with the other's key"
        );
    }
}

/// A seal lands while the `FLUSHED` marker is held back. Here the store is poisoned by a failed
/// flush of a payload no record references yet; the journal holds nothing unflushed, so the seal
/// goes ahead, the marker stays where it was, and the next open reads the seal.
#[test]
fn a_seal_lands_while_the_marker_is_held_back() {
    let w = World::new(31);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _chunk) = write(&store, &mut j, 1);
    j.sync().unwrap();
    // A payload no record references yet; its flush fails, which poisons the store.
    store.put(pocket(), &content(2)).unwrap();
    w.sim.fail_next_sync();
    assert!(store.sync_pending().is_err());
    assert!(store.is_poisoned(), "the scenario did not poison the store");
    let marker = w.data.join(JOURNAL_DIR).join(FLUSH_MARKER);
    let before = w.sim.read(&marker).unwrap();
    assert_eq!(j.seal(), Ok(Seq(seq)), "a held-back marker kept the seal from landing");
    assert_eq!(
        w.sim.read(&marker).unwrap(),
        before,
        "the scenario's marker was not held back"
    );
    drop(j);
    drop(store);
    w.sim.crash();
    let store = w.store();
    let clock: Arc<dyn Clock> = w.clock.clone();
    let rng: Arc<dyn Rng> = w.rng.clone();
    let opened =
        Journal::open_with_payloads(Arc::new(w.fs.clone()), clock, rng, &w.data, NEVER, Arc::clone(&store)).unwrap();
    assert_eq!(opened.evidence.sealed, Some(Seq(seq)), "the seal was not read");
}
