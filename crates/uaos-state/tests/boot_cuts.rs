// SPDX-License-Identifier: Apache-2.0

//! Cut a boot (the chunk store's open, then the journal's, as `journal-crash-writer` boots)
//! before its N-th filesystem step, for every N, then crash or lose power, then reopen twice.
//! Any reopen that fails is a brick, and every acknowledged (crash) or flushed (power loss)
//! record must survive. A first open killed before its manifest once left the directory
//! unopenable for good; this test is the merge-lane proof of `journal-durability` that no cut of
//! a boot bricks a directory.

#![allow(
    clippy::unwrap_used,
    clippy::print_stderr,
    reason = "a test harness: a failed fixture must abort the test, and each sweep reports its size"
)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use uaos_contracts::digest::Sha256Digest;
use uaos_contracts::event::{Actor, Durability, Metadata, types};
use uaos_contracts::id::{CorrelationId, PocketId, TypedId};
use uaos_contracts::limits::Millis;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::ConfigVersion;
use uaos_platform::fs::{AppendFile, Fs, FsError, LockGuard};
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, Rng};
use uaos_state::chunks::keyring::{MemoryKeyring, PocketKeyring};
use uaos_state::chunks::{ChunkDurability, ChunkStore};
use uaos_state::journal::{EventDraft, FlushPolicy, JOURNAL_DIR, Journal, JournalError, read_verified};

const DATA: &str = "/data";
/// Temporaries are unique across boots, as the real ones (pid + counter, created truncating) behave.
static TMP: AtomicU64 = AtomicU64::new(0);
/// Records a prefix acknowledged, and those of them flushed: what a crash, or a power loss, must keep.
type Prefix = (Vec<(u64, Sha256Digest)>, Vec<(u64, Sha256Digest)>);
const LAZY: FlushPolicy = FlushPolicy::Balanced { window: Millis(60_000) };

fn dead(op: &'static str) -> FsError {
    FsError::Io {
        op,
        kind: "dead".to_owned(),
    }
}

#[derive(Debug, Clone)]
struct CutFs {
    sim: SimFs,
    left: Arc<Mutex<Option<u64>>>,
    dead: Arc<AtomicBool>,
    steps: Arc<AtomicU64>,
    trace: Arc<Mutex<Vec<String>>>,
}

impl CutFs {
    fn new(sim: SimFs, cut: Option<u64>) -> Self {
        Self {
            sim,
            left: Arc::new(Mutex::new(cut)),
            dead: Arc::new(AtomicBool::new(false)),
            steps: Arc::new(AtomicU64::new(0)),
            trace: Arc::new(Mutex::new(Vec::new())),
        }
    }
    fn step(&self, what: String) -> Result<(), FsError> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(dead("dead"));
        }
        let mut l = self.left.lock().unwrap();
        if let Some(n) = l.as_mut() {
            if *n == 0 {
                self.dead.store(true, Ordering::SeqCst);
                self.trace.lock().unwrap().push(format!("CUT before {what}"));
                return Err(dead("cut"));
            }
            *n -= 1;
        }
        self.steps.fetch_add(1, Ordering::SeqCst);
        self.trace.lock().unwrap().push(what);
        Ok(())
    }
    fn died(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
struct CutAppend {
    inner: Box<dyn AppendFile>,
    fs: CutFs,
    path: PathBuf,
}

impl AppendFile for CutAppend {
    fn append(&mut self, bytes: &[u8]) -> Result<(), FsError> {
        self.fs
            .step(format!("append {} ({} B)", self.path.display(), bytes.len()))?;
        self.inner.append(bytes)
    }
    fn sync_data(&mut self) -> Result<(), FsError> {
        self.fs.step(format!("sync_data {}", self.path.display()))?;
        self.inner.sync_data()
    }
    fn os_len(&self) -> Result<u64, FsError> {
        self.inner.os_len()
    }
}

impl Fs for CutFs {
    fn create_dir_all(&self, p: &Path) -> Result<(), FsError> {
        self.step(format!("create_dir_all {}", p.display()))?;
        self.sim.create_dir_all(p)
    }
    fn open_append(&self, p: &Path) -> Result<Box<dyn AppendFile>, FsError> {
        self.step(format!("open_append {}", p.display()))?;
        Ok(Box::new(CutAppend {
            inner: self.sim.open_append(p)?,
            fs: self.clone(),
            path: p.to_path_buf(),
        }))
    }
    fn read(&self, p: &Path) -> Result<Vec<u8>, FsError> {
        if self.died() {
            return Err(dead("read"));
        }
        self.sim.read(p)
    }
    fn list_dir(&self, p: &Path) -> Result<Vec<PathBuf>, FsError> {
        if self.died() {
            return Err(dead("list"));
        }
        self.sim.list_dir(p)
    }
    fn rename(&self, a: &Path, b: &Path) -> Result<(), FsError> {
        self.step(format!("rename {} -> {}", a.display(), b.display()))?;
        self.sim.rename(a, b)
    }
    fn remove_file(&self, p: &Path) -> Result<(), FsError> {
        self.step(format!("remove {}", p.display()))?;
        self.sim.remove_file(p)
    }
    fn sync_dir(&self, p: &Path) -> Result<(), FsError> {
        self.step(format!("sync_dir {}", p.display()))?;
        self.sim.sync_dir(p)
    }
    fn write_atomic(&self, p: &Path, b: &[u8]) -> Result<(), FsError> {
        let n = TMP.fetch_add(1, Ordering::SeqCst);
        let name = p.file_name().unwrap().to_str().unwrap();
        let tmp = p.with_file_name(format!("{name}.uaos-tmp-cut-{n}"));
        let mut f = self.open_append(&tmp)?;
        f.append(b)?;
        f.sync_data()?;
        drop(f);
        self.rename(&tmp, p)?;
        self.sync_dir(p.parent().unwrap())
    }
    fn write_unsynced(&self, p: &Path, b: &[u8]) -> Result<(), FsError> {
        let n = TMP.fetch_add(1, Ordering::SeqCst);
        let name = p.file_name().unwrap().to_str().unwrap();
        let tmp = p.with_file_name(format!("{name}.uaos-tmp-cut-{n}"));
        let mut f = self.open_append(&tmp)?;
        f.append(b)?;
        drop(f);
        self.rename(&tmp, p)
    }
    fn sync_file(&self, p: &Path) -> Result<(), FsError> {
        self.step(format!("sync_file {}", p.display()))?;
        self.sim.sync_file(p)
    }
    fn try_lock_exclusive(&self, p: &Path) -> Result<Box<dyn LockGuard>, FsError> {
        self.step(format!("lock {}", p.display()))?;
        self.sim.try_lock_exclusive(p)
    }
}

struct World {
    sim: SimFs,
    clock: Arc<SimClock>,
    rng: Arc<SimRng>,
    keys: Arc<MemoryKeyring>,
}

fn pocket() -> PocketId {
    PocketId::from_parts(7, [7; 10])
}

fn draft(n: u64, chunk: Option<uaos_contracts::digest::ChunkRef>) -> EventDraft {
    let mut random = [0u8; 10];
    random[..8].copy_from_slice(&n.to_le_bytes());
    EventDraft {
        session_id: None,
        pocket_id: chunk.map(|_| pocket()),
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

impl World {
    fn new(seed: u64) -> Self {
        let sim = SimFs::new();
        sim.create_dir_all(Path::new(DATA)).unwrap();
        let rng = Arc::new(SimRng::new(seed));
        Self {
            sim,
            clock: Arc::new(SimClock::new(
                WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
            )),
            keys: Arc::new(MemoryKeyring::new(rng.clone())),
            rng,
        }
    }
    /// A boot like journal-crash-writer: store (if `payloads`), then journal.
    fn boot(&self, fs: Arc<dyn Fs>, payloads: bool) -> Result<(Option<Arc<ChunkStore>>, Journal), String> {
        let clock: Arc<dyn Clock> = self.clock.clone();
        let rng: Arc<dyn Rng> = self.rng.clone();
        if payloads {
            let keys: Arc<dyn PocketKeyring> = self.keys.clone();
            let store = ChunkStore::open_with(
                Arc::clone(&fs),
                Arc::clone(&rng),
                keys,
                Path::new(DATA),
                ChunkDurability::Balanced,
            )
            .map_err(|e| format!("store open: {e}"))?;
            let store = Arc::new(store);
            let j = Journal::open_with_payloads(fs, clock, rng, Path::new(DATA), LAZY, Arc::clone(&store))
                .map(|opened| opened.journal)
                .map_err(|e| format!("journal open: {e}"))?;
            Ok((Some(store), j))
        } else {
            let j = Journal::open(fs, clock, rng, Path::new(DATA), LAZY).map_err(|e| format!("journal open: {e}"))?;
            Ok((None, j))
        }
    }
    fn records(&self) -> Result<Vec<(u64, Sha256Digest)>, JournalError> {
        Ok(read_verified(&self.sim, &Path::new(DATA).join(JOURNAL_DIR))?
            .0
            .iter()
            .map(|r| (r.envelope.seq.0, r.hash))
            .collect())
    }
    fn names(&self) -> Vec<String> {
        self.sim
            .list_dir(&Path::new(DATA).join(JOURNAL_DIR))
            .map(|v| {
                v.iter()
                    .filter_map(|p| p.file_name()?.to_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn write(store: Option<&Arc<ChunkStore>>, j: &mut Journal, n: u64) -> (u64, Sha256Digest) {
    let chunk = store.map(|s| s.put(pocket(), format!("content {n}").as_bytes()).unwrap());
    let a = j.append(draft(n, chunk)).unwrap();
    (a.seq.0, a.hash)
}

/// Cuts boots at every step; `prefix` builds the state before the cut boot (returns acked records,
/// and those flushed).
fn sweep(
    label: &str,
    payloads: bool,
    power: bool,
    cuts_before: &[u64],
    prefix: &dyn Fn(&World) -> Prefix,
) -> Vec<String> {
    let mut bricks = Vec::new();
    for cut in 0u64.. {
        let w = World::new(1000 + cut);
        let (acked, flushed) = prefix(&w);
        // Earlier cut boots (each followed by a crash), to exercise repeated interruption.
        for &earlier in cuts_before {
            let cfs = CutFs::new(w.sim.clone(), Some(earlier));
            let r = w.boot(Arc::new(cfs.clone()), payloads);
            drop(r);
            w.sim.crash();
        }
        let cfs = CutFs::new(w.sim.clone(), Some(cut));
        let first = w.boot(Arc::new(cfs.clone()), payloads);
        let finished = !cfs.died();
        drop(first);
        if power {
            w.sim.power_loss();
        } else {
            w.sim.crash();
        }
        let names_before = w.names();
        // Reopen twice (crash between) with no cut: both must succeed.
        let mut ok = true;
        for round in 0..2 {
            match w.boot(Arc::new(w.sim.clone()), payloads) {
                Ok((store, mut j)) => {
                    let _ = write(store.as_ref(), &mut j, 900 + round);
                    j.sync().unwrap();
                    drop(j);
                    drop(store);
                    w.sim.crash();
                }
                Err(e) => {
                    let trace = cfs.trace.lock().unwrap().clone();
                    bricks.push(format!(
                        "{label}: cut {cut} (power {power}) reopen {round} failed: {e}\n  names before reopen: {names_before:?}\n  last steps: {:?}",
                        trace.iter().rev().take(4).rev().collect::<Vec<_>>()
                    ));
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            let present = w.records().unwrap();
            let must: &Vec<(u64, Sha256Digest)> = if power { &flushed } else { &acked };
            for a in must {
                if !present.contains(a) {
                    bricks.push(format!(
                        "{label}: cut {cut} (power {power}): acknowledged record {} lost",
                        a.0
                    ));
                }
            }
        }
        if finished {
            eprintln!(
                "{label} (power {power}, earlier cuts {cuts_before:?}): {cut} cut points, {} findings",
                bricks.len()
            );
            break;
        }
    }
    bricks
}

fn fresh(_: &World) -> Prefix {
    (Vec::new(), Vec::new())
}

fn existing(payloads: bool) -> impl Fn(&World) -> Prefix {
    move |w: &World| {
        let (store, mut j) = w.boot(Arc::new(w.sim.clone()), payloads).unwrap();
        let mut acked = Vec::new();
        for n in 0..3 {
            acked.push(write(store.as_ref(), &mut j, n));
        }
        j.sync().unwrap();
        let flushed = acked.clone();
        for n in 3..5 {
            acked.push(write(store.as_ref(), &mut j, n)); // unflushed: survives a crash only
        }
        drop(j);
        drop(store);
        w.sim.crash();
        (acked, flushed)
    }
}

#[test]
fn every_cut_of_a_boot_reopens() {
    let mut all = Vec::new();
    for payloads in [false, true] {
        for power in [false, true] {
            let tag = if payloads { "store" } else { "plain" };
            all.extend(sweep(&format!("first open/{tag}"), payloads, power, &[], &fresh));
            all.extend(sweep(
                &format!("existing/{tag}"),
                payloads,
                power,
                &[],
                &existing(payloads),
            ));
        }
    }
    assert!(all.is_empty(), "{} findings:\n{}", all.len(), all.join("\n"));
}

#[test]
fn twice_cut_first_opens_reopen() {
    let mut all = Vec::new();
    for payloads in [false, true] {
        // The first boot is cut at every point up to the manifest write; then the second boot is
        // cut at every point too.
        for earlier in 0..40u64 {
            let tag = if payloads { "store" } else { "plain" };
            all.extend(sweep(
                &format!("first open twice/{tag}/earlier {earlier}"),
                payloads,
                false,
                &[earlier],
                &fresh,
            ));
        }
    }
    assert!(all.is_empty(), "{} findings:\n{}", all.len(), all.join("\n"));
}

fn shredded(chunk: uaos_contracts::digest::ChunkRef, n: u64) -> EventDraft {
    let mut d = draft(n, None);
    d.pocket_id = Some(pocket());
    d.event_type = types::CHUNK_SHREDDED;
    d.side_effect_class = SideEffectClass::LocalIrreversible;
    d.metadata = Metadata::new(
        [(uaos_state::journal::CHUNK_METADATA_KEY.to_owned(), chunk.to_string())]
            .into_iter()
            .collect(),
    )
    .unwrap();
    d
}

/// Existing journals whose reopen has work: a shred cut at step `k` (to complete at open), or a
/// payload lost (to journal as `chunk.lost` at open). Every cut of that reopen must reopen.
#[test]
fn every_cut_of_a_reopen_with_work_reopens() {
    let mut all = Vec::new();
    for power in [false, true] {
        // A payload lost behind the marker.
        let lost = |w: &World| {
            let (store, mut j) = w.boot(Arc::new(w.sim.clone()), true).unwrap();
            let mut acked = Vec::new();
            for n in 0..3 {
                acked.push(write(store.as_ref(), &mut j, n));
            }
            j.sync().unwrap();
            drop(j);
            drop(store);
            w.sim.crash();
            let data = Path::new(DATA).join("chunks").join(pocket().to_string()).join("data");
            let victim = w
                .sim
                .list_dir(&data)
                .unwrap()
                .into_iter()
                .find(|p| p.extension().and_then(|e| e.to_str()) == Some("chunk"))
                .unwrap();
            w.sim.remove_file(&victim).unwrap();
            w.sim.sync_dir(&data).unwrap();
            (acked.clone(), acked)
        };
        all.extend(sweep("lost payload", true, power, &[], &lost));
        for k in 0u64..60 {
            let finished = Arc::new(AtomicBool::new(false));
            let f2 = Arc::clone(&finished);
            let shred = move |w: &World| {
                let cfs = CutFs::new(w.sim.clone(), None);
                let (store, mut j) = w.boot(Arc::new(cfs.clone()), true).unwrap();
                let mut acked = Vec::new();
                let mut chunks = Vec::new();
                for n in 0..3 {
                    let c = store
                        .as_ref()
                        .unwrap()
                        .put(pocket(), format!("content {n}").as_bytes())
                        .unwrap();
                    let a = j.append(draft(n, Some(c))).unwrap();
                    acked.push((a.seq.0, a.hash));
                    chunks.push(c);
                }
                j.sync().unwrap();
                *cfs.left.lock().unwrap() = Some(k);
                if let Ok(pending) = j.shred(shredded(chunks[0], 50)) {
                    let _rewrapped = pending.finish();
                }
                if !cfs.died() {
                    f2.store(true, Ordering::SeqCst);
                }
                drop(j);
                drop(store);
                w.sim.crash();
                (acked.clone(), acked)
            };
            all.extend(sweep(&format!("shred cut {k}"), true, power, &[], &shred));
            if finished.load(Ordering::SeqCst) {
                eprintln!("shred prefix: {k} cut points");
                break;
            }
        }
    }
    assert!(all.is_empty(), "{} findings:\n{}", all.len(), all.join("\n"));
}
