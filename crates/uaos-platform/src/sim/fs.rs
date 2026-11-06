// SPDX-License-Identifier: Apache-2.0

//! An in-memory filesystem that can crash.
//!
//! Every file has two views: what the OS holds (`data`) and the prefix that is durable
//! (`durable_len`). The namespace likewise has a live view and a durable view, updated per
//! directory by [`Fs::sync_dir`]. Two kinds of failure are modelled exactly as needs.
//!
//! * [`SimFs::crash`] — the process dies. OS-held bytes and the live namespace survive; open
//!   handles become stale; locks are released.
//! * [`SimFs::power_loss`] — the machine dies. Files are cut to their durable prefix and the
//!   namespace reverts to its last synced state.
//!
//! Faults: [`SimFs::set_capacity`] makes appends fail with `NoSpace` after writing the prefix
//! that still fits (a torn record); [`SimFs::fail_next_sync`] makes the next flush fail and
//! **drops the unflushed bytes** — Linux's behaviour after a failed writeback, which is why a
//! journal must never "retry fsync and trust the cache".

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::fs::{AppendFile, Fs, FsError, LockGuard, temp_sibling};

type FileId = u64;

#[derive(Debug, Default)]
struct Node {
    data: Vec<u8>,
    durable_len: usize,
    /// A flush of this file failed in cache-keeping mode: its unflushed bytes stay readable but
    /// can never become durable through this file again (Linux after a writeback error).
    doomed: bool,
}

#[derive(Debug, Default)]
struct State {
    live: BTreeMap<PathBuf, FileId>,
    durable: BTreeMap<PathBuf, FileId>,
    nodes: BTreeMap<FileId, Node>,
    dirs: BTreeSet<PathBuf>,
    locks: BTreeSet<PathBuf>,
    next_id: FileId,
    generation: u64,
    capacity: Option<u64>,
    /// Number of flushes to let through before failing one (`Some(0)` = fail the next).
    sync_fault_after: Option<u32>,
    /// A failed file flush keeps the unflushed bytes readable instead of dropping them.
    failed_sync_keeps_cache: bool,
}

impl State {
    fn used_bytes(&self) -> u64 {
        self.nodes
            .values()
            .map(|n| u64::try_from(n.data.len()).unwrap_or(u64::MAX))
            .sum()
    }

    fn parent_exists(&self, path: &Path) -> bool {
        match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => self.dirs.contains(p),
            _ => true,
        }
    }

    fn create(&mut self, path: &Path) -> FileId {
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.insert(id, Node::default());
        self.live.insert(path.to_path_buf(), id);
        id
    }

    /// Drops nodes no longer referenced by either namespace view.
    fn collect_garbage(&mut self) {
        let referenced: BTreeSet<FileId> = self.live.values().chain(self.durable.values()).copied().collect();
        self.nodes.retain(|id, _| referenced.contains(id));
    }

    /// Consumes one flush from the fault countdown; returns `true` if this flush must fail.
    fn sync_should_fail(&mut self) -> bool {
        match self.sync_fault_after {
            Some(0) => {
                self.sync_fault_after = None;
                true
            }
            Some(n) => {
                self.sync_fault_after = Some(n - 1);
                false
            }
            None => false,
        }
    }

    fn take_sync_fault(&mut self, id: FileId, op: &'static str) -> Result<(), FsError> {
        if self.sync_should_fail() {
            let keep = self.failed_sync_keeps_cache;
            if let Some(node) = self.nodes.get_mut(&id) {
                if keep {
                    node.doomed = true;
                } else {
                    node.data.truncate(node.durable_len);
                }
            }
            return Err(FsError::SyncFailed { op });
        }
        Ok(())
    }

    /// A successful flush: everything written becomes durable, unless the file is doomed.
    fn flushed(&mut self, id: FileId) {
        if let Some(node) = self.nodes.get_mut(&id)
            && !node.doomed
        {
            node.durable_len = node.data.len();
        }
    }
}

/// Deterministic, fault-injecting in-memory [`Fs`]. Clones share the same disk, so two
/// "processes" can contend for the same lock.
#[derive(Debug, Clone, Default)]
pub struct SimFs {
    state: Arc<Mutex<State>>,
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    // A panicking test thread must not wedge the simulated disk for the others.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl SimFs {
    /// Creates an empty simulated disk.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Limits total stored bytes. `None` removes the limit.
    pub fn set_capacity(&self, bytes: Option<u64>) {
        lock(&self.state).capacity = bytes;
    }

    /// Chooses what a failed file flush does to the unflushed bytes. Off (the default): they
    /// are dropped, so a read-back sees the loss. On: they stay readable from the cache, later
    /// flushes of the same file report success, and the bytes never become durable — Linux
    /// after a writeback error. Only rewriting the content to a new file makes it durable.
    pub fn set_failed_sync_keeps_cache(&self, on: bool) {
        lock(&self.state).failed_sync_keeps_cache = on;
    }

    /// Makes the next flush (`sync_data`, `sync_dir`, `write_atomic`) fail. For file flushes,
    /// the unflushed bytes are discarded.
    pub fn fail_next_sync(&self) {
        self.fail_sync_after(0);
    }

    /// Lets `n` flushes succeed, then makes the next one fail (as [`SimFs::fail_next_sync`]).
    pub fn fail_sync_after(&self, n: u32) {
        lock(&self.state).sync_fault_after = Some(n);
    }

    /// Disarms a flush failure armed by [`SimFs::fail_sync_after`] that has not fired yet.
    pub fn clear_sync_fault(&self) {
        lock(&self.state).sync_fault_after = None;
    }

    /// Whether a flush failure armed by [`SimFs::fail_sync_after`] has not fired yet.
    #[must_use]
    pub fn sync_fault_pending(&self) -> bool {
        lock(&self.state).sync_fault_after.is_some()
    }

    /// Simulates the process dying: handles become stale and locks are released; everything
    /// already handed to the OS remains.
    pub fn crash(&self) {
        let mut s = lock(&self.state);
        s.generation += 1;
        s.locks.clear();
    }

    /// Simulates the machine losing power: files are cut to their durable prefix and the
    /// namespace reverts to its last synced state. Implies [`SimFs::crash`].
    pub fn power_loss(&self) {
        let mut s = lock(&self.state);
        s.generation += 1;
        s.locks.clear();
        s.live = s.durable.clone();
        for node in s.nodes.values_mut() {
            node.data.truncate(node.durable_len);
        }
        s.collect_garbage();
    }

    /// Silently changes one byte of a file in both its OS and durable views, modelling media
    /// corruption or tampering by another process. Returns `false` if there is no such byte.
    #[must_use]
    pub fn overwrite_byte(&self, path: &Path, offset: usize, value: u8) -> bool {
        let mut s = lock(&self.state);
        let Some(id) = s.live.get(path).copied() else {
            return false;
        };
        s.nodes
            .get_mut(&id)
            .and_then(|n| n.data.get_mut(offset))
            .map(|b| *b = value)
            .is_some()
    }

    /// The OS writes `path`'s cached bytes back on its own, as a real one may at any time: they
    /// become durable without a flush (no fault is consumed).
    pub fn write_back(&self, path: &Path) {
        let mut s = lock(&self.state);
        if let Some(&id) = s.live.get(path) {
            s.flushed(id);
        }
    }

    /// The OS writes back only the first `num`/`den` of `path`'s unflushed bytes (page by
    /// page, from the start), so a later power loss leaves a torn file.
    pub fn write_back_part(&self, path: &Path, num: usize, den: usize) {
        let mut s = lock(&self.state);
        if let Some(&id) = s.live.get(path)
            && let Some(node) = s.nodes.get_mut(&id)
            && !node.doomed
            && node.data.len() > node.durable_len
        {
            let extra = (node.data.len() - node.durable_len) * num / den.max(1);
            node.durable_len += extra;
        }
    }

    /// The OS persists `dir`'s entries on its own, whatever the files' bytes: an entry can become
    /// durable before its data.
    pub fn write_back_dir(&self, dir: &Path) {
        let mut s = lock(&self.state);
        if !s.dirs.contains(dir) {
            return;
        }
        let in_dir = |p: &PathBuf| p.parent() == Some(dir);
        s.durable.retain(|p, _| !in_dir(p));
        let live: Vec<(PathBuf, FileId)> = s
            .live
            .iter()
            .filter(|(p, _)| in_dir(p))
            .map(|(p, id)| (p.clone(), *id))
            .collect();
        s.durable.extend(live);
        s.collect_garbage();
    }

    /// Bytes the OS currently holds for `path` (test inspection).
    #[must_use]
    pub fn os_view(&self, path: &Path) -> Option<Vec<u8>> {
        let s = lock(&self.state);
        s.live.get(path).and_then(|id| s.nodes.get(id)).map(|n| n.data.clone())
    }
}

#[derive(Debug)]
struct SimAppendFile {
    state: Arc<Mutex<State>>,
    id: FileId,
    generation: u64,
}

impl SimAppendFile {
    fn check(&self, s: &State, op: &'static str) -> Result<(), FsError> {
        if s.generation != self.generation {
            return Err(FsError::StaleHandle { op });
        }
        if !s.nodes.contains_key(&self.id) {
            return Err(FsError::NotFound { op });
        }
        Ok(())
    }
}

impl AppendFile for SimAppendFile {
    fn append(&mut self, bytes: &[u8]) -> Result<(), FsError> {
        let mut s = lock(&self.state);
        self.check(&s, "append")?;
        let free = s.capacity.map(|cap| cap.saturating_sub(s.used_bytes()));
        let fits = free.map_or(bytes.len(), |free| {
            usize::try_from(free).unwrap_or(usize::MAX).min(bytes.len())
        });
        let (written, rest) = bytes.split_at(fits);
        if let Some(node) = s.nodes.get_mut(&self.id) {
            node.data.extend_from_slice(written);
        }
        if rest.is_empty() {
            Ok(())
        } else {
            Err(FsError::NoSpace { op: "append" })
        }
    }

    fn sync_data(&mut self) -> Result<(), FsError> {
        let mut s = lock(&self.state);
        self.check(&s, "sync_data")?;
        s.take_sync_fault(self.id, "sync_data")?;
        s.flushed(self.id);
        Ok(())
    }

    fn os_len(&self) -> Result<u64, FsError> {
        let s = lock(&self.state);
        self.check(&s, "os_len")?;
        Ok(s.nodes
            .get(&self.id)
            .map_or(0, |n| u64::try_from(n.data.len()).unwrap_or(u64::MAX)))
    }
}

#[derive(Debug)]
struct SimLockGuard {
    state: Arc<Mutex<State>>,
    path: PathBuf,
    generation: u64,
}

impl LockGuard for SimLockGuard {}

impl Drop for SimLockGuard {
    fn drop(&mut self) {
        let mut s = lock(&self.state);
        // A crash already released every lock; a guard from a dead process must not release a
        // lock re-acquired by its successor.
        if s.generation == self.generation {
            s.locks.remove(&self.path);
        }
    }
}

impl Fs for SimFs {
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        let mut s = lock(&self.state);
        for ancestor in path.ancestors().filter(|a| !a.as_os_str().is_empty()) {
            s.dirs.insert(ancestor.to_path_buf());
        }
        Ok(())
    }

    fn open_append(&self, path: &Path) -> Result<Box<dyn AppendFile>, FsError> {
        let mut s = lock(&self.state);
        if !s.parent_exists(path) {
            return Err(FsError::NotFound { op: "open_append" });
        }
        let id = match s.live.get(path) {
            Some(&id) => id,
            None => s.create(path),
        };
        Ok(Box::new(SimAppendFile {
            state: Arc::clone(&self.state),
            id,
            generation: s.generation,
        }))
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        self.os_view(path).ok_or(FsError::NotFound { op: "read" })
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError> {
        let s = lock(&self.state);
        if !s.dirs.contains(path) {
            return Err(FsError::NotFound { op: "list_dir" });
        }
        let files = s.live.keys().filter(|p| p.parent() == Some(path));
        let subdirs = s.dirs.iter().filter(|d| d.parent() == Some(path));
        let mut out: Vec<PathBuf> = files.chain(subdirs).cloned().collect();
        out.sort();
        Ok(out)
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        let mut s = lock(&self.state);
        if !s.parent_exists(to) {
            return Err(FsError::NotFound { op: "rename" });
        }
        let id = s.live.remove(from).ok_or(FsError::NotFound { op: "rename" })?;
        s.live.insert(to.to_path_buf(), id);
        // A displaced node is unreachable by path; it is collected at the next directory flush
        // or power loss. Collecting here made every rename linear in the number of files.
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        let mut s = lock(&self.state);
        s.live.remove(path).ok_or(FsError::NotFound { op: "remove_file" })?;
        // Collected later, as for `rename`.
        Ok(())
    }

    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        let mut s = lock(&self.state);
        if !s.dirs.contains(path) {
            return Err(FsError::NotFound { op: "sync_dir" });
        }
        if s.sync_should_fail() {
            return Err(FsError::SyncFailed { op: "sync_dir" });
        }
        let in_dir = |p: &PathBuf| p.parent() == Some(path);
        s.durable.retain(|p, _| !in_dir(p));
        let live_entries: Vec<(PathBuf, FileId)> = s
            .live
            .iter()
            .filter(|(p, _)| in_dir(p))
            .map(|(p, id)| (p.clone(), *id))
            .collect();
        s.durable.extend(live_entries);
        s.collect_garbage();
        Ok(())
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        let tmp = temp_sibling(path);
        let result = (|| {
            if self.os_view(&tmp).is_some() {
                self.remove_file(&tmp)?;
            }
            let mut file = self.open_append(&tmp)?;
            file.append(bytes)?;
            file.sync_data()?;
            drop(file);
            self.rename(&tmp, path)?;
            match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => self.sync_dir(parent),
                _ => Ok(()),
            }
        })();
        if result.is_err() && self.os_view(&tmp).is_some() {
            // Mirrors the real implementation's cleanup; failure here changes nothing reported.
            let _cleanup_result = self.remove_file(&tmp);
        }
        result
    }

    fn write_unsynced(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        let tmp = temp_sibling(path);
        let result = (|| {
            let mut file = self.open_append(&tmp)?;
            file.append(bytes)?;
            drop(file);
            self.rename(&tmp, path)
        })();
        if result.is_err() && self.os_view(&tmp).is_some() {
            // Mirrors the real implementation's cleanup; failure here changes nothing reported.
            let _cleanup_result = self.remove_file(&tmp);
        }
        result
    }

    fn sync_file(&self, path: &Path) -> Result<(), FsError> {
        let mut s = lock(&self.state);
        let id = *s.live.get(path).ok_or(FsError::NotFound { op: "sync_file" })?;
        s.take_sync_fault(id, "sync_file")?;
        s.flushed(id);
        Ok(())
    }

    fn try_lock_exclusive(&self, path: &Path) -> Result<Box<dyn LockGuard>, FsError> {
        let mut s = lock(&self.state);
        if !s.parent_exists(path) {
            return Err(FsError::NotFound { op: "lock" });
        }
        if !s.locks.insert(path.to_path_buf()) {
            return Err(FsError::Locked { op: "lock" });
        }
        if !s.live.contains_key(path) {
            s.create(path);
        }
        Ok(Box::new(SimLockGuard {
            state: Arc::clone(&self.state),
            path: path.to_path_buf(),
            generation: s.generation,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn setup() -> (SimFs, PathBuf) {
        let fs = SimFs::new();
        let dir = PathBuf::from("/data/journal");
        fs.create_dir_all(&dir).unwrap();
        (fs, dir)
    }

    #[test]
    fn conforms() {
        let fs = SimFs::new();
        fs.create_dir_all(Path::new("/root")).unwrap();
        crate::fs::conformance::run(&fs, Path::new("/root"));
    }

    #[test]
    fn crash_keeps_os_bytes_and_staleness_is_enforced() {
        let (fs, dir) = setup();
        let seg = dir.join("seg");
        let mut f = fs.open_append(&seg).unwrap();
        f.append(b"acked\n").unwrap();
        fs.crash();
        assert_eq!(fs.read(&seg).unwrap(), b"acked\n");
        assert_eq!(f.append(b"zombie"), Err(FsError::StaleHandle { op: "append" }));
    }

    #[test]
    fn power_loss_keeps_only_durable_bytes_and_synced_entries() {
        let (fs, dir) = setup();
        let seg = dir.join("seg");
        let mut f = fs.open_append(&seg).unwrap();
        f.append(b"durable\n").unwrap();
        f.sync_data().unwrap();
        f.append(b"volatile\n").unwrap();
        fs.sync_dir(&dir).unwrap();
        let unsynced_entry = dir.join("new");
        fs.open_append(&unsynced_entry).unwrap().sync_data().unwrap();

        fs.power_loss();
        assert_eq!(fs.read(&seg).unwrap(), b"durable\n");
        assert!(
            fs.read(&unsynced_entry).is_err(),
            "entry was never made durable by sync_dir"
        );
    }

    #[test]
    fn failed_sync_discards_unflushed_bytes() {
        let (fs, dir) = setup();
        let seg = dir.join("seg");
        let mut f = fs.open_append(&seg).unwrap();
        f.append(b"a\n").unwrap();
        f.sync_data().unwrap();
        f.append(b"b\n").unwrap();
        fs.fail_next_sync();
        assert_eq!(f.sync_data(), Err(FsError::SyncFailed { op: "sync_data" }));
        // The cache no longer has "b": re-reading proves nothing about durability.
        assert_eq!(fs.read(&seg).unwrap(), b"a\n");
        // The next flush "succeeds" — exactly the trap a journal must not fall into.
        f.sync_data().unwrap();
    }

    #[test]
    fn disk_full_writes_a_torn_prefix() {
        let (fs, dir) = setup();
        fs.set_capacity(Some(10));
        let seg = dir.join("seg");
        let mut f = fs.open_append(&seg).unwrap();
        f.append(b"12345\n").unwrap();
        assert_eq!(f.append(b"67890\n"), Err(FsError::NoSpace { op: "append" }));
        assert_eq!(fs.read(&seg).unwrap(), b"12345\n6789");
    }

    #[test]
    fn lock_is_released_by_crash_and_survives_stale_guard_drop() {
        let (fs, dir) = setup();
        let path = dir.join("uaos.lock");
        let first = fs.try_lock_exclusive(&path).unwrap();
        fs.crash();
        let second = fs.try_lock_exclusive(&path).unwrap();
        drop(first); // the dead process's guard must not release the successor's lock
        assert!(matches!(fs.try_lock_exclusive(&path), Err(FsError::Locked { .. })));
        drop(second);
        assert!(fs.try_lock_exclusive(&path).is_ok());
    }

    #[test]
    fn unsynced_write_is_kept_by_a_crash_and_may_vanish_on_power_loss() {
        let (fs, dir) = setup();
        fs.sync_dir(&dir).unwrap();
        let chunk = dir.join("c.chunk");
        fs.write_unsynced(&chunk, b"payload").unwrap();
        fs.crash();
        assert_eq!(
            fs.read(&chunk).unwrap(),
            b"payload",
            "a process crash keeps what the OS holds"
        );
        fs.power_loss();
        assert!(fs.read(&chunk).is_err(), "neither the data nor the entry was flushed");

        // The entry flushed but not the data: the file comes back empty (torn), never mixed.
        fs.write_unsynced(&chunk, b"payload").unwrap();
        fs.sync_dir(&dir).unwrap();
        fs.power_loss();
        assert_eq!(fs.read(&chunk).unwrap(), b"");

        // Data and entry flushed: durable.
        fs.write_unsynced(&chunk, b"payload").unwrap();
        fs.sync_file(&chunk).unwrap();
        fs.sync_dir(&dir).unwrap();
        fs.power_loss();
        assert_eq!(fs.read(&chunk).unwrap(), b"payload");
    }

    #[test]
    fn in_cache_keeping_mode_a_failed_flush_dooms_the_file_but_not_a_rewrite() {
        let (fs, dir) = setup();
        fs.set_failed_sync_keeps_cache(true);
        fs.sync_dir(&dir).unwrap();
        let chunk = dir.join("c.chunk");
        fs.write_unsynced(&chunk, b"payload").unwrap();
        fs.sync_dir(&dir).unwrap();
        fs.fail_next_sync();
        assert!(fs.sync_file(&chunk).is_err());
        assert_eq!(fs.read(&chunk).unwrap(), b"payload", "the cache still serves the bytes");
        fs.sync_file(&chunk).unwrap(); // reports success, as Linux does after the error
        fs.power_loss();
        assert_eq!(fs.read(&chunk).unwrap(), b"", "a doomed file never became durable");

        // Rewriting to a new file is the only way back.
        fs.write_atomic(&chunk, b"payload").unwrap();
        fs.power_loss();
        assert_eq!(fs.read(&chunk).unwrap(), b"payload");
    }

    #[test]
    fn failed_file_sync_discards_the_unflushed_content() {
        let (fs, dir) = setup();
        let chunk = dir.join("c.chunk");
        fs.write_unsynced(&chunk, b"payload").unwrap();
        fs.fail_next_sync();
        assert_eq!(fs.sync_file(&chunk), Err(FsError::SyncFailed { op: "sync_file" }));
        assert_eq!(fs.read(&chunk).unwrap(), b"", "the OS dropped the unflushed pages");
    }

    #[test]
    fn write_atomic_survives_power_loss_as_old_or_new() {
        let (fs, dir) = setup();
        let manifest = dir.join("MANIFEST");
        fs.write_atomic(&manifest, b"old").unwrap();
        fs.fail_next_sync();
        assert!(fs.write_atomic(&manifest, b"new").is_err());
        fs.power_loss();
        assert_eq!(fs.read(&manifest).unwrap(), b"old");
    }

    proptest! {
        /// Whatever happens, after power loss each file holds exactly what was durable.
        #[test]
        fn power_loss_preserves_exactly_the_synced_prefix(
            ops in prop::collection::vec((prop::collection::vec(any::<u8>(), 0..32), any::<bool>()), 0..40)
        ) {
            let (fs, dir) = setup();
            let seg = dir.join("seg");
            let mut f = fs.open_append(&seg).unwrap();
            fs.sync_dir(&dir).unwrap();
            let mut durable = Vec::new();
            let mut written = Vec::new();
            for (bytes, sync) in ops {
                f.append(&bytes).unwrap();
                written.extend_from_slice(&bytes);
                if sync {
                    f.sync_data().unwrap();
                    durable.clone_from(&written);
                }
            }
            fs.power_loss();
            prop_assert_eq!(fs.read(&seg).unwrap(), durable);
        }
    }
}
