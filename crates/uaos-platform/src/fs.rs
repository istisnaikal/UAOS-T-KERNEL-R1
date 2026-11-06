// SPDX-License-Identifier: Apache-2.0

//! Filesystem boundary.
//!
//! The journal and every other durable store reach the disk only through [`Fs`]. The real
//! implementation ([`crate::real::fs::OsFs`]) wraps `std::fs`; the simulation
//! ([`crate::sim::fs::SimFs`]) models the two crash types the journal must survive:
//!
//! * **process crash** (kill -9): bytes already handed to the OS survive;
//! * **power loss**: only bytes made durable with [`AppendFile::sync_data`], and directory
//!   entries made durable with [`Fs::sync_dir`], survive.
//!
//! The API is intentionally narrow: append-only files, whole-file atomic replacement, rename,
//! remove, list, directory sync and an exclusive lock. Narrow APIs are easy to model faithfully,
//! and the conformance tests run every scenario against both implementations.
//!
//! Errors carry the failed operation, never a path: paths contain user names and must not reach
//! user-facing messages unredacted. Callers add context with data-directory-relative names.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Filesystem failure, classified for recovery decisions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FsError {
    /// The target does not exist.
    #[error("{op}: not found")]
    NotFound {
        /// Operation that failed.
        op: &'static str,
    },
    /// The target already exists.
    #[error("{op}: already exists")]
    AlreadyExists {
        /// Operation that failed.
        op: &'static str,
    },
    /// The OS refused access.
    #[error("{op}: permission denied")]
    PermissionDenied {
        /// Operation that failed.
        op: &'static str,
    },
    /// The device is full. An append may have written a prefix of the data before failing.
    #[error("{op}: no space left on device")]
    NoSpace {
        /// Operation that failed.
        op: &'static str,
    },
    /// Flushing to stable storage failed. Data written since the last successful flush must be
    /// considered lost; re-reading the file proves nothing (the OS may serve stale cache).
    #[error("{op}: flushing to stable storage failed; unflushed data must be considered lost")]
    SyncFailed {
        /// Operation that failed.
        op: &'static str,
    },
    /// Another holder owns the exclusive lock.
    #[error("{op}: already locked by another holder")]
    Locked {
        /// Operation that failed.
        op: &'static str,
    },
    /// The handle belongs to a process that no longer exists (simulation of a crash).
    #[error("{op}: the handle belongs to a crashed process")]
    StaleHandle {
        /// Operation that failed.
        op: &'static str,
    },
    /// Any other I/O failure.
    #[error("{op}: I/O error ({kind})")]
    Io {
        /// Operation that failed.
        op: &'static str,
        /// The OS error kind, for diagnostics.
        kind: String,
    },
}

impl FsError {
    /// Classifies a `std::io::Error` raised by `op`.
    #[must_use]
    pub fn from_io(op: &'static str, error: &std::io::Error) -> Self {
        use std::io::ErrorKind as K;
        match error.kind() {
            K::NotFound => Self::NotFound { op },
            K::AlreadyExists => Self::AlreadyExists { op },
            K::PermissionDenied => Self::PermissionDenied { op },
            K::StorageFull | K::QuotaExceeded => Self::NoSpace { op },
            kind => Self::Io {
                op,
                kind: kind.to_string(),
            },
        }
    }
}

/// A file opened for appending.
pub trait AppendFile: Send + fmt::Debug {
    /// Appends all of `bytes`. Returns once the OS holds them (they survive a process crash, not
    /// necessarily a power loss). On [`FsError::NoSpace`] a prefix may have been written.
    ///
    /// # Errors
    /// Any [`FsError`]; the file's tail must then be treated as possibly torn.
    fn append(&mut self, bytes: &[u8]) -> Result<(), FsError>;

    /// Makes every byte appended so far durable against power loss.
    ///
    /// # Errors
    /// [`FsError::SyncFailed`] if the flush failed; see its documentation.
    fn sync_data(&mut self) -> Result<(), FsError>;

    /// Current length of the file as seen by the OS.
    ///
    /// # Errors
    /// Any [`FsError`].
    fn os_len(&self) -> Result<u64, FsError>;
}

/// An exclusive lock, released when dropped (or when the holding process dies).
pub trait LockGuard: Send + fmt::Debug {}

/// The filesystem operations durable stores may use.
pub trait Fs: Send + Sync + fmt::Debug {
    /// Creates a directory and its parents.
    ///
    /// # Errors
    /// Any [`FsError`].
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError>;

    /// Creates a directory and its parents, the ones it creates readable only by their owner: mode
    /// `0700` on Unix. On Windows a directory inherits its parent's permissions, which for the data
    /// directory is the user's own `%LOCALAPPDATA%`. A directory that already exists keeps its
    /// permissions. The default is [`Fs::create_dir_all`], for implementations without permissions,
    /// such as simulations.
    ///
    /// # Errors
    /// Any [`FsError`].
    fn create_private_dir_all(&self, path: &Path) -> Result<(), FsError> {
        self.create_dir_all(path)
    }

    /// Whether the directory `path` is readable only by its owner: on Unix, no group or other
    /// permission bits. `None` where this implementation cannot tell: Windows, whose permissions
    /// are inherited ACLs, and simulations. Never a guess.
    ///
    /// # Errors
    /// Any [`FsError`], e.g. [`FsError::NotFound`].
    fn private_dir(&self, _path: &Path) -> Result<Option<bool>, FsError> {
        Ok(None)
    }

    /// Opens a file for appending, creating it if needed. A newly created file's directory
    /// entry is durable only after [`Fs::sync_dir`] on its parent.
    ///
    /// # Errors
    /// Any [`FsError`].
    fn open_append(&self, path: &Path) -> Result<Box<dyn AppendFile>, FsError>;

    /// Reads a whole file.
    ///
    /// # Errors
    /// Any [`FsError`].
    fn read(&self, path: &Path) -> Result<Vec<u8>, FsError>;

    /// Lists the entries of a directory as full paths, sorted.
    ///
    /// # Errors
    /// Any [`FsError`].
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError>;

    /// Atomically renames `from` to `to`, replacing `to` if it exists. Durable after
    /// [`Fs::sync_dir`] on the parent.
    ///
    /// # Errors
    /// Any [`FsError`].
    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError>;

    /// Removes a file. Durable after [`Fs::sync_dir`] on the parent.
    ///
    /// # Errors
    /// Any [`FsError`].
    fn remove_file(&self, path: &Path) -> Result<(), FsError>;

    /// Makes the directory's entries (creations, renames, removals) durable against power loss.
    /// A no-op on platforms whose filesystems journal metadata synchronously (Windows/NTFS).
    ///
    /// # Errors
    /// Any [`FsError`].
    fn sync_dir(&self, path: &Path) -> Result<(), FsError>;

    /// Replaces `path` with `bytes` atomically and durably: write a sibling temporary file,
    /// flush it, rename it over `path`, then sync the directory. After success, a power loss
    /// leaves either the old or the new content, never a mixture.
    ///
    /// # Errors
    /// Any [`FsError`]. On failure `path` holds its previous content, unless the rename landed and
    /// only the directory flush after it failed: then it holds the new content, which a power loss
    /// may still take back. A caller that must not leave the new content behind removes it.
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError>;

    /// Replaces `path` with `bytes` atomically against a **process crash**, without flushing: a
    /// uniquely named sibling temporary is written and renamed over `path`. After a process crash
    /// `path` holds its old or its new content, never a mixture. After a **power loss** it may hold
    /// the old content, the new content, or an empty or torn file, until [`Fs::sync_file`] on
    /// `path` and [`Fs::sync_dir`] on its parent have both succeeded.
    ///
    /// # Errors
    /// Any [`FsError`]; on failure `path` still holds its previous content.
    fn write_unsynced(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError>;

    /// Makes a closed file's content durable against power loss (its directory entry still
    /// needs [`Fs::sync_dir`]).
    ///
    /// # Errors
    /// [`FsError::SyncFailed`] if the flush failed: the unflushed content must be considered
    /// lost. [`FsError::NotFound`] if there is no such file.
    fn sync_file(&self, path: &Path) -> Result<(), FsError>;

    /// Takes an exclusive lock on `path` (created if absent) without waiting.
    ///
    /// # Errors
    /// [`FsError::Locked`] if another holder (in this or another process) owns it.
    fn try_lock_exclusive(&self, path: &Path) -> Result<Box<dyn LockGuard>, FsError>;
}

/// The marker every temporary file name carries.
const TEMP_MARKER: &str = ".uaos-tmp-";

/// Distinguishes the temporaries of concurrent writes within one process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A sibling temporary path for [`Fs::write_atomic`] and [`Fs::write_unsynced`], unique per
/// call. Two writers replacing the same file at the same time never share a temporary, so
/// neither can tear the other's bytes (S-6).
pub(crate) fn temp_sibling(path: &Path) -> PathBuf {
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = path.file_name().map(std::ffi::OsStr::to_os_string).unwrap_or_default();
    name.push(format!("{TEMP_MARKER}{}-{n}", std::process::id()));
    path.with_file_name(name)
}

/// Whether `name` is a temporary left by an interrupted [`Fs::write_atomic`] or
/// [`Fs::write_unsynced`], in the current form (`<name>.uaos-tmp-<pid>-<n>`) or the form used
/// before temporaries were unique (`<name>.uaos-tmp`). Such files are never referenced and may
/// be removed at startup.
#[must_use]
pub fn is_temp_file_name(name: &str) -> bool {
    name.contains(TEMP_MARKER) || name.ends_with(".uaos-tmp")
}

#[cfg(test)]
mod tests {
    use super::{is_temp_file_name, temp_sibling};
    use std::path::Path;

    #[test]
    fn temp_names_are_unique_per_call_and_recognisable() {
        let target = Path::new("/data/chunks/pkt/data/abc.chunk");
        let (a, b) = (temp_sibling(target), temp_sibling(target));
        assert_ne!(a, b, "two concurrent writers of one file must never share a temporary");
        for t in [&a, &b] {
            assert_eq!(t.parent(), target.parent());
            assert!(is_temp_file_name(t.file_name().and_then(|n| n.to_str()).unwrap()));
        }
        assert!(!is_temp_file_name("abc.chunk"));
        assert!(
            is_temp_file_name("abc.key.uaos-tmp"),
            "the pre-S-6 temporary name is still swept"
        );
    }
}

#[cfg(test)]
pub(crate) mod conformance {
    //! One scenario, run against every [`Fs`] implementation: the simulation must agree with
    //! the real filesystem on everything both can observe.

    use super::{Fs, FsError};
    use std::path::Path;

    pub(crate) fn run(fs: &dyn Fs, root: &Path) {
        let dir = root.join("journal");
        fs.create_dir_all(&dir).unwrap();
        fs.sync_dir(root).unwrap();

        // Append, length, read.
        let seg = dir.join("00000000.jsonl");
        let mut f = fs.open_append(&seg).unwrap();
        f.append(b"one\n").unwrap();
        f.append(b"two\n").unwrap();
        f.sync_data().unwrap();
        assert_eq!(f.os_len().unwrap(), 8);
        assert_eq!(fs.read(&seg).unwrap(), b"one\ntwo\n");

        // Reopening appends, never truncates.
        drop(f);
        let mut f = fs.open_append(&seg).unwrap();
        f.append(b"three\n").unwrap();
        assert_eq!(fs.read(&seg).unwrap(), b"one\ntwo\nthree\n");
        drop(f);

        // Atomic replace, flushed and unflushed.
        let manifest = dir.join("MANIFEST");
        fs.write_atomic(&manifest, b"v1").unwrap();
        fs.write_atomic(&manifest, b"v2").unwrap();
        assert_eq!(fs.read(&manifest).unwrap(), b"v2");
        let marker = dir.join("FLUSHED");
        fs.write_unsynced(&marker, b"m1").unwrap();
        fs.write_unsynced(&marker, b"m2").unwrap();
        assert_eq!(fs.read(&marker).unwrap(), b"m2");
        fs.sync_file(&marker).unwrap();
        assert!(matches!(
            fs.sync_file(&dir.join("absent")),
            Err(FsError::NotFound { .. })
        ));
        fs.remove_file(&marker).unwrap();

        // Listing is sorted and excludes the temporary file.
        let names: Vec<String> = fs
            .list_dir(&dir)
            .unwrap()
            .iter()
            .filter_map(|p| p.file_name()?.to_str().map(str::to_owned))
            .collect();
        assert_eq!(names, ["00000000.jsonl", "MANIFEST"]);

        // Rename and remove.
        let renamed = dir.join("00000000.sealed");
        fs.rename(&seg, &renamed).unwrap();
        assert!(matches!(fs.read(&seg), Err(FsError::NotFound { .. })));
        fs.remove_file(&renamed).unwrap();
        assert!(matches!(fs.read(&renamed), Err(FsError::NotFound { .. })));
        fs.sync_dir(&dir).unwrap();

        // Exclusive lock: a second holder is refused until the first lets go.
        let lock_path = root.join("uaos.lock");
        let guard = fs.try_lock_exclusive(&lock_path).unwrap();
        assert!(matches!(fs.try_lock_exclusive(&lock_path), Err(FsError::Locked { .. })));
        drop(guard);
        let _again = fs.try_lock_exclusive(&lock_path).unwrap();
    }
}
