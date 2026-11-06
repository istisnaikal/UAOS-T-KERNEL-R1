// SPDX-License-Identifier: Apache-2.0

//! The journal manifest: which segment files hold which sequence ranges.
//!
//! The manifest is replaced atomically ([`Fs::write_atomic`]) whenever a segment is created or
//! sealed, never per record. A sealed segment's `last_seq` bounds the records read from it:
//! anything after it in the file (a torn tail, or records superseded by a rewrite after a
//! failed flush) is ignored.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uaos_contracts::digest::Sha256Digest;
use uaos_contracts::wire::Seq;
use uaos_platform::fs::{Fs, FsError};

use super::JournalError;

/// Journal format version this binary reads and writes.
pub const READER_VERSION: u32 = 1;

/// File name of the manifest inside the journal directory.
pub const MANIFEST_FILE: &str = "MANIFEST";

/// Schema tag of the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestSchema {
    /// Version 1.
    #[serde(rename = "uaos.journal_manifest/1")]
    V1,
}

/// State of a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentStatus {
    /// The one segment currently appended to. Always the last entry.
    Active,
    /// Closed normally; its range is complete and flushed.
    Sealed,
    /// Closed after a failed flush; records after `last_seq` were rewritten to the next segment.
    Suspect,
}

/// One segment's entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentEntry {
    /// File name inside the journal directory.
    pub file: String,
    /// Sequence number of the segment's first record.
    pub first_seq: Seq,
    /// Last valid record (sealed/suspect segments); `None` if empty or still active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seq: Option<Seq>,
    /// Chain hash of `last_seq`'s line, so a sealed segment's tail is tamper-evident too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_hash: Option<Sha256Digest>,
    /// Segment state.
    pub status: SegmentStatus,
}

/// The manifest document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema tag, always `uaos.journal_manifest/1`.
    pub schema: ManifestSchema,
    /// Random identifier of this journal; binds the genesis hash to this instance.
    pub journal_id: String,
    /// Oldest reader version able to interpret this journal correctly.
    pub min_reader_version: u32,
    /// Incremented for every new segment; makes segment file names unique.
    pub generation: u64,
    /// Segments in sequence order; the last one is active.
    pub segments: Vec<SegmentEntry>,
}

impl Manifest {
    /// Path of the manifest inside `dir`.
    #[must_use]
    pub fn path(dir: &Path) -> PathBuf {
        dir.join(MANIFEST_FILE)
    }

    /// Reads and validates the manifest.
    ///
    /// # Errors
    /// `Storage` on I/O failure, `Encoding` if unparseable, `ReaderTooOld` if this binary is too
    /// old, `Corrupt` if the segment list violates its invariants.
    pub fn load(fs: &dyn Fs, dir: &Path) -> Result<Self, JournalError> {
        let bytes = fs.read(&Self::path(dir)).map_err(JournalError::Storage)?;
        let manifest: Self =
            serde_json::from_slice(&bytes).map_err(|e| JournalError::Encoding(format!("manifest: {e}")))?;
        if manifest.min_reader_version > READER_VERSION {
            return Err(JournalError::ReaderTooOld {
                reader: READER_VERSION,
                required: manifest.min_reader_version,
            });
        }
        manifest.validate()?;
        Ok(manifest)
    }

    /// Writes the manifest atomically and durably.
    ///
    /// # Errors
    /// `NoSpace` maps to `DiskFull`; other failures to `Storage`.
    pub fn store(&self, fs: &dyn Fs, dir: &Path) -> Result<(), JournalError> {
        self.validate()?;
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|e| JournalError::Encoding(format!("manifest: {e}")))?;
        bytes.push(b'\n');
        fs.write_atomic(&Self::path(dir), &bytes).map_err(|e| match e {
            FsError::NoSpace { .. } => JournalError::DiskFull,
            other => JournalError::Storage(other),
        })
    }

    /// Checks: exactly one active segment, last; ranges contiguous; unique file names.
    ///
    /// # Errors
    /// `Corrupt` describing the first violation.
    pub fn validate(&self) -> Result<(), JournalError> {
        let corrupt = |why: &str| Err(JournalError::Corrupt(format!("manifest: {why}")));
        let Some((last, earlier)) = self.segments.split_last() else {
            return corrupt("no segments");
        };
        if last.status != SegmentStatus::Active || earlier.iter().any(|s| s.status == SegmentStatus::Active) {
            return corrupt("exactly one active segment, and it must be last");
        }
        let mut names = std::collections::BTreeSet::new();
        for pair in self.segments.windows(2) {
            let [a, b] = pair else { continue };
            let next = a.last_seq.map_or(a.first_seq.0, |l| l.0.saturating_add(1));
            if b.first_seq.0 != next {
                return corrupt("segment ranges are not contiguous");
            }
            if a.last_seq.is_some() != a.last_hash.is_some() {
                return corrupt("last_seq and last_hash must be set together");
            }
        }
        for s in &self.segments {
            if !names.insert(s.file.as_str()) {
                return corrupt("duplicate segment file name");
            }
        }
        Ok(())
    }

    /// The active (last) segment.
    #[must_use]
    pub fn active(&self) -> Option<&SegmentEntry> {
        self.segments.last()
    }
}

/// File name for a new segment: first sequence number plus a generation counter, so names
/// never collide even when a recovered segment was empty.
#[must_use]
pub fn segment_file_name(first_seq: u64, generation: u64) -> String {
    format!("seg-{first_seq:020}-{generation:06}.jsonl")
}

/// Returns `true` for names produced by [`segment_file_name`].
#[must_use]
pub fn is_segment_file_name(name: &str) -> bool {
    name.starts_with("seg-")
        && Path::new(name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"))
}
