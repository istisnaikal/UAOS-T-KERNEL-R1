// SPDX-License-Identifier: Apache-2.0

//! Reading and verifying the journal.
//!
//! The chain is checked over the **exact stored bytes** of each line, including its trailing
//! newline: `hash_i = SHA-256(line_i)`, and line `i+1` must carry `prev_hash = hash_i`. The first
//! record chains to a genesis hash bound to the journal's random ID. Anyone can recompute this with
//! stock tools; no canonicalization is involved.
//!
//! Tamper evidence has a stated limit: changing the **last** record of the active segment is
//! detectable only against an externally anchored head.

use std::path::Path;

use uaos_contracts::digest::Sha256Digest;
use uaos_contracts::event::EventEnvelope;
use uaos_platform::crypto::sha256;
use uaos_platform::fs::Fs;

use super::JournalError;
use super::manifest::{Manifest, SegmentStatus};

/// Chain anchor of record 0, bound to this journal instance.
#[must_use]
pub fn genesis_hash(journal_id: &str) -> Sha256Digest {
    let mut input = b"uaos.journal/1 genesis ".to_vec();
    input.extend_from_slice(journal_id.as_bytes());
    sha256(&input)
}

/// A record that passed verification.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedRecord {
    /// The parsed envelope.
    pub envelope: EventEnvelope,
    /// Chain hash of its stored line.
    pub hash: Sha256Digest,
}

/// Summary of a verification pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Journal instance identifier.
    pub journal_id: String,
    /// Number of verified records.
    pub records: u64,
    /// Next sequence number a writer would assign.
    pub next_seq: u64,
    /// Chain hash of the last verified record (genesis if empty).
    pub head: Sha256Digest,
    /// Number of segments listed in the manifest.
    pub segments: usize,
    /// Bytes ignored after the last complete line of the active segment (an unacknowledged
    /// torn write), plus bytes beyond the sealed range of closed segments.
    pub ignored_tail_bytes: u64,
}

/// Verifies the whole journal in `dir` and returns its records in order.
///
/// # Errors
/// `ChainBroken` if any record does not continue the chain, `Corrupt` if a sealed segment is
/// missing or shorter than its recorded range, and manifest errors from [`Manifest::load`].
pub fn read_verified(fs: &dyn Fs, dir: &Path) -> Result<(Vec<VerifiedRecord>, VerifyReport), JournalError> {
    let manifest = Manifest::load(fs, dir)?;
    let mut head = genesis_hash(&manifest.journal_id);
    let mut next_seq: u64 = manifest.segments.first().map_or(0, |s| s.first_seq.0);
    let mut records = Vec::new();
    let mut ignored = 0u64;

    for segment in &manifest.segments {
        if segment.first_seq.0 != next_seq {
            return Err(JournalError::Corrupt(format!(
                "segment {} does not start where the previous ended",
                segment.file
            )));
        }
        let bytes = fs.read(&dir.join(&segment.file)).map_err(JournalError::Storage)?;
        let bound = match segment.status {
            SegmentStatus::Active => None,
            SegmentStatus::Sealed | SegmentStatus::Suspect => Some(segment.last_seq),
        };
        let mut rest: &[u8] = &bytes;
        while let Some(pos) = rest.iter().position(|&b| b == b'\n') {
            if let Some(last) = bound
                && last.is_none_or(|l| next_seq > l.0)
            {
                break;
            }
            let (line, tail) = rest.split_at(pos + 1);
            rest = tail;
            let envelope: EventEnvelope = serde_json::from_slice(line).map_err(|e| JournalError::ChainBroken {
                seq: next_seq,
                reason: format!("line is not a valid uaos.event/1 record ({e})"),
            })?;
            if envelope.seq.0 != next_seq {
                return Err(JournalError::ChainBroken {
                    seq: next_seq,
                    reason: format!("found seq {}", envelope.seq),
                });
            }
            if envelope.prev_hash != head {
                return Err(JournalError::ChainBroken {
                    seq: next_seq,
                    reason: "prev_hash does not match".to_owned(),
                });
            }
            head = sha256(line);
            records.push(VerifiedRecord { envelope, hash: head });
            next_seq += 1;
        }
        ignored += u64::try_from(rest.len()).unwrap_or(u64::MAX);

        if let Some(last) = bound {
            let expected_next = last.map_or(segment.first_seq.0, |l| l.0 + 1);
            if next_seq != expected_next {
                let found = if next_seq > segment.first_seq.0 {
                    format!("seq {}", next_seq - 1)
                } else {
                    "no record".to_owned()
                };
                let recorded = last.map_or_else(|| "no record".to_owned(), |l| format!("seq {l}"));
                return Err(JournalError::Corrupt(format!(
                    "sealed segment {}: the manifest records it through {recorded}, but the file verifies through {found}",
                    segment.file
                )));
            }
            if last.is_some() && segment.last_hash != Some(head) {
                return Err(JournalError::ChainBroken {
                    seq: next_seq.saturating_sub(1),
                    reason: "sealed segment tail hash does not match the manifest".to_owned(),
                });
            }
        }
    }

    let report = VerifyReport {
        journal_id: manifest.journal_id.clone(),
        records: u64::try_from(records.len()).unwrap_or(u64::MAX),
        next_seq,
        head,
        segments: manifest.segments.len(),
        ignored_tail_bytes: ignored,
    };
    Ok((records, report))
}

/// Verifies the journal without keeping the records.
///
/// # Errors
/// As [`read_verified`].
pub fn verify(fs: &dyn Fs, dir: &Path) -> Result<VerifyReport, JournalError> {
    read_verified(fs, dir).map(|(_, report)| report)
}
