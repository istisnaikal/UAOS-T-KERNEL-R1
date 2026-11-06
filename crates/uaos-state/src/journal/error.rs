// SPDX-License-Identifier: Apache-2.0

use uaos_contracts::error::{ErrorCode, codes};
use uaos_platform::PlatformError;
use uaos_platform::fs::FsError;

use crate::chunks::ChunkError;

/// Journal failure. Every variant maps to a registered error code via [`JournalError::code`].
///
/// **Contract for callers of [`super::Journal::append`]:** an error means the record *may*
/// still exist (it can have reached the OS before a later step failed). The caller must not
/// perform the side effect the record announces; recovery surfaces such records as
/// `Indeterminate`, never as completed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JournalError {
    /// Another daemon holds the data-directory lock.
    #[error("another UAOS daemon owns this data directory")]
    InstanceLocked,
    /// The device is full; the writer refuses records until space is freed and
    /// [`super::Journal::recover`] succeeds.
    #[error("the data directory is out of space; journal writes are refused until space is freed")]
    DiskFull,
    /// A flush failed and the rewrite to a fresh segment also failed; the writer has stopped.
    #[error("flushing the journal failed and could not be recovered; the writer has stopped")]
    Stopped,
    /// A write failed for a reason other than space.
    #[error("journal write failed: {0}")]
    Write(FsError),
    /// Reading or managing journal files failed.
    #[error("journal storage error: {0}")]
    Storage(FsError),
    /// The on-disk structure is inconsistent (missing sealed segment, manifest lost, …).
    #[error("journal is corrupt: {0}")]
    Corrupt(String),
    /// A record does not continue the hash chain.
    #[error("journal chain does not verify at seq {seq}: {reason}")]
    ChainBroken {
        /// Sequence number where verification failed.
        seq: u64,
        /// What did not match.
        reason: String,
    },
    /// The journal requires a newer reader than this binary.
    #[error("this binary reads journal format v{reader}, the journal requires v{required}")]
    ReaderTooOld {
        /// Reader version of this binary.
        reader: u32,
        /// Minimum reader version recorded in the manifest.
        required: u32,
    },
    /// A record would exceed the maximum journal line size.
    #[error("record exceeds the maximum journal line size")]
    LineTooLarge,
    /// The clock or randomness source failed; UAOS never fabricates timestamps or IDs.
    #[error("platform failure: {0}")]
    Platform(PlatformError),
    /// A record or the manifest could not be encoded or decoded.
    #[error("encoding error: {0}")]
    Encoding(String),
    /// A record references a content chunk that is not stored (or a chunk without its pocket).
    /// Payloads are written before the records that reference them; the record was not appended.
    #[error("the record references a content chunk that is not stored; write the chunk first")]
    PayloadNotStored,
    /// The attached chunk store failed while the journal flushed or recovered its payloads.
    #[error("payload store: {0}")]
    Payload(ChunkError),
    /// Flushing the attached chunk store failed. The writer refuses records until
    /// [`super::Journal::recover`] has read the pending content back and reported any loss.
    #[error("making stored content durable failed; records are refused until recovery")]
    PayloadFlushFailed,
    /// The journal coordinates a chunk store (`journal/PAYLOADS` exists) and was opened without
    /// it, which would make unverified payload references durable.
    #[error("this journal coordinates a chunk store; open it with its chunk store")]
    PayloadsRequired,
    /// A record breaks a kernel convention (for example `chunk.lost` naming its chunk in
    /// `payload_ref`); it was not appended.
    #[error("record refused: {0}")]
    InvalidRecord(&'static str),
}

impl JournalError {
    /// The registered error code for this failure.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InstanceLocked => codes::JOURNAL_INSTANCE_LOCKED,
            Self::DiskFull => codes::JOURNAL_DISK_FULL,
            Self::Stopped => codes::JOURNAL_FSYNC_FAILED,
            Self::Corrupt(_) | Self::ChainBroken { .. } => codes::JOURNAL_CHAIN_BROKEN,
            Self::ReaderTooOld { .. } => codes::JOURNAL_READER_TOO_OLD,
            Self::Write(_)
            | Self::Storage(_)
            | Self::LineTooLarge
            | Self::Platform(_)
            | Self::Encoding(_)
            | Self::InvalidRecord(_) => codes::JOURNAL_WRITE_FAILED,
            Self::PayloadNotStored => codes::JOURNAL_PAYLOAD_NOT_STORED,
            Self::Payload(e) => e.code(),
            Self::PayloadFlushFailed => codes::STORE_PAYLOAD_FLUSH_FAILED,
            Self::PayloadsRequired => codes::CONFIG_INVALID,
        }
    }
}
