// SPDX-License-Identifier: Apache-2.0

//! The journal: append-only, hash-chained, crash-recovering.
//!
//! Layout inside the data directory:
//!
//! ```text
//! uaos.lock                       exclusive lock: one daemon per data directory
//! journal/MANIFEST                segment list (replaced atomically on rotation)
//! journal/seg-<first seq>-<gen>.jsonl   one uaos.event/1 record per line
//! journal/FLUSHED                 durable point: the last flushed record (every journal)
//! journal/PAYLOADS                the journal coordinates a chunk store; open it with one
//! ```

mod error;
pub mod manifest;
mod scan;
mod writer;

pub use error::JournalError;
pub use scan::{VerifiedRecord, VerifyReport, genesis_hash, read_verified, verify};
pub use writer::{
    Appended, CAUSE_METADATA_KEY, CHUNK_METADATA_KEY, EventDraft, FLUSH_MARKER, FlushPolicy, JOURNAL_DIR, Journal,
    JournalHealth, LOCK_FILE, LostPayload, MAX_LOST_LISTED, OpenEvidence, Opened, PAYLOADS_FLAG,
    RECORD_SEQ_METADATA_KEY, SEAL_FILE,
};
