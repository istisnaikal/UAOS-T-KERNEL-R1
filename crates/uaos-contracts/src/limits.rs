// SPDX-License-Identifier: Apache-2.0

//! Named, unit-typed limits. No magic numbers elsewhere in the kernel: a bound that matters
//! is declared here with its unit and the reason it has this value.

/// A size in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes(pub u64);

impl Bytes {
    /// Returns `true` if `len` bytes fit within this limit.
    #[must_use]
    pub fn admits(self, len: usize) -> bool {
        u64::try_from(len).is_ok_and(|len| len <= self.0)
    }
}

/// Maximum serialized size of an event's inline payload.
///
/// Inline payloads carry metadata only (IDs, amounts, reason codes); content always goes to
/// encrypted chunks. 1 KiB is large enough for any metadata record and small enough that a
/// journal line stays cheap to hash and scan.
pub const MAX_INLINE_PAYLOAD: Bytes = Bytes(1024);

/// Maximum number of entries in an event's `metadata` map. Bounded so that hostile or buggy
/// producers cannot grow journal lines without limit.
pub const MAX_METADATA_ENTRIES: usize = 16;

/// Maximum length of a metadata key.
pub const MAX_METADATA_KEY: Bytes = Bytes(64);

/// Maximum length of a metadata value. Values are short labels, never content.
pub const MAX_METADATA_VALUE: Bytes = Bytes(256);

/// Maximum length of a namespaced event type such as `op.reserved_intent`.
pub const MAX_EVENT_TYPE: Bytes = Bytes(64);

/// Maximum length of a module name.
pub const MAX_MODULE_NAME: Bytes = Bytes(64);

/// Maximum length of an idempotency key supplied by a client or module.
pub const MAX_IDEMPOTENCY_KEY: Bytes = Bytes(128);

/// Maximum length of a reason code such as `hard_cap_reached`.
pub const MAX_REASON_CODE: Bytes = Bytes(64);

/// A duration in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Millis(pub u64);

impl Millis {
    /// The duration in nanoseconds, saturating.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0.saturating_mul(1_000_000)
    }
}

/// Maximum size of one journal line. Envelopes carry metadata only (inline payload ≤ 1 KiB,
/// metadata ≤ 16 × 320 B), so a real record is a few KiB at most; 16 KiB leaves headroom while
/// bounding the memory a reader needs per line.
pub const MAX_JOURNAL_LINE: Bytes = Bytes(16 * 1024);

/// Target size at which the journal rotates to a new segment. 64 MiB keeps a segment quick to
/// verify and cheap to archive, and keeps the number of files small for long-lived journals.
pub const JOURNAL_SEGMENT_TARGET: Bytes = Bytes(64 * 1024 * 1024);

/// Default power-loss window W of balanced durability: acknowledged records reach stable storage
/// within this time. Spike H1 measured group-fsync p99.9 at 5.9 ms on an entry-level `NVMe` drive,
/// so 50 ms is reachable with wide margin while batching flushes.
pub const DEFAULT_FLUSH_WINDOW: Millis = Millis(50);

/// Maximum size of one content chunk. Chunks are individual messages or tool payloads; 16 MiB
/// admits any realistic single message while bounding the memory one read can demand. Larger
/// content is split by the caller.
pub const MAX_CHUNK: Bytes = Bytes(16 * 1024 * 1024);

/// Maximum number of members in one dimension of a credential scope. Scopes are coarse upper
/// bounds; fine-grained rules belong in Cedar policy. The bound also keeps a credential record
/// inside [`MAX_INLINE_PAYLOAD`].
pub const MAX_SCOPE_ITEMS: usize = 8;

/// Maximum number of credentials in one chain, the master included: master, sub and two levels of
/// children. Verification walks the chain on every request, so the bound caps its cost.
pub const MAX_CREDENTIAL_DEPTH: usize = 4;

/// Maximum length of a credential label, an action name or a resource pattern value.
pub const MAX_CREDENTIAL_TOKEN: Bytes = Bytes(64);

/// Maximum length of a credential label, in characters.
pub const MAX_LABEL_CHARS: usize = 64;

/// Maximum number of live (unrevoked) credentials per installation. Bounds the identity tables a
/// verification consults; revoked entries are removed by journal compaction.
pub const MAX_LIVE_CREDENTIALS: usize = 4096;

/// Maximum number of live credentials issued directly by one credential.
pub const MAX_LIVE_CHILDREN: usize = 256;
