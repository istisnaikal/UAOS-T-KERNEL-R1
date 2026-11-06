// SPDX-License-Identifier: Apache-2.0

//! The one structural JSON tokenizer of the kernel.
//!
//! [`parse`] makes one forward pass over a complete, already-buffered body and records every
//! value as a node of a flat, pre-order [`Tape`]: its kind, its raw byte span, its parent, its
//! key inside an object and the end of its subtree. Nothing is copied or decoded unless a
//! reader asks; strings decode lazily and borrow when they hold no escape.
//!
//! The grammar is RFC 8259, fail-closed: invalid UTF-8, a byte-order mark, a lone surrogate, a
//! duplicate key (compared after decoding), anything after the root value or any broken limit
//! rejects the whole document. Numbers are grammar only: never converted, never re-serialized
//! ([`parse_u64`] and [`parse_i64`] read the few integers the kernel needs, with explicit range
//! checks).
//!
//! With its limits, layout, memory bounds and proof obligations. The crate has no workspace
//! dependency, no I/O and no clock; it reports through return values ([`TapeStats`],
//! [`ErrorKind::code`]), never by logging. No error and no `Debug` output carries input bytes.

#![forbid(unsafe_code)]
#![deny(missing_docs, clippy::indexing_slicing, clippy::float_arithmetic)]

mod decode;
mod encode;
mod error;
mod node;
mod number;
mod tape;

/// The bench's copy of the fingerprint (`benches/tape.rs` includes this file), compiled into the
/// unit tests so they can hold it to the real one.
#[cfg(test)]
mod fingerprint_copy;

pub use decode::{Decoded, decode, decode_mapped};
pub use encode::encode_str;
pub use error::{ErrorKind, JsonError, LimitsError, Violation};
pub use node::{Ancestors, Children, Descendants, Kind, Node, NodeId, Span};
pub use number::{parse_i64, parse_u64};
pub use tape::{Tape, TapeStats, parse};

/// The longest raw key, in bytes between its quotes, that the tape records (the layout keeps it
/// in 16 bits). A longer key is refused with [`ErrorKind::KeyTooLong`].
pub const MAX_KEY_LEN: usize = 65_535;

/// The bounds one [`parse`] works within. Every limit is at least 1 and at most its ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    bytes: u32,
    depth: u16,
    nodes: u32,
}

impl Limits {
    /// 32 MiB (the egress door's request limit), 128 levels and 2^20 nodes.
    pub const DEFAULT: Self = Self {
        bytes: 32 * 1024 * 1024,
        depth: 128,
        nodes: 1 << 20,
    };
    /// The largest input any limit allows: offsets stay far from the 32-bit edge.
    pub const MAX_BYTES_CEILING: u32 = 1 << 30;
    /// The deepest nesting any limit allows.
    pub const MAX_DEPTH_CEILING: u16 = 1024;
    /// The most nodes any limit allows (384 MiB of tape).
    pub const MAX_NODES_CEILING: u32 = 1 << 24;

    /// Limits of your own.
    ///
    /// # Errors
    ///
    /// A limit that is zero or above its ceiling.
    pub const fn new(max_bytes: u32, max_depth: u16, max_nodes: u32) -> Result<Self, LimitsError> {
        if max_bytes == 0 || max_bytes > Self::MAX_BYTES_CEILING {
            return Err(LimitsError::MaxBytes);
        }
        if max_depth == 0 || max_depth > Self::MAX_DEPTH_CEILING {
            return Err(LimitsError::MaxDepth);
        }
        if max_nodes == 0 || max_nodes > Self::MAX_NODES_CEILING {
            return Err(LimitsError::MaxNodes);
        }
        Ok(Self {
            bytes: max_bytes,
            depth: max_depth,
            nodes: max_nodes,
        })
    }

    /// The largest input accepted, in bytes.
    #[must_use]
    pub const fn max_bytes(&self) -> u32 {
        self.bytes
    }

    /// The most containers open at once.
    #[must_use]
    pub const fn max_depth(&self) -> u16 {
        self.depth
    }

    /// The most values on one tape.
    #[must_use]
    pub const fn max_nodes(&self) -> u32 {
        self.nodes
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// Every offset is a u32 and every index a usize: `usize` holds every `u32` on the platforms UAOS
// builds for, and inputs are capped at `MAX_BYTES_CEILING`, so neither conversion below can lose
// a value. `as` casts are denied workspace-wide, hence the helpers.
const _: () = assert!(usize::BITS >= 32);

/// A u32 offset or index as a usize (lossless, see above).
pub(crate) fn to_usize(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// A usize offset as a u32. Only called on offsets within an input that passed the size check,
/// which keeps them under 2^30; anything larger saturates rather than wraps.
pub(crate) fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
