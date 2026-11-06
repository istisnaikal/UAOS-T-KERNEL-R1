// SPDX-License-Identifier: Apache-2.0

//! # UAOS final scan
//!
//! The last check before content leaves the machine (red line 2), and the detection primitives it
//! shares with redaction (`uaos-redact`):
//!
//! * [`FinalScanner`] blocks on any detection, or on the exact bytes of any known vault secret,
//!   in the exact outbound body, in each of the four views redaction scans;
//! * `detect` holds the pinned detector sets and the placeholder grammar;
//! * `json` holds the scan's own JSON string tokenizer and decoders;
//! * [`class`] names the classes of secret.
//!
//! **Why a crate of its own**. Redaction finds its strings on the kernel's shared structural
//! tokenizer (`uaos-json`). The final scan must not, so that a fault in that tokenizer cannot hide
//! a secret from both. `cargo xtask arch-check` gives this crate no edge to `uaos-json` and refuses
//! a crate of that name in the crate's closure and in its dev-dependencies', and pins its direct
//! dependencies and those of the workspace crate it reaches, with no build script and no features
//! in either. The clippy and `sources` gates check, from rustc's own dep-info, that each file rustc
//! read for it in the builds the gates check lies in this crate, apart from clippy's own
//! configuration. Other builds, files read at run time, a public surface that takes the outbound
//! bytes and nothing that finds strings for it (no callbacks, trait objects or global state), and a
//! caller that passes the exact outbound body.
//!
//! `detect` and `json` are public, and hidden from the docs, so that `uaos-redact` can share them;
//! they are not an interface for anything else and change with redaction. Redaction's decoders are
//! these, so a fault in them is common to both.
//!
//! This crate performs no I/O and never logs, and no type in it shows content or secret-derived
//! structure in `Debug` output.

#![deny(missing_docs)]
#![deny(clippy::indexing_slicing)]

pub mod class;
// Shared with `uaos-redact`'s redaction, which detects and decodes as the scan does; not an API for
// anyone else. The re-exports below are the API.
#[doc(hidden)]
pub mod detect;
#[doc(hidden)]
pub mod json;
mod scan;

pub use class::DataClass;
pub use detect::{DetectorSet, DetectorVersion, Finding};
pub use scan::{Blocked, FinalScanner, MIN_KNOWN_SECRET_LEN};

use uaos_contracts::error::{ErrorCode, codes};

/// Why content could not be redacted. Every variant means: block the content. Messages never
/// contain content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RedactError {
    /// The session pinned a detector set this build does not have.
    #[error("detector set version {0} is not available")]
    UnknownDetectorVersion(u16),
    /// The content is not valid UTF-8.
    #[error("content is not valid UTF-8")]
    InvalidUtf8,
    /// A JSON string could not be decoded.
    #[error("malformed JSON string: {0}")]
    MalformedJson(&'static str),
    /// Redacting kept finding secrets in its own output.
    #[error("redaction did not converge")]
    Unconverged,
    /// Two different secrets produced the same placeholder.
    #[error("two different secrets produced the same placeholder")]
    PlaceholderCollision,
    /// A known secret is too short to scan for.
    #[error("known secrets must be at least {MIN_KNOWN_SECRET_LEN} bytes")]
    KnownSecretTooShort,
    /// The scanner itself failed.
    #[error("detector failure: {0}")]
    DetectorFailure(&'static str),
    /// The JSON body is past one of the tokenizer's limits (size, depth, nodes, key length); the
    /// label is the tokenizer's stable one.
    #[error("JSON body past a limit: {0}")]
    TooLarge(&'static str),
    /// The JSON body is not one the shared tokenizer reads unambiguously (a duplicate key,
    /// trailing data, a byte-order mark, a malformed number...), or redaction's own output would
    /// not be; the label says which.
    #[error("JSON body refused: {0}")]
    Malformed(&'static str),
}

impl RedactError {
    /// Registered error code. A refusal of the request's own bytes is deterministic, so it gets a
    /// code that is not retryable.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::TooLarge(_) => codes::INGRESS_TOO_LARGE,
            Self::Malformed(_) => codes::INGRESS_MALFORMED,
            _ => codes::REDACT_DETECTOR_FAILURE,
        }
    }
}
