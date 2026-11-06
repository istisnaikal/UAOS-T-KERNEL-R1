// SPDX-License-Identifier: Apache-2.0

//! # UAOS redaction
//!
//! Detection and redaction of high-risk secrets before content leaves the machine (DETECT,
//! TRANSFORM and FINAL; red line 2):
//!
//! * **schema-agnostic**: every JSON string is scanned (keys and values, at any depth, known
//!   and unknown fields), after decoding escapes, so `\u`-escaped secrets are found;
//! * **nested**: each string and text is scanned in four views (as decoded, two further levels
//!   of JSON and percent escapes, and form encoding), so a secret in a tool call's JSON
//!   arguments, a double-escaped `partial_json` or a form body is found;
//! * **boundaries fail closed**: a key glued to separators, or longer than its format, is still
//!   covered whole;
//! * **byte-preserving**: placeholders are spliced into the original bytes; content without a
//!   detection is returned borrowed, byte for byte;
//! * **stable placeholders**: `[REDACTED:<class>:<tag>]`, where the tag is HMAC-SHA-256 under the
//!   pocket's placeholder key. The same secret gets the same placeholder on every turn and after
//!   every restart, a different one in another pocket, and nothing about the secret is revealed;
//! * **idempotent**: output is redacted to a fixpoint, so `redact(redact(x)) == redact(x)`;
//! * **pinned**: a detector set is versioned as a whole and a session keeps its version;
//! * **fail closed**: every error (malformed input, scanner failure, no convergence) is an error
//!   the caller must turn into a block, and [`FinalScanner`] blocks on any detection or known
//!   vault secret in the exact outbound bytes.
//!
//! The final scan ([`FinalScanner`]), the detectors and the classes live in `uaos-redact-scan`, a
//! crate with no dependency path to the shared tokenizer among the packages
//! `cargo xtask arch-check` sees (what it checks and what stays review is); they are re-exported
//! here.
//!
//! This crate performs no I/O and never logs, and no type in it shows content or secret-derived
//! structure in `Debug` output. Scanning is linear in the input (a test bounds the work on
//! adversarial inputs). Recall is bound to the formats detector set v1 claims, measured on
//! synthetic corpus v2 (lists the classes, metrics and limits). Not detected: free-form passwords
//! outside URL userinfo, AWS secret access keys (only key ids), and encodings beyond the four
//! views. Content that would need more than 8 redaction rounds is replaced whole.

#![deny(missing_docs)]
#![deny(clippy::indexing_slicing)]

#[cfg(test)]
mod differential;
mod redactor;

pub use redactor::{Edited, Redaction, Redactor, Replacement};
// The final scan and the detection it shares with redaction live in `uaos-redact-scan`, which has
// no dependency path to the shared tokenizer. They are re-exported, so callers see one API.
pub use uaos_redact_scan::{
    Blocked, DataClass, DetectorSet, DetectorVersion, FinalScanner, Finding, MIN_KNOWN_SECRET_LEN, RedactError,
};

// The final scan callers reach through this crate is the scan crate's own type, not a wrapper of
// the same name, which could find strings with the shared tokenizer before it scans. The pins name
// the crate from the root and this crate's items by `crate::`, so a module named like the scan
// crate stands in for neither. arch-check refuses the other ways it knows to give that name to
// another crate: a dependency under another name, a library named other than after its package, and
// an `extern crate` at a root; and it requires an unconditional edge to the scan crate, so rustc
// refuses a macro-expanded `extern crate`. They hold in each build that compiles the library, among
// them the dev and release builds the gates check, with default and with every feature.
const _: fn(::uaos_redact_scan::FinalScanner) -> crate::FinalScanner = |scanner| scanner;
const _: fn(::uaos_redact_scan::Blocked) -> crate::Blocked = |blocked| blocked;
const _: fn(::uaos_redact_scan::DetectorSet) -> crate::DetectorSet = |detectors| detectors;
