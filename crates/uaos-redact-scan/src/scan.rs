// SPDX-License-Identifier: Apache-2.0

//! The final scan: the last check on the exact bytes about to leave the machine.
//!
//! It runs every detector over every decoded JSON string (so an escaped secret cannot slip through)
//! and over the raw bytes between strings, and looks for the exact bytes of every known vault
//! secret in both. Each of these is checked in the same four views redaction scans: as it is, with
//! JSON and percent escapes decoded once and twice, and with form encoding decoded. Any hit, and
//! any scanner failure, blocks: there is no "send anyway".

use std::collections::BTreeSet;
use std::fmt;

use aho_corasick::AhoCorasick;
use uaos_contracts::error::{ErrorCode, codes};

use crate::RedactError;
use crate::class::DataClass;
use crate::detect::{DetectorSet, DetectorVersion};
use crate::json::{decode, decode_form, decode_nested, strings};

/// Known secrets shorter than this are refused: scanning for them would block ordinary text.
pub const MIN_KNOWN_SECRET_LEN: usize = 8;

/// Why outbound content was blocked. Carries classes only, never content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Blocked {
    /// Detector classes found.
    pub classes: BTreeSet<DataClass>,
    /// Whether a known vault secret was found.
    pub known_secret: bool,
    /// Whether the content could not be scanned completely.
    pub scanner_failure: bool,
}

impl Blocked {
    /// Registered error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        if self.scanner_failure {
            codes::REDACT_DETECTOR_FAILURE
        } else {
            codes::REDACT_BLOCKED
        }
    }

    fn is_empty(&self) -> bool {
        self.classes.is_empty() && !self.known_secret && !self.scanner_failure
    }
}

impl fmt::Display for Blocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("outbound content blocked:")?;
        for class in &self.classes {
            write!(f, " {class}")?;
        }
        if self.known_secret {
            f.write_str(" known_vault_secret")?;
        }
        if self.scanner_failure {
            f.write_str(" scanner_failure")?;
        }
        Ok(())
    }
}

impl std::error::Error for Blocked {}

/// Scans outbound bytes; built once per configuration (detector version, vault contents).
///
/// `Debug` shows the detector version and how many known secrets are loaded, nothing else: the
/// automaton over known secrets encodes their bytes, and a derived `Debug` would print it.
pub struct FinalScanner {
    detectors: DetectorSet,
    known: Option<AhoCorasick>,
    known_count: usize,
}

impl fmt::Debug for FinalScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalScanner")
            .field("version", &self.detectors.version())
            .field("known_secrets", &self.known_count)
            .finish_non_exhaustive()
    }
}

impl FinalScanner {
    /// A scanner for detector set `version` and the exact bytes of every known secret (the
    /// provider keys in the vault).
    ///
    /// # Errors
    /// An unknown version, a known secret shorter than [`MIN_KNOWN_SECRET_LEN`], or a build
    /// failure.
    pub fn new<'s>(
        version: DetectorVersion,
        known_secrets: impl IntoIterator<Item = &'s [u8]>,
    ) -> Result<Self, RedactError> {
        let known: Vec<&[u8]> = known_secrets.into_iter().collect();
        if known.iter().any(|s| s.len() < MIN_KNOWN_SECRET_LEN) {
            return Err(RedactError::KnownSecretTooShort);
        }
        let known_count = known.len();
        let known = if known.is_empty() {
            None
        } else {
            // The error is deliberately dropped: build errors must not echo pattern material.
            Some(
                AhoCorasick::new(&known)
                    .map_err(|_| RedactError::DetectorFailure("known-secret automaton could not be built"))?,
            )
        };
        Ok(Self {
            detectors: DetectorSet::new(version)?,
            known,
            known_count,
        })
    }

    /// Checks non-JSON bytes (headers, form bodies, JSON Lines, text), including JSON and percent
    /// escapes nested in them: a form-encoded DSN or a `\u`-escaped key in a JSON line is found.
    ///
    /// # Errors
    /// [`Blocked`] on any finding or scanner failure.
    pub fn check_bytes(&self, body: &[u8]) -> Result<(), Blocked> {
        let mut blocked = Blocked::default();
        self.check_views(body, &mut blocked);
        if blocked.is_empty() { Ok(()) } else { Err(blocked) }
    }

    /// Checks a JSON body: every string decoded, and the raw bytes between strings (structure,
    /// numbers, and anything a malformed body has outside quotes). Every byte is covered once.
    ///
    /// # Errors
    /// [`Blocked`] on any finding, on malformed JSON strings or invalid UTF-8, or on scanner
    /// failure.
    pub fn check_json(&self, body: &[u8]) -> Result<(), Blocked> {
        let mut blocked = Blocked::default();
        if std::str::from_utf8(body).is_err() {
            // Report what is visible, but such a body can never be cleared.
            self.check_views(body, &mut blocked);
            blocked.scanner_failure = true;
            return Err(blocked);
        }
        let mut raw_from = 0;
        for range in strings(body) {
            let Ok(range) = range else {
                blocked.scanner_failure = true;
                break;
            };
            let open = range.start.saturating_sub(1);
            self.check_views(body.get(raw_from..open).unwrap_or_default(), &mut blocked);
            let decoded = body
                .get(range.clone())
                .ok_or(RedactError::DetectorFailure("string outside the body"))
                .and_then(decode);
            let Ok(d) = decoded else {
                // From the undecodable string on, the bytes are checked raw.
                blocked.scanner_failure = true;
                raw_from = open;
                break;
            };
            self.check_views(d.text.as_bytes(), &mut blocked);
            raw_from = range.end + 1;
        }
        self.check_views(body.get(raw_from.min(body.len())..).unwrap_or_default(), &mut blocked);
        if blocked.is_empty() { Ok(()) } else { Err(blocked) }
    }

    /// Checks `text` in each of its four views, the same views redaction scans.
    fn check_views(&self, text: &[u8], blocked: &mut Blocked) {
        self.check(text, blocked);
        let nested = decode_nested(text, false);
        if let Some(n) = &nested {
            self.check(&n.bytes, blocked);
        }
        if let Some(f) = decode_form(text, false) {
            self.check(&f.bytes, blocked);
        }
        if let Some(n2) = nested.as_ref().and_then(|n| decode_nested(&n.bytes, false)) {
            self.check(&n2.bytes, blocked);
        }
    }

    fn check(&self, text: &[u8], blocked: &mut Blocked) {
        match self.detectors.scan(text) {
            Ok(findings) => blocked.classes.extend(findings.iter().map(|f| f.class)),
            Err(_) => blocked.scanner_failure = true,
        }
        if self.known.as_ref().is_some_and(|k| k.is_match(text)) {
            blocked.known_secret = true;
        }
    }
}
