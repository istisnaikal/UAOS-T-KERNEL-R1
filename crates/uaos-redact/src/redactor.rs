// SPDX-License-Identifier: Apache-2.0

//! Redaction: every detected secret is replaced by a placeholder keyed to the pocket.
//!
//! A placeholder is `[REDACTED:<class>:<tag>]`, where `tag` is the first 64 bits of
//! HMAC-SHA-256 under the pocket's placeholder key over the class and the secret. It is therefore
//! the same on every turn and after every restart (prefix stability), differs between pockets,
//! and reveals nothing about the secret without the key.
//!
//! Each JSON string (and each text) is scanned in up to four views: as it is, with JSON and percent
//! escapes decoded once and twice, and with form encoding decoded, so a secret nested in a tool
//! call's arguments or in a form body is found. A finding in a nested view is mapped back through
//! every view and replaced in the original bytes.
//!
//! Redaction runs to a fixpoint: after the replacements the content is scanned again, so the
//! output contains no detection in any view and `redact(redact(x)) == redact(x)`. Content
//! without a detection is returned borrowed, byte for byte.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Range;

use uaos_json::{ErrorKind, JsonError, Limits, NodeId, Tape};
use uaos_platform::crypto::{SecretKey, hmac_sha256};
use zeroize::{Zeroize, Zeroizing};

use uaos_redact_scan::RedactError;
use uaos_redact_scan::class::DataClass;
use uaos_redact_scan::detect::{DetectorSet, DetectorVersion, Finding, PLACEHOLDER_PREFIX};
use uaos_redact_scan::json::{Decoded, Nested, decode_form, decode_nested, decode_with};

/// Rounds after which redaction that still finds something gives up (and blocks). A round
/// handles one view, so this leaves room for every view plus re-scans.
const MAX_ROUNDS: usize = 8;
/// Domain separation for placeholder tags.
const PLACEHOLDER_DOMAIN: &[u8] = b"uaos.redact.placeholder/1\0";

/// One secret that was replaced. The secret is wiped from memory when this is dropped and never
/// appears in `Debug` output.
pub struct Replacement {
    class: DataClass,
    placeholder: String,
    secret: Zeroizing<String>,
}

impl Replacement {
    /// The class.
    #[must_use]
    pub fn class(&self) -> DataClass {
        self.class
    }

    /// The placeholder that replaced the secret.
    #[must_use]
    pub fn placeholder(&self) -> &str {
        &self.placeholder
    }

    /// The secret, for rehydration toward the client that supplied it. Never log or persist it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.secret
    }
}

impl fmt::Debug for Replacement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Replacement")
            .field("class", &self.class)
            .field("placeholder", &self.placeholder)
            .finish_non_exhaustive()
    }
}

/// The result of redacting text (`T = str`) or a JSON body (`T = [u8]`).
pub struct Redaction<'a, T: ?Sized + ToOwned> {
    output: Cow<'a, T>,
    replacements: Vec<Replacement>,
    edited: Vec<Edited>,
}

/// A node of the tape whose key or string redaction changed: what a module's view masks. Redaction
/// changes the content of strings only, so the id names the same node in the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Edited {
    node: NodeId,
    key: bool,
}

impl Edited {
    /// The node: for a key, the object member whose key it is.
    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }

    /// Whether the member's key changed, rather than the string value at the node.
    #[must_use]
    pub const fn is_key(self) -> bool {
        self.key
    }
}

impl<'a, T: ?Sized + ToOwned> Redaction<'a, T> {
    /// The redacted content.
    #[must_use]
    pub fn output(&self) -> &T {
        &self.output
    }

    /// The redacted content, borrowed from the input when nothing was replaced.
    #[must_use]
    pub fn into_output(self) -> Cow<'a, T> {
        self.output
    }

    /// The distinct secrets replaced, by placeholder.
    #[must_use]
    pub fn replacements(&self) -> &[Replacement] {
        &self.replacements
    }

    /// The classes found (the policy context's `data_classes`).
    #[must_use]
    pub fn classes(&self) -> BTreeSet<DataClass> {
        self.replacements.iter().map(|r| r.class).collect()
    }

    /// Whether nothing was replaced (the output is the input, byte for byte).
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.replacements.is_empty()
    }

    /// The tape's nodes whose key or string changed, in document order, keys before their
    /// values. Empty for text, which has no tape.
    #[must_use]
    pub fn edited(&self) -> &[Edited] {
        &self.edited
    }
}

impl<T: ?Sized + ToOwned> fmt::Debug for Redaction<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Content never appears in Debug output, redacted or not.
        f.debug_struct("Redaction")
            .field("replacements", &self.replacements)
            .finish_non_exhaustive()
    }
}

/// Distinct replacements keyed by placeholder.
#[derive(Default)]
struct Replacements(BTreeMap<String, Replacement>);

impl Replacements {
    fn record(&mut self, class: DataClass, placeholder: &str, secret: &str) -> Result<(), RedactError> {
        match self.0.get(placeholder) {
            Some(existing) if existing.expose_secret() != secret => Err(RedactError::PlaceholderCollision),
            Some(_) => Ok(()),
            None => {
                self.0.insert(
                    placeholder.to_owned(),
                    Replacement {
                        class,
                        placeholder: placeholder.to_owned(),
                        secret: Zeroizing::new(secret.to_owned()),
                    },
                );
                Ok(())
            }
        }
    }

    fn into_vec(self) -> Vec<Replacement> {
        self.0.into_values().collect()
    }
}

/// Redacts content for one pocket under one pinned detector set.
pub struct Redactor {
    detectors: DetectorSet,
    key: SecretKey,
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor")
            .field("version", &self.detectors.version())
            .finish_non_exhaustive()
    }
}

impl Redactor {
    /// A redactor using detector set `version` (pinned by the session) and the pocket's
    /// placeholder key.
    ///
    /// # Errors
    /// [`RedactError::UnknownDetectorVersion`] or a detector compilation failure.
    pub fn new(version: DetectorVersion, placeholder_key: SecretKey) -> Result<Self, RedactError> {
        Ok(Self {
            detectors: DetectorSet::new(version)?,
            key: placeholder_key,
        })
    }

    /// The pinned detector set version.
    #[must_use]
    pub fn version(&self) -> DetectorVersion {
        self.detectors.version()
    }

    /// Secrets in `text`, without redacting.
    ///
    /// # Errors
    /// A detector failure.
    pub fn detect(&self, text: &str) -> Result<Vec<Finding>, RedactError> {
        self.detectors.scan(text.as_bytes())
    }

    /// The placeholder for `secret` of `class` in this pocket.
    #[must_use]
    pub fn placeholder(&self, class: DataClass, secret: &str) -> String {
        let mut message = Vec::with_capacity(PLACEHOLDER_DOMAIN.len() + 32 + secret.len());
        message.extend_from_slice(PLACEHOLDER_DOMAIN);
        message.extend_from_slice(class.as_str().as_bytes());
        message.push(0);
        message.extend_from_slice(secret.as_bytes());
        let tag = hmac_sha256(&self.key, &message);
        message.zeroize();
        let mut out = String::with_capacity(PLACEHOLDER_PREFIX.len() + class.as_str().len() + 18);
        out.push_str("[REDACTED:");
        out.push_str(class.as_str());
        out.push(':');
        for byte in tag.iter().take(8) {
            out.extend(char::from_digit(u32::from(byte >> 4), 16));
            out.extend(char::from_digit(u32::from(byte & 0x0F), 16));
        }
        out.push(']');
        out
    }

    /// Redacts plain text, including secrets inside nested encodings of it (JSON escapes,
    /// percent escapes, form encoding; four views).
    ///
    /// # Errors
    /// Any detector failure: the caller must block the content.
    pub fn redact_text<'a>(&self, text: &'a str) -> Result<Redaction<'a, str>, RedactError> {
        let mut replacements = Replacements::default();
        let output = match self.fixpoint(text.as_bytes(), plain_view, &mut replacements, MAX_ROUNDS)? {
            None => Cow::Borrowed(text),
            Some(bytes) => Cow::Owned(String::from_utf8(bytes).map_err(|_| RedactError::InvalidUtf8)?),
        };
        Ok(Redaction {
            output,
            replacements: replacements.into_vec(),
            edited: Vec::new(),
        })
    }

    /// Redacts every string of a JSON body (keys and values, at any depth, in any field, and JSON
    /// or percent-encoded text nested inside a string) and splices placeholders into the original
    /// bytes. The body is parsed with the kernel's one structural tokenizer (`uaos-json`), then
    /// redacted by [`Redactor::redact_tape`].
    ///
    /// # Errors
    /// Every error blocks:
    /// - [`RedactError::TooLarge`] past a tokenizer limit, with the tokenizer's label, or with
    ///   `"redaction-output-too-large"` when placeholders make the output too long;
    /// - [`RedactError::Malformed`] for a body the tokenizer refuses, or with
    ///   `"redaction-duplicate-key"` when a redacted key equals another key;
    /// - [`RedactError::InvalidUtf8`] and [`RedactError::MalformedJson`] for faults inside a
    ///   string;
    /// - [`RedactError::DetectorFailure`] for a detector failure, a tokenizer short of memory,
    ///   or `"redaction-output-unparsable"` when redaction wrote a body that does not parse,
    ///   which is the redactor's own fault;
    /// - [`RedactError::PlaceholderCollision`] if two secrets would share a placeholder.
    pub fn redact_json<'a>(&self, json: &'a [u8]) -> Result<Redaction<'a, [u8]>, RedactError> {
        let tape = uaos_json::parse(json, &Limits::DEFAULT).map_err(tape_refusal)?;
        self.redact_tape(&tape)
    }

    /// Redacts the strings of a body the caller already parsed, so the request path parses once.
    /// Every member key and every string value is visited in document order, keys before their
    /// values; each is decoded and redacted to a fixpoint exactly as before the move to the
    /// tape.
    ///
    /// The output must fit the limits the tape was parsed under ([`Tape::limits`]), because the
    /// next reader parses it under the same limits: a placeholder can be longer than the secret
    /// it replaces. Only an output longer than the size limit blocks; the build stops as soon as
    /// what is built so far passes the limit. When a key was edited, the output is parsed again
    /// under those limits: replacing a secret inside a key could make two keys equal, or a key
    /// too long.
    ///
    /// # Errors
    /// As [`Redactor::redact_json`], without the parse.
    pub fn redact_tape<'a>(&self, tape: &Tape<'a>) -> Result<Redaction<'a, [u8]>, RedactError> {
        let limits = tape.limits();
        let max_bytes = to_usize(limits.max_bytes());
        let json = tape.input().as_bytes();
        let mut replacements = Replacements::default();
        let mut out: Option<Vec<u8>> = None;
        let mut copied = 0;
        let mut key_edited = false;
        let mut edited = Vec::new();
        for (range, is_key, node) in string_ranges(tape) {
            let content = json.get(range.clone()).ok_or(OUT_OF_BOUNDS)?;
            if let Some(redacted) = self.fixpoint(content, decode_with, &mut replacements, MAX_ROUNDS)? {
                key_edited |= is_key;
                edited.push(Edited { node, key: is_key });
                let buf = out.get_or_insert_with(|| Vec::with_capacity(json.len()));
                buf.extend_from_slice(json.get(copied..range.start).ok_or(OUT_OF_BOUNDS)?);
                buf.extend_from_slice(&redacted);
                copied = range.end;
                // The output starts with `buf`, so a `buf` past the limit is an output past it.
                // This stops the build early; the exact check follows the loop, because a
                // placeholder can also be shorter than its secret.
                if buf.len() > max_bytes {
                    return Err(RedactError::TooLarge("redaction-output-too-large"));
                }
            }
        }
        let output = match out {
            None => Cow::Borrowed(json),
            Some(mut buf) => {
                buf.extend_from_slice(json.get(copied..).ok_or(OUT_OF_BOUNDS)?);
                if buf.len() > max_bytes {
                    return Err(RedactError::TooLarge("redaction-output-too-large"));
                }
                Cow::Owned(buf)
            }
        };
        if key_edited {
            uaos_json::parse(&output, &limits).map_err(output_refusal)?;
        }
        Ok(Redaction {
            output,
            replacements: replacements.into_vec(),
            edited,
        })
    }

    /// Redacts `content` to a fixpoint within `rounds` rounds: each round replaces the findings
    /// of the outermost view that has any, then scans again. `None` if nothing was found.
    ///
    /// Crafted content can chain replacements past the round budget (each replacement opening a new
    /// window). It is then replaced whole by one placeholder: fail closed, without wedging every
    /// later request that carries it.
    fn fixpoint(
        &self,
        content: &[u8],
        view: View,
        replacements: &mut Replacements,
        rounds: usize,
    ) -> Result<Option<Vec<u8>>, RedactError> {
        let mut current: Option<Vec<u8>> = None;
        let mut last_class = None;
        for _ in 0..rounds {
            let raw = current.as_deref().unwrap_or(content);
            let Some(edits) = self.round(raw, view, replacements)? else {
                return Ok(current);
            };
            last_class = edits.first().map(|e| e.class).or(last_class);
            let mut next = Vec::with_capacity(raw.len());
            let mut last = 0;
            for e in edits {
                next.extend_from_slice(raw.get(last..e.range.start).ok_or(OUT_OF_BOUNDS)?);
                next.extend_from_slice(e.placeholder.as_bytes());
                last = e.range.end;
            }
            next.extend_from_slice(raw.get(last..).ok_or(OUT_OF_BOUNDS)?);
            current = Some(next);
        }
        let class = last_class.ok_or(RedactError::Unconverged)?;
        let whole = view(content, false)?;
        let placeholder = self.placeholder(class, whole.text());
        replacements.record(class, &placeholder, whole.text())?;
        Ok(Some(placeholder.into_bytes()))
    }

    /// Scans the views of `raw` from the outside in (the four views of the `json` module) and returns the edits
    /// for the first view with findings, as raw ranges in order. `None` when every view is
    /// clean.
    fn round(&self, raw: &[u8], view: View, replacements: &mut Replacements) -> Result<Option<Vec<Edit>>, RedactError> {
        // Scanning the outer view needs no offset map; it is built only once something is found.
        let outer = view(raw, false)?;
        let found = self.detectors.scan(outer.text().as_bytes())?;
        if !found.is_empty() {
            let outer = view(raw, true)?;
            return self.edits(&found, &[&outer], replacements).map(Some);
        }
        let base = outer.text().as_bytes();
        let nested = decode_nested(base, true).map(Nested::into_decoded).transpose()?;
        if let Some(n) = &nested {
            let found = self.detectors.scan(n.text().as_bytes())?;
            if !found.is_empty() {
                let outer = view(raw, true)?;
                return self.edits(&found, &[&outer, n], replacements).map(Some);
            }
        }
        if let Some(f) = decode_form(base, true).map(Nested::into_decoded).transpose()? {
            let found = self.detectors.scan(f.text().as_bytes())?;
            if !found.is_empty() {
                let outer = view(raw, true)?;
                return self.edits(&found, &[&outer, &f], replacements).map(Some);
            }
        }
        if let Some(n) = &nested
            && let Some(n2) = decode_nested(n.text().as_bytes(), true)
                .map(Nested::into_decoded)
                .transpose()?
        {
            let found = self.detectors.scan(n2.text().as_bytes())?;
            if !found.is_empty() {
                let outer = view(raw, true)?;
                return self.edits(&found, &[&outer, n, &n2], replacements).map(Some);
            }
        }
        Ok(None)
    }

    /// Placeholders for `findings` in the innermost view of `chain` (outermost first), mapped
    /// back to raw ranges. Every map points at the start of the character or escape that
    /// produced a byte, so a range covers whole escapes.
    fn edits(
        &self,
        findings: &[Finding],
        chain: &[&Decoded<'_>],
        replacements: &mut Replacements,
    ) -> Result<Vec<Edit>, RedactError> {
        let text = chain.last().map(|d| d.text()).ok_or(OUT_OF_BOUNDS)?;
        let mut edits = Vec::with_capacity(findings.len());
        for f in findings {
            let secret = slice(text, f.range.clone())?;
            let placeholder = self.placeholder(f.class, secret);
            replacements.record(f.class, &placeholder, secret)?;
            let (mut start, mut end) = (f.range.start, f.range.end);
            for level in chain.iter().rev() {
                start = level.raw(start)?;
                end = level.raw(end)?;
            }
            edits.push(Edit {
                range: start..end,
                placeholder,
                class: f.class,
            });
        }
        Ok(edits)
    }
}

/// A raw range, the placeholder that replaces it, and the class found.
struct Edit {
    range: Range<usize>,
    placeholder: String,
    class: DataClass,
}

/// How the outermost view of some content is decoded: plain text, or a JSON string's contents.
/// The flag asks for an offset map.
type View = fn(&[u8], bool) -> Result<Decoded<'_>, RedactError>;

fn plain_view(raw: &[u8], _mapped: bool) -> Result<Decoded<'_>, RedactError> {
    std::str::from_utf8(raw)
        .map(Decoded::plain)
        .map_err(|_| RedactError::InvalidUtf8)
}

const OUT_OF_BOUNDS: RedactError = RedactError::DetectorFailure("span outside the content");

fn slice(s: &str, range: Range<usize>) -> Result<&str, RedactError> {
    s.get(range)
        .ok_or(RedactError::DetectorFailure("span not on a character boundary"))
}

/// The raw content of every member key and every string value of `tape`, in document order (keys
/// before their values), with whether it is a key and the node it belongs to (for a key, its
/// member). Quotes are excluded. Lazy, so a body of a million values allocates nothing here.
pub(crate) fn string_ranges<'t>(tape: &'t Tape<'_>) -> impl Iterator<Item = (Range<usize>, bool, NodeId)> + 't {
    tape.nodes().flat_map(|node| {
        let id = node.id();
        let key = node.key_span().map(|key| {
            let quoted = key.range();
            (quoted.start.saturating_add(1)..quoted.end.saturating_sub(1), true, id)
        });
        let content = node.content_span().map(|content| (content.range(), false, id));
        key.into_iter().chain(content)
    })
}

/// `u32` to `usize`; every target the kernel supports has a `usize` of at least 32 bits.
fn to_usize(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// Maps a refusal of the shared tokenizer to the error that blocks. Faults inside a string keep the
/// codes they had before the move; limits and structure get deterministic codes; a kind added later
/// falls into `Malformed`, which blocks.
fn tape_refusal(error: JsonError) -> RedactError {
    let label = error.kind().code();
    match error.kind() {
        ErrorKind::TooLarge | ErrorKind::DepthExceeded | ErrorKind::TooManyNodes | ErrorKind::KeyTooLong => {
            RedactError::TooLarge(label)
        }
        ErrorKind::InvalidUtf8 => RedactError::InvalidUtf8,
        ErrorKind::InvalidEscape
        | ErrorKind::InvalidUnicodeEscape
        | ErrorKind::LoneSurrogate
        | ErrorKind::UnterminatedString => RedactError::MalformedJson(label),
        // The tape could not reserve memory for the body. The body may be fine; the host was
        // short, so the request can be retried, and the redactor's own failure code says so.
        ErrorKind::OutOfMemory => RedactError::DetectorFailure(label),
        _ => RedactError::Malformed(label),
    }
}

/// Maps a refusal of redaction's own output, re-parsed after a key edit. Redaction changes only the
/// bytes inside strings, so the structure cannot change: a placeholder can make two keys equal or a
/// key too long, and nothing else. Any other refusal means the redactor wrote a broken body, which
/// is its own fault and not the client's, so it fails with the redactor's code.
fn output_refusal(error: JsonError) -> RedactError {
    match error.kind() {
        ErrorKind::DuplicateKey => RedactError::Malformed("redaction-duplicate-key"),
        ErrorKind::TooLarge | ErrorKind::DepthExceeded | ErrorKind::TooManyNodes | ErrorKind::KeyTooLong => {
            RedactError::TooLarge(error.kind().code())
        }
        ErrorKind::OutOfMemory => RedactError::DetectorFailure(error.kind().code()),
        _ => RedactError::DetectorFailure("redaction-output-unparsable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Content that needs more rounds than the budget is replaced whole instead of failing, so it
    /// cannot wedge every later request.
    #[test]
    fn content_that_does_not_converge_is_replaced_whole() {
        let r = Redactor::new(DetectorVersion::V1, SecretKey::from_bytes([3; 32])).unwrap();
        // The private key first, then the URL password it hid behind a newline.
        let text = concat!(
            "https://u:x-----BEGIN RSA PRIVATE",
            " KEY-----
MIIabc
-----END RSA PRIVATE",
            " KEY-----y@host"
        );
        let mut replacements = Replacements::default();
        let converged = r
            .fixpoint(text.as_bytes(), plain_view, &mut replacements, MAX_ROUNDS)
            .unwrap()
            .unwrap();
        assert!(
            String::from_utf8(converged)
                .unwrap()
                .starts_with("https://u:[REDACTED:url_credentials:")
        );

        let mut replacements = Replacements::default();
        let out = r
            .fixpoint(text.as_bytes(), plain_view, &mut replacements, 1)
            .unwrap()
            .unwrap();
        assert_eq!(out, r.placeholder(DataClass::PrivateKey, text).into_bytes());
        assert!(replacements.into_vec().iter().any(|x| x.expose_secret() == text));
    }
}
