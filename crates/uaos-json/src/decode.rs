// SPDX-License-Identifier: Apache-2.0

//! String decoding. One escape core, [`unescape_at`], serves the strict decoder, the decoder with
//! an offset map and the duplicate-key check (its fingerprints and its run scratch), so all of them
//! read an escape the same way. Nothing falls back silently: a malformed escape is an error, never
//! U+FFFD.

use std::borrow::Cow;
use std::fmt;

use crate::error::{ErrorKind, JsonError};
use crate::{to_u32, to_usize};

/// A decoded string, and the way back from decoded offsets to raw ones.
#[derive(Clone, PartialEq, Eq)]
pub struct Decoded<'a> {
    text: Cow<'a, str>,
    /// For each decoded byte, its content offset if it was copied, or its escape's backslash if
    /// an escape produced it; plus one final entry equal to the content length. `None` when
    /// decoded and raw coincide.
    map: Option<Vec<u32>>,
}

impl<'a> Decoded<'a> {
    /// The decoded text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The decoded text, by value.
    #[must_use]
    pub fn into_text(self) -> Cow<'a, str> {
        self.text
    }

    /// Whether the content held no escape, so decoded and raw offsets coincide.
    #[must_use]
    pub const fn is_identity(&self) -> bool {
        self.map.is_none()
    }

    /// The content offset of decoded offset `decoded`, which may equal the decoded length.
    /// `None` beyond that.
    #[must_use]
    pub fn raw_offset(&self, decoded: usize) -> Option<usize> {
        match &self.map {
            None => (decoded <= self.text.len()).then_some(decoded),
            Some(map) => map.get(decoded).copied().map(to_usize),
        }
    }
}

impl fmt::Debug for Decoded<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The text may be a secret: its length only.
        f.debug_struct("Decoded")
            .field("len", &self.text.len())
            .field("mapped", &self.map.is_some())
            .finish_non_exhaustive()
    }
}

/// Decodes the content of one JSON string (the bytes between its quotes) under exactly the
/// tape's string grammar. Borrows when the content holds no escape.
///
/// # Errors
///
/// A raw quote ([`ErrorKind::UnescapedQuote`]), a raw byte below 0x20, an invalid escape or a
/// lone surrogate; the offset is relative to the content.
pub fn decode(content: &str) -> Result<Cow<'_, str>, JsonError> {
    decode_inner(content, false).map(Decoded::into_text)
}

/// [`decode`], plus the map from decoded offsets back to content offsets that a splice needs.
///
/// # Errors
///
/// As [`decode`].
pub fn decode_mapped(content: &str) -> Result<Decoded<'_>, JsonError> {
    decode_inner(content, true)
}

fn decode_inner(content: &str, mapped: bool) -> Result<Decoded<'_>, JsonError> {
    let bytes = content.as_bytes();
    let mut out: Option<Vec<u8>> = None;
    let mut map: Vec<u32> = Vec::new();
    let mut i = 0;
    loop {
        // Jump to the next quote or backslash; prove the run between holds no control byte.
        let rest = bytes.get(i..).unwrap_or_default();
        let next = memchr::memchr2(b'"', b'\\', rest).map_or(bytes.len(), |at| i + at);
        let run = bytes.get(i..next).unwrap_or_default();
        if let Some(at) = run.iter().position(|&b| b < 0x20) {
            return Err(JsonError::new(ErrorKind::ControlCharacter, i + at));
        }
        if let Some(buf) = out.as_mut() {
            buf.extend_from_slice(run);
            if mapped {
                map.extend((i..next).map(to_u32));
            }
        }
        i = next;
        match bytes.get(i) {
            None => break,
            Some(b'"') => return Err(JsonError::new(ErrorKind::UnescapedQuote, i)),
            Some(_) => {}
        }
        // A backslash: from here on the text is owned. What came before it is copied once, into a
        // text and a map sized exactly from the decoded length, or the decode is refused with
        // `OutOfMemory` when that much cannot be had.
        if out.is_none() {
            let decoded = i + decoded_len(bytes, i);
            let oom = || JsonError::new(ErrorKind::OutOfMemory, i);
            let mut buf = Vec::new();
            buf.try_reserve_exact(decoded).map_err(|_| oom())?;
            buf.extend_from_slice(bytes.get(..i).unwrap_or_default());
            if mapped {
                map.try_reserve_exact(decoded + 1).map_err(|_| oom())?;
                map.extend((0..i).map(to_u32));
            }
            out = Some(buf);
        }
        let buf = out.get_or_insert_with(Vec::new);
        let (ch, consumed) = unescape_at(bytes, i)?;
        let mut utf8 = [0_u8; 4];
        let encoded = ch.encode_utf8(&mut utf8).as_bytes();
        buf.extend_from_slice(encoded);
        if mapped {
            map.extend(std::iter::repeat_n(to_u32(i), encoded.len()));
        }
        i += consumed;
    }
    let Some(buf) = out else {
        return Ok(Decoded {
            text: Cow::Borrowed(content),
            map: None,
        });
    };
    if mapped {
        map.push(to_u32(bytes.len()));
    }
    // Plain runs come from a `&str` and every escape decodes to a whole character, so this
    // cannot fail; it is checked rather than assumed.
    let text = String::from_utf8(buf).map_err(|_| JsonError::new(ErrorKind::InvalidUtf8, 0))?;
    Ok(Decoded {
        text: Cow::Owned(text),
        map: mapped.then_some(map),
    })
}

/// The escape starting with the backslash at `at`: the character it stands for and the number
/// of bytes it spans (2, 6 or 12).
pub(crate) fn unescape_at(bytes: &[u8], at: usize) -> Result<(char, usize), JsonError> {
    let Some(&escape) = bytes.get(at + 1) else {
        return Err(JsonError::new(ErrorKind::InvalidEscape, at));
    };
    let ch = match escape {
        b'"' => '"',
        b'\\' => '\\',
        b'/' => '/',
        b'b' => '\u{8}',
        b'f' => '\u{c}',
        b'n' => '\n',
        b'r' => '\r',
        b't' => '\t',
        b'u' => return unicode_escape(bytes, at),
        _ => return Err(JsonError::new(ErrorKind::InvalidEscape, at)),
    };
    Ok((ch, 2))
}

fn unicode_escape(bytes: &[u8], at: usize) -> Result<(char, usize), JsonError> {
    let unit = hex4(bytes, at + 2).ok_or(JsonError::new(ErrorKind::InvalidUnicodeEscape, at))?;
    if is_high_surrogate(unit) {
        let low = low_surrogate_at(bytes, at + 6).ok_or(JsonError::new(ErrorKind::LoneSurrogate, at))?;
        let code = 0x1_0000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
        let ch = char::from_u32(code).ok_or(JsonError::new(ErrorKind::LoneSurrogate, at))?;
        return Ok((ch, 12));
    }
    if is_low_surrogate(unit) {
        return Err(JsonError::new(ErrorKind::LoneSurrogate, at));
    }
    let ch = char::from_u32(u32::from(unit)).ok_or(JsonError::new(ErrorKind::InvalidUnicodeEscape, at))?;
    Ok((ch, 6))
}

/// The four hexadecimal digits at `at`, in either case.
pub(crate) fn hex4(bytes: &[u8], at: usize) -> Option<u16> {
    let digits = bytes.get(at..at + 4)?;
    digits.iter().try_fold(0_u16, |value, &digit| {
        let nibble = match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => return None,
        };
        Some(value * 16 + u16::from(nibble))
    })
}

/// The low surrogate of a `\uXXXX` escape starting at `at`, if one is there.
pub(crate) fn low_surrogate_at(bytes: &[u8], at: usize) -> Option<u16> {
    if bytes.get(at) != Some(&b'\\') || bytes.get(at + 1) != Some(&b'u') {
        return None;
    }
    hex4(bytes, at + 2).filter(|&unit| is_low_surrogate(unit))
}

pub(crate) const fn is_high_surrogate(unit: u16) -> bool {
    matches!(unit, 0xD800..=0xDBFF)
}

pub(crate) const fn is_low_surrogate(unit: u16) -> bool {
    matches!(unit, 0xDC00..=0xDFFF)
}

/// The decoded UTF-8 bytes of string content the tape has already validated, without
/// allocating. Used to compare escaped keys. Should an escape fail all the same, the iterator
/// stops and [`Unescape::broken`] reports it, so the caller fails closed.
pub(crate) struct Unescape<'a> {
    bytes: &'a [u8],
    at: usize,
    pending: [u8; 4],
    pending_len: usize,
    pending_at: usize,
    broken: bool,
}

impl<'a> Unescape<'a> {
    pub(crate) const fn new(content: &'a [u8]) -> Self {
        Self {
            bytes: content,
            at: 0,
            pending: [0; 4],
            pending_len: 0,
            pending_at: 0,
            broken: false,
        }
    }

    /// Whether an escape failed to decode.
    pub(crate) const fn broken(&self) -> bool {
        self.broken
    }
}

#[cfg(test)]
thread_local! {
    /// How many times `Unescape` was asked for a byte on this thread: lets a unit test bound how
    /// much decoding a run of colliding keys costs.
    pub(crate) static UNESCAPED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The decoded length of `bytes[from..]`, up to its first escape that does not decode, which is
/// where decoding stops with an error: plain runs found with `memchr`, each escape counted by its
/// UTF-8 length.
fn decoded_len(bytes: &[u8], from: usize) -> usize {
    let mut len = 0;
    let mut i = from;
    loop {
        let rest = bytes.get(i..).unwrap_or_default();
        let Some(at) = memchr::memchr(b'\\', rest) else {
            return len + rest.len();
        };
        len += at;
        i += at;
        match unescape_at(bytes, i) {
            Ok((ch, consumed)) => {
                len += ch.len_utf8();
                i += consumed;
            }
            Err(_) => return len,
        }
    }
}

impl Iterator for Unescape<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        #[cfg(test)]
        UNESCAPED.with(|n| n.set(n.get() + 1));
        if self.pending_at < self.pending_len {
            let byte = self.pending.get(self.pending_at).copied();
            self.pending_at += 1;
            return byte;
        }
        let &byte = self.bytes.get(self.at)?;
        if byte != b'\\' {
            self.at += 1;
            return Some(byte);
        }
        let Ok((ch, consumed)) = unescape_at(self.bytes, self.at) else {
            self.broken = true;
            self.at = self.bytes.len();
            return None;
        };
        self.at += consumed;
        self.pending_len = ch.encode_utf8(&mut self.pending).len();
        self.pending_at = 1;
        self.pending.first().copied()
    }
}
