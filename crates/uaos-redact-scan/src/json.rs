// SPDX-License-Identifier: Apache-2.0

//! Schema-agnostic JSON access: every string token (keys and values, known and unknown fields)
//! is found in the raw bytes and decoded, with a map from decoded offsets back to raw offsets so
//! edits are spliced into the original bytes and everything else stays byte-identical.
//!
//! This is not a validating parser; the dialect codec validates structure. It is strict where
//! scanning depends on it: an unterminated string, a malformed escape or a lone surrogate is an
//! error, and every error blocks the content (fail closed).
//!
//! A decoded string can itself carry encoded text: JSON inside a tool call's `arguments`, a
//! double-escaped `partial_json`, a percent-encoded DSN, a form body. Both redaction and the final
//! scan therefore look at the same four **views** of every string, outermost first:
//! 1. the string itself;
//! 2. its JSON and percent escapes decoded ([`decode_nested`]);
//! 3. its form encoding decoded ([`decode_form`]), for text that has one;
//! 4. view 2 decoded once more.

use std::borrow::Cow;
use std::fmt;
use std::ops::Range;

use crate::RedactError;

/// The raw byte ranges of every string's contents (between its quotes), in order.
#[must_use]
pub fn strings(raw: &[u8]) -> Strings<'_> {
    Strings { raw, pos: 0 }
}

/// The iterator [`strings`] returns: one raw range per string, or the error that ends the body.
pub struct Strings<'a> {
    raw: &'a [u8],
    pos: usize,
}

impl fmt::Debug for Strings<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Raw bytes may be secrets: lengths only.
        f.debug_struct("Strings")
            .field("len", &self.raw.len())
            .field("pos", &self.pos)
            .finish()
    }
}

impl Iterator for Strings<'_> {
    type Item = Result<Range<usize>, RedactError>;

    fn next(&mut self) -> Option<Self::Item> {
        let open = self.pos + memchr::memchr(b'"', self.raw.get(self.pos..)?)?;
        let start = open + 1;
        let mut i = start;
        loop {
            // Jump to the next quote or backslash; everything in between is plain content.
            let next = self
                .raw
                .get(i..)
                .and_then(|rest| memchr::memchr2(b'"', b'\\', rest))
                .map(|at| i + at);
            match next.and_then(|at| self.raw.get(at).map(|&b| (at, b))) {
                None => {
                    self.pos = self.raw.len();
                    return Some(Err(RedactError::MalformedJson("unterminated string")));
                }
                Some((at, b'"')) => {
                    self.pos = at + 1;
                    return Some(Ok(start..at));
                }
                Some((at, _)) => i = at + 2,
            }
        }
    }
}

/// A decoded string and the way back to its raw bytes.
pub struct Decoded<'a> {
    /// The decoded text. Read through [`Decoded::text`] outside this crate: the offset map below
    /// describes exactly this text, so nobody else may change it.
    pub(crate) text: Cow<'a, str>,
    /// For each decoded byte, the raw offset of the character or escape that produced it, plus
    /// one final entry for the raw length. `None` when decoded and raw bytes coincide.
    map: Option<Vec<usize>>,
}

impl fmt::Debug for Decoded<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The decoded text may be a secret: length only.
        f.debug_struct("Decoded")
            .field("len", &self.text.len())
            .finish_non_exhaustive()
    }
}

impl<'a> Decoded<'a> {
    /// The decoded text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Text that is its own raw form (no escapes).
    #[must_use]
    pub fn plain(text: &'a str) -> Self {
        Self {
            text: Cow::Borrowed(text),
            map: None,
        }
    }

    /// Raw offset of decoded offset `i` (`i` may equal the decoded length).
    ///
    /// # Errors
    /// [`RedactError::DetectorFailure`] if `i` lies outside the decoded string.
    pub fn raw(&self, i: usize) -> Result<usize, RedactError> {
        match &self.map {
            None => Ok(i),
            Some(map) => map
                .get(i)
                .copied()
                .ok_or(RedactError::DetectorFailure("span outside the decoded string")),
        }
    }
}

/// Decodes the contents of one JSON string, for scanning only (no offset map).
///
/// # Errors
/// As [`decode_with`].
pub(crate) fn decode(raw: &[u8]) -> Result<Decoded<'_>, RedactError> {
    decode_with(raw, false)
}

/// Decodes the contents of one JSON string; with `mapped`, also the map back to raw offsets, for
/// splicing.
///
/// # Errors
/// [`RedactError::MalformedJson`] for a dangling or invalid escape, a lone surrogate or an invalid
/// code point, and [`RedactError::InvalidUtf8`] for content that is not UTF-8.
pub fn decode_with(raw: &[u8], mapped: bool) -> Result<Decoded<'_>, RedactError> {
    if !raw.contains(&b'\\') {
        let text = std::str::from_utf8(raw).map_err(|_| RedactError::InvalidUtf8)?;
        return Ok(Decoded {
            text: Cow::Borrowed(text),
            map: None,
        });
    }
    let mut out = Vec::with_capacity(raw.len());
    // The map costs eight bytes per byte; scanning never needs it.
    let mut map = Vec::with_capacity(if mapped { raw.len() + 1 } else { 0 });
    let note = |map: &mut Vec<usize>, at: usize| {
        if mapped {
            map.push(at);
        }
    };
    let mut i = 0;
    while let Some(&b) = raw.get(i) {
        if b != b'\\' {
            // Copy the whole run up to the next escape at once.
            let rest = raw.get(i..).unwrap_or_default();
            let run = memchr::memchr(b'\\', rest).unwrap_or(rest.len());
            out.extend_from_slice(rest.get(..run).unwrap_or_default());
            if mapped {
                map.extend(i..i + run);
            }
            i += run;
            continue;
        }
        let escape = raw.get(i + 1).ok_or(RedactError::MalformedJson("dangling escape"))?;
        let simple = match escape {
            b'"' => Some(b'"'),
            b'\\' => Some(b'\\'),
            b'/' => Some(b'/'),
            b'b' => Some(0x08),
            b'f' => Some(0x0C),
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            b'u' => None,
            _ => return Err(RedactError::MalformedJson("invalid escape")),
        };
        if let Some(byte) = simple {
            out.push(byte);
            note(&mut map, i);
            i += 2;
            continue;
        }
        let high = hex4(raw, i + 2)?;
        let (code, consumed) = if (0xD800..0xDC00).contains(&high) {
            let low = (raw.get(i + 6) == Some(&b'\\') && raw.get(i + 7) == Some(&b'u'))
                .then(|| hex4(raw, i + 8))
                .transpose()?
                .filter(|low| (0xDC00..0xE000).contains(low))
                .ok_or(RedactError::MalformedJson("lone surrogate"))?;
            (0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00), 12)
        } else if (0xDC00..0xE000).contains(&high) {
            return Err(RedactError::MalformedJson("lone surrogate"));
        } else {
            (high, 6)
        };
        let ch = char::from_u32(code).ok_or(RedactError::MalformedJson("invalid code point"))?;
        let mut buf = [0u8; 4];
        for &byte in ch.encode_utf8(&mut buf).as_bytes() {
            out.push(byte);
            note(&mut map, i);
        }
        i += consumed;
    }
    note(&mut map, raw.len());
    let text = String::from_utf8(out).map_err(|_| RedactError::InvalidUtf8)?;
    Ok(Decoded {
        text: Cow::Owned(text),
        map: mapped.then_some(map),
    })
}

/// One nested level of encoding, decoded for scanning. Owns its bytes: they may not be UTF-8
/// when the input was not.
pub struct Nested {
    /// The decoded bytes of this level; the scan reads them, redaction splices through
    /// [`Nested::into_decoded`].
    pub(crate) bytes: Vec<u8>,
    /// As in [`Decoded`]; empty when built without a map.
    map: Vec<usize>,
}

impl fmt::Debug for Nested {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The decoded bytes may be a secret: length only.
        f.debug_struct("Nested")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl Nested {
    /// As a [`Decoded`] view, for splicing; the input must have been UTF-8.
    ///
    /// # Errors
    /// [`RedactError::InvalidUtf8`] if the decoded bytes are not UTF-8.
    pub fn into_decoded(self) -> Result<Decoded<'static>, RedactError> {
        let text = String::from_utf8(self.bytes).map_err(|_| RedactError::InvalidUtf8)?;
        Ok(Decoded {
            text: Cow::Owned(text),
            map: Some(self.map),
        })
    }
}

/// Decodes one more level of encoding in `raw`, for scanning: JSON escapes (`\n`, `\"`, `\\`,
/// `\u` escapes with surrogate pairs) and ASCII percent escapes (`%41`). Unlike [`decode_with`] it
/// never fails: anything that is not a valid escape stays as it is, so text with a stray
/// backslash or percent sign is scanned, never refused. Output is UTF-8 whenever `raw` is.
/// `None` when there was nothing to decode. With `mapped`, the result maps back to offsets in
/// `raw`.
#[must_use]
pub fn decode_nested(raw: &[u8], mapped: bool) -> Option<Nested> {
    memchr::memchr2(b'\\', b'%', raw)?;
    decode_lenient(raw, mapped, (b'\\', b'%'), |raw, at| match raw.get(at) {
        Some(b'\\') => nested_escape(raw, at),
        Some(b'%') => percent(raw, at),
        _ => None,
    })
}

/// Decodes form encoding (`application/x-www-form-urlencoded`): ASCII percent escapes and `+` as a
/// space, so `-----BEGIN+PRIVATE+KEY-----%0A…` reads as the key it is. Only text with both a `+`
/// and a valid `%XX` escape is decoded; a `+` alone is ordinary text (base64, arithmetic). JSON
/// escapes are left as they are.
#[must_use]
pub fn decode_form(raw: &[u8], mapped: bool) -> Option<Nested> {
    memchr::memchr(b'+', raw)?;
    let has_escape = memchr::memchr_iter(b'%', raw).any(|at| percent(raw, at).is_some());
    if !has_escape {
        return None;
    }
    decode_lenient(raw, mapped, (b'+', b'%'), |raw, at| match raw.get(at) {
        Some(b'+') => Some((' ', 1)),
        Some(b'%') => percent(raw, at),
        _ => None,
    })
}

/// The shared lenient decoder: `escape` decodes the escape at an offset where one of the two
/// `markers` sits, or declines and the byte is kept.
fn decode_lenient(
    raw: &[u8],
    mapped: bool,
    markers: (u8, u8),
    escape: impl Fn(&[u8], usize) -> Option<(char, usize)>,
) -> Option<Nested> {
    let mut out = Vec::with_capacity(raw.len());
    let mut map = Vec::with_capacity(if mapped { raw.len() + 1 } else { 0 });
    let mut decoded_any = false;
    let mut i = 0;
    while i < raw.len() {
        if let Some((ch, consumed)) = escape(raw, i) {
            let mut buf = [0u8; 4];
            for &byte in ch.encode_utf8(&mut buf).as_bytes() {
                out.push(byte);
                if mapped {
                    map.push(i);
                }
            }
            i += consumed;
            decoded_any = true;
            continue;
        }
        // Copy up to the next marker. Markers are ASCII, so a UTF-8 sequence is never split.
        let rest = raw.get(i..).unwrap_or_default();
        let run = rest
            .get(1..)
            .and_then(|r| memchr::memchr2(markers.0, markers.1, r))
            .map_or(rest.len(), |at| at + 1);
        out.extend_from_slice(rest.get(..run).unwrap_or_default());
        if mapped {
            map.extend(i..i + run);
        }
        i += run;
    }
    if mapped {
        map.push(raw.len());
    }
    decoded_any.then_some(Nested { bytes: out, map })
}

/// A valid JSON escape at `at`: the character and how many bytes it takes.
fn nested_escape(raw: &[u8], at: usize) -> Option<(char, usize)> {
    let simple = match raw.get(at + 1)? {
        b'"' => '"',
        b'\\' => '\\',
        b'/' => '/',
        b'b' => '\u{8}',
        b'f' => '\u{c}',
        b'n' => '\n',
        b'r' => '\r',
        b't' => '\t',
        b'u' => {
            let high = hex4(raw, at + 2).ok()?;
            if !(0xD800..0xDC00).contains(&high) {
                // A lone low surrogate is not a char: `from_u32` refuses it, and it stays.
                return char::from_u32(high).map(|ch| (ch, 6));
            }
            let pair = raw.get(at + 6) == Some(&b'\\') && raw.get(at + 7) == Some(&b'u');
            let low = pair
                .then(|| hex4(raw, at + 8).ok())
                .flatten()
                .filter(|low| (0xDC00..0xE000).contains(low))?;
            let ch = char::from_u32(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))?;
            return Some((ch, 12));
        }
        _ => return None,
    };
    Some((simple, 2))
}

/// A percent escape of an ASCII byte at `at`. Non-ASCII bytes stay encoded, so the output stays
/// UTF-8; no claimed format needs them.
fn percent(raw: &[u8], at: usize) -> Option<(char, usize)> {
    let hex = |i: usize| raw.get(i).and_then(|&d| char::from(d).to_digit(16));
    let value = (hex(at + 1)? << 4) | hex(at + 2)?;
    let byte = u8::try_from(value).ok().filter(u8::is_ascii)?;
    Some((char::from(byte), 3))
}

fn hex4(raw: &[u8], at: usize) -> Result<u32, RedactError> {
    let digits = raw
        .get(at..at + 4)
        .ok_or(RedactError::MalformedJson("short unicode escape"))?;
    digits.iter().try_fold(0u32, |acc, &d| {
        char::from(d)
            .to_digit(16)
            .map(|v| (acc << 4) | v)
            .ok_or(RedactError::MalformedJson("invalid unicode escape"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_keys_and_values_and_skips_escaped_quotes() {
        let raw = br#"{"a":"x\"y","b":[1,"z"]}"#;
        let found: Vec<_> = strings(raw).map(|r| &raw[r.unwrap()]).collect();
        assert_eq!(found, [&b"a"[..], br#"x\"y"#, b"b", b"z"]);
    }

    #[test]
    fn decoding_maps_back_to_raw_offsets() {
        let raw = br"A\u0042\nC\ud83d\ude00D";
        let d = decode_with(raw, true).unwrap();
        assert_eq!(d.text, "AB\nC\u{1F600}D");
        assert_eq!(d.raw(1).unwrap(), 1, "B came from the \\u0042 escape");
        assert_eq!(d.raw(3).unwrap(), 9, "C");
        assert_eq!(
            d.raw(4).unwrap(),
            10,
            "the emoji's first byte came from the surrogate pair"
        );
        assert_eq!(d.raw(d.text.len()).unwrap(), raw.len());
    }

    #[test]
    fn nested_levels_decode_leniently_and_map_back() {
        // `~` stands for a backslash, so the fixture reads as the bytes it is.
        let esc = |s: &str| s.replace('~', "\\").into_bytes();
        let raw = esc("a~u0041%42~x~ud83d c%zz~~u0044");
        let n = decode_nested(&raw, true).unwrap();
        assert_eq!(
            n.bytes,
            esc("aAB~x~ud83d c%zz~u0044"),
            "invalid escapes stay as they are"
        );
        let d = n.into_decoded().unwrap();
        assert_eq!(d.raw(1).unwrap(), 1, "A came from the first escape");
        assert_eq!(d.raw(2).unwrap(), 7, "B came from %42");
        assert_eq!(d.raw(d.text.len()).unwrap(), raw.len());
        assert!(decode_nested(b"plain 100% text", false).is_none(), "nothing to decode");
        assert!(decode_nested(b"%C3%A9", false).is_none(), "non-ASCII stays encoded");
    }

    #[test]
    fn malformed_input_is_an_error() {
        assert!(strings(br#"{"a":"open"#).any(|r| r.is_err()));
        assert!(decode(br"\x").is_err());
        assert!(decode(br"\ud83d").is_err());
        assert!(decode(br"\ude00").is_err());
        assert!(decode(br"\u12").is_err());
    }
}
