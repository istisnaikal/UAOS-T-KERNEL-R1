// SPDX-License-Identifier: Apache-2.0

//! Shared by the property, differential and fuzz tests: a generator of valid documents written in
//! varied styles (the spike's styles), mutations that break them, a strict oracle built on
//! `serde_json`, and a check that reads every string and key of a tape.

#![allow(dead_code, reason = "shared by several test crates; each uses a subset")]

use std::collections::BTreeSet;
use std::fmt::{self, Write as _};

use proptest::prelude::*;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use uaos_json::{Kind, Limits, Node, Tape};

/// The fixed seed of every merge run; nightly overrides it with `PROPTEST_RNG_SEED`.
pub(crate) const MERGE_SEED: u64 = 0x5541_4F53_4A53_0001;

/// The proptest configuration of a merge run: `cases` cases from the fixed seed.
pub(crate) fn config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        rng_seed: proptest::test_runner::RngSeed::Fixed(MERGE_SEED),
        ..ProptestConfig::default()
    }
}

/// Text for strings and keys: ASCII, the characters JSON must escape, non-ASCII in every UTF-8
/// length, a character outside the Basic Multilingual Plane, and look-alikes of escapes.
pub(crate) fn text() -> impl Strategy<Value = String> {
    let pieces = prop_oneof![
        "[a-z]{1,6}",
        Just("\"".to_owned()),
        Just("\\".to_owned()),
        Just("/".to_owned()),
        Just("\\u0061".to_owned()),
        Just("\u{0}".to_owned()),
        Just("\u{1f}".to_owned()),
        Just("\n\t\r\u{8}\u{c}".to_owned()),
        Just("\u{7f}".to_owned()),
        Just("é".to_owned()),
        Just("中".to_owned()),
        Just("\u{2028}".to_owned()),
        Just("😀".to_owned()),
        Just(" ".to_owned()),
    ];
    prop::collection::vec(pieces, 0..6).prop_map(|parts| parts.concat())
}

/// A JSON value model: numbers stay text, objects keep their member order and have unique keys.
#[derive(Clone, Debug)]
pub(crate) enum Model {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Model>),
    Object(Vec<(String, Model)>),
}

fn number() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("0".to_owned()),
        Just("-0".to_owned()),
        "-?[1-9][0-9]{0,18}",
        "-?(0|[1-9][0-9]{0,6})\\.[0-9]{1,6}",
        "-?(0|[1-9][0-9]{0,3})(\\.[0-9]{1,3})?[eE][+-]?[0-9]{1,2}",
    ]
}

/// Valid values, up to six levels deep.
pub(crate) fn model() -> impl Strategy<Value = Model> {
    let leaf = prop_oneof![
        Just(Model::Null),
        any::<bool>().prop_map(Model::Bool),
        number().prop_map(Model::Number),
        text().prop_map(Model::String),
    ];
    leaf.prop_recursive(6, 64, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Model::Array),
            prop::collection::vec((text(), inner), 0..6).prop_map(|members| {
                let mut seen = BTreeSet::new();
                Model::Object(
                    members
                        .into_iter()
                        .filter(|(key, _)| seen.insert(key.clone()))
                        .collect(),
                )
            }),
        ]
    })
}

/// How a model is written: whitespace, which characters are escaped, and how.
#[derive(Clone, Copy, Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent style switches, drawn at random"
)]
pub(crate) struct Style {
    pub(crate) pretty: bool,
    pub(crate) escape_slash: bool,
    pub(crate) escape_non_ascii: bool,
    pub(crate) uppercase_hex: bool,
    /// Escape about one ASCII letter in this many as `\u00xx` (0: never).
    pub(crate) escape_ascii_every: u8,
    pub(crate) seed: u64,
}

pub(crate) fn style() -> impl Strategy<Value = Style> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        prop_oneof![Just(0_u8), 2_u8..6],
        any::<u64>(),
    )
        .prop_map(
            |(pretty, escape_slash, escape_non_ascii, uppercase_hex, escape_ascii_every, seed)| Style {
                pretty,
                escape_slash,
                escape_non_ascii,
                uppercase_hex,
                escape_ascii_every,
                seed,
            },
        )
}

/// A valid document and the style it was written in.
pub(crate) fn document() -> impl Strategy<Value = (Model, Style, String)> {
    (model(), style()).prop_map(|(model, style)| {
        let mut out = String::new();
        let mut rng = style.seed | 1;
        write(&model, style, &mut rng, 0, &mut out);
        (model, style, out)
    })
}

fn next(rng: &mut u64) -> u64 {
    // xorshift64: deterministic per document, independent of proptest's own stream.
    *rng ^= *rng << 13;
    *rng ^= *rng >> 7;
    *rng ^= *rng << 17;
    *rng
}

fn space(style: Style, rng: &mut u64, depth: usize, out: &mut String) {
    if style.pretty {
        out.push('\n');
        out.push_str(&"  ".repeat(depth));
    } else if next(rng).is_multiple_of(8) {
        let pick = usize::try_from(next(rng) % 4).unwrap_or(0);
        out.push_str([" ", "\t", "\r\n", "  "].get(pick).copied().unwrap_or(" "));
    }
}

fn write(model: &Model, style: Style, rng: &mut u64, depth: usize, out: &mut String) {
    match model {
        Model::Null => out.push_str("null"),
        Model::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Model::Number(text) => out.push_str(text),
        Model::String(text) => write_string(text, style, rng, out),
        Model::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                space(style, rng, depth + 1, out);
                write(item, style, rng, depth + 1, out);
            }
            if !items.is_empty() {
                space(style, rng, depth, out);
            }
            out.push(']');
        }
        Model::Object(members) => {
            out.push('{');
            for (i, (key, value)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                space(style, rng, depth + 1, out);
                write_string(key, style, rng, out);
                out.push(':');
                if style.pretty {
                    out.push(' ');
                }
                write(value, style, rng, depth + 1, out);
            }
            if !members.is_empty() {
                space(style, rng, depth, out);
            }
            out.push('}');
        }
    }
}

fn unicode_escape(unit: u32, style: Style, out: &mut String) {
    if style.uppercase_hex {
        write!(out, "\\u{unit:04X}").unwrap();
    } else {
        write!(out, "\\u{unit:04x}").unwrap();
    }
}

/// Writes `text` as a string literal, with every escape the style asks for.
pub(crate) fn write_string(text: &str, style: Style, rng: &mut u64, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' if style.escape_slash => out.push_str("\\/"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if u32::from(c) < 0x20 => unicode_escape(u32::from(c), style, out),
            c if !c.is_ascii() && style.escape_non_ascii => {
                let mut units = [0_u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    unicode_escape(u32::from(*unit), style, out);
                }
            }
            c if c.is_ascii_alphabetic()
                && style.escape_ascii_every > 0
                && next(rng).is_multiple_of(u64::from(style.escape_ascii_every)) =>
            {
                unicode_escape(u32::from(c), style, out);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Byte-level mutations of a document, to reach the rejection paths.
#[derive(Clone, Debug)]
pub(crate) enum Mutation {
    Flip(usize, u8),
    Delete(usize, usize),
    Duplicate(usize, usize),
    Insert(usize, &'static [u8]),
}

/// Tokens a mutation inserts: each one breaks or bends a rule of the grammar.
pub(crate) const TOKENS: &[&[u8]] = &[
    b"\\ud800",
    b"\\udc00",
    b"01",
    b"\xEF\xBB\xBF",
    b"\\u0000",
    b"\\u00",
    b",",
    b"}",
    b"]",
    b"{",
    b"[",
    b"\"",
    b"\\",
    b"\x01",
    b"\xff",
    b"1e9999",
    b"-",
    b":",
    b" ",
];

pub(crate) fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), any::<u8>()).prop_map(|(at, byte)| Mutation::Flip(at, byte)),
        (any::<usize>(), 1_usize..8).prop_map(|(at, len)| Mutation::Delete(at, len)),
        (any::<usize>(), 1_usize..16).prop_map(|(at, len)| Mutation::Duplicate(at, len)),
        (any::<usize>(), prop::sample::select(TOKENS)).prop_map(|(at, token)| Mutation::Insert(at, token)),
    ]
}

/// Applies mutations in order; positions wrap around the current length.
pub(crate) fn mutate(document: &str, mutations: &[Mutation]) -> Vec<u8> {
    let mut bytes = document.as_bytes().to_vec();
    for mutation in mutations {
        let len = bytes.len().max(1);
        match *mutation {
            Mutation::Flip(at, byte) => {
                if let Some(slot) = bytes.get_mut(at % len) {
                    *slot = byte;
                }
            }
            Mutation::Delete(at, n) => {
                let start = (at % len).min(bytes.len());
                let end = (start + n).min(bytes.len());
                bytes.drain(start..end);
            }
            Mutation::Duplicate(at, n) => {
                let start = (at % len).min(bytes.len());
                let end = (start + n).min(bytes.len());
                let copy = bytes[start..end].to_vec();
                bytes.splice(end..end, copy);
            }
            Mutation::Insert(at, token) => {
                let at = (at % len).min(bytes.len());
                bytes.splice(at..at, token.iter().copied());
            }
        }
    }
    bytes
}

/// The oracle's verdict on one input.
#[derive(Debug)]
pub(crate) enum Oracle {
    Accepted(Value),
    /// A number outside the f64 range: valid grammar, which the tape accepts and `serde_json`
    /// cannot represent. The one known divergence.
    NumberOutOfRange,
    Rejected(String),
}

/// `serde_json`, strict: the whole input, no duplicate keys.
pub(crate) fn oracle(bytes: &[u8]) -> Oracle {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let result = StrictValue.deserialize(&mut deserializer).and_then(|value| {
        deserializer.end()?;
        Ok(value)
    });
    match result {
        Ok(value) => Oracle::Accepted(value),
        Err(e) if e.to_string().contains("number out of range") => Oracle::NumberOutOfRange,
        Err(e) => Oracle::Rejected(e.to_string()),
    }
}

/// A `Value` whose objects refuse a repeated key.
struct StrictValue;

impl<'de> DeserializeSeed<'de> for StrictValue {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("number out of range"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(StrictValue)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut members = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(StrictValue)?;
            if members.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate key"));
            }
        }
        Ok(Value::Object(members))
    }
}

/// Compares a tape's value with the oracle's: every kind, string, key and number, and the first
/// mismatch found.
pub(crate) fn compare(node: Node<'_, '_>, expected: &Value) -> Result<(), String> {
    match (node.kind(), expected) {
        (Kind::Null, Value::Null) | (Kind::True, Value::Bool(true)) | (Kind::False, Value::Bool(false)) => Ok(()),
        (Kind::Number, Value::Number(number)) => {
            let text = node.number_text().ok_or("number without text")?;
            let reread: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
            (reread == Value::Number(number.clone()))
                .then_some(())
                .ok_or_else(|| format!("number {} at {:?}", text.len(), node.span()))
        }
        (Kind::String, Value::String(text)) => {
            let decoded = node.str_value().map_err(|e| e.to_string())?;
            (decoded.as_deref() == Some(text.as_str()))
                .then_some(())
                .ok_or_else(|| format!("string at {:?}", node.span()))
        }
        (Kind::Array, Value::Array(items)) => {
            let children: Vec<_> = node.children().collect();
            if children.len() != items.len() {
                return Err(format!("array length at {:?}", node.span()));
            }
            children
                .into_iter()
                .zip(items)
                .try_for_each(|(child, item)| compare(child, item))
        }
        (Kind::Object, Value::Object(members)) => {
            let children: Vec<_> = node.children().collect();
            if children.len() != members.len() {
                return Err(format!("object size at {:?}", node.span()));
            }
            for child in children {
                let key = child.key().map_err(|e| e.to_string())?.ok_or("member without key")?;
                let value = members
                    .get(key.as_ref())
                    .ok_or_else(|| format!("key at {:?}", child.key_span()))?;
                if !child.key_is(&key).map_err(|e| e.to_string())? {
                    return Err(format!("key_is at {:?}", child.key_span()));
                }
                compare(child, value)?;
            }
            Ok(())
        }
        (kind, _) => Err(format!("kind {kind:?} at {:?}", node.span())),
    }
}

/// Every check a tape that parsed must pass: its invariants, and every string and key decoding,
/// with and without the offset map.
pub(crate) fn check_tape(tape: &Tape<'_>) -> Result<(), String> {
    tape.verify().map_err(|v| v.to_string())?;
    for node in tape.nodes() {
        node.key().map_err(|e| e.to_string())?;
        node.str_value().map_err(|e| e.to_string())?;
        node.str_value_mapped().map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Tape<'_>, uaos_json::JsonError> {
    uaos_json::parse(bytes, &Limits::DEFAULT)
}
