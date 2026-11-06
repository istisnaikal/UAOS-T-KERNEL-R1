// SPDX-License-Identifier: Apache-2.0

//! Properties of the contract: every tape passes its invariants; the encoder round-trips and writes
//! `serde_json`'s bytes; the decoder and the tape accept the same strings; the offset map keeps its
//! rules; heap stays within its bound; duplicate keys are found after decoding, whatever their
//! spelling.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

mod common;

use std::collections::BTreeSet;
use std::fmt::Write as _;

use common::{check_tape, config, document, parse};
use proptest::prelude::*;
use uaos_json::{Kind, Limits, decode, decode_mapped, encode_str};

/// String content built from pieces that exercise the decoder: plain text, every simple escape,
/// unicode escapes (pairs, lone halves, short or bad hex), raw quotes and control bytes.
fn content() -> impl Strategy<Value = String> {
    let backslash = "\\";
    let pieces = prop_oneof![
        "[a-z]{1,4}",
        Just("é😀".to_owned()),
        prop::sample::select(vec!["\"", "\\", "/", "b", "f", "n", "r", "t", "x", "'", "u"])
            .prop_map(move |e| format!("{backslash}{e}")),
        (0_u32..0x1_0000).prop_map(move |unit| format!("{backslash}u{unit:04x}")),
        (0xD800_u32..0xDC00, 0xDC00_u32..0xE000)
            .prop_map(move |(high, low)| format!("{backslash}u{high:04X}{backslash}u{low:04x}")),
        Just(format!("{backslash}u12")),
        Just("\"".to_owned()),
        Just("\u{1}".to_owned()),
        Just("\u{7f}".to_owned()),
    ];
    prop::collection::vec(pieces, 0..8).prop_map(|parts| parts.concat())
}

proptest! {
    #![proptest_config(config(256))]

    /// Every generated document parses, passes every invariant, and decodes everywhere.
    #[test]
    fn every_tape_passes_its_invariants((_, _, text) in document()) {
        let tape = parse(text.as_bytes()).unwrap();
        check_tape(&tape).map_err(TestCaseError::fail)?;
        prop_assert_eq!(tape.input(), text.as_str());
        let ws = [' ', '\t', '\r', '\n'];
        let start = text.len() - text.trim_start_matches(ws).len();
        let end = text.trim_end_matches(ws).len();
        prop_assert_eq!(tape.root().span().range(), start..end);
    }

    /// The encoder writes `serde_json`'s bytes, and decoding them gives the text back.
    #[test]
    fn encoding_round_trips(text in any::<String>()) {
        let mut encoded = Vec::new();
        encode_str(&text, &mut encoded).unwrap();
        let expected = serde_json::to_string(&text).unwrap();
        prop_assert_eq!(&encoded, expected.as_bytes());
        let tape = parse(&encoded).unwrap();
        prop_assert_eq!(tape.root().kind(), Kind::String);
        let value = tape.root().str_value().unwrap();
        prop_assert_eq!(value.as_deref(), Some(text.as_str()));
        let inner = std::str::from_utf8(&encoded[1..encoded.len() - 1]).unwrap();
        prop_assert_eq!(decode(inner).unwrap(), text.as_str());
    }

    /// The decoder and the tape accept exactly the same string content, and decode it alike.
    #[test]
    fn decoder_and_tape_agree(text in content()) {
        let quoted = format!("\"{text}\"");
        let tape = parse(quoted.as_bytes());
        let decoded = decode(&text);
        prop_assert_eq!(tape.is_ok(), decoded.is_ok(), "{:?} vs {:?}", tape.as_ref().err(), decoded.as_ref().err());
        if let (Ok(tape), Ok(decoded)) = (tape, decoded) {
            prop_assert_eq!(tape.root().str_value().unwrap().unwrap(), decoded);
        }
    }

    /// The offset map: one entry per decoded byte plus the end, never decreasing; a byte copied
    /// from the content maps to itself, a byte an escape produced maps to the escape's backslash.
    #[test]
    fn the_offset_map_keeps_its_rules(text in content()) {
        let Ok(decoded) = decode_mapped(&text) else {
            return Ok(());
        };
        let len = decoded.text().len();
        prop_assert_eq!(decoded.raw_offset(len), Some(text.len()));
        prop_assert_eq!(decoded.raw_offset(len + 1), None);
        let mut previous = 0;
        for at in 0..=len {
            let raw = decoded.raw_offset(at).unwrap();
            prop_assert!(raw >= previous, "map decreases at {}", at);
            prop_assert!(raw <= text.len());
            if at < len {
                let source = text.as_bytes()[raw];
                let copied = source == decoded.text().as_bytes()[at];
                prop_assert!(source == b'\\' || copied, "entry {} maps to an unrelated byte", at);
            }
            previous = raw;
        }
        prop_assert_eq!(decoded.is_identity(), !text.contains('\\'));
    }

    /// Heap stays within the contract's bound.
    #[test]
    fn heap_stays_bounded((_, _, text) in document()) {
        let tape = parse(text.as_bytes()).unwrap();
        let stats = tape.stats();
        let max_nodes = usize::try_from(Limits::DEFAULT.max_nodes()).unwrap();
        prop_assert!(stats.heap_bytes <= 24 * max_nodes);
        let initial = (text.len() / 128 + 1).next_power_of_two().max(16);
        let bound = 24 * initial.max(2 * usize::try_from(stats.nodes).unwrap());
        prop_assert!(stats.heap_bytes <= bound, "{} > {}", stats.heap_bytes, bound);
    }
}

#[test]
fn the_reference_size_reserves_once() {
    // About 1.70 MB holding 12,280 values, the spike's reference shape: the first reserve already
    // holds them, 16,384 nodes or 384 KiB.
    let item = format!("{{\"type\":\"text\",\"text\":\"{}\"}}", "x".repeat(390));
    let items: Vec<&str> = std::iter::repeat_n(item.as_str(), 4_093).collect();
    let body = format!("[{}]", items.join(","));
    assert!((1_690_000..1_710_000).contains(&body.len()), "{}", body.len());
    let tape = parse(body.as_bytes()).unwrap();
    let stats = tape.stats();
    assert_eq!(stats.nodes, 12_280);
    assert_eq!(stats.heap_bytes, 384 * 1024);
}

#[test]
fn member_lookup_and_navigation() {
    let input = br#"{"messages":[{"role":"user","content":"hi"},{"role":"assistant"}],"n":2}"#;
    let tape = parse(input).unwrap();
    let root = tape.root();
    let messages = root.member("messages").unwrap().unwrap();
    assert_eq!(messages.kind(), Kind::Array);
    let roles: Vec<String> = messages
        .children()
        .map(|m| {
            m.member("role")
                .unwrap()
                .unwrap()
                .str_value()
                .unwrap()
                .unwrap()
                .into_owned()
        })
        .collect();
    assert_eq!(roles, ["user", "assistant"]);
    let second = messages.children().nth(1).unwrap();
    assert_eq!(second.ordinal(), 1);
    assert_eq!(
        messages.children().next().unwrap().next_sibling().map(|n| n.id()),
        Some(second.id())
    );
    assert_eq!(second.next_sibling().map(|n| n.id()), None);
    let content = messages.descendants().find(|n| n.key_is("content").unwrap()).unwrap();
    let path: Vec<_> = content.ancestors().map(|n| n.id()).collect();
    assert_eq!(path.last().copied(), Some(root.id()));
    assert_eq!(path.len(), 3);
    assert!(root.member("missing").unwrap().is_none());
    assert!(content.member("x").unwrap().is_none(), "a string has no members");
    assert_eq!(root.member("n").unwrap().unwrap().as_u64(), Some(2));
    assert_eq!(root.subtree_end().index(), tape.nodes().len());
}

/// Keys the duplicate property draws from: empty, short and long (around the 8-byte words the
/// fingerprint folds), with characters that must be escaped, non-ASCII, astral, the pair that
/// shares a fingerprint (`tape.rs` pins it), and enough distinct keys that objects of more than 8
/// members without a repeat occur.
const KEYS: &[&str] = &[
    "",
    "a",
    "ab",
    "abcdefg",
    "abcdefgh",
    "abcdefghi",
    "abcdefghijklmnop",
    "abcdefghijklmnopq",
    "é",
    "😀",
    "k4312",
    "k27385",
    "a/b",
    "tool_use_id",
    "q\"",
    "\\",
    "\0x",
    "x\0",
    "id",
    "type",
    "text",
    "role",
    "content",
    "cache_control",
    "input",
    "name",
    "signature",
    "thinking",
    "is_error",
    "model",
];

/// A generated value: a number, or an object or array of generated values.
#[derive(Clone, Debug)]
enum Doc {
    Number,
    Object(Vec<(usize, u8, Doc)>),
    Array(Vec<Doc>),
}

fn doc() -> impl Strategy<Value = Doc> {
    Just(Doc::Number).prop_recursive(4, 64, 20, |inner| {
        prop_oneof![
            prop::collection::vec((0..KEYS.len(), 0_u8..5, inner.clone()), 0..20).prop_map(Doc::Object),
            prop::collection::vec(inner, 0..4).prop_map(Doc::Array),
        ]
    })
}

/// Writes `key` as JSON string content in one of five spellings that all decode to it: raw,
/// every character escaped (lower- or upper-case hex, astral characters as a surrogate pair),
/// only the first character escaped, or a slash in its short form. Characters JSON forbids raw
/// are always escaped.
fn spell(key: &str, spelling: u8, out: &mut String) {
    let backslash = "\\";
    for (i, ch) in key.chars().enumerate() {
        let escaped = match spelling {
            1 | 2 => true,
            3 => i == 0,
            _ => false,
        };
        if escaped || ch == '"' || ch == '\\' || u32::from(ch) < 0x20 {
            let mut units = [0_u16; 2];
            for unit in ch.encode_utf16(&mut units).iter() {
                if spelling == 2 {
                    write!(out, "{backslash}u{unit:04X}").unwrap();
                } else {
                    write!(out, "{backslash}u{unit:04x}").unwrap();
                }
            }
        } else if spelling == 4 && ch == '/' {
            out.push_str(backslash);
            out.push('/');
        } else {
            out.push(ch);
        }
    }
}

/// Writes `value`; records the earliest second occurrence in the first object that closes with a
/// repeat, which is where the parser reports it.
fn write_value(value: &Doc, out: &mut String, first_closed: &mut Option<u32>) {
    match value {
        Doc::Number => out.push('0'),
        Doc::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out, first_closed);
            }
            out.push(']');
        }
        Doc::Object(members) => {
            out.push('{');
            let mut seen = BTreeSet::new();
            let mut repeat = None;
            for (i, (key, spelling, member)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let at = u32::try_from(out.len()).unwrap();
                out.push('"');
                spell(KEYS.get(*key).unwrap(), *spelling, out);
                out.push_str("\":");
                if !seen.insert(*key) && repeat.is_none() {
                    repeat = Some(at);
                }
                write_value(member, out, first_closed);
            }
            out.push('}');
            if first_closed.is_none() {
                *first_closed = repeat;
            }
        }
    }
}

proptest! {
    #![proptest_config(config(256))]

    /// Duplicate keys are found after decoding, whatever their spelling and nesting, and reported
    /// at the earliest second occurrence of the first object that closes with one. Distinct keys
    /// are accepted, objects of more than 8 members and keys that share a fingerprint included. The
    /// generator knows every key's decoded text and offset, so the expectation is exact and
    /// independent of the parser.
    #[test]
    fn duplicates_are_found_exactly_after_decoding(root in doc()) {
        let mut text = String::new();
        let mut expected = None;
        write_value(&root, &mut text, &mut expected);
        match (parse(text.as_bytes()), expected) {
            (Ok(tape), None) => check_tape(&tape).map_err(TestCaseError::fail)?,
            (Err(e), Some(at)) => {
                prop_assert_eq!(e.kind(), uaos_json::ErrorKind::DuplicateKey, "{}", text);
                prop_assert_eq!(e.offset(), at, "{}", text);
            }
            (Ok(_), Some(at)) => prop_assert!(false, "duplicate key at {} accepted: {}", at, text),
            (Err(e), None) => prop_assert!(false, "distinct keys refused ({:?}): {}", e.kind(), text),
        }
    }
}
