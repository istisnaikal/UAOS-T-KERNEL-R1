// SPDX-License-Identifier: Apache-2.0

//! The redactor's old tokenizer against the shared tape (`uaos-json`): a differential test.
//!
//! Redaction now finds its strings on the tape; the final scan still finds them with the old
//! tokenizer, which stays independent of the tape by design. For every input the tape accepts, the
//! two must find the same strings in the same order, decode them to the same text and map every
//! decoded offset to the same raw offset. Since each string is then redacted by the same fixpoint
//! as before, equal strings give equal output: the redaction corpus checks that end to end.

use std::ops::Range;

use proptest::prelude::*;
use uaos_json::Limits;

use crate::redactor::string_ranges;
use uaos_redact_scan::json::{decode_with, strings};

/// A JSON value to write. Object keys are unique once decoded, so a body is never refused for a
/// duplicate key the generator made by accident.
#[derive(Debug, Clone)]
enum Model {
    Str(String),
    Num(i64),
    Bool(bool),
    Null,
    Arr(Vec<Model>),
    Obj(Vec<(String, Model)>),
}

/// Text that exercises decoding: quotes, backslashes, control characters, non-ASCII of every
/// UTF-8 length, a character outside the Basic Multilingual Plane, and look-alikes of escapes.
fn text() -> impl Strategy<Value = String> {
    let special = prop::sample::select(vec![
        'a', 'u', '0', 'f', ' ', '"', '\\', '/', '\n', '\t', '\r', '\u{8}', '\u{c}', '\u{1}', '\u{1f}', 'é', 'ğ', '€',
        '\u{2028}', '😀',
    ]);
    prop::collection::vec(prop_oneof![3 => special, 1 => any::<char>()], 0..12)
        .prop_map(|chars| chars.into_iter().collect())
}

fn model() -> impl Strategy<Value = Model> {
    let leaf = prop_oneof![
        text().prop_map(Model::Str),
        any::<i64>().prop_map(Model::Num),
        any::<bool>().prop_map(Model::Bool),
        Just(Model::Null),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Model::Arr),
            prop::collection::btree_map(text(), inner, 0..6)
                .prop_map(|members| Model::Obj(members.into_iter().collect())),
        ]
    })
}

/// A small deterministic generator for the writer's choices.
fn roll(seed: &mut u64) -> u64 {
    *seed = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *seed >> 33
}

/// Writes nothing, or one of JSON's whitespace runs: space, tab, line feed and carriage return.
fn space(seed: &mut u64, out: &mut String) {
    if roll(seed).is_multiple_of(3) {
        out.push_str(match roll(seed) % 3 {
            0 => " ",
            1 => "\n\t ",
            _ => "\r\n",
        });
    }
}

/// Writes a string with escapes chosen at random: every short escape (`\"`, `\\`, `\/`, `\b`,
/// `\f`, `\n`, `\r`, `\t`), `\u` escapes in either case, surrogate pairs, and plain characters
/// wherever JSON allows them.
fn write_str(text: &str, seed: &mut u64, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        let code = u32::from(c);
        let choice = roll(seed) % 4;
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' if choice < 2 => out.push_str("\\n"),
            '\t' if choice < 2 => out.push_str("\\t"),
            '\r' if choice < 2 => out.push_str("\\r"),
            '\u{8}' if choice < 2 => out.push_str("\\b"),
            '\u{c}' if choice < 2 => out.push_str("\\f"),
            '/' if choice == 0 => out.push_str("\\/"),
            _ if code < 0x20 || choice == 0 => {
                let mut units = [0_u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    push_unit(*unit, roll(seed).is_multiple_of(2), out);
                }
            }
            _ => out.push(c),
        }
    }
    out.push('"');
}

/// Writes `\\u` and the code unit as four hex digits, in either case.
fn push_unit(unit: u16, upper: bool, out: &mut String) {
    out.push_str("\\u");
    for shift in [12_u16, 8, 4, 0] {
        let digit = char::from_digit(u32::from((unit >> shift) & 0xF), 16).unwrap_or('0');
        out.push(if upper { digit.to_ascii_uppercase() } else { digit });
    }
}

fn write(model: &Model, seed: &mut u64, out: &mut String) {
    space(seed, out);
    match model {
        Model::Str(text) => write_str(text, seed, out),
        Model::Num(n) => out.push_str(&n.to_string()),
        Model::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Model::Null => out.push_str("null"),
        Model::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, seed, out);
            }
            space(seed, out);
            out.push(']');
        }
        Model::Obj(members) => {
            out.push('{');
            for (i, (key, value)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                space(seed, out);
                write_str(key, seed, out);
                space(seed, out);
                out.push(':');
                write(value, seed, out);
            }
            space(seed, out);
            out.push('}');
        }
    }
    space(seed, out);
}

fn document() -> impl Strategy<Value = String> {
    (model(), any::<u64>()).prop_map(|(model, mut seed)| {
        let mut out = String::new();
        write(&model, &mut seed, &mut out);
        out
    })
}

/// Breaks a document: inserts or deletes bytes JSON's structure turns on.
fn mutate(document: &str, edits: &[(usize, u8, bool)]) -> Vec<u8> {
    let mut bytes = document.as_bytes().to_vec();
    for &(at, byte, insert) in edits {
        let at = at % (bytes.len() + 1);
        if insert {
            bytes.insert(at, byte);
        } else if at < bytes.len() {
            bytes.remove(at);
        }
    }
    bytes
}

fn edit() -> impl Strategy<Value = (usize, u8, bool)> {
    (
        any::<usize>(),
        prop::sample::select(b"{}[]:,\"\\ 0u\xff".to_vec()),
        any::<bool>(),
    )
}

/// Asserts that the two tokenizers agree on `json`, if the tape accepts it.
fn agree(json: &[u8]) -> Result<(), TestCaseError> {
    let Ok(tape) = uaos_json::parse(json, &Limits::DEFAULT) else {
        return Ok(());
    };
    let on_tape: Vec<Range<usize>> = string_ranges(&tape).map(|(range, _, _)| range).collect();
    let old: Result<Vec<Range<usize>>, _> = strings(json).collect();
    prop_assert_eq!(
        old.as_ref().ok(),
        Some(&on_tape),
        "the tokenizers found different strings in an accepted body"
    );
    for range in on_tape {
        let content = json
            .get(range)
            .ok_or_else(|| TestCaseError::fail("range outside the body"))?;
        let raw = std::str::from_utf8(content).map_err(|_| TestCaseError::fail("content is not UTF-8"))?;
        let old = decode_with(content, true).map_err(|e| TestCaseError::fail(format!("old decode: {e}")))?;
        let new = uaos_json::decode_mapped(raw).map_err(|e| TestCaseError::fail(format!("tape decode: {e}")))?;
        prop_assert_eq!(old.text(), new.text(), "the decoders disagree on a string's text");
        for decoded in 0..=new.text().len() {
            let old_offset = old.raw(decoded).ok();
            let new_offset = new.raw_offset(decoded);
            prop_assert_eq!(old_offset, new_offset, "the decoders map a decoded offset differently");
        }
    }
    Ok(())
}

/// The seed of every merge run: fixed, so a merge is reproducible. It is the eight bytes the first
/// version of this test used (`uaos-red`, little-endian), so the cases, and the counts, are
/// unchanged. A new seed is a new number here.
const MERGE_SEED: u64 = u64::from_le_bytes(*b"uaos-red");
/// Valid documents per merge. A longer run raises both counts here: `PROPTEST_CASES` cannot,
/// because the counts are set explicitly and the kernel reads no environment outside its
/// composition root.
const VALID_CASES: u32 = 256;
/// Mutated documents per merge. Only about one in six still parses (331 of 2,048 on the merge
/// seed), so this side runs more cases.
const MUTATED_CASES: u32 = 2048;

fn merge_config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        rng_seed: proptest::test_runner::RngSeed::Fixed(MERGE_SEED),
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(merge_config(VALID_CASES))]

    /// Valid documents with every escape form, whitespace and nesting.
    #[test]
    fn tokenizers_agree(document in document()) {
        // Valid by construction: a refusal here means the generator is wrong, and the
        // differential below would otherwise pass without comparing anything.
        prop_assert!(
            uaos_json::parse(document.as_bytes(), &Limits::DEFAULT).is_ok(),
            "the generator wrote a document the tape refuses: {:?}",
            document
        );
        agree(document.as_bytes())?;
    }

}

proptest! {
    #![proptest_config(merge_config(MUTATED_CASES))]

    /// The same documents, broken: whatever the tape still accepts must agree.
    #[test]
    fn tokenizers_agree_on_mutations(document in document(), edits in prop::collection::vec(edit(), 1..4)) {
        agree(&mutate(&document, &edits))?;
    }
}
