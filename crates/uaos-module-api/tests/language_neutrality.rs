// SPDX-License-Identifier: Apache-2.0

//! Language neutrality at the module socket (gate `language-neutrality`).
//!
//! A corpus in the seven GA locales, built around the classic hazards, crosses five stages:
//! `uaos-json` parse, the structural view, selectors, `ModuleText`, and `ModuleState` checkpoint
//! and restore. Every comparison is on bytes, so a pass means 0 byte differences. The hazards:
//! - Turkish dotted and dotless i;
//! - German sharp s and its capital;
//! - precomposed letters against base letters plus combining marks (NFC against NFD);
//! - Arabic with tashkeel, Arabic-Indic digits and the implicit bidi marks;
//! - astral characters;
//! - JSON escapes against raw characters.
//!
//! The tests named in `xtask` seeded violations carry the words their negative expects in their
//! failure message.

#![allow(
    clippy::unwrap_used,
    reason = "test harness: a helper's failure fails the test that called it"
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;

use proptest::prelude::*;
use uaos_json::{Limits, NodeId, parse};
use uaos_module_api::{
    Code, Mask, ModuleState, ModuleText, Predicate, Selector, Step, StructuralView, TextError, ViewText,
    is_explicit_bidi, is_tag, is_variation_selector,
};

/// One sample per GA locale. Invisible and combining characters are written as escapes.
const CORPUS: [(&str, &str); 7] = [
    (
        "en",
        "Continue where we stopped: the build is green 🙂, the 𝔘AOS tests are not.",
    ),
    ("tr", "İstanbul'da ılık bir gün: IŞIK ile ışık aynı değil, İ ile i de."),
    ("de", "Straße, STRASSE und Maß: ẞ ist der Großbuchstabe von ß."),
    (
        "fr",
        "Élève à l'école, déjà là; E\u{301}le\u{300}ve s'écrit aussi ainsi.",
    ),
    ("es", "¿Año nuevo? ¡Señor, mañana! Tambie\u{301}n an\u{303}o."),
    (
        "it",
        "Perché è così? Più caffè, già; perche\u{301} con un accento a parte.",
    ),
    ("ar", "مَرْحَبًا بِالعَالَم\u{200F} ١٢٣ \u{61C}نص\u{200E} done"),
];

/// A JSON string literal for `s`, escaping only what JSON requires.
fn json_string(s: &str) -> String {
    let backslash = '\\';
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push(backslash);
                out.push(c);
            }
            c if u32::from(c) < 0x20 => {
                write!(out, "{backslash}u{:04x}", u32::from(c)).unwrap();
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A one-message request whose content is the JSON literal `content`.
fn request(content: &str) -> String {
    format!(r#"{{"messages":[{{"role":"user","content":{content}}}]}}"#)
}

fn content_ids(view: &StructuralView<'_, '_>) -> Vec<NodeId> {
    Selector::new(vec![
        Step::Key("messages".into()),
        Step::Each,
        Step::Key("content".into()),
    ])
    .unwrap()
    .resolve(view)
    .unwrap()
}

/// The decoded content of a one-message request, through parse, view and selector.
fn through_the_view(body: &str) -> String {
    let tape = parse(body.as_bytes(), &Limits::DEFAULT).unwrap();
    let none = Mask::new();
    let view = StructuralView::new(&tape, &none);
    let ids = content_ids(&view);
    assert_eq!(ids.len(), 1);
    match view.node(ids[0]).unwrap().text().unwrap() {
        Some(ViewText::Plain(text)) => text.into_owned(),
        other => format!("not plain text: {other:?}"),
    }
}

/// How many messages a `MemberIn` on `content` selects in `body`.
fn content_matches(body: &str, value: &str) -> usize {
    let tape = parse(body.as_bytes(), &Limits::DEFAULT).unwrap();
    let none = Mask::new();
    let view = StructuralView::new(&tape, &none);
    Selector::new(vec![
        Step::Key("messages".into()),
        Step::Each,
        Step::Where(Predicate::MemberIn {
            key: "content".into(),
            values: BTreeSet::from([value.to_owned()]),
        }),
    ])
    .unwrap()
    .resolve(&view)
    .unwrap()
    .len()
}

#[test]
fn every_locale_crosses_the_view_byte_for_byte() {
    for (locale, sample) in CORPUS {
        let out = through_the_view(&request(&json_string(sample)));
        assert_eq!(
            out.as_bytes(),
            sample.as_bytes(),
            "{locale}: byte differences through the view"
        );
    }
}

#[test]
fn escaped_and_raw_forms_decode_to_the_same_bytes() {
    let b = '\\';
    // Dotted capital I, an Arabic letter with a mark, and an astral character as a surrogate pair.
    let escaped = format!("\"{b}u0130stanbul {b}u0645{b}u064e {b}ud83d{b}ude42\"");
    let raw = "İstanbul مَ 🙂";
    assert_eq!(through_the_view(&request(&escaped)), raw);
    assert_eq!(through_the_view(&request(&json_string(raw))), raw);
}

#[test]
fn nfc_and_nfd_stay_distinct() {
    let nfc = "café";
    let nfd = "cafe\u{301}";
    assert_ne!(nfc.as_bytes(), nfd.as_bytes());
    for (stored, asked, expected) in [(nfc, nfc, 1), (nfd, nfd, 1), (nfc, nfd, 0), (nfd, nfc, 0)] {
        let body = request(&json_string(stored));
        assert_eq!(
            content_matches(&body, asked),
            expected,
            "normalized: {stored:?} against {asked:?}"
        );
        assert_eq!(
            through_the_view(&body).as_bytes(),
            stored.as_bytes(),
            "normalized on decode"
        );
    }
}

#[test]
fn selectors_never_fold_case() {
    let pairs = [
        ("user", "USER"),
        ("user", "User"),
        ("İstanbul", "istanbul"),
        ("İstanbul", "ISTANBUL"),
        ("ışık", "IŞIK"),
        ("ı", "i"),
        ("straße", "STRASSE"),
        ("straße", "strasse"),
        ("ß", "ẞ"),
        ("Élève", "élève"),
    ];
    for (stored, asked) in pairs {
        let body = request(&json_string(stored));
        assert_eq!(content_matches(&body, stored), 1, "{stored:?} matches itself");
        assert_eq!(
            content_matches(&body, asked),
            0,
            "folded case: {stored:?} matched {asked:?}"
        );
        let other = request(&json_string(asked));
        assert_eq!(
            content_matches(&other, stored),
            0,
            "folded case: {asked:?} matched {stored:?}"
        );
    }
}

#[test]
fn module_text_keeps_every_locale_byte_for_byte() {
    for (locale, sample) in CORPUS {
        let text = ModuleText::new(sample).unwrap();
        assert_eq!(
            text.as_str().as_bytes(),
            sample.as_bytes(),
            "{locale}: byte differences in module text"
        );
    }
}

#[test]
fn module_text_refuses_explicit_bidi_controls() {
    for c in [
        '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    ] {
        assert!(is_explicit_bidi(c));
        let text = format!("ok {c}evil");
        assert_eq!(
            ModuleText::new(text),
            Err(TextError::Bidi),
            "explicit bidi accepted: U+{:04X}",
            u32::from(c)
        );
    }
    for c in ['\u{200E}', '\u{200F}', '\u{61C}'] {
        assert!(!is_explicit_bidi(c));
        assert!(
            ModuleText::new(format!("نص{c}")).is_ok(),
            "an implicit mark is refused: U+{:04X}",
            u32::from(c)
        );
    }
}

#[test]
fn state_restores_every_locale_byte_for_byte() {
    let all: String = CORPUS.iter().map(|(_, sample)| *sample).collect();
    let mut state = ModuleState::new(64 * 1024);
    for (_, sample) in CORPUS {
        state.append(sample.as_bytes()).unwrap();
    }
    assert_eq!(state.as_bytes(), all.as_bytes());
    let checkpoint = state.as_bytes().to_vec();
    let restored = ModuleState::restore(state.limit(), checkpoint).unwrap();
    assert_eq!(restored.as_bytes(), all.as_bytes(), "byte differences after restore");
    assert_eq!(restored, state);
}

#[test]
fn codes_are_locale_free_keys() {
    for word in ["ışık", "straße", "élève", "año", "perché", "مرحبا", "İ_x"] {
        assert!(Code::new(word).is_err(), "{word}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn any_text_crosses_the_view_byte_for_byte(s in any::<String>()) {
        let out = through_the_view(&request(&json_string(&s)));
        prop_assert_eq!(out.as_bytes(), s.as_bytes());
    }

    #[test]
    fn any_module_text_is_kept_or_refused_whole(s in any::<String>()) {
        match ModuleText::new(s.clone()) {
            Ok(text) => {
                prop_assert_eq!(text.as_str().as_bytes(), s.as_bytes());
                let refused = |c: char| {
                    (c.is_control() && !matches!(c, '\n' | '\r' | '\t')) || is_explicit_bidi(c) || is_tag(c)
                };
                prop_assert!(!s.chars().any(refused), "accepted text holds a refused character");
                prop_assert!(!has_variation_run(&s), "accepted text holds a variation run");
            }
            Err(TextError::Control) => prop_assert!(s.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))),
            Err(TextError::Tag) => prop_assert!(s.chars().any(is_tag)),
            Err(TextError::VariationRun) => prop_assert!(has_variation_run(&s)),
            Err(TextError::Bidi) => prop_assert!(s.chars().any(is_explicit_bidi)),
            Err(other) => prop_assert!(false, "unexpected refusal {other:?}"),
        }
    }
}

#[test]
fn keys_never_fold_case() {
    let body = r#"{"Straße":1,"İstanbul":2,"ı":3}"#;
    let tape = parse(body.as_bytes(), &Limits::DEFAULT).unwrap();
    let none = Mask::new();
    let view = StructuralView::new(&tape, &none);
    let found = |key: &str| {
        Selector::new(vec![Step::Key(key.into())])
            .unwrap()
            .resolve(&view)
            .unwrap()
            .len()
    };
    for (stored, asked) in [
        ("Straße", "strasse"),
        ("Straße", "STRASSE"),
        ("İstanbul", "istanbul"),
        ("ı", "i"),
        ("ı", "I"),
    ] {
        assert_eq!(found(stored), 1, "{stored:?} matches itself");
        assert_eq!(found(asked), 0, "folded case: key {stored:?} matched {asked:?}");
    }
}

#[test]
fn module_text_takes_crlf_and_refuses_tag_characters() {
    assert!(ModuleText::new("line one\r\nline two").is_ok(), "CRLF text was refused");
    for c in ['\u{E0000}', '\u{E0041}', '\u{E007F}'] {
        assert!(is_tag(c));
        assert_eq!(
            ModuleText::new(format!("hi{c}")),
            Err(TextError::Tag),
            "a tag character was accepted"
        );
    }
}

/// One variation selector after a base character selects a glyph; a run of them, or one with no
/// base, is refused.
#[test]
fn module_text_refuses_variation_runs() {
    for ok in [
        "\u{2764}\u{FE0F}",
        "\u{6F22}\u{E0100}",
        "1\u{FE0F}\u{20E3}",
        "\u{1820}\u{180B}",
    ] {
        assert!(ModuleText::new(ok).is_ok(), "{ok:?}");
    }
    for run in [
        "a\u{FE0F}\u{FE0F}",
        "\u{FE0F}x",
        "a\u{E0100}\u{E0101}",
        // The Mongolian free variation selectors.
        "\u{1820}\u{180B}\u{180C}",
        "\u{180F}x",
    ] {
        assert_eq!(
            ModuleText::new(run),
            Err(TextError::VariationRun),
            "a variation-selector run was accepted"
        );
    }
}

/// Unicode 16.0 `Default_Ignorable_Code_Point`, as inclusive ranges. Source:
/// `https://www.unicode.org/Public/16.0.0/ucd/DerivedCoreProperties.txt`; re-derive from it when
/// Unicode is bumped, not from `decl.rs`.
const IGNORABLE: &[(u32, u32)] = &[
    (0xAD, 0xAD),
    (0x34F, 0x34F),
    (0x61C, 0x61C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
];

/// Unicode 16.0 `Unified_Ideograph`, as inclusive ranges. Source:
/// `https://www.unicode.org/Public/16.0.0/ucd/PropList.txt`.
const IDEOGRAPHS: &[(u32, u32)] = &[
    (0x3400, 0x4DBF),
    (0x4E00, 0x9FFF),
    (0xFA0E, 0xFA0F),
    (0xFA11, 0xFA11),
    (0xFA13, 0xFA14),
    (0xFA1F, 0xFA1F),
    (0xFA21, 0xFA21),
    (0xFA23, 0xFA24),
    (0xFA27, 0xFA29),
    (0x20000, 0x2A6DF),
    (0x2A700, 0x2B739),
    (0x2B740, 0x2B81D),
    (0x2B820, 0x2CEA1),
    (0x2CEB0, 0x2EBE0),
    (0x2EBF0, 0x2EE5D),
    (0x30000, 0x3134A),
    (0x31350, 0x323AF),
];

fn within(c: char, ranges: &[(u32, u32)]) -> bool {
    ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&u32::from(c)))
}

/// The contract's rule, read by pairs: every variation selector needs the character just before
/// it to be a visible base, and an ideographic one (U+E0100 to U+E01EF) a CJK ideograph.
fn has_variation_run(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    chars.iter().enumerate().any(|(i, c)| {
        if !is_variation_selector(*c) {
            return false;
        }
        let Some(before) = i.checked_sub(1).map(|j| chars[j]) else {
            return true;
        };
        let visible = !before.is_whitespace() && !before.is_control() && !within(before, IGNORABLE);
        let ideographic = u32::from(*c) >= 0xE0100;
        !visible || (ideographic && !within(before, IDEOGRAPHS))
    })
}

#[test]
fn module_text_needs_a_visible_base() {
    // Whitespace, a control and a default-ignorable code point are no base, and an ideographic
    // selector follows a CJK ideograph only.
    for good in [
        "\u{2764}\u{FE0F}",
        "a\u{FE0E}",
        "\u{845B}\u{E0100}",
        "\u{3400}\u{E01EF}",
        "\u{20000}\u{E0101}",
    ] {
        assert!(ModuleText::new(good).is_ok(), "{good:?}");
    }
    for bad in [
        " \u{FE0F}",
        "\t\u{FE0F}",
        "\u{200B}\u{FE0F}",
        "\u{AD}\u{FE0F}",
        "\u{3164}\u{FE0F}",
        "a\u{E0100}",
        "\u{2764}\u{E0100}",
        "\u{845B}\u{FE0F}\u{FE0F}",
    ] {
        assert_eq!(
            ModuleText::new(bad),
            Err(TextError::VariationRun),
            "a variation selector without a visible base passed: {bad:?}"
        );
    }
}
