// SPDX-License-Identifier: Apache-2.0

//! The tape against an independent oracle: `serde_json`, read strictly (the whole input, no
//! repeated key). On every input both must accept or both refuse; on accepted input every kind,
//! string, key and number must agree, and every node's span must re-read as the oracle's subtree.
//! The one known divergence, numbers outside the f64 range, is counted and must stay the only one.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

mod common;

use common::{Oracle, compare, config, document, mutate, mutation, oracle, parse};
use proptest::prelude::*;

/// Escapes written as `~u`, so the source never spells one (see grammar.rs).
fn j(text: &str) -> Vec<u8> {
    text.replace("~u", "\\u").into_bytes()
}

/// How one input came out on both sides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// Both accept, and every value agrees.
    Accepted,
    /// Both refuse.
    Refused,
    /// A number outside the f64 range: the known divergence.
    OutOfRange,
}

/// The verdicts on one input agree, or the input is the known divergence.
fn verdict(bytes: &[u8]) -> Result<Verdict, String> {
    let tape = parse(bytes);
    match (&tape, oracle(bytes)) {
        (Ok(tape), Oracle::Accepted(value)) => {
            compare(tape.root(), &value).map_err(|e| format!("tape differs from serde_json: {e}"))?;
            for node in tape.nodes() {
                let reread: serde_json::Value = serde_json::from_str(node.raw())
                    .map_err(|e| format!("span differs from serde_json at {:?}: {e}", node.span()))?;
                compare(node, &reread).map_err(|e| format!("subtree differs from serde_json: {e}"))?;
            }
            Ok(Verdict::Accepted)
        }
        // Out-of-range numbers: the tape keeps them as text. If the tape refused, it found a
        // rule broken that serde_json, stopping at the number, did not reach.
        (Err(_), Oracle::Rejected(_) | Oracle::NumberOutOfRange) => Ok(Verdict::Refused),
        (Ok(_), Oracle::NumberOutOfRange) => Ok(Verdict::OutOfRange),
        (Ok(_), Oracle::Rejected(why)) => Err(format!(
            "tape accepts what serde_json refuses ({why}): {}",
            String::from_utf8_lossy(bytes)
        )),
        (Err(e), Oracle::Accepted(_)) => Err(format!(
            "tape refuses what serde_json accepts ({e}): {}",
            String::from_utf8_lossy(bytes)
        )),
    }
}

/// Edge cases, each on its own: the escapes and forms the generator might rarely reach.
#[test]
fn edge_cases_agree() {
    let cases = [
        r#"{"a/b":"c\/d"}"#,
        r#"["\"","\\","\/","\b","\f","\n","\r","\t"]"#,
        r#"["~u0000","~u001f","~u007f","~u00e9","~u00E9","~u2028","~uffff","~ufeff"]"#,
        r#"["~ud83d~ude00","~udbff~udfff","~ud800~udc00"]"#,
        r#"{"":0,"~u0000":1," ":2}"#,
        "[0,-0,0.0,-0.0,1e0,1E+0,1e-0,123456789012345678,-123456789012345678]",
        "[18446744073709551615,18446744073709551616,-9223372036854775809]",
        "[1.7976931348623157e308,5e-324,1e-400]",
        "  \r\n\t{ \"a\" : [ 1 , 2 ] , \"b\" : { } }  \n",
        "[[],[[]],{},{\"a\":{}}]",
        r#""é中😀""#,
        "[true,false,null]",
    ];
    for case in cases {
        let bytes = j(case);
        assert_eq!(verdict(&bytes).unwrap(), Verdict::Accepted, "{case}");
    }
    for refused in [
        r#"{"a":1,"~u0061":2}"#,
        r#""~ud800""#,
        "[01]",
        "\u{feff}[]",
        "[1,]",
        "\"\t\"",
        "1 2",
        "",
        "[\"\\x\"]",
    ] {
        let bytes = j(refused);
        assert_eq!(verdict(&bytes).unwrap(), Verdict::Refused, "{refused}");
    }
    // The known divergence, on its own.
    for huge in ["[1E9661]", "-1e400", "1234567890e9999"] {
        assert_eq!(verdict(huge.as_bytes()).unwrap(), Verdict::OutOfRange, "{huge}");
    }
}

proptest! {
    #![proptest_config(config(256))]

    /// Valid documents in every style: both accept, and every value agrees.
    #[test]
    fn generated_documents_agree((_, _, text) in document()) {
        let verdict = verdict(text.as_bytes()).map_err(TestCaseError::fail)?;
        prop_assert_eq!(verdict, Verdict::Accepted, "{}", text);
    }

    /// Broken documents: both refuse, or both accept and agree.
    #[test]
    fn mutated_documents_agree(
        (_, _, text) in document(),
        mutations in prop::collection::vec(mutation(), 1..8),
    ) {
        let bytes = mutate(&text, &mutations);
        verdict(&bytes).map_err(TestCaseError::fail)?;
    }
}

/// The one-off run of the contract: at least 20,000 documents, 0 unexplained disagreements. Ignored
/// on merges; run with `cargo test -p uaos-json --release --test differential -- --ignored`.
#[test]
#[ignore = "long: run on demand and before the pull request leaves draft"]
fn twenty_thousand_documents_agree() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    let mut runner = TestRunner::new(config(20_000));
    let strategy = (document(), prop::collection::vec(mutation(), 0..4));
    let (mut accepted, mut refused, mut out_of_range) = (0_u32, 0_u32, 0_u32);
    for _ in 0..20_000 {
        let ((_, _, text), mutations) = strategy.new_tree(&mut runner).unwrap().current();
        let bytes = mutate(&text, &mutations);
        match verdict(&bytes) {
            Ok(Verdict::Accepted) => accepted += 1,
            Ok(Verdict::Refused) => refused += 1,
            Ok(Verdict::OutOfRange) => out_of_range += 1,
            Err(e) => panic!("{e}"),
        }
    }
    println!(
        "20,000 documents: {accepted} accepted by both, {refused} refused by both, \
         {out_of_range} numbers out of f64 range (tape only), 0 disagreements"
    );
    assert_eq!(accepted + refused + out_of_range, 20_000);
}
