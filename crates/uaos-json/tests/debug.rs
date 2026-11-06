// SPDX-License-Identifier: Apache-2.0

//! No `Debug` or `Display` output carries input bytes: a canary placed in a string, a key and an
//! escaped string never shows, not even a 4-byte window of it.

use uaos_json::{Limits, decode_mapped, parse};

/// Letters no kind, field or type name of the crate contains.
const CANARY: &str = "QXZKWVBNMPLGHJQX";

fn leaks(output: &str) -> Option<&str> {
    CANARY
        .as_bytes()
        .windows(4)
        .filter_map(|w| std::str::from_utf8(w).ok())
        .find(|window| output.contains(window))
}

#[test]
fn debug_output_holds_no_payload() {
    let input = format!(r#"{{"{CANARY}":"{CANARY}","escaped":"\n{CANARY}\t","list":["{CANARY}",{{"k":"{CANARY}"}}]}}"#);
    let tape = parse(input.as_bytes(), &Limits::DEFAULT).unwrap();
    let mut outputs = vec![format!("{tape:?}"), format!("{tape:#?}"), format!("{:?}", tape.stats())];
    for node in tape.nodes() {
        outputs.push(format!("{node:?}"));
        outputs.push(format!("{node:#?}"));
        outputs.push(format!("{:?}", node.children()));
        outputs.push(format!("{:?}", node.descendants()));
        outputs.push(format!("{:?}", node.ancestors()));
        outputs.push(format!("{:?}", node.span()));
        if let Some(mapped) = node.str_value_mapped().unwrap() {
            outputs.push(format!("{mapped:?}"));
            outputs.push(format!("{mapped:#?}"));
        }
    }
    let decoded = decode_mapped("a\\nQXZKWVBNMPLGHJQX").unwrap();
    outputs.push(format!("{decoded:?}"));
    for output in &outputs {
        assert_eq!(leaks(output), None, "payload in Debug output: {output}");
    }
}

#[test]
fn errors_hold_no_payload() {
    let broken = [
        format!(r#"{{"{CANARY}":1,"{CANARY}":2}}"#),
        format!(r#"["{CANARY}" {CANARY}]"#),
        format!("\"{CANARY}\u{1}\""),
        format!(r#"{{"{CANARY}" {CANARY}}}"#),
        format!("[\"{CANARY}\\x\"]"),
    ];
    for input in &broken {
        let error = parse(input.as_bytes(), &Limits::DEFAULT).unwrap_err();
        for output in [format!("{error:?}"), format!("{error}"), format!("{:?}", error.kind())] {
            assert_eq!(leaks(&output), None, "payload in an error: {output}");
        }
    }
}
