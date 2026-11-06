// SPDX-License-Identifier: Apache-2.0

//! Arbitrary text into the string decoder. The decoder and the tape must accept exactly the same
//! string content and decode it alike; the mapped decoder must agree with the plain one and keep
//! its map's rules; whatever decodes must encode back to a string that decodes to it again.

#![no_main]

use libfuzzer_sys::fuzz_target;
use uaos_json::{Limits, decode, decode_mapped, encode_str, parse};

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let plain = decode(content);
    let mapped = decode_mapped(content);
    assert_eq!(plain.is_ok(), mapped.is_ok(), "the mapped decoder disagrees");

    let quoted = format!("\"{content}\"");
    let tape = parse(quoted.as_bytes(), &Limits::DEFAULT);
    assert_eq!(tape.is_ok(), plain.is_ok(), "the decoder and the tape disagree");

    let (Ok(text), Ok(mapped)) = (plain, mapped) else {
        return;
    };
    assert_eq!(mapped.text(), text.as_ref(), "the mapped decoder decodes differently");
    if let Ok(tape) = tape {
        let value = tape.root().str_value().ok().flatten();
        assert_eq!(value.as_deref(), Some(text.as_ref()), "the tape decodes differently");
    }

    // The map: one entry per decoded byte plus the end, never decreasing.
    let len = mapped.text().len();
    assert_eq!(mapped.raw_offset(len), Some(content.len()));
    let mut previous = 0;
    for at in 0..=len {
        let Some(raw) = mapped.raw_offset(at) else {
            panic!("no map entry for decoded byte {at}");
        };
        assert!(raw >= previous && raw <= content.len(), "map entry {at} out of order");
        previous = raw;
    }

    let mut encoded = Vec::new();
    if encode_str(&text, &mut encoded).is_err() {
        return; // refused for memory: nothing was written, nothing to check
    }
    let inner = encoded.get(1..encoded.len().saturating_sub(1)).unwrap_or_default();
    let Ok(inner) = std::str::from_utf8(inner) else {
        panic!("the encoder wrote invalid UTF-8");
    };
    match decode(inner) {
        Ok(again) => assert_eq!(again, text, "encode then decode changed the text"),
        Err(e) => panic!("the encoder wrote content the decoder refuses: {e}"),
    }
});
