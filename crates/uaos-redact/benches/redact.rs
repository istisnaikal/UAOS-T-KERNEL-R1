// SPDX-License-Identifier: Apache-2.0

//! Redaction cost on a long agent session: a ~1.6 MB chat history (about 400k tokens) with secrets
//! sprinkled through it (≤ 25 ms for the whole local pipeline at this size).
//!
//! Run: `cargo bench -p uaos-redact --bench redact`. Prints p50/p99 for redacting the whole body
//! (the worst case: in the pipeline, chunk-digest caching limits this to new content) and for the
//! final scan of the whole redacted body (always paid in full, on every request).
//!
//! Two bodies are measured: prose messages, and the same history with every message carried as
//! a tool call's JSON arguments, so every string has a nested view to decode and scan (the
//! worst case for the nested views).
//! Dependency-free on purpose (`harness = false`).

#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::disallowed_methods,
    reason = "benchmark binary: measures wall time and prints results"
)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use common::{Prng, prose, secret};
use serde_json::{Value, json};
use uaos_platform::crypto::SecretKey;
use uaos_redact::{DataClass, DetectorVersion, FinalScanner, Redactor};

const TARGET_BYTES: usize = 1_600_000;
const ITERATIONS: usize = 60;

fn history(nested: bool) -> Vec<u8> {
    let mut rng = Prng::new(11);
    let mut messages = Vec::new();
    let mut size = 0;
    let mut n = 0_usize;
    while size < TARGET_BYTES {
        let mut text = String::new();
        while text.len() < 800 {
            text.push_str(&prose(&mut rng));
            text.push('\n');
        }
        if n.is_multiple_of(100) {
            let class = DataClass::ALL[(n / 100) % DataClass::ALL.len()];
            let s = secret(&mut rng, class);
            text.push(' ');
            text.push_str(&s.text);
            text.push(' ');
        }
        size += text.len();
        let role = if n.is_multiple_of(2) { "user" } else { "assistant" };
        let content = if nested {
            serde_json::to_string(&json!({ "command": "run", "input": text })).unwrap()
        } else {
            text
        };
        messages.push(json!({ "role": role, "content": content }));
        n += 1;
    }
    serde_json::to_vec(&json!({ "model": "m", "max_tokens": 4096, "messages": Value::Array(messages) })).unwrap()
}

fn percentiles(mut samples: Vec<Duration>) -> (Duration, Duration) {
    samples.sort();
    let at = |q: usize| samples[(samples.len() * q / 100).min(samples.len() - 1)];
    (at(50), at(99))
}

fn measure(name: &str, body: &[u8], redactor: &Redactor, scanner: &FinalScanner) {
    let redacted = redactor.redact_json(body).unwrap();
    let replaced = redacted.replacements().len();
    let output = redacted.into_output().into_owned();
    scanner.check_json(&output).unwrap();

    // The request path parses once and hands redaction the tape, so redaction's own cost is
    // measured without the parse too.
    let tape = uaos_json::parse(body, &uaos_json::Limits::DEFAULT).unwrap();
    let mut redact = Vec::with_capacity(ITERATIONS);
    let mut on_tape = Vec::with_capacity(ITERATIONS);
    let mut scan = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let t = Instant::now();
        let r = redactor.redact_json(body).unwrap();
        redact.push(t.elapsed());
        assert_eq!(r.replacements().len(), replaced);
        let t = Instant::now();
        let r = redactor.redact_tape(&tape).unwrap();
        on_tape.push(t.elapsed());
        assert_eq!(r.replacements().len(), replaced);
        let t = Instant::now();
        scanner.check_json(&output).unwrap();
        scan.push(t.elapsed());
    }
    let (r50, r99) = percentiles(redact);
    let (t50, t99) = percentiles(on_tape);
    let (s50, s99) = percentiles(scan);
    let mb = f64::from(u32::try_from(body.len()).unwrap()) / 1_000_000.0;
    println!("{name}: {mb:.2} MB JSON, {replaced} distinct secrets replaced");
    println!("  redact_json (full body): p50 {r50:?}  p99 {r99:?}");
    println!("  redact_tape (parsed):    p50 {t50:?}  p99 {t99:?}");
    println!("  final scan  (full body): p50 {s50:?}  p99 {s99:?}");
}

fn main() {
    let redactor = Redactor::new(DetectorVersion::V1, SecretKey::from_bytes([1; 32])).unwrap();
    let scanner = FinalScanner::new(DetectorVersion::V1, [b"vault-provider-key-0123456789abcdef".as_slice()]).unwrap();
    measure("prose history", &history(false), &redactor, &scanner);
    measure("tool-call history (nested views)", &history(true), &redactor, &scanner);
}
