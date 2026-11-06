// SPDX-License-Identifier: Apache-2.0

//! The tape's stage cost (decode p95 ≤ 2 ms at 1.7 MB, so at least 0.85 GB/s) and its adversarial
//! rows.
//!
//! Run: `cargo bench -p uaos-json --bench tape`. Prints p50/p95/p99 over 200 parses after 20
//! warm-up runs of a deterministic transcript of about 1.70 MB shaped like an agent session
//! (system blocks, tools, user and assistant turns with text, tool calls and tool results, escapes
//! and non-ASCII), the UTF-8 check alone, throughput and heap, then one timing per adversarial
//! input. Dependency-free on purpose (`harness = false`); nothing here leaves the machine.

#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::disallowed_methods,
    reason = "benchmark binary: measures wall time and prints results"
)]

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use uaos_json::{Limits, parse};

const TARGET_BYTES: usize = 1_700_000;
const WARMUP: usize = 20;
const ITERATIONS: usize = 200;

/// A deterministic PRNG (xorshift64), so every run measures the same body.
struct Prng(u64);

impl Prng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> usize {
        usize::try_from(self.next() % n).unwrap()
    }
}

const WORDS: &[&str] = &[
    "the",
    "file",
    "function",
    "returns",
    "error",
    "test",
    "build",
    "cargo",
    "crate",
    "path",
    "value",
    "config",
    "request",
    "budget",
    "policy",
    "journal",
    "chunk",
    "token",
    "stream",
    "é",
    "naïve",
    "日本語",
    "über",
    "line",
    "struct",
    "impl",
    "match",
    "Result",
    "Option",
    "async",
];

fn prose(rng: &mut Prng, words: usize, out: &mut String) {
    // Escapes as a JSON writer emits them: quotes, backslashes, newlines and tabs, and now and
    // then a unicode escape; `\\u` is spelled at runtime so the source never holds one.
    let unicode = ["\\", "u00e9"].concat();
    for i in 0..words {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(WORDS[rng.below(30)]);
        match rng.below(40) {
            0 => out.push_str("\\n"),
            1 => out.push_str("\\\"quoted\\\""),
            2 => out.push_str("C:\\\\path\\\\to"),
            3 => out.push_str("\\t"),
            4 => out.push_str(&unicode),
            _ => {}
        }
    }
}

/// About `TARGET_BYTES` of a Messages-style request body.
fn transcript() -> String {
    let mut rng = Prng(0x5541_4F53_4A53_0002);
    let mut out = String::with_capacity(TARGET_BYTES + 4096);
    out.push_str(r#"{"model":"model-id","max_tokens":32000,"stream":true,"system":["#);
    for i in 0..3 {
        if i > 0 {
            out.push(',');
        }
        out.push_str(r#"{"type":"text","text":""#);
        prose(&mut rng, 400, &mut out);
        out.push_str(r#""}"#);
    }
    out.push_str(r#"],"tools":["#);
    for i in 0..29 {
        if i > 0 {
            out.push(',');
        }
        write!(out, r#"{{"name":"tool_{i}","description":"#).unwrap();
        out.push('"');
        prose(&mut rng, 60, &mut out);
        out.push_str(
            r#"","input_schema":{"type":"object","properties":{"command":{"type":"string"},"timeout":{"type":"number"}},"required":["command"]}}"#,
        );
    }
    out.push_str(r#"],"messages":["#);
    let mut turn = 0;
    while out.len() < TARGET_BYTES {
        if turn > 0 {
            out.push(',');
        }
        if turn % 2 == 0 {
            out.push_str(r#"{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_"#);
            write!(out, "{turn:08}").unwrap();
            out.push_str(r#"","content":""#);
            let words = 220 + rng.below(400);
            prose(&mut rng, words, &mut out);
            out.push_str(r#""},{"type":"text","text":""#);
            prose(&mut rng, 20, &mut out);
            out.push_str(r#""}]}"#);
        } else {
            out.push_str(r#"{"role":"assistant","content":[{"type":"text","text":""#);
            let words = 40 + rng.below(120);
            prose(&mut rng, words, &mut out);
            out.push_str(r#""},{"type":"tool_use","id":"toolu_"#);
            write!(out, "{turn:08}").unwrap();
            out.push_str(r#"","name":"tool_3","input":{"command":""#);
            prose(&mut rng, 12, &mut out);
            out.push_str(r#"","timeout":120000}}]}"#);
        }
        turn += 1;
    }
    out.push_str("]}");
    out
}

fn percentile(sorted: &[Duration], p: usize) -> Duration {
    sorted[(sorted.len() * p / 100).min(sorted.len() - 1)]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn gb_per_s(bytes: usize, d: Duration) -> f64 {
    f64::from(u32::try_from(bytes).unwrap()) / d.as_secs_f64() / 1e9
}

fn time<T>(runs: usize, mut f: impl FnMut() -> T) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(runs);
    for _ in 0..runs {
        let start = Instant::now();
        let out = f();
        samples.push(start.elapsed());
        std::hint::black_box(out);
    }
    samples.sort();
    samples
}

fn row(label: &str, bytes: usize, samples: &[Duration]) {
    let (p50, p95, p99) = (
        percentile(samples, 50),
        percentile(samples, 95),
        percentile(samples, 99),
    );
    println!(
        "| {label} | {:.2} MB | {:.3} | {:.3} | {:.3} | {:.2} |",
        f64::from(u32::try_from(bytes).unwrap()) / 1e6,
        ms(p50),
        ms(p95),
        ms(p99),
        gb_per_s(bytes, p95)
    );
}

fn adversarial(label: &str, input: &[u8], limits: &Limits) {
    let samples = time(5, || parse(input, limits).map(|tape| tape.stats().nodes));
    let outcome = match parse(input, limits) {
        Ok(tape) => format!(
            "accepted, {} nodes, {} KiB heap",
            tape.stats().nodes,
            tape.stats().heap_bytes / 1024
        ),
        Err(e) => format!("refused: {}", e.kind().code()),
    };
    println!(
        "| {label} | {:.1} MB | {:.1} ms | {outcome} |",
        f64::from(u32::try_from(input.len()).unwrap()) / 1e6,
        ms(percentile(&samples, 50))
    );
}

/// The fingerprint, copied; the crate's unit tests hold the copy to the real one.
#[path = "../src/fingerprint_copy.rs"]
mod fingerprint;

/// An object of keys spelled with every byte escaped: `prefix_len` bytes of `p`, then an 8-byte
/// suffix. `crafted` suffixes all share one fingerprint; otherwise they count up and collide
/// only by chance (the control of the same shape).
fn escaped_keys(prefix_len: usize, count: usize, crafted: bool) -> String {
    let backslash = "\\";
    let prefix = vec![b'p'; prefix_len];
    let suffixes: Vec<[u8; 8]> = if crafted {
        let suffixes = fingerprint::colliding_suffixes(&prefix, 0x5eed_0019, count);
        for suffix in &suffixes {
            let key: Vec<u8> = prefix.iter().chain(suffix.iter()).copied().collect();
            assert_eq!(fingerprint::of(&key), 0x5eed_0019, "the crafted keys do not collide");
        }
        suffixes
    } else {
        (0..u64::try_from(count).unwrap())
            // Base-128 digits: distinct for every count below 2^56, every byte below 0x80.
            .map(|n| std::array::from_fn(|i| u8::try_from((n >> (7 * i)) & 0x7F).unwrap()))
            .collect()
    };
    let mut text = String::from("{");
    for (i, suffix) in suffixes.iter().enumerate() {
        if i > 0 {
            text.push(',');
        }
        text.push('"');
        for &byte in prefix.iter().chain(suffix.iter()) {
            write!(text, "{backslash}u{byte:04x}").unwrap();
        }
        write!(text, "\":{i}").unwrap();
    }
    text.push('}');
    text
}

fn main() {
    let body = transcript();
    let bytes = body.as_bytes();
    let limits = Limits::DEFAULT;
    let tape = parse(bytes, &limits).unwrap();
    let stats = tape.stats();
    println!(
        "Transcript: {} bytes, {} nodes, depth {}, tape heap {} KiB ({} bytes per node)",
        bytes.len(),
        stats.nodes,
        stats.max_depth,
        stats.heap_bytes / 1024,
        24
    );
    drop(tape);

    time(WARMUP, || parse(bytes, &limits).is_ok());
    let parse_samples = time(ITERATIONS, || parse(bytes, &limits).map(|tape| tape.stats().nodes));
    let utf8_samples = time(ITERATIONS, || std::str::from_utf8(bytes).is_ok());
    println!();
    println!("| Stage | Input | p50 ms | p95 ms | p99 ms | GB/s at p95 |");
    println!("|---|---|---|---|---|---|");
    row("parse (whole stage)", bytes.len(), &parse_samples);
    row("UTF-8 check alone", bytes.len(), &utf8_samples);
    let p95 = percentile(&parse_samples, 95);
    println!();
    println!(
        "Budget: parse p95 <= 2 ms at 1.7 MB (>= 0.85 GB/s). Measured p95 {:.3} ms ({:.2} GB/s): {}.",
        ms(p95),
        gb_per_s(bytes.len(), p95),
        if p95 <= Duration::from_millis(2) {
            "within budget"
        } else {
            "OVER BUDGET"
        }
    );

    println!();
    println!("| Adversarial input | Size | p50 | Outcome |");
    println!("|---|---|---|---|");
    let mib32 = 32 * 1024 * 1024 - 16;
    let mut zeros = String::with_capacity(mib32);
    zeros.push('[');
    while zeros.len() < mib32 {
        zeros.push_str("0,");
    }
    zeros.push_str("0]");
    adversarial("`[0,0,…]` to the size limit", zeros.as_bytes(), &limits);
    drop(zeros);

    let mut wide = String::from("{");
    for i in 0..1_000_000 {
        write!(wide, "\"k{i}\":0,").unwrap();
    }
    wide.push_str("\"end\":0}");
    adversarial("one object, 1,000,001 members", wide.as_bytes(), &limits);
    drop(wide);

    let prefix = "p".repeat(4096);
    let mut shared = String::from("{");
    for i in 0..4000 {
        write!(shared, "\"{prefix}{i}\":0,").unwrap();
    }
    shared.push_str("\"end\":0}");
    adversarial("4,001 keys sharing a 4 KiB prefix", shared.as_bytes(), &limits);
    drop(shared);

    let deep = "[".repeat(129) + &"]".repeat(129);
    adversarial("129 levels", deep.as_bytes(), &limits);

    let escapes = format!("\"{}\"", "\\n".repeat(mib32 / 2 - 2));
    adversarial("a string of escapes to the size limit", escapes.as_bytes(), &limits);
    drop(escapes);

    let number = "9".repeat(mib32);
    adversarial("number text to the size limit", number.as_bytes(), &limits);
    drop(number);

    let blank = format!("{}0", " ".repeat(mib32 - 1));
    adversarial("whitespace to the size limit", blank.as_bytes(), &limits);
    drop(blank);

    // Keys crafted offline to share one fingerprint, each against a control of the same shape whose
    // keys do not collide.
    for (prefix, count, shape) in [
        (320, 16_000, "328 escaped bytes each"),
        (40, 100_000, "48 escaped bytes each"),
    ] {
        let crafted = escaped_keys(prefix, count, true);
        adversarial(
            &format!("{count} keys crafted to collide ({shape})"),
            crafted.as_bytes(),
            &limits,
        );
        drop(crafted);
        let control = escaped_keys(prefix, count, false);
        adversarial(&format!("{count} keys, control ({shape})"), control.as_bytes(), &limits);
    }
}
