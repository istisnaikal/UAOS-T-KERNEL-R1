// SPDX-License-Identifier: Apache-2.0

//! The adversarial, each with its asserted outcome. The bench (`benches/tape.rs`) times the same
//! shapes; here only the outcome counts. Keys crafted to share one fingerprint are covered by a
//! unit test in `src/tape.rs`, which can reach the fingerprint.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::fmt::Write as _;

use uaos_json::{ErrorKind, Limits, parse};

/// Just under the 32 MiB default, as the bench builds them.
const NEAR_LIMIT: usize = 32 * 1024 * 1024 - 16;

fn outcome(input: &[u8]) -> Result<u32, ErrorKind> {
    parse(input, &Limits::DEFAULT)
        .map(|tape| tape.stats().nodes)
        .map_err(|e| e.kind())
}

#[test]
fn zeros_to_the_size_limit_are_refused_at_the_node_limit() {
    let mut zeros = String::with_capacity(NEAR_LIMIT);
    zeros.push('[');
    while zeros.len() < NEAR_LIMIT {
        zeros.push_str("0,");
    }
    zeros.push_str("0]");
    assert_eq!(outcome(zeros.as_bytes()), Err(ErrorKind::TooManyNodes));
}

#[test]
fn a_million_members_are_accepted() {
    let mut wide = String::from("{");
    for i in 0..1_000_000 {
        write!(wide, "\"k{i}\":0,").unwrap();
    }
    wide.push_str("\"end\":0}");
    assert_eq!(outcome(wide.as_bytes()), Ok(1_000_002));
}

#[test]
fn keys_sharing_a_long_prefix_are_accepted() {
    let prefix = "p".repeat(4096);
    let mut shared = String::from("{");
    for i in 0..4000 {
        write!(shared, "\"{prefix}{i}\":0,").unwrap();
    }
    shared.push_str("\"end\":0}");
    assert_eq!(outcome(shared.as_bytes()), Ok(4_002));
}

#[test]
fn deep_nesting_is_refused_at_the_depth_limit() {
    let deep = "[".repeat(129) + &"]".repeat(129);
    assert_eq!(outcome(deep.as_bytes()), Err(ErrorKind::DepthExceeded));
}

#[test]
fn scalars_to_the_size_limit_are_accepted_as_one_node() {
    let escapes = format!("\"{}\"", "\\n".repeat(NEAR_LIMIT / 2 - 2));
    assert_eq!(outcome(escapes.as_bytes()), Ok(1), "a string of escapes");
    drop(escapes);
    let number = "9".repeat(NEAR_LIMIT);
    assert_eq!(outcome(number.as_bytes()), Ok(1), "number text");
    drop(number);
    let blank = format!("{}0", " ".repeat(NEAR_LIMIT - 1));
    assert_eq!(outcome(blank.as_bytes()), Ok(1), "whitespace");
}
