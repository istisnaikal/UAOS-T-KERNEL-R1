// SPDX-License-Identifier: Apache-2.0

//! Property fuzzing: arbitrary bytes and mutated documents. Nothing panics; every tape that parses
//! passes its invariants and decodes everywhere; every error points inside the input. Not
//! coverage-guided: that is the nightly cargo-fuzz lane. Merges run 256 cases from a fixed seed;
//! nightly raises `PROPTEST_CASES` and seeds `PROPTEST_RNG_SEED` from the run.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

mod common;

use common::{TOKENS, check_tape, config, document, mutate, mutation, parse};
use proptest::prelude::*;

fn holds(bytes: &[u8]) -> Result<(), TestCaseError> {
    match parse(bytes) {
        Ok(tape) => check_tape(&tape).map_err(TestCaseError::fail),
        Err(e) => {
            prop_assert!(
                usize::try_from(e.offset()).unwrap() <= bytes.len(),
                "error offset {} beyond the input ({} bytes)",
                e.offset(),
                bytes.len()
            );
            Ok(())
        }
    }
}

/// Bytes drawn mostly from JSON's own alphabet, so the parser gets past the first byte.
fn json_ish() -> impl Strategy<Value = Vec<u8>> {
    let byte = prop_oneof![
        prop::sample::select(b"{}[]:,\"\\ \t\n0123456789-+.eEtrufalsn".to_vec()),
        any::<u8>(),
    ];
    prop::collection::vec(byte, 0..512)
}

proptest! {
    #![proptest_config(config(256))]

    #[test]
    fn arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        holds(&bytes)?;
    }

    #[test]
    fn json_alphabet(bytes in json_ish()) {
        holds(&bytes)?;
    }

    #[test]
    fn mutated_documents(
        (_, _, text) in document(),
        mutations in prop::collection::vec(mutation(), 1..8),
    ) {
        holds(&mutate(&text, &mutations))?;
    }

    #[test]
    fn tokens_spliced_anywhere(
        (_, _, text) in document(),
        token in prop::sample::select(TOKENS),
        at in any::<usize>(),
    ) {
        let mut bytes = text.into_bytes();
        let at = at % (bytes.len() + 1);
        bytes.splice(at..at, token.iter().copied());
        holds(&bytes)?;
    }
}
