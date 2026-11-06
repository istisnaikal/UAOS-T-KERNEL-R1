// SPDX-License-Identifier: Apache-2.0

//! Arbitrary bytes into the tape. Nothing may panic; a tape that parses must pass every invariant,
//! decode every key and string with and without the offset map, and hold no more heap than its
//! bound; an error must point inside the input.
//!
//! The memory bound is asserted here, per input, because the process's resident size cannot show
//! it: AddressSanitizer's quarantine and libFuzzer's own tables live in the same process.

#![no_main]

use libfuzzer_sys::fuzz_target;
use uaos_json::{Limits, parse};

fuzz_target!(|data: &[u8]| {
    match parse(data, &Limits::DEFAULT) {
        Ok(tape) => {
            if let Err(violation) = tape.verify() {
                panic!("{violation}");
            }
            // 24 bytes per node of capacity: the first reserve, or at most twice the nodes held.
            let stats = tape.stats();
            let nodes = usize::try_from(stats.nodes).unwrap_or(usize::MAX);
            let first = (data.len() / 128 + 1).next_power_of_two().max(16);
            let bound = 24 * first.max(2 * nodes);
            assert!(
                stats.heap_bytes <= bound,
                "tape heap {} over its bound {bound}",
                stats.heap_bytes
            );
            for node in tape.nodes() {
                if let Err(e) = node.key() {
                    panic!("a key on a tape does not decode: {e}");
                }
                if let Err(e) = node.str_value() {
                    panic!("a string on a tape does not decode: {e}");
                }
                if let Err(e) = node.str_value_mapped() {
                    panic!("a string on a tape does not decode with its map: {e}");
                }
            }
        }
        Err(e) => {
            let offset = usize::try_from(e.offset()).unwrap_or(usize::MAX);
            assert!(
                offset <= data.len(),
                "error offset {offset} beyond {} bytes",
                data.len()
            );
        }
    }
});
