// SPDX-License-Identifier: Apache-2.0

//! A copy of `Fingerprint` in `tape.rs`, for the bench, which cannot reach the crate's private
//! fingerprint and includes this file. The crate compiles it into its unit tests only, and holds it
//! to the real one (`the_bench_copy_is_the_fingerprint`), so a drift fails a test instead of
//! turning the bench's crafted rows into a second control. A `#[path]` module is allowed only where
//! `clippy::disallowed_methods` may be (arch.toml `[allow_audit]`).

const SEED: u64 = 0x9E37_79B9_7F4A_7C15;
const MULTIPLIER: u64 = 0x517C_C1B7_2722_0A95;
const FMIX_FIRST: u64 = 0xFF51_AFD7_ED55_8CCD;
const FMIX_SECOND: u64 = 0xC4CE_B9FE_1A85_EC53;

fn mix(hash: u64, word: u64) -> u64 {
    let mixed = (hash ^ word).wrapping_mul(MULTIPLIER);
    mixed ^ (mixed >> 29)
}

/// The fingerprint of a key's decoded bytes.
pub(crate) fn of(bytes: &[u8]) -> u32 {
    let mut hash = SEED;
    let (words, rest) = bytes.as_chunks::<8>();
    for &word in words {
        hash = mix(hash, u64::from_le_bytes(word));
    }
    if !rest.is_empty() {
        let mut word = [0_u8; 8];
        if let Some(head) = word.get_mut(..rest.len()) {
            head.copy_from_slice(rest);
        }
        hash = mix(hash, u64::from_le_bytes(word));
    }
    let mut k = hash ^ u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    k ^= k >> 33;
    k = k.wrapping_mul(FMIX_FIRST);
    k ^= k >> 33;
    k = k.wrapping_mul(FMIX_SECOND);
    k ^= k >> 33;
    u32::try_from(k >> 32).unwrap_or(0)
}

/// The inverse modulo 2^64 of an odd number, by Newton's iteration.
fn inverse(odd: u64) -> u64 {
    let mut x = odd;
    for _ in 0..6 {
        x = x.wrapping_mul(2_u64.wrapping_sub(odd.wrapping_mul(x)));
    }
    x
}

/// `count` distinct 8-byte suffixes, every byte below 0x80, that give `prefix` + suffix the
/// fingerprint `target`: the fingerprint run backwards, as the first review crafted them. Every
/// inversion step is a bijection, so distinct low halves give distinct suffixes.
pub(crate) fn colliding_suffixes(prefix: &[u8], target: u32, count: usize) -> Vec<[u8; 8]> {
    assert!(prefix.len().is_multiple_of(8), "the prefix must be whole words");
    let mut state = SEED;
    for &word in prefix.as_chunks::<8>().0 {
        state = mix(state, u64::from_le_bytes(word));
    }
    let len = u64::try_from(prefix.len() + 8).unwrap_or(u64::MAX);
    let (unmultiply, unfirst, unsecond) = (inverse(MULTIPLIER), inverse(FMIX_FIRST), inverse(FMIX_SECOND));
    let mut found = Vec::with_capacity(count);
    for low in 0_u64.. {
        let mut k = (u64::from(target) << 32) | low;
        k ^= k >> 33;
        k = k.wrapping_mul(unsecond);
        k ^= k >> 33;
        k = k.wrapping_mul(unfirst);
        k ^= k >> 33;
        let folded = k ^ len;
        let mixed = folded ^ (folded >> 29) ^ (folded >> 58);
        let word = (mixed.wrapping_mul(unmultiply) ^ state).to_le_bytes();
        if word.iter().all(|&b| b < 0x80) {
            found.push(word);
            if found.len() == count {
                break;
            }
        }
    }
    found
}
