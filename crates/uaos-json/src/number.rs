// SPDX-License-Identifier: Apache-2.0

//! Integer readers with explicit range checks. The tape never converts a number; a field the kernel
//! must read as an integer (`max_tokens`, say) goes through these. A fraction, an exponent, `-0` or
//! a value out of range is `None`, never rounded or clamped.

/// The unsigned integer `number` spells (`0` or `[1-9][0-9]*`), if it fits in a `u64`.
#[must_use]
pub fn parse_u64(number: &str) -> Option<u64> {
    let digits = integer_digits(number)?;
    digits.iter().try_fold(0_u64, |value, &digit| {
        value.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
    })
}

/// The integer `number` spells (`-?(0|[1-9][0-9]*)`, but not `-0`), if it fits in an `i64`.
#[must_use]
pub fn parse_i64(number: &str) -> Option<i64> {
    let (negative, rest) = match number.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, number),
    };
    let digits = integer_digits(rest)?;
    if negative && digits == b"0" {
        return None;
    }
    // Accumulate on the negative side, which reaches `i64::MIN`.
    let magnitude = digits.iter().try_fold(0_i64, |value, &digit| {
        value.checked_mul(10)?.checked_sub(i64::from(digit - b'0'))
    })?;
    if negative {
        Some(magnitude)
    } else {
        magnitude.checked_neg()
    }
}

/// The bytes of `text` when it is exactly `0` or `[1-9][0-9]*`.
fn integer_digits(text: &str) -> Option<&[u8]> {
    match text.as_bytes() {
        [b'0'] => Some(b"0"),
        bytes @ [b'1'..=b'9', rest @ ..] if rest.iter().all(u8::is_ascii_digit) => Some(bytes),
        _ => None,
    }
}
