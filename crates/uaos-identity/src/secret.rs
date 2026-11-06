// SPDX-License-Identifier: Apache-2.0

//! The credential secret and its text form.
//!
//! `uaos_sk_` + 52 characters of Crockford base32 (32 random bytes) + 7 characters encoding a
//! CRC-32 of those bytes: 67 characters in total. The fixed prefix gives secret scanners a format
//! to match (UAOS's own redaction class arrives with detector set v2). The checksum lets them
//! reject look-alikes without a lookup. Parsing is strict: only the canonical upper-case alphabet
//! is accepted, so one secret has exactly one text form.

use std::fmt;

use uaos_platform::{PlatformError, Rng};
use zeroize::Zeroizing;

/// The fixed prefix of every UAOS credential.
pub const PREFIX: &str = "uaos_sk_";
/// Length of a credential's text form.
pub const TEXT_LEN: usize = PREFIX.len() + BODY_CHARS + CHECK_CHARS;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const SECRET_BYTES: usize = 32;
const BODY_CHARS: usize = 52;
const CHECK_CHARS: usize = 7;
const CRC32_POLY: u32 = 0xEDB8_8320;

/// Why a presented credential is not well formed. Deliberately says nothing about the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a well-formed UAOS credential")]
pub struct MalformedCredential;

/// A credential secret. Never printed; zeroized on drop.
pub struct Secret(Zeroizing<[u8; SECRET_BYTES]>);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl Secret {
    /// Draws a new secret from `rng`.
    ///
    /// # Errors
    /// Propagates randomness failures; never substitutes weaker randomness.
    pub fn generate(rng: &dyn Rng) -> Result<Self, PlatformError> {
        let mut bytes = Zeroizing::new([0u8; SECRET_BYTES]);
        rng.fill(bytes.as_mut())?;
        Ok(Self(bytes))
    }

    /// The text form handed to the holder, once.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::with_capacity(TEXT_LEN));
        text.push_str(PREFIX);
        push_base32(&mut text, self.0.as_ref());
        push_base32(&mut text, &crc32(self.0.as_ref()).to_be_bytes());
        text
    }

    /// Parses a presented credential.
    ///
    /// # Errors
    /// [`MalformedCredential`] if the prefix, length, alphabet, padding bits or checksum is wrong.
    pub fn parse(text: &str) -> Result<Self, MalformedCredential> {
        let rest = text.strip_prefix(PREFIX).ok_or(MalformedCredential)?;
        if text.len() != TEXT_LEN {
            return Err(MalformedCredential);
        }
        let (body, check) = rest.split_at_checked(BODY_CHARS).ok_or(MalformedCredential)?;
        let mut bytes = Zeroizing::new([0u8; SECRET_BYTES]);
        decode_base32(body, bytes.as_mut())?;
        let mut sum = [0u8; 4];
        decode_base32(check, &mut sum)?;
        if u32::from_be_bytes(sum) == crc32(bytes.as_ref()) {
            Ok(Self(bytes))
        } else {
            Err(MalformedCredential)
        }
    }

    /// The raw secret bytes, for keyed digesting.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Appends `bytes` as Crockford base32, most significant bit first, zero-padding the last
/// character.
fn push_base32(out: &mut String, bytes: &[u8]) {
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let symbol = |value: u64| {
        let index = usize::try_from(value & 0x1f).unwrap_or(0);
        char::from(ALPHABET.get(index).copied().unwrap_or(b'0'))
    };
    for &b in bytes {
        acc = (acc << 8) | u64::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(symbol(acc >> bits));
        }
        acc &= (1u64 << bits) - 1;
    }
    if bits > 0 {
        out.push(symbol(acc << (5 - bits)));
    }
}

/// Decodes exactly `out.len()` bytes from `text`; the padding bits must be zero.
fn decode_base32(text: &str, out: &mut [u8]) -> Result<(), MalformedCredential> {
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let mut written = 0usize;
    for c in text.bytes() {
        let value = ALPHABET.iter().position(|&a| a == c).ok_or(MalformedCredential)?;
        acc = (acc << 5) | u64::try_from(value).map_err(|_| MalformedCredential)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let byte = u8::try_from((acc >> bits) & 0xff).map_err(|_| MalformedCredential)?;
            *out.get_mut(written).ok_or(MalformedCredential)? = byte;
            written += 1;
            acc &= (1u64 << bits) - 1;
        }
    }
    if written == out.len() && acc == 0 && bits < 5 {
        Ok(())
    } else {
        Err(MalformedCredential)
    }
}

/// CRC-32 (IEEE 802.3, reflected), bitwise. Short inputs only; speed is irrelevant here.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (CRC32_POLY & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use uaos_platform::sim::SimRng;

    use super::*;

    #[test]
    fn crc32_matches_the_reference_check_value() {
        // The standard CRC-32 check value for the ASCII digits "123456789".
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn text_form_has_the_documented_shape() {
        let secret = Secret::generate(&SimRng::new(1)).unwrap();
        let text = secret.encode();
        assert_eq!(text.len(), TEXT_LEN);
        assert_eq!(TEXT_LEN, 67);
        assert!(text.starts_with(PREFIX));
        assert!(text[PREFIX.len()..].bytes().all(|b| ALPHABET.contains(&b)));
        assert_eq!(format!("{secret:?}"), "Secret(..)");
    }

    proptest! {
        #[test]
        fn round_trip(seed in any::<u64>()) {
            let secret = Secret::generate(&SimRng::new(seed)).unwrap();
            let parsed = Secret::parse(&secret.encode()).unwrap();
            prop_assert_eq!(parsed.as_bytes(), secret.as_bytes());
        }

        #[test]
        fn any_single_character_change_is_rejected(seed in any::<u64>(), at in 0..TEXT_LEN, with in 0usize..32) {
            let text = Secret::generate(&SimRng::new(seed)).unwrap().encode();
            let mut changed: Vec<u8> = text.as_bytes().to_vec();
            let replacement = if at < PREFIX.len() { b'x' } else { ALPHABET[with] };
            prop_assume!(changed[at] != replacement);
            changed[at] = replacement;
            let changed = String::from_utf8(changed).unwrap();
            prop_assert!(Secret::parse(&changed).is_err());
        }

        #[test]
        fn arbitrary_strings_never_parse_by_accident(body in "[0-9A-HJKMNP-TV-Z]{59}") {
            // Random strings in the right alphabet pass only if the checksum happens to match:
            // about 1 in 2^32, so a failure here means the checksum is not checked.
            let candidate = format!("{PREFIX}{body}");
            prop_assert!(Secret::parse(&candidate).is_err());
        }
    }

    #[test]
    fn lower_case_and_wrong_lengths_are_rejected() {
        let text = Secret::generate(&SimRng::new(3)).unwrap().encode();
        assert!(Secret::parse(&text.to_lowercase()).is_err());
        assert!(Secret::parse(&text[..TEXT_LEN - 1]).is_err());
        assert!(Secret::parse(&format!("{}0", text.as_str())).is_err());
        assert!(Secret::parse("").is_err());
    }
}
