// SPDX-License-Identifier: Apache-2.0

//! Wire-safe unsigned 64-bit integers.
//!
//! JSON numbers are IEEE doubles for many consumers (JavaScript, `jq`, most JSON Schema
//! validators), so a `u64` above 2^53 silently loses precision. Every 64-bit counter is therefore
//! serialized as a canonical decimal string: no sign, no leading zeros (except `"0"`), digits only.
//! Deserialization accepts only that form, so there is exactly one encoding per value.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Error returned when a wire integer is not in canonical decimal form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expected a canonical decimal string (digits only, no leading zeros) that fits in 64 bits")]
pub struct WireIntError;

/// Parses a canonical unsigned decimal string.
///
/// # Errors
/// Returns [`WireIntError`] for empty input, non-digits, leading zeros, or overflow.
pub fn parse_canonical_u64(s: &str) -> Result<u64, WireIntError> {
    let bytes = s.as_bytes();
    let canonical = match bytes {
        [b'0'] => true,
        [] | [b'0', ..] => false,
        _ => bytes.iter().all(u8::is_ascii_digit),
    };
    if !canonical {
        return Err(WireIntError);
    }
    s.parse::<u64>().map_err(|_| WireIntError)
}

/// Parses a canonical signed decimal string (`-` allowed, no `+`, no `-0`).
///
/// # Errors
/// Returns [`WireIntError`] for non-canonical input or overflow.
pub fn parse_canonical_i64(s: &str) -> Result<i64, WireIntError> {
    let (negative, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    if negative && digits == "0" {
        return Err(WireIntError);
    }
    // Validate the digit form with the unsigned rules; the range check happens in `parse`.
    match digits.as_bytes() {
        [b'0'] => {}
        [] | [b'0', ..] => return Err(WireIntError),
        d if d.iter().all(u8::is_ascii_digit) => {}
        _ => return Err(WireIntError),
    }
    s.parse::<i64>().map_err(|_| WireIntError)
}

macro_rules! wire_u64 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(pub u64);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = WireIntError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_canonical_u64(s).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = Cow::<'de, str>::deserialize(deserializer)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "pattern": "^(0|[1-9][0-9]{0,19})$",
                    "description": "Unsigned 64-bit integer as a canonical decimal string."
                })
            }
        }
    };
}

wire_u64! {
    /// Position of an event in its journal. Strictly increasing by one, starting at 0.
    Seq
}

wire_u64! {
    /// Revocation epoch of a credential. Bumping it invalidates every descendant issued under the
    /// previous value.
    Epoch
}

wire_u64! {
    /// Installation-wide count of revocations and epoch bumps (restore guard). Also kept in the OS
    /// keychain; a journal behind the keychain predates a revocation.
    RevocationSeq
}

wire_u64! {
    /// Monotonic clock reading in nanoseconds since an arbitrary per-process origin.
    /// Never compared across processes; used to order and time events within one run.
    MonoNanos
}

wire_u64! {
    /// Version of the immutable configuration snapshot an Operation was evaluated against.
    ConfigVersion
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rejects_non_canonical_forms() {
        for bad in ["", "01", "+1", " 1", "1 ", "-1", "1e3", "18446744073709551616"] {
            assert!(parse_canonical_u64(bad).is_err(), "accepted {bad:?}");
        }
        for bad in ["", "-0", "+1", "-01", "00", "9223372036854775808"] {
            assert!(parse_canonical_i64(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn json_numbers_are_rejected() {
        assert!(serde_json::from_str::<Seq>("5").is_err());
        assert_eq!(serde_json::from_str::<Seq>("\"5\"").ok(), Some(Seq(5)));
    }

    proptest! {
        #[test]
        fn u64_round_trips_exactly(n in any::<u64>()) {
            let json = serde_json::to_string(&Seq(n)).unwrap();
            prop_assert_eq!(serde_json::from_str::<Seq>(&json).unwrap(), Seq(n));
        }

        #[test]
        fn i64_round_trips_exactly(n in any::<i64>()) {
            prop_assert_eq!(parse_canonical_i64(&n.to_string()), Ok(n));
        }
    }
}
