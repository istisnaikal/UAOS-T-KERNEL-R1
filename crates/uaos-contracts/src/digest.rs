// SPDX-License-Identifier: Apache-2.0

//! Algorithm-tagged digests.
//!
//! Two distinct types, so a chain hash can never be used where a chunk reference is
//! expected, or the other way round:
//!
//! * [`Sha256Digest`] — `sha256:<64 hex>`. Chains journal lines over their exact stored bytes;
//!   verifiable with stock `sha256` tooling.
//! * [`ChunkRef`] — `hmac-sha256:<64 hex>`. Addresses content chunks with a keyed digest
//!   (per-pocket key), so after a pocket key is shredded nobody can confirm guesses about
//!   the removed content, and equal content in different pockets is not linkable.
//!
//! Computing digests is not this crate's job; it only defines their representation.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Error returned when a tagged digest cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expected `{tag}:` followed by 64 lowercase hexadecimal digits")]
pub struct DigestParseError {
    tag: &'static str,
}

fn parse_tagged(s: &str, tag: &'static str) -> Result<[u8; 32], DigestParseError> {
    let err = DigestParseError { tag };
    let hex = s
        .strip_prefix(tag)
        .and_then(|rest| rest.strip_prefix(':'))
        .ok_or_else(|| err.clone())?;
    if hex.len() != 64 {
        return Err(err);
    }
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    let mut out = [0u8; 32];
    for (slot, &[hi, lo]) in out.iter_mut().zip(pairs) {
        let (Some(hi), Some(lo)) = (nibble(hi), nibble(lo)) else {
            return Err(err);
        };
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

fn write_tagged(f: &mut fmt::Formatter<'_>, tag: &str, bytes: &[u8; 32]) -> fmt::Result {
    f.write_str(tag)?;
    f.write_str(":")?;
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

macro_rules! tagged_digest {
    ($(#[$doc:meta])* $name:ident, $tag:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wire tag naming the algorithm.
            pub const TAG: &'static str = $tag;

            /// Wraps raw digest bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the raw digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_tagged(f, $tag, &self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }

        impl FromStr for $name {
            type Err = DigestParseError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_tagged(s, $tag).map(Self)
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
                    "pattern": concat!("^", $tag, ":[0-9a-f]{64}$")
                })
            }
        }
    };
}

tagged_digest! {
    /// SHA-256 digest, used for the journal hash chain.
    Sha256Digest, "sha256"
}

tagged_digest! {
    /// Keyed (HMAC-SHA-256, per-pocket key) reference to an encrypted content chunk.
    ChunkRef, "hmac-sha256"
}

tagged_digest! {
    /// Keyed (HMAC-SHA-256, installation identity key) digest of a credential secret. The secret
    /// itself is never stored or journaled.
    CredentialDigest, "hmac-sha256"
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn round_trip(bytes in any::<[u8; 32]>()) {
            let d = Sha256Digest::from_bytes(bytes);
            prop_assert_eq!(d.to_string().parse::<Sha256Digest>().unwrap(), d);
            let c = ChunkRef::from_bytes(bytes);
            prop_assert_eq!(c.to_string().parse::<ChunkRef>().unwrap(), c);
        }
    }

    #[test]
    fn tags_are_not_interchangeable() {
        let d = Sha256Digest::from_bytes([0xab; 32]).to_string();
        assert!(d.parse::<ChunkRef>().is_err());
        assert!(d.to_uppercase().parse::<Sha256Digest>().is_err());
    }
}
