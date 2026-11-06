// SPDX-License-Identifier: Apache-2.0

//! Typed identifiers.
//!
//! Each entity has its own newtype, so IDs cannot be mixed up at compile time, and its own
//! short prefix, so they cannot be mixed up on the wire or in a log line either.
//!
//! Wire form: `<prefix>_<32 lowercase hex>`, where the hex is a `UUIDv7` (RFC 9562) in simple
//! form. Construction is deterministic: the caller supplies the timestamp and the random
//! bytes (normally via `uaos_platform::IdSource`), which keeps simulation seed-reproducible.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

/// Error returned when a typed identifier cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdParseError {
    /// The prefix does not match the expected entity.
    #[error("expected an identifier starting with `{expected}_`")]
    WrongPrefix {
        /// The prefix this identifier type requires.
        expected: &'static str,
    },
    /// The part after the prefix is not 32 lowercase hexadecimal digits.
    #[error("expected 32 lowercase hexadecimal digits after the prefix")]
    BadHex,
    /// The UUID is well formed but not version 7.
    #[error("identifier is not a UUIDv7")]
    NotV7,
}

/// Behaviour shared by all typed identifiers.
pub trait TypedId: Copy + Eq + Ord + fmt::Debug + fmt::Display + FromStr<Err = IdParseError> {
    /// Wire prefix, for example `ses`.
    const PREFIX: &'static str;

    /// Builds an identifier from a Unix timestamp in milliseconds and 10 random bytes.
    fn from_parts(unix_ms: u64, random: [u8; 10]) -> Self;

    /// Returns the underlying `UUIDv7`.
    fn as_uuid(&self) -> Uuid;
}

/// Parses `<prefix>_<32 lowercase hex>` into a `UUIDv7`.
fn parse_prefixed(s: &str, prefix: &'static str) -> Result<Uuid, IdParseError> {
    let hex = s
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('_'))
        .ok_or(IdParseError::WrongPrefix { expected: prefix })?;
    let well_formed = hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !well_formed {
        return Err(IdParseError::BadHex);
    }
    let uuid = Uuid::try_parse(hex).map_err(|_| IdParseError::BadHex)?;
    if uuid.get_version_num() == 7 {
        Ok(uuid)
    } else {
        Err(IdParseError::NotV7)
    }
}

macro_rules! typed_id {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Uuid);

        impl TypedId for $name {
            const PREFIX: &'static str = $prefix;

            fn from_parts(unix_ms: u64, random: [u8; 10]) -> Self {
                Self(uuid::Builder::from_unix_timestamp_millis(unix_ms, &random).into_uuid())
            }

            fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_{}", $prefix, self.0.simple())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_prefixed(s, $prefix).map(Self)
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
                    "pattern": concat!("^", $prefix, "_[0-9a-f]{12}7[0-9a-f]{3}[89ab][0-9a-f]{15}$")
                })
            }
        }
    };
}

typed_id! {
    /// A durable work thread inside a Pocket.
    SessionId, "ses"
}
typed_id! {
    /// An isolation boundary for data, grants, budget binding and keys.
    PocketId, "pkt"
}
typed_id! {
    /// A unit of side effect: model call, tool call, exec, transfer or config change.
    OperationId, "op"
}
typed_id! {
    /// One HTTP request received from a client.
    RequestId, "req"
}
typed_id! {
    /// Ties together everything caused by one user-visible action.
    CorrelationId, "cor"
}
typed_id! {
    /// An immutable fact in the journal.
    EventId, "evt"
}
typed_id! {
    /// A UAOS-issued scoped key (the identifier, never the secret).
    CredentialId, "cred"
}
typed_id! {
    /// A budget hold created before an Operation executes.
    ReservationId, "rsv"
}
typed_id! {
    /// A budget pool.
    PoolId, "pool"
}
typed_id! {
    /// A time-bounded capability grant.
    GrantId, "grt"
}
typed_id! {
    /// A pending human decision.
    ApprovalId, "apr"
}
typed_id! {
    /// A named journal position that can be restored.
    CheckpointId, "chk"
}
typed_id! {
    /// One agent instance under a credential: a main agent or one of its subagents. Several agents
    /// often share a credential, so the credential alone cannot tell them apart. Filled in by
    /// session inference.
    AgentId, "agt"
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn display_parse_round_trip(ms in 0u64..(1u64 << 48), random in any::<[u8; 10]>()) {
            let id = SessionId::from_parts(ms, random);
            let text = id.to_string();
            prop_assert!(text.starts_with("ses_"));
            prop_assert_eq!(text.len(), 4 + 32);
            prop_assert_eq!(text.parse::<SessionId>().unwrap(), id);
            prop_assert_eq!(id.as_uuid().get_version_num(), 7);
        }

        #[test]
        fn construction_is_deterministic(ms in 0u64..(1u64 << 48), random in any::<[u8; 10]>()) {
            prop_assert_eq!(EventId::from_parts(ms, random), EventId::from_parts(ms, random));
        }

        #[test]
        fn later_timestamps_sort_later(ms in 0u64..(1u64 << 47), random in any::<[u8; 10]>()) {
            let a = EventId::from_parts(ms, random);
            let b = EventId::from_parts(ms + 1, random);
            prop_assert!(a < b);
        }
    }

    #[test]
    fn ids_of_different_kinds_do_not_parse_as_each_other() {
        let session = SessionId::from_parts(1, [7; 10]).to_string();
        assert_eq!(
            session.parse::<PocketId>(),
            Err(IdParseError::WrongPrefix { expected: "pkt" })
        );
    }

    #[test]
    fn rejects_uppercase_and_non_v7() {
        let id = OperationId::from_parts(1, [0xab; 10]).to_string();
        assert!(id.bytes().any(|b| b.is_ascii_lowercase() && b != b'o' && b != b'p'));
        assert_eq!(
            id.to_uppercase().replace("OP_", "op_").parse::<OperationId>(),
            Err(IdParseError::BadHex)
        );
        // A valid UUIDv4 in simple form.
        let v4 = "op_9f2b4c1e8a3d4f6b9c0d1e2f3a4b5c6d";
        assert_eq!(v4.parse::<OperationId>(), Err(IdParseError::NotV7));
    }

    #[test]
    fn serde_uses_the_prefixed_string_form() {
        let id = CorrelationId::from_parts(42, [3; 10]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
        assert_eq!(serde_json::from_str::<CorrelationId>(&json).unwrap(), id);
    }
}
