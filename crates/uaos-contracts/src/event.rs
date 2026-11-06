// SPDX-License-Identifier: Apache-2.0

//! The journal event envelope, `uaos.event/1`.
//!
//! The journal stores one envelope per line. The chain is computed over the **exact stored
//! bytes** of each line (`hash_i = SHA-256(line_i)`; line `i+1` carries
//! `prev_hash = hash_i`), so no canonicalization is involved and anyone can verify a
//! journal with stock tools. The `hash` of a line is therefore derived, never stored inside
//! the line itself.
//!
//! Envelopes carry **metadata only**. Content (prompts, outputs, tool payloads) lives in
//! encrypted chunks referenced by `payload_ref`. Inline payloads and metadata are bounded
//! (see [`crate::limits`]) and validated on construction and on deserialization.
//!
//! Event types are open: an unknown `type` is preserved and skipped by readers, which keeps
//! old binaries able to read newer journals as long as `min_reader_version` allows.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::digest::{ChunkRef, Sha256Digest};
use crate::id::{AgentId, CorrelationId, CredentialId, EventId, OperationId, PocketId, RequestId, SessionId};
use crate::limits;
use crate::money::NanoUsd;
use crate::operation::{RiskTier, SideEffectClass};
use crate::time::EventTime;
use crate::wire::{ConfigVersion, Seq};

/// Error returned when an envelope component violates its bounds or format.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    /// Event type is not lowercase dotted segments within the length limit.
    #[error("event type must be dotted lowercase segments (e.g. `op.reserved_intent`), at most {max} bytes")]
    EventType {
        /// Maximum allowed length in bytes.
        max: u64,
    },
    /// Module name is not lowercase kebab-case within the length limit.
    #[error("module name must match ^[a-z][a-z0-9-]*$ and be at most {max} bytes")]
    ModuleName {
        /// Maximum allowed length in bytes.
        max: u64,
    },
    /// Inline payload exceeds its serialized size limit.
    #[error("inline payload exceeds {max} bytes when serialized")]
    InlinePayloadTooLarge {
        /// Maximum allowed serialized size in bytes.
        max: u64,
    },
    /// Metadata has too many entries or an oversized/invalid key or value.
    #[error(
        "metadata violates its bounds (max {max_entries} entries, key ^[a-z0-9_.-]+$ ≤ {max_key} bytes, value ≤ {max_value} bytes)"
    )]
    Metadata {
        /// Maximum number of entries.
        max_entries: usize,
        /// Maximum key length in bytes.
        max_key: u64,
        /// Maximum value length in bytes.
        max_value: u64,
    },
}

fn is_segment(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

macro_rules! validated_string {
    ($(#[$doc:meta])* $name:ident, $validate:expr, $schema:tt) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Cow<'static, str>);

        impl $name {
            /// Validates and wraps an owned string.
            ///
            /// # Errors
            /// Returns [`EnvelopeError`] if the value is not well formed.
            pub fn new(value: impl Into<String>) -> Result<Self, EnvelopeError> {
                let value = value.into();
                let check: fn(&str) -> Result<(), EnvelopeError> = $validate;
                check(&value)?;
                Ok(Self(Cow::Owned(value)))
            }

            /// Returns the string form.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(&*self.0, f)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                Self::new(s).map_err(serde::de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!($schema)
            }
        }
    };
}

validated_string! {
    /// Namespaced event type such as `op.reserved_intent`: at least two dotted lowercase
    /// segments. Open set: unknown types are preserved by readers.
    EventType,
    |s| {
        let ok = limits::MAX_EVENT_TYPE.admits(s.len())
            && s.split('.').count() >= 2
            && s.split('.').all(is_segment);
        if ok { Ok(()) } else { Err(EnvelopeError::EventType { max: limits::MAX_EVENT_TYPE.0 }) }
    },
    { "type": "string", "maxLength": 64, "pattern": "^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$" }
}

impl EventType {
    /// Wraps a compile-time constant. Every constant is checked by the test suite.
    const fn from_static(s: &'static str) -> Self {
        Self(Cow::Borrowed(s))
    }
}

validated_string! {
    /// Name of a module acting as a principal, in lowercase kebab-case.
    ModuleName,
    |s| {
        let mut bytes = s.bytes();
        let ok = limits::MAX_MODULE_NAME.admits(s.len())
            && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
            && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if ok { Ok(()) } else { Err(EnvelopeError::ModuleName { max: limits::MAX_MODULE_NAME.0 }) }
    },
    { "type": "string", "maxLength": 64, "pattern": "^[a-z][a-z0-9-]*$" }
}

/// Event types emitted by the kernel. A module's events are not types of their own: the host
/// journals each as `module.event`, with the module's name and its declared code as fields.
pub mod types {
    use super::EventType;

    /// Budget reserved and write-ahead intent recorded, in one critical record.
    pub const OP_RESERVED_INTENT: EventType = EventType::from_static("op.reserved_intent");
    /// The door connected and the Operation's request is about to leave: journaled (critical) after
    /// the connection is up and before the first byte, so recovery can tell "maybe sent" from
    /// "never sent".
    pub const OP_EXECUTING: EventType = EventType::from_static("op.executing");
    /// Operation committed.
    pub const OP_COMMITTED: EventType = EventType::from_static("op.committed");
    /// Operation failed.
    pub const OP_FAILED: EventType = EventType::from_static("op.failed");
    /// Operation denied before any side effect.
    pub const OP_DENIED: EventType = EventType::from_static("op.denied");
    /// Operation needs a human decision.
    pub const OP_APPROVAL_REQUIRED: EventType = EventType::from_static("op.approval_required");
    /// Startup recovery found an intent without outcome.
    pub const OP_INDETERMINATE: EventType = EventType::from_static("op.indeterminate");
    /// Budget settled against a reservation.
    pub const BUDGET_SETTLED: EventType = EventType::from_static("budget.settled");
    /// Budget reservation released without spend.
    pub const BUDGET_RELEASED: EventType = EventType::from_static("budget.released");
    /// A secret was detected in content that had already been sent; rotate it.
    pub const REDACT_EXPOSED_SECRET: EventType = EventType::from_static("redact.exposed_secret");
    /// A content chunk was crypto-shredded.
    pub const CHUNK_SHREDDED: EventType = EventType::from_static("chunk.shredded");
    /// A record's content chunk could not be read back after a power loss or a failed flush: the
    /// record stands, its payload is reported lost, never silently.
    pub const CHUNK_LOST: EventType = EventType::from_static("chunk.lost");
    /// One budget ledger entry (`uaos.budget_tx/1` in the inline payload).
    pub const BUDGET_ENTRY: EventType = EventType::from_static("budget.entry");
    /// One identity entry (`uaos.credential/1` in the inline payload).
    pub const IDENTITY_ENTRY: EventType = EventType::from_static("identity.entry");
    /// The kernel stop engaged: nothing new is admitted and live streams are cut. The inline
    /// payload names the reason and the engagement's generation, a decimal string
    /// (`{"reason": <code>, "generation": "<n>"}`); the record's actor, correlation and
    /// configuration version are the engager's. It took effect before this record, and boot honours
    /// it.
    pub const KERNEL_STOPPED: EventType = EventType::from_static("kernel.stopped");
    /// A human resumed a stopped kernel through a user-present channel.
    pub const KERNEL_RESUMED: EventType = EventType::from_static("kernel.resumed");
    /// The kernel booted: its inline payload counts what boot recovery read and closed.
    pub const KERNEL_BOOTED: EventType = EventType::from_static("kernel.booted");
    /// The kernel shut down cleanly: admission closed, open Operations ended or were counted, and
    /// the journal was flushed. The inline payload says so
    /// (`{"clean": true, "open_operations": "<n>"}`). It is not a stop: the next boot runs.
    pub const KERNEL_SHUTDOWN: EventType = EventType::from_static("kernel.shutdown");

    /// All kernel event types, for validation and generated documentation.
    pub const ALL: [&EventType; 18] = [
        &OP_RESERVED_INTENT,
        &OP_EXECUTING,
        &OP_COMMITTED,
        &OP_FAILED,
        &OP_DENIED,
        &OP_APPROVAL_REQUIRED,
        &OP_INDETERMINATE,
        &BUDGET_SETTLED,
        &BUDGET_RELEASED,
        &REDACT_EXPOSED_SECRET,
        &CHUNK_SHREDDED,
        &CHUNK_LOST,
        &BUDGET_ENTRY,
        &IDENTITY_ENTRY,
        &KERNEL_STOPPED,
        &KERNEL_RESUMED,
        &KERNEL_BOOTED,
        &KERNEL_SHUTDOWN,
    ];
}

/// Who caused an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Actor {
    /// A human acting through an authenticated, user-present channel.
    Human,
    /// An agent authenticated with a UAOS-issued credential.
    Agent {
        /// The credential used.
        credential: CredentialId,
    },
    /// A module acting under its granted capabilities.
    Module {
        /// The module's name.
        name: ModuleName,
    },
    /// The kernel itself (recovery, reconciliation, scheduled maintenance).
    System,
}

/// When the event must reach the OS relative to its acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Durability {
    /// Handed to the OS before the acknowledgement: survives kill -9. Power-loss durability
    /// follows the configured fsync policy (group commit within W ms, or strict).
    Critical,
    /// Batched; may be lost on process crash within the documented window.
    Standard,
}

/// Schema tag of the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum EventSchema {
    /// Version 1.
    #[serde(rename = "uaos.event/1")]
    V1,
}

/// Small metadata-only payload stored inline in the envelope (≤ 1 KiB serialized).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct InlinePayload(serde_json::Value);

impl JsonSchema for InlinePayload {
    fn schema_name() -> Cow<'static, str> {
        "InlinePayload".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "description": "Metadata-only JSON value, at most 1024 bytes when serialized." })
    }
}

impl InlinePayload {
    /// Validates the serialized size and wraps the value.
    ///
    /// # Errors
    /// Returns [`EnvelopeError::InlinePayloadTooLarge`] if the value serializes to more than
    /// [`limits::MAX_INLINE_PAYLOAD`] bytes.
    pub fn new(value: serde_json::Value) -> Result<Self, EnvelopeError> {
        let too_large = EnvelopeError::InlinePayloadTooLarge {
            max: limits::MAX_INLINE_PAYLOAD.0,
        };
        let len = serde_json::to_vec(&value).map_err(|_| too_large.clone())?.len();
        if limits::MAX_INLINE_PAYLOAD.admits(len) {
            Ok(Self(value))
        } else {
            Err(too_large)
        }
    }

    /// Returns the wrapped value.
    #[must_use]
    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }
}

impl<'de> Deserialize<'de> for InlinePayload {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(serde_json::Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Bounded string-to-string labels. Never content.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(transparent)]
pub struct Metadata(BTreeMap<String, String>);

impl JsonSchema for Metadata {
    fn schema_name() -> Cow<'static, str> {
        "Metadata".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "Bounded labels, never content. Keys and values are limited in BYTES (UTF-8); the maxLength below is the matching character bound for ASCII.",
            "type": "object",
            "maxProperties": 16,
            "propertyNames": { "pattern": "^[a-z0-9_.-]{1,64}$" },
            "additionalProperties": { "type": "string", "maxLength": 256 }
        })
    }
}

impl Metadata {
    /// Validates bounds and wraps the map.
    ///
    /// # Errors
    /// Returns [`EnvelopeError::Metadata`] if any bound is exceeded or a key is malformed.
    pub fn new(map: BTreeMap<String, String>) -> Result<Self, EnvelopeError> {
        let key_ok = |k: &String| {
            !k.is_empty()
                && limits::MAX_METADATA_KEY.admits(k.len())
                && k.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-'))
        };
        let ok = map.len() <= limits::MAX_METADATA_ENTRIES
            && map
                .iter()
                .all(|(k, v)| key_ok(k) && limits::MAX_METADATA_VALUE.admits(v.len()));
        if ok {
            Ok(Self(map))
        } else {
            Err(EnvelopeError::Metadata {
                max_entries: limits::MAX_METADATA_ENTRIES,
                max_key: limits::MAX_METADATA_KEY.0,
                max_value: limits::MAX_METADATA_VALUE.0,
            })
        }
    }

    /// Returns the entries.
    #[must_use]
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    /// Returns `true` if there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for Metadata {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(BTreeMap::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// One journal record, `uaos.event/1`.
///
/// Unknown fields are ignored on read (machine-written, forward compatible). The chain hash
/// of this record is computed over its exact stored bytes and is not a field of the record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[schemars(title = "uaos.event/1", description = "One UAOS journal record (metadata only).")]
pub struct EventEnvelope {
    /// Schema tag, always `uaos.event/1`.
    pub schema: EventSchema,
    /// Unique event identifier.
    pub id: EventId,
    /// Position in the journal: previous `seq` + 1, starting at 0.
    pub seq: Seq,
    /// When it happened.
    pub ts: EventTime,
    /// Session the event belongs to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Pocket the event belongs to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pocket_id: Option<PocketId>,
    /// Operation the event belongs to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    /// Ingress request that caused the event, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    /// The agent instance that caused the event, if known. Absent, it is not written, so records
    /// without it keep exactly the bytes they had before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
    /// Correlation identifier tying together one user-visible action.
    pub correlation_id: CorrelationId,
    /// Causing event, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<EventId>,
    /// Who caused it.
    pub actor: Actor,
    /// Namespaced type, e.g. `op.reserved_intent`.
    #[serde(rename = "type")]
    pub event_type: EventType,
    /// Keyed reference to an encrypted content chunk, if the event has content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<ChunkRef>,
    /// Small metadata-only payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_inline: Option<InlinePayload>,
    /// Estimated cost attributed to this event, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_estimate: Option<NanoUsd>,
    /// Whether the related effect can be undone by a compensating action.
    pub compensable: bool,
    /// How far the related effect reaches.
    pub side_effect_class: SideEffectClass,
    /// Risk tier of the related Operation.
    pub risk_tier: RiskTier,
    /// Durability class this record was written with.
    pub durability: Durability,
    /// Configuration snapshot in force.
    pub config_version: ConfigVersion,
    /// Chain link: SHA-256 of the previous line's exact bytes.
    pub prev_hash: Sha256Digest,
    /// Bounded labels.
    #[serde(default, skip_serializing_if = "Metadata::is_empty")]
    pub metadata: Metadata,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::TypedId;
    use crate::time::WallTime;
    use crate::wire::MonoNanos;

    fn sample() -> EventEnvelope {
        EventEnvelope {
            schema: EventSchema::V1,
            id: EventId::from_parts(1_760_000_000_000, [1; 10]),
            seq: Seq(u64::MAX),
            ts: EventTime {
                wall: WallTime::from_unix_nanos(1_760_000_000_123_456_789).unwrap(),
                mono_ns: MonoNanos(u64::MAX - 1),
            },
            session_id: Some(SessionId::from_parts(1, [2; 10])),
            pocket_id: None,
            operation_id: Some(OperationId::from_parts(1, [3; 10])),
            request_id: None,
            agent_id: None,
            correlation_id: CorrelationId::from_parts(1, [4; 10]),
            parent_id: None,
            actor: Actor::Agent {
                credential: CredentialId::from_parts(1, [5; 10]),
            },
            event_type: types::OP_RESERVED_INTENT,
            payload_ref: Some(ChunkRef::from_bytes([9; 32])),
            payload_inline: Some(InlinePayload::new(serde_json::json!({"model": "m"})).unwrap()),
            cost_estimate: Some(NanoUsd::new(1234)),
            compensable: false,
            side_effect_class: SideEffectClass::External,
            risk_tier: RiskTier::new(2).unwrap(),
            durability: Durability::Critical,
            config_version: ConfigVersion(42),
            prev_hash: Sha256Digest::from_bytes([0; 32]),
            metadata: Metadata::default(),
        }
    }

    #[test]
    fn round_trips_with_64_bit_values_as_strings() {
        let e = sample();
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"seq\":\"18446744073709551615\""));
        assert!(json.contains("\"type\":\"op.reserved_intent\""));
        assert_eq!(serde_json::from_str::<EventEnvelope>(&json).unwrap(), e);
    }

    #[test]
    fn unknown_fields_and_event_types_are_tolerated() {
        let mut v = serde_json::to_value(sample()).unwrap();
        v["type"] = "mod.future.thing".into();
        v["added_in_a_later_minor"] = true.into();
        let parsed: EventEnvelope = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.event_type.as_str(), "mod.future.thing");
    }

    #[test]
    fn wrong_schema_tag_is_rejected() {
        let mut v = serde_json::to_value(sample()).unwrap();
        v["schema"] = "uaos.event/2".into();
        assert!(serde_json::from_value::<EventEnvelope>(v).is_err());
    }

    #[test]
    fn kernel_event_type_constants_are_valid() {
        for t in types::ALL {
            assert!(EventType::new(t.as_str().to_owned()).is_ok(), "{t} is invalid");
        }
    }

    #[test]
    fn event_type_validation() {
        for bad in ["op", "Op.x", "op..x", ".op", "op.", "op.x-y", "1op.x"] {
            assert!(EventType::new(bad).is_err(), "accepted {bad}");
        }
        assert!(EventType::new("a".repeat(30) + "." + &"b".repeat(34)).is_err());
    }

    #[test]
    fn bounds_are_enforced_on_deserialize() {
        let mut v = serde_json::to_value(sample()).unwrap();
        v["payload_inline"] = serde_json::json!({ "x": "y".repeat(2000) });
        assert!(serde_json::from_value::<EventEnvelope>(v).is_err());

        let mut v = serde_json::to_value(sample()).unwrap();
        let big: BTreeMap<String, String> = (0..17).map(|i| (format!("k{i}"), "v".into())).collect();
        v["metadata"] = serde_json::to_value(big).unwrap();
        assert!(serde_json::from_value::<EventEnvelope>(v).is_err());
    }

    /// The journal hashes a record's exact bytes: an envelope without an agent must serialize
    /// exactly as it did before the field existed.
    #[test]
    fn an_absent_agent_id_is_not_written() {
        let json = serde_json::to_string(&sample()).unwrap();
        assert!(!json.contains("agent_id"), "an absent agent_id was written: {json}");
        // The exact bytes `uaos.event/1` wrote for this envelope before `agent_id` existed.
        let golden = r#"{"schema":"uaos.event/1","id":"evt_0199c82cc00071018101010101010101","seq":"18446744073709551615","ts":{"wall":"2025-10-09T08:53:20.123456789Z","mono_ns":"18446744073709551614"},"session_id":"ses_00000000000172028202020202020202","operation_id":"op_00000000000173038303030303030303","correlation_id":"cor_00000000000174048404040404040404","actor":{"kind":"agent","credential":"cred_00000000000175058505050505050505"},"type":"op.reserved_intent","payload_ref":"hmac-sha256:0909090909090909090909090909090909090909090909090909090909090909","payload_inline":{"model":"m"},"cost_estimate":"1234","compensable":false,"side_effect_class":"external","risk_tier":2,"durability":"critical","config_version":"42","prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}"#;
        assert_eq!(json, golden, "an envelope without an agent changed its bytes");
    }

    #[test]
    fn an_agent_id_round_trips() {
        let mut envelope = sample();
        envelope.agent_id = Some(AgentId::from_parts(1, [6; 10]));
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("\"agent_id\":\"agt_"), "{json}");
        assert_eq!(serde_json::from_str::<EventEnvelope>(&json).unwrap(), envelope);
    }
}
