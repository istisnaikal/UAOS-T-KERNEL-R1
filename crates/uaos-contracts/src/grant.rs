// SPDX-License-Identifier: Apache-2.0

//! Capability grants, `uaos.grant/1`.
//!
//! A grant is a time-bounded permission a human issued through an approval. It satisfies the ask
//! policies it lists and never overrides a forbid. A module carries one into a child Operation as a
//! `GrantRef`, which only names a grant: the runtime re-checks the live grant at every use, so an
//! expired or revoked grant fails closed.
//!
//! **Cross-project memory** is a grant of action `memory.read` on another pocket: consent
//! for a cross-pocket read, and the only grant that carries an [`InjectionPolicy`]. A
//! `memory.read` grant on the pocket it applies in satisfies an ask policy for an own-pocket
//! read, as any grant does, and carries no injection policy: nothing is injected from
//! elsewhere.
//!
//! This module defines the wire shapes only. Issuing, matching and revoking are the policy engine's
//! and the runtime's. **Draft until the first release**, like every kernel contract.

use std::borrow::Cow;
use std::collections::BTreeSet;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::credential::ActionName;
use crate::event::ModuleName;
use crate::id::{ApprovalId, CredentialId, GrantId, PocketId, PoolId};
use crate::limits;
use crate::operation::RiskTier;
use crate::time::WallTime;
use crate::token::string_token_serde;

/// The one action whose grants cross pockets.
pub const MEMORY_READ: &str = "memory.read";

/// A grant record is internally inconsistent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// A data class or policy identifier is empty, too long or has disallowed characters.
    #[error("malformed token: {0}")]
    MalformedToken(&'static str),
    /// A set lists more than [`limits::MAX_SCOPE_ITEMS`] members.
    #[error("a grant set lists more than {max} members")]
    TooBroad {
        /// The bound.
        max: usize,
    },
    /// The grant expires at or before its issue.
    #[error("a grant must expire after it is issued")]
    ExpiresBeforeIssue,
    /// An injection policy on a grant other than a cross-pocket `memory.read`, or none on one.
    #[error("an injection policy belongs exactly to `memory.read` grants on another pocket")]
    InjectionMismatch,
    /// A `memory.read` grant on something other than a pocket, or a pocket resource on another
    /// action.
    #[error("a `memory.read` grant is on a pocket, and only `memory.read` grants are")]
    ResourceMismatch,
}

/// The longest name, data class or policy identifier a grant carries, in bytes: the policy
/// engine's own bound.
pub const MAX_GRANT_NAME: usize = 128;

/// Whether `s` fits the policy engine's `Name` grammar: 1..=128 bytes of `[A-Za-z0-9._:/-]`,
/// characters that need no escaping anywhere. The wire must hold every name the engine holds.
fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_GRANT_NAME
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}

/// A model, provider, tool or configuration key name, in the policy engine's `Name` grammar.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantName(String);

impl GrantName {
    /// Validates and wraps a name.
    ///
    /// # Errors
    /// [`GrantError::MalformedToken`] outside the engine's `Name` grammar.
    pub fn new(name: impl Into<String>) -> Result<Self, GrantError> {
        let name = name.into();
        if is_name(&name) {
            Ok(Self(name))
        } else {
            Err(GrantError::MalformedToken("name"))
        }
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

string_token_serde!(GrantName, "^[A-Za-z0-9._:/-]{1,128}$");

/// An ask policy's `@id`, in the policy engine's grammar: 1..=128 bytes of `[A-Za-z0-9._:-]`,
/// never starting with the prefix `grant:`, which names grants in explanations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyId(String);

impl PolicyId {
    /// Validates and wraps a policy identifier.
    ///
    /// # Errors
    /// [`GrantError::MalformedToken`] outside the grammar or with the `grant:` prefix.
    pub fn new(id: impl Into<String>) -> Result<Self, GrantError> {
        let id = id.into();
        let ok = is_name(&id) && !id.contains('/') && !id.starts_with("grant:");
        if ok {
            Ok(Self(id))
        } else {
            Err(GrantError::MalformedToken("policy id"))
        }
    }

    /// Returns the identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for PolicyId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PolicyId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for PolicyId {
    fn schema_name() -> Cow<'static, str> {
        "PolicyId".into()
    }

    // The `grant:` rule as `not`, not as a lookahead, which validators outside ECMA-262 refuse.
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "allOf": [
                { "pattern": "^[A-Za-z0-9._:-]{1,128}$" },
                { "not": { "pattern": "^grant:" } }
            ]
        })
    }
}

/// A data class a grant's approved content carried (`secret.aws`, `pii.email`), in the policy
/// engine's `Name` grammar.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DataClass(String);

impl DataClass {
    /// Validates and wraps a data class.
    ///
    /// # Errors
    /// [`GrantError::MalformedToken`] outside the engine's `Name` grammar.
    pub fn new(class: impl Into<String>) -> Result<Self, GrantError> {
        let class = class.into();
        if is_name(&class) {
            Ok(Self(class))
        } else {
            Err(GrantError::MalformedToken("data class"))
        }
    }

    /// Returns the class.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

string_token_serde!(DataClass, "^[A-Za-z0-9._:/-]{1,128}$");

/// Who holds a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantPrincipal {
    /// An agent authenticated with this credential.
    Agent {
        /// The credential.
        credential: CredentialId,
    },
    /// A module, for the child Operations it requests.
    Module {
        /// The module's name.
        name: ModuleName,
    },
    /// A human, through a user-present channel. It has no other field, and one is refused.
    Human {},
    /// The kernel itself. It has no other field, and one is refused.
    System {},
}

/// What a grant allows its action on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantResource {
    /// A model of a provider, by exact names.
    Model {
        /// The provider, e.g. `anthropic`.
        provider: GrantName,
        /// The model's name.
        name: GrantName,
    },
    /// A tool, by exact name.
    Tool {
        /// The tool's name.
        name: GrantName,
    },
    /// A budget pool.
    Pool {
        /// The pool.
        id: PoolId,
    },
    /// A configuration key, by exact name.
    ConfigKey {
        /// The key.
        name: GrantName,
    },
    /// A pocket, for `memory.read`: another pocket (a cross-pocket read, which needs consent), or
    /// the reading pocket itself (behind an ask).
    Pocket {
        /// The pocket whose memory may be read.
        id: PocketId,
    },
}

/// What may happen to memory read under a cross-pocket grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InjectionPolicy {
    /// It may be appended to the newest human turn as it arrives, labelled with its provenance.
    Auto,
    /// It is held for the human, and appended only once they accept it.
    Ask,
    /// It may inform ranking but never enters a prompt.
    Never,
}

/// One issued grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantRecord {
    /// Identifier (`grt_…`), shown in explanations as `grant:<id>`.
    pub id: GrantId,
    /// Who holds it.
    pub principal: GrantPrincipal,
    /// What it allows: one of the engine's Cedar action names, such as `memory.read`. A record
    /// naming another action does not reload, and boot skips it with an alarm.
    pub action: ActionName,
    /// On what.
    pub resource: GrantResource,
    /// The pocket it applies in: for `memory.read`, the pocket that reads.
    pub pocket: PocketId,
    /// The approval that issued it.
    pub approval: ApprovalId,
    /// When it was issued.
    pub issued_at: WallTime,
    /// From this instant on it no longer applies. The engine keeps whole milliseconds, so a
    /// finer expiry floors: a reloaded grant ends early, never late.
    pub expires_at: WallTime,
    /// The highest risk tier the approval covered; a riskier request is not covered.
    pub max_risk_tier: RiskTier,
    /// The data classes the approved content carried; a request with any other is not covered.
    #[schemars(length(max = 8))]
    pub data_classes: BTreeSet<DataClass>,
    /// `@id`s of the ask policies the grant was issued to satisfy.
    #[schemars(length(max = 8))]
    pub approves: BTreeSet<PolicyId>,
    /// For a cross-pocket `memory.read` only: what may happen to what is read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injection: Option<InjectionPolicy>,
}

impl GrantRecord {
    /// Checks the record's internal consistency.
    ///
    /// # Errors
    /// [`GrantError`] describing the first inconsistency.
    pub fn validate(&self) -> Result<(), GrantError> {
        if self.expires_at <= self.issued_at {
            return Err(GrantError::ExpiresBeforeIssue);
        }
        if self.data_classes.len() > limits::MAX_SCOPE_ITEMS || self.approves.len() > limits::MAX_SCOPE_ITEMS {
            return Err(GrantError::TooBroad {
                max: limits::MAX_SCOPE_ITEMS,
            });
        }
        let memory_read = self.action.as_str() == MEMORY_READ;
        let source = match &self.resource {
            GrantResource::Pocket { id } => Some(*id),
            _ => None,
        };
        if memory_read != source.is_some() {
            return Err(GrantError::ResourceMismatch);
        }
        // Only a read of another pocket injects anything, so only it carries the policy.
        let cross_pocket = memory_read && source != Some(self.pocket);
        if cross_pocket != self.injection.is_some() {
            return Err(GrantError::InjectionMismatch);
        }
        Ok(())
    }
}

/// Schema tag of the grant contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum GrantSchema {
    /// Version 1.
    #[serde(rename = "uaos.grant/1")]
    V1,
}

/// What a grant entry records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantOp {
    /// A grant was issued.
    Issued {
        /// The new grant.
        record: Box<GrantRecord>,
    },
    /// A grant was revoked before it expired.
    Revoked {
        /// The revoked grant.
        grant: GrantId,
    },
}

/// One grant journal entry, `uaos.grant/1`, carried inline by a `grant.entry` record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(
    title = "uaos.grant/1",
    description = "One grant entry: a time-bounded permission issued through an approval, or its revocation."
)]
pub struct GrantEntry {
    /// Schema tag, always `uaos.grant/1`.
    pub schema: GrantSchema,
    /// What happened.
    pub op: GrantOp,
}

impl GrantEntry {
    /// Checks the entry's internal consistency.
    ///
    /// # Errors
    /// [`GrantError`] for an inconsistent issued record.
    pub fn validate(&self) -> Result<(), GrantError> {
        match &self.op {
            GrantOp::Issued { record } => record.validate(),
            GrantOp::Revoked { .. } => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::TypedId;

    fn at(seconds: i128) -> WallTime {
        WallTime::from_unix_nanos(1_760_000_000_000_000_000 + seconds * 1_000_000_000).unwrap()
    }

    fn reading(source: PocketId, reader: PocketId) -> GrantRecord {
        GrantRecord {
            id: GrantId::from_parts(1, [1; 10]),
            principal: GrantPrincipal::Module {
                name: ModuleName::new("mod-notes").unwrap(),
            },
            action: ActionName::new(MEMORY_READ).unwrap(),
            resource: GrantResource::Pocket { id: source },
            pocket: reader,
            approval: ApprovalId::from_parts(1, [2; 10]),
            issued_at: at(0),
            expires_at: at(3600),
            max_risk_tier: RiskTier::new(1).unwrap(),
            data_classes: BTreeSet::new(),
            approves: BTreeSet::new(),
            injection: Some(InjectionPolicy::Ask),
        }
    }

    fn pocket(n: u8) -> PocketId {
        PocketId::from_parts(1, [n; 10])
    }

    #[test]
    fn a_cross_pocket_read_grant_validates_and_round_trips() {
        let entry = GrantEntry {
            schema: GrantSchema::V1,
            op: GrantOp::Issued {
                record: Box::new(reading(pocket(1), pocket(2))),
            },
        };
        entry.validate().unwrap();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"schema\":\"uaos.grant/1\""));
        assert!(json.contains("\"injection\":\"ask\""));
        assert_eq!(serde_json::from_str::<GrantEntry>(&json).unwrap(), entry);
    }

    #[test]
    fn grant_names_take_the_engine_grammar() {
        for good in [
            "secret.aws",
            "pii.email",
            "claude-sonnet-5-5",
            "anthropic/x",
            "a:b",
            &"n".repeat(128),
        ] {
            assert!(GrantName::new(good).is_ok() && DataClass::new(good).is_ok(), "{good}");
        }
        for bad in ["", "a b", "a\"b", "é", &"n".repeat(129)] {
            assert!(GrantName::new(bad).is_err() && DataClass::new(bad).is_err(), "{bad}");
        }
        assert!(PolicyId::new("ask-exec").is_ok());
        for bad in ["grant:x", "a/b", ""] {
            assert!(PolicyId::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn humans_and_the_kernel_can_hold_grants() {
        for principal in [GrantPrincipal::Human {}, GrantPrincipal::System {}] {
            let json = serde_json::to_string(&principal).unwrap();
            assert_eq!(
                serde_json::from_str::<GrantPrincipal>(&json).unwrap(),
                principal,
                "{json}"
            );
        }
        assert_eq!(
            serde_json::to_string(&GrantPrincipal::Human {}).unwrap(),
            r#"{"kind":"human"}"#
        );
        for extra in [
            r#"{"kind":"human","credential":"crd_x"}"#,
            r#"{"kind":"system","name":"mod-x"}"#,
        ] {
            assert!(
                serde_json::from_str::<GrantPrincipal>(extra).is_err(),
                "a principal took a field it does not have: {extra}"
            );
        }
    }

    #[test]
    fn an_own_pocket_read_grant_carries_no_injection_policy() {
        let mut own = reading(pocket(1), pocket(1));
        assert_eq!(
            own.validate(),
            Err(GrantError::InjectionMismatch),
            "an own-pocket grant took an injection policy"
        );
        own.injection = None;
        assert_eq!(own.validate(), Ok(()), "an own-pocket grant could not be journaled");
    }

    #[test]
    fn injection_belongs_exactly_to_memory_reads_on_a_pocket() {
        let mut without = reading(pocket(1), pocket(2));
        without.injection = None;
        assert_eq!(without.validate(), Err(GrantError::InjectionMismatch));
        let mut model_call = reading(pocket(1), pocket(2));
        model_call.action = ActionName::new("model.call").unwrap();
        model_call.resource = GrantResource::Model {
            provider: GrantName::new("anthropic").unwrap(),
            name: GrantName::new("claude-sonnet-5-5").unwrap(),
        };
        assert_eq!(model_call.validate(), Err(GrantError::InjectionMismatch));
        model_call.injection = None;
        assert_eq!(model_call.validate(), Ok(()));
    }

    #[test]
    fn memory_reads_and_pockets_go_together() {
        let mut on_a_model = reading(pocket(1), pocket(2));
        on_a_model.resource = GrantResource::Model {
            provider: GrantName::new("anthropic").unwrap(),
            name: GrantName::new("claude-sonnet-5-5").unwrap(),
        };
        assert_eq!(
            on_a_model.validate(),
            Err(GrantError::ResourceMismatch),
            "a memory.read grant off a pocket validated"
        );
        let mut other_action = reading(pocket(1), pocket(2));
        other_action.action = ActionName::new("model.call").unwrap();
        other_action.injection = None;
        assert_eq!(other_action.validate(), Err(GrantError::ResourceMismatch));
    }

    #[test]
    fn a_grant_must_expire_after_issue_and_stay_narrow() {
        let mut late = reading(pocket(1), pocket(2));
        late.expires_at = late.issued_at;
        assert_eq!(late.validate(), Err(GrantError::ExpiresBeforeIssue));
        let mut broad = reading(pocket(1), pocket(2));
        for n in 0..9 {
            broad.data_classes.insert(DataClass::new(format!("class_{n}")).unwrap());
        }
        assert_eq!(broad.validate(), Err(GrantError::TooBroad { max: 8 }));
    }

    #[test]
    fn data_classes_are_tokens() {
        // The engine's `Name` grammar: what the engine holds, the wire must hold.
        for good in ["secrets_v1", "secret.aws", "Upper", &"x".repeat(128)] {
            assert!(DataClass::new(good).is_ok(), "{good:?}");
        }
        for bad in ["", "with space", &"x".repeat(129)] {
            assert!(DataClass::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn unknown_fields_are_refused() {
        let json = serde_json::to_value(reading(pocket(1), pocket(2))).unwrap();
        let mut extra = json.clone();
        extra
            .as_object_mut()
            .unwrap()
            .insert("override".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<GrantRecord>(extra).is_err());
    }
}
