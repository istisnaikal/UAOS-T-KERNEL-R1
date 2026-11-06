// SPDX-License-Identifier: Apache-2.0

//! Scoped credentials, `uaos.credential/1`.
//!
//! Agents never hold provider keys; they authenticate with credentials UAOS issues. A credential
//! sits in a hierarchy (`master` → `sub` → `child`, depth ≤ [`limits::MAX_CREDENTIAL_DEPTH`]) and
//! carries a [`Scope`], a coarse upper bound on what it may do. Fine-grained rules are Cedar
//! policy.
//!
//! This module defines the wire shapes only. The rules (containment, revocation) live in
//! `uaos-identity`. The record is secret-free by construction: it has a keyed digest of the secret
//! ([`CredentialDigest`]) and no field that could hold the secret itself.
//!
//! **Draft until the first release**, like every kernel contract.

use std::borrow::Cow;
use std::collections::BTreeSet;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::digest::CredentialDigest;
use crate::id::{CredentialId, PocketId, PoolId};
use crate::limits;
use crate::time::WallTime;
use crate::token::string_token_serde;
use crate::wire::{Epoch, RevocationSeq};

/// A credential record or entry is internally inconsistent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    /// A label, action name or pattern value is empty, too long or has disallowed characters.
    #[error("malformed token: {0}")]
    MalformedToken(&'static str),
    /// A scope dimension lists more than [`limits::MAX_SCOPE_ITEMS`] members.
    #[error("a scope dimension lists more than {max} members")]
    ScopeTooBroad {
        /// The bound.
        max: usize,
    },
    /// The kind and the parent disagree: a master has no parent, other kinds have one.
    #[error("kind and parent disagree: a master has no parent; sub and child keys have one")]
    KindParentMismatch,
    /// A sub or child credential without an expiry.
    #[error("sub and child credentials must expire")]
    MissingExpiry,
}

/// What a credential is in the hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// Held by the human principal; issues sub credentials. No parent.
    Master,
    /// Normally one per pocket; what `uaos run` hands to an agent.
    Sub,
    /// Optional, e.g. per subagent.
    Child,
}

/// An action a credential may perform: a kernel action such as `model.call`, or a module
/// action `<module>::<action>`. 1..=64 bytes of `[a-z0-9_.:]`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionName(String);

impl ActionName {
    /// Validates and wraps an action name.
    ///
    /// # Errors
    /// [`CredentialError::MalformedToken`] if empty, too long or outside `[a-z0-9_.:]`.
    pub fn new(name: impl Into<String>) -> Result<Self, CredentialError> {
        let name = name.into();
        let ok = !name.is_empty()
            && limits::MAX_CREDENTIAL_TOKEN.admits(name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b':'));
        if ok {
            Ok(Self(name))
        } else {
            Err(CredentialError::MalformedToken("action name"))
        }
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The literal part of a resource pattern: 1..=64 bytes of printable ASCII without spaces.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PatternValue(String);

impl PatternValue {
    /// Validates and wraps a pattern value.
    ///
    /// # Errors
    /// [`CredentialError::MalformedToken`] if empty, too long or not printable ASCII.
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialError> {
        let value = value.into();
        let ok = !value.is_empty()
            && limits::MAX_CREDENTIAL_TOKEN.admits(value.len())
            && value.bytes().all(|b| b.is_ascii_graphic());
        if ok {
            Ok(Self(value))
        } else {
            Err(CredentialError::MalformedToken("pattern value"))
        }
    }

    /// Returns the value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A human-readable label for a credential: 1..=64 characters without control characters
/// (C0, DEL and C1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Label(String);

impl Label {
    /// Validates and wraps a label.
    ///
    /// # Errors
    /// [`CredentialError::MalformedToken`] if empty, too long or containing control characters.
    pub fn new(label: impl Into<String>) -> Result<Self, CredentialError> {
        let label = label.into();
        let ok = !label.is_empty()
            && label.chars().count() <= limits::MAX_LABEL_CHARS
            && !label.chars().any(char::is_control);
        if ok {
            Ok(Self(label))
        } else {
            Err(CredentialError::MalformedToken("label"))
        }
    }

    /// Returns the label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

string_token_serde!(ActionName, "^[a-z0-9_.:]{1,64}$");
string_token_serde!(PatternValue, "^[!-~]{1,64}$");
string_token_serde!(Label, "^[^\\u0000-\\u001f\\u007f-\\u009f]{1,64}$");

/// What kind of resource a pattern names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// A model, e.g. `claude-sonnet-5-5`.
    Model,
    /// A tool.
    Tool,
    /// A configuration key.
    ConfigKey,
}

/// How a pattern matches. Only these two, so containment between patterns stays decidable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PatternMatch {
    /// The resource name equals the value.
    Exact,
    /// The resource name starts with the value.
    Prefix,
}

/// A resource pattern such as "models whose name starts with `claude-`".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourcePattern {
    /// Kind of resource.
    pub kind: ResourceKind,
    /// How `value` matches.
    #[serde(rename = "match")]
    pub matching: PatternMatch,
    /// The literal name or prefix.
    pub value: PatternValue,
}

/// One dimension of a scope: everything, or only the listed members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(rename = "ScopeSetOf{T}")]
pub enum ScopeSet<T: Ord> {
    /// No restriction in this dimension.
    Any,
    /// Only these members (at most [`limits::MAX_SCOPE_ITEMS`]).
    Only(#[schemars(length(max = 8))] BTreeSet<T>),
}

impl<T: Ord> ScopeSet<T> {
    fn validate(&self) -> Result<(), CredentialError> {
        match self {
            Self::Only(members) if members.len() > limits::MAX_SCOPE_ITEMS => Err(CredentialError::ScopeTooBroad {
                max: limits::MAX_SCOPE_ITEMS,
            }),
            _ => Ok(()),
        }
    }
}

/// What a credential may do at most.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    /// Actions.
    pub actions: ScopeSet<ActionName>,
    /// Resources.
    pub resources: ScopeSet<ResourcePattern>,
    /// Pockets the credential may act in.
    pub pockets: ScopeSet<PocketId>,
    /// Budget pools it may reserve from.
    pub pools: ScopeSet<PoolId>,
    /// From this instant on the credential no longer verifies. `None` only for a master.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<WallTime>,
}

impl Scope {
    /// Checks the scope's bounds.
    ///
    /// # Errors
    /// [`CredentialError::ScopeTooBroad`] if a dimension lists too many members.
    pub fn validate(&self) -> Result<(), CredentialError> {
        self.actions.validate()?;
        self.resources.validate()?;
        self.pockets.validate()?;
        self.pools.validate()
    }
}

/// One issued credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialRecord {
    /// Identifier (`cred_…`), shown in explanations and the journal; not a secret.
    pub id: CredentialId,
    /// Position in the hierarchy.
    pub kind: CredentialKind,
    /// The issuing credential; `None` exactly for a master.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<CredentialId>,
    /// Keyed digest of the secret; verification looks credentials up by it.
    pub digest: CredentialDigest,
    /// Human-readable label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<Label>,
    /// Upper bound on what the credential may do.
    pub scope: Scope,
    /// When it was issued.
    pub issued_at: WallTime,
    /// The parent's epoch at issuance; a different current parent epoch revokes this credential.
    pub parent_epoch: Epoch,
    /// This credential's epoch at issuance (initially 0).
    pub epoch: Epoch,
}

impl CredentialRecord {
    /// Checks the record's internal consistency.
    ///
    /// # Errors
    /// [`CredentialError`] describing the first inconsistency.
    pub fn validate(&self) -> Result<(), CredentialError> {
        let master = self.kind == CredentialKind::Master;
        if master != self.parent.is_none() {
            return Err(CredentialError::KindParentMismatch);
        }
        if !master && self.scope.expires_at.is_none() {
            return Err(CredentialError::MissingExpiry);
        }
        self.scope.validate()
    }
}

/// Schema tag of the credential contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum CredentialSchema {
    /// Version 1.
    #[serde(rename = "uaos.credential/1")]
    V1,
}

/// What an identity entry records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialOp {
    /// A credential was issued.
    Issued {
        /// The new credential.
        record: Box<CredentialRecord>,
    },
    /// One credential was revoked.
    Revoked {
        /// The revoked credential.
        credential: CredentialId,
        /// The installation's revocation count after this revocation (restore guard).
        revocation_seq: RevocationSeq,
    },
    /// A credential's epoch was bumped, revoking every descendant issued under the old one.
    EpochBumped {
        /// The credential whose epoch changed.
        credential: CredentialId,
        /// The new epoch.
        epoch: Epoch,
        /// The installation's revocation count after this bump (restore guard).
        revocation_seq: RevocationSeq,
    },
    /// Recovery after a restored data directory: this entry revokes every master that is still
    /// live, atomically, and raises the journal's revocation count above the keychain's.
    RestoreRecovered {
        /// The installation's revocation count after recovery.
        revocation_seq: RevocationSeq,
    },
}

/// One identity journal entry, `uaos.credential/1`, carried inline by an `identity.entry`
/// record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(
    title = "uaos.credential/1",
    description = "One identity entry: a credential issued or revoked, an epoch bumped, or recovery after a restore."
)]
pub struct CredentialEntry {
    /// Schema tag, always `uaos.credential/1`.
    pub schema: CredentialSchema,
    /// What happened.
    pub op: CredentialOp,
}

impl CredentialEntry {
    /// Checks the entry's internal consistency.
    ///
    /// # Errors
    /// [`CredentialError`] for an inconsistent issued record.
    pub fn validate(&self) -> Result<(), CredentialError> {
        match &self.op {
            CredentialOp::Issued { record } => record.validate(),
            CredentialOp::Revoked { .. } | CredentialOp::EpochBumped { .. } | CredentialOp::RestoreRecovered { .. } => {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::TypedId;

    fn record(kind: CredentialKind, parent: Option<CredentialId>, expires: bool) -> CredentialRecord {
        CredentialRecord {
            id: CredentialId::from_parts(1, [1; 10]),
            kind,
            parent,
            digest: CredentialDigest::from_bytes([7; 32]),
            label: Some(Label::new("ci agent").unwrap()),
            scope: Scope {
                actions: ScopeSet::Only([ActionName::new("model.call").unwrap()].into()),
                resources: ScopeSet::Only(
                    [ResourcePattern {
                        kind: ResourceKind::Model,
                        matching: PatternMatch::Prefix,
                        value: PatternValue::new("claude-").unwrap(),
                    }]
                    .into(),
                ),
                pockets: ScopeSet::Any,
                pools: ScopeSet::Any,
                expires_at: expires.then(|| WallTime::from_unix_nanos(2_000_000_000_000_000_000).unwrap()),
            },
            issued_at: WallTime::from_unix_nanos(1_000_000_000_000_000_000).unwrap(),
            parent_epoch: Epoch(0),
            epoch: Epoch(0),
        }
    }

    #[test]
    fn kind_parent_and_expiry_rules() {
        let parent = Some(CredentialId::from_parts(1, [2; 10]));
        assert_eq!(record(CredentialKind::Master, None, false).validate(), Ok(()));
        assert_eq!(
            record(CredentialKind::Master, parent, true).validate(),
            Err(CredentialError::KindParentMismatch)
        );
        assert_eq!(
            record(CredentialKind::Sub, None, true).validate(),
            Err(CredentialError::KindParentMismatch)
        );
        assert_eq!(
            record(CredentialKind::Sub, parent, false).validate(),
            Err(CredentialError::MissingExpiry)
        );
        assert_eq!(record(CredentialKind::Child, parent, true).validate(), Ok(()));
    }

    #[test]
    fn tokens_are_validated() {
        assert!(ActionName::new("anthropic::messages").is_ok());
        assert!(ActionName::new("Model.Call").is_err());
        assert!(PatternValue::new("has space").is_err());
        assert!(Label::new("line\nbreak").is_err());
        assert!(Label::new("ü ş ı").is_ok());
    }

    #[test]
    fn scope_dimensions_are_bounded() {
        let many: BTreeSet<ActionName> = (0..=limits::MAX_SCOPE_ITEMS)
            .map(|i| ActionName::new(format!("module::a{i}")).unwrap())
            .collect();
        let mut r = record(CredentialKind::Master, None, false);
        r.scope.actions = ScopeSet::Only(many);
        assert!(matches!(r.validate(), Err(CredentialError::ScopeTooBroad { .. })));
    }

    #[test]
    fn a_full_record_fits_an_inline_payload() {
        let mut r = record(CredentialKind::Child, Some(CredentialId::from_parts(1, [2; 10])), true);
        let long = |p: &str, i: usize| format!("{p}{i:0>60}");
        r.label = Some(Label::new("x".repeat(64)).unwrap());
        r.scope.actions = ScopeSet::Only(
            (0..limits::MAX_SCOPE_ITEMS)
                .map(|i| ActionName::new(long("a", i)).unwrap())
                .collect(),
        );
        r.scope.resources = ScopeSet::Only(
            (0..limits::MAX_SCOPE_ITEMS)
                .map(|i| ResourcePattern {
                    kind: ResourceKind::Tool,
                    matching: PatternMatch::Exact,
                    value: PatternValue::new(long("t", i)).unwrap(),
                })
                .collect(),
        );
        let entry = CredentialEntry {
            schema: CredentialSchema::V1,
            op: CredentialOp::Issued { record: Box::new(r) },
        };
        let len = serde_json::to_vec(&entry).unwrap().len();
        // Documents the bound: the widest scopes do NOT fit; issuance must check the size.
        assert!(len > 1024, "{len}");
    }

    #[test]
    fn entries_round_trip() {
        let entry = CredentialEntry {
            schema: CredentialSchema::V1,
            op: CredentialOp::EpochBumped {
                credential: CredentialId::from_parts(1, [3; 10]),
                epoch: Epoch(4),
                revocation_seq: RevocationSeq(9),
            },
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"schema\":\"uaos.credential/1\""));
        assert!(json.contains("\"epoch\":\"4\""));
        assert_eq!(serde_json::from_str::<CredentialEntry>(&json).unwrap(), entry);
    }
}
