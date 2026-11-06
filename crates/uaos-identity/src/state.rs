// SPDX-License-Identifier: Apache-2.0

//! The identity state: a pure replay of `uaos.credential/1` entries.
//!
//! [`IdentityState::check`] decides whether an entry may be applied; [`IdentityState::apply`]
//! applies it. Verification walks a credential's ancestor chain and fails on the first
//! revoked, expired or epoch-stale link. The walk is bounded by
//! [`limits::MAX_CREDENTIAL_DEPTH`].
//!
//! The journal's revocation count and the counter in the OS keychain are compared on every
//! verification ([`guard_status`]):
//!
//! | keychain vs journal | meaning | verification |
//! |---|---|---|
//! | equal | normal | allowed |
//! | one behind | a keychain write after a journaled revocation was interrupted | allowed; the next write or open repairs it |
//! | ahead | the data directory predates a revocation (restored) | refused until restore recovery |
//! | further behind, or implausibly large | the counter was deleted or altered | refused |

use std::collections::BTreeMap;

use uaos_contracts::credential::{
    CredentialEntry, CredentialError, CredentialKind, CredentialOp, CredentialRecord, Scope,
};
use uaos_contracts::digest::CredentialDigest;
use uaos_contracts::error::{ErrorCode, codes};
use uaos_contracts::id::CredentialId;
use uaos_contracts::limits;
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::{Epoch, RevocationSeq};

use crate::scope::scope_within;

/// A keychain counter at or above this value is treated as tampering. Real installations
/// revoke a few times a day; 2^62 is unreachable, while still far from overflow.
pub const GUARD_CEILING: u64 = 1 << 62;

/// Identity failure. Each variant maps to one registered error code.
///
/// The `Display` text may name credential ids and is meant for the local journal and
/// explanations. The API layer answers callers with the registered, generic message for
/// [`IdentityError::code`], never with this text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The presented text is not a well-formed credential.
    #[error("not a well-formed UAOS credential")]
    Malformed,
    /// No credential has the presented digest.
    #[error("unknown credential")]
    Unknown,
    /// The credential, or an ancestor, is revoked (directly or by an epoch bump).
    #[error("credential {0} is revoked")]
    Revoked(CredentialId),
    /// The credential, or an ancestor, has expired.
    #[error("credential {0} has expired")]
    Expired(CredentialId),
    /// A requested scope is not within its parent's.
    #[error("the scope of {0} exceeds its parent's")]
    ScopeExceedsParent(CredentialId),
    /// The chain would be, or is, longer than allowed.
    #[error("credential chain longer than {max}")]
    DepthExceeded {
        /// The bound.
        max: usize,
    },
    /// The data directory is older than the latest revocation (restore guard).
    #[error("the data directory predates revocation {keychain}; the journal has only {journal}")]
    StaleDataDirectory {
        /// Count in the OS keychain.
        keychain: RevocationSeq,
        /// Count in the journal.
        journal: RevocationSeq,
    },
    /// The keychain counter is behind the journal by more than one, or implausibly large.
    #[error("the revocation counter ({keychain}) is inconsistent with the journal ({journal})")]
    CounterInconsistent {
        /// Count in the OS keychain.
        keychain: RevocationSeq,
        /// Count in the journal.
        journal: RevocationSeq,
    },
    /// The identity key is missing or malformed while credentials exist.
    #[error("the identity key is missing or malformed while credentials exist")]
    KeyLost,
    /// The serialized entry would not fit an inline journal payload, or a scope dimension is too
    /// broad.
    #[error("the credential record is too large for one journal entry")]
    RecordTooLarge,
    /// Too many live credentials, overall or under one parent.
    #[error("too many live credentials")]
    LimitReached,
    /// The request breaks a rule (unknown parent, missing expiry, duplicate...).
    #[error("invalid identity request: {0}")]
    InvalidRequest(String),
    /// The OS keychain failed (unreachable or denied).
    #[error("identity keys unavailable: {0}")]
    KeysUnavailable(String),
    /// A recording failed, or a journal entry does not replay; the identity refuses work until
    /// rebuilt from the journal.
    #[error("identity state unavailable: {0}")]
    Unavailable(String),
}

impl IdentityError {
    /// The registered error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Malformed => codes::IDENTITY_MALFORMED,
            Self::Unknown => codes::IDENTITY_UNKNOWN,
            Self::Revoked(_) => codes::IDENTITY_REVOKED,
            Self::Expired(_) => codes::IDENTITY_EXPIRED,
            Self::ScopeExceedsParent(_) => codes::IDENTITY_SCOPE_EXCEEDS_PARENT,
            Self::DepthExceeded { .. } => codes::IDENTITY_DEPTH_EXCEEDED,
            Self::StaleDataDirectory { .. } => codes::IDENTITY_STALE_DATA_DIR,
            Self::CounterInconsistent { .. } => codes::IDENTITY_COUNTER_INCONSISTENT,
            Self::KeyLost => codes::IDENTITY_KEY_LOST,
            Self::RecordTooLarge => codes::IDENTITY_RECORD_TOO_LARGE,
            Self::LimitReached => codes::IDENTITY_LIMIT_REACHED,
            Self::InvalidRequest(_) => codes::IDENTITY_INVALID_REQUEST,
            Self::KeysUnavailable(_) => codes::IDENTITY_KEYS_UNAVAILABLE,
            Self::Unavailable(_) => codes::IDENTITY_UNAVAILABLE,
        }
    }
}

impl From<CredentialError> for IdentityError {
    fn from(e: CredentialError) -> Self {
        match e {
            CredentialError::ScopeTooBroad { .. } => Self::RecordTooLarge,
            other => Self::InvalidRequest(other.to_string()),
        }
    }
}

/// How the keychain counter relates to the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardStatus {
    /// Equal.
    InSync,
    /// One behind: an interrupted keychain write; repairable.
    Lagging,
}

/// Compares the keychain counter with the journal's revocation count.
///
/// # Errors
/// [`IdentityError::StaleDataDirectory`] if the keychain is ahead;
/// [`IdentityError::CounterInconsistent`] if it is further behind or implausibly large.
pub fn guard_status(keychain: RevocationSeq, journal: RevocationSeq) -> Result<GuardStatus, IdentityError> {
    if keychain.0 >= GUARD_CEILING {
        return Err(IdentityError::CounterInconsistent { keychain, journal });
    }
    if keychain == journal {
        Ok(GuardStatus::InSync)
    } else if keychain > journal {
        Err(IdentityError::StaleDataDirectory { keychain, journal })
    } else if keychain.0.checked_add(1) == Some(journal.0) {
        Ok(GuardStatus::Lagging)
    } else {
        Err(IdentityError::CounterInconsistent { keychain, journal })
    }
}

/// A credential and its live status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// The record as issued.
    pub record: CredentialRecord,
    /// Revoked directly.
    pub revoked: bool,
    /// Current epoch; descendants issued under an older one no longer verify.
    pub epoch: Epoch,
}

/// A credential that verified, with the scope it may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The credential.
    pub credential: CredentialId,
    /// Its kind.
    pub kind: CredentialKind,
    /// Its scope (within every ancestor's: checked at issuance; records are immutable).
    pub scope: Scope,
    /// The chain from the credential up to its master.
    pub chain: Vec<CredentialId>,
}

/// The replayed identity state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityState {
    nodes: BTreeMap<CredentialId, Node>,
    by_digest: BTreeMap<CredentialDigest, CredentialId>,
    revocation_seq: RevocationSeq,
}

impl IdentityState {
    /// The highest revocation count recorded in the journal.
    #[must_use]
    pub fn revocation_seq(&self) -> RevocationSeq {
        self.revocation_seq
    }

    /// Whether any credential was ever issued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// A credential and its status.
    #[must_use]
    pub fn node(&self, id: CredentialId) -> Option<&Node> {
        self.nodes.get(&id)
    }

    /// All credentials, in identifier order.
    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    fn live_count(&self) -> usize {
        self.nodes.values().filter(|n| !n.revoked).count()
    }

    fn live_children(&self, parent: CredentialId) -> usize {
        self.nodes
            .values()
            .filter(|n| !n.revoked && n.record.parent == Some(parent))
            .count()
    }

    /// Number of credentials in the chain ending at `id`.
    fn chain_len(&self, id: CredentialId) -> Result<usize, IdentityError> {
        let mut len = 0usize;
        let mut current = Some(id);
        while let Some(cur) = current {
            len += 1;
            if len > limits::MAX_CREDENTIAL_DEPTH {
                return Err(IdentityError::DepthExceeded {
                    max: limits::MAX_CREDENTIAL_DEPTH,
                });
            }
            current = self.known(cur)?.record.parent;
        }
        Ok(len)
    }

    fn known(&self, id: CredentialId) -> Result<&Node, IdentityError> {
        self.nodes
            .get(&id)
            .ok_or_else(|| IdentityError::InvalidRequest(format!("unknown credential {id}")))
    }

    /// Whether `entry` may be applied to this state.
    ///
    /// # Errors
    /// [`IdentityError`] naming the first rule the entry breaks.
    pub fn check(&self, entry: &CredentialEntry) -> Result<(), IdentityError> {
        entry.validate()?;
        let next = self
            .revocation_seq
            .0
            .checked_add(1)
            .ok_or(IdentityError::CounterInconsistent {
                keychain: self.revocation_seq,
                journal: self.revocation_seq,
            })?;
        match &entry.op {
            CredentialOp::Issued { record } => self.check_issue(record),
            CredentialOp::Revoked {
                credential,
                revocation_seq,
            } => {
                if self.known(*credential)?.revoked {
                    return Err(IdentityError::InvalidRequest(format!(
                        "{credential} is already revoked"
                    )));
                }
                exact_seq(*revocation_seq, next)
            }
            CredentialOp::EpochBumped {
                credential,
                epoch,
                revocation_seq,
            } => {
                let node = self.known(*credential)?;
                if node.revoked {
                    return Err(IdentityError::InvalidRequest(format!(
                        "{credential} is revoked; its epoch cannot change"
                    )));
                }
                if Some(epoch.0) != node.epoch.0.checked_add(1) {
                    return Err(IdentityError::InvalidRequest(format!(
                        "epoch of {credential} must advance by one (now {})",
                        node.epoch
                    )));
                }
                exact_seq(*revocation_seq, next)
            }
            CredentialOp::RestoreRecovered { revocation_seq } => {
                // The only entry allowed to skip ahead: it closes the gap to the keychain.
                if revocation_seq.0 >= next {
                    Ok(())
                } else {
                    Err(IdentityError::InvalidRequest(format!(
                        "revocation_seq {revocation_seq} must be at least {next}"
                    )))
                }
            }
        }
    }

    fn check_issue(&self, record: &CredentialRecord) -> Result<(), IdentityError> {
        if self.nodes.contains_key(&record.id) {
            return Err(IdentityError::InvalidRequest(format!("{} already exists", record.id)));
        }
        if self.by_digest.contains_key(&record.digest) {
            return Err(IdentityError::InvalidRequest("digest already in use".to_owned()));
        }
        if record.epoch != Epoch(0) {
            return Err(IdentityError::InvalidRequest(
                "a new credential starts at epoch 0".to_owned(),
            ));
        }
        if self.live_count() >= limits::MAX_LIVE_CREDENTIALS {
            return Err(IdentityError::LimitReached);
        }
        let Some(parent_id) = record.parent else {
            return if record.parent_epoch == Epoch(0) {
                Ok(())
            } else {
                Err(IdentityError::InvalidRequest("a master has no parent epoch".to_owned()))
            };
        };
        let parent = self.known(parent_id)?;
        if parent.revoked {
            return Err(IdentityError::Revoked(parent_id));
        }
        if record.parent_epoch != parent.epoch {
            return Err(IdentityError::InvalidRequest(format!(
                "parent_epoch {} does not match {parent_id}'s epoch {}",
                record.parent_epoch, parent.epoch
            )));
        }
        let expected_kind = if parent.record.kind == CredentialKind::Master {
            CredentialKind::Sub
        } else {
            CredentialKind::Child
        };
        if record.kind != expected_kind {
            return Err(IdentityError::InvalidRequest(format!(
                "a credential issued by a {:?} is a {expected_kind:?}",
                parent.record.kind
            )));
        }
        if self.chain_len(parent_id)? >= limits::MAX_CREDENTIAL_DEPTH {
            return Err(IdentityError::DepthExceeded {
                max: limits::MAX_CREDENTIAL_DEPTH,
            });
        }
        if self.live_children(parent_id) >= limits::MAX_LIVE_CHILDREN {
            return Err(IdentityError::LimitReached);
        }
        if !scope_within(&record.scope, &parent.record.scope) {
            return Err(IdentityError::ScopeExceedsParent(record.id));
        }
        Ok(())
    }

    /// Checks and applies `entry`.
    ///
    /// # Errors
    /// As [`IdentityState::check`]; the state is unchanged on error.
    pub fn apply(&mut self, entry: &CredentialEntry) -> Result<(), IdentityError> {
        self.check(entry)?;
        match &entry.op {
            CredentialOp::Issued { record } => {
                self.by_digest.insert(record.digest, record.id);
                self.nodes.insert(
                    record.id,
                    Node {
                        record: record.as_ref().clone(),
                        revoked: false,
                        epoch: record.epoch,
                    },
                );
            }
            CredentialOp::Revoked {
                credential,
                revocation_seq,
            } => {
                if let Some(node) = self.nodes.get_mut(credential) {
                    node.revoked = true;
                }
                self.revocation_seq = *revocation_seq;
            }
            CredentialOp::EpochBumped {
                credential,
                epoch,
                revocation_seq,
            } => {
                if let Some(node) = self.nodes.get_mut(credential) {
                    node.epoch = *epoch;
                }
                self.revocation_seq = *revocation_seq;
            }
            CredentialOp::RestoreRecovered { revocation_seq } => {
                // Atomic: every live master is revoked by this one entry, so a crash can never
                // leave a half-recovered directory that looks healthy.
                for node in self.nodes.values_mut() {
                    if node.record.kind == CredentialKind::Master {
                        node.revoked = true;
                    }
                }
                self.revocation_seq = *revocation_seq;
            }
        }
        Ok(())
    }

    /// Whether the chain ending at `id` is live at `now`: nothing revoked, expired or
    /// epoch-stale from `id` up to its master. Returns the chain.
    ///
    /// # Errors
    /// The first failing link, checked from `id` upwards.
    pub fn chain_live(&self, id: CredentialId, now: WallTime) -> Result<Vec<CredentialId>, IdentityError> {
        let mut chain = Vec::new();
        let mut current = id;
        loop {
            if chain.len() >= limits::MAX_CREDENTIAL_DEPTH {
                return Err(IdentityError::DepthExceeded {
                    max: limits::MAX_CREDENTIAL_DEPTH,
                });
            }
            chain.push(current);
            let node = self
                .nodes
                .get(&current)
                .ok_or_else(|| IdentityError::Unavailable(format!("dangling credential {current}")))?;
            if node.revoked {
                return Err(IdentityError::Revoked(current));
            }
            if node.record.scope.expires_at.is_some_and(|expiry| now >= expiry) {
                return Err(IdentityError::Expired(current));
            }
            let Some(parent_id) = node.record.parent else {
                return Ok(chain);
            };
            let parent = self
                .nodes
                .get(&parent_id)
                .ok_or_else(|| IdentityError::Unavailable(format!("dangling parent {parent_id}")))?;
            if node.record.parent_epoch != parent.epoch {
                return Err(IdentityError::Revoked(current));
            }
            // Scopes are immutable and checked at issuance; re-checked here as defence in
            // depth against a corrupted state, not because they can change.
            if !scope_within(&node.record.scope, &parent.record.scope) {
                return Err(IdentityError::ScopeExceedsParent(current));
            }
            current = parent_id;
        }
    }

    /// Verifies the credential with `digest` at `now`, given the revocation count held in the
    /// OS keychain.
    ///
    /// # Errors
    /// The restore guard first ([`guard_status`]), then the first failing link of the chain.
    pub fn verify(
        &self,
        digest: &CredentialDigest,
        now: WallTime,
        keychain_seq: RevocationSeq,
    ) -> Result<Verified, IdentityError> {
        guard_status(keychain_seq, self.revocation_seq)?;
        let id = *self.by_digest.get(digest).ok_or(IdentityError::Unknown)?;
        let chain = self.chain_live(id, now)?;
        let node = self.nodes.get(&id).ok_or(IdentityError::Unknown)?;
        Ok(Verified {
            credential: id,
            kind: node.record.kind,
            scope: node.record.scope.clone(),
            chain,
        })
    }
}

fn exact_seq(seq: RevocationSeq, next: u64) -> Result<(), IdentityError> {
    if seq.0 == next {
        Ok(())
    } else {
        Err(IdentityError::InvalidRequest(format!(
            "revocation_seq {seq} must be exactly {next}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_relation() {
        let s = RevocationSeq;
        assert_eq!(guard_status(s(3), s(3)), Ok(GuardStatus::InSync));
        assert_eq!(guard_status(s(2), s(3)), Ok(GuardStatus::Lagging));
        assert!(matches!(
            guard_status(s(4), s(3)),
            Err(IdentityError::StaleDataDirectory { .. })
        ));
        assert!(matches!(
            guard_status(s(0), s(3)),
            Err(IdentityError::CounterInconsistent { .. })
        ));
        assert!(matches!(
            guard_status(s(GUARD_CEILING), s(GUARD_CEILING)),
            Err(IdentityError::CounterInconsistent { .. })
        ));
        assert!(matches!(
            guard_status(s(u64::MAX), s(3)),
            Err(IdentityError::CounterInconsistent { .. })
        ));
    }
}
