// SPDX-License-Identifier: Apache-2.0

//! The identity writer: turns credential operations into recorded entries.
//!
//! As in the ledger, every entry is recorded through an [`IdentitySink`] (normally the journal,
//! as a critical record) **before** the in-memory state changes. A failed recording poisons the
//! writer until it is rebuilt from the journal: the entry may or may not have been recorded, and
//! guessing would let memory and truth diverge.
//!
//! **Restore guard.** Every revocation, epoch bump and restore recovery is journaled first, then
//! the revocation counter in the OS keychain is raised to match. A crash between the two leaves the
//! keychain exactly one behind; [`Identity::reconcile`] repairs that on open. A keychain *ahead* of
//! the journal means the data directory was restored from before a revocation: verification and
//! every write refuse until [`Identity::recover_after_restore`] revokes every live master in one
//! atomic entry.

use std::fmt;
use std::sync::Arc;

use uaos_contracts::credential::{
    CredentialEntry, CredentialKind, CredentialOp, CredentialRecord, CredentialSchema, Label, Scope,
};
use uaos_contracts::digest::CredentialDigest;
use uaos_contracts::id::CredentialId;
use uaos_contracts::limits;
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::{Epoch, RevocationSeq};
use uaos_platform::Rng;
use uaos_platform::crypto::{SecretKey, hmac_sha256};
use uaos_platform::keychain::Keychain;
use zeroize::Zeroizing;

use crate::secret::Secret;
use crate::state::{GUARD_CEILING, GuardStatus, IdentityError, IdentityState, Verified, guard_status};

/// Where identity entries are recorded durably.
pub trait IdentitySink {
    /// Records one entry; returns only once it is durable to the sink's standard.
    ///
    /// # Errors
    /// A description of the failure; the entry may or may not have been recorded.
    fn record(&mut self, entry: &CredentialEntry) -> Result<(), String>;
}

/// An in-memory sink for tests and simulation.
#[derive(Debug, Default)]
pub struct MemorySink {
    /// Entries in recording order.
    pub entries: Vec<CredentialEntry>,
    /// When set, the next `record` fails with this message.
    pub fail_next: Option<String>,
}

impl IdentitySink for MemorySink {
    fn record(&mut self, entry: &CredentialEntry) -> Result<(), String> {
        if let Some(message) = self.fail_next.take() {
            return Err(message);
        }
        self.entries.push(entry.clone());
        Ok(())
    }
}

/// The keychain-held material: the identity key that digests secrets, and the restore-guard
/// counter.
pub struct IdentityKeys {
    hmac: SecretKey,
    keychain: Arc<dyn Keychain>,
    guard_account: String,
    guard: RevocationSeq,
}

impl fmt::Debug for IdentityKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKeys")
            .field("keychain", &self.keychain.backend())
            .field("guard", &self.guard)
            .finish_non_exhaustive()
    }
}

const KEY_LEN: usize = 32;
const GUARD_LEN: usize = 8;

fn keychain_error(e: impl fmt::Display) -> IdentityError {
    IdentityError::KeysUnavailable(e.to_string())
}

impl IdentityKeys {
    /// Loads the identity key and the restore-guard counter.
    ///
    /// The identity key is created only when no credential exists yet
    /// (`credentials_exist == false`). A missing or malformed key while credentials exist is
    /// [`IdentityError::KeyLost`]: creating a new one would silently invalidate every
    /// credential. A malformed counter reads as implausible, so verification refuses
    /// ([`IdentityError::CounterInconsistent`]).
    ///
    /// # Errors
    /// [`IdentityError::KeyLost`], or [`IdentityError::KeysUnavailable`] if the keychain fails.
    pub fn open(
        keychain: Arc<dyn Keychain>,
        rng: &dyn Rng,
        installation: &str,
        credentials_exist: bool,
    ) -> Result<Self, IdentityError> {
        let key_account = format!("{installation}/identity/hmac");
        let guard_account = format!("{installation}/identity/revocation-seq");
        let hmac = match keychain.get(&key_account).map_err(keychain_error)? {
            Some(bytes) => {
                let mut array = Zeroizing::new([0u8; KEY_LEN]);
                if bytes.len() != KEY_LEN {
                    return Err(IdentityError::KeyLost);
                }
                array.copy_from_slice(&bytes);
                SecretKey::from_bytes(*array)
            }
            None if credentials_exist => return Err(IdentityError::KeyLost),
            None => {
                let fresh = SecretKey::generate(rng).map_err(keychain_error)?;
                keychain
                    .set(&key_account, fresh.expose_secret())
                    .map_err(keychain_error)?;
                fresh
            }
        };
        let guard = match keychain.get(&guard_account).map_err(keychain_error)? {
            None => RevocationSeq(0),
            Some(bytes) => match <[u8; GUARD_LEN]>::try_from(bytes.as_slice()) {
                Ok(array) => RevocationSeq(u64::from_be_bytes(array)),
                Err(_) => RevocationSeq(GUARD_CEILING),
            },
        };
        Ok(Self {
            hmac,
            keychain,
            guard_account,
            guard,
        })
    }

    /// The revocation count held in the keychain.
    #[must_use]
    pub fn guard(&self) -> RevocationSeq {
        self.guard
    }

    fn digest(&self, secret: &Secret) -> CredentialDigest {
        CredentialDigest::from_bytes(hmac_sha256(&self.hmac, secret.as_bytes()))
    }

    /// Raises the keychain counter to `to`. Never lowers it.
    fn raise_guard(&mut self, to: RevocationSeq) -> Result<(), IdentityError> {
        if to <= self.guard {
            return Ok(());
        }
        self.keychain
            .set(&self.guard_account, &to.0.to_be_bytes())
            .map_err(keychain_error)?;
        self.guard = to;
        Ok(())
    }
}

/// What to issue.
#[derive(Debug, Clone)]
pub struct IssueRequest {
    /// Identifier for the new credential (from the caller's identifier source).
    pub id: CredentialId,
    /// The issuing credential; `None` issues a master.
    pub parent: Option<CredentialId>,
    /// Optional human-readable label.
    pub label: Option<Label>,
    /// Requested scope; must be within the parent's and expire after `now`.
    pub scope: Scope,
}

/// A freshly issued credential. The text is shown to its holder once and never again.
pub struct Issued {
    /// The text form to hand over.
    pub text: Zeroizing<String>,
    /// The record as journaled.
    pub record: CredentialRecord,
}

impl fmt::Debug for Issued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issued")
            .field("record", &self.record)
            .finish_non_exhaustive()
    }
}

/// What a revoking write left behind in the keychain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardOutcome {
    /// The keychain counter matches the journal.
    Synced,
    /// The entry is recorded and effective, but raising the keychain counter failed. Verification
    /// still works; the next revoking write or [`Identity::reconcile`] repairs it. Report it.
    Lagging,
}

/// The identity: replayed state plus the rules for producing entries.
#[derive(Debug, Default)]
pub struct Identity {
    state: IdentityState,
    poisoned: bool,
}

impl Identity {
    /// Rebuilds the identity from its journaled entries, in order.
    ///
    /// # Errors
    /// [`IdentityError::Unavailable`] naming the first entry that does not apply (a corrupt or
    /// reordered journal).
    pub fn replay(entries: &[CredentialEntry]) -> Result<Self, IdentityError> {
        let mut state = IdentityState::default();
        for (n, entry) in entries.iter().enumerate() {
            state
                .apply(entry)
                .map_err(|e| IdentityError::Unavailable(format!("identity entry {n} does not replay: {e}")))?;
        }
        Ok(Self { state, poisoned: false })
    }

    /// The replayed state.
    #[must_use]
    pub fn state(&self) -> &IdentityState {
        &self.state
    }

    /// Whether a recording failure stopped this writer.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// On open: repairs a keychain counter left one behind by an interrupted write, and reports
    /// how the counter relates to the journal.
    ///
    /// # Errors
    /// [`IdentityError::StaleDataDirectory`] (restore recovery needed),
    /// [`IdentityError::CounterInconsistent`], or a keychain failure during the repair.
    pub fn reconcile(&self, keys: &mut IdentityKeys) -> Result<GuardStatus, IdentityError> {
        let status = guard_status(keys.guard(), self.state.revocation_seq())?;
        if status == GuardStatus::Lagging {
            keys.raise_guard(self.state.revocation_seq())?;
        }
        Ok(status)
    }

    fn ensure_usable(&self) -> Result<(), IdentityError> {
        if self.poisoned {
            Err(IdentityError::Unavailable(
                "an identity recording failed; rebuild from the journal".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    /// Writes are refused on a stale or inconsistent counter: only restore recovery may move a
    /// stale directory forward.
    fn ensure_writable(&self, keys: &IdentityKeys) -> Result<(), IdentityError> {
        self.ensure_usable()?;
        guard_status(keys.guard(), self.state.revocation_seq()).map(|_| ())
    }

    /// Records `entry` and applies it. The state is checked first, so a refused entry is never
    /// recorded; a recording failure poisons the writer.
    fn commit(&mut self, sink: &mut dyn IdentitySink, entry: &CredentialEntry) -> Result<(), IdentityError> {
        self.state.check(entry)?;
        let size = serde_json::to_vec(entry)
            .map_err(|e| IdentityError::Unavailable(e.to_string()))?
            .len();
        if !limits::MAX_INLINE_PAYLOAD.admits(size) {
            return Err(IdentityError::RecordTooLarge);
        }
        if let Err(message) = sink.record(entry) {
            self.poisoned = true;
            return Err(IdentityError::Unavailable(message));
        }
        self.state.apply(entry)
    }

    /// Records a revoking entry, then raises the keychain counter to the journal's.
    fn commit_revoking(
        &mut self,
        sink: &mut dyn IdentitySink,
        keys: &mut IdentityKeys,
        entry: &CredentialEntry,
    ) -> Result<GuardOutcome, IdentityError> {
        self.commit(sink, entry)?;
        Ok(match keys.raise_guard(self.state.revocation_seq()) {
            Ok(()) => GuardOutcome::Synced,
            Err(_) => GuardOutcome::Lagging,
        })
    }

    fn next_seq(&self) -> Result<RevocationSeq, IdentityError> {
        let seq = self.state.revocation_seq();
        seq.0
            .checked_add(1)
            .map(RevocationSeq)
            .ok_or(IdentityError::CounterInconsistent {
                keychain: seq,
                journal: seq,
            })
    }

    /// Issues a credential under `request.parent` at `now`.
    ///
    /// # Errors
    /// [`IdentityError`] if the request breaks a rule: a parent chain that is not live at `now`,
    /// a scope outside the parent's or already expired, depth, limits or size. Also if the
    /// counter is stale or inconsistent, randomness fails, or recording fails.
    pub fn issue(
        &mut self,
        sink: &mut dyn IdentitySink,
        keys: &IdentityKeys,
        rng: &dyn Rng,
        request: IssueRequest,
        now: WallTime,
    ) -> Result<Issued, IdentityError> {
        self.ensure_writable(keys)?;
        if request.scope.expires_at.is_some_and(|expiry| expiry <= now) {
            return Err(IdentityError::InvalidRequest(
                "the requested scope has already expired".to_owned(),
            ));
        }
        let (kind, parent_epoch) = match request.parent {
            None => (CredentialKind::Master, Epoch(0)),
            Some(parent) => {
                let node = self
                    .state
                    .node(parent)
                    .ok_or_else(|| IdentityError::InvalidRequest(format!("unknown parent {parent}")))?;
                let kind = if node.record.kind == CredentialKind::Master {
                    CredentialKind::Sub
                } else {
                    CredentialKind::Child
                };
                let parent_epoch = node.epoch;
                // The whole chain must be usable now; issuing under a dead chain would hand out
                // a secret that can never verify.
                self.state.chain_live(parent, now)?;
                (kind, parent_epoch)
            }
        };
        let secret = Secret::generate(rng).map_err(|e| IdentityError::Unavailable(e.to_string()))?;
        let record = CredentialRecord {
            id: request.id,
            kind,
            parent: request.parent,
            digest: keys.digest(&secret),
            label: request.label,
            scope: request.scope,
            issued_at: now,
            parent_epoch,
            epoch: Epoch(0),
        };
        let entry = CredentialEntry {
            schema: CredentialSchema::V1,
            op: CredentialOp::Issued {
                record: Box::new(record.clone()),
            },
        };
        self.commit(sink, &entry)?;
        Ok(Issued {
            text: secret.encode(),
            record,
        })
    }

    /// Verifies a presented credential at `now`.
    ///
    /// # Errors
    /// [`IdentityError`]: malformed, unknown, revoked, expired, or a stale or inconsistent
    /// revocation counter.
    pub fn verify(&self, keys: &IdentityKeys, presented: &str, now: WallTime) -> Result<Verified, IdentityError> {
        self.ensure_usable()?;
        let secret = Secret::parse(presented).map_err(|_| IdentityError::Malformed)?;
        self.state.verify(&keys.digest(&secret), now, keys.guard())
    }

    /// Revokes one credential; its descendants stop verifying with it.
    ///
    /// # Errors
    /// [`IdentityError`] if the credential is unknown or already revoked, the counter is stale or
    /// inconsistent, or recording fails.
    pub fn revoke(
        &mut self,
        sink: &mut dyn IdentitySink,
        keys: &mut IdentityKeys,
        credential: CredentialId,
    ) -> Result<GuardOutcome, IdentityError> {
        self.ensure_writable(keys)?;
        let entry = CredentialEntry {
            schema: CredentialSchema::V1,
            op: CredentialOp::Revoked {
                credential,
                revocation_seq: self.next_seq()?,
            },
        };
        self.commit_revoking(sink, keys, &entry)
    }

    /// Bumps a credential's epoch: every descendant issued under the previous epoch stops
    /// verifying, while the credential itself stays valid.
    ///
    /// # Errors
    /// As [`Identity::revoke`], and for a revoked credential.
    pub fn bump_epoch(
        &mut self,
        sink: &mut dyn IdentitySink,
        keys: &mut IdentityKeys,
        credential: CredentialId,
    ) -> Result<(Epoch, GuardOutcome), IdentityError> {
        self.ensure_writable(keys)?;
        let node = self
            .state
            .node(credential)
            .ok_or_else(|| IdentityError::InvalidRequest(format!("unknown credential {credential}")))?;
        let epoch = node
            .epoch
            .0
            .checked_add(1)
            .map(Epoch)
            .ok_or_else(|| IdentityError::InvalidRequest("epoch exhausted".to_owned()))?;
        let entry = CredentialEntry {
            schema: CredentialSchema::V1,
            op: CredentialOp::EpochBumped {
                credential,
                epoch,
                revocation_seq: self.next_seq()?,
            },
        };
        let outcome = self.commit_revoking(sink, keys, &entry)?;
        Ok((epoch, outcome))
    }

    /// For a data directory older than the latest revocation: one atomic entry revokes every live
    /// master and catches the journal up with the keychain. Every credential then fails to verify
    /// until the maintainer issues a new master and new keys. Returns the number of masters
    /// revoked.
    ///
    /// # Errors
    /// [`IdentityError::InvalidRequest`] if the directory is not stale; a counter that is
    /// inconsistent rather than ahead; recording failures.
    pub fn recover_after_restore(
        &mut self,
        sink: &mut dyn IdentitySink,
        keys: &mut IdentityKeys,
    ) -> Result<(usize, GuardOutcome), IdentityError> {
        self.ensure_usable()?;
        match guard_status(keys.guard(), self.state.revocation_seq()) {
            Err(IdentityError::StaleDataDirectory { .. }) => {}
            Err(other) => return Err(other),
            Ok(_) => {
                return Err(IdentityError::InvalidRequest(
                    "the data directory is not stale; nothing to recover".to_owned(),
                ));
            }
        }
        let seq = keys
            .guard()
            .0
            .checked_add(1)
            .map(RevocationSeq)
            .ok_or(IdentityError::CounterInconsistent {
                keychain: keys.guard(),
                journal: self.state.revocation_seq(),
            })?;
        let masters = self
            .state
            .nodes()
            .filter(|n| n.record.kind == CredentialKind::Master && !n.revoked)
            .count();
        let entry = CredentialEntry {
            schema: CredentialSchema::V1,
            op: CredentialOp::RestoreRecovered { revocation_seq: seq },
        };
        let outcome = self.commit_revoking(sink, keys, &entry)?;
        Ok((masters, outcome))
    }
}
