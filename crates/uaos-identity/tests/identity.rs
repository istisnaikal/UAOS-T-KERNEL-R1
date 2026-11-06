// SPDX-License-Identifier: Apache-2.0

//! Behaviour of scoped credentials, including regression tests for earlier findings.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests: failures should be loud and immediate"
)]

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use uaos_contracts::credential::{
    ActionName, CredentialKind, Label, PatternMatch, PatternValue, ResourceKind, ResourcePattern, Scope, ScopeSet,
};
use uaos_contracts::error::codes;
use uaos_contracts::event::Actor;
use uaos_contracts::id::{CorrelationId, CredentialId, PocketId, PoolId, TypedId};
use uaos_contracts::limits::{self, Millis};
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::{ConfigVersion, RevocationSeq};
use uaos_identity::scope::{ScopeRequest, scope_covers, scope_within};
use uaos_identity::{
    GUARD_CEILING, GuardOutcome, GuardStatus, Identity, IdentityError, IdentityKeys, IssueRequest, Issued, JournalSink,
    MemorySink, Verified, entries_from_journal,
};
use uaos_platform::fs::Fs;
use uaos_platform::keychain::{Keychain, KeychainError};
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::keychain::SimKeychain;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, Rng};
use uaos_state::journal::{FlushPolicy, JOURNAL_DIR, Journal, read_verified};

const INSTALLATION: &str = "inst-test";
const GUARD_ACCOUNT: &str = "inst-test/identity/revocation-seq";
const KEY_ACCOUNT: &str = "inst-test/identity/hmac";
const T0: i128 = 1_760_000_000_000_000_000;
const HOUR: i128 = 3_600_000_000_000;

fn at(offset_hours: i128) -> WallTime {
    WallTime::from_unix_nanos(T0 + offset_hours * HOUR).unwrap()
}

fn cred(n: u8) -> CredentialId {
    CredentialId::from_parts(1, [n; 10])
}

fn pocket(n: u8) -> PocketId {
    PocketId::from_parts(1, [n; 10])
}

fn pool(n: u8) -> PoolId {
    PoolId::from_parts(1, [n; 10])
}

fn action(name: &str) -> ActionName {
    ActionName::new(name).unwrap()
}

fn pattern(kind: ResourceKind, matching: PatternMatch, value: &str) -> ResourcePattern {
    ResourcePattern {
        kind,
        matching,
        value: PatternValue::new(value).unwrap(),
    }
}

fn master_scope() -> Scope {
    Scope {
        actions: ScopeSet::Any,
        resources: ScopeSet::Any,
        pockets: ScopeSet::Any,
        pools: ScopeSet::Any,
        expires_at: None,
    }
}

fn sub_scope(expires_hours: i128) -> Scope {
    Scope {
        actions: ScopeSet::Only([action("model.call"), action("model.count_tokens")].into()),
        resources: ScopeSet::Only([pattern(ResourceKind::Model, PatternMatch::Prefix, "claude-")].into()),
        pockets: ScopeSet::Only([pocket(1)].into()),
        pools: ScopeSet::Any,
        expires_at: Some(at(expires_hours)),
    }
}

fn keys_for(keychain: &Arc<SimKeychain>, credentials_exist: bool) -> Result<IdentityKeys, IdentityError> {
    IdentityKeys::open(keychain.clone(), &SimRng::new(11), INSTALLATION, credentials_exist)
}

fn set_guard(keychain: &SimKeychain, value: u64) {
    keychain.set(GUARD_ACCOUNT, &value.to_be_bytes()).unwrap();
}

struct World {
    keychain: Arc<SimKeychain>,
    keys: IdentityKeys,
    rng: SimRng,
    identity: Identity,
    sink: MemorySink,
}

impl World {
    fn new() -> Self {
        let keychain = Arc::new(SimKeychain::new());
        let keys = keys_for(&keychain, false).unwrap();
        Self {
            keychain,
            keys,
            rng: SimRng::new(11),
            identity: Identity::default(),
            sink: MemorySink::default(),
        }
    }

    fn issue_at(
        &mut self,
        id: CredentialId,
        parent: Option<CredentialId>,
        scope: Scope,
        now: WallTime,
    ) -> Result<Issued, IdentityError> {
        self.identity.issue(
            &mut self.sink,
            &self.keys,
            &self.rng,
            IssueRequest {
                id,
                parent,
                label: Some(Label::new("test").unwrap()),
                scope,
            },
            now,
        )
    }

    fn issue(&mut self, id: CredentialId, parent: Option<CredentialId>, scope: Scope) -> Result<Issued, IdentityError> {
        self.issue_at(id, parent, scope, at(0))
    }

    fn verify(&self, issued: &Issued, now: WallTime) -> Result<Verified, IdentityError> {
        self.identity.verify(&self.keys, &issued.text, now)
    }

    fn revoke(&mut self, id: CredentialId) -> Result<GuardOutcome, IdentityError> {
        self.identity.revoke(&mut self.sink, &mut self.keys, id)
    }

    fn bump(&mut self, id: CredentialId) -> Result<GuardOutcome, IdentityError> {
        self.identity
            .bump_epoch(&mut self.sink, &mut self.keys, id)
            .map(|(_, outcome)| outcome)
    }
}

// ---------------------------------------------------------------------------------------------
// Issuance and verification
// ---------------------------------------------------------------------------------------------

#[test]
fn issued_credentials_verify_with_their_chain_and_scope() {
    let mut w = World::new();
    let master = w.issue(cred(1), None, master_scope()).unwrap();
    let sub = w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap();
    assert_eq!(sub.record.kind, CredentialKind::Sub);
    let verified = w.verify(&sub, at(1)).unwrap();
    assert_eq!(verified.credential, cred(2));
    assert_eq!(verified.chain, vec![cred(2), cred(1)]);
    let request = |resource: Option<(ResourceKind, &'static str)>, pocket_id: Option<PocketId>| ScopeRequest {
        action: "model.call",
        resource,
        pocket: pocket_id,
        pool: None,
    };
    assert!(scope_covers(
        &verified.scope,
        &request(Some((ResourceKind::Model, "claude-sonnet-5-5")), Some(pocket(1)))
    ));
    assert!(!scope_covers(
        &verified.scope,
        &request(Some((ResourceKind::Model, "gpt-5")), Some(pocket(1)))
    ));
    assert_eq!(w.verify(&master, at(1)).unwrap().kind, CredentialKind::Master);
}

#[test]
fn a_restricted_dimension_left_out_of_a_request_is_denied() {
    // "no resource" or "no pocket" must not slip past a restriction.
    let scope = sub_scope(24);
    let base = ScopeRequest {
        action: "model.call",
        resource: Some((ResourceKind::Model, "claude-x")),
        pocket: Some(pocket(1)),
        pool: None,
    };
    assert!(scope_covers(&scope, &base));
    assert!(!scope_covers(&scope, &ScopeRequest { resource: None, ..base }));
    assert!(!scope_covers(&scope, &ScopeRequest { pocket: None, ..base }));
    // A request that spends nothing carries no pool; a pool restriction does not apply.
    let mut pooled = scope.clone();
    pooled.pools = ScopeSet::Only([pool(1)].into());
    assert!(scope_covers(&pooled, &base));
    assert!(!scope_covers(
        &pooled,
        &ScopeRequest {
            pool: Some(pool(2)),
            ..base
        }
    ));
}

#[test]
fn a_child_can_never_exceed_its_parent() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap();
    let mut wider = sub_scope(12);
    wider.resources = ScopeSet::Any;
    assert_eq!(
        w.issue(cred(3), Some(cred(2)), wider).unwrap_err().code(),
        codes::IDENTITY_SCOPE_EXCEEDS_PARENT
    );
    let mut later = sub_scope(48);
    later.resources = ScopeSet::Only([pattern(ResourceKind::Model, PatternMatch::Prefix, "claude-opus")].into());
    assert!(matches!(
        w.issue(cred(4), Some(cred(2)), later),
        Err(IdentityError::ScopeExceedsParent(_))
    ));
    let mut narrower = sub_scope(12);
    narrower.actions = ScopeSet::Only([action("model.call")].into());
    narrower.resources = ScopeSet::Only([pattern(ResourceKind::Model, PatternMatch::Prefix, "claude-opus")].into());
    assert_eq!(
        w.issue(cred(5), Some(cred(2)), narrower).unwrap().record.kind,
        CredentialKind::Child
    );
    assert_eq!(w.sink.entries.len(), 3, "refused issuances are never recorded");
}

#[test]
fn the_chain_is_bounded() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    for depth in 1..limits::MAX_CREDENTIAL_DEPTH {
        let n = u8::try_from(depth).unwrap() + 1;
        w.issue(cred(n), Some(cred(n - 1)), sub_scope(24)).unwrap();
    }
    let last = u8::try_from(limits::MAX_CREDENTIAL_DEPTH).unwrap();
    let err = w.issue(cred(last + 1), Some(cred(last)), sub_scope(24)).unwrap_err();
    assert_eq!(err.code(), codes::IDENTITY_DEPTH_EXCEEDED);
}

#[test]
fn live_children_per_parent_are_bounded() {
    let mut w = World::new();
    w.issue(cred(0), None, master_scope()).unwrap();
    for i in 0..limits::MAX_LIVE_CHILDREN {
        let id = CredentialId::from_parts(1_000 + u64::try_from(i).unwrap(), [7; 10]);
        w.issue(id, Some(cred(0)), sub_scope(24)).unwrap();
    }
    let err = w.issue(cred(250), Some(cred(0)), sub_scope(24)).unwrap_err();
    assert_eq!(err.code(), codes::IDENTITY_LIMIT_REACHED);
}

#[test]
fn issuing_under_a_dead_chain_or_with_an_expired_scope_is_refused() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap();
    w.issue(cred(3), Some(cred(2)), sub_scope(12)).unwrap();
    w.revoke(cred(2)).unwrap();
    assert_eq!(
        w.issue(cred(4), Some(cred(3)), sub_scope(6)).unwrap_err(),
        IdentityError::Revoked(cred(2)),
        "a revoked grandparent kills the chain"
    );
    w.issue(cred(5), Some(cred(1)), sub_scope(24)).unwrap();
    w.issue(cred(6), Some(cred(5)), sub_scope(12)).unwrap();
    w.bump(cred(1)).unwrap();
    assert!(
        w.issue(cred(7), Some(cred(6)), sub_scope(6)).is_err(),
        "an epoch-stale chain cannot issue"
    );
    let err = w.issue_at(cred(8), Some(cred(1)), sub_scope(1), at(2)).unwrap_err();
    assert_eq!(err.code(), codes::IDENTITY_INVALID_REQUEST, "already expired");
    assert_eq!(
        w.bump(cred(2)).unwrap_err().code(),
        codes::IDENTITY_INVALID_REQUEST,
        "revoked: no bump"
    );
}

#[test]
fn request_mistakes_are_user_errors_not_internal_failures() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    let mut no_expiry = sub_scope(24);
    no_expiry.expires_at = None;
    for err in [
        w.issue(cred(2), Some(cred(1)), no_expiry).unwrap_err(),
        w.issue(cred(1), None, master_scope()).unwrap_err(),
        w.issue(cred(3), Some(cred(99)), sub_scope(24)).unwrap_err(),
    ] {
        assert_eq!(err.code(), codes::IDENTITY_INVALID_REQUEST, "{err}");
    }
    w.issue(cred(4), Some(cred(1)), sub_scope(24)).unwrap();
    w.revoke(cred(4)).unwrap();
    assert_eq!(w.revoke(cred(4)).unwrap_err().code(), codes::IDENTITY_INVALID_REQUEST);
    assert!(!w.identity.is_poisoned());
}

#[test]
fn revocation_takes_effect_on_the_next_verify_for_every_descendant() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    let sub_a = w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap();
    let child = w.issue(cred(3), Some(cred(2)), sub_scope(12)).unwrap();
    let sub_b = w.issue(cred(4), Some(cred(1)), sub_scope(24)).unwrap();
    assert_eq!(w.revoke(cred(2)).unwrap(), GuardOutcome::Synced);
    assert_eq!(w.verify(&sub_a, at(1)).unwrap_err(), IdentityError::Revoked(cred(2)));
    assert_eq!(w.verify(&child, at(1)).unwrap_err(), IdentityError::Revoked(cred(2)));
    assert!(w.verify(&sub_b, at(1)).is_ok(), "a sibling is unaffected");
}

#[test]
fn an_epoch_bump_revokes_descendants_but_not_the_credential() {
    let mut w = World::new();
    let master = w.issue(cred(1), None, master_scope()).unwrap();
    let old_sub = w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap();
    let old_child = w.issue(cred(3), Some(cred(2)), sub_scope(12)).unwrap();
    w.bump(cred(1)).unwrap();
    assert!(w.verify(&master, at(1)).is_ok());
    assert!(
        w.verify(&old_sub, at(1)).is_err(),
        "descendant still verifies after epoch bump"
    );
    assert!(w.verify(&old_child, at(1)).is_err());
    let new_sub = w.issue(cred(4), Some(cred(1)), sub_scope(24)).unwrap();
    assert!(w.verify(&new_sub, at(1)).is_ok(), "issued under the new epoch");
}

#[test]
fn expiry_is_checked_up_the_chain_at_and_after_the_instant() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    w.issue(cred(2), Some(cred(1)), sub_scope(10)).unwrap();
    let child = w.issue(cred(3), Some(cred(2)), sub_scope(5)).unwrap();
    assert!(w.verify(&child, at(4)).is_ok());
    assert_eq!(w.verify(&child, at(5)).unwrap_err(), IdentityError::Expired(cred(3)));
}

#[test]
fn malformed_and_unknown_credentials_are_refused_without_echo() {
    let mut w = World::new();
    let issued = w.issue(cred(1), None, master_scope()).unwrap();
    let err = w.identity.verify(&w.keys, "uaos_sk_not-a-key", at(1)).unwrap_err();
    assert_eq!(err.code(), codes::IDENTITY_MALFORMED);
    assert!(!err.to_string().contains("not-a-key"));
    let other_keychain = Arc::new(SimKeychain::new());
    let foreign = keys_for(&other_keychain, false).unwrap();
    assert_eq!(
        Identity::default()
            .verify(&foreign, &issued.text, at(1))
            .unwrap_err()
            .code(),
        codes::IDENTITY_UNKNOWN
    );
}

#[test]
fn the_secret_never_appears_in_records_entries_or_debug_output() {
    let mut w = World::new();
    let issued = w.issue(cred(1), None, master_scope()).unwrap();
    let text = issued.text.as_str().to_owned();
    let body = &text[uaos_identity::PREFIX.len()..];
    let journaled = serde_json::to_string(&w.sink.entries).unwrap();
    assert!(!journaled.contains(body), "the secret reached the journal entry");
    assert!(!format!("{issued:?}").contains(body));
    assert!(!format!("{:?}", w.keys).contains(body));
    assert!(!format!("{:?}", w.identity).contains(body));
}

// ---------------------------------------------------------------------------------------------
// Keys and the restore guard
// ---------------------------------------------------------------------------------------------

#[test]
fn the_identity_key_persists_and_a_lost_key_is_not_silently_replaced() {
    let mut w = World::new();
    let issued = w.issue(cred(1), None, master_scope()).unwrap();
    let reopened = keys_for(&w.keychain, true).unwrap();
    assert!(w.identity.verify(&reopened, &issued.text, at(1)).is_ok());
    w.keychain.delete(KEY_ACCOUNT).unwrap();
    assert_eq!(keys_for(&w.keychain, true).unwrap_err(), IdentityError::KeyLost);
    assert!(
        w.keychain.get(KEY_ACCOUNT).unwrap().is_none(),
        "no replacement key was created"
    );
    w.keychain.set(KEY_ACCOUNT, b"short").unwrap();
    assert_eq!(keys_for(&w.keychain, true).unwrap_err(), IdentityError::KeyLost);
}

#[test]
fn a_restored_data_directory_fails_closed_and_ordinary_writes_cannot_reopen_it() {
    // Revoking or bumping something else must not close the gap.
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    let revoked_later = w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap();
    w.issue(cred(3), Some(cred(1)), sub_scope(24)).unwrap();
    let backup = w.sink.entries.clone();
    w.revoke(cred(2)).unwrap();
    assert_eq!(w.keys.guard(), RevocationSeq(1));

    let mut restored = Identity::replay(&backup).unwrap();
    let stale = restored.verify(&w.keys, &revoked_later.text, at(1)).unwrap_err();
    assert_eq!(
        stale.code(),
        codes::IDENTITY_STALE_DATA_DIR,
        "the revoked key must not resurrect"
    );
    let mut sink = MemorySink::default();
    for refused in [
        restored.revoke(&mut sink, &mut w.keys, cred(3)).unwrap_err(),
        restored.bump_epoch(&mut sink, &mut w.keys, cred(1)).unwrap_err(),
        restored
            .issue(
                &mut sink,
                &w.keys,
                &w.rng,
                IssueRequest {
                    id: cred(9),
                    parent: Some(cred(1)),
                    label: None,
                    scope: sub_scope(24),
                },
                at(1),
            )
            .unwrap_err(),
    ] {
        assert_eq!(refused.code(), codes::IDENTITY_STALE_DATA_DIR, "{refused}");
    }
    assert!(sink.entries.is_empty(), "nothing was recorded on a stale directory");
    assert_eq!(
        restored.verify(&w.keys, &revoked_later.text, at(1)).unwrap_err().code(),
        codes::IDENTITY_STALE_DATA_DIR
    );

    let (masters, outcome) = restored.recover_after_restore(&mut sink, &mut w.keys).unwrap();
    assert_eq!((masters, outcome), (1, GuardOutcome::Synced));
    assert_eq!(sink.entries.len(), 1, "recovery is one atomic entry");
    assert_eq!(
        restored.verify(&w.keys, &revoked_later.text, at(1)).unwrap_err(),
        IdentityError::Revoked(cred(1))
    );
    let new_master = restored
        .issue(
            &mut sink,
            &w.keys,
            &w.rng,
            IssueRequest {
                id: cred(10),
                parent: None,
                label: None,
                scope: master_scope(),
            },
            at(2),
        )
        .unwrap();
    assert!(restored.verify(&w.keys, &new_master.text, at(3)).is_ok());
}

#[test]
fn recovery_is_refused_when_nothing_is_stale() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    let err = w.identity.recover_after_restore(&mut w.sink, &mut w.keys).unwrap_err();
    assert_eq!(err.code(), codes::IDENTITY_INVALID_REQUEST);
}

#[test]
fn a_tampered_or_deleted_counter_fails_closed_and_cannot_block_revocation_silently() {
    let mut w = World::new();
    let master = w.issue(cred(1), None, master_scope()).unwrap();
    w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap();
    w.revoke(cred(2)).unwrap();
    w.issue(cred(3), Some(cred(1)), sub_scope(24)).unwrap();
    w.revoke(cred(3)).unwrap();

    set_guard(&w.keychain, u64::MAX);
    let tampered = keys_for(&w.keychain, true).unwrap();
    assert_eq!(
        w.identity.verify(&tampered, &master.text, at(1)).unwrap_err().code(),
        codes::IDENTITY_COUNTER_INCONSISTENT
    );

    w.keychain.delete(GUARD_ACCOUNT).unwrap();
    let mut deleted = keys_for(&w.keychain, true).unwrap();
    assert_eq!(
        w.identity.verify(&deleted, &master.text, at(1)).unwrap_err().code(),
        codes::IDENTITY_COUNTER_INCONSISTENT,
        "a counter far behind the journal is not trusted"
    );
    assert_eq!(
        w.identity
            .revoke(&mut w.sink, &mut deleted, cred(1))
            .unwrap_err()
            .code(),
        codes::IDENTITY_COUNTER_INCONSISTENT
    );

    w.keychain.set(GUARD_ACCOUNT, b"bad").unwrap();
    let malformed = keys_for(&w.keychain, true).unwrap();
    assert_eq!(malformed.guard(), RevocationSeq(GUARD_CEILING));
    assert!(w.identity.verify(&malformed, &master.text, at(1)).is_err());
}

#[test]
fn an_interrupted_keychain_write_lags_by_one_and_is_repaired() {
    // A transient keychain failure must not force re-issuing every key.
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    let sub = w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap();
    let other = w.issue(cred(3), Some(cred(1)), sub_scope(24)).unwrap();
    w.keychain.fail_next(KeychainError::Denied);
    assert_eq!(
        w.revoke(cred(2)).unwrap(),
        GuardOutcome::Lagging,
        "recorded, counter not raised"
    );
    assert_eq!(w.verify(&sub, at(1)).unwrap_err(), IdentityError::Revoked(cred(2)));
    assert!(
        w.verify(&other, at(1)).is_ok(),
        "verification keeps working while lagging"
    );

    let mut reopened = keys_for(&w.keychain, true).unwrap();
    assert_eq!(reopened.guard(), RevocationSeq(0));
    assert_eq!(w.identity.reconcile(&mut reopened).unwrap(), GuardStatus::Lagging);
    assert_eq!(reopened.guard(), RevocationSeq(1), "repaired");
    assert_eq!(w.identity.reconcile(&mut reopened).unwrap(), GuardStatus::InSync);
}

#[test]
fn a_recording_failure_poisons_until_replayed() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    w.sink.fail_next = Some("disk full".to_owned());
    let err = w.issue(cred(2), Some(cred(1)), sub_scope(24)).unwrap_err();
    assert_eq!(err.code(), codes::IDENTITY_UNAVAILABLE);
    assert!(w.identity.is_poisoned());
    assert!(w.issue(cred(3), Some(cred(1)), sub_scope(24)).is_err());
    let rebuilt = Identity::replay(&w.sink.entries).unwrap();
    assert!(!rebuilt.is_poisoned());
    assert!(
        rebuilt.state().node(cred(2)).is_none(),
        "the failed entry was not recorded"
    );
}

#[test]
fn an_oversized_record_is_refused_without_poisoning() {
    let mut w = World::new();
    w.issue(cred(1), None, master_scope()).unwrap();
    let long = |p: &str, i: usize| format!("{p}{i:0>60}");
    let mut scope = sub_scope(24);
    scope.resources = ScopeSet::Only(
        (0..limits::MAX_SCOPE_ITEMS)
            .map(|i| pattern(ResourceKind::Tool, PatternMatch::Exact, &long("t", i)))
            .collect(),
    );
    scope.actions = ScopeSet::Only((0..limits::MAX_SCOPE_ITEMS).map(|i| action(&long("a", i))).collect());
    assert_eq!(
        w.issue(cred(2), Some(cred(1)), scope).unwrap_err().code(),
        codes::IDENTITY_RECORD_TOO_LARGE
    );
    assert!(!w.identity.is_poisoned());
}

// ---------------------------------------------------------------------------------------------
// Random hierarchies against an independent model
// ---------------------------------------------------------------------------------------------

const ACTIONS: [&str; 3] = ["model.call", "model.count_tokens", "tool.call"];

fn arb_patterns() -> impl Strategy<Value = ScopeSet<ResourcePattern>> {
    let one = (
        prop_oneof![Just(ResourceKind::Model), Just(ResourceKind::Tool)],
        prop_oneof![Just(PatternMatch::Exact), Just(PatternMatch::Prefix)],
        "[ab]{1,2}",
    )
        .prop_map(|(k, m, v)| pattern(k, m, &v));
    prop_oneof![
        1 => Just(ScopeSet::Any),
        2 => proptest::collection::btree_set(one, 0..3).prop_map(ScopeSet::Only),
    ]
}

fn arb_ids(max: u8) -> impl Strategy<Value = BTreeSet<u8>> {
    proptest::collection::btree_set(1u8..=max, 0..3)
}

fn arb_scope() -> impl Strategy<Value = Scope> {
    let actions = prop_oneof![
        1 => Just(ScopeSet::Any),
        2 => proptest::sample::subsequence(ACTIONS.to_vec(), 0..=3)
            .prop_map(|v| ScopeSet::Only(v.into_iter().map(action).collect())),
    ];
    let pockets = prop_oneof![
        1 => Just(ScopeSet::Any),
        2 => arb_ids(3).prop_map(|s| ScopeSet::Only(s.into_iter().map(pocket).collect())),
    ];
    let pools = prop_oneof![
        1 => Just(ScopeSet::Any),
        2 => arb_ids(2).prop_map(|s| ScopeSet::Only(s.into_iter().map(pool).collect())),
    ];
    (actions, arb_patterns(), pockets, pools, 1i128..48).prop_map(|(actions, resources, pockets, pools, hours)| Scope {
        actions,
        resources,
        pockets,
        pools,
        expires_at: Some(at(hours)),
    })
}

#[derive(Debug, Clone)]
enum Op {
    Revoke(usize),
    Bump(usize),
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![(0usize..16).prop_map(Op::Revoke), (0usize..16).prop_map(Op::Bump)]
}

/// Every request over a small universe, for the independent coverage oracle.
fn request_universe() -> Vec<ScopeRequest<'static>> {
    const NAMES: [&str; 6] = ["a", "b", "aa", "ab", "ba", "bb"];
    let mut resources: Vec<Option<(ResourceKind, &'static str)>> = vec![None];
    for kind in [ResourceKind::Model, ResourceKind::Tool] {
        resources.extend(NAMES.iter().map(|n| Some((kind, *n))));
    }
    let pockets = [None, Some(pocket(1)), Some(pocket(2)), Some(pocket(3))];
    let pools = [None, Some(pool(1)), Some(pool(2))];
    let mut out = Vec::new();
    for action in ACTIONS {
        for resource in &resources {
            for pocket_id in pockets {
                for pool_id in pools {
                    out.push(ScopeRequest {
                        action,
                        resource: *resource,
                        pocket: pocket_id,
                        pool: pool_id,
                    });
                }
            }
        }
    }
    out
}

/// Runs one generated hierarchy; returns (credentials issued, credentials that verified).
fn run_case(requests: Vec<(usize, Scope)>, ops: Vec<Op>) -> Result<(usize, usize), TestCaseError> {
    let mut w = World::new();
    let master = w.issue(cred(0), None, master_scope()).unwrap();
    // Model: id -> (parent, text).
    let mut parent_of: BTreeMap<CredentialId, Option<CredentialId>> = BTreeMap::new();
    let mut texts: Vec<(CredentialId, Issued)> = vec![(cred(0), master)];
    parent_of.insert(cred(0), None);
    for (i, (pick, scope)) in requests.into_iter().enumerate() {
        let parent = texts[pick % texts.len()].0;
        let id = cred(u8::try_from(i + 1).unwrap());
        let parent_scope = w.identity.state().node(parent).unwrap().record.scope.clone();
        let within = scope_within(&scope, &parent_scope);
        match w.issue(id, Some(parent), scope) {
            Ok(done) => {
                prop_assert!(within, "issuance accepted a scope outside its parent");
                parent_of.insert(id, Some(parent));
                texts.push((id, done));
            }
            Err(IdentityError::ScopeExceedsParent(_)) => prop_assert!(!within),
            Err(IdentityError::DepthExceeded { .. }) => {}
            Err(other) => prop_assert!(false, "unexpected refusal: {other}"),
        }
    }
    let mut revoked = BTreeSet::new();
    let mut bumped = BTreeSet::new();
    for op in ops {
        match op {
            Op::Revoke(pick) => {
                let id = texts[pick % texts.len()].0;
                if w.revoke(id).is_ok() {
                    revoked.insert(id);
                }
            }
            Op::Bump(pick) => {
                let id = texts[pick % texts.len()].0;
                if w.bump(id).is_ok() {
                    bumped.insert(id);
                }
            }
        }
    }
    let ancestors = |id: CredentialId| {
        let mut out = Vec::new();
        let mut cur = parent_of[&id];
        while let Some(p) = cur {
            out.push(p);
            cur = parent_of[&p];
        }
        out
    };
    let universe = request_universe();
    let mut verified = 0usize;
    for (id, issued) in &texts {
        let strict = ancestors(*id);
        let expected = !revoked.contains(id)
            && !strict.iter().any(|a| revoked.contains(a))
            && !strict.iter().any(|a| bumped.contains(a));
        let actual = w.verify(issued, at(0));
        prop_assert_eq!(
            actual.is_ok(),
            expected,
            "verification disagrees with the model for {}: {:?}",
            id,
            actual
        );
        if let Ok(v) = actual {
            verified += 1;
            // Independent oracle: anything the credential covers, every ancestor covers.
            for ancestor in &strict {
                let a_scope = &w.identity.state().node(*ancestor).unwrap().record.scope;
                for r in &universe {
                    prop_assert!(
                        !scope_covers(&v.scope, r) || scope_covers(a_scope, r),
                        "a credential covers a request its ancestor does not: {:?}",
                        r.action
                    );
                }
            }
        }
    }
    let replayed = Identity::replay(&w.sink.entries).unwrap();
    prop_assert_eq!(replayed.state(), w.identity.state());
    Ok((texts.len(), verified))
}

/// Property cases: 256 per merge; the nightly lane raises it with `UAOS_IDENTITY_CASES`.
#[allow(clippy::disallowed_methods, reason = "test configuration knob, read once")]
fn cases() -> u32 {
    std::env::var("UAOS_IDENTITY_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256)
}

/// Random hierarchies with revocations and epoch bumps agree with an independent model, and
/// nothing a credential covers is outside an ancestor's coverage. The totals guard against a
/// generator that never exercises anything.
#[test]
fn derivations_match_the_model() {
    let mut runner = TestRunner::new(Config {
        cases: cases(),
        ..Config::default()
    });
    let issued = Cell::new(0usize);
    let verified = Cell::new(0usize);
    let strategy = (
        proptest::collection::vec((0usize..16, arb_scope()), 1..12),
        proptest::collection::vec(arb_op(), 0..4),
    );
    runner
        .run(&strategy, |(requests, ops)| {
            let (i, v) = run_case(requests, ops)?;
            issued.set(issued.get() + i);
            verified.set(verified.get() + v);
            Ok(())
        })
        .unwrap();
    let n = usize::try_from(cases()).unwrap();
    assert!(
        issued.get() > 2 * n,
        "generator too narrow: {} issued over {n} cases",
        issued.get()
    );
    assert!(
        verified.get() > n,
        "too few verifications: {} over {n} cases",
        verified.get()
    );
}

// ---------------------------------------------------------------------------------------------
// Journal round trip
// ---------------------------------------------------------------------------------------------

#[test]
fn journal_entries_survive_a_crash_and_replay_to_the_live_state() {
    let fs = SimFs::new();
    fs.create_dir_all(Path::new("/data")).unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SimClock::new(at(0)));
    let rng: Arc<dyn Rng> = Arc::new(SimRng::new(7));
    let open = || {
        Journal::open(
            Arc::new(fs.clone()),
            clock.clone(),
            rng.clone(),
            Path::new("/data"),
            FlushPolicy::Balanced { window: Millis(60_000) },
        )
        .unwrap()
    };
    let mut w = World::new();
    let mut journal = open();
    let live = {
        let mut sink = JournalSink::new(
            &mut journal,
            CorrelationId::from_parts(1, [3; 10]),
            Actor::System,
            ConfigVersion(1),
        );
        let request = |id, parent, scope| IssueRequest {
            id,
            parent,
            label: None,
            scope,
        };
        w.identity
            .issue(
                &mut sink,
                &w.keys,
                &w.rng,
                request(cred(1), None, master_scope()),
                at(0),
            )
            .unwrap();
        w.identity
            .issue(
                &mut sink,
                &w.keys,
                &w.rng,
                request(cred(2), Some(cred(1)), sub_scope(24)),
                at(0),
            )
            .unwrap();
        w.identity.revoke(&mut sink, &mut w.keys, cred(2)).unwrap();
        w.identity.state().clone()
    };
    fs.crash();
    drop(journal);
    let _reopened = open();
    let (records, _) = read_verified(&fs, &Path::new("/data").join(JOURNAL_DIR)).unwrap();
    let entries = entries_from_journal(&records).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(
        Identity::replay(&entries).unwrap().state(),
        &live,
        "every critical entry survived"
    );
}
