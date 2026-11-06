// SPDX-License-Identifier: Apache-2.0

//! Pocket keyrings: one conformance suite for every implementation, plus the keychain-backed
//! keyring's persistence, crash ordering and shred guarantees.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::path::PathBuf;
use std::sync::Arc;

use uaos_contracts::error::codes;
use uaos_contracts::id::{PocketId, TypedId};
use uaos_platform::Rng;
use uaos_platform::fs::Fs;
use uaos_platform::keychain::{Keychain, KeychainError};
use uaos_platform::sim::SimRng;
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::keychain::SimKeychain;
use uaos_state::chunks::keyring::{KekVersion, KeychainKeyring, KeyringError, MemoryKeyring, PocketKeyring};
use uaos_state::chunks::{ChunkError, ChunkStore};

const INSTALLATION: &str = "inst-0123";

fn pocket(n: u8) -> PocketId {
    PocketId::from_parts(u64::from(n), [n; 10])
}

fn rng(seed: u64) -> Arc<dyn Rng> {
    Arc::new(SimRng::new(seed))
}

/// Behaviour every `PocketKeyring` must share.
fn conformance(keys: &dyn PocketKeyring) {
    let (a, b) = (pocket(1), pocket(2));
    let cas = keys.cas_key(a).unwrap();
    assert_eq!(
        keys.cas_key(a).unwrap().expose_secret(),
        cas.expose_secret(),
        "content key is stable"
    );
    assert_ne!(
        keys.cas_key(b).unwrap().expose_secret(),
        cas.expose_secret(),
        "pockets do not share keys"
    );

    let (v1, k1) = keys.current_kek(a).unwrap();
    assert_eq!(v1, KekVersion(1));
    assert_eq!(keys.current_kek(a).unwrap().1.expose_secret(), k1.expose_secret());

    let v2 = keys.rotate_kek(a).unwrap();
    assert_eq!(v2, KekVersion(2));
    assert_eq!(keys.current_kek(a).unwrap().0, v2);
    assert_eq!(keys.kek_versions(a).unwrap(), [v1, v2]);
    assert_eq!(
        keys.kek(a, v1).unwrap().expose_secret(),
        k1.expose_secret(),
        "old version usable until retired"
    );

    keys.retire_keks_before(a, v2).unwrap();
    assert_eq!(keys.kek_versions(a).unwrap(), [v2]);
    assert!(matches!(keys.kek(a, v1), Err(KeyringError::Retired)));
}

#[test]
fn memory_keyring_conforms() {
    conformance(&MemoryKeyring::new(rng(1)));
}

#[test]
fn keychain_keyring_conforms() {
    conformance(&KeychainKeyring::new(
        Arc::new(SimKeychain::new()),
        rng(2),
        INSTALLATION,
    ));
}

#[test]
fn keychain_keyring_survives_restart() {
    let keychain = Arc::new(SimKeychain::new());
    let before = KeychainKeyring::new(keychain.clone(), rng(3), INSTALLATION);
    let cas = before.cas_key(pocket(1)).unwrap();
    let (v, kek) = before.current_kek(pocket(1)).unwrap();
    drop(before);

    let after = KeychainKeyring::new(keychain, rng(99), INSTALLATION);
    assert_eq!(after.cas_key(pocket(1)).unwrap().expose_secret(), cas.expose_secret());
    let (v_after, kek_after) = after.current_kek(pocket(1)).unwrap();
    assert_eq!((v_after, kek_after.expose_secret()), (v, kek.expose_secret()));
}

#[test]
fn installations_are_isolated() {
    let keychain = Arc::new(SimKeychain::new());
    let one = KeychainKeyring::new(keychain.clone(), rng(4), "inst-a");
    let two = KeychainKeyring::new(keychain, rng(5), "inst-b");
    assert_ne!(
        one.cas_key(pocket(1)).unwrap().expose_secret(),
        two.cas_key(pocket(1)).unwrap().expose_secret()
    );
}

#[test]
fn crash_between_delete_and_index_update_is_repaired() {
    let keychain = Arc::new(SimKeychain::new());
    let keys = KeychainKeyring::new(keychain.clone(), rng(6), INSTALLATION);
    keys.current_kek(pocket(1)).unwrap();
    keys.rotate_kek(pocket(1)).unwrap();
    // A crash during retirement: the old entry is gone, the index still names it.
    let old = format!("{INSTALLATION}/pocket/{}/kek/1", pocket(1));
    assert!(keychain.delete(&old).unwrap());
    let restarted = KeychainKeyring::new(keychain, rng(7), INSTALLATION);
    assert_eq!(
        restarted.kek_versions(pocket(1)).unwrap(),
        [KekVersion(1), KekVersion(2)]
    );
    assert!(matches!(
        restarted.kek(pocket(1), KekVersion(1)),
        Err(KeyringError::Retired)
    ));
    restarted.retire_keks_before(pocket(1), KekVersion(2)).unwrap();
    assert_eq!(restarted.kek_versions(pocket(1)).unwrap(), [KekVersion(2)]);
}

fn store(fs: &SimFs, keys: Arc<dyn PocketKeyring>, seed: u64) -> ChunkStore {
    ChunkStore::open(Arc::new(fs.clone()), rng(seed), keys, &PathBuf::from("/data")).unwrap()
}

#[test]
fn shredding_over_the_keychain_leaves_no_retired_key_behind() {
    let fs = SimFs::new();
    fs.create_dir_all(&PathBuf::from("/data")).unwrap();
    let keychain = Arc::new(SimKeychain::new());
    let keys: Arc<dyn PocketKeyring> = Arc::new(KeychainKeyring::new(keychain.clone(), rng(8), INSTALLATION));
    let chunks = store(&fs, keys, 8);
    let p = pocket(1);
    let doomed = chunks.put(p, b"forget me").unwrap();
    let kept = chunks.put(p, b"keep me").unwrap();

    let report = chunks.shred(p, doomed).unwrap();
    assert_eq!(chunks.get(p, doomed), Err(ChunkError::Unavailable));
    assert_eq!(chunks.get(p, kept).unwrap(), b"keep me");

    let kek_entries: Vec<String> = keychain
        .accounts()
        .into_iter()
        .filter(|a| a.contains("/kek/"))
        .collect();
    assert_eq!(
        kek_entries,
        [format!("{INSTALLATION}/pocket/{p}/kek/{}", report.kek_version.0)],
        "only the current KEK remains in the keychain"
    );
}

#[test]
fn an_unavailable_keychain_fails_loudly() {
    let fs = SimFs::new();
    fs.create_dir_all(&PathBuf::from("/data")).unwrap();
    let keychain = Arc::new(SimKeychain::new());
    let keys: Arc<dyn PocketKeyring> = Arc::new(KeychainKeyring::new(keychain.clone(), rng(9), INSTALLATION));
    let chunks = store(&fs, keys, 9);
    keychain.fail_next(KeychainError::Unavailable("no session bus".to_owned()));
    let err = chunks.put(pocket(1), b"x").unwrap_err();
    assert!(matches!(err, ChunkError::Keyring(KeyringError::Unavailable(_))));
    assert_eq!(err.code(), codes::STORE_KEYRING_UNAVAILABLE);
}
