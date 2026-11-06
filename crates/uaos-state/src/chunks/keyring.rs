// SPDX-License-Identifier: Apache-2.0

//! Pocket key management interface.
//!
//! Each pocket has two kinds of key:
//! * a **content-addressing key** (stable): chunk references are `HMAC(cas_key, plaintext)`,
//!   so equal content in different pockets is unlinkable and, once a pocket's keys are gone,
//!   nobody can confirm guesses about its former content;
//! * versioned **key-encryption keys (KEKs)** that wrap every chunk's random data key.
//!   Shredding a chunk rotates the KEK: survivors are re-wrapped under the new version and the
//!   old versions are destroyed, so a stale copy of the shredded chunk's wrapped key (a backup,
//!   an SSD remnant) can no longer be unwrapped.
//!
//! The production keyring (OS keychain) implements this trait; [`MemoryKeyring`] is the
//! deterministic double used by tests and simulation.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use uaos_contracts::id::PocketId;
use uaos_platform::crypto::SecretKey;
use uaos_platform::{PlatformError, Rng};

/// Version number of a pocket's key-encryption key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KekVersion(pub u32);

/// Keyring failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyringError {
    /// The requested KEK version no longer exists (retired after a shred).
    #[error("key version retired")]
    Retired,
    /// The keyring backend is unreachable or refused access.
    #[error("keyring unavailable: {0}")]
    Unavailable(String),
    /// Key generation failed.
    #[error("key generation failed: {0}")]
    Platform(PlatformError),
}

/// Per-pocket key storage used by the chunk store.
pub trait PocketKeyring: Send + Sync + fmt::Debug {
    /// The pocket's content-addressing key, created on first use.
    ///
    /// # Errors
    /// [`KeyringError`] if the backend fails.
    fn cas_key(&self, pocket: PocketId) -> Result<Arc<SecretKey>, KeyringError>;

    /// The pocket's current KEK, created on first use.
    ///
    /// # Errors
    /// [`KeyringError`] if the backend fails.
    fn current_kek(&self, pocket: PocketId) -> Result<(KekVersion, Arc<SecretKey>), KeyringError>;

    /// A specific KEK version.
    ///
    /// # Errors
    /// [`KeyringError::Retired`] if that version was destroyed.
    fn kek(&self, pocket: PocketId, version: KekVersion) -> Result<Arc<SecretKey>, KeyringError>;

    /// Creates a new current KEK version; older versions stay usable until retired.
    ///
    /// # Errors
    /// [`KeyringError`] if the backend fails.
    fn rotate_kek(&self, pocket: PocketId) -> Result<KekVersion, KeyringError>;

    /// Destroys every KEK version older than `keep_from`.
    ///
    /// # Errors
    /// [`KeyringError`] if the backend fails.
    fn retire_keks_before(&self, pocket: PocketId, keep_from: KekVersion) -> Result<(), KeyringError>;

    /// Live KEK versions, ascending. More than one means a rotation is unfinished.
    ///
    /// # Errors
    /// [`KeyringError`] if the backend fails.
    fn kek_versions(&self, pocket: PocketId) -> Result<Vec<KekVersion>, KeyringError>;
}

#[derive(Debug, Default)]
struct PocketKeys {
    cas: Option<Arc<SecretKey>>,
    keks: BTreeMap<KekVersion, Arc<SecretKey>>,
}

/// In-memory keyring for tests and deterministic simulation. Survives simulated process
/// crashes when the same instance is kept, like an OS keychain. Never injected in production.
#[derive(Debug)]
pub struct MemoryKeyring {
    rng: Arc<dyn Rng>,
    pockets: Mutex<BTreeMap<PocketId, PocketKeys>>,
}

impl MemoryKeyring {
    /// Creates an empty keyring drawing key material from `rng`.
    #[must_use]
    pub fn new(rng: Arc<dyn Rng>) -> Self {
        Self {
            rng,
            pockets: Mutex::new(BTreeMap::new()),
        }
    }

    fn with<T>(
        &self,
        pocket: PocketId,
        f: impl FnOnce(&mut PocketKeys, &dyn Rng) -> Result<T, KeyringError>,
    ) -> Result<T, KeyringError> {
        let mut pockets = self.pockets.lock().unwrap_or_else(PoisonError::into_inner);
        f(pockets.entry(pocket).or_default(), self.rng.as_ref())
    }
}

fn fresh(rng: &dyn Rng) -> Result<Arc<SecretKey>, KeyringError> {
    SecretKey::generate(rng).map(Arc::new).map_err(KeyringError::Platform)
}

impl PocketKeyring for MemoryKeyring {
    fn cas_key(&self, pocket: PocketId) -> Result<Arc<SecretKey>, KeyringError> {
        self.with(pocket, |p, rng| {
            if let Some(k) = &p.cas {
                return Ok(Arc::clone(k));
            }
            let k = fresh(rng)?;
            p.cas = Some(Arc::clone(&k));
            Ok(k)
        })
    }

    fn current_kek(&self, pocket: PocketId) -> Result<(KekVersion, Arc<SecretKey>), KeyringError> {
        self.with(pocket, |p, rng| {
            if let Some((v, k)) = p.keks.iter().next_back() {
                return Ok((*v, Arc::clone(k)));
            }
            let k = fresh(rng)?;
            p.keks.insert(KekVersion(1), Arc::clone(&k));
            Ok((KekVersion(1), k))
        })
    }

    fn kek(&self, pocket: PocketId, version: KekVersion) -> Result<Arc<SecretKey>, KeyringError> {
        self.with(pocket, |p, _| {
            p.keks.get(&version).map(Arc::clone).ok_or(KeyringError::Retired)
        })
    }

    fn rotate_kek(&self, pocket: PocketId) -> Result<KekVersion, KeyringError> {
        self.with(pocket, |p, rng| {
            let next = KekVersion(p.keks.keys().next_back().map_or(1, |v| v.0.saturating_add(1)));
            p.keks.insert(next, fresh(rng)?);
            Ok(next)
        })
    }

    fn retire_keks_before(&self, pocket: PocketId, keep_from: KekVersion) -> Result<(), KeyringError> {
        self.with(pocket, |p, _| {
            p.keks.retain(|v, _| *v >= keep_from);
            Ok(())
        })
    }

    fn kek_versions(&self, pocket: PocketId) -> Result<Vec<KekVersion>, KeyringError> {
        self.with(pocket, |p, _| Ok(p.keks.keys().copied().collect()))
    }
}

/// Production keyring: pocket keys live in the OS keychain.
///
/// Entries, under one installation (normally the journal id):
/// `<installation>/pocket/<pocket>/cas`, `…/kek/<version>`, and `…/kek-index`, the ascending list
/// of live versions. Ordering keeps every crash safe:
/// * rotation stores the new KEK, then adds it to the index (a crash leaves an unindexed entry
///   that the next rotation overwrites);
/// * retirement deletes the old KEKs, then rewrites the index (a crash leaves an index naming a
///   deleted version, which reads as retired and is cleaned by the next retirement).
///
/// Keys are cached in memory after first use; one process owns a data directory (journal lock).
#[derive(Debug)]
pub struct KeychainKeyring {
    keychain: Arc<dyn uaos_platform::keychain::Keychain>,
    rng: Arc<dyn Rng>,
    installation: String,
    cache: Mutex<BTreeMap<String, Arc<SecretKey>>>,
}

fn keychain_err(e: &uaos_platform::keychain::KeychainError) -> KeyringError {
    KeyringError::Unavailable(e.to_string())
}

impl KeychainKeyring {
    /// Creates a keyring for one installation (data directory).
    #[must_use]
    pub fn new(keychain: Arc<dyn uaos_platform::keychain::Keychain>, rng: Arc<dyn Rng>, installation: &str) -> Self {
        Self {
            keychain,
            rng,
            installation: installation.to_owned(),
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    fn account(&self, pocket: PocketId, item: &str) -> String {
        format!("{}/pocket/{pocket}/{item}", self.installation)
    }

    fn cached(&self, account: &str) -> Option<Arc<SecretKey>> {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(account)
            .map(Arc::clone)
    }

    fn remember(&self, account: String, key: &Arc<SecretKey>) {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(account, Arc::clone(key));
    }

    fn forget(&self, account: &str) {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(account);
    }

    /// Loads a key, or `None` if the entry does not exist.
    fn load(&self, account: &str) -> Result<Option<Arc<SecretKey>>, KeyringError> {
        if let Some(k) = self.cached(account) {
            return Ok(Some(k));
        }
        let Some(bytes) = self.keychain.get(account).map_err(|e| keychain_err(&e))? else {
            return Ok(None);
        };
        let raw: [u8; uaos_platform::crypto::KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeyringError::Unavailable("a stored key has the wrong length".to_owned()))?;
        let key = Arc::new(SecretKey::from_bytes(raw));
        self.remember(account.to_owned(), &key);
        Ok(Some(key))
    }

    fn create(&self, account: String) -> Result<Arc<SecretKey>, KeyringError> {
        let key = fresh(self.rng.as_ref())?;
        self.keychain
            .set(&account, key.expose_secret())
            .map_err(|e| keychain_err(&e))?;
        self.remember(account, &key);
        Ok(key)
    }

    fn index(&self, pocket: PocketId) -> Result<Vec<KekVersion>, KeyringError> {
        let Some(bytes) = self
            .keychain
            .get(&self.account(pocket, "kek-index"))
            .map_err(|e| keychain_err(&e))?
        else {
            return Ok(Vec::new());
        };
        let text =
            std::str::from_utf8(&bytes).map_err(|_| KeyringError::Unavailable("malformed key index".to_owned()))?;
        let mut versions = text
            .split(',')
            .filter(|v| !v.is_empty())
            .map(|v| {
                v.parse()
                    .map(KekVersion)
                    .map_err(|_| KeyringError::Unavailable("malformed key index".to_owned()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        versions.sort_unstable();
        versions.dedup();
        Ok(versions)
    }

    fn store_index(&self, pocket: PocketId, versions: &[KekVersion]) -> Result<(), KeyringError> {
        let text = versions.iter().map(|v| v.0.to_string()).collect::<Vec<_>>().join(",");
        self.keychain
            .set(&self.account(pocket, "kek-index"), text.as_bytes())
            .map_err(|e| keychain_err(&e))
    }

    fn kek_account(&self, pocket: PocketId, version: KekVersion) -> String {
        self.account(pocket, &format!("kek/{}", version.0))
    }
}

impl PocketKeyring for KeychainKeyring {
    fn cas_key(&self, pocket: PocketId) -> Result<Arc<SecretKey>, KeyringError> {
        let account = self.account(pocket, "cas");
        match self.load(&account)? {
            Some(k) => Ok(k),
            None => self.create(account),
        }
    }

    fn current_kek(&self, pocket: PocketId) -> Result<(KekVersion, Arc<SecretKey>), KeyringError> {
        if let Some(&current) = self.index(pocket)?.last() {
            return Ok((current, self.kek(pocket, current)?));
        }
        let first = KekVersion(1);
        let key = self.create(self.kek_account(pocket, first))?;
        self.store_index(pocket, &[first])?;
        Ok((first, key))
    }

    fn kek(&self, pocket: PocketId, version: KekVersion) -> Result<Arc<SecretKey>, KeyringError> {
        self.load(&self.kek_account(pocket, version))?
            .ok_or(KeyringError::Retired)
    }

    fn rotate_kek(&self, pocket: PocketId) -> Result<KekVersion, KeyringError> {
        let mut versions = self.index(pocket)?;
        let next = KekVersion(versions.last().map_or(1, |v| v.0.saturating_add(1)));
        self.create(self.kek_account(pocket, next))?;
        versions.push(next);
        self.store_index(pocket, &versions)?;
        Ok(next)
    }

    fn retire_keks_before(&self, pocket: PocketId, keep_from: KekVersion) -> Result<(), KeyringError> {
        let versions = self.index(pocket)?;
        for &old in versions.iter().filter(|v| **v < keep_from) {
            let account = self.kek_account(pocket, old);
            self.keychain.delete(&account).map_err(|e| keychain_err(&e))?;
            self.forget(&account);
        }
        let live: Vec<KekVersion> = versions.into_iter().filter(|v| *v >= keep_from).collect();
        self.store_index(pocket, &live)
    }

    fn kek_versions(&self, pocket: PocketId) -> Result<Vec<KekVersion>, KeyringError> {
        self.index(pocket)
    }
}
