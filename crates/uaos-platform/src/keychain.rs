// SPDX-License-Identifier: Apache-2.0

//! OS keychain boundary.
//!
//! Secrets UAOS must keep across restarts — pocket keys, provider API keys — live in the
//! operating system's credential store, never in the data directory. The interface is narrow on
//! purpose (get / set / delete by account name under one service), so the simulated keychain can
//! model it exactly and every user of it can be tested without touching a real credential store.

use std::fmt;

use zeroize::Zeroizing;

/// Service name under which every UAOS entry is stored.
pub const SERVICE: &str = "uaos";

/// Keychain failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeychainError {
    /// No credential store is reachable (e.g. no Secret Service on a headless Linux host).
    #[error("the OS keychain is not available: {0}")]
    Unavailable(String),
    /// The user or OS refused access.
    #[error("access to the OS keychain was denied")]
    Denied,
    /// An entry exists but its content is not what UAOS stored.
    #[error("a keychain entry is malformed")]
    Malformed,
    /// Any other credential-store failure.
    #[error("keychain error: {0}")]
    Other(String),
}

/// A credential store holding binary secrets by account name.
pub trait Keychain: Send + Sync + fmt::Debug {
    /// Reads a secret; `None` if there is no such entry.
    ///
    /// # Errors
    /// [`KeychainError`] if the store fails.
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError>;

    /// Creates or replaces a secret.
    ///
    /// # Errors
    /// [`KeychainError`] if the store fails.
    fn set(&self, account: &str, secret: &[u8]) -> Result<(), KeychainError>;

    /// Deletes a secret; returns whether it existed.
    ///
    /// # Errors
    /// [`KeychainError`] if the store fails.
    fn delete(&self, account: &str) -> Result<bool, KeychainError>;

    /// Human-readable backend name, for `uaos doctor`.
    fn backend(&self) -> &'static str;
}

#[cfg(test)]
pub(crate) mod conformance {
    //! One scenario for every [`Keychain`]: the simulation must agree with real stores.

    use super::Keychain;

    pub(crate) fn run(keychain: &dyn Keychain, prefix: &str) {
        let account = format!("{prefix}/conformance/ü ş ı");
        let read = || keychain.get(&account).unwrap().map(|secret| secret.to_vec());
        let binary: Vec<u8> = (0..=255u8).collect();
        assert_eq!(read(), None);
        assert!(
            !keychain.delete(&account).unwrap(),
            "deleting a missing entry reports false"
        );
        keychain.set(&account, &binary).unwrap();
        assert_eq!(read(), Some(binary));
        keychain.set(&account, b"replaced").unwrap();
        assert_eq!(read(), Some(b"replaced".to_vec()));
        assert!(keychain.delete(&account).unwrap());
        assert_eq!(read(), None);
    }
}
