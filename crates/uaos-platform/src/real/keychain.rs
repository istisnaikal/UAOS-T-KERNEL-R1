// SPDX-License-Identifier: Apache-2.0

//! The operating system's credential store, through `keyring-core` with an explicitly passed
//! store (never keyring-core's process-global default).

use std::sync::Arc;

use keyring_core::{CredentialStore, Error as KeyringError};
use zeroize::Zeroizing;

use crate::keychain::{Keychain, KeychainError, SERVICE};

/// The native credential store of the current OS.
pub struct OsKeychain {
    store: Arc<CredentialStore>,
    service: String,
    backend: &'static str,
}

impl std::fmt::Debug for OsKeychain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsKeychain")
            .field("service", &self.service)
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

fn map(e: &KeyringError) -> KeychainError {
    match e {
        KeyringError::NoStorageAccess(_) => KeychainError::Denied,
        KeyringError::PlatformFailure(err) => KeychainError::Unavailable(err.to_string()),
        KeyringError::BadEncoding(_) | KeyringError::BadDataFormat(..) => KeychainError::Malformed,
        other => KeychainError::Other(other.to_string()),
    }
}

impl OsKeychain {
    /// Opens the native store for this OS under the UAOS service name.
    ///
    /// # Errors
    /// [`KeychainError::Unavailable`] if the OS has no reachable credential store.
    pub fn native() -> Result<Self, KeychainError> {
        Self::with_service(SERVICE)
    }

    /// Opens the native store under a custom service name (tests use a unique one).
    ///
    /// # Errors
    /// [`KeychainError::Unavailable`] if the OS has no reachable credential store.
    pub fn with_service(service: &str) -> Result<Self, KeychainError> {
        let (store, backend) = native_store()?;
        Ok(Self {
            store,
            service: service.to_owned(),
            backend,
        })
    }

    fn entry(&self, account: &str) -> Result<keyring_core::Entry, KeychainError> {
        self.store.build(&self.service, account, None).map_err(|e| map(&e))
    }
}

#[cfg(windows)]
fn native_store() -> Result<(Arc<CredentialStore>, &'static str), KeychainError> {
    let store: Arc<CredentialStore> = windows_native_keyring_store::Store::new().map_err(|e| map(&e))?;
    Ok((store, "Windows Credential Manager"))
}

#[cfg(target_os = "macos")]
fn native_store() -> Result<(Arc<CredentialStore>, &'static str), KeychainError> {
    let store: Arc<CredentialStore> = apple_native_keyring_store::keychain::Store::new().map_err(|e| map(&e))?;
    Ok((store, "macOS Keychain"))
}

#[cfg(target_os = "linux")]
fn native_store() -> Result<(Arc<CredentialStore>, &'static str), KeychainError> {
    let store: Arc<CredentialStore> = zbus_secret_service_keyring_store::Store::new().map_err(|e| map(&e))?;
    Ok((store, "Secret Service (D-Bus)"))
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn native_store() -> Result<(Arc<CredentialStore>, &'static str), KeychainError> {
    Err(KeychainError::Unavailable(
        "no supported credential store on this OS".to_owned(),
    ))
}

impl Keychain for OsKeychain {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        match self.entry(account)?.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(map(&e)),
        }
    }

    fn set(&self, account: &str, secret: &[u8]) -> Result<(), KeychainError> {
        self.entry(account)?.set_secret(secret).map_err(|e| map(&e))
    }

    fn delete(&self, account: &str) -> Result<bool, KeychainError> {
        match self.entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(KeyringError::NoEntry) => Ok(false),
            Err(e) => Err(map(&e)),
        }
    }

    fn backend(&self) -> &'static str {
        self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes real entries into the OS credential store, so it runs only when explicitly enabled
    /// (`UAOS_TEST_OS_KEYCHAIN=1`). CI enables it on Windows and macOS runners; Linux runners have
    /// no Secret Service daemon.
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "opt-in switch for a test that touches the real OS keychain"
    )]
    fn native_store_conforms() {
        if std::env::var("UAOS_TEST_OS_KEYCHAIN").as_deref() != Ok("1") {
            return;
        }
        let service = format!("uaos-test-{}", std::process::id());
        let keychain = OsKeychain::with_service(&service).unwrap();
        crate::keychain::conformance::run(&keychain, "native");
    }
}
