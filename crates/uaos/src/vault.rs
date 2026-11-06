// SPDX-License-Identifier: Apache-2.0

//! How the CLI reports an OS keychain failure. A failure the host causes, with no keychain there, a
//! locked one, or access refused, is a setup problem: `CLI_KEYCHAIN_UNAVAILABLE`, exit
//! 3. Anything else a keychain reports is `CLI_KEYCHAIN_FAILED`, exit 1.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use uaos_contracts::error::codes;
use uaos_platform::keychain::{Keychain, KeychainError};
use zeroize::Zeroizing;

use crate::Failed;

/// The failure for `e`, from the keychain named `backend`.
pub(crate) fn failed(backend: &str, e: &KeychainError) -> Failed {
    let code = match e {
        KeychainError::Unavailable(_) | KeychainError::Denied => codes::CLI_KEYCHAIN_UNAVAILABLE,
        KeychainError::Malformed | KeychainError::Other(_) => codes::CLI_KEYCHAIN_FAILED,
    };
    Failed::new(code, format!("{backend}: {e}"))
}

/// A keychain that keeps the first failure it returned, so a caller that receives only a
/// failure's text, such as the identity layer's, can still be reported by its kind.
pub(crate) struct Watched {
    inner: Arc<dyn Keychain>,
    first: Mutex<Option<KeychainError>>,
}

impl fmt::Debug for Watched {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Watched")
            .field("backend", &self.inner.backend())
            .finish_non_exhaustive()
    }
}

impl Watched {
    pub(crate) fn new(inner: Arc<dyn Keychain>) -> Self {
        Self {
            inner,
            first: Mutex::new(None),
        }
    }

    /// The first failure, as the CLI reports it; `None` if every call succeeded.
    pub(crate) fn failure(&self) -> Option<Failed> {
        let first = self.first.lock().unwrap_or_else(PoisonError::into_inner);
        first.as_ref().map(|e| failed(self.inner.backend(), e))
    }

    fn seen<T>(&self, result: Result<T, KeychainError>) -> Result<T, KeychainError> {
        if let Err(e) = &result {
            let mut first = self.first.lock().unwrap_or_else(PoisonError::into_inner);
            if first.is_none() {
                *first = Some(e.clone());
            }
        }
        result
    }
}

impl Keychain for Watched {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        self.seen(self.inner.get(account))
    }

    fn set(&self, account: &str, secret: &[u8]) -> Result<(), KeychainError> {
        self.seen(self.inner.set(account, secret))
    }

    fn delete(&self, account: &str) -> Result<bool, KeychainError> {
        self.seen(self.inner.delete(account))
    }

    fn backend(&self) -> &'static str {
        self.inner.backend()
    }
}
