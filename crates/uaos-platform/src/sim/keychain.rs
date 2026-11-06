// SPDX-License-Identifier: Apache-2.0

//! In-memory keychain for tests and deterministic simulation. Keep the same instance across a
//! simulated crash to model the OS keychain surviving process death.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use zeroize::Zeroizing;

use crate::keychain::{Keychain, KeychainError};

#[derive(Debug, Default)]
struct State {
    entries: BTreeMap<String, Vec<u8>>,
    fail_next: Option<KeychainError>,
}

/// Deterministic, fault-injecting keychain. Never injected in production.
#[derive(Debug, Default)]
pub struct SimKeychain {
    state: Mutex<State>,
}

impl SimKeychain {
    /// Creates an empty keychain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes the next operation fail with `error`.
    pub fn fail_next(&self, error: KeychainError) {
        self.lock().fail_next = Some(error);
    }

    /// Account names currently stored, sorted (test inspection).
    #[must_use]
    pub fn accounts(&self) -> Vec<String> {
        self.lock().entries.keys().cloned().collect()
    }

    fn take_fault(state: &mut State) -> Result<(), KeychainError> {
        state.fail_next.take().map_or(Ok(()), Err)
    }
}

impl Keychain for SimKeychain {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        let mut s = self.lock();
        Self::take_fault(&mut s)?;
        Ok(s.entries.get(account).cloned().map(Zeroizing::new))
    }

    fn set(&self, account: &str, secret: &[u8]) -> Result<(), KeychainError> {
        let mut s = self.lock();
        Self::take_fault(&mut s)?;
        s.entries.insert(account.to_owned(), secret.to_vec());
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<bool, KeychainError> {
        let mut s = self.lock();
        Self::take_fault(&mut s)?;
        Ok(s.entries.remove(account).is_some())
    }

    fn backend(&self) -> &'static str {
        "simulated"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conforms() {
        crate::keychain::conformance::run(&SimKeychain::new(), "sim");
    }

    #[test]
    fn injected_faults_fire_once() {
        let k = SimKeychain::new();
        k.fail_next(KeychainError::Denied);
        assert_eq!(k.set("a", b"x"), Err(KeychainError::Denied));
        assert!(k.set("a", b"x").is_ok());
    }
}
