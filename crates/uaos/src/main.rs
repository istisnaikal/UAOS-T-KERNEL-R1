// SPDX-License-Identifier: Apache-2.0

//! The `uaos` binary. The composition root reads the process's arguments and the environment
//! variables it uses once, here, builds the real file system, keychain, clock and randomness, and
//! hands them to [`uaos::run`]; nothing below reads the environment (`clippy.toml`'s owner note for
//! `std::env`).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{IsTerminal as _, Read as _};
use std::process::ExitCode;
use std::sync::Arc;

use uaos::{Invocation, Os, reads_variable, run};
use uaos_contracts::id::CorrelationId;
use uaos_platform::IdSource;
use uaos_platform::keychain::{Keychain, KeychainError};
use uaos_platform::real::fs::OsFs;
use uaos_platform::real::keychain::OsKeychain;
use uaos_platform::real::{OsRng, SystemClock};
use zeroize::Zeroizing;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    // Only the variables the binary reads, and only those whose name and value are text.
    let env: BTreeMap<String, String> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .filter(|(k, _)| reads_variable(k))
        .collect();
    let ids = IdSource::new(SystemClock::new(), OsRng);
    let Ok(correlation) = ids.next::<CorrelationId>() else {
        // The exit code says it all if standard error is closed too.
        let _reported = emit(
            std::io::stderr().lock(),
            "error: the system clock or randomness is unavailable\n",
        );
        return ExitCode::from(1);
    };
    // Where no OS keychain is reachable, every keychain call says so; nothing falls back silently.
    // The passphrase vault for such hosts is not built yet.
    let keychain: Arc<dyn Keychain> = match OsKeychain::native() {
        Ok(k) => Arc::new(k),
        // The reason alone: every call wraps it in `KeychainError::Unavailable` again.
        Err(KeychainError::Unavailable(why)) => Arc::new(Unavailable(why)),
        Err(other) => Arc::new(Unavailable(other.to_string())),
    };
    let outcome = run(&Invocation {
        args,
        env,
        fs: Arc::new(OsFs),
        correlation,
        os: Os::current(),
        keychain,
        clock: Arc::new(SystemClock::new()),
        rng: Arc::new(OsRng),
        stdin: Arc::new(|| {
            // One byte past the longest key and its line end: enough to refuse a longer input
            // without reading all of it (`< /dev/zero` ends), and the buffer never grows, so no
            // reallocation leaves a copy of the key behind.
            let limit = uaos::keys::MAX_KEY_LEN + 3;
            let mut bytes = Vec::with_capacity(limit);
            std::io::stdin()
                .lock()
                .take(u64::try_from(limit).unwrap_or(u64::MAX))
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        }),
        stdin_is_terminal: std::io::stdin().is_terminal(),
    });
    let written = emit(std::io::stdout().lock(), &outcome.stdout) & emit(std::io::stderr().lock(), &outcome.stderr);
    // A command that succeeded but whose output could not be written did not reach its caller:
    // exit 1 (internal). A failed command keeps its own code.
    if !written && outcome.exit_code == 0 {
        return ExitCode::from(1);
    }
    ExitCode::from(outcome.exit_code)
}

/// Writes `text` and flushes; whether it got through.
fn emit(mut out: impl std::io::Write, text: &str) -> bool {
    text.is_empty() || out.write_all(text.as_bytes()).and_then(|()| out.flush()).is_ok()
}

/// The keychain on a host that has none: every call fails with the reason.
#[derive(Debug)]
struct Unavailable(String);

impl Keychain for Unavailable {
    fn get(&self, _account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        Err(KeychainError::Unavailable(self.0.clone()))
    }

    fn set(&self, _account: &str, _secret: &[u8]) -> Result<(), KeychainError> {
        Err(KeychainError::Unavailable(self.0.clone()))
    }

    fn delete(&self, _account: &str) -> Result<bool, KeychainError> {
        Err(KeychainError::Unavailable(self.0.clone()))
    }

    fn backend(&self) -> &'static str {
        "no OS keychain"
    }
}
