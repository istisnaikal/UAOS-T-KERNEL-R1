// SPDX-License-Identifier: Apache-2.0

//! `uaos doctor`, offline: the data directory, the configuration, the journal, the kernel stop, the
//! keychain and the provider keys. It reads and changes nothing, and contacts nothing beyond the OS
//! keychain. Every check reports ok, warn or fail, and details never hold
//! a secret.

use std::collections::BTreeMap;
use std::path::Path;

use uaos_contracts::cli::{CheckStatus, DoctorCheck};
use uaos_platform::fs::{Fs, FsError};
use uaos_platform::keychain::Keychain;

use crate::{config, home, keys};

/// Folders a sync client copies to other machines: a data directory there would leave the
/// machine (red line 1).
const SYNCED: [&str; 5] = ["Dropbox", "OneDrive", "iCloud", "Google Drive", "Mobile Documents"];

fn check(name: &str, status: CheckStatus, detail: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.to_owned(),
        status,
        detail: detail.into(),
    }
}

/// Every check, in a fixed order.
pub(crate) fn run(
    fs: &dyn Fs,
    keychain: &dyn Keychain,
    data_dir: &Path,
    env: &BTreeMap<String, String>,
) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    if !data_dir_checks(fs, data_dir, &mut checks) {
        return checks;
    }
    checks.push(config_check(fs, data_dir));
    let journal = journal_checks(fs, data_dir, &mut checks);
    keychain_checks(fs, keychain, data_dir, journal.as_ref(), &mut checks);
    checks.push(tls_check(env));
    checks
}

/// The data directory exists, is private and is not synced; `false` when it does not exist.
fn data_dir_checks(fs: &dyn Fs, data_dir: &Path, checks: &mut Vec<DoctorCheck>) -> bool {
    use CheckStatus::{Fail, Ok, Warn};
    match fs.list_dir(data_dir) {
        Result::Ok(_) => checks.push(check("data_dir", Ok, "the data directory exists")),
        Err(FsError::NotFound { .. }) => {
            checks.push(check(
                "data_dir",
                Fail,
                "the data directory does not exist; run `uaos init`",
            ));
            return false;
        }
        Err(e) => {
            checks.push(check("data_dir", Fail, format!("the data directory: {e}")));
            return false;
        }
    }
    checks.push(match fs.private_dir(data_dir) {
        Result::Ok(Some(true)) => check("data_dir.private", Ok, "readable only by its owner"),
        Result::Ok(Some(false)) => check(
            "data_dir.private",
            Fail,
            "others may read it; restrict it to its owner (`chmod 700`)",
        ),
        Result::Ok(None) => check(
            "data_dir.private",
            Ok,
            "not checked on this system: its permissions are inherited from the user's own folder",
        ),
        Err(e) => check("data_dir.private", Fail, format!("its permissions: {e}")),
    });
    let shown = data_dir.to_string_lossy();
    checks.push(match SYNCED.iter().find(|s| shown.contains(*s)) {
        Some(sync) => check(
            "data_dir.synced",
            Warn,
            format!("it is inside a {sync} folder, which copies it to other machines; move it"),
        ),
        None => check("data_dir.synced", Ok, "not inside a known sync folder"),
    });
    true
}

fn config_check(fs: &dyn Fs, data_dir: &Path) -> DoctorCheck {
    use CheckStatus::{Fail, Ok, Warn};
    match fs.read(&data_dir.join(config::FILE_NAME)) {
        Result::Ok(bytes) => match config::load(Some(&bytes), &BTreeMap::new()) {
            Result::Ok(_) => check("config", Ok, "valid"),
            Err(config::Refusal::HoldsSecret { classes, .. }) => check(
                "config",
                Fail,
                format!("it holds what looks like a secret ({})", classes.join(", ")),
            ),
            Err(config::Refusal::Invalid(why)) => check("config", Fail, why),
            Err(config::Refusal::Scanner) => check("config", Fail, "the secret scan could not start"),
        },
        Err(FsError::NotFound { .. }) => check(
            "config",
            Warn,
            "no configuration; the defaults apply (`uaos init` writes one)",
        ),
        Err(e) => check("config", Fail, format!("the configuration file: {e}")),
    }
}

/// The kernel, the journal and the stop; the verified journal when it was read.
fn journal_checks(fs: &dyn Fs, data_dir: &Path, checks: &mut Vec<DoctorCheck>) -> Option<home::Journal> {
    use CheckStatus::{Fail, Ok, Warn};
    match home::kernel_running(fs, data_dir) {
        Result::Ok(true) => {
            checks.push(check(
                "kernel",
                Ok,
                "a kernel is running; the journal is not read while it does",
            ));
            return None;
        }
        Result::Ok(false) => checks.push(check("kernel", Ok, "no kernel is running")),
        Err(failed) => {
            checks.push(check("kernel", Fail, failed.detail));
            return None;
        }
    }
    let journal = match home::read_journal(fs, data_dir) {
        Result::Ok(Some(journal)) => journal,
        Result::Ok(None) => {
            checks.push(check("journal", Fail, "there is no journal; run `uaos init`"));
            return None;
        }
        Err(failed) => {
            checks.push(check("journal", Fail, failed.detail));
            return None;
        }
    };
    let s = journal.summary();
    checks.push(if s.ignored_tail_bytes > 0 {
        check(
            "journal",
            Warn,
            format!(
                "{} records verify; {} bytes after the last record were never acknowledged and are ignored",
                s.records, s.ignored_tail_bytes
            ),
        )
    } else {
        check("journal", Ok, format!("{} records verify", s.records))
    });
    checks.push(if s.stop == "running" {
        check("stop", Ok, "the kernel stop is not engaged")
    } else {
        check(
            "stop",
            Warn,
            format!("the kernel stop is engaged: {}; only a human resumes it", s.stop),
        )
    });
    Some(journal)
}

/// The keychain: the installation's identity key when there is a journal, else reachability;
/// then the provider keys.
fn keychain_checks(
    fs: &dyn Fs,
    keychain: &dyn Keychain,
    data_dir: &Path,
    journal: Option<&home::Journal>,
    checks: &mut Vec<DoctorCheck>,
) {
    use CheckStatus::{Fail, Ok};
    let backend = keychain.backend();
    let Some(journal) = journal else {
        checks.push(match keychain.get("uaos-doctor/probe") {
            Result::Ok(_) => check("keychain", Ok, format!("{backend}: reachable")),
            Err(e) => check("keychain", Fail, format!("{backend}: {e}")),
        });
        return;
    };
    let identity = format!("{}/identity/hmac", journal.installation());
    checks.push(match keychain.get(&identity) {
        Result::Ok(Some(_)) => check(
            "keychain",
            Ok,
            format!("{backend}: the installation's identity key is there"),
        ),
        Result::Ok(None) => check(
            "keychain",
            Fail,
            format!("{backend}: the installation's identity key is missing; run `uaos init`"),
        ),
        Err(e) => check("keychain", Fail, format!("{backend}: {e}")),
    });
    checks.push(provider_keys(fs, keychain, data_dir));
}

fn tls_check(env: &BTreeMap<String, String>) -> DoctorCheck {
    let tls: Vec<&str> = ["SSL_CERT_FILE", "SSL_CERT_DIR"]
        .into_iter()
        .filter(|v| env.contains_key(*v))
        .collect();
    if tls.is_empty() {
        check("tls.roots", CheckStatus::Ok, "the system's own trust roots")
    } else {
        check(
            "tls.roots",
            CheckStatus::Warn,
            format!(
                "{} set: the door trusts only the system's roots and ignores them",
                tls.join(" and ")
            ),
        )
    }
}

fn provider_keys(fs: &dyn Fs, keychain: &dyn Keychain, data_dir: &Path) -> DoctorCheck {
    use CheckStatus::{Fail, Ok};
    match keys::list(fs, keychain, data_dir) {
        Err(failed) => check("keys", Fail, failed.detail),
        Result::Ok(list) => {
            let missing: Vec<&str> = list
                .iter()
                .filter(|k| k.state == "active" && !k.in_keychain)
                .map(|k| k.name.as_str())
                .collect();
            let lingering: Vec<&str> = list
                .iter()
                .filter(|k| k.state == "revoked" && k.in_keychain)
                .map(|k| k.name.as_str())
                .collect();
            let active = list.iter().filter(|k| k.state == "active").count();
            if !missing.is_empty() {
                check(
                    "keys",
                    Fail,
                    format!("active but missing from the keychain: {}", missing.join(", ")),
                )
            } else if !lingering.is_empty() {
                check(
                    "keys",
                    Fail,
                    format!("revoked but still in the keychain: {}", lingering.join(", ")),
                )
            } else {
                check("keys", Ok, format!("{active} provider key(s), each in the keychain"))
            }
        }
    }
}
