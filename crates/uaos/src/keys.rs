// SPDX-License-Identifier: Apache-2.0

//! Provider API keys (bring your own key): in the OS keychain under
//! `<installation>/provider/<name>`, never in the data directory, never on the command line, never
//! in any output.
//!
//! The keychain cannot list its entries, so the data directory keeps an index of names, states
//! and times, `keys.json`, which holds no key. Every change takes the data directory's lock, so
//! it never races a running kernel. A key is read from standard input, never from an argument,
//! which a shell history or a process list would keep; a terminal is refused, so it is piped.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use uaos_contracts::cli::ProviderKey;
use uaos_contracts::error::codes;
use uaos_platform::fs::{Fs, FsError};
use uaos_platform::keychain::Keychain;
use zeroize::Zeroizing;

use crate::{Failed, home, vault};

/// The index's file name in the data directory.
pub const INDEX_FILE: &str = "keys.json";
const INDEX_SCHEMA: &str = "uaos.keys/1";
/// The longest key accepted, in bytes.
pub const MAX_KEY_LEN: usize = 4_096;

/// What a change does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Store a key under a name that has none.
    Add,
    /// Replace an active key.
    Rotate,
    /// Delete an active key.
    Revoke,
}

impl Change {
    /// The word the output uses.
    #[must_use]
    pub const fn past(self) -> &'static str {
        match self {
            Self::Add => "added",
            Self::Rotate => "rotated",
            Self::Revoke => "revoked",
        }
    }
}

/// One index entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    name: String,
    active: bool,
    changed: String,
}

fn account(installation: &str, name: &str) -> String {
    format!("{installation}/provider/{name}")
}

fn index_path(data_dir: &Path) -> PathBuf {
    data_dir.join(INDEX_FILE)
}

/// A provider's name: a lowercase letter, then up to 31 lowercase letters, digits, `-` or `_`.
fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && name.len() <= 32
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn read_index(fs: &dyn Fs, data_dir: &Path) -> Result<Vec<Entry>, Failed> {
    let corrupt = |why: &str| Failed::new(codes::CONFIG_INVALID, format!("`{INDEX_FILE}`: {why}"));
    let bytes = match fs.read(&index_path(data_dir)) {
        Ok(bytes) => bytes,
        Err(FsError::NotFound { .. }) => return Ok(Vec::new()),
        Err(e) => return Err(Failed::new(codes::CLI_DATA_DIR, format!("`{INDEX_FILE}`: {e}"))),
    };
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| corrupt("not valid JSON"))?;
    if value.get("schema").and_then(Value::as_str) != Some(INDEX_SCHEMA) {
        return Err(corrupt("an unknown schema"));
    }
    let keys = value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| corrupt("no `keys` list"))?;
    keys.iter()
        .map(|k| {
            let field = |f: &str| k.get(f).and_then(Value::as_str).map(str::to_owned);
            let (Some(name), Some(state), Some(changed)) = (field("name"), field("state"), field("changed")) else {
                return Err(corrupt("an entry without its name, state or time"));
            };
            if !valid_name(&name) || !matches!(state.as_str(), "active" | "revoked") {
                return Err(corrupt("an entry with an invalid name or state"));
            }
            Ok(Entry {
                active: state == "active",
                name,
                changed,
            })
        })
        .collect()
}

fn write_index(fs: &dyn Fs, data_dir: &Path, entries: &[Entry]) -> Result<(), Failed> {
    let keys: Vec<Value> = entries
        .iter()
        .map(|e| json!({"name": e.name, "state": if e.active { "active" } else { "revoked" }, "changed": e.changed}))
        .collect();
    let text = serde_json::to_string_pretty(&json!({"schema": INDEX_SCHEMA, "keys": keys}))
        .map_err(|_| Failed::new(codes::CLI_DATA_DIR, "the key index could not be written"))?;
    fs.write_atomic(&index_path(data_dir), format!("{text}\n").as_bytes())
        .and_then(|()| fs.sync_dir(data_dir))
        .map_err(|e| Failed::new(codes::CLI_DATA_DIR, format!("`{INDEX_FILE}`: {e}")))
}

/// The key from standard input: one line of printable ASCII without spaces, at most
/// [`MAX_KEY_LEN`] bytes. One trailing line end is dropped. Messages never repeat it.
fn read_key(stdin: &crate::Stdin, is_terminal: bool) -> Result<Zeroizing<Vec<u8>>, Failed> {
    let usage = |why: &str| Failed::new(codes::CLI_USAGE, why.to_owned());
    if is_terminal {
        return Err(usage(
            "the key is read from standard input, which is a terminal; pipe it instead, e.g. `printf %s \"$KEY\" | uaos key add <name>`",
        ));
    }
    let mut key =
        Zeroizing::new(stdin().map_err(|e| Failed::new(codes::CLI_USAGE, format!("standard input: {}", e.kind())))?);
    if key.last() == Some(&b'\n') {
        key.pop();
        if key.last() == Some(&b'\r') {
            key.pop();
        }
    }
    if key.is_empty() {
        return Err(usage("standard input held no key"));
    }
    if key.len() > MAX_KEY_LEN {
        return Err(usage("the key is longer than 4096 bytes"));
    }
    if !key.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err(usage("a key is one line of printable ASCII without spaces"));
    }
    Ok(key)
}

/// Adds, rotates or revokes the provider key `name`.
///
/// # Errors
/// [`Failed`]: an invalid name, no such key or one already there, a running kernel, a key that
/// could not be read, or a keychain or file failure. A failed `add` or `rotate` leaves the
/// keychain as it was.
#[allow(
    clippy::too_many_arguments,
    reason = "the invocation's parts, passed apart for clarity"
)]
pub(crate) fn change(
    fs: &dyn Fs,
    keychain: &dyn Keychain,
    data_dir: &Path,
    name: &str,
    what: Change,
    now: &str,
    stdin: &crate::Stdin,
    stdin_is_terminal: bool,
) -> Result<(), Failed> {
    if !valid_name(name) {
        return Err(Failed::new(
            codes::CLI_USAGE,
            "a provider's name is a lowercase letter, then up to 31 lowercase letters, digits, `-` or `_`",
        ));
    }
    let _lock = home::lock(fs, data_dir)?;
    let installation = home::installation(fs, data_dir)?;
    let mut entries = read_index(fs, data_dir)?;
    let at = entries.iter().position(|e| e.name == name);
    let active = at.and_then(|i| entries.get(i)).is_some_and(|e| e.active);
    match (what, active) {
        (Change::Add, true) => {
            return Err(Failed::new(
                codes::CLI_USAGE,
                format!("the key `{name}` exists; replace it with `uaos key rotate {name}`"),
            ));
        }
        (Change::Rotate | Change::Revoke, false) => {
            return Err(Failed::new(
                codes::CLI_USAGE,
                format!("there is no active key `{name}`"),
            ));
        }
        _ => {}
    }
    let account = account(&installation, name);
    match what {
        Change::Add | Change::Rotate => {
            let key = read_key(stdin, stdin_is_terminal)?;
            let failed = |e| vault::failed(keychain.backend(), &e);
            let previous = keychain.get(&account).map_err(failed)?;
            keychain.set(&account, &key).map_err(failed)?;
            upsert(&mut entries, name, true, now);
            if let Err(failed) = write_index(fs, data_dir, &entries) {
                // The index did not change, so neither may the keychain.
                let _restored = match previous {
                    Some(old) => keychain.set(&account, &old).is_ok(),
                    None => keychain.delete(&account).is_ok(),
                };
                return Err(failed);
            }
        }
        Change::Revoke => {
            // The index first: if the delete then fails, `doctor` reports a revoked key still in
            // the keychain, and `key revoke` on a revoked name is refused, so nothing hides it.
            upsert(&mut entries, name, false, now);
            write_index(fs, data_dir, &entries)?;
            keychain
                .delete(&account)
                .map_err(|e| vault::failed(keychain.backend(), &e))?;
        }
    }
    Ok(())
}

fn upsert(entries: &mut Vec<Entry>, name: &str, active: bool, now: &str) {
    match entries.iter_mut().find(|e| e.name == name) {
        Some(entry) => {
            entry.active = active;
            now.clone_into(&mut entry.changed);
        }
        None => entries.push(Entry {
            name: name.to_owned(),
            active,
            changed: now.to_owned(),
        }),
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
}

/// Every provider key the index names, with whether the keychain holds it now.
///
/// # Errors
/// [`Failed`]: not initialized, an unreadable index, or a keychain failure.
pub(crate) fn list(fs: &dyn Fs, keychain: &dyn Keychain, data_dir: &Path) -> Result<Vec<ProviderKey>, Failed> {
    let installation = home::installation(fs, data_dir)?;
    read_index(fs, data_dir)?
        .into_iter()
        .map(|e| {
            let in_keychain = keychain
                .get(&account(&installation, &e.name))
                .map_err(|err| vault::failed(keychain.backend(), &err))?
                .is_some();
            Ok(ProviderKey {
                state: if e.active { "active" } else { "revoked" }.to_owned(),
                name: e.name,
                changed: e.changed,
                in_keychain,
            })
        })
        .collect()
}

/// How many keys the index names as active; 0 when there is no index.
pub(crate) fn active_count(fs: &dyn Fs, data_dir: &Path) -> u32 {
    read_index(fs, data_dir).map_or(0, |entries| {
        u32::try_from(entries.iter().filter(|e| e.active).count()).unwrap_or(u32::MAX)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_plain() {
        for good in ["anthropic", "openai", "my-proxy_2", "a"] {
            assert!(valid_name(good), "{good}");
        }
        for bad in ["", "Anthropic", "1x", "a b", "a/b", "../x", "x".repeat(33).as_str()] {
            assert!(!valid_name(bad), "{bad}");
        }
    }
}
