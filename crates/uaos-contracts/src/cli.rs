// SPDX-License-Identifier: Apache-2.0

//! The `uaos` command line's machine-readable output, `uaos.cli/1`, and its exit codes.
//!
//! With `--json`, every command writes one [`CliOutput`] to standard output and nothing to
//! standard error. The exit code is part of the object, so a caller that reads only the JSON
//! still knows how the command ended. Both are a contract: a change to them is reviewed like a
//! schema change (`cli-contract`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ErrorClass, UaosError};

/// The exit code for success.
pub const EXIT_OK: u8 = 0;

/// The process exit code for an error of `class`: one code per class, so a script can tell a
/// denial, a block and an unreachable provider apart.
#[must_use]
pub const fn exit_code_for(class: ErrorClass) -> u8 {
    match class {
        ErrorClass::Internal => 1,
        ErrorClass::User => 2,
        ErrorClass::Config => 3,
        ErrorClass::Policy => 4,
        ErrorClass::Budget => 5,
        ErrorClass::Provider => 6,
        ErrorClass::Tool => 7,
        ErrorClass::Security => 8,
    }
}

/// The schema tag of [`CliOutput`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CliSchema {
    /// `uaos.cli/1`.
    #[serde(rename = "uaos.cli/1")]
    V1,
}

/// One command's answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CliOutput {
    /// Always `uaos.cli/1`.
    pub schema: CliSchema,
    /// The command's words, joined by one space (`"config show"`); empty when no command was
    /// read.
    pub command: String,
    /// The process's exit code: 0, or [`exit_code_for`] the error's class.
    pub exit_code: u8,
    /// What the command did, on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<CliResult>,
    /// The unified error, on failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<UaosError>,
    /// What failed, on failure: a key, a line or a class, never a value from the input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A command's result, tagged by `kind`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CliResult {
    /// `uaos init`.
    Init {
        /// The data directory.
        data_dir: String,
        /// The configuration file.
        config_file: String,
        /// Whether this run created the configuration; `false` when one was already there.
        created: bool,
        /// The installation id: the journal's id, under which its keys live in the keychain.
        installation: String,
        /// The keychain backend holding the installation's identity key.
        keychain: String,
    },
    /// `uaos status`.
    Status {
        /// The data directory.
        data_dir: String,
        /// Whether `init` has run: the configuration and the journal exist.
        initialized: bool,
        /// Whether a kernel holds the data directory's lock.
        kernel_running: bool,
        /// The configuration: `valid`, `missing` or `invalid`.
        config: String,
        /// The journal, when it was read (not while a kernel runs).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        journal: Option<JournalSummary>,
        /// The provider keys the index names as active.
        provider_keys: u32,
    },
    /// `uaos journal verify`.
    JournalVerify {
        /// What the verification read.
        journal: JournalSummary,
    },
    /// `uaos journal export`: every record's envelope, in order. Payloads stay encrypted.
    JournalExport {
        /// The envelopes (`uaos.event/1`).
        records: Vec<crate::event::EventEnvelope>,
    },
    /// `uaos key add`, `rotate` or `revoke`.
    Key {
        /// The provider's name.
        name: String,
        /// `added`, `rotated` or `revoked`.
        action: String,
    },
    /// `uaos key list`.
    KeyList {
        /// Every provider key the index names, by name.
        keys: Vec<ProviderKey>,
    },
    /// `uaos doctor`.
    Doctor {
        /// Every check, in a fixed order.
        checks: Vec<DoctorCheck>,
    },
    /// `uaos config path`.
    ConfigPath {
        /// The configuration file.
        config_file: String,
    },
    /// `uaos config show`.
    ConfigShow {
        /// The configuration file.
        config_file: String,
        /// Whether the file exists; without it, values come from the environment and defaults.
        file_found: bool,
        /// Every key, in a fixed order.
        values: Vec<ConfigEntry>,
    },
    /// `uaos --version`.
    Version {
        /// The binary's version.
        version: String,
    },
    /// `uaos help`.
    Help {
        /// The help text.
        text: String,
    },
}

/// What a read of the journal found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JournalSummary {
    /// The journal's id, which is also the installation's.
    pub journal_id: String,
    /// Records that verified.
    pub records: u64,
    /// The sequence number the next record gets.
    pub next_seq: u64,
    /// The chain hash of the last record (`sha256:` and hex).
    pub head: String,
    /// Segments the manifest lists.
    pub segments: u64,
    /// Bytes after the last complete record that no writer acknowledged (a torn write), ignored.
    pub ignored_tail_bytes: u64,
    /// `running`, or `stopped` when the kernel stop is engaged.
    pub stop: String,
}

/// A provider key the index names. The key itself is only ever in the OS keychain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderKey {
    /// The provider's name.
    pub name: String,
    /// `active` or `revoked`.
    pub state: String,
    /// When it was last added, rotated or revoked (RFC 3339, UTC).
    pub changed: String,
    /// Whether the keychain holds it now.
    pub in_keychain: bool,
}

/// One `doctor` check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DoctorCheck {
    /// The check's stable name, e.g. `data_dir.private`.
    pub name: String,
    /// The outcome.
    pub status: CheckStatus,
    /// What it found, never a secret.
    pub detail: String,
}

/// A `doctor` check's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Healthy.
    Ok,
    /// Works, but needs attention.
    Warn,
    /// Broken: `doctor` exits non-zero.
    Fail,
}

/// One effective configuration value and where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigEntry {
    /// The dotted key, e.g. `admission.max_bytes`.
    pub key: String,
    /// The value.
    pub value: ConfigValue,
    /// Where it came from.
    pub source: ConfigSource,
}

/// A configuration value. The configuration holds no secrets, so every value may be shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ConfigValue {
    /// A whole number.
    Integer(u64),
    /// Text.
    Text(String),
}

/// Where a configuration value came from, in precedence order: a flag wins over a variable, a
/// variable over the file, the file over the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    /// A command-line flag.
    Flag,
    /// A `UAOS_*` environment variable.
    Env,
    /// The configuration file.
    File,
    /// The built-in default.
    Default,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table, one distinct code per class.
    #[test]
    fn every_class_has_its_own_exit_code() {
        let table = [
            (ErrorClass::Internal, 1),
            (ErrorClass::User, 2),
            (ErrorClass::Config, 3),
            (ErrorClass::Policy, 4),
            (ErrorClass::Budget, 5),
            (ErrorClass::Provider, 6),
            (ErrorClass::Tool, 7),
            (ErrorClass::Security, 8),
        ];
        for (class, code) in table {
            assert_eq!(exit_code_for(class), code, "{class:?}");
        }
        let mut codes: Vec<u8> = table.iter().map(|(c, _)| exit_code_for(*c)).collect();
        codes.push(EXIT_OK);
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), table.len() + 1, "codes must be distinct");
    }

    #[test]
    fn the_output_round_trips_and_tags_its_schema() {
        let out = CliOutput {
            schema: CliSchema::V1,
            command: "config path".to_owned(),
            exit_code: EXIT_OK,
            result: Some(CliResult::ConfigPath {
                config_file: "/d/config.toml".to_owned(),
            }),
            error: None,
            detail: None,
        };
        let json = serde_json::to_string(&out).unwrap_or_default();
        assert_eq!(
            json,
            r#"{"schema":"uaos.cli/1","command":"config path","exit_code":0,"result":{"kind":"config_path","config_file":"/d/config.toml"}}"#
        );
        assert_eq!(serde_json::from_str::<CliOutput>(&json).ok(), Some(out));
    }
}
