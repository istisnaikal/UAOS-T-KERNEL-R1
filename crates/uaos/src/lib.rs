// SPDX-License-Identifier: Apache-2.0

//! # `uaos`, the single binary: B1
//!
//! The composition root. B1 holds the commands that need no request path: `init`, `status`,
//! `doctor`, `journal verify|export`, `key add|rotate|revoke|list`, `config path|show`, `help` and
//! `--version`.
//!
//! [`run`] is the whole command line as a function: it takes the arguments, the environment
//! variables the binary reads, a file system, a keychain, a clock, randomness and standard input,
//! and returns what to print and the exit code.
//! `main.rs` reads the process's arguments and environment once and passes them in, so nothing
//! below it reads the environment, and the tests drive every command on a simulated file
//! system.
//!
//! - **Exit codes:** 0, or one code per error class ([`uaos_contracts::cli::exit_code_for`]).
//! - **`--json`:** one `uaos.cli/1` object on standard output, nothing on standard error.
//! - **No secrets:** the configuration is refused if the final scan finds one, and no message
//!   repeats a value from the input (red line 2).
//! - **Keys only in the OS keychain:** the installation's identity key, created by `init`, and
//!   provider keys, read only from standard input and never printed.
//! - **No network and no telemetry** (red lines 1 and 9); the crate does not depend on
//!   `uaos-egress`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod config;
mod doctor;
mod home;
pub mod keys;
mod vault;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use uaos_contracts::cli::{
    CheckStatus, CliOutput, CliResult, CliSchema, ConfigEntry, ConfigSource, ConfigValue, EXIT_OK, exit_code_for,
};
use uaos_contracts::error::{ErrorCode, REGISTRY, UaosError, codes};
use uaos_contracts::event::types;
use uaos_contracts::id::CorrelationId;
use uaos_platform::fs::{Fs, FsError};
use uaos_platform::keychain::Keychain;
use uaos_platform::{Clock, Rng};
use uaos_state::journal::{FlushPolicy, Journal};

use crate::config::Refusal;

/// The help text, part of the `cli-contract` snapshots.
pub const HELP: &str = "\
uaos: the UAOS kernel's command line (B1 skeleton)

Usage: uaos [--data-dir <path>] [--json] <command>

Commands:
  init               Create the data directory, the journal, the installation's key in the
                     OS keychain, and a default configuration without secrets
  status             Whether UAOS is initialized and running, and what its journal holds
  doctor             Check the data directory, configuration, journal and keychain
  journal verify     Verify the journal's hash chain
  journal export     Print every record's envelope as JSON lines; payloads stay encrypted
  key add <name>     Store a provider's API key in the OS keychain, from standard input
  key rotate <name>  Replace a provider's key, from standard input
  key revoke <name>  Delete a provider's key from the OS keychain
  key list           The provider keys, by name; never their values
  config path        Print the configuration file's path
  config show        Print the effective configuration and where each value comes from
  help               Print this help

Options:
  --data-dir <path>  The data directory (default: per system; also UAOS_DATA_DIR)
  --json             One machine-readable object on standard output (uaos.cli/1)
  -h, --help         Print this help
  -V, --version      Print the version

Exit codes: 0 ok, 1 internal, 2 usage, 3 configuration, 4 denied, 5 budget,
6 provider, 7 tool, 8 blocked.
";

/// The operating system whose conventions decide the default data directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Linux and every Unix but macOS: XDG base directories.
    Unix,
    /// macOS: Application Support.
    MacOs,
    /// Windows: `%LOCALAPPDATA%`.
    Windows,
}

impl Os {
    /// The system this binary was built for.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Unix
        }
    }
}

/// Reads all of standard input, when a command asks for it.
pub type Stdin = Arc<dyn Fn() -> std::io::Result<Vec<u8>> + Send + Sync>;

/// One run of the command line.
#[derive(Clone)]
pub struct Invocation {
    /// The arguments after the program's name.
    pub args: Vec<OsString>,
    /// The environment variables [`reads_variable`] names, and no others.
    pub env: BTreeMap<String, String>,
    /// The file system.
    pub fs: Arc<dyn Fs>,
    /// The run's correlation id, carried by any error it reports.
    pub correlation: CorrelationId,
    /// Whose conventions place the default data directory.
    pub os: Os,
    /// The OS keychain.
    pub keychain: Arc<dyn Keychain>,
    /// The wall clock.
    pub clock: Arc<dyn Clock>,
    /// Randomness, for the journal's ids and the identity key.
    pub rng: Arc<dyn Rng>,
    /// Standard input, read only by `key add` and `key rotate`.
    pub stdin: Stdin,
    /// Whether standard input is a terminal: a key is never typed where it would show.
    pub stdin_is_terminal: bool,
}

impl std::fmt::Debug for Invocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invocation")
            .field("args", &self.args.len())
            .field("os", &self.os)
            .field("keychain", &self.keychain.backend())
            .finish_non_exhaustive()
    }
}

/// What a run prints, and how it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The process's exit code.
    pub exit_code: u8,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

/// Whether the binary reads the environment variable `name`: `UAOS_DATA_DIR`, the
/// configuration's own variables, and the ones that place the default data directory.
#[must_use]
pub fn reads_variable(name: &str) -> bool {
    name == DATA_DIR_VAR
        || matches!(
            name,
            "HOME" | "XDG_DATA_HOME" | "LOCALAPPDATA" | "SSL_CERT_FILE" | "SSL_CERT_DIR"
        )
        || config::variables().any(|v| v == name)
}

const DATA_DIR_VAR: &str = "UAOS_DATA_DIR";

/// Runs one command line.
#[must_use]
pub fn run(invocation: &Invocation) -> Outcome {
    let parsed = parse(&invocation.args);
    let (json, command) = match &parsed {
        Ok(p) => (p.json, p.command.join(" ")),
        // `--json` counts even when the rest of the line could not be read.
        Err(_) => (invocation.args.iter().any(|a| a == "--json"), String::new()),
    };
    let ended = parsed.and_then(|p| dispatch(invocation, &p));
    render(invocation, json, command, ended)
}

/// A command's answer: what the JSON carries, the text, and a failure that still has a result
/// to show (`doctor` with a failed check).
struct Done {
    result: CliResult,
    text: String,
    failure: Option<Failed>,
}

impl Done {
    fn ok(result: CliResult, text: impl Into<String>) -> Self {
        Self {
            result,
            text: text.into(),
            failure: None,
        }
    }
}

/// A failed command: the registered code, and what failed, without any value from the input.
pub(crate) struct Failed {
    pub(crate) code: ErrorCode,
    pub(crate) detail: String,
}

impl Failed {
    pub(crate) fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// The command line, read.
#[derive(Debug, Default)]
struct Parsed {
    command: Vec<String>,
    json: bool,
    data_dir: Option<PathBuf>,
    help: bool,
    version: bool,
}

fn parse(args: &[OsString]) -> Result<Parsed, Failed> {
    let usage = |detail: String| Failed::new(codes::CLI_USAGE, detail);
    let mut parsed = Parsed::default();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let set_dir = |parsed: &mut Parsed, dir: PathBuf| {
            if parsed.data_dir.replace(dir).is_some() {
                Err(usage("`--data-dir` is given twice".to_owned()))
            } else {
                Ok(())
            }
        };
        if arg == "--data-dir" {
            let dir = rest
                .next()
                .ok_or_else(|| usage("`--data-dir` needs a path".to_owned()))?;
            set_dir(&mut parsed, PathBuf::from(dir))?;
            continue;
        }
        let Some(text) = arg.to_str() else {
            return Err(usage("an argument is not valid UTF-8".to_owned()));
        };
        match text {
            "--json" => parsed.json = true,
            "-h" | "--help" => parsed.help = true,
            "-V" | "--version" => parsed.version = true,
            _ => {
                if let Some(dir) = text.strip_prefix("--data-dir=") {
                    if dir.is_empty() {
                        return Err(usage("`--data-dir` needs a path".to_owned()));
                    }
                    set_dir(&mut parsed, PathBuf::from(dir))?;
                } else if text.starts_with('-') {
                    return Err(usage(named("option", text)));
                } else {
                    parsed.command.push(text.to_owned());
                }
            }
        }
    }
    Ok(parsed)
}

/// "unknown option `--x`", naming it only when it is plain ASCII, so no value the user pasted is
/// repeated.
fn named(what: &str, text: &str) -> String {
    let plain = !text.is_empty()
        && text.len() <= 32
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if plain {
        format!("unknown {what} `{text}`")
    } else {
        format!("an unknown {what}")
    }
}

fn dispatch(inv: &Invocation, p: &Parsed) -> Result<Done, Failed> {
    let words: Vec<&str> = p.command.iter().map(String::as_str).collect();
    if p.version {
        if !words.is_empty() || p.help {
            return Err(Failed::new(codes::CLI_USAGE, "`--version` takes no command"));
        }
        let version = env!("CARGO_PKG_VERSION").to_owned();
        let text = format!("uaos {version} (output schema uaos.cli/1)\n");
        return Ok(Done::ok(CliResult::Version { version }, text));
    }
    if p.help || words == ["help"] {
        return Ok(Done::ok(CliResult::Help { text: HELP.to_owned() }, HELP));
    }
    match words.as_slice() {
        [] => Err(Failed::new(codes::CLI_USAGE, "no command given")),
        ["init"] => init(inv, p),
        ["status"] => status(inv, p),
        ["doctor"] => doctor_command(inv, p),
        ["journal", "verify"] => journal_verify(inv, p),
        ["journal", "export"] => journal_export(inv, p),
        ["journal"] => Err(Failed::new(codes::CLI_USAGE, "`journal` needs `verify` or `export`")),
        ["journal", other, ..] => Err(Failed::new(codes::CLI_USAGE, named("journal command", other))),
        ["key", "add", name] => key_change(inv, p, name, keys::Change::Add),
        ["key", "rotate", name] => key_change(inv, p, name, keys::Change::Rotate),
        ["key", "revoke", name] => key_change(inv, p, name, keys::Change::Revoke),
        ["key", "list"] => key_list(inv, p),
        ["key", "add" | "rotate" | "revoke"] => {
            Err(Failed::new(codes::CLI_USAGE, "the key's provider name is missing"))
        }
        ["key"] => Err(Failed::new(
            codes::CLI_USAGE,
            "`key` needs `add`, `rotate`, `revoke` or `list`",
        )),
        ["key", other, ..] => Err(Failed::new(codes::CLI_USAGE, named("key command", other))),
        ["config", "path"] => {
            let file = data_dir(inv, p)?.join(config::FILE_NAME);
            let text = format!("{}\n", file.display());
            Ok(Done::ok(
                CliResult::ConfigPath {
                    config_file: file.display().to_string(),
                },
                text,
            ))
        }
        ["config", "show"] => show(inv, p),
        ["config"] => Err(Failed::new(codes::CLI_USAGE, "`config` needs `path` or `show`")),
        ["config", other, ..] => Err(Failed::new(codes::CLI_USAGE, named("config command", other))),
        [first, ..] => Err(Failed::new(codes::CLI_USAGE, named("command", first))),
    }
}

/// The data directory: the flag, else `UAOS_DATA_DIR`, else the system's convention.
fn data_dir(inv: &Invocation, p: &Parsed) -> Result<PathBuf, Failed> {
    if let Some(dir) = &p.data_dir {
        return Ok(dir.clone());
    }
    let var = |name: &str| inv.env.get(name).filter(|v| !v.is_empty());
    if let Some(dir) = var(DATA_DIR_VAR) {
        return Ok(PathBuf::from(dir));
    }
    let not_found = || {
        Failed::new(
            codes::CLI_DATA_DIR,
            "no default data directory: its variable is unset; pass `--data-dir`",
        )
    };
    match inv.os {
        Os::Windows => var("LOCALAPPDATA")
            .map(|d| Path::new(d).join("uaos"))
            .ok_or_else(not_found),
        Os::MacOs => var("HOME")
            .map(|h| Path::new(h).join("Library").join("Application Support").join("uaos"))
            .ok_or_else(not_found),
        Os::Unix => match var("XDG_DATA_HOME").filter(|d| Path::new(d).is_absolute()) {
            Some(xdg) => Ok(Path::new(xdg).join("uaos")),
            None => var("HOME")
                .map(|h| Path::new(h).join(".local").join("share").join("uaos"))
                .ok_or_else(not_found),
        },
    }
}

fn init(inv: &Invocation, p: &Parsed) -> Result<Done, Failed> {
    let dir = data_dir(inv, p)?;
    let fs_failed = |e: &FsError| Failed::new(codes::CLI_DATA_DIR, format!("the data directory: {e}"));
    inv.fs.create_private_dir_all(&dir).map_err(|e| fs_failed(&e))?;
    // The lock a running kernel holds, held until this command ends.
    let mut lock = Some(home::lock(inv.fs.as_ref(), &dir)?);
    let mut journal = None;
    // An existing journal is only read, never opened for writing: opening runs the journal's
    // recovery, and a journal a kernel kept payloads for opens only with its chunk store.
    let existing = home::read_journal(inv.fs.as_ref(), &dir)?;
    let read = if let Some(read) = existing {
        read
    } else {
        // Opening creates the journal, as a kernel's first start does, and takes the same lock
        // again.
        lock = None;
        journal = Some(
            Journal::open(
                Arc::clone(&inv.fs),
                Arc::clone(&inv.clock),
                Arc::clone(&inv.rng),
                &dir,
                FlushPolicy::default(),
            )
            .map_err(|e| Failed::new(e.code(), format!("the journal: {e}")))?,
        );
        home::read_journal(inv.fs.as_ref(), &dir)?.ok_or_else(home::not_initialized)?
    };
    let file = dir.join(config::FILE_NAME);
    let created = match inv.fs.read(&file) {
        Ok(bytes) => {
            // An existing configuration is kept, never overwritten; it must still be valid.
            config::load(Some(&bytes), &BTreeMap::new()).map_err(refused)?;
            false
        }
        Err(FsError::NotFound { .. }) => {
            inv.fs
                .write_atomic(&file, config::DEFAULT_TEXT.as_bytes())
                .map_err(|e| fs_failed(&e))?;
            inv.fs.sync_dir(&dir).map_err(|e| fs_failed(&e))?;
            true
        }
        Err(e) => return Err(fs_failed(&e)),
    };
    // The installation is the journal's id; its identity key goes in the keychain under it. A key
    // already there is kept; one lost while credentials exist is refused.
    let installation = read.installation().to_owned();
    let credentials_exist = read.envelopes().any(|e| e.event_type == types::IDENTITY_ENTRY);
    // The identity layer reports a keychain failure as text; the watched keychain keeps its kind,
    // so a host without a usable keychain exits 3, not 1.
    let watched = Arc::new(vault::Watched::new(Arc::clone(&inv.keychain)));
    let keychain: Arc<dyn Keychain> = Arc::<vault::Watched>::clone(&watched);
    uaos_identity::IdentityKeys::open(keychain, inv.rng.as_ref(), &installation, credentials_exist).map_err(|e| {
        watched
            .failure()
            .unwrap_or_else(|| Failed::new(e.code(), format!("the installation's identity key: {e}")))
    })?;
    drop((journal, lock));
    let backend = inv.keychain.backend().to_owned();
    let text = if created {
        format!(
            "Initialized UAOS in {}.\nInstallation {installation}; its identity key is in the {backend}.\nConfiguration: {} (no secrets; keys belong in the OS keychain).\n",
            dir.display(),
            file.display()
        )
    } else {
        format!(
            "UAOS is already initialized in {}; its configuration is valid and was left as it is.\nInstallation {installation}; its identity key is in the {backend}.\n",
            dir.display()
        )
    };
    Ok(Done::ok(
        CliResult::Init {
            data_dir: dir.display().to_string(),
            config_file: file.display().to_string(),
            created,
            installation,
            keychain: backend,
        },
        text,
    ))
}

fn status(inv: &Invocation, p: &Parsed) -> Result<Done, Failed> {
    let dir = data_dir(inv, p)?;
    let config = match inv.fs.read(&dir.join(config::FILE_NAME)) {
        Ok(bytes) if config::load(Some(&bytes), &BTreeMap::new()).is_ok() => "valid",
        Ok(_) => "invalid",
        Err(FsError::NotFound { .. }) => "missing",
        Err(e) => return Err(Failed::new(codes::CLI_DATA_DIR, format!("the configuration file: {e}"))),
    };
    let running = home::kernel_running(inv.fs.as_ref(), &dir)?;
    let journal = if running {
        None
    } else {
        home::read_journal(inv.fs.as_ref(), &dir)?.map(|j| j.summary())
    };
    let journal_exists = running || journal.is_some();
    let initialized = config != "missing" && journal_exists;
    let provider_keys = keys::active_count(inv.fs.as_ref(), &dir);
    let journal_line = match &journal {
        Some(j) => format!(
            "Journal: {} records, next {}, head {}; stop {}\n",
            j.records, j.next_seq, j.head, j.stop
        ),
        None if running => "Journal: not read while the kernel runs\n".to_owned(),
        None => "Journal: none\n".to_owned(),
    };
    let text = format!(
        "Data directory: {}\nInitialized: {}\nKernel: {}\nConfiguration: {config}\n{journal_line}Provider keys: {provider_keys}\n",
        dir.display(),
        if initialized { "yes" } else { "no; run `uaos init`" },
        if running { "running" } else { "not running" },
    );
    Ok(Done::ok(
        CliResult::Status {
            data_dir: dir.display().to_string(),
            initialized,
            kernel_running: running,
            config: config.to_owned(),
            journal,
            provider_keys,
        },
        text,
    ))
}

/// The verified journal, read under the data directory's lock so no kernel writes it meanwhile.
fn locked_journal(inv: &Invocation, p: &Parsed) -> Result<home::Journal, Failed> {
    let dir = data_dir(inv, p)?;
    let _lock = home::lock(inv.fs.as_ref(), &dir)?;
    home::read_journal(inv.fs.as_ref(), &dir)?.ok_or_else(home::not_initialized)
}

fn journal_verify(inv: &Invocation, p: &Parsed) -> Result<Done, Failed> {
    let journal = locked_journal(inv, p)?.summary();
    let text = format!(
        "The journal verifies: {} records in {} segment(s), next {}, head {}.\n{}",
        journal.records,
        journal.segments,
        journal.next_seq,
        journal.head,
        if journal.ignored_tail_bytes > 0 {
            format!(
                "{} bytes after the last record were never acknowledged and are ignored.\n",
                journal.ignored_tail_bytes
            )
        } else {
            String::new()
        }
    );
    Ok(Done::ok(CliResult::JournalVerify { journal }, text))
}

fn journal_export(inv: &Invocation, p: &Parsed) -> Result<Done, Failed> {
    let journal = locked_journal(inv, p)?;
    let records: Vec<_> = journal.envelopes().cloned().collect();
    let mut text = String::new();
    for record in &records {
        let line = serde_json::to_string(record)
            .map_err(|_| Failed::new(codes::JOURNAL_WRITE_FAILED, "a record could not be written out"))?;
        text.push_str(&line);
        text.push('\n');
    }
    Ok(Done::ok(CliResult::JournalExport { records }, text))
}

fn key_change(inv: &Invocation, p: &Parsed, name: &str, what: keys::Change) -> Result<Done, Failed> {
    let dir = data_dir(inv, p)?;
    let now = inv
        .clock
        .wall()
        .map_err(|_| Failed::new(codes::CLI_DATA_DIR, "the system clock is unavailable"))?
        .to_string();
    keys::change(
        inv.fs.as_ref(),
        inv.keychain.as_ref(),
        &dir,
        name,
        what,
        &now,
        &inv.stdin,
        inv.stdin_is_terminal,
    )?;
    let action = what.past();
    Ok(Done::ok(
        CliResult::Key {
            name: name.to_owned(),
            action: action.to_owned(),
        },
        format!("The key `{name}` was {action}.\n"),
    ))
}

fn key_list(inv: &Invocation, p: &Parsed) -> Result<Done, Failed> {
    let dir = data_dir(inv, p)?;
    let keys = keys::list(inv.fs.as_ref(), inv.keychain.as_ref(), &dir)?;
    let lines: Vec<String> = keys
        .iter()
        .map(|k| {
            format!(
                "{}  {}  {}  {}\n",
                k.name,
                k.state,
                k.changed,
                if k.in_keychain {
                    "in the keychain"
                } else {
                    "not in the keychain"
                }
            )
        })
        .collect();
    let text = if keys.is_empty() {
        "No provider keys; add one with `uaos key add <name>`.\n".to_owned()
    } else {
        lines.concat()
    };
    Ok(Done::ok(CliResult::KeyList { keys }, text))
}

fn doctor_command(inv: &Invocation, p: &Parsed) -> Result<Done, Failed> {
    let dir = data_dir(inv, p)?;
    let checks = doctor::run(inv.fs.as_ref(), inv.keychain.as_ref(), &dir, &inv.env);
    let lines: Vec<String> = checks
        .iter()
        .map(|c| {
            let mark = match c.status {
                CheckStatus::Ok => "ok  ",
                CheckStatus::Warn => "warn",
                CheckStatus::Fail => "FAIL",
            };
            format!("{mark}  {}: {}\n", c.name, c.detail)
        })
        .collect();
    let text = lines.concat();
    let failed: Vec<&str> = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .map(|c| c.name.as_str())
        .collect();
    let failure = (!failed.is_empty()).then(|| {
        Failed::new(
            codes::CLI_DOCTOR_FAILED,
            format!("failed checks: {}", failed.join(", ")),
        )
    });
    Ok(Done {
        result: CliResult::Doctor { checks },
        text,
        failure,
    })
}

fn show(inv: &Invocation, p: &Parsed) -> Result<Done, Failed> {
    let file = data_dir(inv, p)?.join(config::FILE_NAME);
    let bytes = match inv.fs.read(&file) {
        Ok(bytes) => Some(bytes),
        Err(FsError::NotFound { .. }) => None,
        Err(e) => return Err(Failed::new(codes::CLI_DATA_DIR, format!("the configuration file: {e}"))),
    };
    let values = config::load(bytes.as_deref(), &inv.env).map_err(refused)?;
    let mut text = String::new();
    if bytes.is_none() {
        text = format!("# {} does not exist; run `uaos init`.\n", file.display());
    }
    for entry in &values {
        text.push_str(&line(entry));
    }
    Ok(Done::ok(
        CliResult::ConfigShow {
            config_file: file.display().to_string(),
            file_found: bytes.is_some(),
            values,
        },
        text,
    ))
}

/// `key = value  # source`, TOML-shaped so the lines can be pasted into the file.
fn line(entry: &ConfigEntry) -> String {
    let value = match &entry.value {
        ConfigValue::Integer(n) => n.to_string(),
        ConfigValue::Text(t) => format!("\"{t}\""),
    };
    let source = match entry.source {
        ConfigSource::Flag => "flag",
        ConfigSource::Env => "environment",
        ConfigSource::File => "file",
        ConfigSource::Default => "default",
    };
    format!("{} = {value}  # {source}\n", entry.key)
}

fn refused(r: Refusal) -> Failed {
    match r {
        Refusal::HoldsSecret { place, classes } => Failed::new(
            codes::CONFIG_HOLDS_SECRET,
            format!("{place} holds what looks like a secret ({})", classes.join(", ")),
        ),
        Refusal::Invalid(why) => Failed::new(codes::CONFIG_INVALID, why),
        Refusal::Scanner => Failed::new(codes::REDACT_DETECTOR_FAILURE, "the secret scan could not start"),
    }
}

fn render(inv: &Invocation, json: bool, command: String, ended: Result<Done, Failed>) -> Outcome {
    let unified = |failed: &Failed| {
        let spec = REGISTRY
            .iter()
            .find(|s| s.code == failed.code)
            .or_else(|| REGISTRY.iter().find(|s| s.code == codes::REDACT_DETECTOR_FAILURE));
        let error = spec.map(|s| UaosError::from_spec(s, inv.correlation, None));
        let code = error.as_ref().map_or(1, |e| exit_code_for(e.class));
        (code, error)
    };
    let (exit_code, result, error, detail, text) = match ended {
        Ok(Done {
            result,
            text,
            failure: None,
        }) => (EXIT_OK, Some(result), None, None, text),
        Ok(Done {
            result,
            text,
            failure: Some(failed),
        }) => {
            let (code, error) = unified(&failed);
            (code, Some(result), error, Some(failed.detail), text)
        }
        Err(failed) => {
            let (code, error) = unified(&failed);
            (code, None, error, Some(failed.detail), String::new())
        }
    };
    if json {
        let out = CliOutput {
            schema: CliSchema::V1,
            command,
            exit_code,
            result,
            error,
            detail,
        };
        let stdout = serde_json::to_string(&out).map_or_else(
            |_| "{\"schema\":\"uaos.cli/1\",\"command\":\"\",\"exit_code\":1}".to_owned(),
            |s| s + "\n",
        );
        return Outcome {
            exit_code,
            stdout,
            stderr: String::new(),
        };
    }
    match (error, detail) {
        (Some(e), Some(d)) => {
            let mut stderr = format!("error: {} [{}]\n  {d}\n  {}\n", e.agent_message, e.code, e.remediation);
            if e.code == codes::CLI_USAGE.to_string() {
                stderr.push('\n');
                stderr.push_str(HELP);
            }
            Outcome {
                exit_code,
                stdout: text,
                stderr,
            }
        }
        _ => Outcome {
            exit_code,
            stdout: text,
            stderr: String::new(),
        },
    }
}
