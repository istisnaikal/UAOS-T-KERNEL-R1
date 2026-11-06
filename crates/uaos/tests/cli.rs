// SPDX-License-Identifier: Apache-2.0

//! The command line's contract (`cli-contract`): the help text, the exit codes and the `--json`
//! output of every command, as exact snapshots, run through the library on a simulated file
//! system with a fixed correlation id. A change to any of them fails here and is reviewed like a
//! schema change.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::ops::Deref;
use std::path::Path;
use std::sync::{Arc, Mutex};

use uaos::{HELP, Invocation, Os, Outcome, run};
use uaos_contracts::id::{CorrelationId, TypedId};
use uaos_contracts::time::WallTime;
use uaos_platform::fs::Fs;
use uaos_platform::keychain::Keychain;
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::keychain::SimKeychain;
use uaos_platform::sim::{SimClock, SimRng};

fn correlation() -> CorrelationId {
    CorrelationId::from_parts(1, [7; 10])
}

/// A simulated machine: a file system, a keychain and standard input. Every run on it uses the
/// same clock and the same randomness, so its output is exact.
struct Sim {
    fs: Arc<SimFs>,
    keychain: Arc<SimKeychain>,
    stdin: Arc<Mutex<Vec<u8>>>,
}

impl Deref for Sim {
    type Target = SimFs;
    fn deref(&self) -> &SimFs {
        &self.fs
    }
}

impl Sim {
    /// What the next command reads from standard input.
    fn feed(&self, bytes: &[u8]) {
        *self.stdin.lock().unwrap() = bytes.to_vec();
    }
}

fn sim() -> Sim {
    Sim {
        fs: Arc::new(SimFs::new()),
        keychain: Arc::new(SimKeychain::new()),
        stdin: Arc::new(Mutex::new(Vec::new())),
    }
}

fn invocation(sim: &Sim, args: Vec<OsString>, env: &[(&str, &str)], os: Os) -> Invocation {
    let fs: Arc<dyn Fs> = sim.fs.clone();
    let keychain: Arc<dyn Keychain> = sim.keychain.clone();
    let stdin = Arc::clone(&sim.stdin);
    Invocation {
        args,
        env: env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<BTreeMap<_, _>>(),
        fs,
        correlation: correlation(),
        os,
        keychain,
        clock: Arc::new(SimClock::new(
            WallTime::from_unix_nanos(1_793_923_200_000_000_000).unwrap(),
        )),
        rng: Arc::new(SimRng::new(42)),
        stdin: Arc::new(move || Ok(stdin.lock().map(|s| s.clone()).unwrap_or_default())),
        stdin_is_terminal: false,
    }
}

fn invoke(sim: &Sim, args: &[&str], env: &[(&str, &str)]) -> Outcome {
    run(&invocation(
        sim,
        args.iter().map(OsString::from).collect(),
        env,
        Os::Unix,
    ))
}

/// The help, word for word (seeded violation `cli-help-changed`).
#[test]
fn the_help_text_is_the_contract() {
    let expected = "\
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
    assert_eq!(HELP, expected);
    for args in [&["--help"][..], &["-h"], &["help"]] {
        let out = invoke(&sim(), args, &[]);
        assert_eq!(
            (out.exit_code, out.stdout.as_str(), out.stderr.as_str()),
            (0, expected, ""),
            "{args:?}"
        );
    }
}

/// One exit code per error class, end to end (seeded violation `cli-exit-code-changed`).
#[test]
fn every_failure_ends_with_its_class_exit_code() {
    let fs = sim();
    let cases: [(&[&str], u8); 6] = [
        (&[], 2),
        (&["bogus"], 2),
        (&["--frobnicate"], 2),
        (&["config"], 2),
        (&["--data-dir"], 2),
        (&["--version", "init"], 2),
    ];
    for (args, code) in cases {
        let out = invoke(&fs, args, &[]);
        assert_eq!(out.exit_code, code, "{args:?}: {out:?}");
        assert!(
            out.stdout.is_empty() && out.stderr.contains("[UAOS-CLI-0001]"),
            "{args:?}: {out:?}"
        );
    }
    fs.create_dir_all(Path::new("/d")).unwrap();
    fs.write_atomic(Path::new("/d/config.toml"), b"config_version = 9\n")
        .unwrap();
    let out = invoke(&fs, &["--data-dir", "/d", "config", "show"], &[]);
    assert_eq!(out.exit_code, 3, "{out:?}");
    assert!(out.stderr.contains("[UAOS-CONFIG-0001]") && out.stderr.contains("`config_version`: expected 1"));
}

/// A path in printed text, with `/` between its parts. These tests give Unix-style paths and
/// simulate each system's rules on any host; a Windows host joins the parts with `\`.
fn slashes(text: &str) -> String {
    if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.to_owned()
    }
}

/// The same for JSON, where a `\` in a path is written `\\`.
fn json_slashes(text: &str) -> String {
    if cfg!(windows) {
        text.replace("\\\\", "/")
    } else {
        text.to_owned()
    }
}

/// Every command's `--json`, exactly: one object on standard output, nothing on standard error.
#[test]
fn the_json_output_is_the_contract() {
    let fs = sim();
    let json = |args: &[&str], env: &[(&str, &str)]| {
        let out = invoke(&fs, args, env);
        assert!(out.stderr.is_empty(), "{args:?}: {out:?}");
        assert!(out.stdout.ends_with('\n'));
        (out.exit_code, json_slashes(out.stdout.trim_end()))
    };
    assert_eq!(
        json(&["--json", "--data-dir", "/d", "init"], &[]),
        (
            0,
            r#"{"schema":"uaos.cli/1","command":"init","exit_code":0,"result":{"kind":"init","data_dir":"/d","config_file":"/d/config.toml","created":true,"installation":"956eeb2f2632d7bd03f166b233e3ef28","keychain":"simulated"}}"#.to_owned()
        )
    );
    assert_eq!(
        json(&["init", "--data-dir=/d", "--json"], &[]),
        (
            0,
            r#"{"schema":"uaos.cli/1","command":"init","exit_code":0,"result":{"kind":"init","data_dir":"/d","config_file":"/d/config.toml","created":false,"installation":"956eeb2f2632d7bd03f166b233e3ef28","keychain":"simulated"}}"#.to_owned()
        )
    );
    assert_eq!(
        json(&["--json", "config", "path"], &[("UAOS_DATA_DIR", "/d")]),
        (
            0,
            r#"{"schema":"uaos.cli/1","command":"config path","exit_code":0,"result":{"kind":"config_path","config_file":"/d/config.toml"}}"#.to_owned()
        )
    );
    assert_eq!(
        json(&["--json", "--data-dir", "/d", "config", "show"], &[("UAOS_LOCALE", "tr")]),
        (
            0,
            concat!(
                r#"{"schema":"uaos.cli/1","command":"config show","exit_code":0,"result":{"kind":"config_show","config_file":"/d/config.toml","file_found":true,"values":["#,
                r#"{"key":"config_version","value":1,"source":"file"},"#,
                r#"{"key":"kernel.locale","value":"tr","source":"env"},"#,
                r#"{"key":"admission.max_operations","value":64,"source":"file"},"#,
                r#"{"key":"admission.max_bytes","value":268435456,"source":"file"},"#,
                r#"{"key":"journal.durability","value":"balanced","source":"file"}]}}"#
            )
            .to_owned()
        )
    );
    let version = env!("CARGO_PKG_VERSION");
    assert_eq!(
        json(&["--version", "--json"], &[]),
        (
            0,
            format!(
                r#"{{"schema":"uaos.cli/1","command":"","exit_code":0,"result":{{"kind":"version","version":"{version}"}}}}"#
            )
        )
    );
    assert_eq!(
        json(&["--json", "nope"], &[]),
        (
            2,
            concat!(
                r#"{"schema":"uaos.cli/1","command":"nope","exit_code":2,"error":{"schema":"uaos.error/1","code":"UAOS-CLI-0001","class":"user","severity":"info","retryable":false,"#,
                r#""message_key":"error-cli-usage","agent_message":"The command line could not be read: an unknown command or option, or a missing value.","#,
                r#""remediation":"Run `uaos --help` for the commands and options.","secret_leak_risk":false,"correlation_id":"cor_00000000000177078707070707070707"},"#,
                r#""detail":"unknown command `nope`"}"#
            )
            .to_owned()
        )
    );
}

/// `config-holds-secret`: a configuration holding a key is refused, from the file or from a
/// variable, with exit 3, and the key appears in no output.
#[test]
fn a_configuration_holding_a_secret_is_refused() {
    const KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    let fs = sim();
    fs.create_dir_all(Path::new("/d")).unwrap();
    fs.write_atomic(
        Path::new("/d/config.toml"),
        format!("config_version = 1\n[kernel]\nlocale = \"{KEY}\"\n").as_bytes(),
    )
    .unwrap();
    for (args, env) in [
        (&["--data-dir", "/d", "config", "show"][..], &[][..]),
        (&["--data-dir", "/d", "init"][..], &[][..]),
        (&["--data-dir", "/e", "config", "show"][..], &[("UAOS_LOCALE", KEY)][..]),
        (
            &["--json", "--data-dir", "/e", "config", "show"][..],
            &[("UAOS_LOCALE", KEY)][..],
        ),
    ] {
        let out = invoke(&fs, args, env);
        assert_eq!(out.exit_code, 3, "{args:?}: {out:?}");
        let all = format!("{}{}", out.stdout, out.stderr);
        assert!(all.contains("UAOS-CONFIG-0003"), "{args:?}: {all}");
        assert!(all.contains("aws_access_key_id"), "the class is named: {all}");
        assert!(!all.contains(KEY), "{args:?} repeats the key: {all}");
    }
}

/// `init` creates the directory and the configuration once, and never overwrites one that is
/// there: an invalid one is refused, a valid one kept byte for byte.
#[test]
fn init_is_idempotent_and_keeps_what_it_finds() {
    let fs = sim();
    let first = invoke(&fs, &["--data-dir", "/d", "init"], &[]);
    assert_eq!(first.exit_code, 0, "{first:?}");
    assert_eq!(
        fs.read(Path::new("/d/config.toml")).unwrap(),
        uaos::config::DEFAULT_TEXT.as_bytes()
    );

    let mine = b"config_version = 1\n[admission]\nmax_operations = 3\n";
    fs.write_atomic(Path::new("/d/config.toml"), mine).unwrap();
    let again = invoke(&fs, &["--data-dir", "/d", "init"], &[]);
    assert_eq!(again.exit_code, 0, "{again:?}");
    assert!(again.stdout.contains("already initialized"));
    assert_eq!(fs.read(Path::new("/d/config.toml")).unwrap(), mine);

    fs.write_atomic(Path::new("/d/config.toml"), b"config_version = 1\nbad = 1\n")
        .unwrap();
    let invalid = invoke(&fs, &["--data-dir", "/d", "init"], &[]);
    assert_eq!(invalid.exit_code, 3, "{invalid:?}");
    assert_eq!(
        fs.read(Path::new("/d/config.toml")).unwrap(),
        b"config_version = 1\nbad = 1\n"
    );
}

/// `init` takes the lock the kernel's journal holds; while another holder has it, `init` changes
/// nothing and fails with the journal's own refusal.
#[test]
fn init_refuses_a_data_directory_another_process_holds() {
    let fs = sim();
    fs.create_dir_all(Path::new("/d")).unwrap();
    let held = fs.try_lock_exclusive(Path::new("/d/uaos.lock")).unwrap();
    let out = invoke(&fs, &["--json", "--data-dir", "/d", "init"], &[]);
    assert_eq!(out.exit_code, 3, "{out:?}");
    assert!(out.stdout.contains("UAOS-JOURNAL-0005"), "{out:?}");
    assert!(fs.read(Path::new("/d/config.toml")).is_err(), "nothing written");
    drop(held);
    assert_eq!(invoke(&fs, &["--data-dir", "/d", "init"], &[]).exit_code, 0);
}

/// `config show` without a file: environment and defaults, and the file's absence said.
#[test]
fn config_show_without_a_file_uses_the_environment_and_the_defaults() {
    let out = invoke(
        &sim(),
        &["--data-dir", "/none", "config", "show"],
        &[("UAOS_ADMISSION_MAX_OPERATIONS", "8")],
    );
    assert_eq!(out.exit_code, 0, "{out:?}");
    assert_eq!(
        slashes(&out.stdout),
        "# /none/config.toml does not exist; run `uaos init`.\n\
         config_version = 1  # default\n\
         kernel.locale = \"en\"  # default\n\
         admission.max_operations = 8  # environment\n\
         admission.max_bytes = 268435456  # default\n\
         journal.durability = \"balanced\"  # default\n"
    );
}

/// The default data directory follows each system's convention; without its variable, the
/// command says to pass `--data-dir` (exit 3).
#[test]
fn the_default_data_directory_follows_the_system() {
    let path = |os: Os, env: &[(&str, &str)]| {
        let args = ["config", "path"].iter().map(OsString::from).collect();
        let out = run(&invocation(&sim(), args, env, os));
        (out.exit_code, slashes(&out.stdout))
    };
    assert_eq!(
        path(Os::Unix, &[("HOME", "/home/u")]),
        (0, "/home/u/.local/share/uaos/config.toml\n".to_owned())
    );
    assert_eq!(
        path(Os::Unix, &[("HOME", "/home/u"), ("XDG_DATA_HOME", "/x")]),
        (0, "/x/uaos/config.toml\n".to_owned())
    );
    assert_eq!(
        path(Os::Unix, &[("HOME", "/home/u"), ("XDG_DATA_HOME", "relative")]),
        (0, "/home/u/.local/share/uaos/config.toml\n".to_owned()),
        "a relative XDG_DATA_HOME is ignored, as the specification says"
    );
    assert_eq!(
        path(Os::MacOs, &[("HOME", "/Users/u")]),
        (0, "/Users/u/Library/Application Support/uaos/config.toml\n".to_owned())
    );
    assert_eq!(
        path(Os::Unix, &[("UAOS_DATA_DIR", "/o"), ("HOME", "/home/u")]),
        (0, "/o/config.toml\n".to_owned())
    );
    assert_eq!(path(Os::Unix, &[]).0, 3);
    assert_eq!(path(Os::Windows, &[("HOME", "/home/u")]).0, 3);
}

/// On Unix the data directory is created readable only by its user.
#[cfg(unix)]
#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "reads the permissions the real file system gave, and cleans up after itself"
)]
fn the_data_directory_is_private_on_unix() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = std::env::temp_dir().join(format!("uaos-cli-private-{}", std::process::id()));
    let dir = root.join("nested").join("data");
    let real = sim();
    let mut inv = invocation(
        &real,
        vec!["--data-dir".into(), dir.clone().into_os_string(), "init".into()],
        &[],
        Os::Unix,
    );
    inv.fs = Arc::new(uaos_platform::real::fs::OsFs);
    let out = run(&inv);
    assert_eq!(out.exit_code, 0, "{out:?}");
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    let _cleanup = std::fs::remove_dir_all(&root);
    assert_eq!(mode, 0o700);
}

const INSTALLATION: &str = "956eeb2f2632d7bd03f166b233e3ef28";
const KEY: &str = "sk-test-0123456789abcdef0123456789";

/// A keychain whose every call fails with one error: none on the host, access refused, or an
/// error UAOS does not expect.
#[derive(Debug)]
struct FailingKeychain(uaos_platform::keychain::KeychainError);

impl Keychain for FailingKeychain {
    fn get(&self, _: &str) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, uaos_platform::keychain::KeychainError> {
        Err(self.0.clone())
    }
    fn set(&self, _: &str, _: &[u8]) -> Result<(), uaos_platform::keychain::KeychainError> {
        Err(self.0.clone())
    }
    fn delete(&self, _: &str) -> Result<bool, uaos_platform::keychain::KeychainError> {
        Err(self.0.clone())
    }
    fn backend(&self) -> &'static str {
        "no OS keychain"
    }
}

fn no_secret_service() -> Arc<FailingKeychain> {
    Arc::new(FailingKeychain(uaos_platform::keychain::KeychainError::Unavailable(
        "no Secret Service".to_owned(),
    )))
}

fn initialized() -> Sim {
    let s = sim();
    let out = invoke(&s, &["--data-dir", "/d", "init"], &[]);
    assert_eq!(out.exit_code, 0, "{out:?}");
    s
}

/// `init` creates the journal, whose id names the installation, and the installation's identity key
/// in the keychain; a second `init` keeps both.
#[test]
fn init_puts_the_identity_key_in_the_keychain() {
    let s = initialized();
    let account = format!("{INSTALLATION}/identity/hmac");
    let key = s.keychain.get(&account).unwrap().map(|k| k.to_vec());
    assert_eq!(key.as_ref().map(Vec::len), Some(32), "a 32-byte identity key");
    assert!(
        s.list_dir(Path::new("/d/journal")).unwrap().len() > 1,
        "the journal exists"
    );
    assert_eq!(invoke(&s, &["--data-dir", "/d", "init"], &[]).exit_code, 0);
    assert_eq!(s.keychain.get(&account).unwrap().map(|k| k.to_vec()), key, "kept");
}

/// Without an OS keychain, `init` says so and nothing falls back: the data directory, the journal
/// and the configuration are there, and `init` completes once a keychain is. A host without a
/// usable keychain is a setup problem, exit 3.
#[test]
fn init_without_a_keychain_says_so() {
    let s = sim();
    let mut inv = invocation(
        &s,
        ["--json", "--data-dir", "/d", "init"]
            .iter()
            .map(OsString::from)
            .collect(),
        &[],
        Os::Unix,
    );
    inv.keychain = no_secret_service();
    let out = run(&inv);
    assert_eq!(out.exit_code, 3, "{out:?}");
    assert!(
        out.stdout.contains(r#""code":"UAOS-CLI-0004""#)
            && out
                .stdout
                .contains(r#""detail":"no OS keychain: the OS keychain is not available: no Secret Service""#),
        "{out:?}"
    );
    assert!(s.read(Path::new("/d/config.toml")).is_ok());
    assert_eq!(invoke(&s, &["--data-dir", "/d", "init"], &[]).exit_code, 0, "resumable");
}

/// Each kind of keychain failure, through `init` and `key`: the host's own (none, refused) exits
/// 3; one UAOS does not expect exits 1. Nothing is stored either way.
#[test]
fn a_keychain_failure_exits_by_its_kind() {
    use uaos_platform::keychain::KeychainError;
    let cases = [
        (KeychainError::Unavailable("locked".to_owned()), 3, "UAOS-CLI-0004"),
        (KeychainError::Denied, 3, "UAOS-CLI-0004"),
        (KeychainError::Other("bus reset".to_owned()), 1, "UAOS-CLI-0005"),
        (KeychainError::Malformed, 1, "UAOS-CLI-0005"),
    ];
    for (error, code, id) in cases {
        let s = initialized();
        for args in [
            &["--data-dir", "/d", "init"][..],
            &["--data-dir", "/d", "key", "add", "openai"],
            &["--data-dir", "/d", "key", "list"],
        ] {
            s.feed(KEY.as_bytes());
            if args[2] == "key" && args[3] == "list" {
                // A listed key is looked up in the keychain; without one there is nothing to look up.
                s.write_atomic(
                    Path::new("/d/keys.json"),
                    br#"{"schema":"uaos.keys/1","keys":[{"name":"openai","state":"active","changed":"t"}]}"#,
                )
                .unwrap();
            }
            let mut inv = invocation(&s, args.iter().map(OsString::from).collect(), &[], Os::Unix);
            inv.keychain = Arc::new(FailingKeychain(error.clone()));
            let out = run(&inv);
            assert_eq!(out.exit_code, code, "{error:?} {args:?}: {out:?}");
            assert!(out.stderr.contains(id), "{error:?} {args:?}: {out:?}");
        }
        assert_eq!(
            s.keychain.get(&format!("{INSTALLATION}/provider/openai")).unwrap(),
            None
        );
    }
}

/// `status`, before and after `init`, exactly.
#[test]
fn status_says_what_it_finds() {
    let s = sim();
    let before = invoke(&s, &["--json", "--data-dir", "/d", "status"], &[]);
    assert_eq!(
        (before.exit_code, before.stdout.trim_end()),
        (
            0,
            r#"{"schema":"uaos.cli/1","command":"status","exit_code":0,"result":{"kind":"status","data_dir":"/d","initialized":false,"kernel_running":false,"config":"missing","provider_keys":0}}"#
        )
    );
    let _ = invoke(&s, &["--data-dir", "/d", "init"], &[]);
    let after = invoke(&s, &["--json", "--data-dir", "/d", "status"], &[]);
    assert_eq!(
        (after.exit_code, after.stdout.trim_end()),
        (
            0,
            concat!(
                r#"{"schema":"uaos.cli/1","command":"status","exit_code":0,"result":{"kind":"status","data_dir":"/d","initialized":true,"kernel_running":false,"config":"valid","#,
                r#""journal":{"journal_id":"956eeb2f2632d7bd03f166b233e3ef28","records":0,"next_seq":0,"head":"sha256:dd68f442ddce934d3a674938f68b91f50258a8d4ac9a7d513aa2d10ffc631cc7","segments":1,"ignored_tail_bytes":0,"stop":"running"},"#,
                r#""provider_keys":0}}"#
            )
        )
    );
    let held = s.try_lock_exclusive(Path::new("/d/uaos.lock")).unwrap();
    let running = invoke(&s, &["--data-dir", "/d", "status"], &[]);
    drop(held);
    assert!(
        running.stdout.contains("Kernel: running") && running.stdout.contains("not read while the kernel runs"),
        "{running:?}"
    );
}

/// `journal verify` and `export` read under the lock, so never while a kernel writes.
#[test]
fn the_journal_is_verified_and_exported_under_the_lock() {
    let s = initialized();
    let verify = invoke(&s, &["--data-dir", "/d", "journal", "verify"], &[]);
    assert_eq!(verify.exit_code, 0, "{verify:?}");
    assert!(
        verify
            .stdout
            .starts_with("The journal verifies: 0 records in 1 segment(s)"),
        "{verify:?}"
    );
    let export = invoke(&s, &["--json", "--data-dir", "/d", "journal", "export"], &[]);
    assert_eq!(
        export.stdout.trim_end(),
        r#"{"schema":"uaos.cli/1","command":"journal export","exit_code":0,"result":{"kind":"journal_export","records":[]}}"#
    );
    let held = s.try_lock_exclusive(Path::new("/d/uaos.lock")).unwrap();
    let locked = invoke(&s, &["--data-dir", "/d", "journal", "verify"], &[]);
    drop(held);
    assert_eq!(locked.exit_code, 3, "{locked:?}");
    assert!(locked.stderr.contains("UAOS-JOURNAL-0005"));
    assert_eq!(
        invoke(&sim(), &["--data-dir", "/none", "journal", "export"], &[]).exit_code,
        3
    );
}

/// A provider key lives only in the OS keychain, under the installation: added, listed, rotated and
/// revoked, and never in any output or file.
#[test]
fn provider_keys_live_only_in_the_keychain() {
    let s = initialized();
    let account = format!("{INSTALLATION}/provider/anthropic");
    let mut outputs = Vec::new();
    let mut step = |args: &[&str], code: u8| {
        let out = invoke(&s, args, &[]);
        assert_eq!(out.exit_code, code, "{args:?}: {out:?}");
        outputs.push(format!("{}{}", out.stdout, out.stderr));
        out
    };
    s.feed(format!("{KEY}\n").as_bytes());
    step(&["--data-dir", "/d", "key", "add", "anthropic"], 0);
    assert_eq!(
        s.keychain.get(&account).unwrap().map(|k| k.to_vec()),
        Some(KEY.as_bytes().to_vec()),
        "without its line end"
    );
    step(&["--data-dir", "/d", "key", "add", "anthropic"], 2);
    let list = step(&["--json", "--data-dir", "/d", "key", "list"], 0);
    assert!(
        list.stdout
            .contains(r#""keys":[{"name":"anthropic","state":"active","changed":""#),
        "{list:?}"
    );
    assert!(list.stdout.contains(r#""in_keychain":true"#));
    s.feed(b"sk-test-rotated-9876543210");
    step(&["--data-dir", "/d", "key", "rotate", "anthropic"], 0);
    assert_eq!(
        s.keychain.get(&account).unwrap().map(|k| k.to_vec()),
        Some(b"sk-test-rotated-9876543210".to_vec())
    );
    step(&["--data-dir", "/d", "key", "revoke", "anthropic"], 0);
    assert_eq!(s.keychain.get(&account).unwrap(), None);
    let revoked = step(&["--data-dir", "/d", "key", "list"], 0);
    assert!(
        revoked.stdout.starts_with("anthropic  revoked  ") && revoked.stdout.contains("not in the keychain"),
        "{revoked:?}"
    );
    step(&["--data-dir", "/d", "key", "rotate", "anthropic"], 2);
    step(&["--data-dir", "/d", "key", "revoke", "anthropic"], 2);
    let index = String::from_utf8(s.read(Path::new("/d/keys.json")).unwrap()).unwrap();
    for text in outputs.iter().chain(std::iter::once(&index)) {
        assert!(
            !text.contains(KEY) && !text.contains("rotated-98"),
            "a key leaked: {text}"
        );
    }
}

/// Every way a key is refused, with nothing stored and nothing repeated.
#[test]
fn a_key_is_refused_unless_it_is_piped_and_plain() {
    let s = initialized();
    let add = |name: &str, stdin: &[u8], terminal: bool| {
        s.feed(stdin);
        let mut inv = invocation(
            &s,
            ["--data-dir", "/d", "key", "add", name]
                .iter()
                .map(OsString::from)
                .collect(),
            &[],
            Os::Unix,
        );
        inv.stdin_is_terminal = terminal;
        run(&inv)
    };
    let typed = add("anthropic", KEY.as_bytes(), true);
    assert_eq!(typed.exit_code, 2, "{typed:?}");
    assert!(typed.stderr.contains("pipe it"), "{typed:?}");
    for (name, stdin) in [
        ("anthropic", &b""[..]),
        ("anthropic", b"two words"),
        ("anthropic", "s\u{e7}cret".as_bytes()),
        ("Anthropic", KEY.as_bytes()),
        ("../x", KEY.as_bytes()),
    ] {
        let out = add(name, stdin, false);
        assert_eq!(out.exit_code, 2, "{name} {stdin:?}: {out:?}");
        assert!(
            !out.stderr.contains("two words") && !out.stderr.contains(KEY),
            "{out:?}"
        );
    }
    let held = s.try_lock_exclusive(Path::new("/d/uaos.lock")).unwrap();
    let locked = add("anthropic", KEY.as_bytes(), false);
    drop(held);
    assert_eq!(locked.exit_code, 3, "{locked:?}");
    assert_eq!(
        s.keychain.get(&format!("{INSTALLATION}/provider/anthropic")).unwrap(),
        None,
        "nothing stored"
    );
    assert!(s.read(Path::new("/d/keys.json")).is_err(), "no index");
}

/// `doctor` on a healthy installation, then each failure it must see.
#[test]
fn doctor_checks_the_installation() {
    let s = initialized();
    let healthy = invoke(&s, &["--data-dir", "/d", "doctor"], &[]);
    assert_eq!(healthy.exit_code, 0, "{healthy:?}");
    let names: Vec<&str> = healthy
        .stdout
        .lines()
        .filter_map(|l| l.get(6..)?.split(':').next())
        .collect();
    assert_eq!(
        names,
        [
            "data_dir",
            "data_dir.private",
            "data_dir.synced",
            "config",
            "kernel",
            "journal",
            "stop",
            "keychain",
            "keys",
            "tls.roots"
        ]
    );
    assert!(healthy.stdout.lines().all(|l| l.starts_with("ok  ")), "{healthy:?}");

    let warned = invoke(&s, &["--data-dir", "/d", "doctor"], &[("SSL_CERT_FILE", "/etc/x.pem")]);
    assert_eq!(warned.exit_code, 0);
    assert!(
        warned.stdout.contains("warn  tls.roots: SSL_CERT_FILE set"),
        "{warned:?}"
    );

    s.feed(KEY.as_bytes());
    assert_eq!(
        invoke(&s, &["--data-dir", "/d", "key", "add", "openai"], &[]).exit_code,
        0
    );
    let _gone = s.keychain.delete(&format!("{INSTALLATION}/provider/openai")).unwrap();
    let missing = invoke(&s, &["--json", "--data-dir", "/d", "doctor"], &[]);
    assert_eq!(missing.exit_code, 3, "{missing:?}");
    assert!(
        missing
            .stdout
            .contains(r#"{"name":"keys","status":"fail","detail":"active but missing from the keychain: openai"}"#),
        "{missing:?}"
    );
    assert!(
        missing.stdout.contains(r#""code":"UAOS-CLI-0003""#)
            && missing.stdout.contains(r#""detail":"failed checks: keys""#)
    );

    let _identity = s.keychain.delete(&format!("{INSTALLATION}/identity/hmac")).unwrap();
    let lost = invoke(&s, &["--data-dir", "/d", "doctor"], &[]);
    assert!(
        lost.stdout
            .contains("FAIL  keychain: simulated: the installation's identity key is missing"),
        "{lost:?}"
    );

    let none = invoke(&sim(), &["--data-dir", "/none", "doctor"], &[]);
    assert_eq!(none.exit_code, 3);
    assert!(
        none.stdout
            .starts_with("FAIL  data_dir: the data directory does not exist"),
        "{none:?}"
    );
}

/// A change whose index cannot be written (a failed flush, a full disk) leaves the keychain as it
/// was, so the CLI never makes the index and the keychain disagree.
#[test]
fn a_failed_index_write_leaves_the_keychain_as_it_was() {
    let s = initialized();
    let openai = format!("{INSTALLATION}/provider/openai");
    s.feed(KEY.as_bytes());
    assert_eq!(
        invoke(&s, &["--data-dir", "/d", "key", "add", "openai"], &[]).exit_code,
        0
    );
    s.feed(b"sk-test-replacement-0000");
    s.fail_next_sync();
    let rotate = invoke(&s, &["--data-dir", "/d", "key", "rotate", "openai"], &[]);
    assert_eq!(rotate.exit_code, 3, "{rotate:?}");
    assert_eq!(
        s.keychain.get(&openai).unwrap().map(|k| k.to_vec()),
        Some(KEY.as_bytes().to_vec()),
        "the old key"
    );
    s.feed(KEY.as_bytes());
    s.fail_next_sync();
    let add = invoke(&s, &["--data-dir", "/d", "key", "add", "mistral"], &[]);
    assert_eq!(add.exit_code, 3, "{add:?}");
    assert_eq!(
        s.keychain.get(&format!("{INSTALLATION}/provider/mistral")).unwrap(),
        None,
        "no new key"
    );
    let list = invoke(&s, &["--data-dir", "/d", "key", "list"], &[]);
    assert_eq!(list.stdout.lines().count(), 1, "{list:?}");
    assert!(list.stdout.starts_with("openai  active  "), "{list:?}");
}

/// A second `init` only reads the journal: it writes none of the journal's files, so a journal a
/// kernel keeps payloads for, or sealed at a clean shutdown, stays as the kernel left it.
#[test]
fn a_second_init_leaves_the_journal_as_it_was() {
    let s = initialized();
    let dir = Path::new("/d/journal");
    s.write_atomic(&dir.join("PAYLOADS"), b"uaos.payloads/1\n").unwrap();
    let files = |s: &Sim| -> Vec<(std::path::PathBuf, Vec<u8>)> {
        let names = s.list_dir(dir).unwrap();
        names.into_iter().map(|n| (n.clone(), s.read(&n).unwrap())).collect()
    };
    let before = files(&s);
    let again = invoke(&s, &["--data-dir", "/d", "init"], &[]);
    assert_eq!(again.exit_code, 0, "{again:?}");
    assert_eq!(files(&s), before, "the journal's files are unchanged");
}
