// SPDX-License-Identifier: Apache-2.0

//! `cargo xtask clippy`: clippy over the workspace with warnings denied, failing also on a
//! `clippy.toml` ban whose path resolves to nothing. Clippy reports such a path only as a warning
//! that `-D warnings` does not make fatal, so a typo, or an item moving upstream, would quietly
//! switch a ban off. Cargo is asked for plain text and colour codes are removed anyway: CI colours
//! output, and a coloured header never starts with `warning:`. A note with no warning above it
//! fails the gate too. Paths that draw no warning at all are caught by the canaries in
//! `crates/uaos-egress/tests/bans.rs`.

use std::path::Path;
use std::process::Command;

/// The note clippy attaches to every `clippy.toml` path it cannot resolve.
const UNRESOLVED: &str = "add `allow-invalid = true` to the entry to suppress this warning";

const ARGS: &[&str] = &[
    "clippy",
    "--color",
    "never",
    "--workspace",
    "--all-targets",
    "--locked",
    "--",
    "-D",
    "warnings",
];

pub(crate) fn check(root: &Path) -> Result<(), String> {
    println!("xtask: [clippy] cargo {}", ARGS.join(" "));
    let out = clippy_command(root, &[])
        .output()
        .map_err(|e| format!("[clippy] could not start `cargo`: {e}"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    print!("{}", String::from_utf8_lossy(&out.stdout));
    eprint!("{stderr}");
    // Reported first, also when clippy fails too: a ban that resolves to nothing usually also
    // leaves its canary unfulfilled, and the cause matters more than the symptom.
    let unresolved = unresolved_bans(&stderr);
    if !unresolved.is_empty() {
        return Err(format!(
            "[clippy] clippy.toml bans paths that resolve to nothing, so those bans are off:\n  {}",
            unresolved.join("\n  ")
        ));
    }
    if !out.status.success() {
        return Err(format!("[clippy] failed ({})", out.status));
    }
    // The same build again, now fresh, for the files rustc read (`sources.rs`).
    let messages = clippy_command(root, &["--message-format=json"])
        .output()
        .map_err(|e| format!("[clippy] could not start `cargo`: {e}"))?;
    if !messages.status.success() {
        // Its own output, not only the status.
        return Err(format!(
            "[clippy] the JSON pass failed ({}):\n{}",
            messages.status,
            String::from_utf8_lossy(&messages.stderr)
        ));
    }
    crate::sources::check_build(root, "clippy build", &messages.stdout)
}

/// `cargo clippy` with the gate's arguments, its environment cleared of what could change lint
/// levels, compiler flags or clippy's configuration outside the workspace lint table: an empty
/// `CARGO_ENCODED_RUSTFLAGS` takes priority over every other source of compiler flags (`RUSTFLAGS`
/// in any case on Windows, `CARGO_TARGET_*_RUSTFLAGS`, any Cargo configuration's `rustflags`), an
/// empty `RUSTC_WRAPPER` overrides any configured wrapper, `CLIPPY_ARGS` is removed, and
/// `CLIPPY_CONF_DIR` names the workspace root, so a machine's Cargo `[env]` without `force` cannot
/// point clippy elsewhere either (9; Windows matches these names in any case).
fn clippy_command(root: &Path, cargo_args: &[&str]) -> Command {
    // Cargo's own arguments go before the `--` that starts clippy's.
    let split = ARGS.iter().position(|a| *a == "--").unwrap_or(ARGS.len());
    let (cargo, lints) = ARGS.split_at(split);
    let mut command = Command::new("cargo");
    command
        .args(cargo)
        .args(cargo_args)
        .args(lints)
        .current_dir(root)
        .env("CARGO_ENCODED_RUSTFLAGS", "")
        .env("RUSTC_WRAPPER", "")
        .env_remove("CLIPPY_ARGS")
        .env("CLIPPY_CONF_DIR", root);
    command
}

/// The warnings clippy printed for `clippy.toml` paths it could not resolve: for each note, the
/// nearest `warning:` line above it, or the note itself if there is none (fail closed).
fn unresolved_bans(stderr: &str) -> Vec<String> {
    let lines: Vec<String> = stderr.lines().map(strip_ansi).collect();
    let mut found: Vec<String> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains(UNRESOLVED))
        .map(|(i, note)| {
            lines
                .iter()
                .take(i)
                .rev()
                .find(|l| l.starts_with("warning:"))
                .unwrap_or(note)
                .trim()
                .to_owned()
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

/// `line` without ANSI escape sequences (`ESC [ ... final byte`).
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.next() == Some('[') {
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unresolved_ban_is_found_and_reported_once() {
        let stderr = "warning: `a::b` does not refer to a reachable function\n  --> clippy.toml:3:5\n  = note: add `allow-invalid = true` to the entry to suppress this warning\nwarning: `a::b` does not refer to a reachable function\n  = note: add `allow-invalid = true` to the entry to suppress this warning\n    Finished `dev` profile\n";
        assert_eq!(
            unresolved_bans(stderr),
            vec!["warning: `a::b` does not refer to a reachable function".to_owned()]
        );
        assert!(unresolved_bans("warning: unused variable `x`\n    Finished\n").is_empty());
    }

    /// CI colours cargo's output; the coloured header must still be found.
    #[test]
    fn a_coloured_unresolved_ban_is_found() {
        let stderr = "\x1b[1m\x1b[93mwarning\x1b[0m\x1b[1m\x1b[97m: `a::b` does not refer to a reachable function\x1b[0m\n   \x1b[1m\x1b[96m|\x1b[0m\n   \x1b[1m\x1b[96m= \x1b[0m\x1b[1m\x1b[97mhelp\x1b[0m: add `allow-invalid = true` to the entry to suppress this warning\n";
        assert_eq!(
            unresolved_bans(stderr),
            vec!["warning: `a::b` does not refer to a reachable function".to_owned()]
        );
    }

    /// The child runs without outside compiler flags, wrapper or clippy arguments, and with the
    /// root's clippy configuration, whatever the caller's environment holds.
    #[test]
    fn the_child_environment_is_neutralised() {
        let command = clippy_command(Path::new("."), &[]);
        let envs: Vec<(String, Option<String>)> = command
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().to_ascii_uppercase(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for (name, value) in [
            ("CARGO_ENCODED_RUSTFLAGS", Some(String::new())),
            ("RUSTC_WRAPPER", Some(String::new())),
            ("CLIPPY_ARGS", None),
            ("CLIPPY_CONF_DIR", Some(".".to_owned())),
        ] {
            assert!(envs.contains(&(name.to_owned(), value.clone())), "{name}: {envs:?}");
        }
    }

    /// A note with no warning above it still fails the gate.
    #[test]
    fn a_note_without_its_warning_fails_closed() {
        let stderr = "  = help: add `allow-invalid = true` to the entry to suppress this warning\n";
        assert_eq!(unresolved_bans(stderr).len(), 1);
    }
}
