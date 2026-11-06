// SPDX-License-Identifier: Apache-2.0

//! Gate self-tests: every active merge gate must be shown to **fail** on a seeded violation (P0
//! acceptance). A gate that has never been seen failing is not a gate.
//!
//! For each case the workspace is copied to `target/xtask-negative/<case>`, the gate command
//! is run once on the clean copy (it must pass: this proves the failure below is caused by
//! the seed, not by an unrelated break), the violation is applied, and the gate is run again
//! (it must fail, and its output must name the violation).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::util::{rel, walk_files, workspace_root};

/// How a gate is invoked.
enum Runner {
    /// An external program run in the copy.
    Program {
        program: &'static str,
        args: &'static [&'static str],
    },
    /// An xtask subcommand run in the copy (built into the shared target directory).
    Xtask(&'static [&'static str]),
    /// A git-history gate exercised in a scratch repository: `(clean, violating)` commits.
    History(
        fn(&Path, &str) -> Result<(), String>,
        fn(&Path) -> Result<(String, String), String>,
    ),
}

/// Applies a seeded violation to a workspace copy.
type Seed = Box<dyn Fn(&Path) -> Result<(), String>>;

pub(crate) struct Case {
    pub(crate) id: &'static str,
    pub(crate) gate: &'static str,
    tool: Option<&'static str>,
    seed: Seed,
    runner: Runner,
    expect: &'static str,
}

const CLIPPY: Runner = Runner::Program {
    program: "cargo",
    args: &[
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ],
};
const LIB: &str = "crates/uaos-contracts/src/limits.rs";
/// A case's `tool` when its seed only compiles on Unix. Elsewhere it does not run and does not
/// count as skipped; the CI negative job, which runs on Linux with `--require-all-tools`, runs it.
const UNIX_ONLY: &str = "unix";
/// Likewise for Windows. The CI negative job never runs these: they are proven by running the
/// negatives on Windows.
const WINDOWS_ONLY: &str = "windows";
/// Likewise for Linux, when the test it runs exists only there; the CI negative job runs it.
const LINUX_ONLY: &str = "linux";

fn append(path: &'static str, text: &'static str) -> Seed {
    Box::new(move |ws| {
        let p = ws.join(path);
        let mut s = std::fs::read_to_string(&p).map_err(|e| format!("{path}: {e}"))?;
        s.push_str(text);
        std::fs::write(&p, s).map_err(|e| format!("{path}: {e}"))
    })
}

/// Like [`append`], for text built at run time. Seeds that spell out a guarded attribute are
/// assembled from parts, so this file never contains the attribute `allow-audit` looks for.
fn append_owned(path: &'static str, text: String) -> Seed {
    Box::new(move |ws| {
        let p = ws.join(path);
        let mut s = std::fs::read_to_string(&p).map_err(|e| format!("{path}: {e}"))?;
        s.push_str(&text);
        std::fs::write(&p, s).map_err(|e| format!("{path}: {e}"))
    })
}

fn replace(path: &'static str, old: &'static str, new: &'static str) -> Seed {
    Box::new(move |ws| {
        let p = ws.join(path);
        let s = std::fs::read_to_string(&p).map_err(|e| format!("{path}: {e}"))?;
        // Exactly once: an anchor that also matches elsewhere would seed the first match, which
        // may not be the site the case is about, and the case would then prove nothing.
        match s.matches(old).count() {
            0 => {
                return Err(format!(
                    "seed anchor not found in {path} (update the negative case): {old:?}"
                ));
            }
            1 => {}
            n => {
                return Err(format!(
                    "seed anchor occurs {n} times in {path} (make it unique to its site): {old:?}"
                ));
            }
        }
        std::fs::write(&p, s.replacen(old, new, 1)).map_err(|e| format!("{path}: {e}"))
    })
}

fn write(path: &'static str, text: String) -> Seed {
    Box::new(move |ws| {
        let p = ws.join(path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{path}: {e}"))?;
        }
        std::fs::write(&p, &text).map_err(|e| format!("{path}: {e}"))
    })
}

/// A package in the excluded `fuzz/` folder whose library is `uaos-json`'s source, and an edge to
/// it from the scan crate. With `lock`, the lock file is brought up to date, as a `--locked` build
/// needs.
fn tape_shim(lock: bool) -> Seed {
    let shim = write(
        "fuzz/tape-shim/Cargo.toml",
        "[package]\nname = \"tape-shim\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n\
         [lib]\npath = \"../../crates/uaos-json/src/lib.rs\"\n\n[dependencies]\nmemchr = \"2\"\n"
            .to_owned(),
    );
    let edge = replace(
        "crates/uaos-redact-scan/Cargo.toml",
        "uaos-contracts.workspace = true\n",
        "uaos-contracts.workspace = true\ntape-shim = { path = \"../../fuzz/tape-shim\" }\n",
    );
    both(
        both(shim, edge),
        Box::new(move |ws| {
            if !lock {
                return Ok(());
            }
            let out = Command::new("cargo")
                .args(["metadata", "--offline", "--format-version", "1"])
                .current_dir(ws)
                .output()
                .map_err(|e| format!("cargo metadata: {e}"))?;
            if out.status.success() {
                Ok(())
            } else {
                Err(format!("cargo metadata: {}", String::from_utf8_lossy(&out.stderr)))
            }
        }),
    )
}

fn both(a: Seed, b: Seed) -> Seed {
    Box::new(move |ws| {
        a(ws)?;
        b(ws)
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "a flat table of cases reads better than indirection"
)]
pub(crate) fn cases() -> Vec<Case> {
    vec![
        Case {
            id: "fmt-unformatted",
            gate: "fmt",
            tool: None,
            seed: append(LIB, "\nconst   SEEDED_VIOLATION :u8=1;\n"),
            runner: Runner::Program { program: "cargo", args: &["fmt", "--all", "--", "--check"] },
            expect: "Diff in",
        },
        Case {
            id: "clippy-unwrap",
            gate: "clippy",
            tool: None,
            seed: append(LIB, "\n/// Seeded.\n#[must_use]\npub fn seeded_violation() -> u8 {\n    Some(1_u8).unwrap()\n}\n"),
            runner: CLIPPY,
            expect: "unwrap",
        },
        Case {
            id: "clippy-unsafe",
            gate: "clippy",
            tool: None,
            seed: append(LIB, "\n/// Seeded.\n#[must_use]\npub fn seeded_violation(p: &u8) -> u8 {\n    unsafe { *core::ptr::from_ref(p) }\n}\n"),
            runner: CLIPPY,
            expect: "unsafe",
        },
        Case {
            id: "clippy-ambient-clock",
            gate: "clippy",
            tool: None,
            seed: append(LIB, "\n/// Seeded.\n#[must_use]\npub fn seeded_violation() -> std::time::SystemTime {\n    std::time::SystemTime::now()\n}\n"),
            runner: CLIPPY,
            expect: "disallowed method",
        },
        Case {
            id: "clippy-nondeterministic-map",
            gate: "clippy",
            tool: None,
            seed: append(LIB, "\n/// Seeded.\n#[must_use]\npub fn seeded_violation() -> std::collections::HashMap<u8, u8> {\n    std::collections::HashMap::new()\n}\n"),
            runner: CLIPPY,
            expect: "disallowed type",
        },
        // The API documentation builds with rustdoc's lints denied: a public item's doc that links
        // to a crate-private one fails `cargo doc`.
        Case {
            id: "doc-links-private-item",
            gate: "clippy",
            tool: None,
            seed: replace(
                "crates/uaos-egress/src/connect.rs",
                "/// A point-in-time copy of the door's counters.\n",
                "/// A point-in-time copy of [`Counters`].\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["doc", "--workspace", "--no-deps", "--locked"],
            },
            expect: "links to private item",
        },
        Case {
            id: "test-failure",
            gate: "test",
            tool: None,
            seed: append(LIB, "\n#[cfg(test)]\nmod seeded_violation {\n    #[test]\n    fn fails() {\n        assert_eq!(1 + 1, 3);\n    }\n}\n"),
            runner: Runner::Program { program: "cargo", args: &["test", "--workspace", "--locked"] },
            expect: "seeded_violation",
        },
        Case {
            id: "arch-forbidden-edge",
            gate: "arch-check",
            tool: None,
            seed: replace("arch.toml", "[crate.uaos-platform]\nring = 0\nallow = [\"uaos-contracts\"]", "[crate.uaos-platform]\nring = 0\nallow = []"),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "edge not allowed",
        },
        // The final scan's crate gains an edge to the shared tokenizer, so a fault in the tokenizer
        // could hide a secret from both redaction and the final scan.
        Case {
            id: "final-scan-crate-reaches-tape",
            gate: "arch-check",
            tool: None,
            seed: replace(
                "crates/uaos-redact-scan/Cargo.toml",
                "uaos-contracts.workspace = true\n",
                "uaos-contracts.workspace = true\nuaos-json.workspace = true\n",
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "uaos-redact-scan -> uaos-json: edge not allowed",
        },
        // The scan crate's ban holds on its own, even if an edge is allowed.
        Case {
            id: "final-scan-ban-dropped",
            gate: "arch-check",
            tool: None,
            seed: both(
                replace(
                    "arch.toml",
                    "allow = [\"uaos-contracts\"]\nban = [\"uaos-json\", \"tokio\", \"hyper\", \"reqwest\", \"rusqlite\"]\n",
                    "allow = [\"uaos-contracts\", \"uaos-json\"]\nban = [\"uaos-json\", \"tokio\", \"hyper\", \"reqwest\", \"rusqlite\"]\n",
                ),
                replace(
                    "crates/uaos-redact-scan/Cargo.toml",
                    "uaos-contracts.workspace = true\n",
                    "uaos-contracts.workspace = true\nuaos-json.workspace = true\n",
                ),
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "uaos-redact-scan: transitively depends on banned crate `uaos-json`",
        },
        // An edge behind a feature no default enables is still an edge.
        Case {
            id: "arch-optional-edge-unseen",
            gate: "arch-check",
            tool: None,
            seed: replace(
                "crates/uaos-redact-scan/Cargo.toml",
                "uaos-contracts.workspace = true\n",
                "uaos-contracts.workspace = true\nuaos-json = { workspace = true, optional = true }\n\n[features]\ntape = [\"dep:uaos-json\"]\n",
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "uaos-redact-scan -> uaos-json: edge not allowed",
        },
        // The scan's own tests may not build on the tape.
        Case {
            id: "arch-dev-dependency-reaches-tape",
            gate: "arch-check",
            tool: None,
            seed: replace(
                "crates/uaos-redact-scan/Cargo.toml",
                "uaos-contracts.workspace = true\n",
                "uaos-contracts.workspace = true\n\n[dev-dependencies]\nuaos-json.workspace = true\n",
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "its dev-dependency `uaos-json` reaches `uaos-json`",
        },
        // Another crate's source compiled in by `#[path]` shows in no dependency graph.
        Case {
            id: "arch-source-from-another-crate",
            gate: "arch-check",
            tool: None,
            // A target whose root lies in another crate.
            seed: replace(
                "crates/uaos-redact-scan/Cargo.toml",
                "[lib]\ndoctest = false\n",
                "[lib]\ndoctest = false\npath = \"../uaos-json/src/lib.rs\"\n",
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "has its root outside the crate",
        },
        // A local package outside the workspace is under no rule of arch.toml.
        Case {
            id: "arch-local-package-outside-workspace",
            gate: "arch-check",
            tool: None,
            seed: tape_shim(false),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "tape-shim: a local package outside the workspace",
        },
        // A dependency under another name, or an `extern crate` at a root, could give the scan
        // crate's name to another crate.
        Case {
            id: "arch-renamed-dependency",
            gate: "arch-check",
            tool: None,
            seed: replace(
                "crates/uaos-redact/Cargo.toml",
                "uaos-redact-scan.workspace = true\n",
                "scan = { package = \"uaos-redact-scan\", path = \"../uaos-redact-scan\" }\n",
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "depends on `uaos-redact-scan` as `scan`",
        },
        Case {
            id: "arch-extern-crate-at-root",
            gate: "arch-check",
            tool: None,
            seed: append("crates/uaos-redact/src/lib.rs", "\nextern crate self as uaos_redact_scan;\n"),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "declares `extern crate self` at its root",
        },
        // The same, behind a raw C string that a text scan read as escaped, which hid everything up
        // to the next quote.
        Case {
            id: "arch-extern-crate-behind-c-string",
            gate: "arch-check",
            tool: None,
            seed: append(
                "crates/uaos-redact/src/lib.rs",
                "\nconst _MASK: &::core::ffi::CStr = cr\"\\\";\nextern crate self as uaos_redact_scan;\nconst _UNMASK: char = '\"';\n",
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "declares `extern crate self` at its root",
        },
        // Without the edge, rustc lets a macro give the scan crate's name to another crate.
        Case {
            id: "arch-required-edge-dropped",
            gate: "arch-check",
            tool: None,
            seed: replace("crates/uaos-redact/Cargo.toml", "uaos-redact-scan.workspace = true\n", ""),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "must depend on `uaos-redact-scan`",
        },
        // A library named after another crate.
        Case {
            id: "arch-library-renamed",
            gate: "arch-check",
            tool: None,
            seed: replace(
                "crates/uaos-redact-scan/Cargo.toml",
                "[lib]\ndoctest = false\n",
                "[lib]\ndoctest = false\nname = \"scan\"\n",
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "its library is named `scan`",
        },
        // A build-dependency whose file APIs no clippy ban names could copy the tokenizer into the
        // scan crate's OUT_DIR; so could a build script.
        Case {
            id: "arch-pinned-build-dependency",
            gate: "arch-check",
            tool: None,
            seed: append("crates/uaos-redact-scan/Cargo.toml", "\n[build-dependencies]\nsame-file = \"1\"\n"),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "depends on `same-file`, which its pinned build in arch.toml does not list",
        },
        Case {
            id: "arch-pinned-build-script",
            gate: "arch-check",
            tool: None,
            seed: write(
                "crates/uaos-redact-scan/build.rs",
                "// SPDX-License-Identifier: Apache-2.0\n\n//! Seeded.\n\nfn main() {}\n".to_owned(),
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "has a build script",
        },
        // A workspace crate the scan crate reaches is part of its build.
        Case {
            id: "arch-pinned-closure-unpinned",
            gate: "arch-check",
            tool: None,
            seed: replace(
                "arch.toml",
                "pinned = [\"jiff\", \"schemars\", \"serde\", \"serde_json\", \"thiserror\", \"uuid\"]\n",
                "",
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "reaches `uaos-contracts`, whose build arch.toml must pin too",
        },
        Case {
            id: "arch-pinned-closure-build-script",
            gate: "arch-check",
            tool: None,
            seed: write(
                "crates/uaos-contracts/build.rs",
                "// SPDX-License-Identifier: Apache-2.0\n\n//! Seeded.\n\nfn main() {}\n".to_owned(),
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "uaos-contracts: has a build script",
        },
        // Before edition 2021, literals lex otherwise than the readers of arch-check and
        // allow-audit.
        Case {
            id: "arch-old-edition",
            gate: "arch-check",
            tool: None,
            seed: replace("crates/uaos-redact/Cargo.toml", "edition.workspace = true\n", "edition = \"2018\"\n"),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "uaos-redact: edition 2018",
        },
        // An optional or a target-specific edge may leave the name off rustc's command line.
        Case {
            id: "arch-required-edge-optional",
            gate: "arch-check",
            tool: None,
            seed: replace(
                "crates/uaos-redact/Cargo.toml",
                "uaos-redact-scan.workspace = true\n",
                "uaos-redact-scan = { workspace = true, optional = true }\n",
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "must depend on `uaos-redact-scan`, unconditionally",
        },
        Case {
            id: "arch-required-edge-conditional",
            gate: "arch-check",
            tool: None,
            seed: both(
                replace("crates/uaos-redact/Cargo.toml", "uaos-redact-scan.workspace = true\n", ""),
                append(
                    "crates/uaos-redact/Cargo.toml",
                    "\n[target.'cfg(any())'.dependencies]\nuaos-redact-scan.workspace = true\n",
                ),
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "must depend on `uaos-redact-scan`, unconditionally",
        },
        // A feature makes a build no gate checks.
        Case {
            id: "arch-pinned-features",
            gate: "arch-check",
            tool: None,
            seed: append("crates/uaos-redact-scan/Cargo.toml", "\n[features]\nfast = []\n"),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "declares features (fast)",
        },
        // Doctests build outside the checks that hold `dev_ban`.
        Case {
            id: "arch-dev-ban-doctests-on",
            gate: "arch-check",
            tool: None,
            seed: replace("crates/uaos-redact-scan/Cargo.toml", "[lib]\ndoctest = false\n", "[lib]\n"),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "runs doctests",
        },
        // What rustc read, not how the path is spelled. A path built by a macro.
        Case {
            id: "foreign-source-built-path",
            gate: "sources",
            tool: None,
            seed: append(
                "crates/uaos-redact-scan/src/lib.rs",
                "\nconst _: &str = include_str!(concat!(\"../../uaos-json/\", \"Cargo.toml\"));\n",
            ),
            runner: Runner::Xtask(&["sources", "uaos-redact-scan"]),
            expect: "compiles in",
        },
        // A path behind `cfg_attr`, in a raw string.
        Case {
            id: "foreign-source-cfg-attr-raw",
            gate: "sources",
            tool: None,
            seed: append(
                "crates/uaos-redact-scan/src/lib.rs",
                "\n#[cfg_attr(all(), doc = include_str!(r\"../../uaos-json/Cargo.toml\"))]\nconst _: () = ();\n",
            ),
            runner: Runner::Xtask(&["sources", "uaos-redact-scan"]),
            expect: "compiles in",
        },
        // A file inside the crate that is a symlink to another crate's.
        Case {
            id: "foreign-source-symlink",
            gate: "sources",
            tool: Some(UNIX_ONLY),
            seed: both(
                Box::new(|ws| {
                    #[cfg(unix)]
                    {
                        std::os::unix::fs::symlink(
                            "../../uaos-json/Cargo.toml",
                            ws.join("crates/uaos-redact-scan/src/tape.txt"),
                        )
                        .map_err(|e| format!("symlink: {e}"))
                    }
                    #[cfg(not(unix))]
                    {
                        Err(format!("this seed runs on Unix only, not in {}", ws.display()))
                    }
                }),
                append("crates/uaos-redact-scan/src/lib.rs", "\nconst _: &str = include_str!(\"tape.txt\");\n"),
            ),
            runner: Runner::Xtask(&["sources", "uaos-redact-scan"]),
            expect: "compiles in",
        },
        // A file only builds the clippy gate does not make read, in the dev and in the release
        // profile.
        Case {
            id: "foreign-source-outside-clippy",
            gate: "sources",
            tool: None,
            seed: append(
                "crates/uaos-redact-scan/src/lib.rs",
                "\n#[cfg(not(clippy))]\nconst _: &str = include_str!(\"../../uaos-json/Cargo.toml\");\n",
            ),
            runner: Runner::Xtask(&["sources", "uaos-redact-scan"]),
            expect: "dev check) compiles in",
        },
        Case {
            id: "foreign-source-release-only",
            gate: "sources",
            tool: None,
            seed: append(
                "crates/uaos-redact-scan/src/lib.rs",
                "\n#[cfg(not(debug_assertions))]\nconst _: &str = include_str!(\"../../uaos-json/Cargo.toml\");\n",
            ),
            runner: Runner::Xtask(&["sources", "uaos-redact-scan"]),
            expect: "release check) compiles in",
        },
        // A file only the default features read, outside clippy's build.
        Case {
            id: "foreign-source-default-features-only",
            gate: "sources",
            tool: None,
            seed: both(
                append("crates/uaos-redact/Cargo.toml", "\n[features]\nfast = []\n"),
                append(
                    "crates/uaos-redact/src/lib.rs",
                    "\n#[cfg(not(any(clippy, feature = \"fast\")))]\nconst _: &str = include_str!(\"../../uaos-json/Cargo.toml\");\n",
                ),
            ),
            runner: Runner::Xtask(&["sources", "uaos-redact"]),
            expect: "(target `uaos_redact`, dev check) compiles in",
        },
        // A file only the release build with every feature reads.
        Case {
            id: "foreign-source-release-all-features-only",
            gate: "sources",
            tool: None,
            seed: both(
                append("crates/uaos-redact/Cargo.toml", "\n[features]\nx = []\n"),
                append(
                    "crates/uaos-redact/src/lib.rs",
                    "\n#[cfg(all(not(debug_assertions), feature = \"x\"))]\nconst _: &str = include_str!(\"../../uaos-json/Cargo.toml\");\n",
                ),
            ),
            runner: Runner::Xtask(&["sources", "uaos-redact"]),
            expect: "(target `uaos_redact`, release check, all features) compiles in",
        },
        // What a build script reads.
        Case {
            id: "foreign-source-build-script",
            gate: "sources",
            tool: None,
            seed: write(
                "crates/uaos-redact-scan/build.rs",
                "// SPDX-License-Identifier: Apache-2.0\n\n//! Seeded.\n\n\
                 const _: &str = include_str!(\"../uaos-json/Cargo.toml\");\n\nfn main() {}\n"
                    .to_owned(),
            ),
            runner: Runner::Xtask(&["sources", "uaos-redact-scan"]),
            expect: "(target `build-script-build`, dev check) compiles in",
        },
        // A local package outside the workspace, whose library is another crate's source.
        Case {
            id: "foreign-source-local-package",
            gate: "sources",
            tool: None,
            seed: tape_shim(true),
            runner: Runner::Xtask(&["sources", "uaos-redact-scan"]),
            expect: "fuzz/tape-shim (target `tape_shim`, dev check) compiles in",
        },
        // The clippy gate's own check, on clippy's build.
        Case {
            id: "foreign-source-clippy-only",
            gate: "clippy",
            tool: None,
            seed: append(
                "crates/uaos-redact-scan/src/lib.rs",
                "\n#[cfg(clippy)]\nconst _: &str = include_str!(\"../../uaos-json/Cargo.toml\");\n",
            ),
            runner: Runner::Xtask(&["clippy"]),
            expect: "clippy build) compiles in",
        },
        // The final scan callers reach through `uaos-redact` is the scan crate's own type, not a
        // wrapper of the same name.
        Case {
            id: "final-scan-reexport-replaced",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-redact/src/lib.rs",
                "    Blocked, DataClass, DetectorSet, DetectorVersion, FinalScanner, Finding, MIN_KNOWN_SECRET_LEN, RedactError,\n};\n",
                "    Blocked, DataClass, DetectorSet, DetectorVersion, Finding, MIN_KNOWN_SECRET_LEN, RedactError,\n};\n\n/// The final scan, wrapped.\n#[derive(Debug)]\npub struct FinalScanner(pub uaos_redact_scan::FinalScanner);\n",
            ),
            // The library alone, as the test gate compiles it for its unit tests, so the pins in it
            // are what refuses the wrapper.
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--lib", "--no-run", "--locked"],
            },
            expect: "mismatched types",
        },
        // A wrapper in release builds only, behind a module named like the scan crate. The pins
        // name the crate from the root, so the release build refuses it.
        Case {
            id: "final-scan-pin-shadowed-in-release",
            gate: "sources",
            tool: None,
            seed: replace(
                "crates/uaos-redact/src/lib.rs",
                "pub use uaos_redact_scan::{\n    Blocked, DataClass, DetectorSet, DetectorVersion, FinalScanner, Finding, MIN_KNOWN_SECRET_LEN, RedactError,\n};\n",
                "pub use ::uaos_redact_scan::{\n    Blocked, DataClass, DetectorSet, DetectorVersion, Finding, MIN_KNOWN_SECRET_LEN, RedactError,\n};\n\
                 #[cfg(debug_assertions)]\npub use ::uaos_redact_scan::FinalScanner;\n\
                 #[cfg(not(debug_assertions))]\npub use wrapped::FinalScanner;\n\
                 #[cfg(not(debug_assertions))]\nmod wrapped {\n    /// The final scan, wrapped.\n    #[derive(Debug)]\n    \
                 pub struct FinalScanner(pub ::uaos_redact_scan::FinalScanner);\n}\n\
                 #[cfg(not(debug_assertions))]\nmod uaos_redact_scan {\n    pub(crate) use super::FinalScanner;\n    \
                 pub(crate) use ::uaos_redact_scan::{Blocked, DetectorSet};\n}\n",
            ),
            // Through the gate itself.
            runner: Runner::Xtask(&["sources", "uaos-redact"]),
            expect: "mismatched types",
        },
        // A module named like the scan crate, in every build. Only the pins' root paths refuse it;
        // the library alone is built, so the test-file pin does not.
        Case {
            id: "final-scan-pin-shadowed-by-module",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-redact/src/lib.rs",
                "pub use uaos_redact_scan::{\n    Blocked, DataClass, DetectorSet, DetectorVersion, FinalScanner, Finding, MIN_KNOWN_SECRET_LEN, RedactError,\n};\n",
                "pub use ::uaos_redact_scan::{\n    Blocked, DataClass, DetectorSet, DetectorVersion, Finding, MIN_KNOWN_SECRET_LEN, RedactError,\n};\n\
                 pub use wrapped::FinalScanner;\nmod wrapped {\n    /// The final scan, wrapped.\n    #[derive(Debug)]\n    \
                 pub struct FinalScanner(pub ::uaos_redact_scan::FinalScanner);\n}\n\
                 mod uaos_redact_scan {\n    pub(crate) use super::FinalScanner;\n    \
                 pub(crate) use ::uaos_redact_scan::{Blocked, DetectorSet};\n}\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--lib", "--no-run", "--locked"],
            },
            expect: "mismatched types",
        },
        Case {
            id: "arch-ring1-reaches-kernel",
            gate: "arch-check",
            tool: None,
            seed: both(
                replace("Cargo.toml", "members = [\"crates/*\", \"xtask\"]", "members = [\"crates/*\", \"modules/*\", \"xtask\"]"),
                both(
                write(
                    "modules/mod-seeded/Cargo.toml",
                    "# SPDX-License-Identifier: Apache-2.0\n[package]\nname = \"mod-seeded\"\nversion = \"0.0.0\"\nedition = \"2024\"\nlicense = \"Apache-2.0\"\npublish = false\n\n[dependencies]\nuaos-platform = { path = \"../../crates/uaos-platform\" }\n".to_owned(),
                ),
                write("modules/mod-seeded/src/lib.rs", "// SPDX-License-Identifier: Apache-2.0\n//! Seeded.\n".to_owned()),
                ),
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "Ring 1",
        },
        Case {
            id: "schema-breaking-change",
            gate: "schema-compat",
            tool: None,
            // A retyped reference. (The seed must still compile: `settled` is read by validation.)
            seed: replace(
                "crates/uaos-contracts/src/budget.rs",
                "    pub related_event: Option<EventId>,",
                "    pub related_event: Option<SessionId>,",
            ),
            runner: Runner::Xtask(&["schema-check"]),
            expect: "BREAKING",
        },
        Case {
            id: "schema-drift",
            gate: "schema-compat",
            tool: None,
            seed: replace(
                "crates/uaos-contracts/src/budget.rs",
                "    pub estimated: bool,\n}",
                "    pub estimated: bool,\n    /// Seeded.\n    #[serde(default, skip_serializing_if = \"Option::is_none\")]\n    pub seeded: Option<String>,\n}",
            ),
            runner: Runner::Xtask(&["schema-check"]),
            expect: "out of date",
        },
        Case {
            id: "spdx-header-missing",
            gate: "spdx-headers",
            tool: None,
            seed: replace("crates/uaos-platform/src/real.rs", "// SPDX-License-Identifier: Apache-2.0\n", ""),
            runner: Runner::Xtask(&["headers"]),
            expect: "SPDX header",
        },
        Case {
            id: "gate-registry-incomplete",
            gate: "gate-registry",
            tool: None,
            seed: replace("gates.toml", "id = \"secret-scan\"", "id = \"secret-scan-renamed\""),
            runner: Runner::Xtask(&["gates"]),
            expect: "missing required gate",
        },
        Case {
            // The README's public phase line drifts from the registry.
            id: "docs-phase-line-stale",
            gate: "gate-registry",
            tool: None,
            seed: replace("README.md", "## Status: P3 ", "## Status: P2 "),
            runner: Runner::Xtask(&["gates"]),
            expect: "phase line: README.md names `P2`",
        },
        Case {
            // A merge-lane job left out of the aggregated required check.
            id: "merge-gate-missing-job",
            gate: "gate-registry",
            tool: None,
            seed: replace(".github/workflows/ci.yml", ", paths, negative]", ", paths]"),
            runner: Runner::Xtask(&["gates"]),
            expect: "job `negative` is not in `merge-gate` needs",
        },
        Case {
            // A promise whose phase has passed with nothing built to meet it.
            id: "promise-overdue",
            gate: "gate-registry",
            tool: None,
            seed: append(
                "gates.toml",
                "\n[[promise]]\nid = \"seeded-promised-negative\"\nkind = \"negative\"\nsource = \"seeded\"\nphase = \"P2\"\n",
            ),
            runner: Runner::Xtask(&["gates"]),
            expect: "promise `seeded-promised-negative` (negative `seeded-promised-negative`, seeded) was due in `P2`",
        },
        Case {
            // A negative case that exists but no active gate lists, so nothing runs it, does not
            // meet a promise.
            id: "promise-met-by-unlisted-negative",
            gate: "gate-registry",
            tool: None,
            seed: both(
                replace("gates.toml", ", \"claims-unreadable-text\"]", "]"),
                append(
                    "gates.toml",
                    "\n[[promise]]\nid = \"claims-unreadable-text\"\nkind = \"negative\"\nsource = \"seeded\"\nphase = \"P2\"\n",
                ),
            ),
            runner: Runner::Xtask(&["gates"]),
            expect: "promise `claims-unreadable-text` (negative `claims-unreadable-text`, seeded) was due in `P2`",
        },
        Case {
            // A Ring 1 module arrives without the README announcing it.
            id: "status-module-unlisted",
            gate: "status-truth",
            tool: None,
            seed: write(
                "modules/mod-seeded/Cargo.toml",
                "[package]\nname = \"mod-seeded\"\nversion = \"0.0.0\"\nedition = \"2024\"\n".to_owned(),
            ),
            runner: Runner::Xtask(&["gates"]),
            expect: "crate `mod-seeded` exists but README.md's built list does not name it",
        },
        Case {
            // A product crate exists that the README's built list does not announce.
            id: "status-built-crate-unlisted",
            gate: "status-truth",
            tool: None,
            seed: replace("README.md", "(`uaos-json`)", "(the tokenizer)"),
            runner: Runner::Xtask(&["gates"]),
            expect: "crate `uaos-json` exists but README.md's built list does not name it",
        },
        Case {
            id: "secret-committed",
            gate: "secret-scan",
            tool: Some("gitleaks"),
            // Assembled at runtime so this source file never contains a scannable key.
            seed: write(
                "crates/uaos-contracts/src/seeded.txt",
                format!("aws_access_key_id = {}{}\n", "AKIA", "Q3VZ7XKL2M4N6P5R"),
            ),
            runner: Runner::Program { program: "gitleaks", args: &["dir", "--no-banner", "--redact", "."] },
            expect: "leaks found",
        },
        Case {
            id: "license-not-allowed",
            gate: "cargo-deny",
            tool: Some("cargo-deny"),
            seed: both(
                write(
                    "crates/seeded-gpl/Cargo.toml",
                    "# SPDX-License-Identifier: Apache-2.0\n[package]\nname = \"seeded-gpl\"\nversion = \"0.0.0\"\nedition = \"2024\"\nlicense = \"GPL-3.0-only\"\n".to_owned(),
                ),
                write("crates/seeded-gpl/src/lib.rs", "// SPDX-License-Identifier: Apache-2.0\n//! Seeded.\n".to_owned()),
            ),
            runner: Runner::Program { program: "cargo", args: &["deny", "check", "licenses"] },
            expect: "GPL-3.0",
        },
        Case {
            id: "unaudited-dependency",
            gate: "cargo-vet",
            tool: Some("cargo-vet"),
            seed: both(
                replace(
                    "crates/uaos-contracts/Cargo.toml",
                    "[dependencies]\n",
                    // A crate no imported auditor (Mozilla, Google, Bytecode Alliance, ISRG,
                    // Zcash) has reviewed; widely used crates like `hex` are already vetted.
                    "[dependencies]\nleft-pad = \"1.0.1\"\n",
                ),
                // cargo-vet reads metadata with --locked, so the lockfile must already include
                // the new crate; `cargo fetch` adds it minimally.
                Box::new(|ws| crate::util::capture(ws, "cargo", &["fetch"]).map(|_| ())),
            ),
            runner: Runner::Program { program: "cargo", args: &["vet"] },
            expect: "unvetted",
        },
        Case {
            id: "journal-ack-without-write",
            gate: "journal-durability",
            tool: None,
            // A journal that acknowledges a record without handing it to the OS.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "match self.active.append(&line) {",
                "match Ok::<(), FsError>(()) {",
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-testkit", "--test", "kill"] },
            expect: "lost or changed",
        },
        Case {
            id: "journal-first-open-bricks",
            gate: "journal-durability",
            tool: None,
            // A first open killed before its manifest is stored leaves an empty segment; refusing
            // it makes the directory unopenable forever (kill harness, nightly 39330543607).
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        if len != 0 {\n",
                "        if len != u64::MAX {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "journal", "a_first_open_killed_before_its_manifest_is_stored_starts_cleanly"],
            },
            expect: "left the journal unopenable",
        },
        Case {
            id: "journal-new-history-over-records",
            gate: "journal-durability",
            tool: None,
            // Segments of a real history, whose manifest is gone, taken for a crashed first open: a
            // new history would hide that the old one is lost.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        if len != 0 {\n",
                "        if len != 0 && false {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "journal", "manifest"],
            },
            expect: "a new history started over",
        },
        Case {
            id: "journal-new-history-checks-first-segment-only",
            gate: "journal-durability",
            tool: None,
            // Only the first segment checked: a real history whose first segment is empty would be
            // renamed away and a new history started over its records.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "    for path in &segments {\n        // The length, not the content",
                "    for path in segments.iter().take(1) {\n        // The length, not the content",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "journal", "a_lost_manifest_behind_an_empty_first_segment_is_refused"],
            },
            expect: "a new history started over records behind an empty first segment",
        },
        Case {
            id: "journal-new-history-over-a-marker",
            gate: "journal-durability",
            tool: None,
            // A marker naming a record ignored without a manifest.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        Ok(bytes) if bytes.as_slice() != none.as_bytes() => {\n",
                "        Ok(bytes) if false && bytes.as_slice() != none.as_bytes() => {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "journal", "a_missing_manifest_with_a_recorded_durable_point_is_refused"],
            },
            expect: "a new history started over a recorded durable point",
        },
        Case {
            id: "recovery-drops-old-payload",
            gate: "journal-durability",
            tool: None,
            // A recovery that loses a payload acknowledged several runs earlier, outside the
            // per-kill window the nightly lane reads back. The harness runs in its nightly
            // configuration (sweep before retiring a directory only), so this proves that the
            // sweep the 10,000-kill lane relies on still catches an old loss.
            seed: both(
                both(
                    replace(
                        "crates/uaos-state/src/chunks/mod.rs",
                        "    pub(crate) fn shred_now(",
                        "    pub(crate) fn drop_data(&self, pocket: PocketId, chunk: ChunkRef) {\n        let _gone = self.fs.remove_file(&self.chunk_path(pocket, chunk));\n    }\n\n    pub(crate) fn shred_now(",
                    ),
                    replace(
                        "crates/uaos-state/src/journal/writer.rs",
                        "    let first_unproven = durable.map_or(0, |seq| seq + 1);\n",
                        // The journal's first payload, once it is both 1,500 records and 5
                        // seconds behind the newest record: several runs back on any machine.
                        "    let first_unproven = durable.map_or(0, |seq| seq + 1);\n    if let (Some(first), Some(last)) = (records.iter().find(|r| r.envelope.payload_ref.is_some()), records.last())\n        && records.len() > 1500\n        && last.envelope.ts.wall.unix_millis_saturating() > first.envelope.ts.wall.unix_millis_saturating() + 5000\n        && let (Some(pocket), Some(chunk)) = (first.envelope.pocket_id, first.envelope.payload_ref)\n    {\n        store.drop_data(pocket, chunk);\n    }\n",
                    ),
                ),
                replace(
                    "crates/uaos-testkit/tests/kill.rs",
                    "        Some(\"rotation\") => Some(Sweep::Rotation),\n        Some(\"every-kill\") | None => Some(Sweep::EveryKill),\n",
                    "        Some(\"rotation\") | None => Some(Sweep::Rotation),\n        Some(\"every-kill\") => Some(Sweep::EveryKill),\n",
                ),
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-testkit", "--test", "kill"] },
            expect: "sweep before retiring",
        },
        Case {
            id: "egress-dials-private-range",
            gate: "test",
            tool: None,
            // A door whose classification lets the loopback range through.
            seed: replace(
                "crates/uaos-egress/src/addr.rs",
                "([127, 0, 0, 0], 8, Blocked::Loopback),",
                "([127, 0, 0, 0], 32, Blocked::Loopback),",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-egress",
                    "--test",
                    "door",
                    "private_answers_are_refused_unless_the_upstream_is_declared_private",
                ],
            },
            expect: "the door dialled a private range",
        },
        Case {
            id: "egress-numeric-host",
            gate: "test",
            tool: None,
            // An upstream named by an address literal in disguise (`2130706433`).
            seed: replace(
                "crates/uaos-egress/src/host.rs",
                "if name.rsplit('.').next().is_some_and(is_numeric_label) {",
                "if false && name.rsplit('.').next().is_some_and(is_numeric_label) {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--lib", "address_literals_are_refused"],
            },
            expect: "was accepted as a host name",
        },
        Case {
            id: "egress-ctor-outside-root",
            gate: "clippy",
            tool: None,
            // Code other than the composition root building an egress door.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\npub fn seeded_violation() -> Result<Door, EgressError> {\n    Door::new(\n        Vec::new(),\n        std::sync::Arc::new(SystemResolver),\n        std::sync::Arc::new(uaos_platform::real::SystemClock::new()),\n        hyper_util::rt::TokioExecutor::new(),\n        DoorLimits::default(),\n    )\n}\n",
            ),
            runner: CLIPPY,
            expect: "uaos_egress::Door::new",
        },
        Case {
            id: "egress-private-reaches-link-local",
            gate: "test",
            tool: None,
            // A private upstream admitted to every special-purpose range, metadata included.
            seed: replace(
                "crates/uaos-egress/src/upstream.rs",
                "Reach::Blocked(_) if self.allow_private && is_local_network(ip) => Ok(()),",
                "Reach::Blocked(_) if self.allow_private => Ok(()),",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_private_upstream_never_reaches_link_local_or_special_ranges"],
            },
            expect: "dialled the metadata range",
        },
        Case {
            id: "egress-plaintext-resolved",
            gate: "test",
            tool: None,
            // Plain HTTP that depends on name resolution.
            seed: replace(
                "crates/uaos-egress/src/upstream.rs",
                "            if self.pinned.is_empty() {\n                return Err(UpstreamError::PlaintextNeedsPinned);\n            }\n",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "plain_http_is_declared_only_toward_pinned_local_addresses"],
            },
            expect: "would be resolved",
        },
        Case {
            id: "egress-breaker-admits-after-cooldown",
            gate: "test",
            tool: None,
            // A breaker with no half-open state.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "Breaker::Probing { .. } => Err(PROBE_RECHECK.min(cooldown)),",
                "Breaker::Probing { generation } => Ok(Ticket::Probe { generation }),",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "after_the_cooldown_exactly_one_probe_goes_through"],
            },
            expect: "more than one probe",
        },
        Case {
            id: "net-dns-outside-egress",
            gate: "clippy",
            tool: None,
            // DNS through std, which needs no dependency at all.
            seed: append(
                "crates/uaos-state/src/lib.rs",
                "\n/// Seeded.\n#[must_use]\npub fn seeded_violation() -> bool {\n    use std::net::ToSocketAddrs as _;\n    (\"exfil.example\", 80).to_socket_addrs().is_ok()\n}\n",
            ),
            runner: CLIPPY,
            expect: "std::net::ToSocketAddrs::to_socket_addrs",
        },
        Case {
            id: "net-connect-outside-egress",
            gate: "clippy",
            tool: None,
            // An outbound TCP connection outside the connector.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\npub async fn seeded_violation(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpStream> {\n    tokio::net::TcpSocket::new_v4()?.connect(addr).await\n}\n",
            ),
            runner: CLIPPY,
            expect: "tokio::net::TcpSocket::connect",
        },
        Case {
            id: "net-udp-outside-egress",
            gate: "clippy",
            tool: None,
            // A UDP socket.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\npub async fn seeded_violation() -> std::io::Result<tokio::net::UdpSocket> {\n    tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await\n}\n",
            ),
            runner: CLIPPY,
            expect: "tokio::net::UdpSocket::bind",
        },
        Case {
            id: "spawn-outside-supervisor",
            gate: "clippy",
            tool: None,
            // A task spawned on a runtime handle, outside the supervisor.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\npub fn seeded_violation() {\n    drop(tokio::runtime::Handle::current().spawn(async {}));\n}\n",
            ),
            runner: CLIPPY,
            expect: "tokio::runtime::Handle::spawn",
        },
        Case {
            id: "egress-probe-stuck-on-cancel",
            gate: "test",
            tool: None,
            // A breaker probe whose caller drops the future is never settled.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "            self.door
                .breaker_record(self.upstream, self.ticket, Outcome::NotAttempted);",
                "            let _ = (self.door, self.upstream, self.ticket);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_cancelled_probe_lets_the_next_attempt_probe"],
            },
            expect: "a cancelled probe left the circuit refusing",
        },
        Case {
            id: "egress-embedded-local",
            gate: "test",
            tool: None,
            // An IPv6 form that only embeds a loopback address counted as local.
            seed: replace(
                "crates/uaos-egress/src/addr.rs",
                "    if let IpAddr::V6(v6) = ip\n        && embeds_ipv4(v6)\n    {\n        return false;\n    }\n",
                "    let _ = embeds_ipv4;\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--lib", "plaintext_is_refused_toward_embedded_forms"],
            },
            expect: "2002:7f00:1::1",
        },
        Case {
            id: "egress-forwards-switching-protocols",
            gate: "test",
            tool: None,
            // A 101 answer handed to the caller as final.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "        if parts.status.is_informational() {",
                "        if parts.status.is_informational() && parts.status.as_u16() == 0 {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_switching_protocols_answer_is_an_error"],
            },
            expect: "a 101 reached the caller",
        },
        Case {
            id: "egress-forwards-contradicting-length",
            gate: "test",
            tool: None,
            // A content-length beside transfer-encoding forwarded.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "        }\n        headers.remove(header::CONTENT_LENGTH);\n        return Ok(());",
                "        }\n        return Ok(());",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_content_length_beside_transfer_encoding_is_dropped"],
            },
            expect: "a content-length contradicting the decoded body was forwarded",
        },
        Case {
            id: "osfs-doubled-separator-unc",
            gate: "test",
            tool: Some(WINDOWS_ONLY),
            // A UNC path spelled with doubled separators, which std does not parse as UNC and
            // Windows does.
            seed: replace(
                "crates/uaos-platform/src/real/fs.rs",
                "            .is_some_and(|start| start.iter().all(|b| *b == b'\\\\' || *b == b'/'));",
                "            .is_some_and(|_| false);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-platform", "--lib", "network_and_device_paths_are_refused"],
            },
            expect: "uaos-canary.invalid",
        },
        Case {
            id: "egress-forwards-unknown-transfer-coding",
            gate: "test",
            tool: None,
            // A body coded with something other than `chunked` passed on unmarked.
            seed: replace("crates/uaos-egress/src/door.rs", "        if !chunked_only {", "        if !chunked_only && false {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_transfer_coding_other_than_chunked_is_an_error"],
            },
            expect: "a coded body reached the caller unmarked",
        },
        Case {
            id: "egress-forwards-repeated-length",
            gate: "test",
            tool: None,
            // A repeated content-length passed on as is.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "            headers.insert(header::CONTENT_LENGTH, single);",
                "            let _ = single;",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_repeated_content_length_is_forwarded_once"],
            },
            expect: "a repeated content-length was forwarded",
        },
        Case {
            id: "egress-forwards-bodiless-length",
            gate: "test",
            tool: None,
            // A 204 forwarded with the content-length it should not carry.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "    if status == StatusCode::NO_CONTENT {",
                "    if status == StatusCode::NO_CONTENT && status.as_u16() == 0 {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "content_length_on_answers_without_a_body"],
            },
            expect: "a 204 kept its content-length",
        },
        Case {
            id: "egress-delivered-reported-unsent",
            gate: "test",
            tool: None,
            // A request cut off after it was sent reported as never sent, and retryable.
            seed: replace(
                "crates/uaos-egress/src/lib.rs",
                "            Self::Interrupted(\"the connection failed after the request was sent\")",
                "            Self::Unreachable(\"the connection failed before a response arrived\")",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "errors_say_whether_the_request_may_have_reached_the_provider"],
            },
            expect: "a request the provider received was reported as never sent",
        },
        Case {
            id: "egress-timeout-reported-unsent",
            gate: "test",
            tool: None,
            // No answer within the response timeout reported as nothing sent, retryable.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "                return Err(EgressError::Interrupted(\"no answer within the response timeout\"));",
                "                return Err(EgressError::Timeout);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "no_answer_within_the_response_timeout_is_interrupted"],
            },
            expect: "an unanswered request was reported as never sent",
        },
        Case {
            id: "egress-unsent-reported-delivered",
            gate: "test",
            tool: None,
            // A connection lost before hyper took the request reported as possibly received.
            seed: replace(
                "crates/uaos-egress/src/lib.rs",
                "        let mut unsent = e.is_connect() || e.connect_info().is_none();",
                "        let mut unsent = e.is_connect();",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_connection_lost_before_the_request_left_is_unreachable"],
            },
            expect: "nothing was sent, but the door reported",
        },
        Case {
            id: "egress-unassigned-timeout-reported-delivered",
            gate: "test",
            tool: None,
            // A response timeout before hyper handed the request to a connection reported as
            // possibly received.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "                if handed_over.connection_metadata().is_none() {",
                "                if handed_over.connection_metadata().is_none() && false {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_timeout_before_the_request_was_handed_over_is_not_interrupted"],
            },
            expect: "a request that never left was reported as possibly received",
        },
        Case {
            id: "egress-canceled-reported-delivered",
            gate: "test",
            tool: None,
            // A request hyper handed back unsent reported as possibly received.
            seed: replace(
                "crates/uaos-egress/src/lib.rs",
                "                unsent |= h.is_canceled();",
                "                let _ = h.is_canceled();",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_queued_request_handed_back_is_unreachable"],
            },
            expect: "a request handed back unsent was reported as",
        },
        Case {
            id: "json-duplicate-key-unchecked",
            gate: "test",
            tool: None,
            // An object closes without its duplicate-key check.
            seed: replace("crates/uaos-json/src/tape.rs", "self.check_duplicate_keys()?;", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "plain_duplicate_keys_are_rejected"],
            },
            expect: "duplicate key accepted",
        },
        Case {
            id: "json-escaped-duplicate-compared-raw",
            gate: "test",
            tool: None,
            // Contract §4: an escaped key compared by its raw bytes in a run, so `"a"` and its
            // escaped spelling differ.
            seed: replace(
                "crates/uaos-json/src/tape.rs",
                "        if member.flags & KEY_ESCAPED == 0 {",
                "        if true {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "escaped_duplicate_keys_are_rejected"],
            },
            expect: "escaped duplicate key accepted",
        },
        Case {
            id: "json-fingerprint-raw-bytes",
            gate: "test",
            tool: None,
            // Contract §6: escaped keys fingerprinted over their raw bytes, so `"a"` and its
            // escaped spelling land on different fingerprints and are never compared.
            seed: replace("crates/uaos-json/src/tape.rs", "let fingerprint = if escaped {", "let fingerprint = if false {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "escaped_duplicate_keys_are_rejected"],
            },
            expect: "escaped duplicate key accepted",
        },
        Case {
            id: "json-fingerprint-collision-accepts",
            gate: "test",
            tool: None,
            // Contract §6: members that share a fingerprint are never compared exactly, so a
            // shared fingerprint, a real repeat included, passes.
            seed: replace("crates/uaos-json/src/tape.rs", "        if run.len() < 2 {", "        if run.len() >= 2 {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "plain_duplicate_keys_are_rejected"],
            },
            expect: "duplicate key accepted",
        },
        Case {
            id: "json-fingerprint-collision-rejects",
            gate: "test",
            tool: None,
            // Contract §6: a shared fingerprint taken for a repeat, so two distinct keys that
            // collide refuse the object.
            seed: replace(
                "crates/uaos-json/src/tape.rs",
                "            && key(*a) == key(*b)\n",
                "            && (key(*a) == key(*b) || key_start(*a) != key_start(*b))\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "distinct_keys_sharing_a_fingerprint_are_accepted"],
            },
            expect: "colliding keys rejected",
        },
        Case {
            id: "json-fingerprint-word-order",
            gate: "test",
            tool: None,
            // Contract §6: raw keys fingerprinted a word at a time in the wrong byte order, so a
            // raw key of eight bytes or more and its escaped spelling get different fingerprints
            // and are never compared.
            seed: replace(
                "crates/uaos-json/src/tape.rs",
                "fp.word = u64::from_le_bytes(word);",
                "fp.word = u64::from_be_bytes(word);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--lib", "the_word_path_equals_the_byte_path"],
            },
            expect: "word path differs",
        },
        Case {
            id: "json-run-scratch-doubles",
            gate: "test",
            tool: None,
            // Contract §6: the run scratch reserved per key instead of once per run, so it grows by
            // doubling past its bound.
            seed: both(
                replace(
                    "crates/uaos-json/src/tape.rs",
                    "    decoded.try_reserve_exact(escaped).map_err(|_| oom(first_key))?;\n",
                    "    let _ = escaped;\n",
                ),
                replace(
                    "crates/uaos-json/src/tape.rs",
                    "            let start = decoded.len();\n",
                    "            let start = decoded.len();\n            decoded.try_reserve(content.len()).map_err(|_| oom(member.key_start))?;\n",
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--lib", "the_run_scratch_stays_within_its_bound"],
            },
            expect: "run scratch",
        },
        Case {
            id: "json-pairwise-skips-shared-fingerprint",
            gate: "test",
            tool: None,
            // Contract §6: the small-object path that skips sorting also skips a shared
            // fingerprint, so a small object's repeat passes.
            seed: replace("crates/uaos-json/src/tape.rs", "!any_shared_fingerprint(members)", "true"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "plain_duplicate_keys_are_rejected"],
            },
            expect: "duplicate key accepted",
        },
        Case {
            id: "json-depth-off-by-one",
            gate: "test",
            tool: None,
            // Contract §3: one level more than the limit gets through.
            seed: replace(
                "crates/uaos-json/src/tape.rs",
                "if self.stack.len() >= usize::from(self.limits.max_depth()) {",
                "if self.stack.len() > usize::from(self.limits.max_depth()) {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "depth_limit_is_exact"],
            },
            expect: "depth 129 accepted",
        },
        Case {
            id: "json-lone-surrogate-accepted",
            gate: "test",
            tool: None,
            // Contract §4: a surrogate escape outside a pair passes as a character.
            seed: replace("crates/uaos-json/src/tape.rs", "if lone {", "if false {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "lone_surrogates_are_rejected"],
            },
            expect: "lone surrogate accepted",
        },
        Case {
            id: "json-trailing-data-accepted",
            gate: "test",
            tool: None,
            // Contract §4: bytes after the root value are ignored instead of refused.
            seed: replace(
                "crates/uaos-json/src/tape.rs",
                "if skip_ws(self.bytes, at) != self.bytes.len() {",
                "if false {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "trailing_data_is_rejected"],
            },
            expect: "trailing data accepted",
        },
        Case {
            id: "json-bom-stripped",
            gate: "test",
            tool: None,
            // Contract §4: a byte-order mark stripped, so every span would sit three bytes off
            // the forwarded body.
            seed: replace(
                "crates/uaos-json/src/tape.rs",
                "reject_bom(raw)?;",
                "let raw = raw.strip_prefix(BOM).unwrap_or(raw);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "bom_is_rejected"],
            },
            expect: "BOM accepted",
        },
        Case {
            id: "json-leading-zero-accepted",
            gate: "test",
            tool: None,
            // Contract §4: `01` read as a number, which another parser may refuse or read as octal.
            seed: replace(
                "crates/uaos-json/src/tape.rs",
                "Some(b'0') => j += 1,",
                "Some(b'0') => j = skip_digits(bytes, j),",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "leading_zeros_are_rejected"],
            },
            expect: "leading zero accepted",
        },
        Case {
            id: "json-decode-escape-wrong",
            gate: "test",
            tool: None,
            // Contract §9: the independent oracle bites: one escape decoded wrongly makes the tape
            // disagree with serde_json.
            seed: replace("crates/uaos-json/src/decode.rs", "b'/' => '/',", "b'/' => '\\\\',"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "differential"],
            },
            expect: "differs from serde_json",
        },
        Case {
            id: "osfs-bare-volume",
            gate: "test",
            tool: Some(WINDOWS_ONLY),
            // `\\?\C:` alone, the raw volume, admitted as a disk path.
            seed: replace(
                "crates/uaos-platform/src/real/fs.rs",
                "Prefix::VerbatimDisk(_) => parts.next() != Some(Component::RootDir),",
                "Prefix::VerbatimDisk(_) => false,",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-platform", "--lib", "network_and_device_paths_are_refused"],
            },
            expect: r"create_dir_all \\?\C:",
        },
        Case {
            id: "egress-sends-trace",
            gate: "test",
            tool: None,
            // TRACE echoes the request, credential included, back.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "        if !SENT_METHODS.contains(&request.method) {",
                "        if SENT_METHODS.is_empty() {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "methods_the_door_does_not_send_are_refused_before_contact"],
            },
            expect: "TRACE was not refused before contact",
        },
        Case {
            id: "net-listen-outside-api",
            gate: "clippy",
            tool: None,
            // A listener, whose bind also resolves names, outside the API crate.
            seed: append(
                "crates/uaos-state/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\npub fn seeded_violation() -> std::io::Result<std::net::TcpListener> {\n    std::net::TcpListener::bind(\"localhost:0\")\n}\n",
            ),
            runner: CLIPPY,
            expect: "std::net::TcpListener::bind",
        },
        Case {
            id: "net-resolver-outside-egress",
            gate: "clippy",
            tool: None,
            // Hyper-util's own resolver, a DNS lookup outside the door.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n#[must_use]\npub fn seeded_violation() -> hyper_util::client::legacy::connect::dns::GaiResolver {\n    hyper_util::client::legacy::connect::dns::GaiResolver::new()\n}\n",
            ),
            runner: CLIPPY,
            expect: "GaiResolver::new",
        },
        Case {
            id: "net-socket-listen-outside-api",
            gate: "clippy",
            tool: None,
            // A raw socket turned into a listener outside the API crate.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\npub fn seeded_violation() -> std::io::Result<tokio::net::TcpListener> {\n    tokio::net::TcpSocket::new_v4()?.listen(1)\n}\n",
            ),
            runner: CLIPPY,
            expect: "tokio::net::TcpSocket::listen",
        },
        Case {
            id: "net-unix-connect-addr-outside-egress",
            gate: "clippy",
            tool: Some(UNIX_ONLY),
            // Each `allow-invalid` ban is proven where it exists.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\n#[cfg(unix)]\npub fn seeded_violation() -> std::io::Result<std::os::unix::net::UnixStream> {\n    std::os::unix::net::UnixStream::connect_addr(&std::os::unix::net::SocketAddr::from_pathname(\"/run/seeded.sock\")?)\n}\n",
            ),
            runner: CLIPPY,
            expect: "std::os::unix::net::UnixStream::connect_addr",
        },
        Case {
            id: "net-tokio-unix-connect-outside-egress",
            gate: "clippy",
            tool: Some(UNIX_ONLY),
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\n#[cfg(unix)]\npub async fn seeded_violation() -> std::io::Result<tokio::net::UnixStream> {\n    tokio::net::UnixStream::connect(\"/run/seeded.sock\").await\n}\n",
            ),
            runner: CLIPPY,
            expect: "tokio::net::UnixStream::connect",
        },
        Case {
            id: "net-unix-socket-connect-outside-egress",
            gate: "clippy",
            tool: Some(UNIX_ONLY),
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\n#[cfg(unix)]\npub async fn seeded_violation() -> std::io::Result<tokio::net::UnixStream> {\n    tokio::net::UnixSocket::new_stream()?.connect(\"/run/seeded.sock\").await\n}\n",
            ),
            runner: CLIPPY,
            expect: "tokio::net::UnixSocket::connect",
        },
        Case {
            id: "net-named-pipe-outside-egress",
            gate: "clippy",
            tool: Some(WINDOWS_ONLY),
            // The Windows counterpart of the Unix-socket bans.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\n#[cfg(windows)]\npub fn seeded_violation() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {\n    tokio::net::windows::named_pipe::ClientOptions::new().open(\"seeded\")\n}\n",
            ),
            runner: CLIPPY,
            expect: "named_pipe::ClientOptions::open",
        },
        Case {
            id: "spawn-through-tokio-executor",
            gate: "clippy",
            tool: None,
            // Hyper-util's executor spawns with `tokio::spawn`.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n#[must_use]\npub fn seeded_violation() -> hyper_util::rt::TokioExecutor {\n    hyper_util::rt::TokioExecutor::new()\n}\n",
            ),
            runner: CLIPPY,
            expect: "hyper_util::rt::TokioExecutor",
        },
        Case {
            id: "clippy-ban-path-unresolved",
            gate: "clippy",
            tool: None,
            // A ban whose path resolves to nothing is off, and clippy only warns about it.
            seed: replace(
                "clippy.toml",
                "\"tokio::task::JoinSet::spawn_local_on\"",
                "\"tokio::task::JoinSet::spawn_local_onx\"",
            ),
            runner: Runner::Xtask(&["clippy"]),
            expect: "resolve to nothing",
        },
        Case {
            id: "clippy-ban-silenced",
            gate: "clippy",
            tool: None,
            // A ban that stops firing (here, removed) leaves its canary's expectation unfulfilled,
            // which fails clippy.
            seed: replace(
                "clippy.toml",
                "  { path = \"tokio::net::TcpSocket::listen\", reason = \"only the API crate listens, on loopback (owner: uaos-api)\" },\n",
                "",
            ),
            runner: CLIPPY,
            expect: "unfulfilled",
        },
        Case {
            id: "clippy-config-nested",
            gate: "allow-audit",
            tool: None,
            // A crate-local clippy.toml replaces every ban for its crate.
            seed: write("crates/uaos-state/clippy.toml", "allow-unwrap-in-tests = true\n".to_owned()),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "a clippy.toml below the root",
        },
        Case {
            id: "lints-not-inherited",
            gate: "allow-audit",
            tool: None,
            // A member's own [lints] replaces the workspace's.
            seed: replace(
                "crates/uaos-state/Cargo.toml",
                "[lints]\nworkspace = true",
                "[lints.clippy]\ndisallowed_methods = \"allow\"",
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "must be exactly `workspace = true`",
        },
        Case {
            id: "cargo-config-clippy-override",
            gate: "allow-audit",
            tool: None,
            // Cargo configuration pointing clippy at another config.
            seed: append(".cargo/config.toml", "\n[env]\nCLIPPY_CONF_DIR = \"crates/uaos-state\"\n"),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "`env` is not allowed",
        },
        Case {
            id: "clippy-ban-without-canary",
            gate: "allow-audit",
            tool: None,
            // A ban added without a canary, in a compact layout.
            seed: replace(
                "clippy.toml",
                "disallowed-methods = [",
                "disallowed-methods = [\n  { path=\"std::process::abort\", reason=\"seeded\" },",
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "`std::process::abort` has no canary",
        },
        Case {
            id: "allow-audit-lint-group",
            gate: "allow-audit",
            tool: None,
            // A lint group that contains a guarded lint switches it off.
            seed: append_owned(
                LIB,
                format!(
                    "\n/// Seeded.\n#[{}({}, reason = \"seeded\")]\n#[must_use]\npub fn seeded_violation() -> u8 {{\n    1\n}}\n",
                    "allow", "clippy::style"
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "names `clippy::style`",
        },
        Case {
            id: "allow-audit-macro-attribute",
            gate: "allow-audit",
            tool: None,
            // An attribute a macro builds from its arguments.
            seed: append_owned(
                LIB,
                format!(
                    "\nmacro_rules! seeded {{\n    ($a:meta) => {{\n        #[$a]\n        /// Seeded.\n        pub fn seeded_violation() {{}}\n    }};\n}}\nseeded!({}({}, reason = \"seeded\"));\n",
                    "allow", "clippy::disallowed_methods"
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "names `disallowed_methods`",
        },
        Case {
            id: "allow-audit-path-module",
            gate: "allow-audit",
            tool: None,
            // Library code compiled from a file under an owner path.
            seed: both(
                append(LIB, "\n#[path = \"../tests/seeded.rs\"]\nmod seeded;\n"),
                write("crates/uaos-contracts/tests/seeded.rs", "//! Seeded.\n".to_owned()),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "a `#[path]` module",
        },
        Case {
            id: "allow-audit-nested-target",
            gate: "allow-audit",
            tool: None,
            // A nested folder named like the root's skipped build folder.
            seed: write(
                "crates/uaos-redact/src/target/seeded.rs",
                format!("#[{}({}, reason = \"seeded\")]\nfn seeded() {{}}\n", "allow", "clippy::disallowed_methods"),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "src/target/seeded.rs",
        },
        Case {
            id: "workspace-lints-group-allowed",
            gate: "allow-audit",
            tool: None,
            // A group allowed in the workspace lint table.
            seed: replace(
                "Cargo.toml",
                "disallowed_methods = \"deny\"",
                "disallowed_methods = \"deny\"\nstyle = { level = \"allow\", priority = 1 }",
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "`style` set to `allow`",
        },
        Case {
            id: "clippy-config-case",
            gate: "allow-audit",
            tool: None,
            // A clippy.toml named in another case, which Windows and macOS read.
            seed: write("crates/uaos-state/CLIPPY.TOML", "allow-unwrap-in-tests = true\n".to_owned()),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "replaces the root's bans",
        },
        Case {
            id: "cargo-config-not-alias",
            gate: "allow-audit",
            tool: None,
            // Compiler flags in Cargo configuration.
            seed: append(".cargo/config.toml", "\n[build]\nrustflags = [\"-Aclippy::disallowed_methods\"]\n"),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "`build` is not allowed",
        },
        Case {
            id: "build-script-clippy-env",
            gate: "allow-audit",
            tool: None,
            // A build script that could set clippy's environment, here through a helper that builds
            // the line.
            seed: write(
                "crates/uaos-state/build.rs",
                "fn emit(key: &str, value: &str) {\n    println!(\"cargo:rustc-env={key}={value}\");\n}\n\nfn main() {\n    emit(\"clippy_args\", \"-Aclippy::disallowed_methods\");\n}\n".to_owned(),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "names one of clippy's variables",
        },
        Case {
            id: "canary-malformed",
            gate: "allow-audit",
            tool: None,
            // A marker that is not a canary.
            seed: both(
                replace(
                    "clippy.toml",
                    "disallowed-methods = [",
                    "disallowed-methods = [\n  { path = \"std::process::abort\", reason = \"seeded\" },",
                ),
                append("crates/uaos-egress/tests/bans.rs", "\n// canary: `std::process::abort`\n"),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "is not one banned call",
        },
        Case {
            id: "canary-calls-another-item",
            gate: "allow-audit",
            tool: None,
            // A canary that calls the ban of the same type and method in another crate.
            seed: replace(
                "crates/uaos-egress/tests/bans.rs",
                "let _canary = tokio::net::TcpStream::connect(\"canary.invalid:1\");",
                "let _canary = std::net::TcpStream::connect(\"canary.invalid:1\");",
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "the canary for `tokio::net::TcpStream::connect`",
        },
        Case {
            id: "canary-setup-calls-another-ban",
            gate: "allow-audit",
            tool: None,
            // A canary whose setup line calls another ban of the same lint, which keeps the
            // expectation fulfilled when its own ban is dead.
            seed: replace(
                "crates/uaos-egress/tests/bans.rs",
                "        fn std_datagram_connect(socket: &std::os::unix::net::UnixDatagram) {\n            // canary: `std::os::unix::net::UnixDatagram::connect`\n            let _canary = socket.connect(\"/canary\");",
                "        fn std_datagram_connect() {\n            // canary: `std::os::unix::net::UnixDatagram::connect`\n            let socket = std::os::unix::net::UnixDatagram::unbound().ok();\n            let _canary = socket.map(|s| s.connect(\"/canary\"));",
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "also uses `std::os::unix::net::UnixDatagram::unbound`",
        },
        Case {
            id: "build-script-module",
            gate: "allow-audit",
            tool: None,
            // A build script that keeps its code in another file.
            seed: both(
                write(
                    "crates/uaos-state/build.rs",
                    "mod build_env;\n\nfn main() {\n    build_env::emit();\n}\n".to_owned(),
                ),
                write(
                    "crates/uaos-state/build_env.rs",
                    "pub fn emit() {\n    println!(\"cargo:rustc-env=clippy_args=-Aclippy::disallowed_methods\");\n}\n".to_owned(),
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "uses another file",
        },
        Case {
            id: "build-script-include-in-owner",
            gate: "allow-audit",
            tool: None,
            // A build script in an owner crate, where `include!` is otherwise allowed, that
            // includes the helper setting clippy's arguments.
            seed: both(
                write(
                    "crates/uaos-testkit/build.rs",
                    "include!(\"build_env.rs\");\n\nfn main() {\n    emit_env();\n}\n".to_owned(),
                ),
                write(
                    "crates/uaos-testkit/build_env.rs",
                    "fn emit_env() {\n    println!(\"cargo:rustc-env={}=-Aclippy::disallowed_types\", \"clippy_args\".to_ascii_uppercase());\n}\n".to_owned(),
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "crates/uaos-testkit/build.rs: a build script uses another file",
        },
        Case {
            id: "build-dependency-path",
            gate: "allow-audit",
            tool: None,
            // A path build dependency, whose code runs in the build script.
            seed: both(
                write("crates/uaos-state/build.rs", "fn main() {}\n".to_owned()),
                append("crates/uaos-state/Cargo.toml", "\n[build-dependencies]\nuaos-contracts = { path = \"../uaos-contracts\" }\n"),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "build dependency `uaos-contracts` is a path dependency",
        },
        Case {
            id: "canary-copied-from-sibling",
            gate: "allow-audit",
            tool: None,
            // A canary copied from a sibling in the same module, whose own ban fulfils the
            // expectation.
            seed: replace(
                "crates/uaos-egress/tests/bans.rs",
                "    #[expect(clippy::disallowed_methods, reason = \"canary\")]\n    fn task_spawn_blocking() {\n        // canary: `tokio::task::spawn_blocking`\n        let _canary = tokio::task::spawn_blocking(|| ());",
                "    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = \"canary\")]\n    fn task_spawn_blocking(set: &mut tokio::task::JoinSet<()>) {\n        // canary: `tokio::task::spawn_blocking`\n        let _canary = set.spawn_blocking(|| ());",
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "the canary for `tokio::task::spawn_blocking`",
        },
        Case {
            id: "build-script-declared-path",
            gate: "allow-audit",
            tool: None,
            // A build script at the path `build = "..."` names.
            seed: both(
                write(
                    "crates/uaos-state/build/main.rs",
                    "fn main() {\n    println!(\"cargo:rustc-env=CLIPPY_CONF_DIR=crates\");\n}\n".to_owned(),
                ),
                replace(
                    "crates/uaos-state/Cargo.toml",
                    "name = \"uaos-state\"\n",
                    "name = \"uaos-state\"\nbuild = \"build/main.rs\"\n",
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "main.rs: a build script names one of clippy's variables",
        },
        Case {
            id: "net-unix-connect-outside-egress",
            gate: "clippy",
            tool: Some(UNIX_ONLY),
            // The Unix-socket bans are `allow-invalid`, so a wrong path would go silent; this
            // proves they resolve where they exist.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\n#[cfg(unix)]\npub fn seeded_violation() -> std::io::Result<std::os::unix::net::UnixStream> {\n    std::os::unix::net::UnixStream::connect(\"/run/seeded.sock\")\n}\n",
            ),
            runner: CLIPPY,
            expect: "std::os::unix::net::UnixStream::connect",
        },
        Case {
            id: "arch-ring1-depends-on-hyper",
            gate: "arch-check",
            tool: None,
            // A Ring 1 module that reaches a network crate.
            seed: both(
                both(
                    write(
                        "modules/mod-seeded/Cargo.toml",
                        "[package]\nname = \"mod-seeded\"\nversion = \"0.0.0\"\nedition = \"2024\"\nlicense = \"Apache-2.0\"\npublish = false\n\n[dependencies]\nhyper.workspace = true\n".to_owned(),
                    ),
                    write("modules/mod-seeded/src/lib.rs", "// SPDX-License-Identifier: Apache-2.0\n".to_owned()),
                ),
                replace("Cargo.toml", "members = [\"crates/*\", \"xtask\"]", "members = [\"crates/*\", \"modules/*\", \"xtask\"]"),
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "transitively depends on banned crate `hyper`",
        },
        Case {
            id: "chunk-flushed-before-sync",
            gate: "journal-durability",
            tool: None,
            // A journal that declares records durable before their payloads are.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        self.sync_payloads()?;\n        match self.active.sync_data() {\n            Ok(()) => {\n                self.mark_flushed();\n",
                "        match self.active.sync_data() {\n            Ok(()) => {\n                self.mark_flushed();\n                self.sync_payloads()?;\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "a_flushed_record_never_references_an_unreadable_payload",
                ],
            },
            expect: "lost its payload",
        },
        Case {
            id: "intent-before-chunk-write",
            gate: "journal-durability",
            tool: None,
            // A journal that acknowledges a record whose payload is not stored yet.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "if !store.is_stored(pocket, chunk).map_err(JournalError::Payload)? {",
                "if false && !store.is_stored(pocket, chunk).map_err(JournalError::Payload)? {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "a_record_cannot_reference_a_chunk_that_is_not_stored",
                ],
            },
            expect: "payload before record",
        },
        Case {
            id: "chunk-put-pair-race",
            gate: "journal-durability",
            tool: None,
            // S-6: a chunk store that lets two writers of one chunk interleave.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "while inflight.contains(&key) {",
                "while false && inflight.contains(&key) {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "concurrent_puts_of_one_chunk_never_pair_data_with_the_wrong_key",
                ],
            },
            expect: "paired with the other's key",
        },
        Case {
            id: "chunk-put-shared-temp",
            gate: "journal-durability",
            tool: None,
            // S-6: atomic writes that share one temporary name per target.
            seed: replace(
                "crates/uaos-platform/src/fs.rs",
                "name.push(format!(\"{TEMP_MARKER}{}-{n}\", std::process::id()));",
                "name.push(format!(\"{TEMP_MARKER}{}-{}\", std::process::id(), n * 0));",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-platform", "--lib", "temp_names_are_unique"],
            },
            expect: "never share a temporary",
        },
        Case {
            id: "marker-before-loss-report",
            gate: "journal-durability",
            tool: None,
            // An open that makes the previous run's records durable and moves the durable point
            // before it journals the losses it found. Three defences stop it (report first; no
            // flush while a loss is unreported; the marker refuses to pass one), so all three go.
            seed: both(
                replace(
                    "crates/uaos-state/src/journal/writer.rs",
                    "        self.report_lost()?;\n        self.sync()?;\n        self.store_manifest_if_unstored()?;\n",
                    "        self.sync()?;\n        self.store_manifest_if_unstored()?;\n        self.update_marker(true).map_err(storage)?;\n        self.report_lost()?;\n",
                ),
                both(
                    replace(
                        "crates/uaos-state/src/journal/writer.rs",
                        "        if !self.unreported.is_empty() || store_holds_back || self.manifest_unstored {",
                        "        let _ = store_holds_back;\n        if self.manifest_unstored {",
                    ),
                    replace(
                        "crates/uaos-state/src/journal/writer.rs",
                        "        if !self.unreported.is_empty() {
            return Err(self.unreported_error());
        }
        if self.unflushed.is_empty() {",
                        "        if self.unflushed.is_empty() {",
                    ),
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "h1_open_reports_a_loss_before_its_marker_moves",
                ],
            },
            expect: "has an unreadable payload and no chunk.lost record",
        },
        Case {
            id: "open-stores-manifest-before-flush",
            gate: "journal-durability",
            tool: None,
            // An open that disowns the old copies before the new ones are durable.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "    file.append(tail).map_err(storage)?;\n    let lines",
                "    file.append(tail).map_err(storage)?;\n    manifest.store(fs, dir)?;\n    let lines",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "r2_h1_a_power_loss_during_open_keeps_what_the_previous_run_flushed",
                ],
            },
            expect: "vanished",
        },
        Case {
            id: "is-stored-trusts-earlier-pair",
            gate: "journal-durability",
            tool: None,
            // A store that vouches for an earlier process's pair without rewriting it.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "                self.adopt(key, &content, Some(data_key), Flush::Now)?;\n                Ok(true)",
                "                drop((content, data_key));\n                self.remember(key);\n                Ok(true)",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "r2_m1_is_stored_rewrites_an_earlier_processs_unflushed_pair",
                ],
            },
            expect: "only an earlier process had written",
        },
        Case {
            id: "flush-skips-missing-pending-file",
            gate: "journal-durability",
            tool: None,
            // A flush that treats a vanished pending file as flushed.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "                self.flushed(|| self.fs.sync_file(&path))?;",
                "                match self.fs.sync_file(&path) {\n                    Ok(()) | Err(FsError::NotFound { .. }) => {}\n                    Err(e) => return Err(storage(e)),\n                }",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "r2_m1_a_pending_file_removed_underneath_is_a_flush_failure",
                ],
            },
            expect: "pending payload's file was gone",
        },
        Case {
            id: "loss-set-aside-after-quarantine",
            gate: "journal-durability",
            tool: None,
            // Recovery that remembers a loss only once its quarantine succeeded.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "            // Set aside first: from here on the loss is remembered whatever fails next.\n            locked(&self.lost).push(LostChunk {\n                pocket: key.0,\n                chunk: key.1,\n                cause,\n            });\n            self.forget(key);\n            self.quarantine_pair(key.0, key.1)?;\n        }\n        self.cleared.fetch_max(seen, Ordering::SeqCst);",
                "            self.forget(key);\n            self.quarantine_pair(key.0, key.1)?;\n            locked(&self.lost).push(LostChunk {\n                pocket: key.0,\n                chunk: key.1,\n                cause,\n            });\n        }\n        self.cleared.fetch_max(seen, Ordering::SeqCst);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "r2_m1_a_failed_quarantine_never_drops_a_loss",
                ],
            },
            expect: "dropped by the failed quarantine",
        },
        Case {
            id: "shred-not-completed-at-open",
            gate: "journal-durability",
            tool: None,
            // A journaled shred a crash interrupted, left readable.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "                if unrotated || store.pair_remains(pocket, chunk).map_err(JournalError::Payload)? {",
                "                if false && (unrotated || store.pair_remains(pocket, chunk).map_err(JournalError::Payload)?) {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "a_shred_interrupted_after_its_record_is_completed_at_open",
                ],
            },
            expect: "is still readable",
        },
        Case {
            id: "shred-bypasses-journal",
            gate: "journal-durability",
            tool: None,
            // A coordinated store that shreds without its journal's record.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        if self.attached.load(Ordering::SeqCst) {\n            return Err(ChunkError::ShredThroughJournal);",
                "        if false && self.attached.load(Ordering::SeqCst) {\n            return Err(ChunkError::ShredThroughJournal);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r3_h1_after_a_shred_a_record_needs_its_content_stored_again"],
            },
            expect: "a coordinated store shredded without its journal",
        },
        Case {
            id: "shreds-before-manifest-at-open",
            gate: "journal-durability",
            tool: None,
            // An open that completes shreds before the manifest naming their records is durable.
            seed: both(
                replace(
                    "crates/uaos-state/src/journal/writer.rs",
                    "        self.sync()?;\n        self.store_manifest_if_unstored()?;\n",
                    "        self.sync()?;\n",
                ),
                replace(
                    "crates/uaos-state/src/journal/writer.rs",
                    "        self.update_marker(true).map_err(storage)?;\n        Ok(())\n    }",
                    "        self.store_manifest_if_unstored()?;\n        self.update_marker(true).map_err(storage)?;\n        Ok(())\n    }",
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r3_m2_shreds_at_open_wait_for_the_manifest"],
            },
            expect: "r3 m2: record",
        },
        Case {
            id: "plain-marker-trusted",
            gate: "journal-durability",
            tool: None,
            // The first open with a store trusts a plain journal's marker.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "fs.write_atomic(&dir.join(FLUSH_MARKER), none.as_bytes())",
                "Ok::<(), FsError>(drop(none))",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r4_m1_a_plain_journals_marker_does_not_skip_the_payload_check"],
            },
            expect: "trusted a plain journal's marker",
        },
        Case {
            id: "put-overlapping-failed-flush",
            gate: "journal-durability",
            tool: None,
            // A put whose write overlapped a failed directory flush is acknowledged after a
            // recovery that missed it.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "            if self.poison.load(Ordering::SeqCst) != started {",
                "            if false && self.poison.load(Ordering::SeqCst) != started {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r4_l1_a_put_spanning_a_failed_directory_flush_is_recovered_with_it"],
            },
            expect: "acknowledged after recovery missed it",
        },
        Case {
            id: "failed-shred-vouched",
            gate: "journal-durability",
            tool: None,
            // After a shred fails midway, the store vouches for the content from disk, so a later
            // record cancels the journaled shred.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        if locked(&self.shredding).contains(&key) {\n            return Ok(false);",
                "        if false && locked(&self.shredding).contains(&key) {\n            return Ok(false);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r4_l2_a_failed_shred_never_vouches_for_its_content"],
            },
            expect: "a record referenced content whose shred is recorded",
        },
        Case {
            id: "flush-acked-across-poisoning",
            gate: "journal-durability",
            tool: None,
            // A journal flush acknowledged although a flushed write elsewhere failed while it ran
            // and may have dropped the batch's directory entries.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        drop(self.flush_window.write().unwrap_or_else(PoisonError::into_inner));\n        if self.poison.load(Ordering::SeqCst) != started {",
                "        drop(self.flush_window.write().unwrap_or_else(PoisonError::into_inner));\n        if false && self.poison.load(Ordering::SeqCst) != started {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r5_m2_a_flush_is_not_acknowledged_across_a_failed_rewrap"],
            },
            expect: "acknowledged across a failed flush",
        },
        Case {
            id: "shred-marked-after-record",
            gate: "journal-durability",
            tool: None,
            // A shred whose own flush fails leaves its chunk unmarked, so once the record is
            // durable a later record cancels the shred. A failed flush also
            // marks the chunk again, so the seed removes both marks.
            seed: both(
                replace(
                    "crates/uaos-state/src/journal/writer.rs",
                    "        let marked = store.begin_shred(pocket, chunk).map_err(JournalError::Payload)?;\n",
                    "        let marked = false;\n",
                ),
                replace(
                    "crates/uaos-state/src/journal/writer.rs",
                    "the mark meanwhile.\n            store.keep_refused(pocket, chunk);\n",
                    "the mark meanwhile.\n",
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r5_l1_a_shred_whose_flush_failed_stays_refused"],
            },
            expect: "whose shred record is durable",
        },
        Case {
            id: "failed-put-lifts-shred-mark",
            gate: "journal-durability",
            tool: None,
            // A put lifts a failed shred's mark before its own write fails.
            seed: both(
                replace(
                    "crates/uaos-state/src/chunks/mod.rs",
                    "        self.stored_again(key);\n        Ok(chunk)\n    }",
                    "        Ok(chunk)\n    }",
                ),
                replace(
                    "crates/uaos-state/src/chunks/mod.rs",
                    "        self.check_poison()?;\n        if locked(&self.known).contains(&key) {\n            // Written by this process",
                    "        self.check_poison()?;\n        self.stored_again(key);\n        if locked(&self.known).contains(&key) {\n            // Written by this process",
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r5_l1_a_failed_put_keeps_a_failed_shred_refused"],
            },
            expect: "a failed put lifted the refusal",
        },
        Case {
            id: "rotation-skips-current-key",
            gate: "journal-durability",
            tool: None,
            // A re-wrap that skips a key file already at the current version retires the KEK the
            // durable copy still needs.
            seed: both(
                replace(
                    "crates/uaos-state/src/chunks/mod.rs",
                    "                Ok((data_key, _)) => {\n                    self.write_key(pocket, chunk, &data_key, current, &kek, Flush::Now)?;",
                    "                Ok((data_key, version)) if version < current => {\n                    self.write_key(pocket, chunk, &data_key, current, &kek, Flush::Now)?;",
                ),
                replace(
                    "crates/uaos-state/src/chunks/mod.rs",
                    "                Err(ChunkError::Unavailable | ChunkError::Corrupt) => {}\n                Err(e) => return Err(e),",
                    "                Ok(_) | Err(ChunkError::Unavailable | ChunkError::Corrupt) => {}\n                Err(e) => return Err(e),",
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r5_a_failed_rewrap_never_leaves_a_key_only_a_retired_kek_opens"],
            },
            expect: "retired a KEK a durable key file still needed",
        },
        Case {
            id: "store-flush-poisons-outside-window",
            gate: "journal-durability",
            tool: None,
            // A store flush whose own directory flush fails poisons after the window, so a
            // concurrent journal flush acknowledges its batch in between.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "            self.flushed(|| self.fs.sync_dir(&self.data_dir(pocket)))?;",
                "            self.fs.sync_dir(&self.data_dir(pocket)).map_err(storage)?;",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r6_l1_a_failed_direct_store_flush_is_seen_by_a_concurrent_journal_flush"],
            },
            expect: "acknowledged across a failed flush",
        },
        Case {
            id: "shred-mark-not-restored",
            gate: "journal-durability",
            tool: None,
            // A put during a shred lifts the mark, and a failed flush of the shred record does not
            // restore it.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "the mark meanwhile.\n            store.keep_refused(pocket, chunk);\n",
                "the mark meanwhile.\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r6_l2_a_put_during_a_shred_whose_flush_fails_does_not_lift_the_refusal"],
            },
            expect: "whose shred record is durable",
        },
        Case {
            id: "shred-unmarked-after-written-record",
            gate: "journal-durability",
            tool: None,
            // A shred whose record was written, and whose flush inside `append` failed, lifts its
            // mark as if no record existed.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "            if self.next_seq > before {\n                // The record was written and only the flush inside `append` failed",
                "            if false && self.next_seq > before {\n                // The record was written and only the flush inside `append` failed",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r7_m1_a_shred_whose_flush_inside_append_fails_stays_refused"],
            },
            expect: "whose shred record is durable",
        },
        Case {
            id: "kernel-record-appended-directly",
            gate: "journal-durability",
            tool: None,
            // `append` takes a caller's chunk.shredded or chunk.lost on a coordinated journal.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        if origin == Origin::Caller\n            && self.payloads.is_some()",
                "        if origin == Origin::Caller\n            && self.payloads.is_none()",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r9_l1_kernel_records_cannot_be_appended_directly"],
            },
            expect: "a chunk.shredded record was appended directly",
        },
        Case {
            id: "store-losses-taken-by-caller",
            gate: "journal-durability",
            tool: None,
            // A coordinated store lets a caller recover it or take its losses, so the journal never
            // reports them.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        if self.attached.load(Ordering::SeqCst) {\n            return Err(ChunkError::LossesThroughJournal);",
                "        if false && self.attached.load(Ordering::SeqCst) {\n            return Err(ChunkError::LossesThroughJournal);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r10_l1_a_coordinated_stores_losses_go_through_its_journal"],
            },
            expect: "a caller recovered a coordinated store",
        },
        Case {
            id: "recovery-leaves-store-poisoned",
            gate: "journal-durability",
            tool: None,
            // `recover` treats a poisoned store only while the writer is healthy.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "            && (self.health == JournalHealth::PayloadFlushFailed || store.is_poisoned() || store.has_untaken_losses())",
                "            && (self.health == JournalHealth::PayloadFlushFailed\n                || (self.health == JournalHealth::Healthy && store.is_poisoned())\n                || store.has_untaken_losses())",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r10_a_recovery_out_of_space_also_recovers_a_poisoned_store"],
            },
            expect: "the store stayed poisoned after an Ok recovery",
        },
        Case {
            id: "payload-failure-hides-torn-segment",
            gate: "journal-durability",
            tool: None,
            // A payload flush failure replaces `DiskFull`, so recovery appends after a torn line
            // and the journal no longer opens.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "            if self.health == JournalHealth::Healthy {\n                self.health = JournalHealth::PayloadFlushFailed;\n            }",
                "            self.health = JournalHealth::PayloadFlushFailed;",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r11_h1_a_payload_failure_never_hides_a_torn_segment"],
            },
            expect: "a payload failure hid the torn segment",
        },
        Case {
            id: "lost-content-reads-as-unavailable",
            gate: "journal-durability",
            tool: None,
            // Content whose loss was journaled reads back as never stored or shredded.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "                    Ok(_) => Err(ChunkError::Lost),",
                "                    Ok(_) => Err(ChunkError::Unavailable),",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r12_l3_lost_content_reads_back_as_lost"],
            },
            expect: "lost content read back as never stored or shredded",
        },
        Case {
            id: "unauthentic-loss-skipped-at-open",
            gate: "journal-durability",
            tool: None,
            // An open that skips an unauthentic payload, so its record becomes durable with no
            // chunk.lost record.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "                    self.remember(key);\n                    continue;\n                }\n                Probe::Absent => LossCause::Missing,",
                "                    self.remember(key);\n                    continue;\n                }\n                Probe::Lost(LossCause::Unauthentic) => continue,\n                Probe::Absent => LossCause::Missing,",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r13_l1_an_unauthentic_payload_found_at_open_is_journaled"],
            },
            expect: "survived without its payload and with no chunk.lost record",
        },
        Case {
            id: "unauthentic-loss-skipped-in-recovery",
            gate: "journal-durability",
            tool: None,
            // A recovery that skips an unauthentic payload.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "                    locked(&self.pending).remove(&key);\n                    continue;\n                }\n                Probe::Absent => LossCause::Missing,",
                "                    locked(&self.pending).remove(&key);\n                    continue;\n                }\n                Probe::Lost(LossCause::Unauthentic) => continue,\n                Probe::Absent => LossCause::Missing,",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r13_l1_an_unauthentic_payload_found_in_recovery_is_journaled"],
            },
            expect: "became durable without its payload and with no chunk.lost record",
        },
        Case {
            id: "missing-loss-reads-as-unavailable",
            gate: "journal-durability",
            tool: None,
            // A loss with no file to set aside leaves no marker.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        self.fs\n            .write_unsynced(&self.lost_marker(pocket, chunk), b\"\")\n            .map_err(storage)?;",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r13_l2_a_missing_payload_reads_back_as_lost"],
            },
            expect: "a journaled loss reads back as never stored or shredded",
        },
        Case {
            id: "shredded-content-reads-as-lost",
            gate: "journal-durability",
            tool: None,
            // A shred that leaves an earlier loss's marker.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        match self.fs.remove_file(&self.lost_marker(pocket, chunk)) {",
                "        match Err::<(), FsError>(FsError::NotFound { op: \"seeded\" }) {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r13_l3_lost_then_shredded_reads_back_as_shredded"],
            },
            expect: "deliberately shredded content reads back as lost",
        },
        Case {
            id: "shred-of-quarantined-payload-skipped",
            gate: "journal-durability",
            tool: None,
            // An open that ignores a loss marker when it decides whether a journaled shred
            // finished, so the KEK is never rotated.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        for path in [self.key_path(pocket, chunk), self.chunk_path(pocket, chunk), lost] {",
                "        let _ = lost;\n        for path in [self.key_path(pocket, chunk), self.chunk_path(pocket, chunk)] {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r14_m1_a_shred_whose_payload_was_quarantined_is_completed"],
            },
            expect: "was never rotated",
        },
        Case {
            id: "loss-cause-overwritten",
            gate: "journal-durability",
            tool: None,
            // A chunk set aside twice reported with its later cause.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        causes.entry((l.pocket, l.chunk)).or_insert(l.cause);",
                "        causes.insert((l.pocket, l.chunk), l.cause);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r14_l2_the_cause_the_bytes_showed_is_the_cause_reported"],
            },
            expect: "cause reported for record",
        },
        Case {
            id: "shred-incomplete-key-only",
            gate: "journal-durability",
            tool: None,
            // An open that judges a shred finished once its key file is gone.
            seed: both(
                replace(
                    "crates/uaos-state/src/chunks/mod.rs",
                    "        for path in [self.key_path(pocket, chunk), self.chunk_path(pocket, chunk), lost] {\n            match self.fs.read(&path) {",
                    "        let _ = lost;\n        for path in [self.key_path(pocket, chunk)] {\n            match self.fs.read(&path) {",
                ),
                replace(
                    "crates/uaos-state/src/chunks/mod.rs",
                    "        Ok(self.keys.kek_versions(pocket).map_err(ChunkError::Keyring)?.len() > 1)",
                    "        Ok(false)",
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r3_l3_a_shred_failing_midway_at_open_is_finished_by_the_next"],
            },
            expect: "a retried open left a shred unfinished",
        },
        Case {
            id: "store-flush-failure-forgotten",
            gate: "journal-durability",
            tool: None,
            // A chunk store that forgets a failed flush and vouches for its chunks again.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        if self.is_poisoned() {\n            Err(ChunkError::FlushFailed)",
                "        if false && self.is_poisoned() {\n            Err(ChunkError::FlushFailed)",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "h3_a_store_flush_failure_stops_the_journal",
                ],
            },
            expect: "saw the store's failure",
        },
        Case {
            id: "recovery-reflushes-same-file",
            gate: "journal-durability",
            tool: None,
            // Recovery that flushes the file whose flush failed instead of rewriting it.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "                Probe::Readable { content, data_key } => {\n                    self.write_pair(key.0, key.1, &content, Some(data_key), Flush::Now)?;\n                    locked(&self.pending).remove(&key);\n                    continue;",
                "                Probe::Readable { .. } => {\n                    for path in [self.chunk_path(key.0, key.1), self.key_path(key.0, key.1)] {\n                        self.fs.sync_file(&path).map_err(storage)?;\n                    }\n                    locked(&self.pending).remove(&key);\n                    continue;",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "h4_recovery_rewrites_content_instead_of_reflushing_the_failed_file",
                ],
            },
            expect: "re-flushed in place",
        },
        Case {
            id: "chunk-rewrite-unflushed",
            gate: "journal-durability",
            tool: None,
            // A chunk from an earlier process replaced by a write that is not flushed.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "Probe::Readable { data_key, .. } => self.adopt(key, content, Some(data_key), Flush::Now)?",
                "Probe::Readable { data_key, .. } => self.adopt(key, content, Some(data_key), self.flush_mode())?",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "n1_a_rewrite_of_a_chunk_from_an_earlier_process_is_flushed",
                ],
            },
            expect: "replaced by an unflushed copy",
        },
        Case {
            id: "chunk-rewrite-new-data-key",
            gate: "journal-durability",
            tool: None,
            // A rewrite under a fresh data key, so a failure between its two files breaks the pair.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "            Some(k) => k,\n            None => SecretKey::generate",
                "            Some(_) | None => SecretKey::generate",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "n2_a_rewrite_that_fails_between_its_two_files_leaves_a_readable_pair",
                ],
            },
            expect: "never written",
        },
        Case {
            id: "loss-flushed-before-report",
            gate: "journal-durability",
            tool: None,
            // A flush while a found loss waits to be journaled.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        if !self.unreported.is_empty() {\n            return Err(self.unreported_error());\n        }\n",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "n3_a_loss_waiting_to_be_journaled_holds_back_every_flush",
                ],
            },
            expect: "while a loss waited to be journaled",
        },
        Case {
            id: "open-trusts-previous-segment",
            gate: "journal-durability",
            tool: None,
            // An open that seals the previous run's segment in place instead of copying it.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "    if proven_end == end {\n",
                "    if true {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "n4_open_copies_the_previous_runs_records_instead_of_flushing_their_file_again",
                ],
            },
            expect: "cache kept:",
        },
        Case {
            id: "arch-json-io-dependency",
            gate: "arch-check",
            tool: None,
            // The tokenizer stays pure; an async runtime in its graph fails.
            seed: replace(
                "crates/uaos-json/Cargo.toml",
                "[dependencies]\nmemchr.workspace = true\n",
                "[dependencies]\nmemchr.workspace = true\ntokio.workspace = true\n",
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "transitively depends on banned crate `tokio`",
        },
        Case {
            id: "ledger-reserve-beyond-available",
            gate: "budget-concurrency",
            tool: None,
            // A ledger that accepts any reservation while the pool is not already in debt. The cap
            // is enforced twice (ledger state and the contract's per-entry rule), so both go.
            seed: both(
                replace(
                    "crates/uaos-ledger/src/state.rs",
                    "if usable < amount {",
                    "if usable < NanoUsd::ZERO {",
                ),
                replace(
                    "crates/uaos-contracts/src/budget.rs",
                    "if matches!(self.kind, K::Reserve | K::TransferOut) && self.balance_after.is_negative() {",
                    "if matches!(self.kind, K::Reserve | K::TransferOut) && self.balance_after < NanoUsd::new(i64::MIN) {",
                ),
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-ledger", "--test", "ledger"] },
            expect: "hard cap breached",
        },
        Case {
            id: "redact-detector-drops-a-format",
            gate: "redaction-corpus",
            tool: None,
            // A detector set that no longer recognises one AWS key prefix.
            seed: replace(
                "crates/uaos-redact-scan/src/detect.rs",
                "        anchor(\"ASIA\", C::AwsAccessKeyId, true, AWS),\n",
                "",
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-redact", "--test", "corpus"] },
            expect: "recall below",
        },
        Case {
            id: "redact-generator-draws-slash-password",
            gate: "redaction-corpus",
            tool: None,
            // The corpus generator draws a password starting with `//`, a stated miss, again, as on
            // CI seed 4814893562051029426.
            seed: replace(
                "crates/uaos-redact/tests/common/mod.rs",
                "    candidate.contains(\"://\") || candidate.starts_with(\"//\") || port_then_path || template\n",
                "    candidate.contains(\"://\") || port_then_path || template\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--test", "redact", "the_ci_seed_that_drew_a_stated_miss_is_redacted"],
            },
            expect: "a secret survived redaction",
        },
        Case {
            id: "redact-url-password-stops-at-slash",
            gate: "redaction-corpus",
            tool: None,
            // A URL password ends at its first `/` again.
            seed: replace(
                "crates/uaos-redact-scan/src/detect.rs",
                r#"matches!(b, b'"' | b'<' | b'>' | b'`')"#,
                r#"matches!(b, b'"' | b'<' | b'>' | b'`' | b'/')"#,
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-redact", "--test", "corpus"] },
            expect: "recall below",
        },
        Case {
            id: "policy-slicing-drops-unconstrained",
            gate: "policy-semantics",
            tool: None,
            // Slicing that loses action-unconstrained policies, so a forbid without an action
            // constraint stops applying.
            seed: replace(
                "crates/uaos-policy/src/engine.rs",
                "ActionConstraint::Any => true,",
                "ActionConstraint::Any => false,",
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-policy", "--test", "policy"] },
            expect: "unconstrained forbid skipped",
        },
        Case {
            id: "policy-error-fails-open",
            gate: "policy-semantics",
            tool: None,
            // An engine that, like plain Cedar, skips an erroring policy.
            seed: replace(
                "crates/uaos-policy/src/engine.rs",
                "if !errors.is_empty() {",
                "if errors.is_empty() && !errors.is_empty() {",
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-policy", "--test", "policy"] },
            expect: "an erroring policy failed open",
        },
        Case {
            id: "policy-grant-overrides-forbid",
            gate: "policy-semantics",
            tool: None,
            // A grant is an approval and must never beat a forbid.
            seed: replace(
                "crates/uaos-policy/src/engine.rs",
                "CedarDecision::Deny if !matched.is_empty() =>",
                "CedarDecision::Deny if !matched.is_empty() && grants.is_empty() =>",
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-policy", "--test", "policy"] },
            expect: "a grant must never override a forbid",
        },
        Case {
            id: "dco-missing-signoff",
            gate: "dco",
            tool: Some("git"),
            seed: Box::new(|_| Ok(())),
            runner: Runner::History(crate::dco::check, dco_history),
            expect: "lack a matching DCO",
        },
        Case {
            id: "dco-unsigned-content-merge",
            gate: "dco",
            tool: Some("git"),
            seed: Box::new(|_| Ok(())),
            // Clean: an unsigned conflict-free merge (exempt). Violating: an unsigned merge
            // that resolves a conflict with new content.
            runner: Runner::History(crate::dco::check, dco_merge_history),
            expect: "lack a matching DCO",
        },
        Case {

            id: "allow-audit-guarded-lint-outside-owner",
            gate: "allow-audit",
            tool: None,
            // An ambient-clock ban switched off in a crate that does not own the clock.
            seed: append_owned(
                LIB,
                format!(
                    "
/// Seeded.
#[{}({}, reason = \"seeded\")]
#[must_use]
pub fn seeded_violation() -> u8 {{
    1
}}
",
                    "allow", "clippy::disallowed_methods"
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "outside its owners",
        },
        // The macro renamed by `use`.
        Case {
            id: "allow-audit-include-renamed",
            gate: "allow-audit",
            tool: None,
            seed: append(LIB, "\nuse core::include as pull;\n"),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "`include` named outside the owners",
        },
        // The same, behind a raw C string the text scan read as escaped, which hid everything up to
        // the next quote.
        Case {
            id: "allow-audit-hidden-behind-c-string",
            gate: "allow-audit",
            tool: None,
            seed: append_owned(
                LIB,
                format!(
                    "
/// Seeded.
pub const SEEDED_MASK: &::core::ffi::CStr = cr\"\\\";
/// Seeded.
#[{}({}, reason = \"seeded\")]
#[must_use]
pub fn seeded_violation() -> char {{
    '\"'
}}
",
                    "allow", "clippy::disallowed_methods"
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "outside its owners",
        },
        Case {
            id: "allow-audit-unsafe-outside-owner",
            gate: "allow-audit",
            tool: None,
            // `unsafe_code` re-enabled for one item outside any owner path. The workspace only
            // denies it, so a local allow would compile; uaos-contracts forbids it outright.
            seed: append_owned(
                "crates/uaos-ledger/src/lib.rs",
                format!(
                    "
/// Seeded.
#[{}({})]
#[must_use]
pub fn seeded_violation() -> u8 {{
    1
}}
",
                    "allow", "unsafe_code"
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "outside its owners",
        },
        Case {
            id: "allow-audit-hidden-by-cache-tag",
            gate: "allow-audit",
            tool: None,
            // A signed cache tag committed into a source folder must not hide an `unsafe_code`
            // allow from the audit.
            seed: both(
                write(
                    "crates/uaos-ledger/src/CACHEDIR.TAG",
                    "Signature: 8a477f597d28d172789f06886806bc55\n".to_owned(),
                ),
                append_owned(
                    "crates/uaos-ledger/src/lib.rs",
                    format!(
                        "
/// Seeded.
#[{}({})]
#[must_use]
pub fn seeded_hidden_violation() -> u8 {{
    1
}}
",
                        "allow", "unsafe_code"
                    ),
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "outside its owners",
        },
        Case {
            id: "vet-ratchet-unnoted-exemption",
            gate: "vet-ratchet",
            tool: None,
            // A new exemption without a `notes` reason.
            seed: append(
                "supply-chain/config.toml",
                "
[[exemptions.seeded-unaudited-crate]]
version = \"1.0.0\"
criteria = \"safe-to-deploy\"
",
            ),
            runner: Runner::Xtask(&["vet-ratchet"]),
            expect: "without notes",
        },
        Case {
            // Redaction's walk of the tape skips member keys: the differential must see it.
            id: "redact-tape-differential-disagrees",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-redact/src/redactor.rs",
                "        let key = node.key_span().map(|key| {",
                "        let key = node.key_span().filter(|_| false).map(|key| {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--lib", "differential::tokenizers_agree"],
            },
            expect: "the tokenizers found different strings",
        },
        Case {
            // A body the tokenizer refuses is passed through as if clean: a fallback that fails
            // open.
            id: "redact-tape-refusal-passes",
            gate: "redaction-corpus",
            tool: None,
            seed: replace(
                "crates/uaos-redact/src/redactor.rs",
                "        let tape = uaos_json::parse(json, &Limits::DEFAULT).map_err(tape_refusal)?;",
                "        let Ok(tape) = uaos_json::parse(json, &Limits::DEFAULT) else {
            return Ok(Redaction { output: Cow::Borrowed(json), replacements: Vec::new(), edited: Vec::new() });
        };",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--test", "redact", "arbitrary_bytes_never_panic_and_errors_block"],
            },
            expect: "a body the tokenizer refuses was redacted, not blocked",
        },
        Case {
            // An edited key is not checked, so redaction can emit a duplicate key.
            id: "redact-skips-reparse-after-key-edit",
            gate: "redaction-corpus",
            tool: None,
            seed: replace(
                "crates/uaos-redact/src/redactor.rs",
                "        if key_edited {",
                "        if key_edited && json.is_empty() {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--test", "redact", "a_duplicate_made_by_redaction_blocks"],
            },
            expect: "unwrap_err",
        },
        // The exact size check is off by one.
        Case {
            id: "redact-size-check-off-by-one",
            gate: "redaction-corpus",
            tool: None,
            seed: replace(
                "crates/uaos-redact/src/redactor.rs",
                "                if buf.len() > max_bytes {\n                    return Err(RedactError::TooLarge(\"redaction-output-too-large\"));\n                }\n                Cow::Owned(buf)",
                "                if buf.len() > max_bytes + 1 {\n                    return Err(RedactError::TooLarge(\"redaction-output-too-large\"));\n                }\n                Cow::Owned(buf)",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--test", "redact", "an_output_that_outgrows_the_limits_blocks"],
            },
            expect: "an output one byte over the limit came back",
        },
        // A structural refusal gets the retryable detector code that INGRESS_MALFORMED exists to
        // avoid.
        Case {
            id: "redact-structural-refusal-retryable",
            gate: "redaction-corpus",
            tool: None,
            seed: replace(
                "crates/uaos-redact/src/redactor.rs",
                "        _ => RedactError::Malformed(label),",
                "        _ => RedactError::DetectorFailure(label),",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--test", "redact", "every_tokenizer_refusal_maps_as_the_contract_says"],
            },
            expect: "is mapped against the refusal table",
        },
        // Only the check inside the loop is left, so an overflow in the bytes after the last
        // replacement passes.
        Case {
            id: "redact-output-tail-unchecked",
            gate: "redaction-corpus",
            tool: None,
            seed: replace(
                "crates/uaos-redact/src/redactor.rs",
                "                if buf.len() > max_bytes {\n                    return Err(RedactError::TooLarge(\"redaction-output-too-large\"));\n                }\n                Cow::Owned(buf)",
                "                Cow::Owned(buf)",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--test", "redact", "an_overflow_in_the_tail_blocks"],
            },
            expect: "unwrap_err",
        },
        // The check inside the loop projects the whole output again, so a body whose redaction
        // shrinks is refused.
        Case {
            id: "redact-shrinking-output-refused",
            gate: "redaction-corpus",
            tool: None,
            seed: replace(
                "crates/uaos-redact/src/redactor.rs",
                "                if buf.len() > max_bytes {\n                    return Err(RedactError::TooLarge(\"redaction-output-too-large\"));\n                }\n            }\n        }",
                "                if buf.len().saturating_add(json.len().saturating_sub(copied)) > max_bytes {\n                    return Err(RedactError::TooLarge(\"redaction-output-too-large\"));\n                }\n            }\n        }",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--test", "redact", "an_output_that_shrinks_fits_at_the_limit"],
            },
            expect: "TooLarge",
        },
        // A later string resets the key-edit flag, so the duplicate an earlier key edit made goes
        // unchecked.
        Case {
            id: "redact-key-edit-forgotten",
            gate: "redaction-corpus",
            tool: None,
            seed: replace(
                "crates/uaos-redact/src/redactor.rs",
                "                key_edited |= is_key;",
                "                key_edited = is_key;",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--test", "redact", "a_duplicate_made_by_redaction_blocks"],
            },
            expect: "a later edit hid the duplicate",
        },
        // The re-parse uses the default limits, not the tape's.
        Case {
            id: "redact-reparse-ignores-tape-limits",
            gate: "redaction-corpus",
            tool: None,
            seed: replace(
                "crates/uaos-redact/src/redactor.rs",
                "            uaos_json::parse(&output, &limits).map_err(output_refusal)?;",
                "            uaos_json::parse(&output, &Limits::DEFAULT).map_err(output_refusal)?;",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--test", "redact", "the_reparse_uses_the_tapes_limits"],
            },
            expect: "depth_exceeded",
        },
        // A placeholder longer than its secret pushes the output past the caller's limits, and the
        // next reader would refuse what redaction let through.
        Case {
            id: "redact-output-outgrows-limits",
            gate: "redaction-corpus",
            tool: None,
            // Removes both size checks. The exact check after the loop is what blocks; the one
            // inside the loop only stops the build early.
            seed: both(
                replace(
                    "crates/uaos-redact/src/redactor.rs",
                    "                if buf.len() > max_bytes {\n                    return Err(RedactError::TooLarge(\"redaction-output-too-large\"));\n                }\n            }\n        }",
                    "            }\n        }",
                ),
                replace(
                    "crates/uaos-redact/src/redactor.rs",
                    "                if buf.len() > max_bytes {\n                    return Err(RedactError::TooLarge(\"redaction-output-too-large\"));\n                }\n                Cow::Owned(buf)",
                    "                Cow::Owned(buf)",
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--test", "redact", "an_output_that_outgrows_the_limits_blocks"],
            },
            expect: "unwrap_err",
        },
        // The re-parse after a key edit calls a limit refusal malformed.
        Case {
            id: "redact-reparse-limit-called-malformed",
            gate: "redaction-corpus",
            tool: None,
            seed: replace(
                "crates/uaos-redact/src/redactor.rs",
                "            RedactError::TooLarge(error.kind().code())\n        }\n        ErrorKind::OutOfMemory => RedactError::DetectorFailure(error.kind().code()),",
                "            RedactError::Malformed(error.kind().code())\n        }\n        ErrorKind::OutOfMemory => RedactError::DetectorFailure(error.kind().code()),",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--test", "redact", "a_key_that_outgrows_the_key_limit_blocks"],
            },
            expect: "TooLarge(\"key_too_long\")",
        },
        Case {
            // The schedule flushes late: a quiet journal holds an acknowledged record past W (P1).
            id: "coordinator-waits-for-next-append",
            gate: "journal-durability",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "            && now >= deadline\n",
                "            && now >= deadline.saturating_mul(2)\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "a_quiet_journal_flushes_within_the_window"],
            },
            expect: "a deadline is still pending after the flush",
        },
        Case {
            // Every append is flushed on its own: no group commit (P2).
            id: "coordinator-flushes-per-append",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "        let appended = match self.journal.append(draft) {",
                "        let appended = match self.journal.append(draft).and_then(|appended| self.journal.sync().map(|()| appended)) {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "a_burst_shares_one_flush"],
            },
            expect: "the burst was flushed per append, not shared",
        },
        Case {
            // A full queue refuses instead of making the caller wait (P10).
            id: "state-queue-drops-on-full",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "self.commands.send(command).await.map_err(|_| StateError::Closed)",
                "self.commands.try_send(command).map_err(|_| StateError::Closed)",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "a_full_queue_applies_backpressure"],
            },
            expect: "on an `Err` value: Closed",
        },
        // A refused start drops the actor's timer on the caller's thread, a runtime worker, and
        // dropping a runtime there panics.
        Case {
            id: "state-actor-timer-dropped-on-caller",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "            runtime.shutdown_background();",
                "            drop(runtime);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "a_refused_start_hands_the_journal_back"],
            },
            expect: "Cannot drop a runtime",
        },
        // Every append restarts the deadline, so a record acknowledged at 0 waits for a later one's
        // deadline.
        Case {
            id: "journal-deadline-follows-newest",
            gate: "journal-durability",
            tool: None,
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "            self.unflushed_since_mono = self.clock.mono().0;\n        }\n        self.unflushed.push(line);",
                "        }\n        self.unflushed_since_mono = self.clock.mono().0;\n        self.unflushed.push(line);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "journal", "the_flush_deadline_follows_the_oldest_unflushed_record"],
            },
            expect: "a later append moved the deadline",
        },
        // The actor waits for the next command and never on its timer, so a quiet journal stays
        // unflushed.
        Case {
            id: "coordinator-ignores-its-timer",
            gate: "journal-durability",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "                    Some(wait) => tokio::time::sleep(wait).await,",
                "                    Some(_) => std::future::pending::<()>().await,",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "the_actor_flushes_a_quiet_journal_on_its_own"],
            },
            expect: "the actor did not flush a quiet journal on its own",
        },
        // The last flush's failure is swallowed.
        Case {
            id: "state-final-flush-unreported",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "        final_flush: core.sync(),",
                "        final_flush: core.sync().or(Ok(())),",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "the_final_flush_is_reported"],
            },
            expect: "the final flush's failure was not reported",
        },
        // The actor serves what it drained last-in first-out.
        Case {
            id: "state-queue-reorders-waiting-callers",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "        while let Ok(command) = queue.commands.try_recv() {\n            let _next_deadline = core.tick();",
                "        let mut drained = Vec::new();\n        while let Ok(command) = queue.commands.try_recv() {\n            drained.push(command);\n        }\n        for command in drained.into_iter().rev() {\n            let _next_deadline = core.tick();",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "waiting_callers_are_served_in_arrival_order"],
            },
            expect: "callers were served out of arrival order",
        },
        // The coordinator's delay is what §4 states as P1's measured delay; a stat that always
        // reads zero would state nothing.
        Case {
            id: "state-flush-delay-unmeasured",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "            let delay = now.saturating_sub(deadline.max(self.retry_at));",
                "            let delay = now.saturating_sub(now);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "stats_measure_the_flush_delay_and_carry_the_health"],
            },
            expect: "the delay is not deadline to flush",
        },
        // An actor whose thread unwinds leaves the kernel admitting.
        Case {
            id: "actor-end-leaves-kernel-running",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "            let _engaged = stop.engage(StopReason::JournalFailed, by);",
                "            let _ignored = (stop, by);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--lib", "an_actor_that_unwinds_engages_the_stop"],
            },
            expect: "an actor that unwound left the kernel admitting",
        },
        // Tries are rationed by time, never by traffic.
        Case {
            id: "stop-retry-ignores-pause",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "        if self.clock.mono().0 < self.stop_retry_at {\n            return match (now, &self.stop_error) {",
                "        if !now && self.clock.mono().0 < self.stop_retry_at {\n            return match (now, &self.stop_error) {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "appends_inside_the_pause_try_nothing"],
            },
            expect: "an append inside the pause tried the stop record again",
        },
        // The pause doubles.
        Case {
            id: "stop-backoff-never-doubles",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "        self.stop_backoff = self.stop_backoff.saturating_mul(2).min(STOP_RETRY_MAX);",
                "        self.stop_backoff = self.stop_backoff.min(STOP_RETRY_MAX);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "the_stop_records_pause_doubles_to_five_seconds"],
            },
            expect: "the stop record's pauses are not 10 ms doubling to 5 s",
        },
        // The pause stops at 5 s.
        Case {
            id: "stop-backoff-uncapped",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "        self.stop_backoff = self.stop_backoff.saturating_mul(2).min(STOP_RETRY_MAX);",
                "        self.stop_backoff = self.stop_backoff.saturating_mul(2);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "the_stop_records_pause_doubles_to_five_seconds"],
            },
            expect: "the stop record's pauses are not 10 ms doubling to 5 s",
        },
        // The records before a failing stop record are flushed anyway.
        Case {
            id: "stop-failure-skips-earlier-flush",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "            let _flushed = self.journal.sync();\n",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "a_failing_stop_record_still_flushes_what_came_before"],
            },
            expect: "a failing stop record kept the records before it from being flushed",
        },
        // A stop record whose flush failed is flushed, not appended again.
        Case {
            id: "stop-record-appended-twice",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "        if pending.is_none() {",
                "        if pending.is_none() || pending.is_some() {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "a_stop_record_is_journaled_once"],
            },
            expect: "one engagement was journaled twice",
        },
        // A failing clock or random source engages the stop.
        Case {
            id: "stop-ignores-platform-failure",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "matches!(error, JournalError::Platform(_)).then_some(StopReason::JournalFailed)",
                "matches!(error, JournalError::Platform(_)).then_some(StopReason::JournalFailed).filter(|_| false)",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "a_platform_failure_engages_the_stop"],
            },
            expect: "a kernel that could not journal kept admitting",
        },
        // A failed sync engages the stop.
        Case {
            id: "sync-failure-keeps-admitting",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "        if let Err(error) = self.journal.sync() {\n            self.engage_for_failure(&error);\n",
                "        if let Err(error) = self.journal.sync() {\n            let _ignored = &error;\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "journal_failures_engage_the_stop"],
            },
            expect: "a failed sync kept the kernel admitting",
        },
        // The actor's schedule retries a failed stop record with no command.
        Case {
            id: "tick-skips-stop-retry",
            gate: "journal-durability",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "        let stop = self.stop_pending().then_some(self.stop_retry_at);\n",
                "        let stop = self.stop_pending().then_some(self.stop_retry_at).filter(|_| false);\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "a_failed_stop_record_lands_on_its_own_once_space_returns"],
            },
            expect: "a failed stop record did not land on its own once space returned",
        },
        // The stop record's flush counts toward P1.
        Case {
            id: "state-flush-age-misses-stop-flush",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "        self.stop_appended = None;\n        if let Some((since, now)) = waiting {\n            self.note_flush_age(now.saturating_sub(since));\n        }\n",
                "        self.stop_appended = None;\n        let _unmeasured = waiting;\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "the_stop_records_flush_is_measured"],
            },
            expect: "the stop record's flush was not measured",
        },
        // P5's mechanism, proven before resume exists.
        Case {
            id: "stop-generation-ignored",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/stop.rs",
                "        if generation == engagement.generation {\n            engagement.recorded = generation;\n        }\n",
                "        let _any = generation;\n        engagement.recorded = engagement.generation;\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "stop", "a_stale_generation_does_not_mark_the_stop_recorded"],
            },
            expect: "another generation's record marked this engagement recorded",
        },
        // The record carries the generation.
        Case {
            id: "stop-record-drops-generation",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/stop.rs",
                "                \"generation\": self.generation.to_string(),\n",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "the_stop_record_goes_first"],
            },
            expect: "the stop record lost its reason or its generation",
        },
        // The record carries who engaged the stop.
        Case {
            id: "stop-record-drops-engager",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/stop.rs",
                "        let (actor, correlation_id, config_version) = (by.actor, by.correlation_id, by.config_version);",
                "        let (actor, correlation_id, config_version) = (by.actor, CorrelationId::from_parts(0, [0; 10]), ConfigVersion(0));",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "the_stop_record_goes_first"],
            },
            expect: "the stop record lost who engaged it",
        },
        // The relay engages as the EngagedBy it was given.
        Case {
            id: "relay-engages-as-someone-else",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/relay.rs",
                "            let _engaged = self.stop.engage(StopReason::BudgetOverrun, self.engaged_by.clone());",
                "            let _engaged = self.stop.engage(StopReason::BudgetOverrun, EngagedBy { actor: uaos_contracts::event::Actor::Human, ..self.engaged_by.clone() });",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "an_overrun_stops_the_kernel"],
            },
            expect: "the overrun engaged the stop as someone else",
        },
        // Only a shutdown the previous run's marker proves durable is clean.
        Case {
            id: "shutdown-unflushed-read-as-clean",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/boot.rs",
                "&& evidence.sealed == Some(last.envelope.seq) =>",
                "&& evidence.sealed.is_none_or(|_| true) =>",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "startup", "a_shutdown_that_failed_to_flush_is_a_crash"],
            },
            expect: "a shutdown that failed to flush was read as clean",
        },
        // The shutdown seals its record.
        Case {
            id: "shutdown-not-sealed",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "        if let Err(error) = self.journal.seal() {",
                "        if let Err(error) = self.journal.sync() {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "startup", "a_clean_shutdown_boots_running"],
            },
            expect: "a durable shutdown was not read as clean",
        },
        // The open's own records follow the previous run's end and do not decide it.
        Case {
            id: "opens-own-records-decide-the-end",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/boot.rs",
                "        .take_while(|r| evidence.own_from.is_none_or(|own| r.envelope.seq < own));",
                "        .take_while(|_| true);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "only_a_proven_shutdown_is_clean_and_the_opens_own_records_do_not_count"],
            },
            expect: "the open's own record after a durable shutdown made the end a crash",
        },
        // Admission re-checks draining under the lock drain takes.
        Case {
            id: "drain-race-admits-past-the-count",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/admission.rs",
                "        // Again under the lock `drain` takes: an Operation is either counted before the shutdown\n        // reads `in_flight`, or refused.\n        if let Some(refusal) = self.inner.draining() {\n            return Err(refusal);\n        }\n",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-runtime",
                    "--lib",
                    "admission::tests::an_operation_checked_before_the_drain_is_refused_after_the_count",
                ],
            },
            expect: "an Operation was admitted after the shutdown counted none open",
        },
        // A stop record written by an append that then failed its own flush is not appended again.
        Case {
            id: "stop-inline-flush-failure-forgotten",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "                    if self.journal.next_seq() > before {",
                "                    if self.journal.next_seq() > before && before.0 == u64::MAX {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "a_stop_record_whose_inline_flush_failed_is_journaled_once"],
            },
            expect: "an engagement whose inline flush failed was journaled twice",
        },
        // A writer that ends by itself is not counted as a kill.
        Case {
            id: "kill-writer-exit-unseen",
            gate: "journal-durability",
            tool: None,
            seed: replace(
                "crates/uaos-testkit/src/bin/journal-crash-writer.rs",
                "        next = Seq(next.0 + 1);\n",
                "        next = Seq(next.0 + 1);\n        if n == 3 {\n            return Err(\"seeded: the writer stops by itself\".to_owned());\n        }\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-testkit", "--test", "kill"],
            },
            expect: "exited on its own",
        },
        // No open writes a seal; the marker an open moves proves nothing.
        Case {
            id: "open-writes-the-seal",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        self.update_marker(true).map_err(storage)?;\n        Ok(())\n",
                "        self.update_marker(true).map_err(storage)?;\n        if let Some((seq, hash)) = self.last_flushed {\n            let _ = self.fs.write_atomic(&self.dir.join(SEAL_FILE), format!(\"{SEAL_PREFIX} {seq} {hash}\\n\").as_bytes());\n        }\n        Ok(())\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "startup", "an_intervening_open_does_not_prove_a_failed_shutdown"],
            },
            expect: "an open after a failed shutdown made it read as clean",
        },
        // The seal goes before anything can run, so a later run's lost records do not read as
        // the clean end before it.
        Case {
            id: "seal-kept-after-boot",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/startup.rs",
                "    journal.unseal().map_err(StartupError::Unseal)?;\n",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "startup", "a_run_whose_records_were_lost_is_not_read_as_clean"],
            },
            expect: "a run whose records were lost read as the clean end before it",
        },
        // A failed seal write is removed again.
        Case {
            id: "seal-failure-left-behind",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "            let _removed_or_never_written = self.unseal();\n",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "journal", "a_seal_whose_write_failed_is_removed"],
            },
            expect: "a seal whose write failed was left behind",
        },
        // The seal must name its record's hash, not only its sequence number.
        Case {
            id: "seal-hash-unchecked",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        .any(|r| r.hash == hash && r.envelope.seq.0 == seq)\n",
                "        .any(|r| (r.hash == hash || !hash.to_string().is_empty()) && r.envelope.seq.0 == seq)\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "journal", "only_a_seal_naming_a_record_with_its_hash_counts"],
            },
            expect: "a seal naming another hash was trusted",
        },
        // A start cut at every change reads no false clean end; without the seal's removal, a run
        // whose records were lost does.
        Case {
            id: "start-cut-keeps-the-seal",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/startup.rs",
                "    journal.unseal().map_err(StartupError::Unseal)?;\n",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "startup", "a_start_cut_anywhere_never_reads_a_false_clean_end"],
            },
            expect: "read the wrong end",
        },
        // The seal does not wait for the marker.
        Case {
            id: "seal-waits-for-the-marker",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        let _held_back_is_harmless = self.update_marker(true);\n        Ok(Seq(seq))\n",
                "        let _held_back_is_harmless = self.update_marker(true);\n        if self.payloads.as_ref().is_some_and(|store| store.is_poisoned()) {\n            return Err(JournalError::Stopped);\n        }\n        Ok(Seq(seq))\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "a_seal_lands_while_the_marker_is_held_back"],
            },
            expect: "a held-back marker kept the seal from landing",
        },
        // A clean shutdown is not the stop; the next boot runs.
        Case {
            id: "shutdown-persists-as-stopped",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/stop.rs",
                "        if record.event_type == types::KERNEL_STOPPED {\n",
                "        if record.event_type == types::KERNEL_STOPPED || record.event_type == types::KERNEL_SHUTDOWN {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "startup", "a_clean_shutdown_boots_running"],
            },
            expect: "a clean shutdown booted stopped",
        },
        // P7: the record is written after admission closed and the Operations in flight ended, not
        // before.
        Case {
            id: "shutdown-record-before-drain",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "    admission.drain();\n    let _waited = tokio::time::timeout(deadline, async {\n        while admission.in_flight().0 > 0 {\n            tokio::time::sleep(Duration::from_millis(10)).await;\n        }\n    })\n    .await;\n    let open = admission.in_flight().0;\n    state.shutdown(ShutdownReason::new(by, open)).await\n",
                "    let report = state.shutdown(ShutdownReason::new(by, admission.in_flight().0)).await;\n    admission.drain();\n    let _waited = tokio::time::timeout(deadline, async {\n        while admission.in_flight().0 > 0 {\n            tokio::time::sleep(Duration::from_millis(10)).await;\n        }\n    })\n    .await;\n    report\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "startup", "a_clean_shutdown_boots_running"],
            },
            expect: "the shutdown record went ahead of an Operation still running",
        },
        // P7: a journal older than shutdown records is "unknown"; its missing shutdown is no
        // evidence of a crash.
        Case {
            id: "missing-shutdown-trusted-on-old-journal",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/boot.rs",
                "    if !capable {\n        return (LastEnd::Unknown, false);\n",
                "    if !capable {\n        return (LastEnd::Crashed, false);\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "startup", "an_old_journal_is_unknown"],
            },
            expect: "a missing shutdown on an old journal was trusted as evidence",
        },
        // P7: only a journal that ends with the shutdown is clean; a record after it is a boot that
        // ended before its own record.
        Case {
            id: "shutdown-clean-despite-later-records",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/boot.rs",
                "    match previous.skip(after).last() {\n",
                "    match previous.skip(after).find(|r| r.envelope.event_type == types::KERNEL_SHUTDOWN) {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "startup", "a_crash_after_a_shutdown_capable_boot_is_evidence"],
            },
            expect: "a shutdown followed by an interrupted boot was read as clean",
        },
        // P7: work still open at the shutdown ran past its record, so a stop engaged then may be
        // lost.
        Case {
            id: "open-work-at-shutdown-read-as-clean",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/boot.rs",
                "            LastEnd::Clean => open_at_shutdown,\n",
                "            LastEnd::Clean => false,\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "startup", "work_left_open_at_the_deadline_is_counted"],
            },
            expect: "work that ran past the shutdown record was read as a clean end",
        },
        // P8: boot reads the records the open verified, not the journal again.
        Case {
            id: "boot-reads-journal-twice",
            gate: "test",
            tool: None,
            seed: both(
                replace(
                    "crates/uaos-runtime/src/startup.rs",
                    "    let Opened {\n        mut journal,\n        records,\n",
                    "    let reader = Arc::clone(&fs);\n    let Opened {\n        mut journal,\n        records: _verified,\n",
                ),
                replace(
                    "crates/uaos-runtime/src/startup.rs",
                    "    let Booted { stop, ledger, report } =\n",
                    "    let records = uaos_state::journal::read_verified(reader.as_ref(), &data_dir.join(uaos_state::journal::JOURNAL_DIR)).map_err(StartupError::Open)?.0;\n    let Booted { stop, ledger, report } =\n",
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "startup", "startup_reads_the_journal_once"],
            },
            expect: "startup read the journal again after its open",
        },
        // A record queued after an engaged stop goes ahead of the stop's.
        Case {
            id: "stop-record-queued-behind-others",
            gate: "journal-durability",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "        self.record_stop(true)?;\n        // The journal flushes inside an append",
                "        // The journal flushes inside an append",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "the_stop_record_goes_first"],
            },
            expect: "the stop record did not go first",
        },
        // A stop whose record failed is taken for recorded, so it is never tried again.
        Case {
            id: "stop-record-dropped-on-failure",
            gate: "journal-durability",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "                self.stats.stop_record_retries += 1;\n",
                "                self.stats.stop_record_retries += 1;\n                if let Some((stop, _)) = &self.stop {\n                    stop.recorded(engaged.generation());\n                }\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "a_full_disk_keeps_the_stop_and_retries"],
            },
            expect: "a stop whose record failed was taken for recorded",
        },
        // The stop is marked recorded before its record is written.
        Case {
            id: "stop-marked-recorded-before-append",
            gate: "journal-durability",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "        let draft = engaged.draft().map_err(|_| StateError::StopRecord)?;\n",
                "        if let Some((stop, _)) = &self.stop {\n            stop.recorded(engaged.generation());\n        }\n        let draft = engaged.draft().map_err(|_| StateError::StopRecord)?;\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "a_full_disk_keeps_the_stop_and_retries"],
            },
            expect: "a stop whose record failed was taken for recorded",
        },
        // A failing journal does not engage the stop, so admission goes on.
        Case {
            id: "journal-failure-keeps-admitting",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "            let _engaged = stop.engage(reason, by.clone());",
                "            let _ignored = (stop, reason, by);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "journal_failures_engage_the_stop"],
            },
            expect: "a failing journal kept admitting",
        },
        // The actor does not wake on an engagement, so with no command a stop's record waits for
        // the next one.
        Case {
            id: "state-actor-ignores-stop",
            gate: "journal-durability",
            tool: None,
            seed: replace("crates/uaos-runtime/src/state.rs", "                () = stopped => Wake::Stop,\n", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "the_actor_records_a_stop_on_its_own"],
            },
            expect: "the actor did not record a stop on its own",
        },
        // P1 under power loss: the actor flushes 10 ms after the deadline, so a power loss in
        // between takes records the bound promised to keep.
        Case {
            id: "coordinator-flushes-late-under-power-loss",
            gate: "journal-durability",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "            && now >= deadline\n",
                "            && now >= deadline.saturating_add(10_000_000)\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "acknowledged_records_survive_a_power_loss_past_the_window"],
            },
            expect: "before the power loss was lost",
        },
        // P1 measured directly misses the flushes the journal runs inside an append, which under
        // load are nearly all of them.
        Case {
            id: "state-flush-age-misses-inline-flush",
            gate: "journal-durability",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "            self.note_flush_age(now.saturating_sub(since));\n        }\n        Ok(appended)",
                "        }\n        Ok(appended)",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "stats_measure_the_oldest_record_at_each_flush"],
            },
            expect: "a flush inside an append was not measured",
        },
        // The stats never report the queue depth.
        Case {
            id: "state-queue-depth-unreported",
            gate: "test",
            tool: None,
            seed: replace("crates/uaos-runtime/src/state.rs", "                stats.queued = queued;\n", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "stats_count_the_commands_still_queued"],
            },
            expect: "the stats do not count the commands behind them",
        },
        // A retry's delay is counted from the original deadline.
        Case {
            id: "state-retry-delay-from-deadline",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "            let delay = now.saturating_sub(deadline.max(self.retry_at));",
                "            let delay = now.saturating_sub(deadline);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "stats_measure_the_flush_delay_and_carry_the_health"],
            },
            expect: "a retry's delay is not counted from its retry time",
        },
        // The drain serves every queued command before the schedule runs again, so a due flush
        // waits behind all of them.
        Case {
            id: "state-drain-skips-schedule",
            gate: "journal-durability",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/state.rs",
                "            let _next_deadline = core.tick();\n            if !core.handle(command, queue.commands.len()) {",
                "            if !core.handle(command, queue.commands.len()) {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "a_due_flush_waits_at_most_one_command"],
            },
            expect: "the drain held a due flush back",
        },
        // A thread the operating system refuses is not counted.
        Case {
            id: "supervisor-os-refusal-uncounted",
            gate: "test",
            tool: Some(LINUX_ONLY),
            seed: replace(
                "crates/uaos-runtime/src/supervisor.rs",
                "            self.inner.refused.fetch_add(1, Ordering::Relaxed);\n            SpawnError::Thread",
                "            SpawnError::Thread",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "state", "an_os_refusal_is_counted"],
            },
            expect: "an OS refusal was not counted",
        },
        // The claims lint reads every text file, this one included, so each seed builds its
        // forbidden term from parts at run time.
        Case {
            id: "claims-forbidden-word",
            gate: "claims-lint",
            tool: None,
            seed: append_owned("README.md", format!("\nThe journal is {}-proof.\n", "tamper")),
            runner: Runner::Xtask(&["claims"]),
            expect: "used as a claim",
        },
        Case {
            id: "claims-forbidden-word-txt",
            gate: "claims-lint",
            tool: None,
            // Plain text, outside docs/ and the top level.
            seed: write(
                "crates/uaos-contracts/NOTES.txt",
                format!("Moving to a new window happens with zero data {}.\n", "loss"),
            ),
            runner: Runner::Xtask(&["claims"]),
            expect: "crates/uaos-contracts/NOTES.txt:1:",
        },
        Case {
            id: "claims-forbidden-word-code-comment",
            gate: "claims-lint",
            tool: None,
            // A claim in a Rust comment is still a public claim.
            seed: append_owned(LIB, format!("\n// The ledger is {}.\n", ["bullet", "proof"].concat())),
            runner: Runner::Xtask(&["claims"]),
            expect: "crates/uaos-contracts/src/limits.rs:",
        },
        Case {
            id: "claims-forbidden-word-string-literal",
            gate: "claims-lint",
            tool: None,
            // A string literal is shown to users (help text, errors): a claim, not a mention.
            seed: append_owned(
                LIB,
                format!("\npub const SEEDED_TAGLINE: &str = \"A {} proxy\";\n", ["flaw", "less"].concat()),
            ),
            runner: Runner::Xtask(&["claims"]),
            expect: "crates/uaos-contracts/src/limits.rs:",
        },
        Case {
            id: "claims-nul-undeclared",
            gate: "claims-lint",
            tool: None,
            // UTF-16 text holds NUL bytes; only extensions declared binary are skipped.
            seed: Box::new(|ws| {
                std::fs::write(ws.join("docs").join("utf16.txt"), b"\xff\xfeo\x00k\x00\n\x00")
                    .map_err(|e| format!("docs/utf16.txt: {e}"))
            }),
            runner: Runner::Xtask(&["claims"]),
            expect: "docs/utf16.txt: holds a NUL byte",
        },
        Case {
            id: "claims-declared-binary-text",
            gate: "claims-lint",
            tool: None,
            // A `binary` declaration cannot take text out of the scan.
            seed: both(
                append(".gitattributes", "*.md binary\n"),
                append_owned("README.md", format!("\nThe journal is {}-proof.\n", "tamper")),
            ),
            runner: Runner::Xtask(&["claims"]),
            expect: "README.md:",
        },
        Case {
            id: "claims-unreadable-text",
            gate: "claims-lint",
            tool: None,
            // Latin-1 text: not binary, not UTF-8. The lint cannot read it, so it fails closed.
            seed: Box::new(|ws| {
                std::fs::write(ws.join("docs").join("latin1.txt"), b"caf\xe9 au lait\n")
                    .map_err(|e| format!("docs/latin1.txt: {e}"))
            }),
            runner: Runner::Xtask(&["claims"]),
            expect: "latin1.txt: not UTF-8",
        },
        Case {
            id: "identity-epoch-check-skipped",
            gate: "test",
            tool: None,
            // Verification that ignores an ancestor's epoch bump.
            seed: replace(
                "crates/uaos-identity/src/state.rs",
                "if node.record.parent_epoch != parent.epoch {",
                "if node.record.parent_epoch != parent.epoch && node.revoked {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-identity", "--test", "identity", "derivations_match_the_model"],
            },
            expect: "verification disagrees with the model",
        },
        Case {
            id: "contract-without-changelog",
            gate: "docs-contract-sync",
            tool: Some("git"),
            seed: Box::new(|_| Ok(())),
            runner: Runner::History(crate::docs_sync::check, docs_sync_history),
            expect: "CHANGELOG",
        },
        Case {
            id: "module-unknown-feature-loaded",
            gate: "test",
            tool: None,
            // Contract §3: admission compares every required feature with the kernel's offer.
            seed: replace("crates/uaos-module-api/src/manifest.rs", "match manifest.requires().iter().find(|f| !self.features.contains(f)) {", "match manifest.requires().iter().find(|_| false) {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "admission_compares_every_required_feature"],
            },
            expect: "a missing feature was admitted",
        },
        Case {
            id: "module-act-at-observe-point",
            gate: "test",
            tool: None,
            // Contract §2 rule 7: an acting hook at a point that only observes is refused at load.
            seed: replace("crates/uaos-module-api/src/manifest.rs", "if hook.mode == HookMode::Act && !hook.point.acts() {", "if false && hook.mode == HookMode::Act && !hook.point.acts() {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "a_manifest_is_refused_whole_for_each_reason"],
            },
            expect: "was not refused",
        },
        Case {
            id: "module-state-unbounded",
            gate: "test",
            tool: None,
            // Contract §5: module state never grows past its bound.
            seed: replace("crates/uaos-module-api/src/state.rs", "if u32::try_from(wanted).is_ok_and(|n| n <= self.limit) {", "if u32::try_from(wanted).is_ok() {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "state_is_bounded_and_unchanged_on_refusal"],
            },
            expect: "state grew past its bound",
        },
        Case {
            id: "module-state-call-kept",
            gate: "test",
            tool: None,
            // Contract §5: a call that outgrew its state is struck whole, not kept in part.
            seed: replace("crates/uaos-module-api/src/state.rs", "self.exceeded = true;", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "a_call_that_outgrows_its_state_is_struck_whole"],
            },
            expect: "an outgrown call was kept",
        },
        Case {
            id: "module-decls-at-unhooked-point",
            gate: "test",
            tool: None,
            // A point the manifest does not hook takes no declaration.
            seed: replace("crates/uaos-module-api/src/decl.rs", "Some(p) => manifest.hook(p).ok_or(Strike::NotHooked)?.mode() == HookMode::Observe,", "Some(p) => manifest.hook(p).is_none_or(|h| h.mode() == HookMode::Observe),"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "nothing_is_declared_at_a_point_the_module_did_not_hook"],
            },
            expect: "declarations accepted at an unhooked point",
        },
        Case {
            id: "module-event-value-undeclared",
            gate: "test",
            tool: None,
            // A module event carries only the value names its manifest declares.
            seed: replace("crates/uaos-module-api/src/decl.rs", "declared.fields.contains(name)", "declared.fields.contains(name) || name.as_str().is_ascii()"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "an_event_carries_only_declared_value_names"],
            },
            expect: "an undeclared value name was emitted",
        },
        Case {
            id: "module-text-accepts-bidi-override",
            gate: "language-neutrality",
            tool: None,
            // Module text refuses explicit bidirectional controls.
            seed: replace("crates/uaos-module-api/src/decl.rs", "if text.chars().any(is_explicit_bidi) {", "if text.chars().any(|_| false) {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "language_neutrality", "module_text_refuses_explicit_bidi_controls"],
            },
            expect: "explicit bidi accepted",
        },
        Case {
            id: "view-masked-key-readable",
            gate: "test",
            tool: None,
            // A key detection flagged reads as masked.
            seed: replace("crates/uaos-module-api/src/view.rs", "let masked = self.key_masked();", "let masked = false;"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "masked_keys_and_numbers_read_as_masked"],
            },
            expect: "a masked key was readable",
        },
        Case {
            id: "view-masked-key-found-by-name",
            gate: "test",
            tool: None,
            // A member whose key is masked is never found by name.
            seed: replace("crates/uaos-module-api/src/view.rs", ".filter(|n| !self.wrap(*n).key_masked())", ".filter(|_| true)"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "masked_keys_and_numbers_read_as_masked"],
            },
            expect: "a masked key was found by name",
        },
        Case {
            id: "selector-predicate-unbounded",
            gate: "test",
            tool: None,
            // A predicate lists a bounded number of values.
            seed: replace("crates/uaos-module-api/src/selector.rs", "if values.len() > MAX_PREDICATE_VALUES {", "if values.len() > usize::MAX - 1 {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_selector_is_bounded"],
            },
            expect: "an unbounded predicate was accepted",
        },
        Case {
            id: "selector-folds-case",
            gate: "language-neutrality",
            tool: None,
            // Selectors compare bytes and never fold case.
            seed: replace("crates/uaos-module-api/src/selector.rs", "Some(ViewText::Plain(text)) => Ok(values.contains(text.as_ref())),", "Some(ViewText::Plain(text)) => Ok(values.iter().any(|v| v.to_lowercase() == text.to_lowercase())),"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "language_neutrality", "selectors_never_fold_case"],
            },
            expect: "folded case",
        },
        Case {
            id: "path-pattern-crosses-segment",
            gate: "test",
            tool: None,
            // A prefix pattern matches by whole segments.
            seed: replace("crates/uaos-module-api/src/codec.rs", ".is_some_and(|rest| rest.is_empty() || prefix.ends_with('/') || rest.starts_with('/')),", ".is_some(),"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "path_patterns_match_canonical_paths_by_segment"],
            },
            expect: "matched a pattern it should not",
        },
        Case {
            id: "path-not-canonical",
            gate: "test",
            tool: None,
            // A path that is not canonical never matches.
            seed: replace(
                "crates/uaos-module-api/src/codec.rs",
                "if !canonical(path) {\n            return false;",
                "if false && !canonical(path) {\n            return false;",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "path_patterns_match_canonical_paths_by_segment"],
            },
            expect: "matched a pattern it should not",
        },
        Case {
            id: "agent-id-serialized-when-absent",
            gate: "test",
            tool: None,
            // Contract §8: an envelope without an agent keeps its exact bytes (the journal hashes them).
            seed: replace("crates/uaos-contracts/src/event.rs", "#[serde(default, skip_serializing_if = \"Option::is_none\")]\n    pub agent_id: Option<AgentId>,", "#[serde(default)]\n    pub agent_id: Option<AgentId>,"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-contracts", "--lib", "an_absent_agent_id_is_not_written"],
            },
            expect: "an absent agent_id was written",
        },
        Case {
            id: "endpoint-unmatched-not-denied",
            gate: "test",
            tool: None,
            // A path no endpoint matches is denied, never forwarded.
            seed: replace("crates/uaos-module-api/src/codec.rs", ".unwrap_or(EndpointClass::Denied)", ".unwrap_or(EndpointClass::Metadata)"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "an_endpoint_s_class_is_the_strictest_match_and_unknown_paths_are_denied"],
            },
            expect: "an endpoint got a weaker class",
        },
        Case {
            id: "module-rank-empty-accepted",
            gate: "test",
            tool: None,
            // An empty ranking is a strike, not a silent veto.
            seed: replace("crates/uaos-module-api/src/decl.rs", "if ranked.is_empty() || ranked.len() > MAX_RANK", "if ranked.len() > MAX_RANK"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "an_empty_ranking_is_a_strike"],
            },
            expect: "an empty ranking vetoed the route without a reason",
        },
        Case {
            id: "view-masked-container-leaks",
            gate: "test",
            tool: None,
            // Masking a container masks everything inside it.
            seed: replace("crates/uaos-module-api/src/view.rs", "self.node.ancestors().any(|a| self.mask.masks_value(a.id()))", "self.node.ancestors().any(|_| false)"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_masked_container_masks_everything_inside"],
            },
            expect: "inside a masked container was",
        },
        Case {
            id: "role-check-ancestors-only",
            gate: "test",
            tool: None,
            // An edit's role check covers the node's whole subtree, not only its ancestors.
            seed: replace("crates/uaos-module-api/src/codec.rs", "for (_, inside) in self.roles.range(id..node.subtree_end()) {", "for (_, inside) in self.roles.range(id..id) {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_strip_never_encloses_a_forbidden_role"],
            },
            expect: "an edit's roles missed its subtree",
        },
        Case {
            id: "replay-declares-again",
            gate: "test",
            tool: None,
            // An event delivered by a replay is marked, so its declarations are discarded.
            seed: replace("crates/uaos-module-api/src/module.rs", "self.replay = true;", "self.replay = false;"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "a_replay_rebuilds_state_and_declares_nothing"],
            },
            expect: "a replay requested a child Operation again",
        },
        Case {
            id: "module-text-accepts-tag",
            gate: "language-neutrality",
            tool: None,
            // Module text refuses Unicode tag characters.
            seed: replace("crates/uaos-module-api/src/decl.rs", "if text.chars().any(is_tag) {", "if text.chars().any(|_| false) {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "language_neutrality", "module_text_takes_crlf_and_refuses_tag_characters"],
            },
            expect: "a tag character was accepted",
        },
        Case {
            id: "path-parameter-canonical",
            gate: "test",
            tool: None,
            // A path parameter (`;`) is not canonical.
            seed: replace("crates/uaos-module-api/src/codec.rs", "['?', '#', '%', ';', '\\\\']", "['?', '#', '%', '\\\\']"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "path_patterns_match_canonical_paths_by_segment"],
            },
            expect: "matched a pattern it should not",
        },
        Case {
            id: "module-cancel-without-feature",
            gate: "test",
            tool: None,
            // Cancelling a child Operation needs child_operations.
            seed: replace("crates/uaos-module-api/src/decl.rs", "Decl::CancelOp(_) if !manifest.requires().contains(&KernelFeature::ChildOperations) => {", "Decl::CancelOp(_) if false => {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "cancelling_a_child_needs_child_operations"],
            },
            expect: "a cancellation was accepted without child_operations",
        },
        Case {
            id: "chunk-lost-drops-agent",
            gate: "test",
            tool: None,
            // Contract §8: a chunk.lost record carries the agent of the record it reports.
            seed: replace("crates/uaos-state/src/journal/writer.rs", "agent_id: referencing.agent_id,", "agent_id: None,"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "a_lost_payload_record_names_the_agent_of_the_record_it_reports"],
            },
            expect: "a lost-payload record dropped the agent",
        },
        Case {
            id: "module-manifest-reread",
            gate: "test",
            tool: None,
            // Every call is checked against the manifest admitted, not a later one.
            seed: replace("crates/uaos-module-api/src/module.rs", "    pub const fn manifest(&self) -> &Manifest {\n        &self.manifest\n    }", "    pub fn manifest(&self) -> &Manifest {\n        self.module.manifest()\n    }"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "a_module_is_checked_against_its_admitted_manifest"],
            },
            expect: "a module grew its manifest after admission",
        },
        Case {
            id: "view-sealed-mask-drifts",
            gate: "test",
            tool: None,
            // A sealed mask answers exactly as an unsealed one.
            seed: replace("crates/uaos-module-api/src/view.rs", "covered.push((*id, node.subtree_end()));", "covered.push((*id, *id));"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "sealed_and_unsealed_views_agree"],
            },
            expect: "a sealed view disagreed with an unsealed one",
        },
        Case {
            id: "strip-removes-anchor",
            gate: "test",
            tool: None,
            // A strip removes what is inside its anchor, never the anchor.
            seed: replace("crates/uaos-module-api/src/codec.rs", "            .and_then(|n| n.parent())\n", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_strip_keeps_its_anchor_and_masked_content"],
            },
            expect: "a strip removed its own anchor",
        },
        Case {
            id: "strip-touches-masked",
            gate: "test",
            tool: None,
            // Roles come from the masked view, so a strip never touches masked content.
            seed: replace("crates/uaos-module-api/src/codec.rs", "            && !view.touches_masked(id)\n", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_strip_keeps_its_anchor_and_masked_content"],
            },
            expect: "a strip touched masked content",
        },
        Case {
            id: "selector-unbudgeted",
            gate: "test",
            tool: None,
            // Resolution spends a visit budget and stops when it is spent.
            seed: replace("crates/uaos-module-api/src/selector.rs", "self.0 = self.0.checked_sub(n).ok_or(SelectorError::Budget)?;", "self.0 = self.0.saturating_sub(n);"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_selector_stops_at_its_budget"],
            },
            expect: "a selector ran past its budget",
        },
        Case {
            id: "usage-undeclared-dimension",
            gate: "test",
            tool: None,
            // Usage names only the dimensions its codec declares.
            seed: replace("crates/uaos-module-api/src/codec.rs", "if self.dims.iter().all(|(name, _)| declared.contains(name)) {", "if true || self.dims.iter().all(|(name, _)| declared.contains(name)) {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "usage_reports_name_declared_dimensions_once"],
            },
            expect: "an undeclared billing dimension was accepted",
        },
        Case {
            id: "module-text-accepts-variation-run",
            gate: "language-neutrality",
            tool: None,
            // Runs of variation selectors carry invisible bytes; module text refuses them.
            seed: replace("crates/uaos-module-api/src/decl.rs", "                base = None;\n", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "language_neutrality", "module_text_refuses_variation_runs"],
            },
            expect: "a variation-selector run was accepted",
        },
        Case {
            id: "failure-deny-after-the-fact",
            gate: "test",
            tool: None,
            // A failure after forwarding cannot deny, so `Deny` there is refused at load.
            seed: replace("crates/uaos-module-api/src/manifest.rs", "if hook.on_failure == OnFailure::Deny && !hook.point.denies() {", "if false && hook.on_failure == OnFailure::Deny && !hook.point.denies() {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "a_failure_cannot_deny_after_the_fact"],
            },
            expect: "a failure policy that cannot deny was loaded",
        },
        Case {
            id: "grant-memory-read-off-a-pocket",
            gate: "test",
            tool: None,
            // A memory.read grant is on a pocket, and only memory.read grants are.
            seed: replace("crates/uaos-contracts/src/grant.rs", "if memory_read != source.is_some() {", "if false && memory_read != source.is_some() {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-contracts", "--lib", "memory_reads_and_pockets_go_together"],
            },
            expect: "a memory.read grant off a pocket validated",
        },
        Case {
            id: "cedar-cross-pocket-without-grant",
            gate: "test",
            tool: None,
            // Only a grant, which carries consent, allows a cross-pocket read.
            seed: replace("crates/uaos-policy/src/engine.rs", "if asking.is_empty() && cross_pocket {", "if false && asking.is_empty() && cross_pocket {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-policy", "--test", "policy", "a_permit_alone_only_asks_for_a_cross_pocket_read"],
            },
            expect: "a permit allowed a cross-pocket read without consent",
        },
        Case {
            id: "cedar-own-pocket-read-asks",
            gate: "test",
            tool: None,
            // A read of the requesting pocket follows policy; no consent loop.
            seed: replace("crates/uaos-policy/src/model.rs", "self.action == Action::MemoryRead && self.resource != Resource::Pocket(self.pocket)", "self.action == Action::MemoryRead"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-policy", "--test", "policy", "a_permit_alone_only_asks_for_a_cross_pocket_read"],
            },
            expect: "a read of the own pocket asked for consent",
        },
        Case {
            id: "grant-carried-ignored",
            gate: "test",
            tool: None,
            // Only the grant a request carries can satisfy it.
            seed: replace("crates/uaos-policy/src/engine.rs", "                            && request.grant.is_none_or(|carried| g.id == carried)
", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-policy", "--test", "policy", "only_the_carried_grant_allows_a_cross_pocket_read"],
            },
            expect: "the decision cited a grant the request did not carry",
        },
        Case {
            id: "grant-wire-drops-provider",
            gate: "test",
            tool: None,
            // Every grant goes to the wire and back unchanged. The valid-by-construction property
            // catches it: a fifth of its grants are model grants.
            seed: replace("crates/uaos-policy/src/wire.rs", "provider: wire_name(provider)?,", "provider: wire_name(model)?,"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-policy", "--test", "policy", "every_valid_grant_loads_and_round_trips"],
            },
            expect: "a grant changed through the wire",
        },
        Case {
            id: "grant-unnamed-cross-pocket-allowed",
            gate: "test",
            tool: None,
            // A cross-pocket read that names no grant has none.
            seed: replace("crates/uaos-policy/src/engine.rs", "        if request.crosses_pockets() && request.grant.is_none() {\n            return Ok(Vec::new());\n        }\n", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-policy", "--test", "policy", "only_the_carried_grant_allows_a_cross_pocket_read"],
            },
            expect: "a cross-pocket read naming no grant was allowed",
        },
        Case {
            id: "grant-own-pocket-unjournalable",
            gate: "test",
            tool: None,
            // Only a cross-pocket grant carries an injection policy, so an own-pocket one can be
            // journaled.
            seed: replace("crates/uaos-contracts/src/grant.rs", "let cross_pocket = memory_read && source != Some(self.pocket);", "let cross_pocket = memory_read;"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-contracts", "--lib", "an_own_pocket_read_grant_carries_no_injection_policy"],
            },
            expect: "an own-pocket grant took an injection policy",
        },
        Case {
            id: "engine-loads-unjournalable-grant",
            gate: "test",
            tool: None,
            // The engine loads no grant the wire cannot journal.
            seed: replace("crates/uaos-policy/src/engine.rs", "        check_grant(grant).map_err(|e| PolicyError::Rule {", "        Ok::<(), crate::WireError>(()).map_err(|e| PolicyError::Rule {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-policy", "--test", "policy", "every_engine_grant_round_trips_through_the_wire"],
            },
            expect: "the engine loaded a grant the wire cannot hold",
        },
        Case {
            id: "grant-id-twice-loaded",
            gate: "test",
            tool: None,
            // The engine refuses a grant id twice.
            seed: replace("crates/uaos-policy/src/engine.rs", "        if !ids.insert(grant.id) {\n", "        if !ids.insert(grant.id) && false {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-policy", "--test", "policy", "a_grant_id_twice_is_refused"],
            },
            expect: "a grant id was loaded twice",
        },
        Case {
            id: "grant-principal-ignores-fields",
            gate: "test",
            tool: None,
            // A principal with no fields refuses any field.
            seed: replace("crates/uaos-contracts/src/grant.rs", "    Human {},\n", "    Human,\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-contracts", "--lib", "humans_and_the_kernel_can_hold_grants"],
            },
            expect: "a principal took a field it does not have",
        },
        Case {
            id: "stop-admits-new-op",
            gate: "test",
            tool: None,
            // Admission checks the stop first.
            seed: replace("crates/uaos-runtime/src/admission.rs", "        if let Some(refusal) = self.inner.stopped().or_else(|| self.inner.draining()) {\n", "        if let Some(refusal) = self.inner.draining() {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "stop", "a_stopped_kernel_admits_nothing"],
            },
            expect: "a stopped kernel admitted an Operation",
        },
        Case {
            id: "stop-not-persisted",
            gate: "test",
            tool: None,
            // A journaled stop is honoured at boot.
            seed: replace("crates/uaos-runtime/src/stop.rs", "            state = BootState::Stopped(StopReason::from_code(code));\n", "            let _ignored = code;\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "stop", "a_journaled_stop_survives_a_restart"],
            },
            expect: "a journaled stop did not survive a restart",
        },
        Case {
            id: "admission-counts-requests",
            gate: "test",
            tool: None,
            // Admission counts bytes in flight, not only requests.
            seed: replace("crates/uaos-runtime/src/admission.rs", "            Some(total) if total <= self.inner.limits.max_bytes => {\n                used.operations += 1;\n", "            Some(total) if total <= u64::MAX => {\n                used.operations += 1;\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "stop", "admission_counts_bytes_in_flight"],
            },
            expect: "admission counted requests, not bytes",
        },
        Case {
            id: "relay-forwards-over-ceiling",
            gate: "test",
            tool: None,
            // One nano-USD over the reservation cuts.
            seed: replace("crates/uaos-runtime/src/relay.rs", "        if cost > self.ceiling {\n", "        if cost.get() > self.ceiling.get() + 1 {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "one_nano_usd_over_the_ceiling_is_never_forwarded"],
            },
            expect: "a usage report over the ceiling was forwarded",
        },
        Case {
            id: "relay-overrun-keeps-kernel-running",
            gate: "test",
            tool: None,
            // An overrun engages the kernel stop.
            seed: replace(
                "crates/uaos-runtime/src/relay.rs",
                "            let _engaged = self.stop.engage(StopReason::BudgetOverrun, self.engaged_by.clone());\n",
                "            let _engaged = StopReason::BudgetOverrun;\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "an_overrun_stops_the_kernel"],
            },
            expect: "an overrun left the kernel running",
        },
        Case {
            id: "relay-ignores-stop",
            gate: "test",
            tool: None,
            // A live relay cuts at its next poll.
            seed: replace("crates/uaos-runtime/src/relay.rs", "    fn poll_stop(&mut self, cx: &mut Context<'_>) -> Option<StopReason> {\n", "    fn poll_stop(&mut self, cx: &mut Context<'_>) -> Option<StopReason> {\n        if cx.waker().will_wake(cx.waker()) {\n            return None;\n        }\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "a_stop_cuts_a_waiting_stream"],
            },
            expect: "a stop did not cut a waiting stream",
        },
        Case {
            id: "relay-keeps-upstream-after-cut",
            gate: "test",
            tool: None,
            // A cut drops the upstream before the body yields again.
            seed: replace("crates/uaos-runtime/src/relay.rs", "        self.ready.clear();\n        self.upstream = None;\n", "        self.ready.clear();\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "a_cut_drops_the_upstream_at_once"],
            },
            expect: "a cut kept the upstream",
        },
        Case {
            id: "relay-cut-ends-clean",
            gate: "test",
            tool: None,
            // Without a terminal frame a cut ends in an error (red line 9).
            seed: replace("crates/uaos-runtime/src/relay.rs", "        Some(Poll::Ready(Some(Err(RelayError::Cut(reason)))))\n", "        let _reason = reason;\n        Some(Poll::Ready(None))\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "a_cut_without_a_terminal_frame_ends_in_an_error"],
            },
            expect: "a cut ended cleanly, as if the answer were complete",
        },
        Case {
            id: "relay-event-unbounded",
            gate: "test",
            tool: None,
            // An event past its bound cuts.
            seed: replace("crates/uaos-runtime/src/sse.rs", "            max_event,\n        }\n", "            max_event: usize::MAX,\n        }\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "an_event_past_its_bound_cuts"],
            },
            expect: "an event past its bound was forwarded",
        },
        Case {
            id: "sse-split-crlf-twice",
            gate: "test",
            tool: None,
            // A CRLF split across two pieces is one line ending.
            seed: replace("crates/uaos-runtime/src/sse.rs", "            if next == b'\\n' {\n                i += 1;\n            }\n", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "any_chunking_relays_the_same_bytes_and_events"],
            },
            expect: "the relay saw different events than an event-stream parser",
        },
        Case {
            id: "unbounded-channel",
            gate: "clippy",
            tool: None,
            // Every channel is bounded.
            seed: append(
                "crates/uaos-runtime/src/lib.rs",
                "\n/// Seeded.\npub fn seeded_violation() {\n    drop(tokio::sync::mpsc::unbounded_channel::<()>());\n}\n",
            ),
            runner: CLIPPY,
            expect: "tokio::sync::mpsc::unbounded_channel",
        },
        Case {
            id: "stop-code-is-the-overrun",
            gate: "test",
            tool: None,
            // Every refusal under a stop says RUNTIME_STOPPED.
            seed: replace("crates/uaos-runtime/src/admission.rs", "            code: codes::RUNTIME_STOPPED,\n", "            code: if reason == StopReason::BudgetOverrun { codes::BUDGET_STREAM_OVERRUN } else { codes::RUNTIME_STOPPED },\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "stop", "every_stopped_refusal_says_stopped"],
            },
            expect: "a stopped kernel's refusal carried another code",
        },
        Case {
            id: "stop-record-handed-out-once",
            gate: "test",
            tool: None,
            // The stop's record is handed out until it is journaled. The record is handed out once:
            // asking for it marks it recorded.
            seed: replace(
                "crates/uaos-runtime/src/stop.rs",
                "        let engagement = self.inner.engagement().clone();\n",
                "        let engagement = self.inner.engagement().clone();\n        self.inner.engagement().recorded = engagement.generation;\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "stop", "the_record_is_handed_out_until_it_is_journaled"],
            },
            expect: "a stop's record was handed out once and could be lost",
        },
        Case {
            id: "boot-honours-any-resume",
            gate: "test",
            tool: None,
            // Only a human resumes a stopped kernel.
            seed: replace("crates/uaos-runtime/src/stop.rs", "record.event_type == types::KERNEL_RESUMED && record.actor == Actor::Human", "record.event_type == types::KERNEL_RESUMED"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "stop", "an_unknown_stop_reason_still_boots_stopped_and_a_resume_boots_running"],
            },
            expect: "a resume by a non-human actor booted the kernel running",
        },
        Case {
            id: "relay-settles-running-total",
            gate: "test",
            tool: None,
            // A stream that did not finish settles the full reservation.
            seed: replace("crates/uaos-runtime/src/relay.rs", "usage_final: end == RelayEnd::Completed && ended,", "usage_final: ended || !ended,"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "a_stream_that_does_not_finish_settles_the_full_reservation"],
            },
            expect: "a stream that did not finish settled at its running total",
        },
        Case {
            id: "relay-meters-usage-frames-only",
            gate: "test",
            tool: None,
            // An end frame is read strictly, not only a usage frame.
            seed: replace("crates/uaos-runtime/src/relay.rs", "            self.read(&data)?\n", "            if kind == FrameKind::Usage { self.read(&data)? } else { None }\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "usage_on_an_end_frame_is_metered"],
            },
            expect: "usage on an end frame went unmetered",
        },
        Case {
            id: "relay-idle-deadline-never-resets",
            gate: "test",
            tool: None,
            // Each wait on the upstream starts a new idle deadline.
            seed: replace("crates/uaos-runtime/src/relay.rs", "        if !self.waiting {\n", "        if self.idle.is_none() {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "upstream_activity_resets_the_idle_deadline"],
            },
            expect: "upstream activity did not reset the idle deadline",
        },
        Case {
            id: "sse-empty-event-name-kept",
            gate: "test",
            tool: None,
            // An empty event name is the default type, as no name.
            seed: replace("crates/uaos-runtime/src/relay.rs", "            None | Some(b\"\") => None,\n", "            None => None,\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "an_empty_event_name_is_no_name"],
            },
            expect: "an empty event name reached the codec as a name",
        },
        Case {
            id: "relay-empty-usage-report-counts",
            gate: "test",
            tool: None,
            // A report naming no dimension is no report.
            seed: replace("crates/uaos-runtime/src/relay.rs", "            .filter(|report| !report.dims().is_empty()))\n", "            .filter(|_| true))\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "an_empty_usage_report_is_no_report"],
            },
            expect: "an empty usage report counted as a report",
        },
        Case {
            id: "relay-report-after-end-final",
            gate: "test",
            tool: None,
            // A report after the dialect's end is not final.
            seed: replace("crates/uaos-runtime/src/relay.rs", "            self.ended = kind == FrameKind::End;\n", "            self.ended |= kind == FrameKind::End;\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "a_report_after_the_end_is_not_final"],
            },
            expect: "a report after the dialect's end counted as final",
        },
        Case {
            id: "admission-tells-a-misfit-to-retry",
            gate: "test",
            tool: None,
            // A request that can never fit is refused for good.
            seed: replace("crates/uaos-runtime/src/admission.rs", "        (bytes > self.limits.max_bytes).then_some(Refusal {\n", "        (bytes > u64::MAX).then_some(Refusal {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "stop", "a_request_that_can_never_fit_is_not_told_to_retry"],
            },
            expect: "a request that can never fit was told to retry",
        },
        Case {
            id: "boot-config-drift-unchecked",
            gate: "test",
            tool: None,
            // A configuration older than the journal's is refused.
            seed: replace("crates/uaos-runtime/src/boot.rs", "        && journaled > config.version()\n", "        && journaled < config.version()\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "an_older_configuration_is_refused_before_anything_is_written"],
            },
            expect: "a configuration older than the journal booted",
        },
        Case {
            id: "boot-recovery-skipped",
            gate: "test",
            tool: None,
            // Open reservations are settled at boot, never left open or released.
            seed: replace("crates/uaos-runtime/src/boot.rs", "        match ledger.recover(&mut sink, &Actor::System) {\n", "        match Ok::<_, uaos_ledger::LedgerError>(uaos_ledger::Recovery::default()) {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "an_open_reservation_settles_in_full_and_is_never_released"],
            },
            expect: "boot left an open reservation open",
        },
        Case {
            id: "boot-indeterminate-twice",
            gate: "test",
            tool: None,
            // An Operation already indeterminate is terminal for boot.
            seed: replace("crates/uaos-runtime/src/boot.rs", "    &types::OP_INDETERMINATE,\n];\n", "    &types::OP_DENIED,\n];\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "open_intents_become_indeterminate_once"],
            },
            expect: "an open intent was not made indeterminate, or a closed one was",
        },
        Case {
            id: "boot-intents-follow-ledger",
            gate: "test",
            tool: None,
            // A crash after the ledger's entries still closes every intent on the next boot. Only
            // the convergence property sees it.
            seed: replace("crates/uaos-runtime/src/boot.rs", "    let intents = open_intents(records);\n", "    let intents = if recovery.settled_estimated + recovery.completed > 0 { open_intents(records) } else { Vec::new() };\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "a_crash_during_boot_converges"],
            },
            expect: "a crash during boot did not converge",
        },
        Case {
            id: "boot-ignores-journaled-stop",
            gate: "test",
            tool: None,
            // A journaled stop boots stopped.
            seed: replace("crates/uaos-runtime/src/boot.rs", "    let stop = Stop::booted(stop_state);\n", "    let stop = Stop::running();\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "a_journaled_stop_boots_stopped_and_recovery_still_runs"],
            },
            expect: "a journaled stop did not boot stopped",
        },
        Case {
            id: "boot-unexplained",
            gate: "test",
            tool: None,
            // Every boot is journaled with its counts (red line 9).
            seed: replace("crates/uaos-runtime/src/boot.rs", "    journal.append(booted_draft(&report, correlation)?)?;\n", "    let _ = booted_draft(&report, correlation)?;\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "every_boot_is_explained_once"],
            },
            expect: "a boot went unexplained",
        },
        Case {
            id: "boot-denied-reopened",
            gate: "test",
            tool: None,
            // A denied Operation is left alone.
            seed: replace("crates/uaos-runtime/src/boot.rs", "    &types::OP_DENIED,\n", "    &types::OP_FAILED,\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "open_intents_become_indeterminate_once"],
            },
            expect: "an open intent was not made indeterminate, or a closed one was",
        },
        Case {
            id: "boot-ledger-error-erased",
            gate: "test",
            tool: None,
            // A journal failure in recovery keeps its code.
            seed: replace("crates/uaos-runtime/src/boot.rs", "            Err(error) => return Err(sink.take_refusal().map_or(BootError::Ledger(error), BootError::Journal)),\n", "            Err(error) => return Err(BootError::Ledger(error)),\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "a_full_disk_reads_the_same_wherever_boot_meets_it"],
            },
            expect: "a journal failure during recovery lost its code",
        },
        Case {
            id: "boot-intent-effect-dropped",
            gate: "test",
            tool: None,
            // The record carries the intent's effect.
            seed: replace("crates/uaos-runtime/src/boot.rs", "        side_effect_class: intent.side_effect_class,\n", "        side_effect_class: SideEffectClass::None,\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "open_intents_become_indeterminate_once"],
            },
            expect: "the indeterminate record hid the intent's effect",
        },
        Case {
            id: "boot-stop-loss-unexplained",
            gate: "test",
            tool: None,
            // A boot after a crash says a stop may be lost.
            seed: replace("crates/uaos-runtime/src/boot.rs", "    let stop_may_be_lost = stop_state == BootState::Running\n        && match last_end {\n", "    let stop_may_be_lost = false\n        && match last_end {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "a_boot_after_a_crash_says_a_stop_may_be_lost"],
            },
            expect: "a crash that may have lost a stop was not said so",
        },
        Case {
            id: "boot-stale-records-accepted",
            gate: "test",
            tool: None,
            // Records that are not the journal's are refused.
            seed: replace("crates/uaos-runtime/src/boot.rs", "    if !(ends_at_head && from_genesis && contiguous) {\n", "    if !(ends_at_head && from_genesis && contiguous) && false {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "records_that_are_not_the_journals_are_refused_before_anything_is_written"],
            },
            expect: "boot wrote over records that are not the journal's",
        },
        Case {
            id: "boot-partial-records-accepted",
            gate: "test",
            tool: None,
            // The records are the whole journal.
            seed: replace("crates/uaos-runtime/src/boot.rs", "    let from_genesis = records.first().is_none_or(|first| first.envelope.seq == Seq(0));\n", "    let from_genesis = true;\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "records_that_are_not_the_journals_are_refused_before_anything_is_written"],
            },
            expect: "boot accepted records that are not the journal's",
        },
        Case {
            id: "boot-interrupted-boot-unseen",
            gate: "test",
            tool: None,
            // An interrupted boot is evidence of a crash.
            seed: replace("crates/uaos-runtime/src/boot.rs", "    let crashed = interrupted\n", "    let crashed = interrupted && false\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "a_crash_during_boot_converges"],
            },
            expect: "an interrupted boot hid a lost stop",
        },
        Case {
            id: "boot-gapped-records-accepted",
            gate: "test",
            tool: None,
            // The records follow one another.
            seed: replace("crates/uaos-runtime/src/boot.rs", "    let contiguous = records\n", "    let contiguous = true || records\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "records_that_are_not_the_journals_are_refused_before_anything_is_written"],
            },
            expect: "boot accepted records that are not the journal's",
        },
        Case {
            id: "boot-ledger-evidence-ignored",
            gate: "test",
            tool: None,
            // Recovered ledger work is evidence of a crash.
            seed: replace("crates/uaos-runtime/src/boot.rs", "        || recovery.settled_estimated + recovery.completed + recovery.transfers_completed > 0;\n", "        || false;\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "a_boot_after_a_crash_says_a_stop_may_be_lost"],
            },
            expect: "a crash that may have lost a stop was not said so",
        },
        Case {
            id: "boot-closed-reopened",
            gate: "test",
            tool: None,
            // A closed Operation stays closed.
            seed: replace("crates/uaos-runtime/src/boot.rs", "            seen.entry(operation).or_insert(Seen::Open { at, intent: envelope });\n", "            seen.insert(operation, Seen::Open { at, intent: envelope });\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "a_closed_operation_stays_closed_and_its_first_intent_speaks"],
            },
            expect: "a closed Operation was reopened",
        },
        Case {
            id: "boot-evidence-from-first-boot",
            gate: "test",
            tool: None,
            // The evidence is read after the last boot record. Since slice 4a the last boot also
            // decides how the run ended, and the upgrade test tells the last boot from the first.
            seed: replace("crates/uaos-runtime/src/boot.rs", "        .rposition(|r| r.envelope.event_type == types::KERNEL_BOOTED);\n", "        .position(|r| r.envelope.event_type == types::KERNEL_BOOTED);\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "startup", "an_old_journal_is_unknown"],
            },
            expect: "the end of the run was read from an older boot than the last",
        },
        Case {
            id: "boot-intent-ids-dropped",
            gate: "test",
            tool: None,
            // The record keeps the Operation's ids.
            seed: replace("crates/uaos-runtime/src/boot.rs", "        session_id: intent.session_id,\n", "        session_id: None,\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "boot", "the_indeterminate_record_carries_the_intents_ids"],
            },
            expect: "the indeterminate record dropped the Operation's ids",
        },
        Case {
            id: "boot-stuck-not-surfaced",
            gate: "test",
            tool: None,
            // A boot that left an item stuck surfaces.
            seed: replace("crates/uaos-runtime/src/boot.rs", "        || report.settled_estimated + report.completed + report.transfers_completed + report.stuck.len() > 0\n", "        || report.settled_estimated + report.completed + report.transfers_completed > 0\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--lib", "a_boot_that_leaves_an_item_stuck_counts_it_and_surfaces"],
            },
            expect: "a boot that left an item stuck was journaled as routine",
        },
        Case {
            id: "relay-content-json-cuts",
            gate: "test",
            tool: None,
            // A content frame's JSON never cuts a stream.
            seed: replace("crates/uaos-runtime/src/relay.rs", "            self.read(&data).unwrap_or(None)\n", "            self.read(&data)?\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "a_content_frame_never_cuts_for_its_json"],
            },
            expect: "a content frame was cut for its JSON",
        },
        Case {
            id: "relay-skips-content-frames",
            gate: "test",
            tool: None,
            // A usage report on a frame the codec mislabels is still metered.
            seed: replace("crates/uaos-runtime/src/relay.rs", "            self.read(&data).unwrap_or(None)\n", "            None\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "usage_on_a_mislabelled_frame_is_still_metered"],
            },
            expect: "usage on a mislabelled frame went unmetered",
        },
        Case {
            id: "relay-node-bound-too-tight",
            gate: "test",
            tool: None,
            // A frame read for usage may hold the request's own 2^20 nodes.
            seed: replace("crates/uaos-runtime/src/relay.rs", "const MAX_EVENT_NODES: u32 = 1 << 20;\n", "const MAX_EVENT_NODES: u32 = 65_536;\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "a_large_end_frame_within_the_bounds_is_metered"],
            },
            expect: "a large end frame within the bounds was cut",
        },
        Case {
            id: "relay-idle-timeout-uncapped",
            gate: "test",
            tool: None,
            // A timeout over a year arms no timer.
            seed: replace("crates/uaos-runtime/src/relay.rs", "        if self.limits.idle_timeout > MAX_IDLE_TIMEOUT {\n", "        if self.limits.idle_timeout > Duration::MAX {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "a_huge_idle_timeout_disables_the_cut_without_a_panic"],
            },
            expect: "a huge idle timeout panicked",
        },
        Case {
            id: "relay-skips-content-usage",
            gate: "test",
            tool: None,
            // A report on a frame the codec calls content is metered.
            seed: replace("crates/uaos-runtime/src/relay.rs", "        if kind == FrameKind::Ping {\n", "        if matches!(kind, FrameKind::Ping | FrameKind::Content) {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "usage_on_a_frame_the_codec_calls_content_is_metered"],
            },
            expect: "usage on a frame the codec calls content went unmetered",
        },
        Case {
            id: "selector-member-scan-uncharged",
            gate: "test",
            tool: None,
            // Every member a lookup examines spends a visit.
            seed: replace("crates/uaos-module-api/src/selector.rs", "        visits.spend(1)?;\n        // A key compares as it decodes and stops at the first difference: O(key) at most.\n", "        // A key compares as it decodes and stops at the first difference: O(key) at most.\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_lookup_spends_a_visit_per_member"],
            },
            expect: "a member scan was not charged",
        },
        Case {
            id: "selector-raw-bound-too-tight",
            gate: "test",
            tool: None,
            // The raw-length shortcut refuses only what cannot decode to a value.
            seed: replace("crates/uaos-module-api/src/selector.rs", "const MAX_RAW_TEXT: usize = 6 * MAX_SELECTOR_TEXT;\n", "const MAX_RAW_TEXT: usize = 5 * MAX_SELECTOR_TEXT;\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_string_that_decodes_short_enough_still_matches"],
            },
            expect: "an escaped string that decodes to a value was refused",
        },
        Case {
            id: "module-text-invisible-base",
            gate: "language-neutrality",
            tool: None,
            // A variation selector's base is visible.
            seed: replace("crates/uaos-module-api/src/decl.rs", "                base = (!c.is_whitespace() && !c.is_control() && !is_default_ignorable(c)).then_some(c);\n", "                base = Some(c);\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "language_neutrality", "module_text_needs_a_visible_base"],
            },
            expect: "a variation selector without a visible base passed",
        },
        Case {
            id: "module-text-ideographic-any-base",
            gate: "language-neutrality",
            tool: None,
            // An ideographic selector follows a CJK ideograph only.
            seed: replace("crates/uaos-module-api/src/decl.rs", "                if !base.is_some_and(|b| !ideographic || is_unified_ideograph(b)) {\n", "                if !base.is_some_and(|_| !ideographic || true) {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "language_neutrality", "module_text_needs_a_visible_base"],
            },
            expect: "a variation selector without a visible base passed",
        },
        Case {
            id: "selector-raw-bound-too-loose",
            gate: "test",
            tool: None,
            // Past the raw bound a string is never decoded.
            seed: replace("crates/uaos-module-api/src/selector.rs", "is_some_and(|len| len > MAX_RAW_TEXT)", "is_some_and(|len| len > 2 * MAX_RAW_TEXT)"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--lib", "a_string_past_the_raw_bound_is_never_decoded"],
            },
            expect: "a string past the raw bound was decoded",
        },
        Case {
            id: "mask-seal-keyless-key",
            gate: "test",
            tool: None,
            // A key finding on a node with no key refuses the seal.
            seed: replace("crates/uaos-module-api/src/view.rs", "            .any(|id| tape.node(*id).and_then(|node| node.key_span()).is_none())\n", "            .any(|id| tape.node(*id).is_none())\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_key_finding_on_a_keyless_node_refuses_the_seal"],
            },
            expect: "a key finding on a keyless node was sealed",
        },
        Case {
            id: "rolemap-fresh-budget-per-assign",
            gate: "test",
            tool: None,
            // A RoleMap carries one budget for all of a codec's roles.
            seed: replace("crates/uaos-module-api/src/codec.rs", "        let mut visits = Visits::new(MAX_VISITS.saturating_sub(self.spent));\n", "        let mut visits = Visits::per_call();\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_codecs_roles_share_one_budget"],
            },
            expect: "a codec's roles each got a fresh budget",
        },
        Case {
            id: "call-event-manifest-reread",
            gate: "test",
            tool: None,
            // An event is checked against the manifest admitted, not a later one.
            seed: replace("crates/uaos-module-api/src/module.rs", "        check_decls(self.manifest(), None, out.as_slice())?;\n", "        check_decls(self.module.manifest(), None, out.as_slice())?;\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "a_module_is_checked_against_its_admitted_manifest"],
            },
            expect: "an event was checked against a manifest grown after admission",
        },
        Case {
            id: "call-event-keeps-outgrown-state",
            gate: "test",
            tool: None,
            // The event procedure strikes an event that outgrew its state.
            seed: replace("crates/uaos-module-api/src/module.rs", "        if copy.exceeded() {\n            return Err(Strike::StateExceeded);\n        }\n        check_decls(self.manifest(), None, out.as_slice())?;\n", "        check_decls(self.manifest(), None, out.as_slice())?;\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "an_event_that_outgrows_its_state_is_struck_whole"],
            },
            expect: "an outgrown event was kept",
        },
        Case {
            id: "view-masked-key-matched-by-name",
            gate: "test",
            tool: None,
            // A masked key matches no name in the selectors' key check either.
            seed: replace("crates/uaos-module-api/src/view.rs", "    pub fn key_is(&self, name: &str) -> Result<bool, JsonError> {\n        if self.key_masked() {\n            return Ok(false);\n        }\n", "    pub fn key_is(&self, name: &str) -> Result<bool, JsonError> {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "masked_keys_and_numbers_read_as_masked"],
            },
            expect: "a masked key matched its name",
        },
        Case {
            id: "selector-each-uncharged",
            gate: "test",
            tool: None,
            // `Each` charges every child it selects.
            seed: replace("crates/uaos-module-api/src/selector.rs", "                            visits.spend(1)?;\n                            next.insert(child.id());\n", "                            next.insert(child.id());\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "each_child_and_array_element_spends_a_visit"],
            },
            expect: "a child or an element was examined uncharged",
        },
        Case {
            id: "mask-seal-literal-value",
            gate: "test",
            tool: None,
            // A value finding on a literal refuses the seal.
            seed: replace("crates/uaos-module-api/src/view.rs", "            if matches!(node.kind(), Kind::True | Kind::False | Kind::Null) {\n", "            if false {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_value_finding_on_a_literal_refuses_the_seal"],
            },
            expect: "a value finding on a literal was sealed",
        },
        Case {
            id: "host-procedure-keeps-outgrown-state",
            gate: "test",
            tool: None,
            // The crate's call procedure strikes a call that outgrew its state.
            seed: replace("crates/uaos-module-api/src/module.rs", "        if copy.exceeded() {\n            return Err(Strike::StateExceeded);\n        }\n        check_decls(self.manifest(), Some(cx.point()), out.as_slice())?;\n", "        check_decls(self.manifest(), Some(cx.point()), out.as_slice())?;\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "a_call_that_outgrows_its_state_is_struck_whole"],
            },
            expect: "an outgrown call was kept",
        },
        // A stage cannot be skipped. A shortcut from `Received` to the final scan makes the
        // module's compile-fail doctest compile.
        Case {
            id: "stage-skipped",
            gate: "kernel-tokens",
            tool: None,
            seed: append(
                "crates/uaos-runtime/src/pipeline.rs",
                "\nimpl<'r> Operation<'r, Received> {\n    /// Seeded: a shortcut past every stage.\n    ///\n    /// # Errors\n    /// None.\n    pub fn scan(self, _scanner: &FinalScanner) -> Result<Operation<'r, Scanned>, Exit> {\n        let started = self.core.ids.counters.now();\n        let scanned = Scanned {\n            request: self.core.request.clone(),\n            json: false,\n            classes: BTreeSet::new(),\n            route: Route::declared(\"seeded\"),\n        };\n        Ok(self.core.advance(scanned, Stage::Scanned, started))\n    }\n}\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--doc", "--locked"],
            },
            expect: "compiled successfully",
        },
        // A `Ready` cannot be assembled outside the pipeline: with the fields public, the
        // compile-fail doctest that forges one compiles.
        Case {
            id: "ready-outside-pipeline",
            gate: "kernel-tokens",
            tool: None,
            seed: both(
                replace(
                    "crates/uaos-runtime/src/pipeline.rs",
                    "pub struct Operation<'r, S> {\n    core: Core<'r>,\n    stage: S,\n}",
                    "pub struct Operation<'r, S> {\n    /// Seeded.\n    pub core: Core<'r>,\n    /// Seeded.\n    pub stage: S,\n}",
                ),
                both(
                    replace(
                        "crates/uaos-runtime/src/pipeline.rs",
                        "struct Core<'r> {\n    ids: Ids,",
                        "pub struct Core<'r> {\n    /// Seeded.\n    pub ids: Ids,",
                    ),
                    both(
                        replace(
                            "crates/uaos-runtime/src/pipeline.rs",
                            "/// What every state carries, and [`Ready`] keeps. Private to this module.\nstruct Ids {",
                            "/// Seeded.\npub struct Ids {",
                        ),
                        replace(
                            "crates/uaos-runtime/src/pipeline.rs",
                            "pub struct Ready {\n    ids: Ids,\n    stage: Scanned,\n}",
                            "pub struct Ready {\n    /// Seeded.\n    pub ids: Ids,\n    /// Seeded.\n    pub stage: Scanned,\n}",
                        ),
                    ),
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--doc", "--locked"],
            },
            expect: "compiled successfully",
        },
        // The kernel builds and passes with zero modules: a hook stage that refuses without one
        // fails the pipeline's test.
        Case {
            id: "runtime-requires-module",
            gate: "kernel-tokens",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/pipeline.rs",
                "        Ok(self.hook_with(SplicePlan::new(), RoleMap::new()))",
                "        let op = self.hook_with(SplicePlan::new(), RoleMap::new());\n        Err(op.core.refuse(Stage::Hooked, codes::RUNTIME_OVERLOAD, 0))",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "pipeline", "--locked"],
            },
            expect: "the kernel must pass with zero modules",
        },
        // An edit that touches a role that forbids edits is refused.
        Case {
            id: "splice-ignores-forbidden-roles",
            gate: "kernel-tokens",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/splice.rs",
                "        if touching.iter().any(|role| role.forbids_edit()) {\n",
                "        if touching.iter().any(|role| role.forbids_edit() && *role == Role::Volatile) {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--lib", "--locked", "splice::tests"],
            },
            expect: "a_forbidden_edit_refuses_the_whole_plan",
        },
        // The role check covers the whole subtree an edit removes, not only the ancestors.
        Case {
            id: "splice-checks-ancestors-only",
            gate: "kernel-tokens",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/splice.rs",
                "        let touching = roles.touching(view, edit.node).ok_or(SpliceError::UnknownNode)?;\n",
                "        let touching = roles.governing(view, edit.node).ok_or(SpliceError::UnknownNode)?;\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--lib", "--locked", "splice::tests"],
            },
            expect: "a_forbidden_edit_refuses_the_whole_plan",
        },
        // A live edit lies strictly inside its anchor.
        Case {
            id: "splice-live-edit-anywhere",
            gate: "kernel-tokens",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/splice.rs",
                "        if let Class::Live(anchor) = edit.class {\n",
                "        if let (Class::Live(anchor), false) = (edit.class, true) {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--lib", "--locked", "splice::tests"],
            },
            expect: "a_forbidden_edit_refuses_the_whole_plan",
        },
        // An edit never touches what redaction masked.
        Case {
            id: "splice-ignores-mask",
            gate: "kernel-tokens",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/splice.rs",
                "        if view.touches_masked(edit.node) {\n",
                "        if view.touches_masked(edit.node) && edit.class == Class::Replayed {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--lib", "--locked", "splice::tests"],
            },
            expect: "a_forbidden_edit_refuses_the_whole_plan",
        },
        // No edit lies inside what another strips.
        Case {
            id: "splice-overlap-unchecked",
            gate: "kernel-tokens",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/splice.rs",
                "        if previous == Some(edit.node) || edit.node.get() < covered_until {\n",
                "        if previous == Some(edit.node) {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--lib", "--locked", "splice::tests"],
            },
            expect: "malformed_plans_are_refused",
        },
        // A strip takes exactly one comma with each run of removed siblings.
        Case {
            id: "splice-strip-keeps-comma",
            gate: "kernel-tokens",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/splice.rs",
                "                (Some(kept), _) => kept.span().range().end..last.span().range().end,\n",
                "                (Some(_), _) => child_start(first)..last.span().range().end,\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--lib", "--locked", "splice::tests"],
            },
            expect: "strips_take_exactly_one_comma",
        },
        // The edited body is parsed again under the request's limits before it may leave.
        Case {
            id: "splice-output-unchecked",
            gate: "kernel-tokens",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/splice.rs",
                "    uaos_json::parse(&out, limits).map_err(parse_refusal)?;\n",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--lib", "--locked", "splice::tests"],
            },
            expect: "limits_hold_after_splicing",
        },
        // A plan on a body that is not JSON is refused, never skipped.
        Case {
            id: "pipeline-plan-on-text-applied",
            gate: "kernel-tokens",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/pipeline.rs",
                "            Err(splice::SpliceError::NotJson)\n",
                "            Ok(None)\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--lib", "--locked", "pipeline::tests"],
            },
            expect: "the_plan_is_applied_or_refused_at_splice",
        },
        // The door gets the bytes the final scan read, moved and never rebuilt. Rebuilt after the
        // scan from the client's body, it would send what redaction replaced; the call-site test
        // fails.
        Case {
            id: "pipeline-ready-gets-the-original",
            gate: "kernel-tokens",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/pipeline.rs",
                "        Ok(Ready { ids: core.ids, stage })\n",
                "        let mut stage = stage;\n        stage.request.body = core.request.body.clone();\n        Ok(Ready { ids: core.ids, stage })\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--lib", "--locked", "pipeline::tests"],
            },
            expect: "the_door_gets_exactly_the_bytes_the_scan_read",
        },
        // The client's credentials never leave (A-18): kept, the client's key reaches the scan.
        Case {
            id: "pipeline-forwards-client-credentials",
            gate: "kernel-tokens",
            tool: None,
            seed: replace("crates/uaos-runtime/src/pipeline.rs", "    \"authorization\",\n", "    \"x-not-a-header\",\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "pipeline", "--locked"],
            },
            expect: "only_the_headers_that_leave_are_scanned_and_kept",
        },
        // Every header that leaves is scanned, as the body and the path are.
        Case {
            id: "pipeline-headers-unscanned",
            gate: "kernel-tokens",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/pipeline.rs",
                "                .chain(headers)\n",
                "                .chain(headers.take(0))\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "pipeline", "--locked"],
            },
            expect: "the_final_scan_blocks_a_vault_key_anywhere_it_would_leave",
        },
        // A body past a tokenizer limit is refused whatever it claims to be, not redacted as text.
        Case {
            id: "pipeline-limit-read-as-text",
            gate: "kernel-tokens",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/pipeline.rs",
                "                        | ErrorKind::KeyTooLong => Some(codes::INGRESS_TOO_LARGE),\n",
                "                        | ErrorKind::KeyTooLong => declares_json(&request.headers).then_some(codes::INGRESS_TOO_LARGE),\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "pipeline", "--locked"],
            },
            expect: "a_body_is_json_text_or_bytes_and_limits_always_refuse",
        },
        // A redacted key masks its member's key (A-6), not only a value.
        Case {
            id: "pipeline-mask-misses-keys",
            gate: "kernel-tokens",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/pipeline.rs",
                "                        mask.key(edited.node());\n",
                "                        mask.value(edited.node());\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "pipeline", "--locked"],
            },
            expect: "a_secret_is_redacted_on_the_tape_and_masked_by_node",
        },
        // A body that cannot be redacted is still scanned, so its secret is blocked, not sent.
        Case {
            id: "pipeline-unredacted-body-unscanned",
            gate: "kernel-tokens",
            tool: None,
            seed: replace(
                "crates/uaos-runtime/src/pipeline.rs",
                "            std::iter::once((body, request.body.as_ref()))\n",
                "            std::iter::once((body, if out.json { request.body.as_ref() } else { &[][..] }))\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "pipeline", "--locked"],
            },
            expect: "a_secret_in_bytes_is_blocked_not_sent",
        },
        // Redaction names the nodes it changed, for the mask (A-6).
        Case {
            id: "redact-edited-nodes-dropped",
            gate: "redaction-corpus",
            tool: None,
            seed: replace(
                "crates/uaos-redact/src/redactor.rs",
                "                edited.push(Edited { node, key: is_key });\n",
                "                let _ = node;\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-redact", "--test", "redact", "--locked"],
            },
            expect: "redaction_names_the_nodes_it_changed",
        },
        // A library compiles without its dev-dependencies. `is_parse_too_large` exists only with
        // hyper's `server` feature, which the egress crate enables for its tests alone.
        Case {
            id: "lib-needs-dev-feature",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos-egress/src/lib.rs",
                "                unparsable |= h.is_parse() || h.is_parse_status();\n",
                "                unparsable |= h.is_parse() || h.is_parse_too_large();\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["check", "--workspace", "--lib", "--locked"],
            },
            expect: "is_parse_too_large",
        },
        // The help text, the exit codes and the `--json` output are a contract, snapshot-tested.
        Case {
            id: "cli-help-changed",
            gate: "cli-contract",
            tool: None,
            seed: replace(
                "crates/uaos/src/lib.rs",
                "  key list           The provider keys, by name; never their values\n",
                "  key list           The provider keys\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos", "--test", "cli", "--locked"],
            },
            expect: "the_help_text_is_the_contract",
        },
        Case {
            id: "cli-exit-code-changed",
            gate: "cli-contract",
            tool: None,
            seed: replace(
                "crates/uaos-contracts/src/cli.rs",
                "        ErrorClass::User => 2,\n",
                "        ErrorClass::User => 64,\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos", "--test", "cli", "--locked"],
            },
            expect: "every_failure_ends_with_its_class_exit_code",
        },
        // A configuration holding a secret is refused. Without the scan of the file, a key in it
        // reaches validation, which refuses it for another reason.
        Case {
            id: "config-holds-secret",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos/src/config.rs",
                "    if let Some(bytes) = file {\n        scan(&scanner, bytes, \"the file\")?;\n    }\n",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos", "--test", "cli", "--locked"],
            },
            expect: "a_configuration_holding_a_secret_is_refused",
        },
        // The binary never names the door.
        Case {
            id: "arch-bin-depends-on-egress",
            gate: "arch-check",
            tool: None,
            seed: replace(
                "crates/uaos/Cargo.toml",
                "uaos-contracts.workspace = true\n",
                "uaos-contracts.workspace = true\nuaos-egress.workspace = true\n",
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "uaos -> uaos-egress: edge not allowed",
        },
        // A provider key reaches the OS keychain and nothing else. A key typed at a terminal is
        // refused, so it never sits in a scrollback.
        Case {
            id: "key-read-from-terminal",
            gate: "test",
            tool: None,
            seed: replace("crates/uaos/src/keys.rs", "    if is_terminal {\n", "    if is_terminal && MAX_KEY_LEN == 0 {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos", "--test", "cli", "--locked"],
            },
            expect: "a_key_is_refused_unless_it_is_piped_and_plain",
        },
        // A refusal says why, never what was read.
        Case {
            id: "key-echoed-in-output",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos/src/keys.rs",
                "        return Err(usage(\"a key is one line of printable ASCII without spaces\"));\n",
                "        return Err(Failed::new(codes::CLI_USAGE, format!(\"not a key: {}\", String::from_utf8_lossy(&key))));\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos", "--test", "cli", "--locked"],
            },
            expect: "a_key_is_refused_unless_it_is_piped_and_plain",
        },
        // Every entry lives under its installation, so two data directories never share a key.
        Case {
            id: "key-account-outside-installation",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos/src/keys.rs",
                "    format!(\"{installation}/provider/{name}\")\n",
                "    format!(\"provider/{name}{}\", &installation[..0])\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos", "--test", "cli", "--locked"],
            },
            expect: "provider_keys_live_only_in_the_keychain",
        },
        // A second `init` only reads the journal; reopening it for writing would run recovery
        // and refuse a journal that needs its chunk store.
        Case {
            id: "init-reopens-journal",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos/src/lib.rs",
                "    let existing = home::read_journal(inv.fs.as_ref(), &dir)?;\n",
                "    let existing = None::<home::Journal>;\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos", "--test", "cli", "--locked"],
            },
            expect: "a_second_init_leaves_the_journal_as_it_was",
        },
        // Disk full: an index that could not be written takes the keychain change back.
        Case {
            id: "key-index-failure-keeps-new-key",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos/src/keys.rs",
                "                let _restored = match previous {\n                    Some(old) => keychain.set(&account, &old).is_ok(),\n                    None => keychain.delete(&account).is_ok(),\n                };\n",
                "                let _restored = previous.is_some();\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos", "--test", "cli", "--locked"],
            },
            expect: "a_failed_index_write_leaves_the_keychain_as_it_was",
        },
        // `doctor` sees an active key the keychain lost.
        Case {
            id: "doctor-misses-missing-key",
            gate: "test",
            tool: None,
            seed: replace(
                "crates/uaos/src/doctor.rs",
                "                .filter(|k| k.state == \"active\" && !k.in_keychain)\n",
                "                .filter(|k| k.state == \"active\" && !k.in_keychain && k.name.is_empty())\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos", "--test", "cli", "--locked"],
            },
            expect: "doctor_checks_the_installation",
        },
        // A host without a usable keychain is a setup problem, exit 3, not an internal failure.
        Case {
            id: "cli-keychain-missing-exits-internal",
            gate: "cli-contract",
            tool: None,
            seed: replace(
                "crates/uaos/src/vault.rs",
                "        KeychainError::Unavailable(_) | KeychainError::Denied => codes::CLI_KEYCHAIN_UNAVAILABLE,\n",
                "        KeychainError::Unavailable(_) | KeychainError::Denied => codes::CLI_KEYCHAIN_FAILED,\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos", "--test", "cli", "--locked"],
            },
            expect: "a_keychain_failure_exits_by_its_kind",
        },
        // The identity layer passes a keychain failure on as text; without the watched keychain,
        // `init` would report it as the identity layer's internal failure.
        Case {
            id: "cli-init-keychain-failure-unclassified",
            gate: "cli-contract",
            tool: None,
            seed: replace(
                "crates/uaos/src/lib.rs",
                "        watched\n            .failure()\n            .unwrap_or_else(",
                "        None::<Failed>.unwrap_or_else(",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos", "--test", "cli", "--locked"],
            },
            expect: "init_without_a_keychain_says_so",
        },
        // A failed check is an exit code a script can read, not only a line of text.
        Case {
            id: "cli-doctor-exits-zero-on-failure",
            gate: "cli-contract",
            tool: None,
            seed: replace(
                "crates/uaos/src/lib.rs",
                "    let failure = (!failed.is_empty()).then(|| {\n",
                "    let failure = (failed.is_empty() && !failed.is_empty()).then(|| {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos", "--test", "cli", "--locked"],
            },
            expect: "doctor_checks_the_installation",
        },
    ]
}

/// Outcome of one case.
enum Outcome {
    Proven,
    Skipped(String),
    /// The case is for another operating system.
    Elsewhere(&'static str),
    Broken(String),
}

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let require_all = args.iter().any(|a| a == "--require-all-tools");
    let anchors_only = args.iter().any(|a| a == "--anchors");
    let selected: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let root = workspace_root();
    let base = root.join("target").join("xtask-negative");
    let shared_target = base.join("target");

    let mut failures = Vec::new();
    let mut skipped = Vec::new();
    let mut elsewhere = 0usize;
    for case in cases() {
        if !selected.is_empty() && !selected.iter().any(|s| s.as_str() == case.id) {
            continue;
        }
        let outcome = if anchors_only {
            check_anchors(&case, &root, &base)
        } else {
            run_case(&case, &root, &base, &shared_target)
        };
        match outcome {
            Outcome::Proven if anchors_only => println!("  ANCHORED {:<30} its seed applies", case.id),
            Outcome::Proven => println!(
                "  PROVEN   {:<30} gate `{}` fails on its seeded violation",
                case.id, case.gate
            ),
            Outcome::Skipped(why) => {
                println!("  SKIPPED  {:<30} {why}", case.id);
                skipped.push(case.id);
            }
            Outcome::Elsewhere(os) => {
                println!("  NOT HERE {:<30} runs on {os} only", case.id);
                elsewhere += 1;
            }
            Outcome::Broken(why) => {
                println!("  BROKEN   {:<30} {why}", case.id);
                failures.push(format!("{}: {why}", case.id));
            }
        }
    }
    if require_all && !skipped.is_empty() {
        failures.push(format!("skipped with --require-all-tools: {}", skipped.join(", ")));
    }
    if failures.is_empty() && anchors_only {
        println!("xtask negative --anchors: every selected seed applies; nothing was built or run");
        Ok(())
    } else if failures.is_empty() {
        println!(
            "xtask negative: every exercised gate bites ({} skipped for missing tools, {elsewhere} for another system)",
            skipped.len()
        );
        Ok(())
    } else {
        Err(format!("gate self-test failed:\n  {}", failures.join("\n  ")))
    }
}

/// `--anchors`: applies the case's seed to a fresh copy and stops there, building and running
/// nothing, so a seed whose anchor went stale shows in seconds, on any system and whatever tool
/// the case needs. A history case builds its own repository, so it has no anchor to check.
fn check_anchors(case: &Case, root: &Path, base: &Path) -> Outcome {
    if matches!(case.runner, Runner::History(..)) {
        return Outcome::Proven;
    }
    let ws = base.join("anchors");
    match copy_workspace(root, &ws).and_then(|()| (case.seed)(&ws)) {
        Ok(()) => Outcome::Proven,
        Err(e) => Outcome::Broken(e),
    }
}

fn run_case(case: &Case, root: &Path, base: &Path, shared_target: &Path) -> Outcome {
    match case.tool {
        Some(UNIX_ONLY) if !cfg!(unix) => return Outcome::Elsewhere("Unix"),
        Some(WINDOWS_ONLY) if !cfg!(windows) => return Outcome::Elsewhere("Windows"),
        Some(LINUX_ONLY) if !cfg!(target_os = "linux") => return Outcome::Elsewhere("Linux"),
        Some(tool) if ![UNIX_ONLY, WINDOWS_ONLY, LINUX_ONLY].contains(&tool) && !tool_available(tool) => {
            return Outcome::Skipped(format!("`{tool}` not installed"));
        }
        _ => {}
    }
    if let Runner::History(gate, make_history) = &case.runner {
        let repo = base.join(case.id);
        return match history_case(&repo, *gate, *make_history, case.expect) {
            Ok(()) => Outcome::Proven,
            Err(e) => Outcome::Broken(e),
        };
    }
    let ws = base.join(case.id);
    let attempt = || -> Result<(), String> {
        copy_workspace(root, &ws)?;
        let (clean_ok, clean_out) = invoke(&case.runner, &ws, shared_target)?;
        if !clean_ok {
            return Err(format!(
                "gate fails on the CLEAN copy, so the seeded failure proves nothing:\n{}",
                tail(&clean_out)
            ));
        }
        (case.seed)(&ws)?;
        let (seeded_ok, seeded_out) = invoke(&case.runner, &ws, shared_target)?;
        if seeded_ok {
            return Err("gate PASSED on the seeded violation — it does not bite".to_owned());
        }
        if !seeded_out.contains(case.expect) {
            return Err(format!(
                "gate failed, but its output does not mention `{}` — it may have failed for another reason:\n{}",
                case.expect,
                tail(&seeded_out)
            ));
        }
        Ok(())
    };
    match attempt() {
        Ok(()) => Outcome::Proven,
        Err(e) => Outcome::Broken(e),
    }
}

fn invoke(runner: &Runner, ws: &Path, shared_target: &Path) -> Result<(bool, String), String> {
    let mut cmd = match runner {
        Runner::Program { program, args } => {
            let mut c = Command::new(program);
            c.args(*args);
            c
        }
        Runner::Xtask(args) => {
            let mut c = Command::new("cargo");
            c.args(["run", "--quiet", "-p", "xtask", "--"]).args(*args);
            c
        }
        Runner::History(..) => return Err("history cases are not invoked in a workspace copy".to_owned()),
    };
    let out = cmd
        .current_dir(ws)
        .env("CARGO_TARGET_DIR", shared_target)
        .output()
        .map_err(|e| format!("could not start gate: {e}"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text))
}

fn tail(s: &str) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(25)..].join("\n")
}

fn tool_available(tool: &str) -> bool {
    let (program, args): (&str, &[&str]) = match tool {
        "cargo-deny" => ("cargo", &["deny", "--version"]),
        "cargo-vet" => ("cargo", &["vet", "--version"]),
        other => (other, &["--version"]),
    };
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn copy_workspace(root: &Path, dest: &Path) -> Result<(), String> {
    if dest.exists() {
        std::fs::remove_dir_all(dest).map_err(|e| format!("clean {}: {e}", dest.display()))?;
    }
    for file in walk_files(root)? {
        let relative = rel(root, &file);
        let target: PathBuf = dest.join(&relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        std::fs::copy(&file, &target).map_err(|e| format!("copy {relative}: {e}"))?;
        // Copies keep the source's modification time on some platforms (Windows CopyFile).
        // Cargo would then consider the copy unchanged and reuse artifacts built from a
        // previous, seeded copy in the shared target directory. Stamp every file as new.
        std::fs::File::options()
            .write(true)
            .open(&target)
            .and_then(|f| f.set_modified(std::time::SystemTime::now()))
            .map_err(|e| format!("touch {relative}: {e}"))?;
    }
    Ok(())
}

fn git(repo: &Path, args: &[&str]) -> Result<String, String> {
    crate::util::capture(repo, "git", args).map(|s| s.trim().to_owned())
}

fn scratch_repo(repo: &Path) -> Result<(), String> {
    if repo.exists() {
        std::fs::remove_dir_all(repo).map_err(|e| format!("clean {}: {e}", repo.display()))?;
    }
    std::fs::create_dir_all(repo).map_err(|e| format!("{}: {e}", repo.display()))?;
    git(repo, &["init", "-q"])?;
    git(repo, &["config", "user.name", "Gate Selftest"])?;
    git(repo, &["config", "user.email", "selftest@invalid.example"])?;
    git(repo, &["commit", "-q", "--allow-empty", "-s", "-m", "root"])?;
    Ok(())
}

/// Returns `(clean_range, violating_range)`.
fn dco_history(repo: &Path) -> Result<(String, String), String> {
    scratch_repo(repo)?;
    git(repo, &["commit", "-q", "--allow-empty", "-s", "-m", "signed"])?;
    git(repo, &["commit", "-q", "--allow-empty", "-m", "unsigned"])?;
    Ok(("HEAD~2..HEAD~1".to_owned(), "HEAD~1..HEAD".to_owned()))
}

/// Returns `(clean_range, violating_range)`, each spanning one unsigned merge and the signed
/// commit it brings in: first a content-free merge, then one that resolves a conflict.
fn dco_merge_history(repo: &Path) -> Result<(String, String), String> {
    scratch_repo(repo)?;
    let write = |file: &str, text: &str| std::fs::write(repo.join(file), text).map_err(|e| e.to_string());
    let trunk = git(repo, &["rev-parse", "--abbrev-ref", "HEAD"])?;
    write("a.txt", "base\n")?;
    git(repo, &["add", "-A"])?;
    git(repo, &["commit", "-q", "-s", "-m", "base"])?;

    git(repo, &["checkout", "-q", "-b", "side"])?;
    write("a.txt", "side\n")?;
    git(repo, &["commit", "-q", "-s", "-am", "side"])?;
    git(repo, &["checkout", "-q", &trunk])?;
    write("b.txt", "trunk\n")?;
    git(repo, &["add", "-A"])?;
    git(repo, &["commit", "-q", "-s", "-m", "trunk"])?;
    git(repo, &["merge", "-q", "--no-ff", "--no-edit", "side"])?;
    let content_free = git(repo, &["rev-parse", "HEAD"])?;

    git(repo, &["checkout", "-q", "-b", "side2"])?;
    write("a.txt", "side2\n")?;
    git(repo, &["commit", "-q", "-s", "-am", "side2"])?;
    git(repo, &["checkout", "-q", &trunk])?;
    write("a.txt", "trunk2\n")?;
    git(repo, &["commit", "-q", "-s", "-am", "trunk2"])?;
    if git(repo, &["merge", "-q", "--no-edit", "side2"]).is_ok() {
        return Err("expected a merge conflict in the seeded history".to_owned());
    }
    write("a.txt", "resolved by hand\n")?;
    git(repo, &["add", "a.txt"])?;
    git(repo, &["commit", "-q", "--no-edit"])?;
    let resolved = git(repo, &["rev-parse", "HEAD"])?;

    Ok((
        format!("{content_free}^1..{content_free}"),
        format!("{resolved}^1..{resolved}"),
    ))
}

fn docs_sync_history(repo: &Path) -> Result<(String, String), String> {
    scratch_repo(repo)?;
    let schemas = repo.join("schemas");
    std::fs::create_dir_all(&schemas).map_err(|e| e.to_string())?;
    std::fs::write(schemas.join("event.v1.json"), "{}\n").map_err(|e| e.to_string())?;
    std::fs::write(repo.join("CHANGELOG.md"), "# Changelog\n- event v1\n").map_err(|e| e.to_string())?;
    git(repo, &["add", "-A"])?;
    git(repo, &["commit", "-q", "-s", "-m", "contract with changelog"])?;
    std::fs::write(schemas.join("event.v1.json"), "{\"changed\":true}\n").map_err(|e| e.to_string())?;
    git(repo, &["add", "-A"])?;
    git(repo, &["commit", "-q", "-s", "-m", "contract without changelog"])?;
    Ok(("HEAD~2..HEAD~1".to_owned(), "HEAD~1..HEAD".to_owned()))
}

fn history_case(
    repo: &Path,
    gate: fn(&Path, &str) -> Result<(), String>,
    make_history: fn(&Path) -> Result<(String, String), String>,
    expect: &str,
) -> Result<(), String> {
    let (clean, violating) = make_history(repo)?;
    gate(repo, &clean).map_err(|e| format!("gate fails on the CLEAN history: {e}"))?;
    match gate(repo, &violating) {
        Ok(()) => Err("gate PASSED on the seeded violation — it does not bite".to_owned()),
        Err(e) if e.contains(expect) => Ok(()),
        Err(e) => Err(format!("gate failed without mentioning `{expect}`: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::replace;

    /// A seed anchor names exactly one site: one that also matched elsewhere would seed the first
    /// match, which may not be the case's site.
    #[test]
    fn a_seed_anchor_must_occur_exactly_once() {
        let dir = std::env::temp_dir().join(format!("uaos-xtask-seed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f.rs"), "a\nb\na\n").unwrap();
        assert!(replace("f.rs", "b\n", "c\n")(&dir).is_ok());
        let twice = replace("f.rs", "a\n", "x\n")(&dir).unwrap_err();
        assert!(twice.contains("occurs 2 times"), "{twice}");
        let missing = replace("f.rs", "zzz", "y")(&dir).unwrap_err();
        assert!(missing.contains("not found"), "{missing}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
