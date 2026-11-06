// SPDX-License-Identifier: Apache-2.0

//! Every file rustc reads for a local crate lies in that crate's own directory, or in the output
//! directory of that crate's own build script. The dependency graph cannot show a file taken from
//! elsewhere (`#[path]`, an `include` macro, a symlink, a target's `path` in the manifest), and no
//! reading of the source text sees every spelling of one: `cfg_attr`, raw strings, escapes, a path
//! built by a macro.
//!
//! So this check reads what rustc itself recorded. For every artifact of a local package (each
//! workspace member, and any path dependency outside the workspace, which arch-check refuses as
//! well) in the build it is handed, the dep-info file rustc wrote lists each file the compilation
//! read. Each is resolved, symlinks included, and must lie under the package's directory or under
//! the `OUT_DIR` its own build script was given. Clippy's own configuration, the workspace
//! `Cargo.toml` and `clippy.toml`, is listed too and allowed by exact path.
//!
//! It sees the builds it is handed, and only those:
//! * the clippy gate hands it clippy's build: dev profile, default features, `cfg(clippy)`;
//! * `cargo xtask sources [package]`, which CI runs after the clippy gate, checks every target
//!   in the dev profile with default features and with every feature, and every target of the
//!   final scan's crate and `uaos-redact` in the release profile, both ways too (see [`BUILDS`]).
//!
//! Both run on Linux, macOS and Windows in CI. A file only another build reads (another target,
//! profile, mix of features, or a `cfg` none of these builds sets) is not seen. Neither is a file
//! a proc macro or a build script opens at run time, since rustc does not record it. The final
//! scan's crate has no build script, and its direct dependencies are pinned in arch.toml; for
//! other crates that stays review.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use cargo_metadata::diagnostic::DiagnosticLevel;
use cargo_metadata::{CargoOpt, Message, MetadataCommand, PackageId, TargetKind};

/// A build `cargo xtask sources` makes: its name, its arguments, and whether, run for the whole
/// workspace, it covers only [`RELEASE_PACKAGES`].
struct Build {
    name: &'static str,
    args: &'static [&'static str],
    t14_only: bool,
}

/// The builds `cargo xtask sources` makes beside the clippy gate's, so a `cfg` on `clippy`,
/// `debug_assertions` or a feature does not hide a file from every build the gates check. Default
/// features are what the test job builds; the features a shipped binary unifies are review until a
/// release job builds one. No workspace crate declares features today, so the builds with every
/// feature reuse the default ones.
const BUILDS: &[Build] = &[
    Build {
        name: "dev check",
        args: &[],
        t14_only: false,
    },
    Build {
        name: "dev check, all features",
        args: &["--all-features"],
        t14_only: false,
    },
    Build {
        name: "release check",
        args: &["--release"],
        t14_only: true,
    },
    Build {
        name: "release check, all features",
        args: &["--release", "--all-features"],
        t14_only: true,
    },
];

/// The packages whose release build the final scan's independence rests on: the scan's crate, and
/// `uaos-redact`, whose identity pins keep the type it re-exports the scan's own. Their closures
/// reach `aws-lc-sys` through `uaos-platform`, so the release check still builds it; a release
/// check of the whole workspace would add the rest, bundled SQLite among them, on three systems for
/// every merge.
const RELEASE_PACKAGES: &[&str] = &["uaos-redact-scan", "uaos-redact"];

/// Runs `cargo check` over `package` (the whole workspace when `None`) in each of [`BUILDS`],
/// and the check on each.
pub(crate) fn run(root: &Path, package: Option<&str>) -> Result<(), String> {
    for build_spec in BUILDS {
        let build = build_spec.name;
        let mut command = check_command(build_spec, package);
        println!("xtask: [sources] cargo check, {build}");
        // As the clippy gate: no compiler flags or wrapper from outside the workspace.
        let output = command
            .current_dir(root)
            .env("CARGO_ENCODED_RUSTFLAGS", "")
            .env("RUSTC_WRAPPER", "")
            .stderr(Stdio::inherit())
            .output()
            .map_err(|e| format!("[sources] could not start `cargo`: {e}"))?;
        if !output.status.success() {
            // With JSON output, rustc's errors arrive on stdout; show them.
            for message in Message::parse_stream(BufReader::new(output.stdout.as_slice())).flatten() {
                if let Message::CompilerMessage(compiler) = message
                    && compiler.message.level == DiagnosticLevel::Error
                    && let Some(rendered) = compiler.message.rendered
                {
                    eprint!("{rendered}");
                }
            }
            return Err(format!("[sources] the {build} failed ({})", output.status));
        }
        check_build(root, build, &output.stdout)?;
    }
    Ok(())
}

/// `cargo check` for one of [`BUILDS`], over `package`, or when `None` over the whole workspace
/// or, for a build that covers only them, [`RELEASE_PACKAGES`].
fn check_command(build: &Build, package: Option<&str>) -> Command {
    let mut command = Command::new("cargo");
    command
        .args(["check", "--all-targets", "--locked", "--message-format=json"])
        .args(build.args);
    match package {
        Some(name) => {
            command.args(["--package", name]);
        }
        None if build.t14_only => {
            for name in RELEASE_PACKAGES {
                command.args(["--package", name]);
            }
        }
        None => {
            command.arg("--workspace");
        }
    }
    command
}

/// Checks the dep-info of every local artifact named in `messages`, cargo's JSON output for the
/// build named `build`.
pub(crate) fn check_build(root: &Path, build: &str, messages: &[u8]) -> Result<(), String> {
    let odd = control_character_names(root)?;
    if !odd.is_empty() {
        return Err(format!(
            "[sources] names holding a control character, which a dep-info file cannot record \
             unambiguously:\n  {}",
            odd.join("\n  ")
        ));
    }
    let metadata = MetadataCommand::new()
        .current_dir(root)
        .features(CargoOpt::AllFeatures)
        .other_options(vec!["--locked".to_owned()])
        .exec()
        .map_err(|e| format!("[sources] cargo metadata: {e}"))?;
    // A package with no source is a local one: a workspace member, or a path dependency outside the
    // workspace.
    let local: BTreeSet<&PackageId> = metadata
        .packages
        .iter()
        .filter(|p| p.source.is_none())
        .map(|p| &p.id)
        .collect();
    // Clippy records the configuration it read, the workspace manifest (its lint table) and
    // `clippy.toml`, as dependencies; they configure the lints and compile nothing in.
    let configuration: BTreeSet<PathBuf> = ["Cargo.toml", "clippy.toml"]
        .iter()
        .filter_map(|name| canonical(&root.join(name)).ok())
        .collect();
    let messages = Message::parse_stream(BufReader::new(messages))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("[sources] reading cargo's output: {e}"))?;
    // The output directories each local package's build scripts were given: a package may read its
    // own build script's output, not another package's. Every one is kept, should a build run a
    // package's script more than once.
    let mut out_dirs: BTreeMap<&PackageId, Vec<PathBuf>> = BTreeMap::new();
    for message in &messages {
        if let Message::BuildScriptExecuted(script) = message
            && local.contains(&script.package_id)
        {
            out_dirs
                .entry(&script.package_id)
                .or_default()
                .push(canonical(script.out_dir.as_std_path())?);
        }
    }
    let mut checked = 0usize;
    let mut violations = Vec::new();
    for message in &messages {
        let Message::CompilerArtifact(artifact) = message else {
            continue;
        };
        if !local.contains(&artifact.package_id) {
            continue;
        }
        let crate_dir = canonical(
            artifact
                .manifest_path
                .as_std_path()
                .parent()
                .ok_or("[sources] a manifest path has no parent")?,
        )?;
        let own_outputs = out_dirs.get(&artifact.package_id).map_or(&[][..], Vec::as_slice);
        for resolved in files_read(root, artifact)? {
            if !resolved.starts_with(&crate_dir)
                && !own_outputs.iter().any(|out| resolved.starts_with(out))
                && !configuration.contains(&resolved)
            {
                violations.push(format!(
                    "{} (target `{}`, {build}) compiles in {}, outside its own directory",
                    crate::util::rel(root, &crate_dir),
                    artifact.target.name,
                    resolved.display()
                ));
            }
        }
        checked += 1;
    }
    if checked == 0 {
        return Err(format!("[sources] cargo reported no local artifact in the {build}"));
    }
    if violations.is_empty() {
        println!("xtask sources: {checked} local target(s) in the {build} read only their own crate's files");
        Ok(())
    } else {
        violations.sort();
        violations.dedup();
        Err(format!(
            "source taken from outside a crate:\n  {}",
            violations.join("\n  ")
        ))
    }
}

/// Every file rustc read for `artifact`, resolved through symlinks, from its dep-info file.
fn files_read(root: &Path, artifact: &cargo_metadata::Artifact) -> Result<BTreeSet<PathBuf>, String> {
    let build_script = artifact.target.kind.contains(&TargetKind::CustomBuild);
    let dep_info = dep_info_of(artifact.filenames.iter().map(|f| f.as_std_path()), build_script).ok_or_else(|| {
        format!(
            "[sources] no dep-info for `{}` (target `{}`): the files it read cannot be checked",
            artifact.package_id, artifact.target.name
        )
    })?;
    let text = std::fs::read_to_string(&dep_info).map_err(|e| format!("{}: {e}", dep_info.display()))?;
    let mut read = BTreeSet::new();
    for file in dependencies(&text).map_err(|e| format!("[sources] {}: {e}", dep_info.display()))? {
        let path = if file.is_absolute() { file } else { root.join(&file) };
        read.insert(canonical(&path)?);
    }
    // A dep-info file that does not list the target's own root was cut short or is not the
    // target's: it proves nothing.
    let target_root = canonical(artifact.target.src_path.as_std_path())?;
    if !read.contains(&target_root) {
        return Err(format!(
            "[sources] {} does not list the root of target `{}` ({}), so it cannot be trusted",
            dep_info.display(),
            artifact.target.name,
            target_root.display()
        ));
    }
    Ok(read)
}

/// The dep-info file rustc wrote beside an artifact: `deps/<name>-<hash>.d` beside
/// `deps/lib<name>-<hash>.rmeta` (or `.rlib`, or an executable `<name>-<hash>`), and for a build
/// script, the `build_script_build-<hash>.d` in its build directory.
fn dep_info_of<'a>(filenames: impl Iterator<Item = &'a Path>, build_script: bool) -> Option<PathBuf> {
    for file in filenames {
        let dir = file.parent()?;
        if build_script {
            let found = std::fs::read_dir(dir).ok()?.filter_map(Result::ok).find_map(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                (name.starts_with("build_script_build-") && name.ends_with(".d")).then(|| entry.path())
            });
            if found.is_some() {
                return found;
            }
            continue;
        }
        let stem = file.file_stem()?.to_string_lossy().into_owned();
        let name = stem.strip_prefix("lib").unwrap_or(&stem);
        let candidate = dir.join(format!("{name}.d"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// The files a dep-info file lists, read strictly. rustc writes one rule per output,
/// `<output>: <file> <file>...`, then each file again on a line of its own, `<file>:`, which reads
/// the same on every system (a drive letter's colon included); `#` lines record environment
/// variables. A space in a path is written `\ `, and nothing else is escaped. A line that is none
/// of these, or rules that list other files than the lines of their own, fail the check instead of
/// being skipped.
fn dependencies(text: &str) -> Result<Vec<PathBuf>, String> {
    let mut in_rules = BTreeSet::new();
    let mut on_own_lines = BTreeSet::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((_, files)) = line.split_once(": ") {
            in_rules.extend(split_escaped(files));
        } else if let Some([file]) = line.strip_suffix(':').map(split_escaped).as_deref() {
            on_own_lines.insert(file.clone());
        } else {
            return Err(format!("a dep-info line this check does not understand: {line:?}"));
        }
    }
    if in_rules.is_empty() || in_rules != on_own_lines {
        return Err("its rules and its lines of their own list different files".to_owned());
    }
    Ok(in_rules.into_iter().map(PathBuf::from).collect())
}

/// `text` split at each space that is not escaped as `\ `, with the escapes removed.
fn split_escaped(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut part = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&' ') => {
                part.push(' ');
                chars.next();
            }
            ' ' => {
                if !part.is_empty() {
                    parts.push(std::mem::take(&mut part));
                }
            }
            _ => part.push(c),
        }
    }
    if !part.is_empty() {
        parts.push(part);
    }
    parts
}

/// The paths under `root`, below the folders every file-walking check skips, whose name holds a
/// control character. rustc writes a path into a dep-info file as it is, so a newline in one could
/// make a line of it read as another file.
fn control_character_names(root: &Path) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.chars().any(char::is_control) {
                found.push(format!("{:?}", crate::util::rel(root, &path)));
                continue;
            }
            let file_type = entry.file_type().map_err(|e| format!("stat {}: {e}", path.display()))?;
            if file_type.is_dir() && !crate::util::skipped_dir(root, &dir, &path, &name) {
                stack.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

fn canonical(path: &Path) -> Result<PathBuf, String> {
    std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dep_info_lists_each_file_in_its_rules_and_on_a_line_of_its_own() {
        let text = "/t/deps/scan-1.d: crates/scan/src/lib.rs ../json/src/tape.rs C:\\w\\x.rs a\\ b.rs\n\n\
                    crates/scan/src/lib.rs:\n../json/src/tape.rs:\nC:\\w\\x.rs:\na\\ b.rs:\n\n\
                    # env-dep:CARGO_PKG_NAME=scan\n";
        let mut files = dependencies(text).unwrap();
        files.sort();
        // Sorted the same way: `Path` orders by component, and on Windows `C:\\` is a prefix that
        // sorts before `..`, so a literal order would hold on one system only.
        let mut expected = vec![
            PathBuf::from("../json/src/tape.rs"),
            PathBuf::from("C:\\w\\x.rs"),
            PathBuf::from("a b.rs"),
            PathBuf::from("crates/scan/src/lib.rs"),
        ];
        expected.sort();
        assert_eq!(files, expected);
    }

    /// A newline in a path splits a line; what follows must not pass as a file of the crate.
    #[test]
    fn a_line_it_does_not_understand_fails_the_check() {
        let split = "/t/x.d: src/x\ncrates/s/src/lib.rs\n\nsrc/x\ncrates/s/src/lib.rs:\n";
        assert!(dependencies(split).unwrap_err().contains("does not understand"));
        let unescaped = "/t/x.d: a.rs\n\na.rs b.rs:\n";
        assert!(dependencies(unescaped).is_err());
    }

    #[test]
    fn rules_and_own_lines_must_agree_and_list_something() {
        assert!(dependencies("/t/x.d: a.rs\n\nb.rs:\n").is_err());
        assert!(dependencies("/t/x.d: a.rs b.rs\n\na.rs:\n").is_err());
        assert!(dependencies("").is_err());
        assert!(dependencies("# env-dep:X=1\n").is_err());
    }

    /// What each build covers when no package is named.
    #[test]
    fn the_builds_cover_the_workspace_in_dev_and_the_t14_crates_in_release() {
        let args = |build: &Build, package| -> Vec<String> {
            check_command(build, package)
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        let names: Vec<&str> = BUILDS.iter().map(|b| b.name).collect();
        assert_eq!(
            names,
            [
                "dev check",
                "dev check, all features",
                "release check",
                "release check, all features"
            ]
        );
        for build in BUILDS {
            let all = args(build, None);
            let release = all.iter().any(|a| a == "--release");
            assert_eq!(release, build.t14_only, "{}", build.name);
            assert_eq!(
                all.iter().any(|a| a == "--all-features"),
                build.name.ends_with("all features")
            );
            if release {
                assert!(!all.iter().any(|a| a == "--workspace"), "{all:?}");
                for package in ["uaos-redact-scan", "uaos-redact"] {
                    assert!(
                        all.windows(2).any(|w| w[0] == "--package" && w[1] == package),
                        "{all:?}"
                    );
                }
            } else {
                assert!(all.iter().any(|a| a == "--workspace"), "{all:?}");
            }
            let one = args(build, Some("x"));
            assert!(
                one.windows(2).any(|w| w[0] == "--package" && w[1] == "x") && !one.contains(&"--workspace".to_owned())
            );
        }
    }

    #[test]
    fn only_an_escaped_space_stays_in_a_path() {
        assert_eq!(split_escaped("a\\ b c  d\\"), ["a b", "c", "d\\"]);
        assert_eq!(split_escaped("C:\\\\ x\\y"), ["C:\\ x\\y"]);
    }
}
