// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::Command;

/// Root of the workspace (the parent of the xtask crate).
///
/// Resolved at run time from the `CARGO_MANIFEST_DIR` that `cargo run` sets, falling back to
/// the compile-time value only when xtask is launched directly. A compile-time path alone is
/// wrong whenever the same binary is reused for another checkout (gate self-test copies).
pub(crate) fn workspace_root() -> PathBuf {
    let manifest_dir =
        std::env::var_os("CARGO_MANIFEST_DIR").map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from);
    manifest_dir.parent().map_or(manifest_dir.clone(), Path::to_path_buf)
}

/// Runs a command in `dir`, inheriting stdio, and fails with the step name if it fails.
pub(crate) fn run_step(dir: &Path, name: &str, program: &str, args: &[&str]) -> Result<(), String> {
    println!("xtask: [{name}] {program} {}", args.join(" "));
    let status = Command::new(program)
        .args(args)
        .current_dir(dir)
        .status()
        .map_err(|e| format!("[{name}] could not start `{program}`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("[{name}] failed ({status})"))
    }
}

/// Runs a command in `dir` and captures stdout; fails on non-zero exit.
pub(crate) fn capture(dir: &Path, program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("could not start `{program}`: {e}"))?;
    if out.status.success() {
        String::from_utf8(out.stdout).map_err(|e| format!("`{program}` produced non-UTF-8 output: {e}"))
    } else {
        Err(format!(
            "`{program} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Directories never scanned by file-walking checks.
pub(crate) const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// Recursively lists files under `root`, skipping [`SKIP_DIRS`] directly under it.
pub(crate) fn walk_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let file_type = entry.file_type().map_err(|e| format!("stat {}: {e}", path.display()))?;
            if file_type.is_dir() {
                if !skipped_dir(root, &dir, &path, &name) {
                    stack.push(path);
                }
            } else if file_type.is_file() {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Whether a file walk skips the folder `path`, named `name`, in `dir`. The root's build, VCS and
/// package folders are skipped, and any nested `target` folder Cargo marks as a build directory (a
/// signed `CACHEDIR.TAG`, as in `fuzz/target`); another nested folder with one of those names is
/// scanned. Only `target` qualifies: `.gitignore` ignores it at every depth, so nothing lands in
/// one without `git add -f`, while a tag committed in `docs/` or `src/` would hide that folder from
/// every check.
pub(crate) fn skipped_dir(root: &Path, dir: &Path, path: &Path, name: &str) -> bool {
    let build_output = name == "target" && is_cache_directory(path);
    build_output || dir == root && SKIP_DIRS.contains(&name)
}

/// Path relative to `root` with forward slashes, for stable messages.
pub(crate) fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// The signature line a cache directory tag starts with (<https://bford.info/cachedir/>); Cargo
/// writes it into every build directory it creates.
const CACHEDIR_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

/// `dir` holds a `CACHEDIR.TAG` that starts with the standard signature. The caller also requires
/// the folder to be named `target`: the signature is public, so it alone proves nothing.
fn is_cache_directory(dir: &Path) -> bool {
    std::fs::read(dir.join("CACHEDIR.TAG")).is_ok_and(|tag| tag.starts_with(CACHEDIR_SIGNATURE))
}
