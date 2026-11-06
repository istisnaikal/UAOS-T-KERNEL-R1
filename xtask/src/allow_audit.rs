// SPDX-License-Identifier: Apache-2.0

//! Where guarded lints may be switched off.
//!
//! The workspace denies `unsafe_code`, and `clippy.toml` bans ambient clocks, randomness,
//! filesystem, process and thread APIs outside their owning crates. Both can be undone by a
//! single `#[allow(...)]` anywhere, and that would make every other gate decorative. This check
//! finds every `#[allow(...)]` / `#[expect(...)]` (inner or outer, including inside `cfg_attr`)
//! that names a guarded lint, and fails unless the file sits under one of that lint's owner
//! paths in `arch.toml` `[allow_audit]`.
//!
//! Lints can also be switched off where no attribute shows: a `clippy.toml` below the root replaces
//! the root's bans for its crate, a member's own `[lints]` replaces the workspace's, and Cargo
//! configuration can point clippy elsewhere or pass lint flags. Those fail here too, and so does a
//! `clippy.toml` ban without a canary in the ban canary files.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use cargo_metadata::{DependencyKind, MetadataCommand};
use serde::Deserialize;

use crate::util::{rel, walk_files};

#[derive(Debug, Deserialize)]
struct ArchFile {
    allow_audit: BTreeMap<String, Vec<String>>,
}

/// The bans in `clippy.toml`, in any layout TOML allows.
#[derive(Debug, Deserialize)]
struct ClippyFile {
    #[serde(rename = "disallowed-methods", default)]
    methods: Vec<Ban>,
    #[serde(rename = "disallowed-types", default)]
    types: Vec<Ban>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Ban {
    Path(String),
    Entry { path: String },
}

impl Ban {
    fn path(&self) -> &str {
        match self {
            Self::Path(p) | Self::Entry { path: p } => p,
        }
    }
}

/// Where every `clippy.toml` ban has its canary: a call of the banned item under `#[expect]`,
/// marked by a `// canary:` comment that names the path in backticks.
const CANARY_FILES: &[&str] = &["crates/uaos-egress/tests/bans.rs", "crates/uaos-platform/tests/bans.rs"];

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(root.join("arch.toml")).map_err(|e| format!("arch.toml: {e}"))?;
    let arch: ArchFile = toml::from_str(&text).map_err(|e| format!("arch.toml [allow_audit]: {e}"))?;
    let owners = arch.allow_audit;
    let io_owners = owners.get("clippy::disallowed_methods").cloned().unwrap_or_default();

    let files = walk_files(root)?;
    let mut violations = config_overrides(root, &files)?;
    violations.extend(canary_gaps(root)?);
    let mut found = 0usize;
    for path in files {
        // In any case: Windows and macOS compile `x.RS` for `mod x;`.
        if !path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("rs"))
        {
            continue;
        }
        let relative = rel(root, &path);
        let source = std::fs::read_to_string(&path).map_err(|e| format!("{relative}: {e}"))?;
        let code = masked(&source);
        // Any mention in code, not only in an attribute: a macro can build the attribute from its
        // arguments, and a lint group or an old name switches the lint off too.
        for (lint, patterns) in &owners {
            let owned = patterns.iter().any(|p| path_matches(p, &relative));
            for word in switches(lint) {
                for (line, at) in word_positions(&code, &word) {
                    // `deny(...)` and `forbid(...)` only make a lint stricter.
                    if matches!(enclosing_call(&code, at), "deny" | "forbid") {
                        continue;
                    }
                    found += 1;
                    if !owned {
                        violations.push(format!(
                            "{relative}:{line}: names `{word}`, which can switch `{lint}` off, outside its owners ({})",
                            patterns.join(", ")
                        ));
                    }
                }
            }
        }
        // Code compiled from a file elsewhere would be judged by the wrong file's path.
        if !io_owners.iter().any(|p| path_matches(p, &relative)) {
            for line in path_attribute_lines(&code) {
                violations.push(format!(
                    "{relative}:{line}: a `#[path]` module outside the owners of `clippy::disallowed_methods`"
                ));
            }
            for line in word_lines(&code, "include") {
                if include_at(&code, line) {
                    violations.push(format!(
                        "{relative}:{line}: `include!` outside the owners of `clippy::disallowed_methods`"
                    ));
                } else {
                    // `use core::include as pull;` and then `pull!(..)` (over the closing fixes).
                    violations.push(format!(
                        "{relative}:{line}: `include` named outside the owners of `clippy::disallowed_methods`, where a `use` can rename the macro"
                    ));
                }
            }
        }
    }
    if violations.is_empty() {
        println!(
            "xtask allow-audit: {found} guarded-lint mention(s), all inside their owners; no lint override in configuration; every ban has a well-formed canary"
        );
        Ok(())
    } else {
        Err(format!(
            "{} way(s) to switch a guarded lint off outside its owners (arch.toml [allow_audit]):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ))
    }
}

/// The words that switch `lint` off: its name, its old name and the groups that contain it.
fn switches(lint: &str) -> Vec<String> {
    let mut words = vec![short_name(lint).to_owned()];
    if let Some(old) = short_name(lint).strip_suffix('s')
        && lint.starts_with("clippy::disallowed_")
    {
        words.push(old.to_owned());
    }
    if lint.starts_with("clippy::disallowed_") {
        words.extend(["clippy::all".to_owned(), "clippy::style".to_owned()]);
    }
    words
}

/// `source` with every string, char literal and comment replaced by spaces, newlines kept.
pub(crate) fn masked(source: &str) -> String {
    blanked(source, true)
}

/// `source` with every comment, and every string and char literal if `literals`, replaced by
/// spaces, newlines kept.
fn blanked(source: &str, literals: bool) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0usize;
    while let Some(&c) = chars.get(i) {
        let skipped = skip_literal_or_comment(&chars, i);
        if skipped > i {
            // Comments start with `/`; nothing else `skip_literal_or_comment` skips does.
            let blank = literals || c == '/';
            for k in i..skipped {
                let kept = chars.get(k).copied().unwrap_or(' ');
                out.push(if blank && kept != '\n' { ' ' } else { kept });
            }
            i = skipped;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Whether `path` (`a::b::C`) occurs in `code` whole, not as the tail of a longer path or
/// identifier.
fn path_occurs(code: &str, path: &str) -> bool {
    code.match_indices(path).any(|(at, _)| {
        let before = code.get(..at).and_then(|s| s.chars().next_back());
        let after = code.get(at + path.len()..).and_then(|s| s.chars().next());
        !before.is_some_and(|c| c == ':' || is_ident_char(Some(c))) && !is_ident_char(after)
    })
}

/// The 1-based lines on which `word` occurs in `code` as a whole word.
fn word_lines(code: &str, word: &str) -> Vec<usize> {
    word_positions(code, word).into_iter().map(|(line, _)| line).collect()
}

/// `(1-based line, byte offset)` of every whole-word occurrence of `word` in `code`.
pub(crate) fn word_positions(code: &str, word: &str) -> Vec<(usize, usize)> {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    code.match_indices(word)
        .filter(|(at, _)| {
            let before = code.get(..*at).and_then(|s| s.chars().next_back());
            let after = code.get(at + word.len()..).and_then(|s| s.chars().next());
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
        .map(|(at, _)| (code.get(..at).map_or(0, |s| s.matches('\n').count()) + 1, at))
        .collect()
}

/// The name before the innermost unclosed `(` that contains byte `at` of `code` (`allow` in
/// `allow(clippy::x)`), or `""` when none does.
fn enclosing_call(code: &str, at: usize) -> &str {
    let before = code.get(..at).unwrap_or_default();
    let mut depth = 0usize;
    for (i, c) in before.char_indices().rev() {
        match c {
            ')' => depth += 1,
            '(' if depth == 0 => {
                let head = before.get(..i).unwrap_or_default().trim_end();
                let start = head
                    .char_indices()
                    .rev()
                    .take_while(|(_, c)| c.is_ascii_alphanumeric() || *c == '_')
                    .last()
                    .map_or(head.len(), |(k, _)| k);
                return head.get(start..).unwrap_or_default();
            }
            '(' => depth -= 1,
            _ => {}
        }
    }
    ""
}

/// Whether the line holds `include!` (the macro, not an identifier named `include`).
fn include_at(code: &str, line: usize) -> bool {
    code.lines().nth(line - 1).is_some_and(|l| {
        l.match_indices("include").any(|(at, _)| {
            let rest = l.get(at + "include".len()..).unwrap_or_default().trim_start();
            let before = l.get(..at).and_then(|s| s.chars().next_back());
            rest.starts_with('!') && !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        })
    })
}

/// The 1-based lines with a `#[path = ...]` or `#![path = ...]` attribute.
fn path_attribute_lines(code: &str) -> Vec<usize> {
    code.lines()
        .enumerate()
        .filter(|(_, l)| {
            l.match_indices('#').any(|(at, _)| {
                let rest = l.get(at + 1..).unwrap_or_default().trim_start();
                let rest = rest.strip_prefix('!').unwrap_or(rest).trim_start();
                rest.strip_prefix('[')
                    .map(str::trim_start)
                    .and_then(|r| r.strip_prefix("path"))
                    .is_some_and(|r| r.trim_start().starts_with('='))
            })
        })
        .map(|(n, _)| n + 1)
        .collect()
}

/// Lint switches outside attributes:
/// * a `clippy.toml` below the root, or one named in another case (Windows and macOS match
///   names regardless of case);
/// * Cargo configuration holding anything but `[alias]`, in any `.cargo` folder, in any case;
/// * a build script, wherever `build = "..."` puts it, setting clippy's environment for the
///   compiler;
/// * CI workflows setting compiler flags, a compiler wrapper or clippy's configuration;
/// * a workspace member (as Cargo sees them, path dependencies included) whose `[lints]` is not
///   exactly `workspace = true`;
/// * the workspace lint table not denying a guarded lint, or allowing a group that contains one.
fn config_overrides(root: &Path, files: &[PathBuf]) -> Result<Vec<String>, String> {
    let mut problems = Vec::new();
    for path in files {
        let relative = rel(root, path);
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let parent = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if (name == "clippy.toml" || name == ".clippy.toml") && relative != "clippy.toml" {
            problems.push(format!(
                "{relative}: a clippy.toml below the root, or named in another case, replaces the root's bans"
            ));
        }
        if parent == ".cargo" && (name == "config" || name == "config.toml") {
            let doc = read_toml(root, path)?;
            for key in doc.as_table().into_iter().flat_map(|t| t.keys()) {
                if key != "alias" {
                    problems.push(format!(
                        "{relative}: `{key}` is not allowed; Cargo configuration holds only [alias], since other keys can change lint levels, compiler flags or clippy's configuration"
                    ));
                }
            }
        }
    }
    let metadata = MetadataCommand::new()
        .manifest_path(root.join("Cargo.toml"))
        .no_deps()
        .exec()
        .map_err(|e| format!("cargo metadata: {e}"))?;
    for package in &metadata.packages {
        // Cargo's own list of build scripts: `build.rs`, or the file `build = "..."` names.
        for script in package.targets.iter().filter(|t| t.is_custom_build()) {
            let path = script.src_path.as_std_path();
            let relative = rel(root, path);
            let text = std::fs::read_to_string(path).map_err(|e| format!("{relative}: {e}"))?;
            if names_clippy_variable(&text) {
                problems.push(format!(
                    "{relative}: a build script names one of clippy's variables, so it could set them for the compiler"
                ));
            }
            // The check reads this file only, so a build script stays one file, in owner crates
            // too, where `#[path]` and `include!` are otherwise allowed.
            if uses_another_file(&text) {
                problems.push(format!(
                    "{relative}: a build script uses another file (a `mod` in another file, `#[path]` or an `include` macro), which this check does not read; keep it to one file"
                ));
            }
        }
        // A path dependency's code runs inside the build script, where this check does not read it.
        for dep in package.dependencies.iter().filter(|d| d.kind == DependencyKind::Build) {
            if dep.path.is_some() {
                problems.push(format!(
                    "{}: build dependency `{}` is a path dependency, whose code runs in the build script unchecked",
                    rel(root, package.manifest_path.as_std_path()),
                    dep.name
                ));
            }
        }
        let manifest = package.manifest_path.as_std_path();
        let doc = read_toml(root, manifest)?;
        let inherits = doc
            .get("lints")
            .and_then(toml::Value::as_table)
            .is_some_and(|t| t.len() == 1 && t.get("workspace").and_then(toml::Value::as_bool) == Some(true));
        if !inherits {
            problems.push(format!(
                "{}: [lints] must be exactly `workspace = true`, or the workspace's guarded lints do not apply",
                rel(root, manifest)
            ));
        }
    }
    let workspace = read_toml(root, &root.join("Cargo.toml"))?;
    let lints = workspace.get("workspace").and_then(|w| w.get("lints"));
    let level_of = |table: &str, key: &str| -> Option<String> {
        match lints.and_then(|l| l.get(table)).and_then(|t| t.get(key)) {
            Some(toml::Value::String(s)) => Some(s.clone()),
            Some(toml::Value::Table(t)) => t.get("level").and_then(toml::Value::as_str).map(str::to_owned),
            _ => None,
        }
    };
    for (table, lint) in [
        ("clippy", "disallowed_methods"),
        ("clippy", "disallowed_types"),
        ("rust", "unsafe_code"),
    ] {
        if !matches!(level_of(table, lint).as_deref(), Some("deny" | "forbid")) {
            problems.push(format!("Cargo.toml: [workspace.lints.{table}] must deny `{lint}`"));
        }
    }
    for key in ["all", "style", "disallowed_method", "disallowed_type"] {
        if let Some(level @ ("allow" | "expect")) = level_of("clippy", key).as_deref() {
            problems.push(format!(
                "Cargo.toml: [workspace.lints.clippy] `{key}` set to `{level}` switches a guarded lint off"
            ));
        }
    }
    Ok(problems)
}

/// Whether a build script names one of clippy's variables (`CLIPPY_ARGS`, `CLIPPY_CONF_DIR`, in any
/// case: Windows matches variable names regardless of case) in its code or strings, which it could
/// set for the compiler (`cargo:rustc-env`), also through a helper that builds the line. Comments
/// and lint paths (`clippy::...`) do not count.
fn names_clippy_variable(build_script: &str) -> bool {
    blanked(build_script, false).to_ascii_uppercase().contains("CLIPPY_")
}

/// Whether `source` uses code or text from another file, in code: a module in another file
/// (`mod name;`), a `#[path = ...]` attribute, or `include!`, `include_str!` or
/// `include_bytes!`.
fn uses_another_file(source: &str) -> bool {
    let code = masked(source);
    let file_module = word_positions(&code, "mod").into_iter().any(|(_, at)| {
        let rest = code.get(at + "mod".len()..).unwrap_or_default().trim_start();
        let ident_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        ident_len > 0 && rest.get(ident_len..).unwrap_or_default().trim_start().starts_with(';')
    });
    let include = ["include", "include_str", "include_bytes"].iter().any(|name| {
        word_positions(&code, name).into_iter().any(|(_, at)| {
            code.get(at + name.len()..)
                .unwrap_or_default()
                .trim_start()
                .starts_with('!')
        })
    });
    file_module || include || !path_attribute_lines(&code).is_empty()
}

fn read_toml(root: &Path, path: &Path) -> Result<toml::Value, String> {
    let relative = rel(root, path);
    let text = std::fs::read_to_string(path).map_err(|e| format!("{relative}: {e}"))?;
    toml::from_str(&text).map_err(|e| format!("{relative}: {e}"))
}

/// Problems with the canaries of the bans in `clippy.toml` (see [`canary_problems`]).
fn canary_gaps(root: &Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(root.join("clippy.toml")).map_err(|e| format!("clippy.toml: {e}"))?;
    let files = CANARY_FILES
        .iter()
        .map(|f| {
            std::fs::read_to_string(root.join(f))
                .map(|t| (*f, t))
                .map_err(|e| format!("{f}: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    canary_problems(&text, &files)
}

/// Every ban needs a canary: a `// canary:` marker naming it, at the top of a function whose only
/// `#[expect]` names a disallowed lint, followed by the banned item within three lines, spelled by
/// its own path in code: its name after the marker, and either the full path of its type (a method)
/// or its whole path (an item in a module) there or in the function's signature. A call of another
/// ban with the same name or in the same module does not count, nor does a module-level import, and
/// no other ban of the same lint may appear anywhere in the function. Canary files compile only
/// under `cfg(unix)` or `cfg(windows)`, which CI's systems cover.
fn canary_problems(clippy_toml: &str, files: &[(&str, String)]) -> Result<Vec<String>, String> {
    let config: ClippyFile = toml::from_str(clippy_toml).map_err(|e| format!("clippy.toml: {e}"))?;
    let mut problems = Vec::new();
    for (file, text) in files {
        for (n, line) in text.lines().enumerate() {
            let t = line.trim_start();
            let cfg = t.starts_with("#[cfg") || t.starts_with("#![cfg");
            if cfg && t != "#[cfg(unix)]" && t != "#[cfg(windows)]" {
                problems.push(format!(
                    "{file}:{}: canaries compile only under `cfg(unix)` or `cfg(windows)`",
                    n + 1
                ));
            }
        }
    }
    for (ban, list) in config
        .methods
        .iter()
        .map(|b| (b, &config.methods))
        .chain(config.types.iter().map(|b| (b, &config.types)))
    {
        let path = ban.path();
        let marker = format!("// canary: `{path}`");
        let found = files.iter().find_map(|(file, text)| {
            let lines: Vec<&str> = text.lines().collect();
            lines
                .iter()
                .position(|l| l.trim() == marker)
                .map(|at| (*file, lines, at))
        });
        match found {
            None => problems.push(format!(
                "clippy.toml: `{path}` has no canary in {}",
                CANARY_FILES.join(" or ")
            )),
            Some((file, lines, at)) => {
                if !well_formed(&lines, at, path) {
                    problems.push(format!(
                        "{file}:{}: the canary for `{path}` is not one banned call spelled by its own path (a method's type path, an item's module path) in a function whose only `#[expect]` names a disallowed lint",
                        at + 1
                    ));
                } else if let Some(other) = other_ban_in(&lines, at, path, list) {
                    problems.push(format!(
                        "{file}:{}: the canary for `{path}` also uses `{other}`, another ban of the same lint, which keeps its expectation fulfilled if its own ban stops firing",
                        at + 1
                    ));
                }
            }
        }
    }
    Ok(problems)
}

/// The line of the `fn` a canary marker sits at the top of: one or two lines above it.
fn function_line(lines: &[&str], marker: usize) -> Option<usize> {
    (marker.saturating_sub(2)..marker)
        .rev()
        .find(|&k| lines.get(k).is_some_and(|l| l.trim_start().starts_with("fn ")))
}

/// The function that starts at line `function`, up to its closing brace, comments and strings
/// masked.
fn function_code(lines: &[&str], function: usize) -> String {
    let code = masked(&lines.get(function..).unwrap_or_default().join("\n"));
    let mut depth = 0usize;
    for (at, c) in code.char_indices() {
        match c {
            '{' => depth += 1,
            '}' if depth == 1 => return code.get(..=at).unwrap_or_default().to_owned(),
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    code
}

/// Whether `code` spells the banned item `path` by its own path: its name as a whole word, and
/// a method's full type path or an item's whole module path.
fn spells(code: &str, path: &str) -> bool {
    let name = path.rsplit("::").next().unwrap_or(path);
    let pinned = match path.rsplit_once("::") {
        Some((owner, _))
            if owner
                .rsplit("::")
                .next()
                .and_then(|segment| segment.chars().next())
                .is_some_and(char::is_uppercase) =>
        {
            path_occurs(code, owner)
        }
        _ => path_occurs(code, path),
    };
    pinned && !word_lines(code, name).is_empty()
}

/// Another ban of the same list that the canary function for `path` spells anywhere in its
/// signature or body: a setup call or a second call would keep the shared `#[expect]` fulfilled
/// when the canary's own ban stops firing.
fn other_ban_in(lines: &[&str], marker: usize, path: &str, list: &[Ban]) -> Option<String> {
    let code = function_code(lines, function_line(lines, marker)?);
    list.iter()
        .map(Ban::path)
        .find(|other| *other != path && spells(&code, other))
        .map(str::to_owned)
}

fn well_formed(lines: &[&str], marker: usize, path: &str) -> bool {
    let name = path.rsplit("::").next().unwrap_or(path);
    let Some(function) = function_line(lines, marker) else {
        return false;
    };
    let attributes: Vec<&str> = lines
        .get(..function)
        .unwrap_or_default()
        .iter()
        .rev()
        .take_while(|l| l.trim_start().starts_with("#["))
        .copied()
        .collect();
    let expects: Vec<&&str> = attributes.iter().filter(|l| l.contains("#[expect(")).collect();
    let names_disallowed = expects.iter().all(|l| l.contains("clippy::disallowed_"));
    // The signature and the three lines after the marker, comments and strings masked, so
    // neither the marker nor a comment names the item.
    let code = masked(
        &lines
            .get(function..(marker + 4).min(lines.len()))
            .unwrap_or_default()
            .join("\n"),
    );
    let after: Vec<&str> = code.lines().skip(marker + 1 - function).collect();
    let calls = !word_lines(&after.join("\n"), name).is_empty();
    // std and tokio share type and method names, and sibling canaries share modules, so the owner's
    // name alone does not pin the item: a method needs its type's full path, an item in a module
    // its whole path.
    expects.len() == 1 && names_disallowed && calls && spells(&code, path)
}

/// `clippy::disallowed_methods` → `disallowed_methods`; `unsafe_code` stays as is.
fn short_name(lint: &str) -> &str {
    lint.rsplit("::").next().unwrap_or(lint)
}

/// If a string, raw string, char literal or comment starts at `i`, returns the index just past
/// it; otherwise returns `i`. Lifetimes (`'a`) are not literals.
fn skip_literal_or_comment(chars: &[char], i: usize) -> usize {
    let at = |k: usize| chars.get(k).copied();
    match (at(i), at(i + 1)) {
        (Some('/'), Some('/')) => (i..chars.len()).find(|&k| at(k) == Some('\n')).unwrap_or(chars.len()),
        (Some('/'), Some('*')) => {
            let mut depth = 0usize;
            let mut k = i;
            while k < chars.len() {
                match (at(k), at(k + 1)) {
                    (Some('/'), Some('*')) => {
                        depth += 1;
                        k += 2;
                    }
                    (Some('*'), Some('/')) => {
                        depth -= 1;
                        k += 2;
                        if depth == 0 {
                            return k;
                        }
                    }
                    _ => k += 1,
                }
            }
            chars.len()
        }
        (Some('"'), _) => end_of_quoted(chars, i + 1),
        (Some('b' | 'c'), Some('"')) => end_of_quoted(chars, i + 2),
        (Some('r' | 'b' | 'c'), _) if !is_ident_char(i.checked_sub(1).and_then(at)) => {
            // r"..", r#".."#, br"..", br#".."#, cr"..", cr#".."#: C strings too, or a raw one read
            // as escaped would end the literal early and hide what follows.
            let mut k = i + 1;
            if matches!(at(i), Some('b' | 'c')) {
                if at(k) != Some('r') {
                    return i;
                }
                k += 1;
            }
            let hashes = (k..chars.len()).take_while(|&p| at(p) == Some('#')).count();
            k += hashes;
            if at(k) != Some('"') {
                return i;
            }
            k += 1;
            while k < chars.len() {
                if at(k) == Some('"') && (1..=hashes).all(|h| at(k + h) == Some('#')) {
                    return k + 1 + hashes;
                }
                k += 1;
            }
            chars.len()
        }
        (Some('\''), Some('\\')) => (i + 2..chars.len())
            .find(|&k| at(k) == Some('\''))
            .map_or(chars.len(), |k| k + 1),
        (Some('\''), Some(_)) if at(i + 2) == Some('\'') => i + 3,
        _ => i,
    }
}

fn end_of_quoted(chars: &[char], mut k: usize) -> usize {
    while let Some(c) = chars.get(k) {
        match c {
            '\\' => k += 2,
            '"' => return k + 1,
            _ => k += 1,
        }
    }
    chars.len()
}

fn is_ident_char(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Owner patterns are path prefixes; a `*` segment matches exactly one path segment.
fn path_matches(pattern: &str, path: &str) -> bool {
    let mut pattern_parts = pattern.split('/').peekable();
    let mut path_parts = path.split('/');
    while let Some(p) = pattern_parts.next() {
        let last = pattern_parts.peek().is_none();
        if last && p.is_empty() {
            // Trailing slash: a directory prefix; everything below it matches.
            return true;
        }
        let Some(segment) = path_parts.next() else {
            return false;
        };
        let ok = if p == "*" {
            true
        } else if last {
            // Final pattern segment without a trailing slash: an exact file, or a file-name
            // prefix such as `real` matching `real.rs` and the `real/` directory.
            segment == p || segment.starts_with(p)
        } else {
            segment == p
        };
        if !ok {
            return false;
        }
        if last {
            return true;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A raw C string ending in a backslash.
    #[test]
    fn c_strings_are_literals() {
        let code = masked("const A: &CStr = cr\"\\\";\nhidden();\nconst B: &CStr = c\"x\\\"y\";\nseen();\n");
        assert!(code.contains("hidden()"), "{code}");
        assert!(code.contains("seen()"), "{code}");
        assert!(!code.contains('x'), "{code}");
    }

    #[test]
    fn finds_single_and_multi_line_mentions() {
        let code = masked(
            "#![allow(\n    clippy::print_stdout,\n    clippy::disallowed_methods,\n)]\nfn f() {}\n#[cfg_attr(test, allow(unsafe_code))]\nfn g() {}\n",
        );
        assert_eq!(word_lines(&code, "disallowed_methods"), vec![3]);
        assert_eq!(word_lines(&code, "unsafe_code"), vec![6]);
    }

    #[test]
    fn the_enclosing_call_tells_stricter_from_weaker() {
        let code = "#![forbid(unsafe_code)]\n#[allow(\n    clippy::style,\n)]\nm!(allow(x(y), clippy::all));\n";
        let at = |w: &str| code.find(w).unwrap();
        assert_eq!(enclosing_call(code, at("unsafe_code")), "forbid");
        assert_eq!(enclosing_call(code, at("clippy::style")), "allow");
        assert_eq!(enclosing_call(code, at("clippy::all")), "allow");
        assert_eq!(enclosing_call("disallowed_methods", 0), "");
    }

    #[test]
    fn literals_and_comments_are_not_code() {
        let src = concat!(
            "let s = \"#[allow(unsafe_code)]\";\n",
            "let r = r#\"#![allow(unsafe_code)]\"#;\n",
            "// #[allow(unsafe_code)]\n",
            "/* #[allow(unsafe_code)] */\n",
            "let c = '#'; fn f<'a>(x: &'a u8) {}\n",
            "#[allow(clippy::disallowed_methods)]\n",
        );
        let code = masked(src);
        assert!(word_lines(&code, "unsafe_code").is_empty());
        assert_eq!(word_lines(&code, "disallowed_methods"), vec![6]);
    }

    #[test]
    fn word_boundaries() {
        assert_eq!(word_lines("allow(unsafe_code)", "unsafe_code"), vec![1]);
        assert!(word_lines("forbid(unsafe_code_x)", "unsafe_code").is_empty());
        assert!(word_lines("disallowed_methods_extra", "disallowed_methods").is_empty());
    }

    #[test]
    fn owner_patterns() {
        assert!(path_matches(
            "crates/uaos-platform/src/real",
            "crates/uaos-platform/src/real.rs"
        ));
        assert!(path_matches(
            "crates/uaos-platform/src/real",
            "crates/uaos-platform/src/real/fs.rs"
        ));
        assert!(!path_matches(
            "crates/uaos-platform/src/real",
            "crates/uaos-platform/src/sim.rs"
        ));
        assert!(path_matches("crates/*/tests/", "crates/uaos-ledger/tests/ledger.rs"));
        assert!(!path_matches("crates/*/tests/", "crates/uaos-ledger/src/lib.rs"));
        assert!(path_matches("xtask/", "xtask/src/main.rs"));
        assert!(!path_matches(
            "crates/uaos-platform/src/os/",
            "crates/uaos-policy/src/os/x.rs"
        ));
    }

    const CANARY: &str = "    #[expect(clippy::disallowed_methods, reason = \"canary\")]\n    fn c_d() {\n        // canary: `c::d`\n        let _canary = c::d();\n    }\n";

    /// Every layout TOML allows is read, not only `path = "...` with spaces.
    #[test]
    fn every_ban_layout_needs_a_canary() {
        let config = "disallowed-methods = [\n  { path=\"a::b\", reason = \"x\" }, { path = \"c::d\" },\n  \"e::f\",\n]\ndisallowed-types = [{ path = \"g::H\" }]\nallow-unwrap-in-tests = true\n";
        let problems = canary_problems(config, &[("bans.rs", CANARY.to_owned())]).unwrap();
        assert_eq!(problems.len(), 3, "{problems:?}");
        for missing in ["`a::b`", "`e::f`", "`g::H`"] {
            assert!(problems.iter().any(|p| p.contains(missing)), "{missing}: {problems:?}");
        }
    }

    /// A canary that calls another banned item whose name contains its own does not count.
    #[test]
    fn a_canary_must_call_its_own_item() {
        let config = "disallowed-methods = [\"a::S::send_to\"]\n";
        let canary = |call: &str| {
            CANARY
                .replace("fn c_d()", "fn c_d(x: &a::S)")
                .replace("c::d()", call)
                .replace("`c::d`", "`a::S::send_to`")
        };
        assert_eq!(
            canary_problems(config, &[("bans.rs", canary("x.try_send_to()"))])
                .unwrap()
                .len(),
            1
        );
        assert!(
            canary_problems(config, &[("bans.rs", canary("x.send_to()"))])
                .unwrap()
                .is_empty()
        );
    }

    /// A canary spells its own item's path in code: a method's full type path, an item in a module
    /// its whole path. Another ban with the same name, a type of the same name in another crate
    /// (std and tokio), a sibling in the same module, an import or a comment does not count.
    #[test]
    fn a_canary_must_spell_its_own_path() {
        let check = |config: &str, text: String| canary_problems(config, &[("bans.rs", text)]).unwrap().len();
        let canary =
            |marker: &str, call: &str| CANARY.replace("`c::d`", &format!("`{marker}`")).replace("c::d()", call);
        let method = "disallowed-methods = [\"a::Server::create\"]\n";
        let server = |call: &str| canary("a::Server::create", call);
        assert_eq!(check(method, server("a::Server::new().create()")), 0);
        assert_eq!(check(method, server("Server::new().create()")), 1, "through an import");
        assert_eq!(
            check(method, server("b::Server::new().create()")),
            1,
            "a type of the same name"
        );
        assert_eq!(check(method, server("std::fs::File::create()")), 1, "another ban");
        assert_eq!(check(method, server("File::create() // a::Server")), 1, "a comment");
        let in_signature = server("s.create()").replace("fn c_d()", "fn c_d(s: &a::Server)");
        assert_eq!(check(method, in_signature), 0);
        let function = "disallowed-methods = [\"a::task::spawn_blocking\"]\n";
        let blocking = |call: &str| canary("a::task::spawn_blocking", call);
        assert_eq!(check(function, blocking("a::task::spawn_blocking(f)")), 0);
        assert_eq!(check(function, blocking("spawn_blocking(f)")), 1, "through an import");
        let sibling = blocking("set.spawn_blocking(f)").replace("fn c_d()", "fn c_d(set: &mut a::task::JoinSet)");
        assert_eq!(check(function, sibling), 1, "a sibling in the same module");
    }

    /// No other ban of the same lint anywhere in the canary function, so neither a setup call nor a
    /// later call can keep the shared expectation fulfilled; a ban of the other lint (a banned type
    /// in a method canary's signature) does not count.
    #[test]
    fn a_canary_uses_no_other_ban_of_its_lint() {
        let config = "disallowed-methods = [\"a::S::connect\", \"a::S::unbound\"]\ndisallowed-types = [\"a::S\"]\n";
        let unbound = "    #[expect(clippy::disallowed_methods, reason = \"canary\")]\n    fn s_unbound() {\n        // canary: `a::S::unbound`\n        let _canary = a::S::unbound();\n    }\n    #[expect(clippy::disallowed_types, reason = \"canary\")]\n    fn s_type() {\n        // canary: `a::S`\n        let _canary: Option<a::S> = None;\n    }\n";
        let connect = |body: &str| {
            format!(
                "    #[expect(clippy::disallowed_methods, reason = \"canary\")]\n    fn s_connect(s: &a::S) {{\n        // canary: `a::S::connect`\n{body}    }}\n{unbound}"
            )
        };
        let check = |body: &str| canary_problems(config, &[("bans.rs", connect(body))]).unwrap();
        assert!(check("        let _canary = s.connect();\n").is_empty());
        let setup = check("        let t = a::S::unbound();\n        let _canary = t.connect();\n");
        assert_eq!(setup.len(), 1, "{setup:?}");
        assert!(setup[0].contains("also uses `a::S::unbound`"), "{setup:?}");
        let later = check("        let _canary = s.connect();\n\n\n\n\n        let _later = a::S::unbound();\n");
        assert_eq!(later.len(), 1, "a call past the third line: {later:?}");
        assert!(
            check("        let _canary = s.connect(); // a::S::unbound()\n").is_empty(),
            "a comment"
        );
    }

    /// A path occurs whole, not inside a longer identifier or path.
    #[test]
    fn a_path_occurs_only_whole() {
        assert!(path_occurs("let f = std::fs::File::open(p);", "std::fs::File"));
        assert!(path_occurs("(std::fs::File)", "std::fs::File"));
        assert!(
            !path_occurs("let t: std::fs::FileType;", "std::fs::File"),
            "a longer identifier"
        );
        assert!(!path_occurs("let p: std::path::PathBuf;", "std::path::Path"));
        assert!(!path_occurs("tokio::task::spawn_blocking(f)", "tokio::task::spawn"));
        assert!(
            !path_occurs("a::std::fs::File::open(p)", "std::fs::File"),
            "a longer path"
        );
    }

    /// A build script that uses another file.
    #[test]
    fn a_build_script_using_another_file_is_found() {
        assert!(uses_another_file("mod build_env;\nfn main() {}\n"));
        assert!(uses_another_file("pub mod emit ;\n"));
        assert!(uses_another_file("include!(\"build_env.rs\");\nfn main() {}\n"));
        assert!(uses_another_file(
            "fn main() {\n    let s = include_str !(\"env.txt\");\n}\n"
        ));
        assert!(uses_another_file("#[path = \"env.rs\"]\nmod env;\n"));
        assert!(!uses_another_file(
            "mod inline {\n    pub fn f() {}\n}\nfn include_all() {}\n"
        ));
        assert!(!uses_another_file(
            "// mod build_env;\nlet s = \"mod x;\";\nfn modx() {}\n"
        ));
    }

    /// A build script naming one of clippy's variables, in any case, directly or through a helper
    /// that builds the line; a comment, a lint path or prose naming clippy is not one.
    #[test]
    fn a_build_script_naming_a_clippy_variable_is_found() {
        assert!(names_clippy_variable(
            "println!(\"cargo:rustc-env=CLIPPY_CONF_DIR=x\");"
        ));
        assert!(names_clippy_variable("println!(\"cargo::rustc-env=clippy_args=x\");"));
        assert!(names_clippy_variable(
            "fn emit(k: &str, v: &str) {\n    println!(\"cargo:rustc-env={k}={v}\");\n}\n\nfn main() {\n    emit(\"CLIPPY_ARGS\", \"-Aclippy::disallowed_methods\");\n}\n"
        ));
        assert!(!names_clippy_variable("println!(\"cargo:rustc-env=GIT_HASH=x\");"));
        assert!(!names_clippy_variable(
            "//! Linted by `cargo xtask clippy`; sets no CLIPPY_CONF_DIR.\n#[allow(clippy::print_stdout)]\nfn main() {}\n"
        ));
    }

    /// A marker outside a single-`#[expect]` canary, or a canary under another `cfg`, does not
    /// count.
    #[test]
    fn a_canary_must_be_well_formed() {
        let config = "disallowed-methods = [\"c::d\"]\n";
        assert!(
            canary_problems(config, &[("bans.rs", CANARY.to_owned())])
                .unwrap()
                .is_empty()
        );
        let stray = "// canary: `c::d`\nfn other() {}\n".to_owned();
        assert_eq!(canary_problems(config, &[("bans.rs", stray)]).unwrap().len(), 1);
        let gated = format!("#[cfg(target_os = \"none\")]\n{CANARY}");
        assert_eq!(canary_problems(config, &[("bans.rs", gated)]).unwrap().len(), 1);
        let other_call = CANARY.replace("c::d()", "x::y()");
        assert_eq!(canary_problems(config, &[("bans.rs", other_call)]).unwrap().len(), 1);
    }

    /// Any mention in code counts, also inside a macro call; comments and strings do not.
    #[test]
    fn mentions_in_code_are_found_anywhere() {
        let code = masked(
            "// clippy::all in a comment\nlet s = \"disallowed_methods\";\nseeded!(allow(clippy::disallowed_methods));\n#[allow(clippy::style)]\nfn f() {}\n",
        );
        assert_eq!(word_lines(&code, "disallowed_methods"), vec![3]);
        assert_eq!(word_lines(&code, "clippy::style"), vec![4]);
        assert!(word_lines(&code, "clippy::all").is_empty());
        assert!(word_lines(&masked("let disallowed_methods_count = 1;"), "disallowed_methods").is_empty());
        assert_eq!(
            switches("clippy::disallowed_methods"),
            vec![
                "disallowed_methods",
                "disallowed_method",
                "clippy::all",
                "clippy::style"
            ]
        );
    }

    /// `#[path]` modules and `include!` are found.
    #[test]
    fn path_modules_and_includes_are_found() {
        let code = masked(
            "#[path = \"../tests/x.rs\"]\nmod x;\n# [ path=\"y.rs\" ] mod y;\ninclude!(\"z.inc\");\nlet include = 1;\n",
        );
        assert_eq!(path_attribute_lines(&code), vec![1, 3]);
        assert!(include_at(&code, 4));
        assert!(!include_at(&code, 5));
    }
}
