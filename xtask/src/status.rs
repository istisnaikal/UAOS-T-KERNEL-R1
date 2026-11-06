// SPDX-License-Identifier: Apache-2.0

//! Public status truth: what the README says is built must match the workspace. The phase-line
//! check reads only the phase token; this check reads the claims themselves.
//!
//! A document marks its status lists with HTML comments, invisible when rendered:
//!
//! ```text
//! <!-- status:built --> ... <!-- /status:built -->
//! <!-- status:not-built --> ... <!-- /status:not-built -->
//! ```
//!
//! Inside a region, a crate is a backticked name such as `` `uaos-runtime` `` or `` `mod-example` ``.
//! The rules:
//!
//! * a crate in a **built** region must exist (`crates/<name>/Cargo.toml` or
//!   `modules/<name>/Cargo.toml`);
//! * a crate in a **not-built** region must not exist;
//! * every crate named in a region must be declared in `arch.toml`, so a misspelt name cannot pass
//!   as "not built";
//! * every document must hold both regions, and the README's built regions together must name
//!   every existing product crate (Ring 0 tables in `arch.toml`, and every crate under `modules/`;
//!   not dev or tool crates), so a new crate cannot arrive unannounced;
//! * markers must pair up, in order, without nesting.

use std::collections::BTreeSet;
use std::path::Path;

/// Documents whose status regions are checked. Each must have both kinds.
const DOCUMENTS: &[&str] = &["README.md"];
const README: &str = "README.md";
const BUILT: &str = "built";
const NOT_BUILT: &str = "not-built";

/// One marked region: its kind and the crates it names.
struct Region {
    kind: &'static str,
    crates: Vec<String>,
}

pub(crate) fn check(root: &Path, problems: &mut Vec<String>) {
    let declared = match declared_crates(root) {
        Ok(d) => d,
        Err(e) => {
            problems.push(format!("status: arch.toml: {e}"));
            return;
        }
    };
    let mut readme_built = BTreeSet::new();
    for doc in DOCUMENTS {
        let text = match std::fs::read_to_string(root.join(doc)) {
            Ok(t) => t,
            Err(e) => {
                problems.push(format!("status: cannot read {doc}: {e}"));
                continue;
            }
        };
        let regions = match regions(&text) {
            Ok(r) => r,
            Err(e) => {
                problems.push(format!("status: {doc}: {e}"));
                continue;
            }
        };
        for kind in [BUILT, NOT_BUILT] {
            if !regions.iter().any(|r| r.kind == kind) {
                problems.push(format!("status: {doc} has no `<!-- status:{kind} -->` region"));
            }
        }
        for region in &regions {
            for name in &region.crates {
                if !declared.names.contains(name) {
                    problems.push(format!(
                        "status: {doc} names `{name}`, which arch.toml does not declare (misspelt, or \
                         declare it first)"
                    ));
                    continue;
                }
                let exists = crate_exists(root, name);
                if region.kind == BUILT && !exists {
                    problems.push(format!("status: {doc} lists `{name}` as built, but it does not exist"));
                }
                if region.kind == NOT_BUILT && exists {
                    problems.push(format!("status: {doc} names built crate `{name}` as not built"));
                }
                if *doc == README && region.kind == BUILT {
                    readme_built.insert(name.clone());
                }
            }
        }
    }
    for product in &declared.product {
        if crate_exists(root, product) && !readme_built.contains(product) {
            problems.push(format!(
                "status: crate `{product}` exists but README.md's built list does not name it"
            ));
        }
    }
}

/// Crates the workspace declares: every `[crate.*]` table and every name in an `allow` list of
/// `arch.toml`, plus every crate under `modules/`, which `arch.toml` governs as Ring 1 through
/// `[ring1]` without a table each. The product crates the README must announce are the Ring 0
/// tables and every Ring 1 module.
struct Declared {
    names: BTreeSet<String>,
    product: BTreeSet<String>,
}

fn declared_crates(root: &Path) -> Result<Declared, String> {
    let text = std::fs::read_to_string(root.join("arch.toml")).map_err(|e| e.to_string())?;
    let value: toml::Table = toml::from_str(&text).map_err(|e| e.to_string())?;
    let mut names = BTreeSet::new();
    let mut product = BTreeSet::new();
    let crates = value
        .get("crate")
        .and_then(toml::Value::as_table)
        .ok_or("no [crate.*] tables")?;
    for (name, table) in crates {
        names.insert(name.clone());
        let ring = table.get("ring");
        if ring.and_then(toml::Value::as_integer).is_some_and(|r| r == 0 || r == 1) {
            product.insert(name.clone());
        }
        let allow = table.get("allow").and_then(toml::Value::as_array);
        for entry in allow.into_iter().flatten().filter_map(toml::Value::as_str) {
            if entry != "*" {
                names.insert(entry.to_owned());
            }
        }
    }
    let modules = root.join("modules");
    if modules.is_dir() {
        let entries = std::fs::read_dir(&modules).map_err(|e| format!("modules/: {e}"))?;
        for entry in entries {
            let path = entry.map_err(|e| format!("modules/: {e}"))?.path();
            if path.join("Cargo.toml").is_file()
                && let Some(name) = path.file_name().and_then(|n| n.to_str())
            {
                names.insert(name.to_owned());
                product.insert(name.to_owned());
            }
        }
    }
    Ok(Declared { names, product })
}

fn crate_exists(root: &Path, name: &str) -> bool {
    ["crates", "modules"]
        .iter()
        .any(|dir| root.join(dir).join(name).join("Cargo.toml").is_file())
}

/// The marked regions of `text`, in order.
fn regions(text: &str) -> Result<Vec<Region>, String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(open_at) = rest.find("<!-- status:") {
        if rest.get(..open_at).is_some_and(|gap| gap.contains("<!-- /status:")) {
            return Err("a closing `<!-- /status:` marker comes before any opening marker".to_owned());
        }
        let after_open = rest.get(open_at + "<!-- status:".len()..).unwrap_or_default();
        let kind = if after_open.starts_with("built -->") {
            BUILT
        } else if after_open.starts_with("not-built -->") {
            NOT_BUILT
        } else {
            return Err("a `<!-- status:` marker is neither `built -->` nor `not-built -->`".to_owned());
        };
        let body_start = after_open.get(kind.len() + " -->".len()..).unwrap_or_default();
        let close = format!("<!-- /status:{kind} -->");
        let Some(close_at) = body_start.find(&close) else {
            return Err(format!("`<!-- status:{kind} -->` is never closed by `{close}`"));
        };
        let body = body_start.get(..close_at).unwrap_or_default();
        if body.contains("<!-- status:") || body.contains("<!-- /status:") {
            return Err(format!(
                "a `status:{kind}` region holds another marker (regions do not nest)"
            ));
        }
        out.push(Region {
            kind,
            crates: crate_names(body),
        });
        rest = body_start.get(close_at + close.len()..).unwrap_or_default();
    }
    if rest.contains("<!-- /status:") {
        return Err("a closing `<!-- /status:` marker has no opening marker".to_owned());
    }
    Ok(out)
}

/// Backticked crate names in `body`: `uaos`, `uaos-*` or `mod-*`, lowercase ASCII.
fn crate_names(body: &str) -> Vec<String> {
    body.split('`')
        .skip(1)
        .step_by(2)
        .filter(|token| {
            let shaped = token
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            shaped && (*token == "uaos" || token.starts_with("uaos-") || token.starts_with("mod-"))
        })
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regions_and_names_are_read() {
        let text = "a <!-- status:built -->`uaos-json`, `cargo`, `mod-example`<!-- /status:built --> b \
                    <!-- status:not-built -->`uaos`<!-- /status:not-built -->";
        let found = regions(text).unwrap_or_default();
        assert_eq!(found.len(), 2);
        assert_eq!(found.first().map(|r| r.kind), Some(BUILT));
        assert_eq!(
            found.first().map(|r| r.crates.clone()),
            Some(vec!["uaos-json".to_owned(), "mod-example".to_owned()])
        );
        assert_eq!(found.get(1).map(|r| r.crates.clone()), Some(vec!["uaos".to_owned()]));
    }

    #[test]
    fn malformed_markers_are_refused() {
        assert!(regions("<!-- status:built --> no close").is_err());
        assert!(regions("<!-- status:shipped --> x <!-- /status:shipped -->").is_err());
        assert!(regions("x <!-- /status:built -->").is_err());
        // A stray closing marker before an opener.
        assert!(regions("<!-- /status:built --> <!-- status:built -->`uaos`<!-- /status:built -->").is_err());
        assert!(
            regions(
                "<!-- status:built --> <!-- status:not-built --> <!-- /status:not-built --> <!-- /status:built -->"
            )
            .is_err()
        );
    }
}
