// SPDX-License-Identifier: Apache-2.0

//! Dependency-direction enforcement. See arch.toml for the rules.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use cargo_metadata::{CargoOpt, DependencyKind, Edition, MetadataCommand, PackageId, TargetKind};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ArchFile {
    ring1: Ring1,
    #[serde(rename = "crate")]
    crates: BTreeMap<String, CrateRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ring1 {
    allow: Vec<String>,
    /// Crates no Ring 1 module may reach, even transitively (no ambient authority).
    #[serde(default)]
    ban: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrateRule {
    #[allow(dead_code, reason = "documents the ring; validated by deserialization only")]
    ring: toml::Value,
    allow: Vec<String>,
    ban: Vec<String>,
    /// Crates the crate's tests and benches may not reach either: the closures of its
    /// dev-dependencies. Optional.
    #[serde(default)]
    dev_ban: Vec<String>,
    /// When set, the crate's whole set of normal and build dependencies, by package name, and the
    /// crate has no build script and no features: what goes into its build is fixed here. Optional.
    #[serde(default)]
    pinned: Option<Vec<String>>,
    /// Packages the crate must have as normal dependencies, under their own names. Optional.
    #[serde(default)]
    require: Vec<String>,
}

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let arch_text = std::fs::read_to_string(root.join("arch.toml")).map_err(|e| format!("arch.toml: {e}"))?;
    let arch: ArchFile = toml::from_str(&arch_text).map_err(|e| format!("arch.toml: {e}"))?;

    // Every feature on: an edge behind a feature no default enables is still an edge.
    let metadata = MetadataCommand::new()
        .current_dir(root)
        .features(CargoOpt::AllFeatures)
        .exec()
        .map_err(|e| format!("cargo metadata: {e}"))?;
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or("cargo metadata returned no resolve graph")?;

    let workspace: BTreeMap<&PackageId, &cargo_metadata::Package> =
        metadata.workspace_packages().into_iter().map(|p| (&p.id, p)).collect();
    let names: BTreeMap<&PackageId, &str> = metadata.packages.iter().map(|p| (&p.id, p.name.as_str())).collect();
    let nodes: BTreeMap<&PackageId, &cargo_metadata::Node> = resolve.nodes.iter().map(|n| (&n.id, n)).collect();

    // A local package outside the workspace (a path dependency into an excluded folder, or a
    // `[patch]` to a path) is under none of the rules below, and could compile any crate's source
    // under another name. Every local crate is a member.
    let mut violations: Vec<String> = metadata
        .packages
        .iter()
        .filter(|p| p.source.is_none() && !workspace.contains_key(&p.id))
        .map(|p| {
            format!(
                "{}: a local package outside the workspace ({}); arch.toml covers members only",
                p.name,
                crate::util::rel(root, p.manifest_path.as_std_path())
            )
        })
        .collect();
    for (id, package) in &workspace {
        let name = package.name.as_str();
        let rel_manifest = crate::util::rel(root, package.manifest_path.as_std_path());
        let is_ring1 = rel_manifest.starts_with("modules/");
        let rule = arch.crates.get(name);
        if rule.is_none() && !is_ring1 {
            violations.push(format!(
                "{name}: not declared in arch.toml (every crate declares its edges)"
            ));
            continue;
        }
        let allowed: BTreeSet<&str> = if is_ring1 {
            arch.ring1.allow.iter().map(String::as_str).collect()
        } else {
            rule.map(|r| r.allow.iter().map(String::as_str).collect())
                .unwrap_or_default()
        };
        let Some(node) = nodes.get(id) else {
            violations.push(format!("{name}: missing from resolve graph"));
            continue;
        };

        // Direct product edges (normal + build) to workspace crates.
        for dep in &node.deps {
            let is_product_edge = dep
                .dep_kinds
                .iter()
                .any(|k| matches!(k.kind, DependencyKind::Normal | DependencyKind::Build));
            if !is_product_edge || !workspace.contains_key(&dep.pkg) {
                continue;
            }
            let dep_name = names.get(&dep.pkg).copied().unwrap_or("?");
            if !(allowed.contains("*") || allowed.contains(dep_name)) {
                let ring = if is_ring1 {
                    " (Ring 1 may only use uaos-contracts and uaos-module-api)"
                } else {
                    ""
                };
                violations.push(format!("{name} -> {dep_name}: edge not allowed by arch.toml{ring}"));
            }
        }

        // Transitive closure over product edges, for bans. Ring 1 crates share one ban list.
        let bans: &[String] = if is_ring1 {
            &arch.ring1.ban
        } else {
            rule.map_or(&[][..], |r| r.ban.as_slice())
        };
        if !bans.is_empty() {
            let closure = product_closure(id, &nodes);
            for banned in bans {
                if closure.iter().any(|p| names.get(*p).copied() == Some(banned.as_str())) {
                    violations.push(format!("{name}: transitively depends on banned crate `{banned}`"));
                }
            }
        }

        let dev_bans = rule.map_or(&[][..], |r| r.dev_ban.as_slice());
        violations.extend(dev_ban_violations(name, node, dev_bans, &nodes, &names));

        violations.extend(manifest_rules(package, !dev_bans.is_empty()));
        if let Some(rule) = rule {
            violations.extend(pinned_build(package, node, rule, &names));
            if rule.pinned.is_some() {
                violations.extend(unpinned_in_closure(name, id, &nodes, &workspace, &arch.crates));
            }
        }
        violations.extend(foreign_roots(root, package)?);
        violations.extend(extern_crates(package)?);
    }

    if violations.is_empty() {
        println!(
            "xtask arch-check: {} workspace crates conform to arch.toml",
            workspace.len()
        );
        Ok(())
    } else {
        Err(format!("architecture violations:\n  {}", violations.join("\n  ")))
    }
}

/// For a crate that bans some crates from its tests: each dev-dependency that is, or reaches,
/// one of them.
fn dev_ban_violations(
    name: &str,
    node: &cargo_metadata::Node,
    dev_bans: &[String],
    nodes: &BTreeMap<&PackageId, &cargo_metadata::Node>,
    names: &BTreeMap<&PackageId, &str>,
) -> Vec<String> {
    let mut found = Vec::new();
    for dep in node.deps.iter().filter(|d| {
        d.dep_kinds
            .iter()
            .any(|k| matches!(k.kind, DependencyKind::Development))
    }) {
        let mut reach = product_closure(&dep.pkg, nodes);
        reach.insert(&dep.pkg);
        for banned in dev_bans {
            if reach.iter().any(|p| names.get(*p).copied() == Some(banned.as_str())) {
                let via = names.get(&dep.pkg).copied().unwrap_or("?");
                found.push(format!(
                    "{name}: its dev-dependency `{via}` reaches `{banned}`, banned from its tests by arch.toml"
                ));
            }
        }
    }
    found
}

fn product_closure<'a>(
    start: &'a PackageId,
    nodes: &BTreeMap<&'a PackageId, &'a cargo_metadata::Node>,
) -> BTreeSet<&'a PackageId> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![start];
    while let Some(id) = stack.pop() {
        let Some(node) = nodes.get(id) else { continue };
        for dep in &node.deps {
            let product = dep
                .dep_kinds
                .iter()
                .any(|k| matches!(k.kind, DependencyKind::Normal | DependencyKind::Build));
            if product && seen.insert(&dep.pkg) {
                stack.push(&dep.pkg);
            }
        }
    }
    seen
}

/// What a member's manifest may not do:
/// * run doctests, when the crate has a `dev_ban`: rustdoc builds them with the dev-dependencies,
///   outside the dep-info check;
/// * take a dependency under another name, or name its library other than after the package:
///   `uaos_redact_scan` could then name another crate, and the identity pins in `uaos-redact` would
///   compare a type with itself.
fn manifest_rules(package: &cargo_metadata::Package, has_dev_ban: bool) -> Vec<String> {
    let name = package.name.as_str();
    let own = name.replace('-', "_");
    let doctests = package
        .targets
        .iter()
        .filter(|t| has_dev_ban && t.doctest)
        .map(|t| {
            format!(
                "{name}: target `{}` runs doctests, which build outside the checks that hold its dev_ban; set `doctest = false`",
                t.name
            )
        });
    let renamed = package.dependencies.iter().filter_map(|d| {
        d.rename.as_ref().map(|alias| {
            format!(
                "{name}: depends on `{}` as `{alias}`; a dependency goes by its own name",
                d.name
            )
        })
    });
    let library = package
        .targets
        .iter()
        .filter(|t| t.kind.iter().any(is_library) && t.name != own)
        .map(|t| format!("{name}: its library is named `{}`, not `{own}`", t.name));
    // arch-check and allow-audit read source as edition 2021 and later do: before it, `cr#"a"` is
    // an identifier, a `#` and a string, not one literal (over the closing fixes).
    let edition = matches!(package.edition, Edition::E2015 | Edition::E2018).then(|| {
        format!(
            "{name}: edition {}, which lexes literals otherwise than the readers of arch-check and allow-audit; use 2021 or later",
            package.edition
        )
    });
    doctests.chain(renamed).chain(library).chain(edition).collect()
}

fn is_library(kind: &TargetKind) -> bool {
    matches!(
        kind,
        TargetKind::Lib
            | TargetKind::RLib
            | TargetKind::DyLib
            | TargetKind::CDyLib
            | TargetKind::StaticLib
            | TargetKind::ProcMacro
    )
}

/// What arch.toml fixes for a crate beyond its edges:
/// * `require`: packages it must have as normal dependencies. While a name is passed to rustc as a
///   dependency, rustc refuses a macro-expanded `extern crate` that would give it to another crate.
/// * `pinned`: its whole set of normal and build dependencies, and no build script and no features.
///   A build script, or a build-dependency's file APIs, which no clippy ban names, can write any
///   source into its `OUT_DIR`, which the dep-info check allows; a feature makes a build no gate
///   checks.
fn pinned_build(
    package: &cargo_metadata::Package,
    node: &cargo_metadata::Node,
    rule: &CrateRule,
    names: &BTreeMap<&PackageId, &str>,
) -> Vec<String> {
    let name = package.name.as_str();
    let deps_of = |kinds: &[DependencyKind]| -> BTreeSet<&str> {
        node.deps
            .iter()
            .filter(|d| d.dep_kinds.iter().any(|k| kinds.contains(&k.kind)))
            .map(|d| names.get(&d.pkg).copied().unwrap_or("?"))
            .collect()
    };
    // Unconditionally: an optional or a target-specific edge may leave the name off rustc's command
    // line, and then a macro-expanded `extern crate` may take it (over the closing fixes).
    let mut found: Vec<String> = rule
        .require
        .iter()
        .filter(|r| {
            !package.dependencies.iter().any(|d| {
                d.name == **r
                    && d.kind == DependencyKind::Normal
                    && d.target.is_none()
                    && !d.optional
                    && d.rename.is_none()
            })
        })
        .map(|r| format!("{name}: must depend on `{r}`, unconditionally (arch.toml `require`)"))
        .collect();
    let Some(pinned) = &rule.pinned else {
        return found;
    };
    let direct = deps_of(&[DependencyKind::Normal, DependencyKind::Build]);
    let listed: BTreeSet<&str> = pinned.iter().map(String::as_str).collect();
    for extra in direct.difference(&listed) {
        found.push(format!(
            "{name}: depends on `{extra}`, which its pinned build in arch.toml does not list"
        ));
    }
    for missing in listed.difference(&direct) {
        found.push(format!(
            "{name}: arch.toml pins `{missing}`, which it does not depend on"
        ));
    }
    for target in package
        .targets
        .iter()
        .filter(|t| t.kind.contains(&TargetKind::CustomBuild))
    {
        found.push(format!(
            "{name}: has a build script (`{}`), which its pinned build does not allow",
            target.name
        ));
    }
    if !package.features.is_empty() {
        let features: Vec<&str> = package.features.keys().map(String::as_str).collect();
        found.push(format!(
            "{name}: declares features ({}), which its pinned build does not allow",
            features.join(", ")
        ));
    }
    found
}

/// The workspace crates a pinned crate reaches whose own build is not pinned. They are part of its
/// build: a build script or a feature in one would put code into it as surely (over the closing
/// fixes).
fn unpinned_in_closure(
    name: &str,
    id: &PackageId,
    nodes: &BTreeMap<&PackageId, &cargo_metadata::Node>,
    workspace: &BTreeMap<&PackageId, &cargo_metadata::Package>,
    rules: &BTreeMap<String, CrateRule>,
) -> Vec<String> {
    product_closure(id, nodes)
        .into_iter()
        .filter_map(|reached| workspace.get(reached))
        .map(|member| member.name.as_str())
        .filter(|member| rules.get(*member).is_none_or(|r| r.pinned.is_none()))
        .map(|member| format!("{name}: reaches `{member}`, whose build arch.toml must pin too (`pinned`)"))
        .collect()
}

/// Target roots that declare `extern crate`. At a crate's root, `extern crate self as x;` (or
/// `extern crate other as x;`) gives the name `x` to another crate for the whole crate, `::x` paths
/// included, so the identity pins in `uaos-redact` would compare a type with itself. rustc refuses
/// that from a macro or an `include!` while `x` is passed to it as a dependency (which `require`
/// holds for the pins), and an `extern crate` below the root does not reach `::x`. So the root's
/// own items are where it can be, and they are read with a parser, not a text scan, which a literal
/// it misreads could blind. A root that does not parse fails the check.
fn extern_crates(package: &cargo_metadata::Package) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    for target in &package.targets {
        let src = target.src_path.as_std_path();
        let source = std::fs::read_to_string(src).map_err(|e| format!("{}: {e}", src.display()))?;
        match syn::parse_file(&source) {
            Ok(file) => {
                for item in &file.items {
                    if let syn::Item::ExternCrate(item) = item {
                        found.push(format!(
                            "{}: target `{}` declares `extern crate {}` at its root, which can give a dependency's name to another crate",
                            package.name, target.name, item.ident
                        ));
                    }
                }
            }
            Err(e) => found.push(format!(
                "{}: target `{}`'s root does not parse, so its items cannot be checked: {e}",
                package.name, target.name
            )),
        }
    }
    Ok(found)
}

/// Targets whose root file lies outside the crate's directory (`[lib] path = "../.."`): they
/// compile another crate's source with no edge. Every other way in (`#[path]`, `include!`,
/// symlinks) is checked on what rustc read, by the clippy gate (`sources.rs`).
fn foreign_roots(root: &Path, package: &cargo_metadata::Package) -> Result<Vec<String>, String> {
    let manifest = package.manifest_path.as_std_path();
    let dir = manifest.parent().ok_or("a manifest path has no parent")?;
    let dir = std::fs::canonicalize(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut found = Vec::new();
    for target in &package.targets {
        let src = target.src_path.as_std_path();
        let resolved = std::fs::canonicalize(src).map_err(|e| format!("{}: {e}", src.display()))?;
        if !resolved.starts_with(&dir) {
            found.push(format!(
                "{}: target `{}` has its root outside the crate ({})",
                package.name,
                target.name,
                crate::util::rel(root, &resolved)
            ));
        }
    }
    Ok(found)
}
