// SPDX-License-Identifier: Apache-2.0

//! Contract schema export and drift/breaking-change detection.
//!
//! `schemas/<name>.v<major>.json` is the committed, reviewable form of every wire contract.
//! `schema-check` regenerates them in memory and classifies every difference:
//!
//! * **breaking** — a removed or retyped property, a newly required property, a changed
//!   enum/const/pattern/format/bound/reference, a removed definition. Fails with a demand
//!   for a major bump (new `uaos.<name>/<major+1>` tag and an ADR).
//! * **additive / cosmetic** — a new optional property, a new definition, changed
//!   descriptions. Fails as "out of date" until `cargo xtask schemas` is run and committed,
//!   so the committed files never lie.
//!
//! The classifier is deliberately conservative: anything it does not understand is breaking.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

const DIR: &str = "schemas";

fn generated() -> Result<Vec<(String, String)>, String> {
    uaos_contracts::schema::exported()
        .into_iter()
        .map(|s| {
            let text = serde_json::to_string_pretty(&s.schema).map_err(|e| format!("{}: {e}", s.name))?;
            Ok((s.file_name(), text + "\n"))
        })
        .collect()
}

pub(crate) fn write(root: &Path) -> Result<(), String> {
    let dir = root.join(DIR);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{DIR}: {e}"))?;
    for (file, text) in generated()? {
        std::fs::write(dir.join(&file), text).map_err(|e| format!("{DIR}/{file}: {e}"))?;
        println!("xtask schemas: wrote {DIR}/{file}");
    }
    Ok(())
}

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let dir = root.join(DIR);
    let generated = generated()?;
    let mut problems = Vec::new();
    let mut expected_files = BTreeSet::new();

    for (file, text) in &generated {
        expected_files.insert(file.clone());
        let path = dir.join(file);
        let Ok(committed_text) = std::fs::read_to_string(&path) else {
            problems.push(format!("{DIR}/{file}: not committed — run `cargo xtask schemas`"));
            continue;
        };
        if committed_text.replace("\r\n", "\n") == *text {
            continue;
        }
        let old: Value = serde_json::from_str(&committed_text).map_err(|e| format!("{DIR}/{file}: {e}"))?;
        let new: Value = serde_json::from_str(text).map_err(|e| format!("generated {file}: {e}"))?;
        let mut breaking = Vec::new();
        diff(&old, &new, "#", &mut breaking);
        if breaking.is_empty() {
            problems.push(format!(
                "{DIR}/{file}: out of date (non-breaking change) — run `cargo xtask schemas` and commit"
            ));
        } else {
            problems.push(format!(
                "{DIR}/{file}: BREAKING change without a major bump — introduce the next major \
                 (`uaos.<name>/<major+1>`) with an ADR:\n      {}",
                breaking.join("\n      ")
            ));
        }
    }

    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_json = Path::new(&name)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("json"));
            if is_json && !expected_files.contains(&name) {
                problems.push(format!(
                    "{DIR}/{name}: committed but no longer generated (retiring a major needs an ADR)"
                ));
            }
        }
    }

    if problems.is_empty() {
        println!(
            "xtask schema-check: {} contract schemas match the code",
            generated.len()
        );
        Ok(())
    } else {
        Err(format!("schema gate failed:\n  {}", problems.join("\n  ")))
    }
}

/// Keys whose change never affects compatibility.
const COSMETIC: &[&str] = &["description", "title", "examples", "$comment"];

/// Collects breaking differences between `old` and `new` at `path`.
fn diff(old: &Value, new: &Value, path: &str, breaking: &mut Vec<String>) {
    match (old, new) {
        (Value::Object(o), Value::Object(n)) => {
            let keys: BTreeSet<&String> = o.keys().chain(n.keys()).collect();
            for key in keys {
                let here = format!("{path}/{key}");
                match (o.get(key.as_str()), n.get(key.as_str())) {
                    (Some(a), Some(b)) if a == b => {}
                    _ if COSMETIC.contains(&key.as_str()) => {}
                    (Some(a), Some(b)) if key == "properties" || key == "$defs" => {
                        diff_members(a, b, &here, key == "properties", n.get("required"), breaking);
                    }
                    (Some(a), Some(b)) if key == "required" => diff_required(a, b, &here, breaking),
                    (Some(a), Some(b)) if a.is_object() && b.is_object() => diff(a, b, &here, breaking),
                    (Some(_), Some(_)) => breaking.push(format!("{here}: changed")),
                    (Some(_), None) => breaking.push(format!("{here}: removed")),
                    (None, Some(_)) if key == "required" => {
                        breaking.push(format!("{here}: properties became required"));
                    }
                    (None, Some(_)) => breaking.push(format!("{here}: constraint added")),
                    (None, None) => {}
                }
            }
        }
        _ if old == new => {}
        _ => breaking.push(format!("{path}: changed")),
    }
}

/// Compares `properties` or `$defs` maps. New members are additive unless they are
/// required properties; removed members are breaking.
fn diff_members(
    old: &Value,
    new: &Value,
    path: &str,
    is_properties: bool,
    new_required: Option<&Value>,
    breaking: &mut Vec<String>,
) {
    let (Value::Object(o), Value::Object(n)) = (old, new) else {
        breaking.push(format!("{path}: changed shape"));
        return;
    };
    let required: BTreeSet<&str> = new_required
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    for (name, old_schema) in o {
        match n.get(name) {
            Some(new_schema) => diff(old_schema, new_schema, &format!("{path}/{name}"), breaking),
            None => breaking.push(format!("{path}/{name}: removed")),
        }
    }
    if is_properties {
        for name in n.keys().filter(|k| !o.contains_key(*k)) {
            if required.contains(name.as_str()) {
                breaking.push(format!("{path}/{name}: new required property"));
            }
        }
    }
}

/// Any change to the required set is breaking: added entries break old writers, removed
/// entries break old readers.
fn diff_required(old: &Value, new: &Value, path: &str, breaking: &mut Vec<String>) {
    let set = |v: &Value| -> BTreeSet<String> {
        v.as_array()
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
            .unwrap_or_default()
    };
    let (o, n) = (set(old), set(new));
    for added in n.difference(&o) {
        breaking.push(format!("{path}: `{added}` became required"));
    }
    for removed in o.difference(&n) {
        breaking.push(format!("{path}: `{removed}` is no longer required"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn breaking(old: &Value, new: &Value) -> Vec<String> {
        let mut out = Vec::new();
        diff(old, new, "#", &mut out);
        out
    }

    #[test]
    fn optional_property_and_descriptions_are_not_breaking() {
        let old = json!({"type":"object","properties":{"a":{"type":"string"}},"required":["a"],"description":"x"});
        let new = json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a"],"description":"y"});
        assert!(breaking(&old, &new).is_empty());
    }

    #[test]
    fn removals_retypes_and_new_requirements_are_breaking() {
        let old = json!({"type":"object","properties":{"a":{"type":"string"}},"required":["a"]});
        assert!(!breaking(&old, &json!({"type":"object","properties":{},"required":[]})).is_empty());
        assert!(
            !breaking(
                &old,
                &json!({"type":"object","properties":{"a":{"type":"boolean"}},"required":["a"]})
            )
            .is_empty()
        );
        assert!(!breaking(&old, &json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a","b"]})).is_empty());
        assert!(!breaking(&json!({"enum":["x","y"]}), &json!({"enum":["x","y","z"]})).is_empty());
        assert!(!breaking(&json!({"pattern":"^a$"}), &json!({"pattern":"^b$"})).is_empty());
    }
}
