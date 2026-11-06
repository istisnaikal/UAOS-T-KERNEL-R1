// SPDX-License-Identifier: Apache-2.0

//! Open-decision markers. A value that cannot be filled in yet (a contact address, a legal entity)
//! is written as a marker naming its decision ID, never as a plausible-looking placeholder. Merges
//! list them; a release fails while any remain (red line 10).

use std::path::Path;

use crate::util::{rel, walk_files};

const TEXT_EXTENSIONS: &[&str] = &["md", "rs", "toml", "yml", "yaml", "txt"];
/// Text files that conventionally have no extension.
const EXTENSIONLESS_TEXT: &[&str] = &["CODEOWNERS", "NOTICE", "LICENSE"];

fn needle() -> String {
    // Built at runtime so this file does not match itself.
    ["PENDING", "-DECISION("].concat()
}

pub(crate) fn check(root: &Path, release: bool) -> Result<(), String> {
    let needle = needle();
    let mut found = Vec::new();
    for path in walk_files(root)? {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if !TEXT_EXTENSIONS.contains(&ext) && !EXTENSIONLESS_TEXT.contains(&name) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            if line.contains(&needle) {
                found.push(format!("{}:{}: {}", rel(root, &path), i + 1, line.trim()));
            }
        }
    }
    if found.is_empty() {
        println!("xtask decisions: no open decision markers");
        return Ok(());
    }
    let list = found.join("\n  ");
    if release {
        Err(format!(
            "{} open decision marker(s) block the release:\n  {list}",
            found.len()
        ))
    } else {
        println!(
            "xtask decisions: {} open decision marker(s) (allowed before release):\n  {list}",
            found.len()
        );
        Ok(())
    }
}
