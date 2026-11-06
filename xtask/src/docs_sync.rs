// SPDX-License-Identifier: Apache-2.0

//! "Docs changed with contract" (a merge blocker). When the committed contract surface (`schemas/`)
//! changes in a range, must change in the same range, so no contract change ships undocumented.
//! Generated reference docs join this rule when the docs site lands (P3).

use std::path::Path;

use crate::util::capture;

const CONTRACT_SURFACE: &[&str] = &["schemas/"];
const CHANGELOG: &str = "CHANGELOG.md";

pub(crate) fn check(repo: &Path, range: &str) -> Result<(), String> {
    let changed = capture(repo, "git", &["diff", "--name-only", range])?;
    let files: Vec<&str> = changed.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let contract: Vec<&str> = files
        .iter()
        .copied()
        .filter(|f| CONTRACT_SURFACE.iter().any(|p| f.starts_with(p)))
        .collect();
    if contract.is_empty() || files.contains(&CHANGELOG) {
        println!("xtask docs-sync: ok ({} contract file(s) changed)", contract.len());
        Ok(())
    } else {
        Err(format!(
            "contract surface changed without a {CHANGELOG} entry:\n  {}",
            contract.join("\n  ")
        ))
    }
}
