// SPDX-License-Identifier: Apache-2.0

//! cargo-vet exemption ratchet.
//!
//! An exemption says "we use this crate without an audit". CONTRIBUTING.md requires a reason
//! for each one, yet the first 233 were added without one. This check makes that debt shrink
//! monotonically:
//!
//! * exemptions **without** a `notes` reason may never exceed [`UNNOTED_BASELINE`], so every
//!   new exemption must carry a reason;
//! * when the unnoted count falls below the baseline, the check fails until the baseline is
//!   lowered in the same change. Progress is locked in and cannot silently slide back.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

/// Exemptions without a `notes` reason: 233 when the ratchet was introduced, 227 since the
/// cedar-policy and schemars bumps noted their six, 226 since the RUSTSEC-2026-0385 update noted
/// `ctutils`, and 225 since the yanked `async-executor` 1.14.0 was replaced with a noted 1.14.1.
/// Lower it as reasons are added or crates audited; raising it requires review of `xtask/` by its
/// code owner and defeats the purpose.
const UNNOTED_BASELINE: usize = 225;

#[derive(Debug, Deserialize)]
struct VetConfig {
    #[serde(default)]
    exemptions: BTreeMap<String, Vec<Exemption>>,
}

#[derive(Debug, Deserialize)]
struct Exemption {
    #[serde(default)]
    notes: Option<String>,
}

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let path = root.join("supply-chain").join("config.toml");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("supply-chain/config.toml: {e}"))?;
    let config: VetConfig = toml::from_str(&text).map_err(|e| format!("supply-chain/config.toml: {e}"))?;
    let total: usize = config.exemptions.values().map(Vec::len).sum();
    let unnoted: Vec<&str> = config
        .exemptions
        .iter()
        .flat_map(|(name, entries)| {
            entries
                .iter()
                .filter(|e| e.notes.as_deref().is_none_or(|n| n.trim().is_empty()))
                .map(move |_| name.as_str())
        })
        .collect();
    match unnoted.len().cmp(&UNNOTED_BASELINE) {
        std::cmp::Ordering::Equal => {
            println!(
                "xtask vet-ratchet: {total} exemption(s), {} without notes (baseline {UNNOTED_BASELINE})",
                unnoted.len()
            );
            Ok(())
        }
        std::cmp::Ordering::Greater => Err(format!(
            "{} cargo-vet exemptions without notes, baseline {UNNOTED_BASELINE}: every new exemption \
             needs a `notes = \"...\"` reason (CONTRIBUTING.md). Candidates: {}",
            unnoted.len(),
            unnoted.iter().rev().take(5).copied().collect::<Vec<_>>().join(", ")
        )),
        std::cmp::Ordering::Less => Err(format!(
            "ratchet: only {} exemptions lack notes now; lower UNNOTED_BASELINE in \
             xtask/src/vet_ratchet.rs from {UNNOTED_BASELINE} to {} in this change",
            unnoted.len(),
            unnoted.len()
        )),
    }
}
