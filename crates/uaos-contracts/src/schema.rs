// SPDX-License-Identifier: Apache-2.0

//! JSON Schema export of the wire contracts.
//!
//! `cargo xtask schemas` writes these to `schemas/<name>.v<major>.json`; `cargo xtask schema-check`
//! regenerates them in memory and fails the merge on drift, and on any breaking change that is not
//! accompanied by a major-version bump.

use schemars::{Schema, schema_for};

use crate::budget::{BudgetTx, LedgerDelta};
use crate::cli::CliOutput;
use crate::credential::CredentialEntry;
use crate::error::UaosError;
use crate::event::EventEnvelope;
use crate::grant::GrantEntry;
use crate::operation::Operation;

/// One exported contract schema.
#[derive(Debug, Clone)]
pub struct ExportedSchema {
    /// Contract name, e.g. `event`.
    pub name: &'static str,
    /// Major version, matching the `uaos.<name>/<major>` tag.
    pub major: u32,
    /// The generated JSON Schema.
    pub schema: Schema,
}

impl ExportedSchema {
    /// File name under `schemas/`, e.g. `event.v1.json`.
    #[must_use]
    pub fn file_name(&self) -> String {
        format!("{}.v{}.json", self.name, self.major)
    }
}

/// All exported wire contracts, in a stable order.
#[must_use]
pub fn exported() -> Vec<ExportedSchema> {
    vec![
        ExportedSchema {
            name: "budget_tx",
            major: 1,
            schema: schema_for!(BudgetTx),
        },
        ExportedSchema {
            name: "cli",
            major: 1,
            schema: schema_for!(CliOutput),
        },
        ExportedSchema {
            name: "credential",
            major: 1,
            schema: schema_for!(CredentialEntry),
        },
        ExportedSchema {
            name: "error",
            major: 1,
            schema: schema_for!(UaosError),
        },
        ExportedSchema {
            name: "event",
            major: 1,
            schema: schema_for!(EventEnvelope),
        },
        ExportedSchema {
            name: "grant",
            major: 1,
            schema: schema_for!(GrantEntry),
        },
        ExportedSchema {
            name: "op-ledger",
            major: 1,
            schema: schema_for!(LedgerDelta),
        },
        ExportedSchema {
            name: "operation",
            major: 1,
            schema: schema_for!(Operation),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_and_serializable() {
        let all = exported();
        let mut names: Vec<_> = all.iter().map(ExportedSchema::file_name).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), all.len());
        for s in all {
            assert!(serde_json::to_string(&s.schema).is_ok());
        }
    }
}
