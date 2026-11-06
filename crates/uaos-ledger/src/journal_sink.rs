// SPDX-License-Identifier: Apache-2.0

//! Recording ledger entries in the journal, and reading them back.
//!
//! Each entry is one critical `budget.entry` record whose inline payload is the `uaos.budget_tx/1`
//! entry. The journal acknowledges only after the OS holds the record, so a reservation is
//! crash-durable before its Operation can execute.

use serde::Deserialize as _;
use uaos_contracts::budget::{BudgetTx, BudgetTxKind};
use uaos_contracts::event::{Durability, InlinePayload, Metadata, types};
use uaos_contracts::id::{CorrelationId, OperationId};
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::wire::ConfigVersion;
use uaos_state::journal::{EventDraft, Journal, JournalError, VerifiedRecord};

use crate::ledger::LedgerSink;

/// Records entries as `budget.entry` journal records for one correlated action. The event's
/// actor is the entry's own principal, so the two can never disagree.
#[derive(Debug)]
pub struct JournalSink<'a> {
    journal: &'a mut Journal,
    correlation: CorrelationId,
    operation: Option<OperationId>,
    config_version: ConfigVersion,
    /// The journal's own error from the last append it refused, kept with its code.
    refused: Option<JournalError>,
}

impl<'a> JournalSink<'a> {
    /// A sink attributing entries to `correlation` (and `operation`, if any).
    pub fn new(
        journal: &'a mut Journal,
        correlation: CorrelationId,
        operation: Option<OperationId>,
        config_version: ConfigVersion,
    ) -> Self {
        Self {
            journal,
            correlation,
            operation,
            config_version,
            refused: None,
        }
    }

    /// The journal's error from the last append it refused. The ledger sees only its text
    /// (`LedgerError::Sink`); a caller that must report the journal's own code takes it here.
    pub const fn take_refusal(&mut self) -> Option<JournalError> {
        self.refused.take()
    }
}

impl LedgerSink for JournalSink<'_> {
    fn record(&mut self, tx: &BudgetTx) -> Result<(), String> {
        let payload = serde_json::to_value(tx).map_err(|e| e.to_string())?;
        let draft = EventDraft {
            session_id: tx.session_id,
            pocket_id: None,
            operation_id: self.operation,
            request_id: None,
            agent_id: None,
            correlation_id: self.correlation,
            parent_id: None,
            actor: tx.principal.clone(),
            event_type: types::BUDGET_ENTRY,
            payload_ref: None,
            payload_inline: Some(InlinePayload::new(payload).map_err(|e| e.to_string())?),
            cost_estimate: None,
            compensable: false,
            side_effect_class: SideEffectClass::None,
            // An overrun (spend beyond the reservation) is an S1 condition: journaled at the
            // highest risk tier so that it surfaces, never as routine bookkeeping.
            risk_tier: if tx.kind == BudgetTxKind::Adjust {
                RiskTier::MAX
            } else {
                RiskTier::new(0).map_err(|e| e.to_string())?
            },
            durability: Durability::Critical,
            config_version: self.config_version,
            metadata: Metadata::default(),
        };
        self.journal.append(draft).map(|_| ()).map_err(|e| {
            let text = e.to_string();
            self.refused = Some(e);
            text
        })
    }
}

/// Extracts the ledger entries from verified journal records, in order.
///
/// # Errors
/// A description of the first `budget.entry` record whose payload is not a valid entry.
pub fn entries_from_journal(records: &[VerifiedRecord]) -> Result<Vec<BudgetTx>, String> {
    records
        .iter()
        .filter(|r| r.envelope.event_type == types::BUDGET_ENTRY)
        .map(|r| {
            let payload = r
                .envelope
                .payload_inline
                .as_ref()
                .ok_or_else(|| format!("budget.entry at seq {} has no payload", r.envelope.seq))?;
            // Read from the borrowed payload, not a copy of it: boot reads every entry.
            BudgetTx::deserialize(payload.as_value())
                .map_err(|e| format!("budget.entry at seq {} is malformed: {e}", r.envelope.seq))
        })
        .collect()
}
