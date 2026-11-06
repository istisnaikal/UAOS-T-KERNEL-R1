// SPDX-License-Identifier: Apache-2.0

//! Recording identity entries in the journal, and reading them back.
//!
//! Each entry is one critical `identity.entry` record whose inline payload is the
//! `uaos.credential/1` entry. The journal acknowledges only after the OS holds the record, so a
//! revocation is crash-durable before `revoke` returns.

use uaos_contracts::credential::CredentialEntry;
use uaos_contracts::event::{Actor, Durability, InlinePayload, Metadata, types};
use uaos_contracts::id::CorrelationId;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::wire::ConfigVersion;
use uaos_state::journal::{EventDraft, Journal, VerifiedRecord};

use crate::identity::IdentitySink;

/// Records entries as `identity.entry` journal records for one correlated action.
#[derive(Debug)]
pub struct JournalSink<'a> {
    journal: &'a mut Journal,
    correlation: CorrelationId,
    actor: Actor,
    config_version: ConfigVersion,
}

impl<'a> JournalSink<'a> {
    /// A sink attributing entries to `correlation` and `actor`.
    pub fn new(
        journal: &'a mut Journal,
        correlation: CorrelationId,
        actor: Actor,
        config_version: ConfigVersion,
    ) -> Self {
        Self {
            journal,
            correlation,
            actor,
            config_version,
        }
    }
}

impl IdentitySink for JournalSink<'_> {
    fn record(&mut self, entry: &CredentialEntry) -> Result<(), String> {
        let payload = serde_json::to_value(entry).map_err(|e| e.to_string())?;
        let draft = EventDraft {
            session_id: None,
            pocket_id: None,
            operation_id: None,
            request_id: None,
            agent_id: None,
            correlation_id: self.correlation,
            parent_id: None,
            actor: self.actor.clone(),
            event_type: types::IDENTITY_ENTRY,
            payload_ref: None,
            payload_inline: Some(InlinePayload::new(payload).map_err(|e| e.to_string())?),
            cost_estimate: None,
            compensable: false,
            side_effect_class: SideEffectClass::None,
            risk_tier: RiskTier::new(0).map_err(|e| e.to_string())?,
            durability: Durability::Critical,
            config_version: self.config_version,
            metadata: Metadata::default(),
        };
        self.journal.append(draft).map(|_| ()).map_err(|e| e.to_string())
    }
}

/// Extracts the identity entries from verified journal records, in order.
///
/// # Errors
/// A description of the first `identity.entry` record whose payload is not a valid entry.
pub fn entries_from_journal(records: &[VerifiedRecord]) -> Result<Vec<CredentialEntry>, String> {
    records
        .iter()
        .filter(|r| r.envelope.event_type == types::IDENTITY_ENTRY)
        .map(|r| {
            let payload = r
                .envelope
                .payload_inline
                .as_ref()
                .ok_or_else(|| format!("identity.entry at seq {} has no payload", r.envelope.seq))?;
            serde_json::from_value(payload.as_value().clone())
                .map_err(|e| format!("identity.entry at seq {} is malformed: {e}", r.envelope.seq))
        })
        .collect()
}
