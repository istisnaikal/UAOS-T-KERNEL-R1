// SPDX-License-Identifier: Apache-2.0

//! # UAOS test harnesses (dev-only)
//!
//! Never part of a release build. Holds harnesses that need real processes and real disks, starting
//! with the kill harness behind the `journal-durability` gate:
//!
//! * `journal-crash-writer` (binary) appends records to a real journal with the production
//!   stack (`OsFs`, system clock, OS randomness) and prints `seq hash` for each acknowledged
//!   record, flushing stdout after every line;
//! * `tests/kill.rs` kills that writer at random acknowledgement counts and random times
//!   (`TerminateProcess` on Windows, `SIGKILL` on Unix), reopens the journal, and checks that every
//!   acknowledged record is present with exactly the acknowledged hash.

#![deny(missing_docs)]

use std::sync::Arc;

use uaos_contracts::event::{Actor, Durability, Metadata, types};
use uaos_contracts::id::{CorrelationId, PocketId, TypedId};
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::wire::ConfigVersion;
use uaos_platform::sim::SimRng;
use uaos_state::chunks::keyring::{KeyringError, MemoryKeyring, PocketKeyring};
use uaos_state::journal::EventDraft;

/// The pocket the kill harness stores payloads in.
#[must_use]
pub fn kill_pocket() -> PocketId {
    PocketId::from_parts(0x0001_8000_0000, [0x6b; 10])
}

/// The payload the kill harness stores for the record with sequence number `seq`: distinct per
/// record, so every intent references its own chunk.
#[must_use]
pub fn kill_payload(seq: u64) -> Vec<u8> {
    format!("kill-harness payload for record {seq}\n")
        .repeat(16)
        .into_bytes()
}

/// A keyring that yields the same pocket keys in every process, so the harness can read the
/// chunks a killed writer stored. Test-only: deterministic keys are never acceptable elsewhere.
///
/// # Errors
/// Key generation failure.
pub fn kill_keyring() -> Result<Arc<MemoryKeyring>, KeyringError> {
    let keys = Arc::new(MemoryKeyring::new(Arc::new(SimRng::new(0x6b11_6b11))));
    // Fixed order: the content key first, then KEK v1, whatever the store does next.
    keys.cas_key(kill_pocket())?;
    keys.current_kek(kill_pocket())?;
    Ok(keys)
}

/// A representative critical record (write-ahead intent of an external operation).
#[must_use]
pub fn intent_draft(n: u64) -> EventDraft {
    let mut random = [0u8; 10];
    random[..8].copy_from_slice(&n.to_le_bytes());
    EventDraft {
        session_id: None,
        pocket_id: None,
        operation_id: None,
        request_id: None,
        agent_id: None,
        correlation_id: CorrelationId::from_parts(n, random),
        parent_id: None,
        actor: Actor::System,
        event_type: types::OP_RESERVED_INTENT,
        payload_ref: None,
        payload_inline: None,
        cost_estimate: None,
        compensable: false,
        side_effect_class: SideEffectClass::External,
        risk_tier: RiskTier::MAX,
        durability: Durability::Critical,
        config_version: ConfigVersion(1),
        metadata: Metadata::default(),
    }
}
