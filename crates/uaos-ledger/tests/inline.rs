// SPDX-License-Identifier: Apache-2.0

//! The one-record intent's E1 slice (intent contract): the compact ledger delta and the journal
//! reader, §10 rows 4 (the delta), 5 and 21. Each test that guards a rule names it in its failure
//! message, which its seeded violation in `xtask negative` expects.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::path::Path;
use std::sync::Arc;

use serde_json::{Value, json};
use uaos_contracts::budget::{BudgetTx, BudgetTxKind, IdempotencyKey, ReasonCode};
use uaos_contracts::digest::Sha256Digest;
use uaos_contracts::error::codes;
use uaos_contracts::event::{Actor, Durability, EventEnvelope, EventSchema, EventType, InlinePayload, Metadata, types};
use uaos_contracts::id::{CorrelationId, CredentialId, EventId, OperationId, PoolId, ReservationId, TypedId};
use uaos_contracts::limits::{MAX_INLINE_PAYLOAD, Millis};
use uaos_contracts::money::NanoUsd;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::time::{EventTime, WallTime};
use uaos_contracts::wire::{ConfigVersion, MonoNanos, Seq};
use uaos_ledger::inline::{
    CompactError, DeltaEntry, LEDGER_DELTA_VERSION, LedgerDelta, ReadError, compact, expand, read_entries,
};
use uaos_ledger::{Ledger, MemorySink, Usage};
use uaos_platform::fs::Fs;
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_state::journal::{EventDraft, FlushPolicy, Journal, VerifiedRecord};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

fn op(n: u8) -> OperationId {
    OperationId::from_parts(1, [n; 10])
}

fn rsv(n: u8) -> ReservationId {
    ReservationId::from_parts(2, [n; 10])
}

fn pool() -> PoolId {
    PoolId::from_parts(3, [1; 10])
}

fn agent() -> Actor {
    Actor::Agent {
        credential: CredentialId::from_parts(4, [7; 10]),
    }
}

fn usd(n: i64) -> NanoUsd {
    NanoUsd::new(n)
}

fn entry(kind: BudgetTxKind, amount: i64, before: i64, after: i64, reason: &str) -> DeltaEntry {
    DeltaEntry {
        kind,
        amount: usd(amount),
        before: usd(before),
        after: usd(after),
        reason: ReasonCode::new(reason).unwrap(),
        settled: false,
        estimated: false,
    }
}

fn delta(reservation: ReservationId, entries: Vec<DeltaEntry>) -> Value {
    serde_json::to_value(LedgerDelta {
        v: LEDGER_DELTA_VERSION,
        pool: pool(),
        reservation,
        entries,
    })
    .unwrap()
}

/// A reserve of 30 from 100, the intent's one entry.
fn reserve() -> DeltaEntry {
    entry(BudgetTxKind::Reserve, 30, 100, 70, "reserve")
}

/// A settlement at 20 of the 30 reserved: `[settle, release]`.
fn settlement() -> Vec<DeltaEntry> {
    let mut settle = entry(BudgetTxKind::Settle, 20, 70, 70, "settle");
    settle.settled = false;
    let mut release = entry(BudgetTxKind::Release, 10, 70, 80, "release_remainder");
    release.settled = true;
    vec![settle, release]
}

fn release() -> Vec<DeltaEntry> {
    let mut release = entry(BudgetTxKind::Release, 30, 70, 100, "release");
    release.settled = true;
    vec![release]
}

fn with_ledger(fields: Value, ledger: Value) -> Value {
    let mut payload = fields;
    payload.as_object_mut().unwrap().insert("ledger".to_owned(), ledger);
    payload
}

/// Verified records built in memory, with consecutive sequence numbers.
#[derive(Default)]
struct Records(Vec<VerifiedRecord>);

impl Records {
    fn push(&mut self, event_type: EventType, operation: Option<OperationId>, payload: Option<Value>) -> &mut Self {
        let seq = u64::try_from(self.0.len()).unwrap();
        let envelope = EventEnvelope {
            schema: EventSchema::V1,
            id: EventId::from_parts(1_760_000_000_000 + seq, [1; 10]),
            seq: Seq(seq),
            ts: EventTime {
                wall: WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
                mono_ns: MonoNanos(seq),
            },
            session_id: None,
            pocket_id: None,
            operation_id: operation,
            request_id: None,
            agent_id: None,
            correlation_id: CorrelationId::from_parts(5, [5; 10]),
            parent_id: None,
            actor: agent(),
            event_type,
            payload_ref: None,
            payload_inline: payload.map(|p| InlinePayload::new(p).unwrap()),
            cost_estimate: None,
            compensable: false,
            side_effect_class: SideEffectClass::External,
            risk_tier: RiskTier::new(1).unwrap(),
            durability: Durability::Critical,
            config_version: ConfigVersion(1),
            prev_hash: Sha256Digest::from_bytes([0; 32]),
            metadata: Metadata::default(),
        };
        self.0.push(VerifiedRecord {
            envelope,
            hash: Sha256Digest::from_bytes([0; 32]),
        });
        self
    }

    /// A one-record intent of `operation` for `reservation`.
    fn intent(&mut self, operation: OperationId, reservation: ReservationId) -> &mut Self {
        let payload = with_ledger(
            json!({"kind": "model_call", "upstream": "primary", "durability": "balanced"}),
            delta(reservation, vec![reserve()]),
        );
        self.push(types::OP_RESERVED_INTENT, Some(operation), Some(payload))
    }

    fn executing(&mut self, operation: OperationId) -> &mut Self {
        self.push(types::OP_EXECUTING, Some(operation), None)
    }

    fn closing(&mut self, event_type: EventType, operation: OperationId, entries: Vec<DeltaEntry>) -> &mut Self {
        self.closing_for(event_type, operation, rsv(1), entries)
    }

    fn closing_for(
        &mut self,
        event_type: EventType,
        operation: OperationId,
        reservation: ReservationId,
        entries: Vec<DeltaEntry>,
    ) -> &mut Self {
        let payload = with_ledger(json!({"reason": "test"}), delta(reservation, entries));
        self.push(event_type, Some(operation), Some(payload))
    }

    fn read(&self) -> Result<Vec<BudgetTx>, ReadError> {
        read_entries(&self.0)
    }
}

/// The reader's refusal; `what` names the rule if the reader accepts instead (the message each
/// rule's seeded violation in `xtask negative` expects).
fn refused(records: &Records, what: &str) -> ReadError {
    records.read().expect_err(what)
}

// --------------------------------------------------------------------------------------------- The
// delta: compact and expand
// ---------------------------------------------------------------------------------------------

/// The ledger's own entries for one Operation: a reserve, then a settlement with a remainder, an
/// overrun, or a release.
fn ledger_entries() -> Vec<Vec<BudgetTx>> {
    let mut groups = Vec::new();
    for case in 0_u8..3 {
        let mut ledger = Ledger::default();
        let mut sink = MemorySink::default();
        ledger
            .allocate(
                &mut sink,
                pool(),
                usd(1_000),
                &agent(),
                IdempotencyKey::new("fund").unwrap(),
            )
            .unwrap();
        let held = ledger
            .reserve(&mut sink, pool(), rsv(case), usd(300), &agent())
            .unwrap();
        match case {
            0 => {
                ledger
                    .settle(&mut sink, held.begin(), Usage::Reported(usd(120)), &agent())
                    .unwrap();
            }
            1 => {
                ledger
                    .settle(&mut sink, held.begin(), Usage::Reported(usd(450)), &agent())
                    .unwrap();
            }
            _ => {
                ledger.release(&mut sink, held, &agent()).unwrap();
            }
        }
        // The allocate is not an Operation's; the reserve and the close are.
        groups.push(sink.entries[1..2].to_vec());
        groups.push(sink.entries[2..].to_vec());
    }
    groups
}

#[test]
fn compacted_entries_expand_to_exactly_the_ledgers_entries() {
    for group in ledger_entries() {
        let delta = compact(&group, &agent()).unwrap();
        assert_eq!(delta.v, LEDGER_DELTA_VERSION);
        assert_eq!(expand(&delta, &agent()).unwrap(), group, "expansion lost a field");
        // Through JSON as well: what a reader parses is what the writer meant.
        let parsed: LedgerDelta = serde_json::from_value(serde_json::to_value(&delta).unwrap()).unwrap();
        assert_eq!(parsed, delta);
    }
}

#[test]
fn compact_refuses_what_expansion_would_not_reproduce() {
    let groups = ledger_entries();
    let settle = &groups[1];
    assert_eq!(compact(&[], &agent()), Err(CompactError::Count));
    let three = [settle[0].clone(), settle[1].clone(), settle[1].clone()];
    assert_eq!(compact(&three, &agent()), Err(CompactError::Count));
    // Another principal than the record's actor: the expansion would name the actor.
    assert_eq!(compact(settle, &Actor::System), Err(CompactError::NotReproducible));
    let mut keyed = settle.clone();
    keyed[0].idempotency_key = IdempotencyKey::new("caller-key").unwrap();
    assert_eq!(compact(&keyed, &agent()), Err(CompactError::NotReproducible));
    let mut mixed = settle.clone();
    mixed[1].reservation_id = Some(rsv(9));
    assert_eq!(compact(&mixed, &agent()), Err(CompactError::Binding));
    let mut allocate = settle.clone();
    allocate[0].kind = BudgetTxKind::Allocate;
    assert_eq!(compact(&allocate, &agent()), Err(CompactError::Kind));
}

// ---------------------------------------------------------------------------------------------
// §10 row 4 (the delta): the largest records fit
// ---------------------------------------------------------------------------------------------

/// The longest reason a `ReasonCode` admits (64 bytes).
const LONGEST_REASON: &str = "abcdefghijklmnopqrstuvwxyz_abcdefghijklmnopqrstuvwxyz_abcdefghij";

/// `[settle, adjust]` with every amount at a 64-bit extreme and the longest reason.
fn extreme_settlement(reason: &str) -> Vec<DeltaEntry> {
    let mut settle = entry(BudgetTxKind::Settle, i64::MAX, i64::MIN, i64::MIN, reason);
    settle.settled = true;
    settle.estimated = true;
    let mut adjust = entry(BudgetTxKind::Adjust, i64::MIN, i64::MIN, i64::MIN, reason);
    adjust.settled = true;
    adjust.estimated = true;
    vec![settle, adjust]
}

fn largest_records() -> Vec<(&'static str, EventType, Value)> {
    let extreme = |entries| delta(rsv(u8::MAX), entries);
    // `[CONSCIOUS ASSUMPTION]` An upstream name is a token of at most 64 bytes, like a reason code
    // or a module name; S4 bounds it where the route is configured.
    let upstream = "u".repeat(64);
    vec![
        (
            "op.failed with [settle, adjust]",
            types::OP_FAILED,
            with_ledger(
                json!({"reason": LONGEST_REASON, "usage_final": false, "may_have_taken_effect": true}),
                extreme(extreme_settlement(LONGEST_REASON)),
            ),
        ),
        (
            "a stuck_repair resolution with [settle, adjust]",
            types::OP_COMMITTED,
            with_ledger(
                json!({"reason": "stuck_repair", "resolution": "settled"}),
                extreme(extreme_settlement("stuck_repair")),
            ),
        ),
        (
            "the intent at its bounds",
            types::OP_RESERVED_INTENT,
            with_ledger(
                json!({"kind": "budget_transfer", "upstream": upstream, "durability": "balanced"}),
                extreme(vec![entry(
                    BudgetTxKind::Reserve,
                    i64::MAX,
                    i64::MIN,
                    i64::MIN,
                    LONGEST_REASON,
                )]),
            ),
        ),
    ]
}

#[test]
fn the_largest_records_fit_the_inline_payload_and_journal() {
    let fs = SimFs::new();
    fs.create_dir_all(Path::new("/data")).unwrap();
    let mut journal = Journal::open(
        Arc::new(fs.clone()),
        Arc::new(SimClock::new(
            WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
        )),
        Arc::new(SimRng::new(7)),
        Path::new("/data"),
        FlushPolicy::Balanced { window: Millis(60_000) },
    )
    .unwrap();
    for (what, event_type, payload) in largest_records() {
        let bytes = serde_json::to_vec(&payload).unwrap().len();
        assert!(
            MAX_INLINE_PAYLOAD.admits(bytes),
            "{what} is {bytes} bytes, past the inline payload's {} bytes",
            MAX_INLINE_PAYLOAD.0
        );
        let draft = EventDraft {
            session_id: None,
            pocket_id: None,
            operation_id: Some(op(1)),
            request_id: None,
            agent_id: None,
            correlation_id: CorrelationId::from_parts(5, [5; 10]),
            parent_id: None,
            actor: agent(),
            event_type,
            payload_ref: None,
            payload_inline: Some(InlinePayload::new(payload).unwrap()),
            cost_estimate: None,
            compensable: false,
            side_effect_class: SideEffectClass::External,
            risk_tier: RiskTier::MAX,
            durability: Durability::Critical,
            config_version: ConfigVersion(1),
            metadata: Metadata::default(),
        };
        journal.append(draft).unwrap();
    }
}

// ---------------------------------------------------------------------------------------------
// The reader: valid histories
// ---------------------------------------------------------------------------------------------

#[test]
fn a_one_record_journal_reads_back_the_entries_its_ledger_wrote() {
    let mut ledger = Ledger::default();
    let mut sink = MemorySink::default();
    ledger
        .allocate(
            &mut sink,
            pool(),
            usd(100),
            &agent(),
            IdempotencyKey::new("fund").unwrap(),
        )
        .unwrap();
    let held = ledger.reserve(&mut sink, pool(), rsv(1), usd(30), &agent()).unwrap();
    ledger
        .settle(&mut sink, held.begin(), Usage::Reported(usd(20)), &agent())
        .unwrap();
    let (fund, reserve, close) = (&sink.entries[0], &sink.entries[1..2], &sink.entries[2..]);
    let mut records = Records::default();
    records
        .push(types::BUDGET_ENTRY, None, Some(serde_json::to_value(fund).unwrap()))
        .push(
            types::OP_RESERVED_INTENT,
            Some(op(1)),
            Some(with_ledger(
                json!({"kind": "model_call", "upstream": "primary", "durability": "balanced"}),
                serde_json::to_value(compact(reserve, &agent()).unwrap()).unwrap(),
            )),
        )
        .executing(op(1))
        .push(
            types::OP_COMMITTED,
            Some(op(1)),
            Some(with_ledger(
                json!({"reason": "completed", "usage_final": true}),
                serde_json::to_value(compact(close, &agent()).unwrap()).unwrap(),
            )),
        );
    let read = records.read().unwrap();
    assert_eq!(
        read, sink.entries,
        "the reader did not return the ledger's entries in order"
    );
    assert_eq!(Ledger::replay(&read).unwrap().state(), ledger.state());
}

#[test]
fn every_closing_place_of_the_table_reads() {
    // Denied by the final scan, before `op.executing`.
    let mut denied = Records::default();
    denied.intent(op(1), rsv(1)).closing(types::OP_DENIED, op(1), release());
    denied.read().unwrap();
    // Failed before `op.executing`, released.
    let mut failed = Records::default();
    failed.intent(op(1), rsv(1)).closing(types::OP_FAILED, op(1), release());
    failed.read().unwrap();
    // Failed after `op.executing`, settled.
    let mut after = Records::default();
    after
        .intent(op(1), rsv(1))
        .executing(op(1))
        .closing(types::OP_FAILED, op(1), settlement());
    after.read().unwrap();
    // Recovered at boot: the full reservation, estimated; then a resolution without entries.
    let mut recovered = Records::default();
    let mut estimated = entry(BudgetTxKind::Settle, 30, 70, 70, "settle_estimated");
    estimated.settled = true;
    estimated.estimated = true;
    recovered
        .intent(op(1), rsv(1))
        .closing(types::OP_INDETERMINATE, op(1), vec![estimated])
        .push(types::OP_COMMITTED, Some(op(1)), Some(json!({"reason": "evidence"})));
    recovered.read().unwrap();
    // A stuck item, then its repair as the Operation's resolution.
    let mut repaired = Records::default();
    let mut repair = entry(BudgetTxKind::Release, 30, 70, 100, "stuck_repair");
    repair.settled = true;
    repaired
        .intent(op(1), rsv(1))
        .push(
            types::OP_INDETERMINATE,
            Some(op(1)),
            Some(json!({"reason": "crash_recovery"})),
        )
        .closing(types::OP_FAILED, op(1), vec![repair]);
    let read = repaired.read().unwrap();
    assert_eq!(
        read.last().unwrap().idempotency_key.as_str(),
        format!("{}:repair_release", rsv(1))
    );
}

#[test]
fn a_two_record_history_is_read_as_before() {
    // Committed without `op.executing`, and a second intent: no transition check applies.
    let mut ledger = Ledger::default();
    let mut sink = MemorySink::default();
    ledger
        .allocate(
            &mut sink,
            pool(),
            usd(100),
            &agent(),
            IdempotencyKey::new("fund").unwrap(),
        )
        .unwrap();
    let held = ledger.reserve(&mut sink, pool(), rsv(1), usd(30), &agent()).unwrap();
    ledger
        .settle(&mut sink, held.begin(), Usage::Reported(usd(30)), &agent())
        .unwrap();
    let mut records = Records::default();
    for tx in &sink.entries[..2] {
        records.push(types::BUDGET_ENTRY, None, Some(serde_json::to_value(tx).unwrap()));
    }
    records
        .push(types::OP_RESERVED_INTENT, Some(op(1)), Some(json!({"model": "m"})))
        .push(
            types::BUDGET_ENTRY,
            None,
            Some(serde_json::to_value(&sink.entries[2]).unwrap()),
        )
        .push(types::OP_COMMITTED, Some(op(1)), None)
        .push(types::OP_RESERVED_INTENT, Some(op(1)), Some(json!({"model": "m"})));
    assert_eq!(
        records.read().unwrap(),
        sink.entries,
        "a two-record journal was refused or read differently"
    );
}

// The reader's refusals, one per row of §5.2 and rule of §3.3
// ---------------------------------------------------------------------------------------------

#[test]
fn an_unknown_op_type_carrying_a_delta_is_unreadable() {
    let mut records = Records::default();
    records.push(
        EventType::new("op.settled_later").unwrap(),
        Some(op(1)),
        Some(with_ledger(json!({}), delta(rsv(1), release()))),
    );
    let error = refused(&records, "an unknown op. carrier was accepted");
    assert_eq!(
        error.code(),
        codes::BUDGET_ENTRIES_UNREADABLE,
        "an unknown carrier was not refused as unreadable: {error}"
    );
}

#[test]
fn a_delta_from_a_newer_writer_is_unreadable() {
    // Another version.
    let mut newer = delta(rsv(1), vec![reserve()]);
    newer["v"] = json!(2);
    let mut records = Records::default();
    records.push(
        types::OP_RESERVED_INTENT,
        Some(op(1)),
        Some(with_ledger(json!({}), newer)),
    );
    assert_eq!(
        refused(&records, "a delta of another version was accepted").code(),
        codes::BUDGET_ENTRIES_UNREADABLE
    );
    // A field this kernel does not know, on the delta and on an entry.
    for path in ["top", "entry"] {
        let mut extra = delta(rsv(1), vec![reserve()]);
        if path == "top" {
            extra["priority"] = json!(1);
        } else {
            extra["entries"][0]["tax"] = json!("0");
        }
        let mut records = Records::default();
        records.push(
            types::OP_RESERVED_INTENT,
            Some(op(1)),
            Some(with_ledger(json!({}), extra)),
        );
        let error = refused(&records, "a delta with an unknown field was accepted");
        assert_eq!(
            error.code(),
            codes::BUDGET_ENTRIES_UNREADABLE,
            "a delta with an unknown field was not refused as unreadable: {error}"
        );
    }
    // An entry kind this kernel does not know.
    let mut kind = delta(rsv(1), vec![reserve()]);
    kind["entries"][0]["kind"] = json!("rebate");
    let mut records = Records::default();
    records.push(
        types::OP_RESERVED_INTENT,
        Some(op(1)),
        Some(with_ledger(json!({}), kind)),
    );
    assert_eq!(
        refused(&records, "a delta with an unknown entry kind was accepted").code(),
        codes::BUDGET_ENTRIES_UNREADABLE
    );
}

#[test]
fn a_delta_that_does_not_parse_is_inconsistent() {
    let mut broken = delta(rsv(1), vec![reserve()]);
    broken["entries"][0]["amount"] = json!("thirty");
    let mut records = Records::default();
    records.push(
        types::OP_RESERVED_INTENT,
        Some(op(1)),
        Some(with_ledger(json!({}), broken)),
    );
    let error = refused(&records, "a delta that does not parse was accepted");
    assert!(
        matches!(
            error,
            ReadError::Inconsistent {
                why: "a ledger delta does not parse",
                ..
            }
        ),
        "a delta that does not parse was accepted: {error:?}"
    );
}

#[test]
fn a_record_out_of_its_place_is_refused() {
    // A settlement where only a release fits: `op.denied` before `op.executing`.
    let mut records = Records::default();
    records
        .intent(op(1), rsv(1))
        .closing(types::OP_DENIED, op(1), settlement());
    let error = refused(&records, "entries out of their place were accepted");
    assert!(
        matches!(
            error,
            ReadError::Inconsistent {
                why: "a closing record's entries do not fit its place",
                ..
            }
        ),
        "entries out of their place were accepted: {error:?}"
    );
    // A step the Operation's state does not allow: committed without `op.executing`.
    let mut records = Records::default();
    records
        .intent(op(1), rsv(1))
        .closing(types::OP_COMMITTED, op(1), settlement());
    assert!(matches!(
        refused(&records, "a commit without op.executing was accepted"),
        ReadError::Inconsistent {
            why: "a step its Operation's state does not allow",
            ..
        }
    ));
    // A delta on an Operation without a one-record intent.
    let mut records = Records::default();
    records.closing(types::OP_FAILED, op(1), release());
    assert_eq!(
        refused(&records, "a delta on an Operation without an intent was accepted").code(),
        codes::BUDGET_LEDGER_INCONSISTENT
    );
}

#[test]
fn an_outcome_without_its_closing_entries_is_refused() {
    let mut records = Records::default();
    records
        .intent(op(1), rsv(1))
        .push(types::OP_DENIED, Some(op(1)), Some(json!({"reason": "scan"})));
    let error = refused(&records, "an outcome that leaves the reservation open was accepted");
    assert!(
        matches!(
            error,
            ReadError::Inconsistent {
                why: "a first outcome after a one-record intent carries no closing entries",
                ..
            }
        ),
        "an outcome that leaves the reservation open was accepted: {error:?}"
    );
}

#[test]
fn an_intent_without_its_operation_is_refused() {
    let mut records = Records::default();
    records.push(
        types::OP_RESERVED_INTENT,
        None,
        Some(with_ledger(json!({}), delta(rsv(1), vec![reserve()]))),
    );
    let error = refused(&records, "an intent without an operation_id was accepted");
    assert!(
        matches!(
            error,
            ReadError::Inconsistent {
                why: "a ledger delta on a record without an Operation",
                ..
            }
        ),
        "an intent without an operation_id was accepted: {error:?}"
    );
}

#[test]
fn a_closing_record_for_another_reservation_is_refused() {
    let mut records = Records::default();
    records
        .intent(op(1), rsv(1))
        .closing_for(types::OP_DENIED, op(1), rsv(2), release());
    let error = refused(&records, "a close of another reservation was accepted");
    assert!(
        matches!(
            error,
            ReadError::Inconsistent {
                why: "a closing record names a reservation its intent did not establish",
                ..
            }
        ),
        "a close of another reservation was accepted: {error:?}"
    );
    // An intent that names another Operation's reservation.
    let mut records = Records::default();
    records.intent(op(1), rsv(1)).intent(op(2), rsv(1));
    assert!(matches!(
        refused(
            &records,
            "an intent naming another Operation's reservation was accepted"
        ),
        ReadError::Inconsistent {
            why: "an intent names another Operation's reservation",
            ..
        }
    ));
}

#[test]
fn entries_after_the_outcome_are_refused() {
    // Recovery settled the reservation; a resolution may not carry entries again.
    let mut estimated = entry(BudgetTxKind::Settle, 30, 70, 70, "settle_estimated");
    estimated.settled = true;
    estimated.estimated = true;
    let mut repair = entry(BudgetTxKind::Settle, 30, 70, 70, "stuck_repair");
    repair.settled = true;
    let mut records = Records::default();
    records
        .intent(op(1), rsv(1))
        .closing(types::OP_INDETERMINATE, op(1), vec![estimated])
        .closing(types::OP_COMMITTED, op(1), vec![repair]);
    let error = refused(&records, "entries after the reservation closed were accepted");
    assert!(
        matches!(
            error,
            ReadError::Inconsistent {
                why: "a record after its Operation's outcome carries entries",
                ..
            }
        ),
        "entries after the reservation closed were accepted: {error:?}"
    );
}

#[test]
fn a_second_intent_is_refused() {
    let mut records = Records::default();
    records.intent(op(1), rsv(1)).intent(op(1), rsv(2));
    let error = refused(&records, "a second one-record intent was accepted");
    assert!(
        matches!(
            error,
            ReadError::Inconsistent {
                why: "an Operation has a second one-record intent",
                ..
            }
        ),
        "a second one-record intent was accepted: {error:?}"
    );
    // A one-record intent after a two-record one.
    let mut records = Records::default();
    records
        .push(types::OP_RESERVED_INTENT, Some(op(1)), Some(json!({"model": "m"})))
        .intent(op(1), rsv(1));
    assert!(matches!(
        refused(&records, "a one-record intent after a two-record one was accepted"),
        ReadError::Inconsistent {
            why: "a one-record intent follows a two-record one",
            ..
        }
    ));
}

#[test]
fn a_budget_entry_never_names_a_one_record_reservation() {
    let mut ledger = Ledger::default();
    let mut sink = MemorySink::default();
    ledger
        .allocate(
            &mut sink,
            pool(),
            usd(100),
            &agent(),
            IdempotencyKey::new("fund").unwrap(),
        )
        .unwrap();
    let held = ledger.reserve(&mut sink, pool(), rsv(1), usd(30), &agent()).unwrap();
    ledger.release(&mut sink, held, &agent()).unwrap();
    let mut records = Records::default();
    records.intent(op(1), rsv(1)).push(
        types::BUDGET_ENTRY,
        None,
        Some(serde_json::to_value(&sink.entries[2]).unwrap()),
    );
    let error = refused(&records, "a budget.entry closing a one-record reservation was accepted");
    assert!(
        matches!(
            error,
            ReadError::Inconsistent {
                seq: 1,
                why: "a budget.entry names a reservation a one-record intent established"
            }
        ),
        "a budget.entry closing a one-record reservation was accepted: {error:?}"
    );
}

#[test]
fn a_resolution_must_be_a_repair() {
    let mut records = Records::default();
    records
        .intent(op(1), rsv(1))
        .push(
            types::OP_INDETERMINATE,
            Some(op(1)),
            Some(json!({"reason": "crash_recovery"})),
        )
        .closing(types::OP_FAILED, op(1), release());
    assert!(matches!(
        refused(&records, "a resolution that is not a repair was accepted"),
        ReadError::Inconsistent {
            why: "a resolution's entries are not a repair's",
            ..
        }
    ));
}

// Carriers by type
// ---------------------------------------------------------------------------------------------

#[test]
fn a_known_type_that_carries_no_entries_refuses_a_delta() {
    for event_type in [types::BUDGET_SETTLED, types::BUDGET_RELEASED, types::KERNEL_BOOTED] {
        let mut records = Records::default();
        records.push(
            event_type.clone(),
            None,
            Some(with_ledger(json!({}), delta(rsv(1), release()))),
        );
        let error = refused(&records, "a delta on a known type that carries none was accepted");
        assert!(
            matches!(
                error,
                ReadError::Inconsistent {
                    why: "a ledger delta on a record type that carries none",
                    ..
                }
            ),
            "a delta on {event_type} was not refused: {error:?}"
        );
    }
    // `op.executing` and `op.approval_required` in a one-record history.
    let mut records = Records::default();
    records
        .intent(op(1), rsv(1))
        .closing(types::OP_EXECUTING, op(1), release());
    assert!(matches!(
        refused(&records, "a delta on op.executing was accepted"),
        ReadError::Inconsistent {
            why: "a ledger delta on a record type that carries none",
            ..
        }
    ));
    let mut records = Records::default();
    records
        .intent(op(1), rsv(1))
        .closing(types::OP_APPROVAL_REQUIRED, op(1), release());
    assert_eq!(
        refused(&records, "a delta on op.approval_required was accepted").code(),
        codes::BUDGET_LEDGER_INCONSISTENT
    );
}

#[test]
fn an_unknown_kernel_domain_carrier_is_unreadable_and_a_module_event_is_not_read() {
    for name in ["kernel.rebalanced", "grant.charged"] {
        let mut records = Records::default();
        records.push(
            EventType::new(name).unwrap(),
            None,
            Some(with_ledger(json!({}), delta(rsv(1), release()))),
        );
        let error = refused(&records, "a carrier of an unknown kernel type was accepted");
        assert_eq!(
            error.code(),
            codes::BUDGET_ENTRIES_UNREADABLE,
            "a carrier of the unknown kernel type {name} was not refused: {error}"
        );
    }
    // A module's event payload is its own: a field named `ledger` is not read.
    let mut records = Records::default();
    records.push(
        EventType::new("module.event").unwrap(),
        None,
        Some(json!({"ledger": "the module's own word"})),
    );
    assert_eq!(records.read().unwrap(), Vec::<BudgetTx>::new());
}
