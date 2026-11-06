// SPDX-License-Identifier: Apache-2.0

//! Projections are a pure function of the journal: incremental maintenance (across journal
//! crashes and reopens) must equal a rebuild from scratch, and a projection that no longer
//! matches its journal must rebuild itself.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use proptest::prelude::*;
use uaos_contracts::event::{Actor, Durability, EventType, Metadata, types};
use uaos_contracts::id::{CorrelationId, OperationId, TypedId};
use uaos_contracts::limits::Millis;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::ConfigVersion;
use uaos_platform::fs::Fs;
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, Rng};
use uaos_state::journal::{EventDraft, FlushPolicy, JOURNAL_DIR, Journal};
use uaos_state::projection::{ProjectionError, Projections};

struct World {
    fs: SimFs,
    clock: Arc<SimClock>,
    rng: Arc<SimRng>,
    data: PathBuf,
}

impl World {
    fn new(seed: u64) -> Self {
        let fs = SimFs::new();
        let data = PathBuf::from("/data");
        fs.create_dir_all(&data).unwrap();
        Self {
            fs,
            clock: Arc::new(SimClock::new(
                WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
            )),
            rng: Arc::new(SimRng::new(seed)),
            data,
        }
    }

    fn journal(&self) -> Journal {
        let clock: Arc<dyn Clock> = self.clock.clone();
        let rng: Arc<dyn Rng> = self.rng.clone();
        Journal::open(
            Arc::new(self.fs.clone()),
            clock,
            rng,
            &self.data,
            FlushPolicy::Balanced { window: Millis(60_000) },
        )
        .unwrap()
    }

    fn dir(&self) -> PathBuf {
        self.data.join(JOURNAL_DIR)
    }
}

fn draft(event_type: EventType, op: Option<u8>, correlation: u8) -> EventDraft {
    EventDraft {
        session_id: None,
        pocket_id: None,
        operation_id: op.map(|o| OperationId::from_parts(u64::from(o), [o; 10])),
        request_id: None,
        agent_id: None,
        correlation_id: CorrelationId::from_parts(u64::from(correlation), [correlation; 10]),
        parent_id: None,
        actor: Actor::System,
        event_type,
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

fn event_type(kind: u8) -> EventType {
    match kind % 5 {
        0 => types::OP_RESERVED_INTENT,
        1 => types::OP_COMMITTED,
        2 => types::OP_FAILED,
        3 => types::OP_INDETERMINATE,
        _ => EventType::new("mod.test.note").unwrap(),
    }
}

#[test]
fn operation_states_and_open_intents() {
    let w = World::new(1);
    let mut j = w.journal();
    j.append(draft(types::OP_RESERVED_INTENT, Some(1), 7)).unwrap();
    j.append(draft(types::OP_COMMITTED, Some(1), 7)).unwrap();
    j.append(draft(types::OP_RESERVED_INTENT, Some(2), 8)).unwrap();
    j.append(draft(EventType::new("mod.test.note").unwrap(), Some(2), 8))
        .unwrap();

    let mut p = Projections::open_in_memory().unwrap();
    let caught = p.catch_up(&w.fs, &w.dir()).unwrap();
    assert_eq!((caught.applied, caught.rebuilt), (4, true));

    let op1 = p.operation(OperationId::from_parts(1, [1; 10])).unwrap().unwrap();
    assert_eq!((op1.state.as_str(), op1.first_seq, op1.last_seq), ("committed", 0, 1));
    let op2 = p.operation(OperationId::from_parts(2, [2; 10])).unwrap().unwrap();
    assert_eq!(
        op2.state, "reserved",
        "an unknown event type does not change the recorded state"
    );
    assert_eq!(
        p.open_intents().unwrap(),
        [OperationId::from_parts(2, [2; 10]).to_string()]
    );

    let trace = p.trace(CorrelationId::from_parts(8, [8; 10])).unwrap();
    assert_eq!(trace.iter().map(|e| e.seq).collect::<Vec<_>>(), [2, 3]);
}

#[test]
fn apply_refuses_records_that_do_not_continue_the_cursor() {
    let w = World::new(2);
    let mut j = w.journal();
    for i in 0..3 {
        j.append(draft(types::OP_RESERVED_INTENT, Some(i), i)).unwrap();
    }
    let (records, _) = uaos_state::journal::read_verified(&w.fs, &w.dir()).unwrap();
    let mut p = Projections::open_in_memory().unwrap();
    assert!(matches!(
        p.apply(&records[1..]),
        Err(ProjectionError::Discontinuous { expected: 0 })
    ));
    p.apply(&records[..2]).unwrap();
    assert!(matches!(
        p.apply(&records[..1]),
        Err(ProjectionError::Discontinuous { expected: 2 })
    ));
}

#[test]
fn a_projection_of_another_journal_rebuilds_itself() {
    let (a, b) = (World::new(3), World::new(4));
    for (w, n) in [(&a, 3), (&b, 5)] {
        let mut j = w.journal();
        for i in 0..n {
            j.append(draft(types::OP_RESERVED_INTENT, Some(i), i)).unwrap();
        }
    }
    let mut p = Projections::open_in_memory().unwrap();
    p.catch_up(&a.fs, &a.dir()).unwrap();
    let switched = p.catch_up(&b.fs, &b.dir()).unwrap();
    assert!(switched.rebuilt);
    let mut fresh = Projections::open_in_memory().unwrap();
    fresh.rebuild(&b.fs, &b.dir()).unwrap();
    assert_eq!(p.dump().unwrap(), fresh.dump().unwrap());
}

#[test]
fn file_backed_projection_persists_and_can_be_deleted() {
    #[allow(clippy::disallowed_methods, reason = "test scaffolding for a real SQLite file")]
    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("uaos-projection-{}", std::process::id()));
        let _stale = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
    let w = World::new(5);
    let mut j = w.journal();
    for i in 0..10 {
        j.append(draft(event_type(i), Some(i % 3), i % 4)).unwrap();
    }
    let dir = scratch();
    let db: &Path = &dir.join("state.db");
    let before = {
        let mut p = Projections::open(db).unwrap();
        p.catch_up(&w.fs, &w.dir()).unwrap();
        p.dump().unwrap()
    };
    {
        let mut p = Projections::open(db).unwrap();
        assert_eq!(p.catch_up(&w.fs, &w.dir()).unwrap().applied, 0, "cursor persisted");
        assert_eq!(p.dump().unwrap(), before);
    }
    #[allow(clippy::disallowed_methods, reason = "test scaffolding: delete the cache")]
    {
        let _gone = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
    }
    let mut p = Projections::open(db).unwrap();
    assert!(p.catch_up(&w.fs, &w.dir()).unwrap().rebuilt);
    assert_eq!(p.dump().unwrap(), before, "a deleted projection rebuilds identically");
}

// ── Rebuild equivalence ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Op {
    Append { kind: u8, op: Option<u8>, correlation: u8 },
    CatchUp,
    CrashJournal,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        8 => (any::<u8>(), prop::option::of(0u8..6), 0u8..4)
            .prop_map(|(kind, op, correlation)| Op::Append { kind, op, correlation }),
        3 => Just(Op::CatchUp),
        1 => Just(Op::CrashJournal),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn incremental_equals_rebuild(seed in any::<u64>(), ops in prop::collection::vec(op(), 1..80)) {
        let w = World::new(seed);
        let mut j = w.journal();
        let mut incremental = Projections::open_in_memory().unwrap();
        for step in ops {
            match step {
                Op::Append { kind, op, correlation } => {
                    j.append(draft(event_type(kind), op, correlation)).unwrap();
                }
                Op::CatchUp => {
                    let outcome = incremental.catch_up(&w.fs, &w.dir()).unwrap();
                    prop_assert!(!outcome.rebuilt || incremental.event_count().unwrap() == u64::try_from(outcome.applied).unwrap());
                }
                Op::CrashJournal => {
                    w.fs.crash();
                    drop(j);
                    j = w.journal();
                }
            }
        }
        incremental.catch_up(&w.fs, &w.dir()).unwrap();
        let mut rebuilt = Projections::open_in_memory().unwrap();
        rebuilt.rebuild(&w.fs, &w.dir()).unwrap();
        prop_assert_eq!(incremental.dump().unwrap(), rebuilt.dump().unwrap());
    }
}
