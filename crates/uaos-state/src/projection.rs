// SPDX-License-Identifier: Apache-2.0

//! SQLite projections of the journal (the journal is the truth, SQLite a cache).
//!
//! A projection is a pure function of the journal. It holds **metadata only** — event index,
//! operation states, the cursor — never content (content lives encrypted in the chunk store).
//! Because it is derived, it may be deleted at any time: [`Projections::catch_up`] continues
//! from the cursor, and rebuilds from scratch whenever the cursor no longer matches the journal
//! (a different journal, a rewritten history, a damaged cache).
//!
//! The defining property, proven in tests: an incrementally maintained projection is identical
//! to one rebuilt from scratch ([`Projections::dump`] compares them canonically).
//!
//! SQLite opens its file itself, outside `uaos_platform::fs`. That is acceptable only because
//! nothing here is a source of truth: losing or corrupting the file loses nothing.

use std::fmt::Write as _;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use uaos_contracts::digest::Sha256Digest;
use uaos_contracts::event::{Actor, types};
use uaos_contracts::id::{CorrelationId, OperationId};
use uaos_contracts::operation::OperationState;
use uaos_platform::fs::Fs;

use crate::journal::{JournalError, VerifiedRecord, read_verified};

/// Projection schema version; a mismatch triggers a rebuild.
const SCHEMA_VERSION: &str = "1";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    ts_wall TEXT NOT NULL,
    type TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    session_id TEXT,
    pocket_id TEXT,
    operation_id TEXT,
    request_id TEXT,
    parent_id TEXT,
    actor TEXT NOT NULL,
    payload_ref TEXT,
    side_effect_class TEXT NOT NULL,
    risk_tier INTEGER NOT NULL,
    compensable INTEGER NOT NULL,
    cost_nano_usd INTEGER,
    hash TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS events_by_correlation ON events(correlation_id, seq);
CREATE INDEX IF NOT EXISTS events_by_operation ON events(operation_id, seq);
CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    side_effect_class TEXT NOT NULL,
    compensable INTEGER NOT NULL,
    risk_tier INTEGER NOT NULL,
    first_seq INTEGER NOT NULL,
    last_seq INTEGER NOT NULL
) STRICT;
";

/// Projection failure.
#[derive(Debug, thiserror::Error)]
pub enum ProjectionError {
    /// SQLite reported an error.
    #[error("projection database error: {0}")]
    Sql(#[from] rusqlite::Error),
    /// Reading the journal failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Records do not continue the projection's cursor.
    #[error("records do not continue the projection cursor (expected seq {expected})")]
    Discontinuous {
        /// Sequence number the projection expected next.
        expected: u64,
    },
    /// A value does not fit the projection's integer columns.
    #[error("value out of range for the projection")]
    OutOfRange,
}

/// Where the projection stands relative to the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    /// Last applied sequence number.
    pub seq: u64,
    /// Chain hash of that record.
    pub hash: Sha256Digest,
}

/// What [`Projections::catch_up`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatchUp {
    /// Records applied in this call.
    pub applied: usize,
    /// Whether the projection was discarded and rebuilt from the journal's start.
    pub rebuilt: bool,
}

/// One projected event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRow {
    /// Sequence number.
    pub seq: u64,
    /// Event type.
    pub event_type: String,
    /// Operation, if any.
    pub operation_id: Option<String>,
}

/// One projected operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRow {
    /// Latest lifecycle state recorded in the journal.
    pub state: String,
    /// First and last journal records concerning it.
    pub first_seq: u64,
    /// Last journal record concerning it.
    pub last_seq: u64,
}

/// The projection database.
#[derive(Debug)]
pub struct Projections {
    conn: Connection,
}

fn to_i64(v: u64) -> Result<i64, ProjectionError> {
    i64::try_from(v).map_err(|_| ProjectionError::OutOfRange)
}

fn to_u64(v: i64) -> Result<u64, ProjectionError> {
    u64::try_from(v).map_err(|_| ProjectionError::OutOfRange)
}

fn snake<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The operation state an event type records, if it records one.
fn state_for(event_type: &str) -> Option<OperationState> {
    let pairs = [
        (&types::OP_RESERVED_INTENT, OperationState::Reserved),
        (&types::OP_COMMITTED, OperationState::Committed),
        (&types::OP_FAILED, OperationState::Failed),
        (&types::OP_DENIED, OperationState::Denied),
        (&types::OP_APPROVAL_REQUIRED, OperationState::ApprovalRequired),
        (&types::OP_INDETERMINATE, OperationState::Indeterminate),
    ];
    pairs.iter().find(|(t, _)| t.as_str() == event_type).map(|(_, s)| *s)
}

fn actor_label(actor: &Actor) -> String {
    match actor {
        Actor::Human => "human".to_owned(),
        Actor::Agent { credential } => format!("agent:{credential}"),
        Actor::Module { name } => format!("module:{name}"),
        Actor::System => "system".to_owned(),
    }
}

impl Projections {
    /// Opens (or creates) the projection database at `path`.
    ///
    /// # Errors
    /// SQLite failures.
    pub fn open(path: &Path) -> Result<Self, ProjectionError> {
        Self::init(Connection::open(path)?)
    }

    /// Opens a throwaway in-memory projection.
    ///
    /// # Errors
    /// SQLite failures.
    pub fn open_in_memory() -> Result<Self, ProjectionError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, ProjectionError> {
        // WAL for concurrent readers; NORMAL sync is enough for a rebuildable cache.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        let mut p = Self { conn };
        if p.meta("schema_version")?.as_deref() != Some(SCHEMA_VERSION) {
            p.clear()?;
        }
        Ok(p)
    }

    fn meta(&self, key: &str) -> Result<Option<String>, ProjectionError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    fn clear(&mut self) -> Result<(), ProjectionError> {
        let tx = self.conn.transaction()?;
        tx.execute_batch("DELETE FROM events; DELETE FROM operations; DELETE FROM meta;")?;
        tx.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)",
            [SCHEMA_VERSION],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The last applied record, if any.
    ///
    /// # Errors
    /// SQLite failures, or a malformed stored cursor.
    pub fn cursor(&self) -> Result<Option<Cursor>, ProjectionError> {
        let (Some(seq), Some(hash)) = (self.meta("cursor_seq")?, self.meta("cursor_hash")?) else {
            return Ok(None);
        };
        let seq = seq.parse::<u64>().map_err(|_| ProjectionError::OutOfRange)?;
        let hash = hash.parse::<Sha256Digest>().map_err(|_| ProjectionError::OutOfRange)?;
        Ok(Some(Cursor { seq, hash }))
    }

    /// Applies records that directly continue the cursor, atomically with the cursor update.
    ///
    /// # Errors
    /// `Discontinuous` if the first record does not follow the cursor (sequence number and
    /// chain link); SQLite failures.
    pub fn apply(&mut self, records: &[VerifiedRecord]) -> Result<(), ProjectionError> {
        let Some(first) = records.first() else { return Ok(()) };
        let cursor = self.cursor()?;
        let expected = cursor.map_or(0, |c| c.seq + 1);
        let links = cursor.is_none_or(|c| first.envelope.prev_hash == c.hash);
        if first.envelope.seq.0 != expected || !links {
            return Err(ProjectionError::Discontinuous { expected });
        }
        let tx = self.conn.transaction()?;
        for rec in records {
            let e = &rec.envelope;
            let seq = to_i64(e.seq.0)?;
            tx.execute(
                "INSERT INTO events(seq, id, ts_wall, type, correlation_id, session_id, pocket_id, operation_id,
                    request_id, parent_id, actor, payload_ref, side_effect_class, risk_tier, compensable,
                    cost_nano_usd, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                params![
                    seq,
                    e.id.to_string(),
                    e.ts.wall.to_string(),
                    e.event_type.as_str(),
                    e.correlation_id.to_string(),
                    e.session_id.map(|v| v.to_string()),
                    e.pocket_id.map(|v| v.to_string()),
                    e.operation_id.map(|v| v.to_string()),
                    e.request_id.map(|v| v.to_string()),
                    e.parent_id.map(|v| v.to_string()),
                    actor_label(&e.actor),
                    e.payload_ref.map(|v| v.to_string()),
                    snake(&e.side_effect_class),
                    i64::from(e.risk_tier.get()),
                    i64::from(e.compensable),
                    e.cost_estimate.map(uaos_contracts::money::NanoUsd::get),
                    rec.hash.to_string(),
                ],
            )?;
            if let Some(op) = e.operation_id {
                let state = state_for(e.event_type.as_str());
                tx.execute(
                    "INSERT INTO operations(id, state, side_effect_class, compensable, risk_tier, first_seq, last_seq)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                     ON CONFLICT(id) DO UPDATE SET
                        state = COALESCE(?7, operations.state),
                        last_seq = excluded.last_seq",
                    params![
                        op.to_string(),
                        state.map_or_else(|| snake(&OperationState::Proposed), |s| snake(&s)),
                        snake(&e.side_effect_class),
                        i64::from(e.compensable),
                        i64::from(e.risk_tier.get()),
                        seq,
                        state.map(|s| snake(&s)),
                    ],
                )?;
            }
        }
        let last = records.last().map_or(first, |r| r);
        tx.execute(
            "INSERT INTO meta(key, value) VALUES ('cursor_seq', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [last.envelope.seq.0.to_string()],
        )?;
        tx.execute(
            "INSERT INTO meta(key, value) VALUES ('cursor_hash', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [last.hash.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Brings the projection up to date with the journal in `journal_dir`. Continues from the
    /// cursor when the journal still contains the cursor's record unchanged; otherwise discards
    /// everything and rebuilds.
    ///
    /// # Errors
    /// Journal verification or SQLite failures.
    pub fn catch_up(&mut self, fs: &dyn Fs, journal_dir: &Path) -> Result<CatchUp, ProjectionError> {
        let (records, report) = read_verified(fs, journal_dir)?;
        // The journal may not start at seq 0 once compaction exists: index by offset.
        let base = records.first().map_or(0, |r| r.envelope.seq.0);
        let index_of = |seq: u64| seq.checked_sub(base).and_then(|i| usize::try_from(i).ok());
        let same_journal = self.meta("journal_id")?.as_deref() == Some(report.journal_id.as_str());
        let cursor = self.cursor()?;
        let continues = same_journal
            && cursor.is_none_or(|c| {
                index_of(c.seq)
                    .and_then(|i| records.get(i))
                    .is_some_and(|r| r.envelope.seq.0 == c.seq && r.hash == c.hash)
            });
        let rebuilt = !continues;
        if rebuilt {
            self.clear()?;
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES ('journal_id', ?1)",
                [report.journal_id.as_str()],
            )?;
        }
        let pending = match self.cursor()? {
            Some(c) => index_of(c.seq + 1).and_then(|i| records.get(i..)).unwrap_or_default(),
            None => &records[..],
        };
        self.apply(pending)?;
        Ok(CatchUp {
            applied: pending.len(),
            rebuilt,
        })
    }

    /// Discards the projection and rebuilds it from the journal.
    ///
    /// # Errors
    /// Journal verification or SQLite failures.
    pub fn rebuild(&mut self, fs: &dyn Fs, journal_dir: &Path) -> Result<CatchUp, ProjectionError> {
        self.clear()?;
        self.catch_up(fs, journal_dir)
    }

    /// The latest state of an operation.
    ///
    /// # Errors
    /// SQLite failures.
    pub fn operation(&self, id: OperationId) -> Result<Option<OperationRow>, ProjectionError> {
        self.conn
            .query_row(
                "SELECT state, first_seq, last_seq FROM operations WHERE id = ?1",
                [id.to_string()],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
            )
            .optional()?
            .map(|(state, first, last)| {
                Ok(OperationRow {
                    state,
                    first_seq: to_u64(first)?,
                    last_seq: to_u64(last)?,
                })
            })
            .transpose()
    }

    /// Events of one correlation, in journal order (the basis of `uaos trace`).
    ///
    /// # Errors
    /// SQLite failures.
    pub fn trace(&self, correlation: CorrelationId) -> Result<Vec<EventRow>, ProjectionError> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, type, operation_id FROM events WHERE correlation_id = ?1 ORDER BY seq")?;
        let rows = stmt.query_map([correlation.to_string()], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?;
        rows.map(|row| {
            let (seq, event_type, operation_id) = row?;
            Ok(EventRow {
                seq: to_u64(seq)?,
                event_type,
                operation_id,
            })
        })
        .collect()
    }

    /// Operations whose write-ahead intent was recorded but no outcome followed. After a crash
    /// these become `Indeterminate`: never assumed done, never assumed undone (red line 3).
    ///
    /// # Errors
    /// SQLite failures.
    pub fn open_intents(&self) -> Result<Vec<String>, ProjectionError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM operations WHERE state = ?1 ORDER BY first_seq")?;
        let rows = stmt.query_map([snake(&OperationState::Reserved)], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Canonical text dump of every row, ordered deterministically. Two projections of the same
    /// journal must produce identical dumps.
    ///
    /// # Errors
    /// SQLite failures.
    pub fn dump(&self) -> Result<String, ProjectionError> {
        let mut out = String::new();
        for (table, order) in [("meta", "key"), ("events", "seq"), ("operations", "id")] {
            let mut stmt = self.conn.prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))?;
            let columns = stmt.column_count();
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                // Writing to a String cannot fail.
                let _infallible = write!(out, "{table}");
                for i in 0..columns {
                    let value: rusqlite::types::Value = row.get(i)?;
                    let _infallible = write!(out, "|{value:?}");
                }
                out.push('\n');
            }
        }
        Ok(out)
    }

    /// Number of projected events (diagnostics).
    ///
    /// # Errors
    /// SQLite failures.
    pub fn event_count(&self) -> Result<u64, ProjectionError> {
        let n: i64 = self.conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        to_u64(n)
    }
}
