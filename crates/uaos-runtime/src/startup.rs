// SPDX-License-Identifier: Apache-2.0

//! The kernel's startup sequence. The journal opens once, with its chunk store, and hands back the
//! records it verified. Boot recovers from those records and writes its own: no actor runs yet, so
//! there is no second writer. Then the journal moves into the state actor, its one writer from then
//! on. The actor keeps the stop boot restored: a stop the journal left engaged is already
//! journaled, so nothing is recorded twice. Opening admission is the caller's step 5.

use std::path::PathBuf;
use std::sync::Arc;

use uaos_contracts::event::Actor;
use uaos_contracts::id::CorrelationId;
use uaos_contracts::wire::Seq;
use uaos_ledger::Ledger;
use uaos_platform::fs::Fs;
use uaos_platform::{Clock, Rng};
use uaos_state::chunks::ChunkStore;
use uaos_state::journal::{FlushPolicy, Journal, JournalError, Opened};

use crate::boot::{BootError, BootReport, Booted, boot};
use crate::config::ConfigSnapshot;
use crate::state::{StartRefused, StateActor, StateCore, StateHandle, start_state_actor, state_queue};
use crate::stop::{EngagedBy, Stop};
use crate::supervisor::Supervisor;

/// Where the journal lives and how it flushes: what [`Journal::open_with_payloads`] takes.
#[derive(Clone)]
#[non_exhaustive]
pub struct JournalSource {
    /// The file system.
    pub fs: Arc<dyn Fs>,
    /// The clock the journal and the actor's flush schedule run on.
    pub clock: Arc<dyn Clock>,
    /// Randomness for record identifiers.
    pub rng: Arc<dyn Rng>,
    /// The data directory.
    pub data_dir: PathBuf,
    /// The flush policy.
    pub flush: FlushPolicy,
    /// The chunk store whose durability the journal coordinates.
    pub payloads: Arc<ChunkStore>,
}

impl JournalSource {
    /// The journal in `data_dir`, with its chunk store.
    #[must_use]
    pub fn new(
        fs: Arc<dyn Fs>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        data_dir: PathBuf,
        flush: FlushPolicy,
        payloads: Arc<ChunkStore>,
    ) -> Self {
        Self {
            fs,
            clock,
            rng,
            data_dir,
            flush,
            payloads,
        }
    }
}

impl std::fmt::Debug for JournalSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalSource")
            .field("data_dir", &self.data_dir)
            .field("flush", &self.flush)
            .finish_non_exhaustive()
    }
}

/// A started kernel: boot's results, and the state actor that owns the journal.
#[derive(Debug)]
#[non_exhaustive]
pub struct Started {
    /// The stop, as the journal left it; the actor journals its later engagements.
    pub stop: Stop,
    /// The ledger, replayed and recovered. It writes to the journal through the actor once wires
    /// its sink there (`StateHandle::blocking`).
    pub ledger: Ledger,
    /// What the boot did.
    pub report: BootReport,
    /// The sequence number the first record after boot takes.
    pub next_seq: Seq,
    /// The handle every writer appends through.
    pub state: StateHandle,
    /// The actor's thread.
    pub actor: StateActor,
}

/// Why the kernel did not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartupError {
    /// The journal did not open; nothing of this start was written.
    #[error("the journal did not open: {0}")]
    Open(#[source] JournalError),
    /// Boot refused or failed (its own error says whether anything was written).
    #[error("boot failed: {0}")]
    Boot(#[source] BootError),
    /// The previous clean end's seal could not be removed. Starting would let a later loss of this
    /// run's records read as that clean end, so the kernel does not start. Boot's records are then
    /// acknowledged but not flushed: after a crash the next boot reads a crash (boot's record
    /// follows the shutdown), after a power loss it reads the clean end again, which is honest,
    /// since nothing ran.
    #[error("the previous clean end's seal could not be removed: {0}")]
    Unseal(#[source] JournalError),
    /// The actor's thread did not start. The refusal hands back the journal, with boot's records
    /// acknowledged, so the caller can flush it before it exits.
    #[error("{0}")]
    Actor(#[source] Box<StartRefused>),
}

/// Starts the kernel: opens the journal once, boots from the records it verified, removes the
/// previous clean end's seal, and moves the journal into the state actor, which serves a queue of
/// `queue_capacity` commands. The actor engages the stop as the system, under `correlation`, if the
/// journal fails. This is the only way a kernel starts: building a core with [`StateCore::new`]
/// skips the seal's removal, and is for tests and benches.
///
/// # Errors
/// [`StartupError`]: the open, boot, the seal's removal, or the actor's start.
pub fn start_kernel(
    source: JournalSource,
    config: &ConfigSnapshot,
    correlation: CorrelationId,
    supervisor: &Supervisor,
    queue_capacity: usize,
) -> Result<Started, StartupError> {
    let JournalSource {
        fs,
        clock,
        rng,
        data_dir,
        flush,
        payloads,
    } = source;
    let Opened {
        mut journal,
        records,
        evidence,
    } = Journal::open_with_payloads(fs, clock, rng, &data_dir, flush, payloads).map_err(StartupError::Open)?;
    let Booted { stop, ledger, report } =
        boot(&mut journal, &records, evidence, config, correlation).map_err(StartupError::Boot)?;
    // Boot was the records' last reader.
    drop(records);
    // Before anything can run, the clean end's seal goes: from here on this run's records may be
    // lost to a crash, and a loss must not read as the end the seal recorded.
    journal.unseal().map_err(StartupError::Unseal)?;
    let next_seq = journal.next_seq();
    let by = EngagedBy {
        actor: Actor::System,
        correlation_id: correlation,
        config_version: config.version(),
    };
    let core = StateCore::new(journal).with_stop(stop.clone(), by);
    let (state, queue) = state_queue(queue_capacity);
    let actor = start_state_actor(supervisor, core, queue).map_err(StartupError::Actor)?;
    Ok(Started {
        stop,
        ledger,
        report,
        next_seq,
        state,
        actor,
    })
}
