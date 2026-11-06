// SPDX-License-Identifier: Apache-2.0

//! Stores a payload and appends a record that references it, on a real journal and chunk store,
//! until killed, acknowledging each record on stdout.
//!
//! Usage: `journal-crash-writer <data-dir> <strict|balanced> [kernel|direct]`
//!
//! * `kernel` (the default): the kernel's startup sequence runs first: the journal opens once, boot
//!   recovers from what it verified and journals `kernel.booted`, and the journal moves into the
//!   state actor. Every record then goes through the actor, as in a running kernel: a line is
//!   printed only after the actor's acknowledgement came back.
//! * `direct`: the records go straight into the journal, as before the actor existed; kept to
//!   tell a loss in the journal from one in the actor.
//!
//! Output: `start <next seq>` once, then `<seq> <hash> <chunk>` per acknowledged record. A line is
//! printed only after the append returned, i.e. after the record reached the OS, and the record is
//! appended only after its payload is stored (chunks before the record that references them). The
//! harness treats every complete line it reads as a promise: the record and its payload must both
//! survive the kill.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a harness binary whose protocol is its stdout"
)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use uaos_contracts::digest::ChunkRef;
use uaos_contracts::id::{CorrelationId, TypedId};
use uaos_contracts::wire::{ConfigVersion, Seq};
use uaos_platform::fs::Fs;
use uaos_platform::real::fs::OsFs;
use uaos_platform::real::{OsRng, SystemClock};
use uaos_platform::{Clock, Rng};
use uaos_runtime::{
    ConfigSnapshot, DEFAULT_QUEUE_CAPACITY, JournalSource, LocaleTag, Supervisor, SupervisorLimits, start_kernel,
};
use uaos_state::chunks::{ChunkDurability, ChunkStore};
use uaos_state::journal::{Appended, EventDraft, FlushPolicy, Journal};
use uaos_testkit::{intent_draft, kill_keyring, kill_payload, kill_pocket};

/// The exit code when the writer ends by itself, never by a kill.
const WRITER_FAILED: u8 = 3;

/// Where the records go.
enum Writer {
    /// Straight into the journal (boxed: the journal is much larger than a handle).
    Direct(Box<Journal>),
    /// Through the state actor of a started kernel, on a runtime of the writer's own.
    Kernel {
        runtime: tokio::runtime::Runtime,
        state: uaos_runtime::StateHandle,
        /// Kept alive: its thread is the journal's one writer.
        _actor: uaos_runtime::StateActor,
    },
}

impl Writer {
    fn append(&mut self, draft: EventDraft) -> Result<Appended, String> {
        match self {
            Self::Direct(journal) => journal.append(draft).map_err(|e| e.to_string()),
            Self::Kernel { runtime, state, .. } => runtime.block_on(state.append(draft)).map_err(|e| e.to_string()),
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(dir), Some(mode)) = (args.first(), args.get(1)) else {
        eprintln!("usage: journal-crash-writer <data-dir> <strict|balanced> [kernel|direct]");
        return ExitCode::from(2);
    };
    let through_kernel = match args.get(2).map(String::as_str) {
        None | Some("kernel") => true,
        Some("direct") => false,
        Some(other) => {
            eprintln!("unknown path {other:?}: kernel or direct");
            return ExitCode::from(2);
        }
    };
    let (policy, durability) = if mode == "strict" {
        (FlushPolicy::Strict, ChunkDurability::Strict)
    } else {
        (FlushPolicy::default(), ChunkDurability::Balanced)
    };
    match run(PathBuf::from(dir), policy, durability, through_kernel) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e}");
            // Its own code, so the harness tells it from a kill (TerminateProcess exits 1).
            ExitCode::from(WRITER_FAILED)
        }
    }
}

fn run(
    data: PathBuf,
    policy: FlushPolicy,
    durability: ChunkDurability,
    through_kernel: bool,
) -> Result<ExitCode, String> {
    let fs: Arc<dyn Fs> = Arc::new(OsFs);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let rng: Arc<dyn Rng> = Arc::new(OsRng);
    let keys = kill_keyring().map_err(|e| format!("keyring failed: {e}"))?;
    fs.create_dir_all(&data).map_err(|e| format!("data directory: {e}"))?;
    let store = Arc::new(
        ChunkStore::open_with(Arc::clone(&fs), Arc::clone(&rng), keys, &data, durability)
            .map_err(|e| format!("chunk store open failed: {e}"))?,
    );
    let (mut writer, start) = if through_kernel {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map_err(|e| format!("runtime: {e}"))?;
        let supervisor = Supervisor::new(runtime.handle().clone(), SupervisorLimits::default());
        let config = ConfigSnapshot::new(
            ConfigVersion(1),
            LocaleTag::new("en").map_err(|e| format!("locale: {e}"))?,
        );
        let source = JournalSource::new(fs, clock, rng, data, policy, Arc::clone(&store));
        let started = start_kernel(
            source,
            &config,
            CorrelationId::from_parts(1, [0x6b; 10]),
            &supervisor,
            DEFAULT_QUEUE_CAPACITY,
        )
        .map_err(|e| format!("start failed: {e}"))?;
        let start = started.next_seq;
        (
            Writer::Kernel {
                runtime,
                state: started.state,
                _actor: started.actor,
            },
            start,
        )
    } else {
        let journal = Journal::open_with_payloads(fs, clock, rng, &data, policy, Arc::clone(&store))
            .map_err(|e| format!("open failed: {e}"))?
            .journal;
        let start = journal.next_seq();
        (Writer::Direct(Box::new(journal)), start)
    };

    let mut out = std::io::stdout().lock();
    if writeln!(out, "start {start}").and_then(|()| out.flush()).is_err() {
        return Ok(ExitCode::from(WRITER_FAILED));
    }
    // The actor is the journal's one writer, and a healthy kernel journals nothing of its own
    // between these appends, so each record takes the next sequence number; its payload is
    // derived from that number before it is stored.
    let mut next = start;
    for n in 0u64.. {
        let chunk: ChunkRef = store
            .put(kill_pocket(), &kill_payload(next.0))
            .map_err(|e| format!("put failed: {e}"))?;
        let mut draft = intent_draft(n);
        draft.pocket_id = Some(kill_pocket());
        draft.payload_ref = Some(chunk);
        let acked = writer.append(draft).map_err(|e| format!("append failed: {e}"))?;
        if acked.seq != next {
            return Err(format!(
                "record {} took sequence number {}: something else wrote to the journal",
                next, acked.seq
            ));
        }
        next = Seq(next.0 + 1);
        if writeln!(out, "{} {} {}", acked.seq, acked.hash, chunk)
            .and_then(|()| out.flush())
            .is_err()
        {
            // The reader is gone (the harness is killing us); stop quietly.
            return Ok(ExitCode::SUCCESS);
        }
    }
    Ok(ExitCode::SUCCESS)
}
