// SPDX-License-Identifier: Apache-2.0

//! Acknowledgement latency of the **production** journal and chunk store on the machine it runs on
//! ("Measured numbers"). The nightly lane runs it on every OS.
//!
//! Usage: `journal-ack-bench <scratch-dir>`. The directory must not exist or must be empty; it is
//! left in place for inspection.
//!
//! Measures, with the real stack (`OsFs`, system clock, OS randomness):
//!
//! | series        | what one sample is                                                         |
//! |---------------|----------------------------------------------------------------------------|
//! | `balanced`    | one `Journal::append` of a critical record under the default window W      |
//! |               | (includes the flushes the window triggers, so it is the ack a caller sees) |
//! | `strict`      | one `Journal::append` with a flush before every acknowledgement            |
//! | `group-flush` | one `Journal::sync` after 64 unflushed appends                             |
//! | `chunk-put`   | one `ChunkStore::put` of a new 4 KiB chunk (data plus wrapped key)          |
//! |               | in strict mode: both files flushed before it returns                       |
//! | `chunk-put-balanced` | the same put in balanced mode: handed to the OS only                |
//! | `group-flush-chunks` | one `Journal::sync` after 64 records, each with its own new chunk:  |
//! |               | 128 chunk files, then the segment, made durable, in that order            |
//!
//! Output: a Markdown table on stdout (the nightly job appends it to the run summary), then one
//! `json:` line with the same numbers in nanoseconds for artifacts.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::disallowed_methods,
    reason = "benchmark binary: measures wall time and prints results"
)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use uaos_contracts::id::{PocketId, TypedId};
use uaos_platform::fs::Fs;
use uaos_platform::real::fs::OsFs;
use uaos_platform::real::{OsRng, SystemClock};
use uaos_platform::{Clock, Rng};
use uaos_state::chunks::keyring::MemoryKeyring;
use uaos_state::chunks::{ChunkDurability, ChunkStore};
use uaos_state::journal::{FlushPolicy, Journal};
use uaos_testkit::intent_draft;

const BALANCED_RECORDS: u64 = 20_000;
const STRICT_RECORDS: u64 = 2_000;
const GROUP_SIZE: u64 = 64;
const GROUPS: u64 = 500;
const CHUNKS: u64 = 1_000;
const CHUNK_BYTES: usize = 4 * 1024;

struct Series {
    name: &'static str,
    samples: Vec<Duration>,
}

fn main() -> ExitCode {
    let Some(dir) = std::env::args().nth(1).map(PathBuf::from) else {
        eprintln!("usage: journal-ack-bench <scratch-dir>");
        return ExitCode::from(2);
    };
    match run(&dir) {
        Ok(series) => {
            print!("{}", report(&series));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("journal-ack-bench: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(dir: &Path) -> Result<Vec<Series>, String> {
    let fs: Arc<dyn Fs> = Arc::new(OsFs);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let rng: Arc<dyn Rng> = Arc::new(OsRng);
    let open = |name: &str, policy: FlushPolicy| {
        Journal::open(
            Arc::clone(&fs),
            Arc::clone(&clock),
            Arc::clone(&rng),
            &dir.join(name),
            policy,
        )
        .map_err(|e| format!("open {name}: {e}"))
    };

    let mut balanced = Vec::new();
    let mut journal = open("balanced", FlushPolicy::default())?;
    for n in 0..BALANCED_RECORDS {
        let start = Instant::now();
        journal
            .append(intent_draft(n))
            .map_err(|e| format!("balanced append: {e}"))?;
        balanced.push(start.elapsed());
    }
    drop(journal);

    let mut strict = Vec::new();
    let mut journal = open("strict", FlushPolicy::Strict)?;
    for n in 0..STRICT_RECORDS {
        let start = Instant::now();
        journal
            .append(intent_draft(n))
            .map_err(|e| format!("strict append: {e}"))?;
        strict.push(start.elapsed());
    }
    drop(journal);

    // A window far longer than the run, so only the explicit `sync` flushes.
    let mut group = Vec::new();
    let never = FlushPolicy::Balanced {
        window: uaos_contracts::limits::Millis(u64::MAX / 2),
    };
    let mut journal = open("group", never)?;
    let mut n = 0u64;
    for _ in 0..GROUPS {
        for _ in 0..GROUP_SIZE {
            journal
                .append(intent_draft(n))
                .map_err(|e| format!("group append: {e}"))?;
            n += 1;
        }
        let start = Instant::now();
        journal.sync().map_err(|e| format!("group sync: {e}"))?;
        group.push(start.elapsed());
    }
    drop(journal);

    let mut chunk = Vec::new();
    let keys = Arc::new(MemoryKeyring::new(Arc::clone(&rng)));
    let store = ChunkStore::open(Arc::clone(&fs), Arc::clone(&rng), keys, &dir.join("chunks"))
        .map_err(|e| format!("open chunk store: {e}"))?;
    let pocket = PocketId::from_parts(1, [7; 10]);
    let mut content = vec![0u8; CHUNK_BYTES];
    for i in 0..CHUNKS {
        // Distinct content per chunk, so every put stores a new chunk.
        for (slot, byte) in content.iter_mut().zip(i.to_le_bytes()) {
            *slot = byte;
        }
        let start = Instant::now();
        store.put(pocket, &content).map_err(|e| format!("chunk put: {e}"))?;
        chunk.push(start.elapsed());
    }
    drop(store);
    let (chunk_balanced, group_chunks) = payload_series(&fs, &clock, &rng, &dir.join("payloads"), never)?;

    Ok(vec![
        Series {
            name: "balanced",
            samples: balanced,
        },
        Series {
            name: "strict",
            samples: strict,
        },
        Series {
            name: "group-flush",
            samples: group,
        },
        Series {
            name: "chunk-put",
            samples: chunk,
        },
        Series {
            name: "chunk-put-balanced",
            samples: chunk_balanced,
        },
        Series {
            name: "group-flush-chunks",
            samples: group_chunks,
        },
    ])
}

/// Each put hands both chunk files to the OS; the journal's flush makes them durable before the
/// records that reference them. Returns the put latencies and the latencies of flushes that each
/// cover `GROUP_SIZE` records with their own new chunk.
fn payload_series(
    fs: &Arc<dyn Fs>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn Rng>,
    data: &Path,
    window: FlushPolicy,
) -> Result<(Vec<Duration>, Vec<Duration>), String> {
    let mut puts = Vec::new();
    let mut flushes = Vec::new();
    fs.create_dir_all(data).map_err(|e| format!("payload dir: {e}"))?;
    let keys = Arc::new(MemoryKeyring::new(Arc::clone(rng)));
    let store = Arc::new(
        ChunkStore::open_with(Arc::clone(fs), Arc::clone(rng), keys, data, ChunkDurability::Balanced)
            .map_err(|e| format!("open balanced chunk store: {e}"))?,
    );
    let mut journal = Journal::open_with_payloads(
        Arc::clone(fs),
        Arc::clone(clock),
        Arc::clone(rng),
        data,
        window,
        Arc::clone(&store),
    )
    .map(|opened| opened.journal)
    .map_err(|e| format!("open journal with payloads: {e}"))?;
    let pocket = PocketId::from_parts(2, [9; 10]);
    let mut content = vec![0u8; CHUNK_BYTES];
    let mut i = 0u64;
    for _ in 0..GROUPS {
        for _ in 0..GROUP_SIZE {
            for (slot, byte) in content.iter_mut().zip(i.to_le_bytes()) {
                *slot = byte;
            }
            i += 1;
            let start = Instant::now();
            let reference = store
                .put(pocket, &content)
                .map_err(|e| format!("balanced chunk put: {e}"))?;
            puts.push(start.elapsed());
            let mut draft = intent_draft(i);
            draft.pocket_id = Some(pocket);
            draft.payload_ref = Some(reference);
            journal.append(draft).map_err(|e| format!("append with payload: {e}"))?;
        }
        let start = Instant::now();
        journal.sync().map_err(|e| format!("flush with payloads: {e}"))?;
        flushes.push(start.elapsed());
    }
    Ok((puts, flushes))
}

/// The sample at quantile `permille / 1000` (nearest rank).
fn quantile(sorted: &[Duration], permille: usize) -> Duration {
    let rank = (sorted.len() * permille).div_ceil(1000).saturating_sub(1);
    sorted.get(rank).copied().unwrap_or_default()
}

fn micros(d: Duration) -> String {
    let nanos = d.as_nanos();
    format!("{}.{} µs", nanos / 1000, (nanos % 1000) / 100)
}

fn report(series: &[Series]) -> String {
    let mut md = format!(
        "### Journal acknowledgement latency ({} / {})\n\n| series | n | p50 | p95 | p99 | p99.9 | max |\n|---|---|---|---|---|---|---|\n",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let mut json = String::from("json: {");
    for (i, s) in series.iter().enumerate() {
        let mut sorted = s.samples.clone();
        sorted.sort();
        let q = |p| quantile(&sorted, p);
        let max = sorted.last().copied().unwrap_or_default();
        let _infallible = writeln!(
            md,
            "| {} | {} | {} | {} | {} | {} | {} |",
            s.name,
            sorted.len(),
            micros(q(500)),
            micros(q(950)),
            micros(q(990)),
            micros(q(999)),
            micros(max)
        );
        let sep = if i == 0 { "" } else { "," };
        let _infallible = write!(
            json,
            "{sep}\"{}\":{{\"n\":{},\"p50_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"p999_ns\":{},\"max_ns\":{}}}",
            s.name,
            sorted.len(),
            q(500).as_nanos(),
            q(950).as_nanos(),
            q(990).as_nanos(),
            q(999).as_nanos(),
            max.as_nanos()
        );
    }
    let _infallible = writeln!(
        md,
        "\nThese numbers describe the machine that ran the bench. CI runners use shared virtual \
         disks, so their numbers are runner numbers, not reference hardware."
    );
    json.push('}');
    format!("{md}\n{json}\n")
}
