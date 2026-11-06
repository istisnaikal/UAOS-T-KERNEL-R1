// SPDX-License-Identifier: Apache-2.0

//! The `journal-durability` gate: kill a real writer process at random points and prove that every
//! acknowledged record survives, unchanged, on the real filesystem, **and so does the payload it
//! references**: in balanced mode chunks are only handed to the OS, never flushed, before the
//! record that references them is acknowledged.
//!
//! The writer is a kernel (`UAOS_CRASH_PATH=kernel`, the default): it runs the startup sequence
//! (the journal opens once, boot recovers and journals `kernel.booted`, the journal moves into the
//! state actor) and appends every record through the actor, acknowledging only what the actor
//! acknowledged. `UAOS_CRASH_PATH=direct` appends straight into the journal instead, to tell a loss
//! in the journal from one in the actor.
//!
//! Kill points: after k acknowledgements, after a random delay, or before the writer has printed
//! `start`, while it opens the store, recovers the journal and boots. So the writer is caught
//! blocked on its output, in the middle of journal I/O, and in the middle of recovery and boot.
//! Iterations:
//! `UAOS_CRASH_ITERATIONS` (default 40 per merge; nightly runs use 10,000). Seed:
//! `UAOS_CRASH_SEED` (printed on failure for replay).
//!
//! Payload sweeps, `UAOS_CRASH_SWEEP`:
//! * `every-kill` (the default, the merge lane): after every kill, every payload acknowledged in
//!   the directory is read back;
//! * `rotation` (the nightly lane): after every kill, the payloads acknowledged since the last
//!   writer that finished its open started are read back (normally the only ones after the
//!   `FLUSHED` marker, which a recovery rewrites), and every payload of a directory is read back
//!   before the directory is retired. A loss never heals in this
//!   harness (no content is stored twice, a lost chunk is quarantined, the parent only reads),
//!   so the sweep before retirement catches every loss a sweep after every kill would; only the
//!   iteration it is reported at differs, and the seed replays it.

#![allow(
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::disallowed_methods,
    reason = "process-level test harness: real processes, real files, a real clock"
)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use std::sync::Arc;

use uaos_contracts::digest::{ChunkRef, Sha256Digest};
use uaos_platform::Rng;
use uaos_platform::real::OsRng;
use uaos_platform::real::fs::OsFs;
use uaos_platform::sim::SimRng;
use uaos_state::chunks::ChunkStore;
use uaos_state::journal::{JOURNAL_DIR, read_verified};
use uaos_testkit::{kill_keyring, kill_payload, kill_pocket};

const WRITER: &str = env!("CARGO_BIN_EXE_journal-crash-writer");
/// Start a fresh data directory this often; a retired directory is deleted at once, so long
/// nightly runs stay bounded in size.
const ITERATIONS_PER_DIRECTORY: u32 = 25;

/// An acknowledged record: its hash and the chunk it references.
type Ack = (Sha256Digest, ChunkRef);

/// Which acknowledged payloads are read back after a kill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sweep {
    EveryKill,
    Rotation,
}

fn sweep_mode() -> Sweep {
    let mode = std::env::var("UAOS_CRASH_SWEEP").ok();
    let sweep = match mode.as_deref() {
        Some("rotation") => Some(Sweep::Rotation),
        Some("every-kill") | None => Some(Sweep::EveryKill),
        Some(_) => None,
    };
    assert!(
        sweep.is_some(),
        "UAOS_CRASH_SWEEP must be `every-kill` or `rotation`, not {mode:?}"
    );
    sweep.unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kill {
    /// Before `start`: in process start, store open or journal recovery.
    BeforeStart,
    AfterDelay,
    AfterAcks,
}

/// Wall time per phase, summed over all kills, so a slow run names its cost centre.
#[derive(Default)]
struct Phases {
    /// Spawn to `start`: process start, store open, journal open and recovery.
    boot: Duration,
    boot_max: Duration,
    /// The last writer's boot: a kill before `start` waits a random part of it.
    last_boot: Duration,
    /// `start` to the kill.
    run: Duration,
    /// The kill to the writer's last line.
    drain: Duration,
    /// Reading and verifying the journal.
    verify: Duration,
    /// Opening the chunk store to read payloads back.
    store_open: Duration,
    /// Reading payloads back.
    sweep: Duration,
    payload_reads: u64,
    /// Deleting retired directories.
    retire: Duration,
    retire_failures: u32,
    /// Kills that landed before the writer printed `start`.
    boot_kills: u32,
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn random_below(rng: &SimRng, bound: u64) -> u64 {
    let mut b = [0u8; 8];
    rng.fill(&mut b).unwrap();
    u64::from_le_bytes(b) % bound.max(1)
}

fn scratch_root() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("uaos-kill-{}", std::process::id()));
    let _stale = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Which path the writer's records take: `kernel` (the default) or `direct`.
fn crash_path() -> String {
    let path = std::env::var("UAOS_CRASH_PATH").unwrap_or_else(|_| "kernel".to_owned());
    assert!(
        path == "kernel" || path == "direct",
        "UAOS_CRASH_PATH must be `kernel` or `direct`, not {path:?}"
    );
    path
}

/// The exit code the writer returns when it ends by itself (`journal-crash-writer`).
const WRITER_FAILED: i32 = 3;

/// Whether the kill ended the writer.
fn killed(status: std::process::ExitStatus) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        status.signal() == Some(9) && status.code() != Some(WRITER_FAILED)
    }
    #[cfg(not(unix))]
    {
        // `Child::kill` calls `TerminateProcess(handle, 1)`; the writer never exits 1 by itself
        // (it exits 0, 2, WRITER_FAILED or a panic's 101), and a crash has a code of its own.
        status.code() == Some(1)
    }
}

fn spawn(data: &Path, mode: &str) -> Child {
    Command::new(WRITER)
        .arg(data)
        .arg(mode)
        .arg(crash_path())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

/// Parses `<seq> <hash> <chunk>` acknowledgement lines; ignores a torn final line.
fn parse_ack(line: &str) -> Option<(u64, Ack)> {
    if !line.ends_with('\n') {
        return None;
    }
    let mut words = line.trim_end_matches(['\r', '\n']).split(' ');
    let seq = words.next()?.parse().ok()?;
    let hash = words.next()?.parse().ok()?;
    let chunk = words.next()?.parse().ok()?;
    Some((seq, (hash, chunk)))
}

/// Checks the writer's `start <next seq>` line: a journal never restarts before an acknowledged
/// record.
fn check_start(line: &str, acked: &BTreeMap<u64, Ack>, seed: u64, i: u32) {
    let start: Option<u64> = line.trim().strip_prefix("start ").and_then(|s| s.parse().ok());
    assert!(
        start.is_some(),
        "seed {seed:#x}, iteration {i}: writer did not start: {line:?}"
    );
    let start = start.unwrap();
    assert!(
        start >= acked.keys().next_back().map_or(0, |s| s + 1),
        "seed {seed:#x}, iteration {i}: journal restarted at {start}, before an acknowledged record"
    );
}

/// Reads acknowledged payloads back from a freshly opened store: every one must be with the OS.
fn check_payloads<'a>(
    data: &Path,
    acks: impl Iterator<Item = (&'a u64, &'a Ack)>,
    seed: u64,
    when: &str,
    phases: &mut Phases,
) {
    let opening = Instant::now();
    let store = ChunkStore::open(Arc::new(OsFs), Arc::new(OsRng), kill_keyring().unwrap(), data).unwrap();
    phases.store_open += opening.elapsed();
    let started = Instant::now();
    for (seq, (_, chunk)) in acks {
        phases.payload_reads += 1;
        assert_eq!(
            store.get(kill_pocket(), *chunk).ok(),
            Some(kill_payload(*seq)),
            "seed {seed:#x}, {when}: acknowledged record {seq} lost its payload"
        );
    }
    phases.sweep += started.elapsed();
}

/// Retires a directory: in rotation mode every payload it acknowledged is read back first.
fn retire(data: &Path, acked: &BTreeMap<u64, Ack>, sweep: Sweep, seed: u64, i: u32, phases: &mut Phases) {
    if sweep == Sweep::Rotation {
        let when = format!("iteration {i}, sweep before retiring {}", data.display());
        check_payloads(data, acked.iter(), seed, &when, phases);
    }
    let started = Instant::now();
    if std::fs::remove_dir_all(data).is_err() {
        phases.retire_failures += 1;
    }
    phases.retire += started.elapsed();
}

/// Starts a writer on `data`, kills it at a random point and records every acknowledgement it
/// printed before dying. Returns whether it printed `start`, i.e. finished opening the directory.
fn run_writer(
    data: &Path,
    i: u32,
    rng: &SimRng,
    acked: &mut BTreeMap<u64, Ack>,
    seed: u64,
    phases: &mut Phases,
) -> bool {
    let mode = if i.is_multiple_of(2) { "balanced" } else { "strict" };
    let kill = match random_below(rng, 6) {
        0 | 1 => Kill::AfterDelay,
        5 => Kill::BeforeStart,
        _ => Kill::AfterAcks,
    };
    let spawned = Instant::now();
    let mut child = spawn(data, mode);
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut started = false;
    let mut run_began = None;

    if kill == Kill::BeforeStart {
        // A random point of a boot as long as the last one, which grows with the directory: the
        // longest boot so far would put most of these kills after `start` (nightly 39319600117:
        // 2-7% of kills landed in a boot, not one in six).
        let last_boot = u64::try_from(phases.last_boot.as_micros()).unwrap_or(u64::MAX);
        std::thread::sleep(Duration::from_micros(random_below(rng, last_boot + 1)));
    } else {
        let mut first = String::new();
        reader.read_line(&mut first).unwrap();
        check_start(&first, acked, seed, i);
        started = true;
        let boot = spawned.elapsed();
        phases.boot += boot;
        phases.boot_max = phases.boot_max.max(boot);
        phases.last_boot = boot;
        run_began = Some(Instant::now());
        if kill == Kill::AfterDelay {
            std::thread::sleep(Duration::from_millis(random_below(rng, 40)));
        } else {
            let k = 1 + random_below(rng, 400);
            let mut line = String::new();
            for read in 0..k {
                line.clear();
                // The end of its output before the kill: the writer exited on its own.
                assert!(
                    reader.read_line(&mut line).unwrap() > 0,
                    "seed {seed:#x}, iteration {i}: the writer exited on its own after {read} of {k} acknowledgements"
                );
                if let Some((seq, ack)) = parse_ack(&line) {
                    acked.insert(seq, ack);
                }
            }
        }
    }
    // A writer that ended by itself was not killed: an append its kernel refused, or a record it
    // did not expect, would otherwise pass as a kill and quietly shrink the sample.
    let early = child.try_wait().unwrap();
    assert!(
        early.is_none(),
        "seed {seed:#x}, iteration {i}: the writer exited on its own ({early:?}) before it was killed"
    );
    child.kill().unwrap(); // TerminateProcess on Windows, SIGKILL on Unix
    let status = child.wait().unwrap();
    // A writer that ends by itself returns WRITER_FAILED; one the kill ended does not (Unix: the
    // signal; Windows: TerminateProcess's exit code 1).
    assert!(
        killed(status),
        "seed {seed:#x}, iteration {i}: the writer exited on its own ({status}) rather than by the kill"
    );
    if let Some(t) = run_began {
        phases.run += t.elapsed();
    }
    // Everything the writer printed before dying was acknowledged.
    let drained = Instant::now();
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap() > 0 {
        if line.starts_with("start ") && line.ends_with('\n') {
            check_start(&line, acked, seed, i);
            started = true;
        } else if let Some((seq, ack)) = parse_ack(&line) {
            acked.insert(seq, ack);
        }
        line.clear();
    }
    phases.drain += drained.elapsed();
    if !started {
        phases.boot_kills += 1;
    }
    started
}

/// Checks that every acknowledged record is in the journal with its acknowledged hash. Returns
/// the number of records, or `None` while no writer has finished opening the directory.
fn check_journal(
    data: &Path,
    acked: &BTreeMap<u64, Ack>,
    opened: bool,
    seed: u64,
    i: u32,
    phases: &mut Phases,
) -> Option<u64> {
    let verifying = Instant::now();
    let verified = read_verified(&OsFs, &data.join(JOURNAL_DIR));
    // No writer has finished opening this directory, so nothing was promised: a writer killed in
    // its first open may leave no journal, or half of one. The next writer must still open it
    // (`check_start`).
    if verified.is_err() && !opened {
        phases.verify += verifying.elapsed();
        return None;
    }
    if let Err(e) = &verified {
        assert!(
            verified.is_ok(),
            "seed {seed:#x}, iteration {i}: journal does not verify: {e}"
        );
    }
    let (records, report) = verified.unwrap();
    let present: BTreeMap<u64, Sha256Digest> = records.iter().map(|r| (r.envelope.seq.0, r.hash)).collect();
    for (seq, (hash, _)) in acked {
        assert_eq!(
            present.get(seq),
            Some(hash),
            "seed {seed:#x}, iteration {i}: acknowledged record {seq} lost or changed"
        );
    }
    phases.verify += verifying.elapsed();
    Some(report.records)
}

#[test]
fn kill_minus_nine_loses_no_acknowledged_record() {
    let iterations = u32::try_from(env_u64("UAOS_CRASH_ITERATIONS", 40)).unwrap();
    let seed = env_u64("UAOS_CRASH_SEED", 0x005E_ED0F_CA5E);
    let sweep = sweep_mode();
    let rng = SimRng::new(seed);
    let root = scratch_root();
    let mut generation = 0u32;
    let mut data = root.join("gen-0");
    let mut acked: BTreeMap<u64, Ack> = BTreeMap::new();
    // The first sequence number acknowledged after the last writer that finished its open
    // started: everything before it was behind that writer's `FLUSHED` marker.
    let mut floor = 0u64;
    let mut opened = false;
    let mut total_acked = 0u64;
    let mut phases = Phases::default();
    let began = Instant::now();

    for i in 0..iterations {
        if i > 0 && i % ITERATIONS_PER_DIRECTORY == 0 {
            retire(&data, &acked, sweep, seed, i - 1, &mut phases);
            generation += 1;
            data = root.join(format!("gen-{generation}"));
            acked.clear();
            floor = 0;
            opened = false;
        }
        let before_this_run = acked.keys().next_back().map_or(0, |s| s + 1);
        let started = run_writer(&data, i, &rng, &mut acked, seed, &mut phases);
        opened |= started;
        let Some(records) = check_journal(&data, &acked, opened, seed, i, &mut phases) else {
            continue;
        };
        let when = format!("iteration {i}");
        match sweep {
            Sweep::EveryKill => check_payloads(&data, acked.iter(), seed, &when, &mut phases),
            Sweep::Rotation => check_payloads(&data, acked.range(floor..), seed, &when, &mut phases),
        }
        // A writer that printed `start` finished its open, so it wrote a `FLUSHED` marker
        // covering everything acknowledged before it ran; the next writer's recovery rewrites
        // only what came after that marker.
        if started {
            floor = before_this_run;
        }
        total_acked = total_acked.max(records);
    }
    retire(&data, &acked, sweep, seed, iterations.saturating_sub(1), &mut phases);
    eprintln!(
        "kill harness: {iterations} kills ({} before `start`) through the {} path, seed {seed:#x}, sweep {sweep:?}, up to {total_acked} records per directory, 0 lost",
        phases.boot_kills,
        crash_path()
    );
    eprintln!(
        "kill harness phases: boot {:.1?} (longest {:.1?}), run {:.1?}, drain {:.1?}, journal verify {:.1?}, store opens {:.1?}, payload reads {:.1?} ({}), retiring {:.1?} ({} failed); total {:.1?}",
        phases.boot,
        phases.boot_max,
        phases.run,
        phases.drain,
        phases.verify,
        phases.store_open,
        phases.sweep,
        phases.payload_reads,
        phases.retire,
        phases.retire_failures,
        began.elapsed()
    );
    let _cleanup = std::fs::remove_dir_all(&root);
}
