// SPDX-License-Identifier: Apache-2.0

//! The state actor: the journal's one writer once boot has finished, and its durability coordinator
//! (P3).
//!
//! - [`StateCore`] holds the [`Journal`] and does all of the work deterministically, on the time
//!   the platform clock gives it, so tests drive it on simulated time.
//! - [`state_queue`] makes the bounded queue and the [`StateHandle`] every other part of the
//!   runtime writes through; [`start_state_actor`] runs a core on one dedicated thread from the
//!   supervisor. The queue exists before the actor starts, so boot can hand out the handle first
//!   and start the actor last.
//!
//! **The flush schedule.** The journal flushes on its own only inside an append, once the window W
//! has passed since the last flush, so the last records before a quiet period would stay unflushed
//! past W. The core flushes at the journal's deadline: the time the oldest unflushed record was
//! acknowledged, plus W. It reads the journal's own clock, so the deadline and "now" share one
//! origin.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use uaos_contracts::event::{Durability, EnvelopeError, InlinePayload, Metadata, types};
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::wire::Seq;
use uaos_platform::Clock;
use uaos_state::journal::{Appended, EventDraft, FlushPolicy, Journal, JournalError, JournalHealth};

use crate::admission::Admission;
use crate::ledger_task::LedgerHandle;
use crate::stop::{Engaged, EngagedBy, Stop, StopReason, StopWatch};
use crate::supervisor::{SpawnError, Supervisor};

/// Commands the queue holds before a caller waits.
pub const DEFAULT_QUEUE_CAPACITY: usize = 1024;

/// How long the core waits before it retries a flush that failed at its deadline. A failed flush
/// leaves the journal degraded (its health says so); retrying at once would spin.
const FLUSH_RETRY: Duration = Duration::from_millis(50);

/// The first pause before a stop record that failed is tried again by the schedule; it doubles
/// after each failure, up to [`STOP_RETRY_MAX`]. An append or a sync tries it at once.
const STOP_RETRY_FIRST: Duration = Duration::from_millis(10);
/// The longest pause between two tries of a stop record.
const STOP_RETRY_MAX: Duration = Duration::from_secs(5);

/// The name of the actor's thread.
const THREAD_NAME: &str = "uaos-state";

/// Why the state actor could not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StateError {
    /// The actor ended after the command was queued: shut down, or its thread is gone. What it
    /// did with the command is unknown.
    #[error("the state actor has ended")]
    Closed,
    /// The command was refused before it was queued: the actor has ended. Nothing was written.
    #[error("the state actor has ended; the command was not queued")]
    NotQueued,
    /// An engaged stop's record could not land, so the command was refused before its own line was
    /// written: inside the stop record's pause, without touching the journal; or on an append that
    /// tried the stop record first and failed, after which the stop's line may be in the journal
    /// but the command's is not. The journal's own error says why the stop record failed.
    #[error("a stop record is pending: {0}")]
    StopPending(JournalError),
    /// The journal refused, with its own error and code.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The stop record could not be built (it always fits the envelope; kept for honesty).
    #[error("the stop record could not be built")]
    StopRecord,
    /// The shutdown record could not be built (it always fits the envelope).
    #[error("the shutdown record could not be built")]
    ShutdownRecord,
}

/// A clean shutdown, as asked for. It is not the stop: the next boot runs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShutdownReason {
    /// Who asked: an operator, or the system on a signal.
    pub by: EngagedBy,
    /// Operations still open when the wait for them ended.
    pub open_operations: u32,
}

impl ShutdownReason {
    /// A shutdown asked for by `by`, with `open_operations` still open.
    #[must_use]
    pub const fn new(by: EngagedBy, open_operations: u32) -> Self {
        Self { by, open_operations }
    }
}

/// What a clean shutdown wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShutdownReport {
    /// The `kernel.shutdown` record.
    pub record: Seq,
    /// The last record durable against power loss: the shutdown record.
    pub flushed_through: Option<Seq>,
}

/// What the actor has done, for operators and for the bus (exports it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct StateStats {
    /// Flushes the core ran because a deadline passed.
    pub deadline_flushes: u64,
    /// Flushes at a deadline that failed.
    pub failed_flushes: u64,
    /// How long ago the oldest acknowledged record that is not flushed yet was acknowledged,
    /// in nanoseconds; `None` when every acknowledged record is flushed.
    pub oldest_unflushed_nanos: Option<u64>,
    /// The coordinator's delay at the last deadline flush it started, successful or failed: from
    /// the time the flush was due (the deadline, or the retry time after a failed flush) to the
    /// time it started, in nanoseconds. The flush's own time is not included. `None` before the
    /// first deadline flush.
    pub flush_delay_last_nanos: Option<u64>,
    /// The longest such delay so far; `None` before the first deadline flush.
    pub flush_delay_max_nanos: Option<u64>,
    /// P1, measured directly: the longest any acknowledged record waited before a flush that
    /// covered it started, in nanoseconds, over every flush the core ran. That is a flush at a
    /// deadline, one the journal ran inside an append, or one a caller asked for. `None` before
    /// the first such flush. P1 says it stays within W plus the coordinator's delay.
    pub flush_age_max_nanos: Option<u64>,
    /// Tries of a stop record that failed.
    pub stop_record_retries: u64,
    /// Commands still waiting in the queue when the actor made this answer.
    pub queued: usize,
    /// The journal's health when the actor made this answer.
    pub health: JournalHealth,
}

impl Default for StateStats {
    fn default() -> Self {
        Self {
            deadline_flushes: 0,
            failed_flushes: 0,
            oldest_unflushed_nanos: None,
            flush_delay_last_nanos: None,
            flush_delay_max_nanos: None,
            flush_age_max_nanos: None,
            stop_record_retries: 0,
            queued: 0,
            health: JournalHealth::Healthy,
        }
    }
}

/// One request to the actor, with the slot its answer goes to.
enum Command {
    Append(Box<EventDraft>, oneshot::Sender<Result<Appended, StateError>>),
    Sync(oneshot::Sender<Result<(), StateError>>),
    Health(oneshot::Sender<JournalHealth>),
    FlushPolicy(oneshot::Sender<FlushPolicy>),
    Stats(oneshot::Sender<StateStats>),
    Shutdown(ShutdownReason, oneshot::Sender<Result<ShutdownReport, StateError>>),
}

impl fmt::Debug for Command {
    /// The kind only: a draft may hold a payload, and payloads are never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Append(..) => "Append",
            Self::Sync(_) => "Sync",
            Self::Health(_) => "Health",
            Self::FlushPolicy(_) => "FlushPolicy",
            Self::Stats(_) => "Stats",
            Self::Shutdown(..) => "Shutdown",
        })
    }
}

/// The journal and its flush schedule, without a thread: every step is a plain call.
#[derive(Debug)]
pub struct StateCore {
    journal: Journal,
    /// The journal's own clock: its deadlines count from this clock's origin.
    clock: Arc<dyn Clock>,
    stats: StateStats,
    /// No deadline flush is tried before this time (monotonic nanoseconds) after one failed.
    retry_at: u64,
    /// The stop the core journals, and who engages it when the journal fails.
    stop: Option<(Stop, EngagedBy)>,
    /// No stop record is tried before this time after one failed: not by the schedule, and not
    /// by an append or a sync, which are refused meanwhile with the failure below.
    stop_retry_at: u64,
    /// The pause after the next failed stop record.
    stop_backoff: Duration,
    /// The last stop record's failure, returned without I/O until `stop_retry_at`.
    stop_error: Option<StateError>,
    /// The generation and sequence number of a stop record appended whose flush failed: a retry
    /// flushes it and never appends it again.
    stop_appended: Option<(u64, Seq)>,
}

impl StateCore {
    /// A core that owns `journal`, on the journal's own clock. A kernel starts through
    /// [`crate::start_kernel`], which also removes a clean end's seal before the actor runs; a core
    /// built here directly is for tests and benches.
    #[must_use]
    pub fn new(journal: Journal) -> Self {
        let clock = Arc::clone(journal.clock());
        Self {
            journal,
            clock,
            stats: StateStats::default(),
            retry_at: 0,
            stop: None,
            stop_retry_at: 0,
            stop_backoff: STOP_RETRY_FIRST,
            stop_error: None,
            stop_appended: None,
        }
    }

    /// The core journals `stop`'s engagements ahead of every later record, and engages it as `by`
    /// when the journal fails. Without this, a core keeps no stop (the bench, and tests of the
    /// flush schedule alone).
    #[must_use]
    pub fn with_stop(mut self, stop: Stop, by: EngagedBy) -> Self {
        self.stop = Some((stop, by));
        self
    }

    /// Appends a record; the acknowledgement means what [`Journal::append`]'s does.
    ///
    /// # Errors
    /// The journal's refusal.
    pub fn append(&mut self, draft: EventDraft) -> Result<Appended, StateError> {
        // An engaged stop's record goes ahead of every later record. When it cannot land, this
        // command's line is not written either, whatever the stop record's try did. The refusal
        // says so, and the ledger task reads it as a write that wrote nothing: it tries the close
        // again instead of poisoning the ledger (of E4).
        self.record_stop(true).map_err(|error| match error {
            StateError::Journal(error) => StateError::StopPending(error),
            other => other,
        })?;
        // The journal flushes inside an append once W has passed since its last flush; that
        // flush covers the records already waiting, so their age counts toward P1.
        let waiting = self.journal.unflushed_since().map(|since| (since, self.clock.mono().0));
        let before = self.journal.flushed_through();
        let appended = match self.journal.append(draft) {
            Ok(appended) => appended,
            Err(error) => {
                self.engage_for_failure(&error);
                return Err(error.into());
            }
        };
        if let Some((since, now)) = waiting
            && self.journal.flushed_through() != before
        {
            self.note_flush_age(now.saturating_sub(since));
        }
        Ok(appended)
    }

    /// Flushes every acknowledged record now.
    ///
    /// # Errors
    /// The journal's refusal.
    pub fn sync(&mut self) -> Result<(), StateError> {
        if let Err(error) = self.record_stop(true) {
            // The records already in the journal come before the stop's, so flushing them keeps
            // the order, and a power loss then takes only what the stop's failure left unwritten.
            let _flushed = self.journal.sync();
            return Err(error);
        }
        let waiting = self.journal.unflushed_since().map(|since| (since, self.clock.mono().0));
        if let Err(error) = self.journal.sync() {
            self.engage_for_failure(&error);
            return Err(error.into());
        }
        if let Some((since, now)) = waiting {
            self.note_flush_age(now.saturating_sub(since));
        }
        Ok(())
    }

    /// Journals the engaged stop, if its record is not in the journal yet: appended, then flushed
    /// at once whatever the mode, then marked recorded. A failure keeps the stop engaged and
    /// unrecorded, and nothing is tried again for a pause that doubles, from 10 ms up to 5 s.
    /// Inside the pause the schedule waits, and `now` (an append or a sync) is refused with the
    /// last failure without touching the disk: a recovery on a full disk may leave an empty segment
    /// file behind, so tries are rationed by time, not by traffic.
    fn record_stop(&mut self, now: bool) -> Result<(), StateError> {
        let Some(engaged) = self.stop.as_ref().and_then(|(stop, _)| stop.unrecorded()) else {
            return Ok(());
        };
        if self.clock.mono().0 < self.stop_retry_at {
            // Inside the pause nothing touches the journal: the refusal wrote nothing.
            return match (now, &self.stop_error) {
                (true, Some(StateError::Journal(error))) => Err(StateError::StopPending(error.clone())),
                (true, Some(error)) => Err(error.clone()),
                _ => Ok(()),
            };
        }
        match self.write_stop(&engaged) {
            Ok(()) => {
                if let Some((stop, _)) = &self.stop {
                    stop.recorded(engaged.generation());
                }
                self.stop_backoff = STOP_RETRY_FIRST;
                self.stop_retry_at = 0;
                self.stop_error = None;
                Ok(())
            }
            Err(error) => {
                self.stats.stop_record_retries += 1;
                self.stop_retry_at = self.clock.mono().0.saturating_add(nanos(self.stop_backoff));
                self.stop_backoff = self.stop_backoff.saturating_mul(2).min(STOP_RETRY_MAX);
                self.stop_error = Some(error.clone());
                Err(error)
            }
        }
    }

    fn write_stop(&mut self, engaged: &Engaged) -> Result<(), StateError> {
        // Records already waiting are flushed with the stop's, so their wait counts toward P1.
        let waiting = self.journal.unflushed_since().map(|since| (since, self.clock.mono().0));
        // A failed journal refuses records until it recovers, and space may have returned since.
        // Recovery journals the losses it finds first: those are the journal's own records, and
        // the stop's record follows them.
        if self.journal.health() != JournalHealth::Healthy {
            self.journal.recover()?;
        }
        // A record an earlier try appended, whose flush failed, is still in the journal:
        // recovery rewrote it unflushed. It is flushed, never appended a second time.
        let pending = self
            .stop_appended
            .filter(|(generation, seq)| *generation == engaged.generation() && *seq < self.journal.next_seq());
        if pending.is_none() {
            let draft = engaged.draft().map_err(|_| StateError::StopRecord)?;
            let before = self.journal.next_seq();
            match self.journal.append(draft) {
                Ok(appended) => self.stop_appended = Some((engaged.generation(), appended.seq)),
                Err(error) => {
                    // The line can be written though the append failed: a flush inside it, due
                    // under strict mode or once W has passed, failed afterwards. It is then in the
                    // journal, and the next try flushes it.
                    if self.journal.next_seq() > before {
                        self.stop_appended = Some((engaged.generation(), before));
                    }
                    return Err(error.into());
                }
            }
        }
        // Flushed at once, whatever the mode: this is the record a restart reads.
        self.journal.sync()?;
        self.stop_appended = None;
        if let Some((since, now)) = waiting {
            self.note_flush_age(now.saturating_sub(since));
        }
        Ok(())
    }

    /// A failing journal engages the stop: a kernel that cannot journal refuses work.
    fn engage_for_health(&self) {
        self.engage_stop(stop_reason_for(self.journal.health()));
    }

    /// As [`StateCore::engage_for_health`], and for a failure of the platform under the journal
    /// (its clock or its randomness) too: the journal stays healthy then, but every append fails,
    /// so the kernel cannot journal.
    fn engage_for_failure(&self, error: &JournalError) {
        self.engage_stop(
            stop_reason_for(self.journal.health())
                .or_else(|| matches!(error, JournalError::Platform(_)).then_some(StopReason::JournalFailed)),
        );
    }

    /// Engages the stop the core journals, if it has one, as the core's own engager.
    fn engage_stop(&self, reason: Option<StopReason>) {
        if let Some((stop, by)) = &self.stop
            && let Some(reason) = reason
        {
            let _engaged = stop.engage(reason, by.clone());
        }
    }

    /// Whether an engaged stop still waits for its record.
    fn stop_pending(&self) -> bool {
        self.stop.as_ref().is_some_and(|(stop, _)| stop.unrecorded().is_some())
    }

    /// A watch on the stop the core journals, if it has one.
    fn stop_watch(&self) -> Option<StopWatch> {
        self.stop.as_ref().map(|(stop, _)| stop.watch())
    }

    fn note_flush_age(&mut self, age: u64) {
        self.stats.flush_age_max_nanos = Some(self.stats.flush_age_max_nanos.map_or(age, |max| max.max(age)));
    }

    /// Runs the flush schedule: flushes if the deadline has passed, and returns the next time
    /// the core must run again (monotonic nanoseconds), or `None` when nothing waits for a
    /// flush.
    pub fn tick(&mut self) -> Option<u64> {
        // A failure keeps the stop engaged; the next try is scheduled below.
        let _unrecorded = self.record_stop(false);
        let now = self.clock.mono().0;
        if let Some(deadline) = self.journal.flush_deadline()
            && now >= deadline
            && now >= self.retry_at
        {
            // Due at the deadline, or at the retry time after a failed flush.
            let delay = now.saturating_sub(deadline.max(self.retry_at));
            self.stats.flush_delay_last_nanos = Some(delay);
            self.stats.flush_delay_max_nanos =
                Some(self.stats.flush_delay_max_nanos.map_or(delay, |max| max.max(delay)));
            let since = self.journal.unflushed_since();
            if self.journal.sync().is_ok() {
                self.stats.deadline_flushes += 1;
                if let Some(since) = since {
                    self.note_flush_age(now.saturating_sub(since));
                }
            } else {
                self.stats.failed_flushes += 1;
                // From the end of the failed flush, so a slow failing disk still gets the pause.
                self.retry_at = self.clock.mono().0.saturating_add(nanos(FLUSH_RETRY));
                self.engage_for_health();
            }
        }
        let flush = self
            .journal
            .flush_deadline()
            .map(|deadline| deadline.max(self.retry_at));
        let stop = self.stop_pending().then_some(self.stop_retry_at);
        match (flush, stop) {
            (Some(flush), Some(stop)) => Some(flush.min(stop)),
            (flush, stop) => flush.or(stop),
        }
    }

    /// The journal's health.
    #[must_use]
    pub fn health(&self) -> JournalHealth {
        self.journal.health()
    }

    /// The last record durable against power loss, if any.
    #[must_use]
    pub fn flushed_through(&self) -> Option<Seq> {
        self.journal.flushed_through()
    }

    /// What the core has done so far.
    #[must_use]
    pub fn stats(&self) -> StateStats {
        let now = self.clock.mono().0;
        let mut stats = self.stats;
        stats.oldest_unflushed_nanos = self.journal.unflushed_since().map(|since| now.saturating_sub(since));
        stats.health = self.journal.health();
        stats
    }

    /// The core's clock, now (monotonic nanoseconds).
    #[must_use]
    pub fn now(&self) -> u64 {
        self.clock.mono().0
    }

    /// Gives the journal back, for a caller that takes over writing.
    #[must_use]
    pub fn into_journal(self) -> Journal {
        self.journal
    }

    /// Writes the clean shutdown: every record flushed first, an engaged stop's included, then
    /// `kernel.shutdown`, flushed. After it the actor ends.
    ///
    /// # Errors
    /// The journal's refusal; the shutdown is then not clean, and the next boot says so, but in the
    /// one (a seal that failed and could not be removed).
    pub fn shutdown(&mut self, reason: &ShutdownReason) -> Result<ShutdownReport, StateError> {
        self.sync()?;
        let draft = shutdown_draft(reason).map_err(|_| StateError::ShutdownRecord)?;
        let appended = self.append(draft)?;
        // Sealed: a file names the shutdown record once it is flushed, and only a clean end writes
        // one. The next boot reads the end as clean only if the seal names it.
        if let Err(error) = self.journal.seal() {
            self.engage_for_failure(&error);
            return Err(error.into());
        }
        Ok(ShutdownReport {
            record: appended.seq,
            flushed_through: self.journal.flushed_through(),
        })
    }

    /// Serves one command; `queued` is how many more wait behind it. `false` once the actor
    /// must end: after a clean shutdown.
    fn handle(&mut self, command: Command, queued: usize) -> bool {
        // A caller that stopped waiting dropped its slot; its answer has nowhere to go, and the
        // work is done either way.
        match command {
            Command::Append(draft, reply) => {
                let _unanswered = reply.send(self.append(*draft));
            }
            Command::Sync(reply) => {
                let _unanswered = reply.send(self.sync());
            }
            Command::Health(reply) => {
                let _unanswered = reply.send(self.health());
            }
            Command::FlushPolicy(reply) => {
                let _unanswered = reply.send(self.journal.flush_policy());
            }
            Command::Stats(reply) => {
                let mut stats = self.stats();
                stats.queued = queued;
                let _unanswered = reply.send(stats);
            }
            Command::Shutdown(reason, reply) => {
                let done = self.shutdown(&reason);
                // A failed shutdown leaves the actor serving: the caller may retry or exit.
                let ended = done.is_ok();
                let _unanswered = reply.send(done);
                return !ended;
            }
        }
        true
    }
}

/// Where the runtime writes the journal once boot has finished. Clones share one queue.
#[derive(Debug, Clone)]
pub struct StateHandle {
    commands: mpsc::Sender<Command>,
}

impl StateHandle {
    /// Appends a record. A full queue makes the caller wait; it never drops the record.
    ///
    /// # Errors
    /// [`StateError::NotQueued`] or [`StateError::Closed`] after the actor ended; the journal's
    /// own refusal otherwise, or [`StateError::StopPending`] while a stop record waits.
    pub async fn append(&self, draft: EventDraft) -> Result<Appended, StateError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Append(Box::new(draft), reply)).await?;
        answer.await.map_err(|_| StateError::Closed)?
    }

    /// Flushes every acknowledged record now.
    ///
    /// # Errors
    /// [`StateError::NotQueued`] or [`StateError::Closed`] after the actor ended; the journal's
    /// own refusal otherwise, or [`StateError::StopPending`] while a stop record waits.
    pub async fn sync(&self) -> Result<(), StateError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Sync(reply)).await?;
        answer.await.map_err(|_| StateError::Closed)?
    }

    /// The journal's health.
    ///
    /// # Errors
    /// [`StateError::NotQueued`] or [`StateError::Closed`] after the actor ended.
    pub async fn health(&self) -> Result<JournalHealth, StateError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Health(reply)).await?;
        answer.await.map_err(|_| StateError::Closed)
    }

    /// The policy the journal flushes under: what an intent records as its `durability`.
    ///
    /// # Errors
    /// [`StateError::NotQueued`] or [`StateError::Closed`] after the actor ended.
    pub async fn flush_policy(&self) -> Result<FlushPolicy, StateError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::FlushPolicy(reply)).await?;
        answer.await.map_err(|_| StateError::Closed)
    }

    /// Shuts the actor down cleanly: flushes, writes `kernel.shutdown`, flushes it, and ends; later
    /// commands get [`StateError::NotQueued`]. [`shut_down`] closes admission and waits for open
    /// work first.
    ///
    /// # Errors
    /// [`StateError::NotQueued`] or [`StateError::Closed`] after the actor ended; the journal's
    /// own refusal otherwise, or [`StateError::StopPending`] while a stop record waits.
    pub async fn shutdown(&self, reason: ShutdownReason) -> Result<ShutdownReport, StateError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Shutdown(reason, reply)).await?;
        answer.await.map_err(|_| StateError::Closed)?
    }

    /// What the actor has done so far.
    ///
    /// # Errors
    /// [`StateError::NotQueued`] or [`StateError::Closed`] after the actor ended.
    pub async fn stats(&self) -> Result<StateStats, StateError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Stats(reply)).await?;
        answer.await.map_err(|_| StateError::Closed)
    }

    /// Commands waiting in the queue now.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.commands.max_capacity() - self.commands.capacity()
    }

    /// Queues a command. Refused before it is queued once the actor has ended: nothing was
    /// written.
    async fn send(&self, command: Command) -> Result<(), StateError> {
        self.commands.send(command).await.map_err(|_| StateError::NotQueued)
    }
}

/// The actor's end of the queue, until [`start_state_actor`] takes it.
#[derive(Debug)]
pub struct StateQueue {
    commands: mpsc::Receiver<Command>,
}

/// A bounded queue of `capacity` commands (at least one, at most what a bounded channel holds)
/// and the handle that writes to it.
#[must_use]
pub fn state_queue(capacity: usize) -> (StateHandle, StateQueue) {
    // No more than a bounded channel holds: a larger capacity is clamped, never a panic.
    let (commands, receiver) = mpsc::channel(capacity.clamp(1, tokio::sync::Semaphore::MAX_PERMITS));
    (StateHandle { commands }, StateQueue { commands: receiver })
}

/// How the actor ended, for whoever joins its thread.
#[derive(Debug)]
#[non_exhaustive]
pub struct StateExit {
    /// The last flush, run once every handle was dropped. Its failure is reported only here:
    /// records acknowledged before it may not have reached the disk, and the next open cannot
    /// tell that they existed.
    pub final_flush: Result<(), StateError>,
    /// The journal's health at the end.
    pub health: JournalHealth,
    /// The last record durable against power loss, if any.
    pub flushed_through: Option<Seq>,
}

/// The actor's private timer. Dropping a tokio runtime inside an async context panics, and a
/// refused spawn drops the timer on the caller's thread, which may be a runtime worker. This
/// guard shuts the runtime down without waiting, wherever it is dropped.
struct Timer(Option<tokio::runtime::Runtime>);

impl Drop for Timer {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

/// The actor's thread, until it is joined.
#[derive(Debug)]
#[must_use = "join it to learn whether the final flush succeeded"]
pub struct StateActor {
    thread: std::thread::JoinHandle<Option<StateExit>>,
}

impl StateActor {
    /// Waits for the actor to end, which it does once every handle is dropped, and returns how
    /// it ended. This blocks: call it outside a runtime's workers.
    ///
    /// # Errors
    /// [`StateError::Closed`] if the thread ended without a report: it panicked (the lint wall
    /// denies panics) or never received its journal ([`start_state_actor`] rules that out).
    pub fn join(self) -> Result<StateExit, StateError> {
        self.thread.join().ok().flatten().ok_or(StateError::Closed)
    }

    /// Whether the actor's thread has ended.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.thread.is_finished()
    }
}

/// A start that was refused. The core and the queue come back, so the caller can still flush
/// what the journal acknowledged, or try again: a refusal loses nothing. It is `Send` but not
/// `Sync`, because the journal's file handles are not, so it does not convert into a
/// `Box<dyn Error + Send + Sync>`; take the core back out instead.
#[derive(Debug, thiserror::Error)]
#[error("the state actor could not start: {error}")]
#[non_exhaustive]
pub struct StartRefused {
    /// Why it was refused.
    pub error: SpawnError,
    /// The core, with the journal and every record it acknowledged.
    pub core: StateCore,
    /// The queue, with every command already in it.
    pub queue: StateQueue,
}

/// Starts the actor: `core` serves `queue` on a dedicated thread from `supervisor` until every
/// handle is dropped, then flushes once more and ends. [`StateActor::join`] gives the
/// [`StateExit`].
///
/// # Errors
/// [`StartRefused`] if the supervisor or the operating system refuses the thread, or if the
/// timer the actor waits on cannot be built ([`SpawnError::Timer`]). The core and the queue
/// come back in it.
pub fn start_state_actor(
    supervisor: &Supervisor,
    core: StateCore,
    queue: StateQueue,
) -> Result<StateActor, Box<StartRefused>> {
    // The actor waits on a timer of its own, so its deadlines do not depend on how the main
    // runtime is built: a current-thread runtime drives timers only from its own `block_on`.
    // It is built here, so a failure is reported at start and not as a dead actor later.
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_time().build() else {
        return Err(refused(SpawnError::Timer, core, queue));
    };
    let timer = Timer(Some(runtime));
    // The thread gets its work only once it exists, so a refusal leaves the work here to hand
    // back. One message, so the channel holds it without waiting.
    let (give, take) = std::sync::mpsc::sync_channel::<(StateCore, StateQueue, Timer)>(1);
    let spawned = supervisor.spawn_dedicated(THREAD_NAME, move || {
        take.recv().ok().map(|(core, queue, timer)| run(core, queue, timer))
    });
    match spawned {
        Err(error) => Err(refused(error, core, queue)),
        Ok(thread) => match give.send((core, queue, timer)) {
            Ok(()) => Ok(StateActor { thread }),
            // The thread is already gone, so the work comes back.
            Err(std::sync::mpsc::SendError((core, queue, _timer))) => Err(refused(SpawnError::Thread, core, queue)),
        },
    }
}

fn refused(error: SpawnError, core: StateCore, queue: StateQueue) -> Box<StartRefused> {
    Box::new(StartRefused { error, core, queue })
}

/// Engages the stop with `journal_failed` if the actor's thread unwinds. The lint wall denies
/// panics, but one in a dependency would still leave the kernel without a writer, and a kernel that
/// cannot journal must refuse work. A normal end engages nothing.
struct EndGuard(Option<(Stop, EngagedBy)>);

impl Drop for EndGuard {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Some((stop, by)) = self.0.take()
        {
            let _engaged = stop.engage(StopReason::JournalFailed, by);
        }
    }
}

/// The actor's life: serve the queue until every handle is gone, then flush once more.
fn run(mut core: StateCore, mut queue: StateQueue, timer: Timer) -> StateExit {
    let _guard = EndGuard(core.stop.clone());
    if let Some(runtime) = timer.0.as_ref() {
        serve(&mut core, &mut queue, runtime);
    }
    // The timer ends here, on the actor's own thread.
    drop(timer);
    StateExit {
        final_flush: core.sync(),
        health: core.health(),
        flushed_through: core.flushed_through(),
    }
}

/// What woke the actor.
enum Wake {
    /// A command, or `None` once every handle is gone.
    Command(Option<Command>),
    /// The schedule's next time came.
    Deadline,
    /// The stop changed: an engagement waits for its record.
    Stop,
}

/// The actor's loop: run the schedule, wait for a command, the next deadline or a change of the
/// stop, serve every command already queued, and again. The schedule also runs between queued
/// commands, so a stream of commands cannot hold a due flush back.
fn serve(core: &mut StateCore, queue: &mut StateQueue, timer: &tokio::runtime::Runtime) {
    let mut watch = core.stop_watch();
    loop {
        let wait = core
            .tick()
            .map(|at| Duration::from_nanos(at.saturating_sub(core.now())));
        // The timer registers when the sleep is made, so it is made inside the actor's runtime,
        // never before `block_on` enters it.
        let wake = timer.block_on(async {
            let deadline = async {
                match wait {
                    Some(wait) => tokio::time::sleep(wait).await,
                    None => std::future::pending::<()>().await,
                }
            };
            let stopped = async {
                match watch.as_mut() {
                    Some(watch) => watch.changed().await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                command = queue.commands.recv() => Wake::Command(command),
                () = deadline => Wake::Deadline,
                () = stopped => Wake::Stop,
            }
        });
        let command = match wake {
            Wake::Command(Some(command)) => command,
            // Every handle is gone.
            Wake::Command(None) => return,
            Wake::Deadline | Wake::Stop => continue,
        };
        if !core.handle(command, queue.commands.len()) {
            return;
        }
        while let Ok(command) = queue.commands.try_recv() {
            let _next_deadline = core.tick();
            if !core.handle(command, queue.commands.len()) {
                return;
            }
        }
    }
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// The stop reason a journal health calls for; `None` while it is healthy.
#[must_use]
pub fn stop_reason_for(health: JournalHealth) -> Option<StopReason> {
    match health {
        JournalHealth::Healthy => None,
        JournalHealth::DiskFull => Some(StopReason::DiskFull),
        JournalHealth::PayloadFlushFailed => Some(StopReason::PayloadFlushFailed),
        JournalHealth::WriteFailed | JournalHealth::FlushFailed => Some(StopReason::JournalFailed),
    }
}

/// The `kernel.shutdown` record: critical, as the one who asked, with
/// `{"clean": true, "open_operations": "<n>"}`, the count as a decimal string (`wire`'s rule). Open
/// work left behind is surfaced at the highest risk tier.
fn shutdown_draft(reason: &ShutdownReason) -> Result<EventDraft, EnvelopeError> {
    Ok(EventDraft {
        session_id: None,
        pocket_id: None,
        operation_id: None,
        request_id: None,
        agent_id: None,
        correlation_id: reason.by.correlation_id,
        parent_id: None,
        actor: reason.by.actor.clone(),
        event_type: types::KERNEL_SHUTDOWN,
        payload_ref: None,
        payload_inline: Some(InlinePayload::new(serde_json::json!({
            "clean": true,
            "open_operations": reason.open_operations.to_string(),
        }))?),
        cost_estimate: None,
        compensable: false,
        side_effect_class: SideEffectClass::None,
        risk_tier: if reason.open_operations > 0 {
            RiskTier::MAX
        } else {
            RiskTier::MIN
        },
        durability: Durability::Critical,
        config_version: reason.by.config_version,
        metadata: Metadata::default(),
    })
}

/// How long past its deadline a shutdown waits for the ledger task's answer before it counts the
/// task as one open Operation and goes on. The task starts no close after the deadline; the grace
/// covers the command it is in: a write already handed to the actor, and the one or two that
/// command may still make (a transfer's second record, or the release after a refused
/// `op.executing`).
pub const LEDGER_DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Shuts the kernel down cleanly: closes admission with `RUNTIME_DRAINING`, and the ledger task's
/// `reserve` and `execute` with it; waits up to `deadline` for the Operations in flight to end
/// while the task keeps performing closes; then ends the task, which drains until every token is
/// closed or the deadline passes; and only then has the state actor write and flush
/// `kernel.shutdown` and end. Cutting the Operations still open at the deadline, as a stop cuts
/// them, lands with the pipeline that drives them; until then they are counted in the record, and
/// the next boot's recovery closes them.
///
/// `open_operations` is at least the number of Operations left open, from two reads in this
/// order: admission's in-flight count, read before the task is told to end (a caller still
/// waiting on a close's reply holds its permit until then), plus the reservations still open in
/// the task's ledger when it ends, stuck items excepted. An Operation can be counted twice, never
/// zero times. A task that does not answer within [`LEDGER_DRAIN_GRACE`] past the deadline, or
/// that had already ended, is counted as one: what it left open is unknown, so the next boot
/// says work was left open (a stop may have been lost) rather than nothing.
///
/// `ledger` is `None` only where no ledger task runs: with a task running, `None` would leave
/// its open reservations uncounted.
///
/// # Errors
/// As [`StateHandle::shutdown`].
pub async fn shut_down(
    admission: &Admission,
    state: &StateHandle,
    ledger: Option<&LedgerHandle>,
    by: EngagedBy,
    deadline: Duration,
) -> Result<ShutdownReport, StateError> {
    let now = tokio::time::Instant::now();
    // A deadline too far to represent (`Duration::MAX`) waits a year instead of panicking.
    let until = now
        .checked_add(deadline)
        .or_else(|| now.checked_add(Duration::from_hours(24 * 365)))
        .unwrap_or(now);
    admission.drain();
    if let Some(ledger) = ledger {
        ledger.drain();
    }
    let _waited = tokio::time::timeout_at(until, async {
        while admission.in_flight().0 > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let admitted = admission.in_flight().0;
    let left = match ledger {
        // The drain ends at `until`; a task that has not answered a grace later (one stuck in a
        // write the state actor has not answered) is counted as one, and the shutdown goes on.
        Some(ledger) => {
            let answered = tokio::time::timeout_at(
                until.checked_add(LEDGER_DRAIN_GRACE).unwrap_or(until),
                ledger.shutdown(until),
            )
            .await;
            match answered {
                Ok(Ok(open)) => open.0,
                Ok(Err(_)) | Err(_) => 1,
            }
        }
        None => 0,
    };
    let open = admitted.saturating_add(left);
    state.shutdown(ShutdownReason::new(by, open)).await
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use uaos_contracts::event::Actor;
    use uaos_contracts::id::{CorrelationId, TypedId};
    use uaos_contracts::wire::ConfigVersion;

    use super::*;

    fn the_actor() -> EngagedBy {
        EngagedBy {
            actor: Actor::System,
            correlation_id: CorrelationId::from_parts(9, [9; 10]),
            config_version: ConfigVersion(1),
        }
    }

    /// An actor whose thread unwinds leaves no writer, so it engages the stop with
    /// `journal_failed`; one that ends normally engages nothing.
    #[test]
    fn an_actor_that_unwinds_engages_the_stop() {
        let stop = Stop::running();
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            let _guard = EndGuard(Some((stop.clone(), the_actor())));
            std::panic::resume_unwind(Box::new("seeded"));
        }));
        assert!(unwound.is_err());
        assert_eq!(
            stop.reason(),
            Some(StopReason::JournalFailed),
            "an actor that unwound left the kernel admitting"
        );

        let stop = Stop::running();
        drop(EndGuard(Some((stop.clone(), the_actor()))));
        assert!(!stop.is_engaged(), "an actor that ended normally stopped the kernel");
    }
}
