// SPDX-License-Identifier: Apache-2.0

//! The data directory: its lock, its journal and the installation it names.
//!
//! The installation id is the journal's id: the keychain keeps the installation's keys under it, so
//! two data directories never share an entry. A kernel holds `uaos.lock` while it runs; a command
//! that writes takes the same lock, and one that only reads checks it, so a read of the journal
//! never races its writer.

use std::path::{Path, PathBuf};

use uaos_contracts::cli::JournalSummary;
use uaos_contracts::error::codes;
use uaos_contracts::event::EventEnvelope;
use uaos_platform::fs::{Fs, FsError, LockGuard};
use uaos_runtime::{BootState, boot_state};
use uaos_state::journal::{JOURNAL_DIR, LOCK_FILE, VerifiedRecord, VerifyReport, read_verified};

use crate::Failed;

/// The journal's directory inside the data directory.
pub(crate) fn journal_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(JOURNAL_DIR)
}

/// Takes the data directory's lock, the one a running kernel holds.
///
/// # Errors
/// [`codes::JOURNAL_INSTANCE_LOCKED`] while a kernel (or another command) holds it.
pub(crate) fn lock(fs: &dyn Fs, data_dir: &Path) -> Result<Box<dyn LockGuard>, Failed> {
    fs.try_lock_exclusive(&data_dir.join(LOCK_FILE)).map_err(|e| match e {
        FsError::Locked { .. } => Failed::new(
            codes::JOURNAL_INSTANCE_LOCKED,
            "a running kernel holds this data directory; stop it first (the control API, B2, will do this while it runs)",
        ),
        FsError::NotFound { .. } => not_initialized(),
        other => Failed::new(codes::CLI_DATA_DIR, format!("the data directory's lock: {other}")),
    })
}

/// Whether a kernel holds the lock now. Probing takes the lock for an instant when it is free.
///
/// # Errors
/// [`codes::CLI_DATA_DIR`] when the lock file cannot be opened.
pub(crate) fn kernel_running(fs: &dyn Fs, data_dir: &Path) -> Result<bool, Failed> {
    match fs.try_lock_exclusive(&data_dir.join(LOCK_FILE)) {
        Ok(guard) => {
            drop(guard);
            Ok(false)
        }
        Err(FsError::Locked { .. }) => Ok(true),
        Err(FsError::NotFound { .. }) => Ok(false),
        Err(other) => Err(Failed::new(
            codes::CLI_DATA_DIR,
            format!("the data directory's lock: {other}"),
        )),
    }
}

/// The verified journal, or `None` when there is none yet.
///
/// # Errors
/// The journal's own code when it does not verify, e.g. `UAOS-JOURNAL-0002`.
pub(crate) fn read_journal(fs: &dyn Fs, data_dir: &Path) -> Result<Option<Journal>, Failed> {
    let dir = journal_dir(data_dir);
    match fs.list_dir(&dir) {
        Err(FsError::NotFound { .. }) => return Ok(None),
        Err(e) => return Err(Failed::new(codes::CLI_DATA_DIR, format!("the journal: {e}"))),
        Ok(entries) if entries.is_empty() => return Ok(None),
        Ok(_) => {}
    }
    let (records, report) = read_verified(fs, &dir).map_err(|e| Failed::new(e.code(), format!("the journal: {e}")))?;
    Ok(Some(Journal { records, report }))
}

/// A verified journal.
pub(crate) struct Journal {
    pub(crate) records: Vec<VerifiedRecord>,
    pub(crate) report: VerifyReport,
}

impl Journal {
    /// The installation id: the journal's.
    pub(crate) fn installation(&self) -> &str {
        &self.report.journal_id
    }

    pub(crate) fn envelopes(&self) -> impl Iterator<Item = &EventEnvelope> {
        self.records.iter().map(|r| &r.envelope)
    }

    /// What the read found, for `status`, `journal verify` and `doctor`.
    pub(crate) fn summary(&self) -> JournalSummary {
        let stop = match boot_state(self.envelopes()) {
            BootState::Running => "running".to_owned(),
            BootState::Stopped(reason) => format!("stopped ({})", reason.code()),
        };
        JournalSummary {
            journal_id: self.report.journal_id.clone(),
            records: self.report.records,
            next_seq: self.report.next_seq,
            head: self.report.head.to_string(),
            segments: u64::try_from(self.report.segments).unwrap_or(u64::MAX),
            ignored_tail_bytes: self.report.ignored_tail_bytes,
            stop,
        }
    }
}

/// The installation id of an initialized data directory.
///
/// # Errors
/// [`codes::CLI_DATA_DIR`] when the directory holds no journal: `init` has not run.
pub(crate) fn installation(fs: &dyn Fs, data_dir: &Path) -> Result<String, Failed> {
    read_journal(fs, data_dir)?
        .map(|j| j.installation().to_owned())
        .ok_or_else(not_initialized)
}

pub(crate) fn not_initialized() -> Failed {
    Failed::new(
        codes::CLI_DATA_DIR,
        "this data directory is not initialized; run `uaos init`",
    )
}
