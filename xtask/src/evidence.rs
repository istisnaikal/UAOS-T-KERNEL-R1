// SPDX-License-Identifier: Apache-2.0

//! Evidence freshness.
//!
//! Some proofs only run nightly: 10,000 real kills per OS, 100,000 ledger schedules, a fresh
//! redaction corpus, per-OS latency. Such a proof says something about a release only if three
//! things hold:
//!
//! * the run **passed**;
//! * it is **recent** (at most `--max-age-hours`, default 48);
//! * it ran on **the code being released**: nothing under `crates/`, `xtask/`, `Cargo.toml`,
//!   `Cargo.lock` or `rust-toolchain.toml` differs between the nightly's commit and the
//!   candidate.
//!
//! `--streak N` also requires N consecutive nights (distinct UTC dates), newest first, each green
//! and bound to the candidate. The the first release go/no-go uses 7.
//!
//! Reads run history with the GitHub CLI (`gh run list`), so it needs network access and
//! authentication. It is a release gate, not a merge gate.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;
use uaos_contracts::time::WallTime;

use crate::util::capture;

const WORKFLOW: &str = "nightly.yml";
const BRANCH: &str = "main";
const HISTORY: &str = "40";
const DEFAULT_MAX_AGE_HOURS: i128 = 48;
const NANOS_PER_HOUR: i128 = 3_600_000_000_000;
const NANOS_PER_DAY: i128 = 24 * NANOS_PER_HOUR;
/// Paths whose content defines "the code" for evidence binding.
const BOUND_PATHS: &[&str] = &["crates", "xtask", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"];

/// One workflow run as `gh run list --json` reports it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Run {
    pub(crate) database_id: u64,
    pub(crate) status: String,
    pub(crate) conclusion: String,
    pub(crate) created_at: WallTime,
    pub(crate) head_sha: String,
}

/// What the evidence supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Report {
    /// Newest green run bound to the candidate.
    pub(crate) newest: u64,
    /// Consecutive bound green nights, newest first.
    pub(crate) streak: usize,
}

pub(crate) fn check(root: &Path, args: &[String]) -> Result<(), String> {
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let candidate = value("--candidate").unwrap_or_else(|| "HEAD".to_owned());
    let streak: usize = value("--streak").map_or(Ok(1), |s| s.parse().map_err(|_| "--streak takes a number"))?;
    let max_age: i128 = value("--max-age-hours").map_or(Ok(DEFAULT_MAX_AGE_HOURS), |s| {
        s.parse().map_err(|_| "--max-age-hours takes a number")
    })?;

    let json = capture(
        root,
        "gh",
        &[
            "run",
            "list",
            "--workflow",
            WORKFLOW,
            "--branch",
            BRANCH,
            "--limit",
            HISTORY,
            "--json",
            "databaseId,status,conclusion,createdAt,headSha",
        ],
    )?;
    let runs: Vec<Run> = serde_json::from_str(&json).map_err(|e| format!("gh run list: {e}"))?;
    let candidate_sha = capture(root, "git", &["rev-parse", &candidate])?.trim().to_owned();
    let bound = |sha: &str| -> bool {
        let mut args = vec!["diff", "--name-only", sha, candidate_sha.as_str(), "--"];
        args.extend_from_slice(BOUND_PATHS);
        capture(root, "git", &args).is_ok_and(|out| out.trim().is_empty())
    };
    let now = now()?;
    let report = evaluate(&runs, bound, now, max_age, streak)?;
    println!(
        "xtask evidence: run {} is green, fresh and bound to {}; streak {} night(s) (required {streak})",
        report.newest,
        candidate_sha.get(..12).unwrap_or(&candidate_sha),
        report.streak
    );
    Ok(())
}

fn now() -> Result<WallTime, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("system clock: {e}"))?
        .as_nanos();
    let nanos = i128::try_from(nanos).map_err(|_| "system clock out of range".to_owned())?;
    WallTime::from_unix_nanos(nanos).map_err(|e| format!("system clock: {e}"))
}

/// Decides whether `runs` (newest first, as `gh` lists them) support the candidate.
pub(crate) fn evaluate(
    runs: &[Run],
    bound: impl Fn(&str) -> bool,
    now: WallTime,
    max_age_hours: i128,
    required_streak: usize,
) -> Result<Report, String> {
    let completed: Vec<&Run> = runs.iter().filter(|r| r.status == "completed").collect();
    let Some(newest) = completed.first() else {
        return Err("no completed nightly run on main: there is no nightly evidence at all".to_owned());
    };
    if newest.conclusion != "success" {
        return Err(format!(
            "the newest nightly run {} concluded `{}`; evidence is red",
            newest.database_id, newest.conclusion
        ));
    }
    if !bound(&newest.head_sha) {
        return Err(format!(
            "the newest green nightly run {} ran on {}, whose code differs from the candidate; \
             evidence must come from the code being released",
            newest.database_id,
            newest.head_sha.get(..12).unwrap_or(&newest.head_sha)
        ));
    }
    let age = now.as_unix_nanos() - newest.created_at.as_unix_nanos();
    if age > max_age_hours * NANOS_PER_HOUR {
        return Err(format!(
            "the newest bound green nightly run {} is {} h old (maximum {max_age_hours} h)",
            newest.database_id,
            age / NANOS_PER_HOUR
        ));
    }
    let mut nights = BTreeSet::new();
    for run in &completed {
        if run.conclusion != "success" || !bound(&run.head_sha) {
            break;
        }
        nights.insert(run.created_at.as_unix_nanos().div_euclid(NANOS_PER_DAY));
    }
    if nights.len() < required_streak {
        return Err(format!(
            "only {} consecutive bound green night(s); {required_streak} required",
            nights.len()
        ));
    }
    Ok(Report {
        newest: newest.database_id,
        streak: nights.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_NS: i128 = NANOS_PER_DAY;
    const T0: i128 = 1_760_000_000_000_000_000;

    fn run(id: u64, day: i128, conclusion: &str, sha: &str) -> Run {
        Run {
            database_id: id,
            status: "completed".to_owned(),
            conclusion: conclusion.to_owned(),
            created_at: WallTime::from_unix_nanos(T0 + day * DAY_NS).unwrap(),
            head_sha: sha.to_owned(),
        }
    }

    fn now(day: i128) -> WallTime {
        WallTime::from_unix_nanos(T0 + day * DAY_NS + NANOS_PER_HOUR).unwrap()
    }

    #[test]
    fn green_fresh_bound_runs_count_as_nights() {
        let runs = vec![
            run(3, 2, "success", "c"),
            run(2, 1, "success", "c"),
            run(1, 0, "success", "c"),
        ];
        let report = evaluate(&runs, |s| s == "c", now(2), 48, 3).unwrap();
        assert_eq!(report, Report { newest: 3, streak: 3 });
    }

    #[test]
    fn a_red_newest_run_fails() {
        let runs = vec![run(2, 1, "failure", "c"), run(1, 0, "success", "c")];
        assert!(evaluate(&runs, |_| true, now(1), 48, 1).unwrap_err().contains("red"));
    }

    #[test]
    fn evidence_from_other_code_does_not_count() {
        let runs = vec![run(1, 0, "success", "old")];
        assert!(
            evaluate(&runs, |s| s == "new", now(0), 48, 1)
                .unwrap_err()
                .contains("differs")
        );
    }

    #[test]
    fn stale_evidence_fails() {
        let runs = vec![run(1, 0, "success", "c")];
        assert!(evaluate(&runs, |_| true, now(3), 48, 1).unwrap_err().contains("old"));
    }

    #[test]
    fn the_streak_stops_at_the_first_failure_and_counts_dates_not_runs() {
        let runs = vec![
            run(5, 3, "success", "c"),
            run(4, 3, "success", "c"),
            run(3, 2, "success", "c"),
            run(2, 1, "failure", "c"),
            run(1, 0, "success", "c"),
        ];
        let report = evaluate(&runs, |_| true, now(3), 48, 2).unwrap();
        assert_eq!(report.streak, 2, "two runs on day 3 are one night; day 1 failed");
        assert!(evaluate(&runs, |_| true, now(3), 48, 3).is_err());
    }

    #[test]
    fn no_evidence_is_an_error_not_a_pass() {
        assert!(evaluate(&[], |_| true, now(0), 48, 1).is_err());
    }
}
