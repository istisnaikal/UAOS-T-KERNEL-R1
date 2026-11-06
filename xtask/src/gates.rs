// SPDX-License-Identifier: Apache-2.0

//! The gate registry (`gates.toml`).
//!
//! Every merge blocker and required behavior is listed with its status. An
//! **active** gate names the CI job that runs it and the negative case that proves it bites.
//! A **pending** gate names the phase that brings its subject into existence; pending gates
//! block a *release*, never silently pass a merge. The required sets below are copied from
//! the project's merge rules and may only shrink through an RFC.
//!
//! Two rules keep the registry from drifting behind the documents:
//! * **Overdue.** A pending gate or behavior whose phase lies before the project's phase fails
//!   the merge. A phase is left only with its gates active, or re-phased by a recorded decision.
//! * **Promises.** A `[[promise]]` names a proof an ADR or the threat model commits to, by the id
//!   it will carry: an active gate, an active behavior or a negative case. An unmet promise blocks
//!   a release, and one whose phase has passed fails the merge. A promise is not a pending gate:
//!   keeps `surface` out of the pending count, and the count it reports is kept apart here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

/// The gates every merge must keep active.
const REQUIRED_GATES: &[&str] = &[
    "fmt",
    "clippy",
    "sources",
    "test",
    "secret-scan",
    "cargo-deny",
    "cargo-vet",
    "spdx-headers",
    "dco",
    "codeql",
    "arch-check",
    "schema-compat",
    "docs-contract-sync",
    "language-neutrality",
    "gate-registry",
    "status-truth",
    "gate-selftest",
    "path-spaces-unicode",
    "allow-audit",
    "vet-ratchet",
    "claims-lint",
    "journal-durability",
    "budget-concurrency",
    "redaction-corpus",
    "policy-semantics",
    "cli-contract",
    "kernel-tokens",
];

/// The behaviors every merge must keep proven.
const REQUIRED_BEHAVIORS: &[&str] = &["disk-full", "budget-double-spend"];

/// Promises the registry tracks; none in this repository.
const REQUIRED_PROMISES: &[&str] = &[];

/// Phases, in order; the order decides what is overdue.
const PHASES: &[&str] = &["P0", "P1", "P2", "P3"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    project: Project,
    gate: Vec<Gate>,
    behavior: Vec<Behavior>,
    #[serde(default)]
    promise: Vec<Promise>,
}

/// A proof a document commits to, by the id it will carry once it exists.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Promise {
    id: String,
    /// `gate` (an active gate), `behavior` (an active behavior) or `negative` (a negative case).
    kind: String,
    source: String,
    phase: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Project {
    phase: String,
}

/// The workflow whose jobs form the merge lane, and its aggregating job.
const MERGE_WORKFLOW: &str = "ci.yml";
const MERGE_GATE_JOB: &str = "merge-gate";
/// The ruleset applied to `main`. Its required status checks must be exactly the aggregating job
/// plus the checks that live outside the merge workflow.
const RULESET: &str = ".github/rulesets/main.json";
/// Required checks that run in another workflow and so cannot be `needs` of the aggregator.
const OUTSIDE_MERGE_WORKFLOW: &[&str] = &["codeql"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gate {
    id: String,
    source: String,
    lane: String,
    status: String,
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    job: Option<String>,
    #[serde(default)]
    negative: Vec<String>,
    #[serde(default)]
    negative_exempt: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Behavior {
    id: String,
    source: String,
    status: String,
    phase: String,
    #[serde(default)]
    gate: Option<String>,
}

pub(crate) fn check(root: &Path, release: bool) -> Result<(), String> {
    let text = std::fs::read_to_string(root.join("gates.toml")).map_err(|e| format!("gates.toml: {e}"))?;
    let registry: Registry = toml::from_str(&text).map_err(|e| format!("gates.toml: {e}"))?;
    let workflows = workflow_jobs(root)?;
    let cases = crate::negative::cases();
    let case_gate: BTreeMap<&str, &str> = cases.iter().map(|c| (c.id, c.gate)).collect();
    let negative_ids: BTreeSet<&str> = case_gate.keys().copied().collect();
    let negative_gates: BTreeSet<&str> = case_gate.values().copied().collect();

    let mut problems = Vec::new();
    let mut ids = BTreeSet::new();
    let mut pending = Vec::new();

    for g in &registry.gate {
        if !ids.insert(g.id.as_str()) {
            problems.push(format!("gate `{}` is listed twice", g.id));
        }
        if g.source.trim().is_empty() {
            problems.push(format!("gate `{}` has no source", g.id));
        }
        if !matches!(g.lane.as_str(), "merge" | "nightly" | "release") {
            problems.push(format!("gate `{}`: lane must be merge, nightly or release", g.id));
        }
        match g.status.as_str() {
            "active" => check_active_gate(g, &workflows, &case_gate, &mut problems),
            "pending" => check_pending_gate(g, &registry.project.phase, &mut problems, &mut pending),
            other => problems.push(format!("gate `{}`: status `{other}` must be active or pending", g.id)),
        }
    }
    for required in REQUIRED_GATES {
        if !ids.contains(required) {
            problems.push(format!("missing required gate `{required}` "));
        }
    }
    for case_gate in &negative_gates {
        if !ids.contains(case_gate) {
            problems.push(format!("negative case targets unknown gate `{case_gate}`"));
        }
    }

    let active: BTreeSet<&str> = registry
        .gate
        .iter()
        .filter(|g| g.status == "active")
        .map(|g| g.id.as_str())
        .collect();
    check_behaviors(
        &registry.behavior,
        &active,
        &registry.project.phase,
        &mut problems,
        &mut pending,
    );
    let outstanding = check_promises(&registry, &negative_ids, &mut problems);
    check_phase(root, &registry.project, &mut problems);
    crate::status::check(root, &mut problems);
    check_merge_gate(root, &registry.gate, &mut problems);

    if release && !pending.is_empty() {
        problems.push(format!(
            "release requires zero pending gates; pending: {}",
            pending.join(", ")
        ));
    }
    if release && !outstanding.is_empty() {
        problems.push(format!(
            "release requires every promise met; outstanding: {}",
            outstanding.join(", ")
        ));
    }
    if problems.is_empty() {
        println!(
            "xtask gates: {} gates, {} behaviors registered; {} pending (allowed before release); \
             {} of {} promises outstanding (allowed until their phase ends)",
            registry.gate.len(),
            registry.behavior.len(),
            pending.len(),
            outstanding.len(),
            registry.promise.len()
        );
        Ok(())
    } else {
        Err(format!("gate registry problems:\n  {}", problems.join("\n  ")))
    }
}

/// An active gate runs in a CI job and lists the negative cases that prove it bites, each labelled
/// for this gate: a case proves the gate it seeds, so one labelled for another gate proves nothing
/// here.
fn check_active_gate(
    g: &Gate,
    workflows: &BTreeSet<String>,
    case_gate: &BTreeMap<&str, &str>,
    problems: &mut Vec<String>,
) {
    match &g.job {
        Some(job) if workflows.contains(job) => {}
        Some(job) => problems.push(format!("gate `{}`: job `{job}` not found in .github/workflows", g.id)),
        None => problems.push(format!("gate `{}`: active gates must name their CI job", g.id)),
    }
    if g.negative.is_empty() && g.negative_exempt.is_none() {
        problems.push(format!(
            "gate `{}`: active gates must list a negative case or a `negative_exempt` reason",
            g.id
        ));
    }
    for c in &g.negative {
        match case_gate.get(c.as_str()) {
            None => problems.push(format!("gate `{}`: negative case `{c}` does not exist", g.id)),
            Some(labelled) if *labelled != g.id => problems.push(format!(
                "gate `{}`: negative case `{c}` is labelled for gate `{labelled}`",
                g.id
            )),
            Some(_) => {}
        }
    }
}

/// A pending gate names a known phase that has not passed yet.
fn check_pending_gate(g: &Gate, project_phase: &str, problems: &mut Vec<String>, pending: &mut Vec<String>) {
    match &g.phase {
        Some(p) if PHASES.contains(&p.as_str()) => {
            if overdue(p, project_phase) {
                problems.push(format!(
                    "gate `{}` is pending past its phase `{p}` (project phase `{project_phase}`): \
                     activate it, or re-phase it by a recorded decision",
                    g.id
                ));
            }
            pending.push(format!("{} ({p})", g.id));
        }
        Some(p) => problems.push(format!("gate `{}`: unknown phase `{p}`", g.id)),
        None => problems.push(format!(
            "gate `{}`: pending gates must name the phase that activates them",
            g.id
        )),
    }
}

/// Behaviors are pending with a phase, or active on an **active** gate: a behavior "active" on a
/// pending gate would be run by nothing.
fn check_behaviors(
    behaviors: &[Behavior],
    active_gates: &BTreeSet<&str>,
    project_phase: &str,
    problems: &mut Vec<String>,
    pending: &mut Vec<String>,
) {
    let mut behavior_ids = BTreeSet::new();
    for b in behaviors {
        if !behavior_ids.insert(b.id.as_str()) {
            problems.push(format!("behavior `{}` is listed twice", b.id));
        }
        if b.source.trim().is_empty() || !PHASES.contains(&b.phase.as_str()) {
            problems.push(format!("behavior `{}`: needs a source and a known phase", b.id));
        }
        match b.status.as_str() {
            "pending" => {
                if overdue(&b.phase, project_phase) {
                    problems.push(format!(
                        "behavior `{}` is pending past its phase `{}` (project phase `{project_phase}`): \
                         activate it, or re-phase it by a recorded decision",
                        b.id, b.phase
                    ));
                }
                pending.push(format!("behavior {} ({})", b.id, b.phase));
            }
            "active" if b.gate.as_deref().is_some_and(|g| active_gates.contains(g)) => {}
            "active" => problems.push(format!(
                "behavior `{}`: active behaviors must name an active gate",
                b.id
            )),
            other => problems.push(format!(
                "behavior `{}`: status `{other}` must be active or pending",
                b.id
            )),
        }
    }
    for required in REQUIRED_BEHAVIORS {
        if !behavior_ids.contains(required) {
            problems.push(format!("missing required behavior `{required}`"));
        }
    }
}

/// Checks every promise and returns the unmet ones as `id (phase)`.
///
/// A promise is met when its id is an **active** gate, an **active** behavior or an existing
/// negative case, as its kind says. Registering a gate as pending does not meet a promise of an
/// active gate.
fn check_promises(registry: &Registry, negative_ids: &BTreeSet<&str>, problems: &mut Vec<String>) -> Vec<String> {
    let project_phase = registry.project.phase.as_str();
    let mut seen = BTreeSet::new();
    let mut outstanding = Vec::new();
    for p in &registry.promise {
        if !seen.insert(p.id.as_str()) {
            problems.push(format!("promise `{}` is listed twice", p.id));
        }
        if p.source.trim().is_empty() {
            problems.push(format!("promise `{}` has no source", p.id));
        }
        if !PHASES.contains(&p.phase.as_str()) {
            problems.push(format!("promise `{}`: unknown phase `{}`", p.id, p.phase));
            continue;
        }
        let met = match p.kind.as_str() {
            "gate" => registry.gate.iter().any(|g| g.id == p.id && g.status == "active"),
            "behavior" => registry.behavior.iter().any(|b| b.id == p.id && b.status == "active"),
            // The case must exist and an active gate must list it as its proof (each listed case is
            // labelled for the gate that lists it, see `check_active_gate`). A case that only
            // exists, or is labelled for a pending gate, proves nothing yet.
            "negative" => {
                negative_ids.contains(p.id.as_str())
                    && registry
                        .gate
                        .iter()
                        .any(|g| g.status == "active" && g.negative.contains(&p.id))
            }
            other => {
                problems.push(format!(
                    "promise `{}`: kind `{other}` must be gate, behavior or negative",
                    p.id
                ));
                continue;
            }
        };
        if met {
            continue;
        }
        if overdue(&p.phase, project_phase) {
            problems.push(format!(
                "promise `{}` ({} `{}`, {}) was due in `{}` and the project is at `{project_phase}`: \
                 build it, or amend the promise by a recorded decision",
                p.id, p.kind, p.id, p.source, p.phase
            ));
        }
        outstanding.push(format!("{} ({})", p.id, p.phase));
    }
    for required in REQUIRED_PROMISES {
        if !seen.contains(required) {
            problems.push(format!(
                "missing required promise `{required}`: dropping a promise needs an ADR or a recorded \
                 decision, and a change to REQUIRED_PROMISES in xtask/src/gates.rs"
            ));
        }
    }
    outstanding
}

/// `phase` comes before `project_phase` in [`PHASES`]. Unknown phases are reported elsewhere and
/// are never overdue here.
fn overdue(phase: &str, project_phase: &str) -> bool {
    let index = |name: &str| PHASES.iter().position(|p| *p == name);
    matches!((index(phase), index(project_phase)), (Some(a), Some(b)) if a < b)
}

/// The README status heading must name the registry's phase, so the public phase line cannot
/// go stale.
fn check_phase(root: &Path, project: &Project, problems: &mut Vec<String>) {
    let phase = project.phase.as_str();
    if !PHASES.contains(&phase) {
        problems.push(format!("[project] phase `{phase}` is not a known phase"));
        return;
    }
    let sources: [(&str, &str); 1] = [("README.md", "## Status: ")];
    for (file, prefix) in sources {
        let Ok(text) = std::fs::read_to_string(root.join(file)) else {
            problems.push(format!("phase line: cannot read {file}"));
            continue;
        };
        let named: Vec<&str> = text
            .lines()
            .filter_map(|line| line.strip_prefix(prefix))
            .map(|rest| {
                rest.split(|c: char| c.is_whitespace() || c == ',')
                    .next()
                    .unwrap_or_default()
            })
            .collect();
        match named.as_slice() {
            [] => problems.push(format!("phase line: {file} has no line starting with `{prefix}`")),
            [one] if *one == phase => {}
            [one] => problems.push(format!(
                "phase line: {file} names `{one}` but gates.toml [project] phase is `{phase}`"
            )),
            _ => problems.push(format!("phase line: {file} has more than one `{prefix}` line")),
        }
    }
}

/// The ruleset requires one aggregated check per workflow instead of every job by name, so a new
/// merge-lane job can never be left out of the required set. Checked here:
/// * `merge-gate` exists in the merge workflow, runs `if: always()` and `needs` exactly every
///   other job of that workflow;
/// * the ruleset's required checks are exactly `merge-gate` plus the checks of other workflows;
/// * every active merge-lane gate runs in a job one of those required checks covers.
fn check_merge_gate(root: &Path, gates: &[Gate], problems: &mut Vec<String>) {
    let path = root.join(".github").join("workflows").join(MERGE_WORKFLOW);
    let Ok(text) = std::fs::read_to_string(&path) else {
        problems.push(format!("merge gate: cannot read .github/workflows/{MERGE_WORKFLOW}"));
        return;
    };
    let jobs = jobs_with_bodies(&text);
    let others: BTreeSet<&str> = jobs
        .iter()
        .map(|(id, _)| id.as_str())
        .filter(|id| *id != MERGE_GATE_JOB)
        .collect();
    match jobs.iter().find(|(id, _)| id == MERGE_GATE_JOB) {
        None => problems.push(format!(
            "merge gate: job `{MERGE_GATE_JOB}` is missing from {MERGE_WORKFLOW}"
        )),
        Some((_, body)) => {
            if !body.iter().any(|l| l.trim() == "if: always()") {
                problems.push(format!(
                    "merge gate: `{MERGE_GATE_JOB}` must run `if: always()`, or a failed or skipped job \
                     would skip it and a skipped required check counts as passing"
                ));
            }
            let needs = body.iter().find_map(|l| l.trim().strip_prefix("needs:")).map(|list| {
                list.trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect::<BTreeSet<&str>>()
            });
            match needs {
                None => problems.push(format!(
                    "merge gate: `{MERGE_GATE_JOB}` has no single-line `needs: [...]`"
                )),
                Some(needs) => {
                    for missing in others.difference(&needs) {
                        problems.push(format!(
                            "merge gate: job `{missing}` is not in `{MERGE_GATE_JOB}` needs, so no required check covers it"
                        ));
                    }
                    for unknown in needs.difference(&others) {
                        problems.push(format!("merge gate: `{MERGE_GATE_JOB}` needs unknown job `{unknown}`"));
                    }
                }
            }
        }
    }

    match ruleset_required_checks(root) {
        Err(e) => problems.push(format!("merge gate: {RULESET}: {e}")),
        Ok(required) => {
            let expected: BTreeSet<&str> = std::iter::once(MERGE_GATE_JOB)
                .chain(OUTSIDE_MERGE_WORKFLOW.iter().copied())
                .collect();
            let actual: BTreeSet<&str> = required.iter().map(String::as_str).collect();
            if actual != expected {
                problems.push(format!(
                    "merge gate: {RULESET} requires {actual:?}; it must require exactly {expected:?}"
                ));
            }
        }
    }

    for g in gates.iter().filter(|g| g.lane == "merge" && g.status == "active") {
        if let Some(job) = &g.job
            && !others.contains(job.as_str())
            && !OUTSIDE_MERGE_WORKFLOW.contains(&job.as_str())
        {
            problems.push(format!(
                "merge gate: active gate `{}` runs in job `{job}`, which no required check covers",
                g.id
            ));
        }
    }
}

/// The required status-check contexts of the versioned ruleset.
fn ruleset_required_checks(root: &Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(root.join(RULESET)).map_err(|e| e.to_string())?;
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let rules = json
        .get("rules")
        .and_then(serde_json::Value::as_array)
        .ok_or("no `rules` array")?;
    let checks = rules
        .iter()
        .find(|r| r.get("type").and_then(serde_json::Value::as_str) == Some("required_status_checks"))
        .and_then(|r| r.pointer("/parameters/required_status_checks"))
        .and_then(serde_json::Value::as_array)
        .ok_or("no required_status_checks rule")?;
    checks
        .iter()
        .map(|c| {
            c.get("context")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| "a required check has no context".to_owned())
        })
        .collect()
}

/// Jobs of one workflow file in order, each with the lines of its body (more deeply indented
/// lines up to the next job key).
fn jobs_with_bodies(text: &str) -> Vec<(String, Vec<&str>)> {
    let mut jobs: Vec<(String, Vec<&str>)> = Vec::new();
    let mut in_jobs = false;
    for line in text.lines() {
        if line.starts_with("jobs:") {
            in_jobs = true;
            continue;
        }
        if in_jobs && !line.starts_with(' ') && !line.trim().is_empty() && !line.starts_with('#') {
            in_jobs = false;
        }
        if !in_jobs {
            continue;
        }
        if let Some(key) = line.strip_prefix("  ").and_then(|l| l.strip_suffix(':'))
            && !key.starts_with(' ')
            && !key.starts_with('#')
        {
            jobs.push((key.to_owned(), Vec::new()));
        } else if let Some((_, body)) = jobs.last_mut() {
            body.push(line);
        }
    }
    jobs
}

/// Job IDs declared in `.github/workflows/*.yml` (two-space-indented keys under `jobs:`).
fn workflow_jobs(root: &Path) -> Result<BTreeSet<String>, String> {
    let dir = root.join(".github").join("workflows");
    let mut jobs = BTreeSet::new();
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut in_jobs = false;
        for line in text.lines() {
            if line.starts_with("jobs:") {
                in_jobs = true;
                continue;
            }
            if in_jobs && !line.starts_with(' ') && !line.trim().is_empty() && !line.starts_with('#') {
                in_jobs = false;
            }
            if in_jobs
                && let Some(key) = line.strip_prefix("  ").and_then(|l| l.strip_suffix(':'))
                && !key.starts_with(' ')
                && !key.starts_with('#')
            {
                jobs.insert(key.to_owned());
            }
        }
    }
    Ok(jobs)
}
