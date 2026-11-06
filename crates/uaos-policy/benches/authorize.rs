// SPDX-License-Identifier: Apache-2.0

//! Decision latency (policy decision p99 ≤ 1 ms, excluding I/O).
//!
//! Run: `cargo bench -p uaos-policy --bench authorize`. Prints p50/p99/p99.9/max over 20,000
//! decisions after a warm-up, for three sets (the claim must name its mix):
//! * **mixed:** 1,000 permits, conditional forbids and ask-permits spread across actions, tools
//!   and providers;
//! * **one action:** 1,000 policies that all constrain `exec`, the worst case for per-action
//!   slicing;
//! * **grants:** 10,000 grants on `exec` plus the mixed set; grants are matched by index.
//!
//! Dependency-free on purpose (`harness = false`).

#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::disallowed_methods,
    reason = "benchmark binary: measures wall time and prints results"
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use uaos_contracts::id::{CredentialId, GrantId, PocketId, TypedId};
use uaos_contracts::operation::RiskTier;
use uaos_policy::{Action, Grant, Name, PolicyEngine, Principal, Request, Resource};

const POLICIES: usize = 1_000;
const DECISIONS: usize = 20_000;
const NOW: u64 = 1_760_000_000_000;

fn policies() -> String {
    let mut text = String::new();
    for i in 0..POLICIES {
        let _infallible = match i % 5 {
            0 => writeln!(
                text,
                "@id(\"p{i}\") permit(principal is Uaos::Agent, action == Uaos::Action::\"model.call\", resource in Uaos::Provider::\"prov{}\");",
                i % 50
            ),
            1 => writeln!(
                text,
                "@id(\"t{i}\") permit(principal is Uaos::Agent, action == Uaos::Action::\"tool.call\", resource == Uaos::Tool::\"tool{}\");",
                i % 300
            ),
            2 => writeln!(
                text,
                "@id(\"f{i}\") forbid(principal, action == Uaos::Action::\"model.call\", resource) when {{ context.data_classes.contains(\"class{}\") && context.risk_tier > 2 }};",
                i % 40
            ),
            3 => writeln!(
                text,
                "@id(\"a{i}\") @effect(\"ask\") permit(principal is Uaos::Agent, action == Uaos::Action::\"exec\", resource == Uaos::Tool::\"tool{}\");",
                i % 300
            ),
            _ => writeln!(
                text,
                "@id(\"g{i}\") forbid(principal, action, resource) when {{ context.pocket == \"blocked-{i}\" }};"
            ),
        };
    }
    text
}

fn request(i: usize) -> Request {
    let (action, resource) = match i % 3 {
        0 => (
            Action::ModelCall,
            Resource::Model {
                provider: Name::new(format!("prov{}", i % 50)).unwrap(),
                model: Name::new("m").unwrap(),
            },
        ),
        1 => (
            Action::ToolCall,
            Resource::Tool(Name::new(format!("tool{}", i % 300)).unwrap()),
        ),
        _ => (
            Action::Exec,
            Resource::Tool(Name::new(format!("tool{}", i % 300)).unwrap()),
        ),
    };
    let data_classes: BTreeSet<Name> = (0..3)
        .map(|k| Name::new(format!("class{}", (i + k) % 40)).unwrap())
        .collect();
    Request {
        principal: Principal::Agent(CredentialId::from_parts(1, [1; 10])),
        action,
        resource,
        pocket: PocketId::from_parts(1, [1; 10]),
        grant: None,
        risk_tier: RiskTier::new(u8::try_from(i % 4).unwrap()).unwrap(),
        data_classes,
        now_ms: NOW,
    }
}

fn percentile(sorted: &[Duration], per_mille: usize) -> Duration {
    let last = sorted.len().saturating_sub(1);
    sorted[((last * per_mille + 500) / 1000).min(last)]
}

/// 1,000 policies, all on `exec`: permits per tool, conditional forbids, asks.
fn one_action() -> String {
    let mut text = String::new();
    for i in 0..POLICIES {
        let _infallible = match i % 3 {
            0 => writeln!(
                text,
                "@id(\"x{i}\") permit(principal is Uaos::Agent, action == Uaos::Action::\"exec\", resource == Uaos::Tool::\"tool{}\");",
                i % 300
            ),
            1 => writeln!(
                text,
                "@id(\"y{i}\") forbid(principal, action == Uaos::Action::\"exec\", resource) when {{ context.data_classes.contains(\"class{}\") && context.risk_tier > 2 }};",
                i % 40
            ),
            _ => writeln!(
                text,
                "@id(\"z{i}\") @effect(\"ask\") permit(principal is Uaos::Agent, action == Uaos::Action::\"exec\", resource == Uaos::Tool::\"tool{}\");",
                i % 300
            ),
        };
    }
    text
}

/// 10,000 live grants on `exec`, one per agent and tool.
fn grants() -> Vec<Grant> {
    (0..10_000_u64)
        .map(|i| Grant {
            id: GrantId::from_parts(i + 1, [1; 10]),
            principal: Principal::Agent(CredentialId::from_parts(i % 100 + 1, [2; 10])),
            action: Action::Exec,
            resource: Resource::Tool(Name::new(format!("tool{}", i % 300)).unwrap()),
            pocket: PocketId::from_parts(1, [1; 10]),
            expires_at_ms: NOW + 3_600_000,
            max_risk_tier: RiskTier::new(3).unwrap(),
            data_classes: BTreeSet::new(),
            approves: BTreeSet::new(),
        })
        .collect()
}

fn measure(name: &str, policies: &str, grants: &[Grant], requests: &[Request]) {
    let load_start = Instant::now();
    let engine = PolicyEngine::load(policies, grants, NOW).unwrap();
    let load = load_start.elapsed();
    for r in requests.iter().take(2_000) {
        let _warm = engine.authorize(r);
    }
    let mut samples = Vec::with_capacity(requests.len());
    let mut effects = std::collections::BTreeMap::new();
    for r in requests {
        let t = Instant::now();
        let d = engine.authorize(r);
        samples.push(t.elapsed());
        *effects.entry(format!("{:?}", d.effect)).or_insert(0usize) += 1;
    }
    samples.sort();
    println!("{name}: loaded and validated in {load:.1?}");
    println!(
        "  authorize x{}: p50={:.1?} p99={:.1?} p99.9={:.1?} max={:.1?}  effects={effects:?}",
        requests.len(),
        percentile(&samples, 500),
        percentile(&samples, 990),
        percentile(&samples, 999),
        samples.last().copied().unwrap_or_default()
    );
}

fn main() {
    let mixed: Vec<Request> = (0..DECISIONS).map(request).collect();
    measure("mixed (1,000 policies)", &policies(), &[], &mixed);

    let exec: Vec<Request> = (0..DECISIONS).map(|i| request(i * 3 + 2)).collect();
    measure("one action (1,000 policies on exec)", &one_action(), &[], &exec);

    let granted: Vec<Request> = (0..DECISIONS)
        .map(|i| {
            let mut r = request(i * 3 + 2);
            r.principal = Principal::Agent(CredentialId::from_parts(u64::try_from(i % 100).unwrap() + 1, [2; 10]));
            r
        })
        .collect();
    measure("grants (10,000 on exec + mixed set)", &policies(), &grants(), &granted);
}
