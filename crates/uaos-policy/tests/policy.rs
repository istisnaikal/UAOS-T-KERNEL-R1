// SPDX-License-Identifier: Apache-2.0

//! The reference monitor's guarantees: default deny, fail closed, `Deny > Ask > Allow`, strict
//! loading, time-bounded grants, and per-action slicing that never changes a decision.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "the parser-depth tests run on a thread with a small, explicit stack (std::thread::Builder)"
)]

use std::collections::BTreeSet;

use proptest::prelude::*;
use uaos_contracts::event::ModuleName;
use uaos_contracts::grant::{DataClass, GrantName, InjectionPolicy, PolicyId};
use uaos_contracts::id::{ApprovalId, CredentialId, GrantId, PocketId, PoolId, TypedId};
use uaos_contracts::operation::RiskTier;
use uaos_contracts::time::WallTime;
use uaos_policy::{
    Action, Basis, CLOCK_TOLERANCE_MS, Effect, Grant, Name, PolicyEngine, PolicyError, Principal, Request, Resource,
    check_grant, grant_crosses_pockets, grant_record,
};

const NOW: u64 = 1_760_000_000_000;

fn agent(n: u8) -> Principal {
    Principal::Agent(CredentialId::from_parts(u64::from(n), [n; 10]))
}

fn pocket(n: u8) -> PocketId {
    PocketId::from_parts(u64::from(n), [n; 10])
}

fn model(provider: &str, model: &str) -> Resource {
    Resource::Model {
        provider: Name::new(provider).unwrap(),
        model: Name::new(model).unwrap(),
    }
}

fn request(principal: Principal, action: Action, resource: Resource) -> Request {
    Request {
        principal,
        action,
        resource,
        pocket: pocket(1),
        grant: None,
        risk_tier: RiskTier::new(1).unwrap(),
        data_classes: BTreeSet::new(),
        now_ms: NOW,
    }
}

fn engine(policies: &str) -> PolicyEngine {
    PolicyEngine::load(policies, &[], NOW).unwrap()
}

const ALLOW_ANTHROPIC: &str = r#"
@id("anthropic-for-agents")
permit(principal is Uaos::Agent, action == Uaos::Action::"model.call", resource in Uaos::Provider::"anthropic");
"#;

#[test]
fn nothing_is_allowed_by_default() {
    let d = engine("").authorize(&request(agent(1), Action::ModelCall, model("anthropic", "m")));
    assert_eq!((d.effect, d.basis), (Effect::Deny, Basis::NoMatchingPermit));
}

#[test]
fn a_permit_allows_and_explains_itself() {
    let d = engine(ALLOW_ANTHROPIC).authorize(&request(agent(1), Action::ModelCall, model("anthropic", "m")));
    assert_eq!((d.effect, d.basis), (Effect::Allow, Basis::Permitted));
    assert_eq!(d.policies, ["anthropic-for-agents"]);
    assert_eq!(d.explain(), "allowed by anthropic-for-agents");
    let other = engine(ALLOW_ANTHROPIC).authorize(&request(agent(1), Action::ModelCall, model("openai", "m")));
    assert_eq!(other.effect, Effect::Deny, "the provider hierarchy scopes the permit");
}

#[test]
fn forbid_wins_over_permit() {
    let policies = format!(
        "{ALLOW_ANTHROPIC}\n@id(\"no-aws-secrets\")\nforbid(principal, action == Uaos::Action::\"model.call\", resource) when {{ context.data_classes.contains(\"secret.aws\") }};"
    );
    let mut req = request(agent(1), Action::ModelCall, model("anthropic", "m"));
    req.data_classes.insert(Name::new("secret.aws").unwrap());
    let d = engine(&policies).authorize(&req);
    assert_eq!((d.effect, d.basis), (Effect::Deny, Basis::Forbidden));
    assert_eq!(d.policies, ["no-aws-secrets"]);
}

#[test]
fn ask_outranks_allow_and_deny_outranks_ask() {
    let ask = r#"
@id("exec-needs-approval") @effect("ask") @reason("exec is high risk")
permit(principal is Uaos::Agent, action == Uaos::Action::"exec", resource);
@id("exec-git-ok")
permit(principal is Uaos::Agent, action == Uaos::Action::"exec", resource == Uaos::Tool::"git");
"#;
    let git = request(agent(1), Action::Exec, Resource::Tool(Name::new("git").unwrap()));
    let d = engine(ask).authorize(&git);
    assert_eq!((d.effect, d.basis), (Effect::Ask, Basis::ApprovalRequired));
    assert_eq!(d.policies, ["exec-needs-approval"]);

    let with_forbid =
        format!("{ask}\n@id(\"no-exec\")\nforbid(principal, action == Uaos::Action::\"exec\", resource);");
    assert_eq!(engine(&with_forbid).authorize(&git).effect, Effect::Deny);
}

/// Cedar skips a policy whose evaluation errors. This forbid overflows at runtime, so plain
/// Cedar would answer Allow; UAOS must answer Deny.
#[test]
fn an_erroring_forbid_fails_closed() {
    let policies = format!(
        "{ALLOW_ANTHROPIC}\n@id(\"overflowing-forbid\")\nforbid(principal, action == Uaos::Action::\"model.call\", resource) when {{ context.risk_tier * 9223372036854775807 > 0 }};"
    );
    // Risk tier 2: 2 × i64::MAX overflows at evaluation time.
    let mut req = request(agent(1), Action::ModelCall, model("anthropic", "m"));
    req.risk_tier = RiskTier::new(2).unwrap();
    let d = engine(&policies).authorize(&req);
    assert_eq!((d.effect, d.basis), (Effect::Deny, Basis::EvaluationError));
    assert_eq!(d.errors.len(), 1);
    assert!(
        d.errors[0].starts_with("policy overflowing-forbid: "),
        "errors name the policy by @id: {:?}",
        d.errors
    );
    assert!(d.explain().starts_with("denied: evaluation failed"));
}

#[test]
fn loading_rules_are_strict() {
    let reject = |src: &str| PolicyEngine::load(src, &[], NOW).unwrap_err();
    assert!(
        matches!(reject("permit(principal, action, resource);"), PolicyError::Rule { .. }),
        "missing @id"
    );
    assert!(matches!(
        reject("@id(\"a\") permit(principal, action, resource);\n@id(\"a\") forbid(principal, action, resource);"),
        PolicyError::Rule { .. }
    ));
    assert!(matches!(
        reject("@id(\"a\") @efect(\"ask\") permit(principal, action, resource);"),
        PolicyError::Rule { .. }
    ));
    assert!(matches!(
        reject("@id(\"a\") @effect(\"ask\") forbid(principal, action, resource);"),
        PolicyError::Rule { .. }
    ));
    assert!(matches!(
        reject("@id(\"a\") @effect(\"allow\") permit(principal, action, resource);"),
        PolicyError::Rule { .. }
    ));
    assert!(matches!(
        reject("@id(\"grant:x\") permit(principal, action, resource);"),
        PolicyError::Rule { .. }
    ));
    assert!(matches!(
        reject("@id(\"a\") permit(principal, action, resource) when { context.no_such_field == 1 };"),
        PolicyError::Invalid(_)
    ));
    assert!(matches!(
        reject("@id(\"a\") permit(principal, action, resource"),
        PolicyError::Parse(_)
    ));
}

#[test]
fn grants_are_scoped_and_expire() {
    let grant = Grant {
        id: GrantId::from_parts(1, [1; 10]),
        principal: agent(1),
        action: Action::Exec,
        resource: Resource::Tool(Name::new("git").unwrap()),
        pocket: pocket(1),
        expires_at_ms: NOW + 60_000,
        max_risk_tier: RiskTier::new(1).unwrap(),
        data_classes: BTreeSet::new(),
        approves: BTreeSet::new(),
    };
    let e = PolicyEngine::load("", std::slice::from_ref(&grant), NOW).unwrap();
    let git = request(agent(1), Action::Exec, Resource::Tool(Name::new("git").unwrap()));
    let d = e.authorize(&git);
    assert_eq!((d.effect, d.basis), (Effect::Allow, Basis::Granted));
    assert_eq!(d.policies, [format!("grant:{}", grant.id)]);

    let mut later = git.clone();
    later.now_ms = NOW + 60_000;
    let at_expiry = PolicyEngine::load("", std::slice::from_ref(&grant), NOW).unwrap();
    let d = at_expiry.authorize(&later);
    assert_eq!(
        (d.effect, d.basis),
        (Effect::Deny, Basis::NoMatchingPermit),
        "inert at expiry even if never removed"
    );
    let mut elsewhere = git.clone();
    elsewhere.pocket = pocket(2);
    assert_eq!(e.authorize(&elsewhere).effect, Effect::Deny, "scoped to its pocket");
    let mut someone_else = git.clone();
    someone_else.principal = agent(2);
    assert_eq!(
        e.authorize(&someone_else).effect,
        Effect::Deny,
        "scoped to its principal"
    );
    let curl = request(agent(1), Action::Exec, Resource::Tool(Name::new("curl").unwrap()));
    assert_eq!(e.authorize(&curl).effect, Effect::Deny, "scoped to its resource");

    let expired = PolicyEngine::load("", &[grant], NOW + 60_000).unwrap();
    assert_eq!(
        expired.authorize(&git).effect,
        Effect::Deny,
        "already expired grants are not loaded"
    );
}

#[test]
fn names_cannot_inject_policy_text() {
    assert!(Name::new("git\" ) || true //").is_err());
    assert!(Name::new("").is_err());
    assert!(Name::new("a".repeat(129)).is_err());
    assert!(Name::new("anthropic/claude-sonnet-5.5:latest").is_ok());
}

// ── Properties ───────────────────────────────────────────────────────────────────────────

/// Building blocks for random policy sets: action-unconstrained, single-action and action-list
/// policies, some pinned to one resource (`resource == …`), with and without conditions.
fn policy_piece(i: usize, kind: u8, action: u8, flag: u8) -> String {
    let actions = ["model.call", "exec", "tool.call", "budget.transfer"];
    let a = actions[usize::from(action) % actions.len()];
    let action_clause = match flag % 3 {
        0 => format!("action == Uaos::Action::\"{a}\""),
        1 => "action".to_owned(),
        _ => format!("action in [Uaos::Action::\"{a}\", Uaos::Action::\"model.call\"]"),
    };
    // Pin a resource only where the schema allows it: a single action of that resource's type.
    let resource = match (flag % 3, a, (kind / 4) % 3) {
        (0, "exec" | "tool.call", 1) => "resource == Uaos::Tool::\"git\"",
        (0, "exec" | "tool.call", 2) => "resource == Uaos::Tool::\"fs\"",
        (0, "model.call", 1 | 2) => "resource == Uaos::Model::\"anthropic/m\"",
        _ => "resource",
    };
    let cond = if flag.is_multiple_of(2) {
        ""
    } else {
        " when { context.risk_tier > 1 }"
    };
    match kind % 4 {
        0 => format!("@id(\"p{i}\") permit(principal, {action_clause}, {resource}){cond};"),
        1 => format!("@id(\"f{i}\") forbid(principal, {action_clause}, {resource}){cond};"),
        2 => format!("@id(\"a{i}\") @effect(\"ask\") permit(principal, {action_clause}, {resource}){cond};"),
        _ => format!(
            "@id(\"e{i}\") forbid(principal, {action_clause}, {resource}) when {{ context.risk_tier * 9223372036854775807 > 0 }};"
        ),
    }
}

fn random_request(action: u8, tier: u8) -> Request {
    let (action, resource) = match action % 7 {
        0 => (Action::ModelCall, model("anthropic", "m")),
        1 => (Action::Exec, Resource::Tool(Name::new("git").unwrap())),
        2 => (Action::ToolCall, Resource::Tool(Name::new("fs").unwrap())),
        3 => (Action::Exec, Resource::Tool(Name::new("curl").unwrap())),
        4 => (Action::ModelCall, model("openai", "m")),
        5 => (Action::ToolCall, Resource::Tool(Name::new("git").unwrap())),
        _ => (
            Action::BudgetTransfer,
            Resource::Pool(uaos_contracts::id::PoolId::from_parts(1, [1; 10])),
        ),
    };
    let mut r = request(agent(1), action, resource);
    r.risk_tier = RiskTier::new(tier % 4).unwrap();
    r
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Slicing by action never changes any decision.
    #[test]
    fn slicing_preserves_decisions(
        pieces in prop::collection::vec((any::<u8>(), any::<u8>(), any::<u8>()), 0..12),
        grants in prop::collection::vec((any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>()), 0..3),
        req in (any::<u8>(), any::<u8>()),
    ) {
        let text: Vec<String> = pieces.iter().enumerate().map(|(i, (k, a, f))| policy_piece(i, *k, *a, *f)).collect();
        // One grant per id: the engine refuses an id twice.
        let mut seen = BTreeSet::new();
        let grants: Vec<Grant> = grants.into_iter().map(random_grant).filter(|g| seen.insert(g.id)).collect();
        let e = PolicyEngine::load(&text.join("\n"), &grants, NOW).unwrap();
        let r = random_request(req.0, req.1);
        prop_assert_eq!(e.authorize(&r), e.authorize_unsliced(&r));
    }
}

/// The slicing oracle was built from the slices, so a policy dropped by slicing vanished from both
/// sides. These forbids must reach every action they constrain.
#[test]
fn an_unconstrained_forbid_applies_to_every_action() {
    let policies = r#"
@id("all-agents") permit(principal is Uaos::Agent, action, resource);
@id("lockdown") forbid(principal, action, resource) when { context.risk_tier > 2 };
"#;
    let e = engine(policies);
    for (action, resource) in [
        (Action::ModelCall, model("anthropic", "m")),
        (Action::Exec, Resource::Tool(Name::new("git").unwrap())),
        (Action::ToolCall, Resource::Tool(Name::new("fs").unwrap())),
        (Action::ConfigChange, Resource::ConfigKey(Name::new("k").unwrap())),
    ] {
        let mut r = request(agent(1), action, resource);
        r.risk_tier = RiskTier::new(3).unwrap();
        let d = e.authorize(&r);
        assert_eq!(
            (d.effect, d.basis),
            (Effect::Deny, Basis::Forbidden),
            "unconstrained forbid skipped for {action:?}"
        );
    }
}

#[test]
fn an_action_list_forbid_applies_to_each_listed_action() {
    let policies = r#"
@id("all-agents") permit(principal is Uaos::Agent, action, resource);
@id("no-tools") forbid(principal, action in [Uaos::Action::"exec", Uaos::Action::"tool.call"], resource);
"#;
    let e = engine(policies);
    for action in [Action::Exec, Action::ToolCall] {
        let d = e.authorize(&request(agent(1), action, Resource::Tool(Name::new("git").unwrap())));
        assert_eq!(d.effect, Effect::Deny, "action-list forbid skipped for {action:?}");
    }
    let model_call = e.authorize(&request(agent(1), Action::ModelCall, model("anthropic", "m")));
    assert_eq!(model_call.effect, Effect::Allow);
}

/// The grant an approval of `exec git` at risk tier 1 would issue, for 60 s from `NOW`.
fn exec_grant(expires_at_ms: u64) -> Grant {
    Grant {
        id: GrantId::from_parts(7, [7; 10]),
        principal: agent(1),
        action: Action::Exec,
        resource: Resource::Tool(Name::new("git").unwrap()),
        pocket: pocket(1),
        expires_at_ms,
        max_risk_tier: RiskTier::new(1).unwrap(),
        data_classes: BTreeSet::new(),
        approves: BTreeSet::from(["exec-needs-approval".to_owned()]),
    }
}

/// A grant compiled to a plain permit, and the ask check fired on any matching ask policy, so the
/// approval flow ("retry after approval succeeds via the new grant") could never work. A grant is
/// the approval: it satisfies the ask; a forbid still wins.
#[test]
fn a_grant_satisfies_an_ask_but_never_a_forbid() {
    let ask = r#"
@id("exec-needs-approval") @effect("ask") @reason("exec is high risk")
permit(principal is Uaos::Agent, action == Uaos::Action::"exec", resource);
"#;
    let git = request(agent(1), Action::Exec, Resource::Tool(Name::new("git").unwrap()));
    let before = engine(ask).authorize(&git);
    assert_eq!((before.effect, before.basis), (Effect::Ask, Basis::ApprovalRequired));
    assert_eq!(before.reasons, ["exec-needs-approval: exec is high risk"]);

    let grant = exec_grant(NOW + 60_000);
    let approved = PolicyEngine::load(ask, std::slice::from_ref(&grant), NOW).unwrap();
    let d = approved.authorize(&git);
    assert_eq!((d.effect, d.basis), (Effect::Allow, Basis::Granted));
    assert_eq!(
        d.policies,
        [format!("grant:{}", grant.id), "exec-needs-approval".to_owned()]
    );
    assert!(d.explain().contains("the grant is the approval"));

    let curl = request(agent(1), Action::Exec, Resource::Tool(Name::new("curl").unwrap()));
    assert_eq!(
        approved.authorize(&curl).effect,
        Effect::Ask,
        "the grant approves only its own resource"
    );

    let with_forbid = format!("{ask}\n@id(\"no-exec\") forbid(principal, action == Uaos::Action::\"exec\", resource);");
    let forbidden = PolicyEngine::load(&with_forbid, std::slice::from_ref(&grant), NOW).unwrap();
    let d = forbidden.authorize(&git);
    assert_eq!(
        (d.effect, d.basis),
        (Effect::Deny, Basis::Forbidden),
        "a grant must never override a forbid"
    );
    assert_eq!(d.policies, ["no-exec"]);
}

/// About 80 nested parentheses overflowed Cedar's parser and aborted the process. The text is now
/// refused before Cedar sees it. Run on a 1 MiB stack, so a regression aborts the test binary
/// instead of passing quietly.
#[test]
fn deeply_nested_policy_text_is_refused_not_a_crash() {
    let shapes = [
        format!(
            "@id(\"deep\") permit(principal, action, resource) when {{ {}true{} }};",
            "(".repeat(80),
            ")".repeat(80)
        ),
        format!(
            "@id(\"sets\") permit(principal, action, resource) when {{ {}1{}.contains(1) }};",
            "[".repeat(80),
            "]".repeat(80)
        ),
        format!(
            "@id(\"ifs\") permit(principal, action, resource) when {{ {}true{} }};",
            "if true then ".repeat(300),
            " else false".repeat(300)
        ),
        format!(
            "@id(\"chain\") permit(principal, action, resource) when {{ {} }};",
            vec!["true"; 5_000].join(" && ")
        ),
        format!(
            "@id(\"long\") permit(principal, action, resource) when {{ context.pocket == \"{}\" }};",
            "x".repeat(20_000)
        ),
    ];
    let outcome = std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            shapes
                .iter()
                .map(|text| matches!(PolicyEngine::load(text, &[], NOW), Err(PolicyError::Rule { .. })))
                .collect::<Vec<bool>>()
        })
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(outcome, [true; 5], "every over-deep shape is refused by rule");
}

/// A policy at the nesting and `if` bounds with `operators` operators, evaluated on a thread
/// with `stack` bytes of stack.
fn at_bounds(stack: usize, operators: usize) -> Effect {
    let mut ifs = "true".to_owned();
    for _ in 0..16 {
        ifs = format!("if context.risk_tier > 1 then {ifs} else false");
    }
    let chain = vec!["context.risk_tier > 1"; operators / 3].join(" && ");
    let text = format!(
        "@id(\"bounded\") permit(principal, action == Uaos::Action::\"exec\", resource) when {{ {}{ifs}{} && {chain} }};",
        "(".repeat(7),
        ")".repeat(7)
    );
    std::thread::Builder::new()
        .stack_size(stack)
        .spawn(move || {
            let e = PolicyEngine::load(&text, &[], NOW).unwrap();
            let mut r = request(agent(1), Action::Exec, Resource::Tool(Name::new("git").unwrap()));
            r.risk_tier = RiskTier::new(2).unwrap();
            let d = e.authorize(&r);
            assert!(
                d.effect == Effect::Allow || d.basis == Basis::EvaluationError,
                "only Allow or a fail-closed Deny: {}",
                d.explain()
            );
            d.effect
        })
        .unwrap()
        .join()
        .unwrap()
}

/// Every bound at once never crashes, even on a 1 MiB stack in a debug build: the parser is
/// protected by the bounds, and Cedar's evaluator and typechecker refuse to recurse with less
/// than 100 KiB of stack left, so the worst case is a fail-closed Deny.
#[test]
fn a_policy_at_every_bound_never_crashes() {
    at_bounds(1 << 20, 213);
}

/// The bounds leave room for real policies: one at every bound evaluates normally. Measured: a
/// release build needs 1 MiB of stack for it, a debug build 8 MiB (its frames are far larger).
#[test]
fn a_policy_at_every_bound_evaluates() {
    assert_eq!(at_bounds(8 << 20, 213), Effect::Allow);
}

/// An `@id` could pose as an explanation; explanations were ordered by position.
#[test]
fn ids_are_plain_and_explanations_are_sorted_by_id() {
    for bad in ["x, grant:forged", "has space", "a/b", ""] {
        let text = format!("@id(\"{bad}\") permit(principal, action, resource);");
        assert!(
            matches!(PolicyEngine::load(&text, &[], NOW), Err(PolicyError::Rule { .. })),
            "{bad:?}"
        );
    }
    let policies = r#"
@id("zeta") permit(principal is Uaos::Agent, action == Uaos::Action::"exec", resource);
@id("alpha") permit(principal is Uaos::Agent, action == Uaos::Action::"exec", resource);
"#;
    let d = engine(policies).authorize(&request(
        agent(1),
        Action::Exec,
        Resource::Tool(Name::new("git").unwrap()),
    ));
    assert_eq!(d.policies, ["alpha", "zeta"]);
}

/// `provider/model` was not injective while providers could contain `/`.
#[test]
fn a_provider_name_with_a_slash_fails_closed() {
    let e = engine(ALLOW_ANTHROPIC);
    let d = e.authorize(&request(agent(1), Action::ModelCall, model("anthropic/x", "m")));
    assert_eq!((d.effect, d.basis), (Effect::Deny, Basis::EvaluationError));
}

/// Templates were dropped from the set without passing the loading rules.
#[test]
fn templates_are_refused() {
    let template = "@id(\"t\") permit(principal == ?principal, action, resource);";
    assert!(matches!(
        PolicyEngine::load(template, &[], NOW),
        Err(PolicyError::Rule { .. })
    ));
}

/// A request clock that runs backwards could revive an expired grant.
#[test]
fn a_clock_running_backwards_is_refused() {
    let e = PolicyEngine::load("", &[exec_grant(NOW + 60_000)], NOW).unwrap();
    let mut late = request(agent(1), Action::Exec, Resource::Tool(Name::new("git").unwrap()));
    late.now_ms = NOW + 120_000;
    assert_eq!(e.authorize(&late).effect, Effect::Deny, "expired by then");
    let mut early = late.clone();
    early.now_ms = NOW + 30_000;
    let d = e.authorize(&early);
    assert_eq!(
        (d.effect, d.basis),
        (Effect::Deny, Basis::EvaluationError),
        "the clock went back 90 s"
    );
    let mut jitter = late.clone();
    jitter.now_ms = late.now_ms - CLOCK_TOLERANCE_MS;
    assert_ne!(e.authorize(&jitter).basis, Basis::EvaluationError, "within tolerance");
}

/// Principals, actions with their resources, and data classes the grant properties draw from.
fn any_principal(n: u8) -> Principal {
    match n % 4 {
        0 | 1 => agent(n % 2),
        2 => Principal::Module(uaos_contracts::event::ModuleName::new("mod-x").unwrap()),
        _ => Principal::Human,
    }
}

fn any_target(n: u8) -> (Action, Resource) {
    match n % 6 {
        0 => (Action::Exec, Resource::Tool(Name::new("git").unwrap())),
        1 => (Action::Exec, Resource::Tool(Name::new("curl").unwrap())),
        2 => (Action::ToolCall, Resource::Tool(Name::new("git").unwrap())),
        3 => (Action::ConfigChange, Resource::ConfigKey(Name::new("git").unwrap())),
        // Pockets 0 and 1, like the requests' pockets: some reads cross, some stay home.
        4 => (Action::MemoryRead, Resource::Pocket(pocket((n / 6) % 2))),
        _ => (Action::ModelCall, model("anthropic", "m")),
    }
}

fn any_classes(n: u8) -> BTreeSet<Name> {
    ["secret.aws", "pii.email"]
        .iter()
        .enumerate()
        .filter(|(i, _)| n & (1 << i) != 0)
        .map(|(_, c)| Name::new(*c).unwrap())
        .collect()
}

fn random_grant(seed: (u8, u8, u8, u8, u8)) -> Grant {
    let (who, target, place, life, scope) = seed;
    let (action, resource) = any_target(target);
    Grant {
        id: GrantId::from_parts(u64::from(who) + 1, [who; 10]),
        principal: any_principal(who),
        action,
        resource,
        pocket: pocket(place % 2),
        expires_at_ms: NOW + u64::from(life % 3) * 30_000,
        max_risk_tier: RiskTier::new(scope % 4).unwrap(),
        data_classes: any_classes(scope >> 2),
        approves: BTreeSet::new(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// `evaluation_errors_never_allow` passed with the fail-closed branch removed. Here a permit
    /// and an erroring forbid always both apply, so plain Cedar would answer Allow; UAOS must
    /// answer Deny.
    #[test]
    fn an_applicable_erroring_policy_always_denies(
        pieces in prop::collection::vec((any::<u8>(), any::<u8>(), any::<u8>()), 0..8),
        action in any::<u8>(),
        tier in 2_u8..4,
    ) {
        let r = random_request(action, tier);
        let id = r.action.cedar_id();
        let mut text: Vec<String> = pieces.iter().enumerate().map(|(i, (k, a, f))| policy_piece(i, *k, *a, *f)).collect();
        text.push(format!("@id(\"permit-all\") permit(principal, action == Uaos::Action::\"{id}\", resource);"));
        text.push(format!(
            "@id(\"erroring\") forbid(principal, action == Uaos::Action::\"{id}\", resource) when {{ context.risk_tier * 9223372036854775807 > 0 }};"
        ));
        let e = PolicyEngine::load(&text.join("\n"), &[], NOW).unwrap();
        let d = e.authorize(&r);
        prop_assert_eq!((d.effect, d.basis), (Effect::Deny, Basis::EvaluationError), "an erroring policy failed open");
    }

    /// Grants are matched natively; with any policy set that has no ask policies, the result equals
    /// compiling each grant to its permit. Principals, actions, resources, pockets, expiry, risk
    /// tiers and data classes all vary. A cross-pocket `memory.read` is the one place the two
    /// differ, by design: a permit is never consent, so where a native grant allows, its compiled
    /// permit only asks. There the property checks that both deny alike, and that nothing but a
    /// grant allows.
    #[test]
    fn native_grants_equal_their_permits(
        grants in prop::collection::vec((any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>()), 0..5),
        pieces in prop::collection::vec((any::<u8>(), any::<u8>(), any::<u8>()), 0..6),
        req in (any::<u8>(), any::<u8>(), any::<u8>(), 0_u64..90_000, any::<u8>()),
    ) {
        // Policy pieces without asks: kinds 0 (permit), 1 (forbid), 3 (erroring forbid).
        let policies: Vec<String> = pieces
            .iter()
            .enumerate()
            .map(|(i, (k, a, f))| policy_piece(i, if k % 4 == 2 { 0 } else { *k }, *a, *f))
            .collect();
        // One grant per id: the engine refuses an id twice.
        let mut seen = BTreeSet::new();
        let grants: Vec<Grant> = grants.into_iter().map(random_grant).filter(|g| seen.insert(g.id)).collect();
        let native = PolicyEngine::load(&policies.join("\n"), &grants, NOW).unwrap();
        let mut texts = policies.clone();
        texts.extend(
            grants
                .iter()
                .filter(|g| g.expires_at_ms > NOW)
                .enumerate()
                .map(|(i, g)| g.equivalent_permit(&format!("g{i}")).unwrap()),
        );
        let compiled = PolicyEngine::load(&texts.join("\n"), &[], NOW).unwrap();
        let (action, resource) = any_target(req.1);
        let mut r = request(any_principal(req.0), action, resource);
        r.pocket = pocket(req.2 % 2);
        r.now_ms = NOW + req.3;
        r.risk_tier = RiskTier::new(req.4 % 4).unwrap();
        r.data_classes = any_classes(req.4 >> 2);
        let (n, c) = (native.authorize(&r), compiled.authorize(&r));
        if r.crosses_pockets() {
            // The request names no grant, so neither form may allow; where the compiled form
            // denies, nothing native allows either (the named-grant property covers the rest).
            prop_assert!(n.effect != Effect::Allow, "a cross-pocket read naming no grant was allowed");
            prop_assert!(c.effect != Effect::Allow, "a permit allowed a cross-pocket read");
            prop_assert!(c.effect != Effect::Deny || n.effect == Effect::Deny);
        } else {
            prop_assert_eq!(n.effect, c.effect);
        }
    }

    /// Distinct principals and resources never share a Cedar identity, so neither grants nor
    /// pinned policies can match the wrong thing (the grant property above relies on it).
    #[test]
    fn entity_ids_are_injective(a in any::<u8>(), b in any::<u8>(), x in "[a-z]{1,3}(/[a-z]{1,3})?", y in "[a-z]{1,3}(/[a-z]{1,3})?") {
        let resource = |n: u8, name: &str| match n % 4 {
            0 => Resource::Tool(Name::new(name).unwrap()),
            1 => Resource::ConfigKey(Name::new(name).unwrap()),
            2 => model("p", name),
            _ => Resource::Pool(uaos_contracts::id::PoolId::from_parts(u64::from(n), [n; 10])),
        };
        let (ra, rb) = (resource(a, &x), resource(b, &y));
        let g = |r: &Resource| {
            let mut grant = exec_grant(NOW + 1);
            grant.resource = r.clone();
            grant.equivalent_permit("g").unwrap()
        };
        prop_assert_eq!(ra == rb, g(&ra) == g(&rb));
    }
}

/// A grant covers the request its approval saw, nothing riskier.
#[test]
fn a_grant_covers_no_riskier_request() {
    let ask = r#"
@id("exec-needs-approval") @effect("ask") permit(principal is Uaos::Agent, action == Uaos::Action::"exec", resource);
@id("prod-needs-approval") @effect("ask") permit(principal is Uaos::Agent, action == Uaos::Action::"exec", resource) when { context.risk_tier > 2 };
"#;
    let e = PolicyEngine::load(ask, &[exec_grant(NOW + 60_000)], NOW).unwrap();
    let git = request(agent(1), Action::Exec, Resource::Tool(Name::new("git").unwrap()));
    assert_eq!(e.authorize(&git).basis, Basis::Granted, "the approved shape");

    let mut riskier = git.clone();
    riskier.risk_tier = RiskTier::new(3).unwrap();
    let d = e.authorize(&riskier);
    assert_eq!(
        (d.effect, d.basis),
        (Effect::Ask, Basis::ApprovalRequired),
        "a higher tier is not covered"
    );

    let mut secret = git.clone();
    secret.data_classes.insert(Name::new("secret.aws").unwrap());
    assert_eq!(
        e.authorize(&secret).effect,
        Effect::Ask,
        "a new data class is not covered"
    );

    // The tier 3 request also fires an ask the approval never named.
    let mut wider = exec_grant(NOW + 60_000);
    wider.max_risk_tier = RiskTier::new(3).unwrap();
    let e = PolicyEngine::load(ask, &[wider], NOW).unwrap();
    let d = e.authorize(&riskier);
    assert_eq!(d.effect, Effect::Ask, "an ask the grant does not list stays an ask");
    assert_eq!(d.policies, ["exec-needs-approval", "prod-needs-approval"]);
}

/// A request refused as malformed must not move the clock mark.
#[test]
fn a_malformed_request_does_not_move_the_clock() {
    let e = PolicyEngine::load(ALLOW_ANTHROPIC, &[], NOW).unwrap();
    let mut bogus = request(agent(1), Action::ModelCall, model("anthropic", "m"));
    bogus.now_ms = u64::MAX;
    assert_eq!(e.authorize(&bogus).basis, Basis::EvaluationError);
    let fine = request(agent(1), Action::ModelCall, model("anthropic", "m"));
    assert_eq!(e.authorize(&fine).effect, Effect::Allow);
}

/// The clock tolerance never extends a grant; expiry is judged at the latest clock seen.
#[test]
fn a_grant_expires_at_the_latest_clock_seen() {
    let e = PolicyEngine::load("", &[exec_grant(NOW + 60_000)], NOW).unwrap();
    let mut after = request(agent(1), Action::Exec, Resource::Tool(Name::new("git").unwrap()));
    after.now_ms = NOW + 60_001;
    assert_eq!(e.authorize(&after).effect, Effect::Deny);
    let mut just_before = after.clone();
    just_before.now_ms = NOW + 59_000;
    assert_eq!(
        e.authorize(&just_before).effect,
        Effect::Deny,
        "within the tolerance, but the latest clock is past expiry"
    );
}

/// Slicing follows action groups from the schema in use.
#[test]
fn action_groups_reach_their_members() {
    let schema = include_str!("../src/uaos.cedarschema").replace(
        "  action \"tool.call\", \"exec\" appliesTo {",
        "  action \"dangerous\";\n  action \"tool.call\", \"exec\" in [\"dangerous\"] appliesTo {",
    );
    let policies = r#"
@id("all") permit(principal, action, resource);
@id("no-dangerous") forbid(principal, action in [Uaos::Action::"dangerous"], resource);
"#;
    let e = PolicyEngine::load_with_schema(&schema, policies, &[], NOW).unwrap();
    for action in [Action::Exec, Action::ToolCall] {
        let r = request(agent(1), action, Resource::Tool(Name::new("git").unwrap()));
        let d = e.authorize(&r);
        assert_eq!((d.effect, d.basis), (Effect::Deny, Basis::Forbidden), "{action:?}");
        assert_eq!(d, e.authorize_unsliced(&r));
    }
    let model_call = e.authorize(&request(agent(1), Action::ModelCall, model("anthropic", "m")));
    assert_eq!(model_call.effect, Effect::Allow, "not in the group");
}

/// Shapes the first bounds missed (index chains, a comment ended by a lone CR) are refused or
/// handled, and nothing within the bounds crashes on a 1 MiB stack.
#[test]
fn no_shape_within_or_beyond_the_bounds_crashes() {
    let wrap = |body: String| format!("@id(\"s\") permit(principal, action, resource) when {{ {body} }};");
    let shapes = [
        // Beyond: must be refused by rule.
        (wrap(format!("context{} == 1", "[\"a\"]".repeat(3_000))), true),
        (
            format!(
                "// note\r@id(\"cr\") permit(principal, action, resource) when {{ {}true{} }};",
                "(".repeat(80),
                ")".repeat(80)
            ),
            true,
        ),
        // Within: may fail validation or evaluation, but must not crash.
        (wrap(format!("context{} == 1", "[\"a\"]".repeat(250))), false),
        (wrap(format!("context{} == 1", ".a".repeat(250))), false),
        (wrap(format!("{}true", "!".repeat(250))), false),
        (wrap(format!("{}1{} == 1", "-".repeat(250), "")), false),
        (wrap(format!("{}1{}.contains(1)", "[".repeat(7), "]".repeat(7))), false),
    ];
    let outcome = std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            shapes
                .iter()
                .map(|(text, refused)| {
                    let loaded = PolicyEngine::load(text, &[], NOW);
                    if let Ok(e) = &loaded {
                        let _decided = e.authorize(&request(
                            agent(1),
                            Action::Exec,
                            Resource::Tool(Name::new("git").unwrap()),
                        ));
                    }
                    !*refused || matches!(loaded, Err(PolicyError::Rule { .. }))
                })
                .collect::<Vec<bool>>()
        })
        .unwrap()
        .join()
        .unwrap();
    assert!(outcome.iter().all(|ok| *ok), "{outcome:?}");
}

/// Cross-project memory: reading another pocket is denied unless a grant names the reader, the
/// source pocket and the reading pocket, while it lives, and a forbid still wins over the grant.
#[test]
fn cross_pocket_memory_reads_need_a_grant() {
    let notes = Principal::Module(ModuleName::new("mod-notes").unwrap());
    let read = |source: u8, reader: u8| Request {
        pocket: pocket(reader),
        grant: Some(GrantId::from_parts(1, [7; 10])),
        ..request(notes.clone(), Action::MemoryRead, Resource::Pocket(pocket(source)))
    };
    let none = PolicyEngine::load("", &[], NOW).unwrap();
    assert_eq!(
        none.authorize(&read(1, 2)).effect,
        Effect::Deny,
        "allowed without a grant"
    );

    let grant = Grant {
        id: GrantId::from_parts(1, [7; 10]),
        principal: notes.clone(),
        action: Action::MemoryRead,
        resource: Resource::Pocket(pocket(1)),
        pocket: pocket(2),
        expires_at_ms: NOW + 60_000,
        max_risk_tier: RiskTier::new(1).unwrap(),
        data_classes: BTreeSet::new(),
        approves: BTreeSet::new(),
    };
    let e = PolicyEngine::load("", std::slice::from_ref(&grant), NOW).unwrap();
    let d = e.authorize(&read(1, 2));
    assert_eq!((d.effect, d.basis), (Effect::Allow, Basis::Granted));
    assert_eq!(
        e.authorize(&read(3, 2)).effect,
        Effect::Deny,
        "a grant for one source pocket read another"
    );
    assert_eq!(
        e.authorize(&read(1, 4)).effect,
        Effect::Deny,
        "a grant for one reading pocket read from another"
    );
    let mut someone_else = read(1, 2);
    someone_else.principal = agent(1);
    assert_eq!(e.authorize(&someone_else).effect, Effect::Deny, "scoped to its holder");
    let mut later = read(1, 2);
    later.now_ms = NOW + 60_000;
    assert_eq!(e.authorize(&later).effect, Effect::Deny, "inert at expiry");

    let forbidden = PolicyEngine::load(
        r#"@id("no-memory") forbid(principal, action == Uaos::Action::"memory.read", resource);"#,
        std::slice::from_ref(&grant),
        NOW,
    )
    .unwrap();
    assert_eq!(
        forbidden.authorize(&read(1, 2)).effect,
        Effect::Deny,
        "a grant beat a forbid"
    );
}

#[test]
fn a_permit_alone_only_asks_for_a_cross_pocket_read() {
    let notes = Principal::Module(ModuleName::new("mod-notes").unwrap());
    let read = |source: u8, reader: u8| Request {
        pocket: pocket(reader),
        ..request(notes.clone(), Action::MemoryRead, Resource::Pocket(pocket(source)))
    };
    let named = format!(
        r#"@id("notes-read") permit(principal == Uaos::Module::"mod-notes", action == Uaos::Action::"memory.read", resource == Uaos::Pocket::"{}");"#,
        pocket(1)
    );
    let blanket = r#"@id("notes-all") permit(principal == Uaos::Module::"mod-notes", action, resource);"#;
    for text in [named.as_str(), blanket] {
        let e = PolicyEngine::load(text, &[], NOW).unwrap();
        let d = e.authorize(&read(1, 2));
        assert_eq!(
            (d.effect, d.basis),
            (Effect::Ask, Basis::ApprovalRequired),
            "a permit allowed a cross-pocket read without consent: {text}"
        );
    }
    let named_only = PolicyEngine::load(&named, &[], NOW).unwrap();
    assert_eq!(
        named_only.authorize(&read(3, 2)).effect,
        Effect::Deny,
        "the permit names another pocket"
    );
    // Reading the requesting pocket itself crosses nothing: no consent loop, ordinary policy.
    let own = PolicyEngine::load(blanket, &[], NOW).unwrap().authorize(&read(1, 1));
    assert_eq!(
        (own.effect, own.basis),
        (Effect::Allow, Basis::Permitted),
        "a read of the own pocket asked for consent"
    );
    let none = PolicyEngine::load("", &[], NOW).unwrap();
    assert_eq!(
        none.authorize(&read(1, 1)).effect,
        Effect::Deny,
        "default deny still holds"
    );

    let grant = Grant {
        id: GrantId::from_parts(1, [7; 10]),
        principal: notes.clone(),
        action: Action::MemoryRead,
        resource: Resource::Pocket(pocket(1)),
        pocket: pocket(2),
        expires_at_ms: NOW + 60_000,
        max_risk_tier: RiskTier::new(1).unwrap(),
        data_classes: BTreeSet::new(),
        approves: BTreeSet::new(),
    };
    let consented = PolicyEngine::load(blanket, std::slice::from_ref(&grant), NOW).unwrap();
    let mut carrying = read(1, 2);
    carrying.grant = Some(grant.id);
    let d = consented.authorize(&carrying);
    assert_eq!(
        (d.effect, d.basis),
        (Effect::Allow, Basis::Granted),
        "the grant is the consent"
    );
}

fn memory_grant(n: u8, expires_at_ms: u64) -> Grant {
    Grant {
        id: GrantId::from_parts(u64::from(n) + 1, [n; 10]),
        principal: Principal::Module(ModuleName::new("mod-notes").unwrap()),
        action: Action::MemoryRead,
        resource: Resource::Pocket(pocket(1)),
        pocket: pocket(2),
        expires_at_ms,
        max_risk_tier: RiskTier::new(3).unwrap(),
        data_classes: BTreeSet::new(),
        approves: BTreeSet::new(),
    }
}

/// `mod-notes` in pocket 2 reads pocket 1, carrying `grant`.
fn reading_with(grant: Option<GrantId>) -> Request {
    Request {
        pocket: pocket(2),
        grant,
        ..request(
            Principal::Module(ModuleName::new("mod-notes").unwrap()),
            Action::MemoryRead,
            Resource::Pocket(pocket(1)),
        )
    }
}

/// Two live grants for the same read, as after a renewal. The one the request carries decides, and
/// the decision cites it.
#[test]
fn only_the_carried_grant_allows_a_cross_pocket_read() {
    let (first, second) = (memory_grant(1, NOW + 60_000), memory_grant(2, NOW + 120_000));
    let e = PolicyEngine::load("", &[first.clone(), second.clone()], NOW).unwrap();
    for carried in [&first, &second] {
        let d = e.authorize(&reading_with(Some(carried.id)));
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(
            d.policies,
            vec![format!("grant:{}", carried.id)],
            "the decision cited a grant the request did not carry"
        );
    }
    assert_eq!(
        e.authorize(&reading_with(None)).effect,
        Effect::Deny,
        "a cross-pocket read naming no grant was allowed"
    );
    let unknown = GrantId::from_parts(99, [9; 10]);
    assert_eq!(e.authorize(&reading_with(Some(unknown))).effect, Effect::Deny);
    let asking = PolicyEngine::load(
        r#"@id("notes-all") permit(principal, action, resource);"#,
        std::slice::from_ref(&first),
        NOW,
    )
    .unwrap();
    assert_eq!(
        asking.authorize(&reading_with(None)).effect,
        Effect::Ask,
        "a permit only asks"
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Over random grants, permits and named grants, a cross-pocket read is allowed exactly when
    /// the grant it names is live and covers it.
    #[test]
    fn a_cross_pocket_read_is_allowed_only_by_the_grant_it_names(
        lives in prop::collection::vec((0_u64..3, 0_u8..4, any::<u8>()), 0..4),
        named in prop::option::of(0_usize..5),
        permitted in any::<bool>(),
        req in (0_u64..90_000, 0_u8..4, any::<u8>()),
    ) {
        let grants: Vec<Grant> = lives
            .iter()
            .enumerate()
            .map(|(i, (life, tier, classes))| Grant {
                expires_at_ms: NOW + life * 30_000,
                max_risk_tier: RiskTier::new(*tier).unwrap(),
                data_classes: any_classes(*classes),
                ..memory_grant(u8::try_from(i).unwrap(), 0)
            })
            .collect();
        let policies = if permitted { r#"@id("notes-all") permit(principal, action, resource);"# } else { "" };
        let e = PolicyEngine::load(policies, &grants, NOW).unwrap();
        let named_id = named.map(|k| grants.get(k).map_or(GrantId::from_parts(99, [9; 10]), |g| g.id));
        let mut r = reading_with(named_id);
        r.now_ms = NOW + req.0;
        r.risk_tier = RiskTier::new(req.1).unwrap();
        r.data_classes = any_classes(req.2);
        let covering = named.and_then(|k| grants.get(k)).is_some_and(|g| {
            r.now_ms < g.expires_at_ms
                && r.risk_tier.get() <= g.max_risk_tier.get()
                && r.data_classes.is_subset(&g.data_classes)
        });
        let expected = if covering { Effect::Allow } else if permitted { Effect::Ask } else { Effect::Deny };
        prop_assert_eq!(e.authorize(&r).effect, expected, "the named grant did not decide the read");
    }

    /// The engine loads exactly the grants the wire can hold, and every grant it loads goes to a
    /// record and back unchanged. The generator reaches every principal and resource, every action,
    /// names at 128 bytes, providers with `/`, sets past 8, and expiries on both sides of the
    /// wire's maximum.
    #[test]
    fn every_engine_grant_round_trips_through_the_wire(grant in any_wide_grant()) {
        let loads = PolicyEngine::load("", std::slice::from_ref(&grant), NOW).is_ok();
        prop_assert_eq!(loads, check_grant(&grant).is_ok(), "the engine loaded a grant the wire cannot hold");
        if loads {
            let injection = grant_crosses_pockets(&grant).then_some(InjectionPolicy::Ask);
            let issued_at = WallTime::from_unix_nanos(i128::from(NOW - 1) * 1_000_000).unwrap();
            let record = grant_record(&grant, ApprovalId::from_parts(1, [3; 10]), issued_at, injection).unwrap();
            prop_assert_eq!(Grant::try_from(&record).unwrap(), grant, "a grant changed through the wire");
        }
    }

    /// The wire's policy identifiers are exactly the engine's `@id`s.
    #[test]
    fn policy_ids_agree_with_engine_ids(id in prop_oneof!["[A-Za-z0-9._:/ -]{0,20}", "grant:[a-z]{0,4}", "[a-z]{128,129}"]) {
        let engine = PolicyEngine::load(&format!(r#"@id("{id}") permit(principal, action, resource);"#), &[], NOW).is_ok();
        prop_assert_eq!(PolicyId::new(id.clone()).is_ok(), engine, "{}", id);
    }

    /// The two crates' name grammars accept exactly the same strings.
    #[test]
    fn grant_names_agree_with_engine_names(s in "[A-Za-z0-9._:/ \"é-]{0,130}") {
        prop_assert_eq!(Name::new(s.clone()).is_ok(), GrantName::new(s.clone()).is_ok());
        prop_assert_eq!(Name::new(s.clone()).is_ok(), DataClass::new(s).is_ok());
    }
}

/// A name in the engine's grammar, boundary lengths and `/` included.
fn any_name() -> impl Strategy<Value = Name> {
    prop_oneof!["[A-Za-z0-9._:-]{1,12}", "[a-z0-9]{1,6}/[a-z0-9]{1,6}", "[a-z]{128}"]
        .prop_map(|s| Name::new(s).unwrap())
}

fn any_wide_grant() -> impl Strategy<Value = Grant> {
    let principal = prop_oneof![
        any::<u8>().prop_map(|n| Principal::Agent(CredentialId::from_parts(u64::from(n), [n; 10]))),
        Just(Principal::Human),
        Just(Principal::Module(ModuleName::new("mod-x").unwrap())),
        Just(Principal::System),
    ];
    let resource = prop_oneof![
        (any_name(), any_name()).prop_map(|(provider, model)| Resource::Model { provider, model }),
        any_name().prop_map(Resource::Tool),
        any::<u8>().prop_map(|n| Resource::Pool(PoolId::from_parts(u64::from(n), [n; 10]))),
        any_name().prop_map(Resource::ConfigKey),
        (0_u8..2).prop_map(|n| Resource::Pocket(pocket(n))),
    ];
    let expiry = prop_oneof![
        NOW..NOW + 100_000,
        253_402_207_199_000_u64..=253_402_207_201_100,
        (u64::MAX - 10)..=u64::MAX
    ];
    let asks = prop::collection::btree_set(
        prop_oneof!["[a-f][a-z0-9._:-]{0,12}", "grant:[a-z]{1,4}", "[a-z]{1,4}/[a-z]{1,4}"],
        0..10,
    );
    (
        principal,
        prop::sample::select(Action::ALL.to_vec()),
        resource,
        0_u8..2,
        expiry,
        0_u8..4,
        prop::collection::btree_set(any_name(), 0..10),
        asks,
    )
        .prop_map(
            |(principal, action, resource, place, expires_at_ms, tier, data_classes, approves)| Grant {
                id: GrantId::from_parts(1, [1; 10]),
                principal,
                action,
                resource,
                pocket: pocket(place),
                expires_at_ms,
                max_risk_tier: RiskTier::new(tier).unwrap(),
                data_classes,
                approves,
            },
        )
}

/// An own-pocket read behind an ask is approved by a grant, and the wire can journal that grant.
#[test]
fn an_own_pocket_read_behind_an_ask_is_approved_by_a_grant() {
    let ask_all = r#"@id("ask-all") @effect("ask") permit(principal, action, resource);"#;
    let own = Request {
        pocket: pocket(1),
        ..reading_with(None)
    };
    assert_eq!(
        PolicyEngine::load(ask_all, &[], NOW).unwrap().authorize(&own).effect,
        Effect::Ask
    );
    let grant = Grant {
        pocket: pocket(1),
        approves: BTreeSet::from(["ask-all".to_owned()]),
        ..memory_grant(1, NOW + 60_000)
    };
    let issued = WallTime::from_unix_nanos(i128::from(NOW) * 1_000_000).unwrap();
    let record = grant_record(&grant, ApprovalId::from_parts(1, [3; 10]), issued, None);
    assert!(record.is_ok(), "an own-pocket grant could not be journaled: {record:?}");
    let approved = PolicyEngine::load(ask_all, &[grant], NOW).unwrap();
    assert_eq!(
        approved.authorize(&own).effect,
        Effect::Allow,
        "the approval did not satisfy the ask"
    );
}

/// Naming a grant narrows any action, not only memory reads.
#[test]
fn a_named_grant_narrows_other_actions_too() {
    let ask = r#"@id("ask-exec") @effect("ask") permit(principal, action == Uaos::Action::"exec", resource);"#;
    let tool = Resource::Tool(Name::new("git").unwrap());
    let grant = |n: u8, approves: &[&str]| Grant {
        id: GrantId::from_parts(u64::from(n), [n; 10]),
        principal: agent(1),
        action: Action::Exec,
        resource: tool.clone(),
        pocket: pocket(1),
        expires_at_ms: NOW + 60_000,
        max_risk_tier: RiskTier::new(3).unwrap(),
        data_classes: BTreeSet::new(),
        approves: approves.iter().map(|s| (*s).to_owned()).collect(),
    };
    let (silent, approving) = (grant(1, &[]), grant(2, &["ask-exec"]));
    let e = PolicyEngine::load(ask, &[silent.clone(), approving.clone()], NOW).unwrap();
    let mut r = request(agent(1), Action::Exec, tool.clone());
    assert_eq!(
        e.authorize(&r).effect,
        Effect::Allow,
        "naming none, any covering grant decides"
    );
    r.grant = Some(silent.id);
    assert_eq!(
        e.authorize(&r).effect,
        Effect::Ask,
        "a named grant that does not approve the ask satisfied it"
    );
    r.grant = Some(approving.id);
    assert_eq!(e.authorize(&r).effect, Effect::Allow);
}

/// A carried cross-pocket grant must also approve every ask that fires.
#[test]
fn a_carried_grant_must_approve_the_asks_of_a_cross_pocket_read() {
    let ask_all = r#"@id("ask-all") @effect("ask") permit(principal, action, resource);"#;
    let approving = Grant {
        approves: BTreeSet::from(["ask-all".to_owned()]),
        ..memory_grant(1, NOW + 60_000)
    };
    let silent = memory_grant(2, NOW + 60_000);
    let e = PolicyEngine::load(ask_all, &[approving.clone(), silent.clone()], NOW).unwrap();
    assert_eq!(e.authorize(&reading_with(Some(approving.id))).effect, Effect::Allow);
    assert_eq!(
        e.authorize(&reading_with(Some(silent.id))).effect,
        Effect::Ask,
        "a carried grant skipped the ask"
    );
}

/// The wire keeps nanoseconds and the engine milliseconds: a finer expiry floors, so a reloaded
/// grant ends early, never late.
#[test]
fn a_finer_expiry_floors_on_reload() {
    let grant = memory_grant(1, NOW + 60_000);
    let issued = WallTime::from_unix_nanos(i128::from(NOW) * 1_000_000).unwrap();
    let mut record = grant_record(
        &grant,
        ApprovalId::from_parts(1, [3; 10]),
        issued,
        Some(InjectionPolicy::Ask),
    )
    .unwrap();
    record.expires_at = WallTime::from_unix_nanos(i128::from(NOW + 60_000) * 1_000_000 + 999_999).unwrap();
    assert_eq!(
        Grant::try_from(&record).unwrap().expires_at_ms,
        NOW + 60_000,
        "a reloaded grant ended late"
    );
}

/// One grant id twice refuses the set.
#[test]
fn a_grant_id_twice_is_refused() {
    let grant = memory_grant(1, NOW + 60_000);
    let refused = PolicyEngine::load("", &[grant.clone(), grant], NOW);
    assert!(
        matches!(&refused, Err(PolicyError::Rule { problem, .. }) if problem.contains("used twice")),
        "a grant id was loaded twice"
    );
}

/// A grant valid by construction: every principal, every action with its own resource kind, names
/// up to 128 bytes and with `/` everywhere but a provider, up to 8 classes and asks, a live expiry.
fn any_valid_grant() -> impl Strategy<Value = Grant> {
    let provider = || prop_oneof!["[A-Za-z0-9._:-]{1,12}", "[a-z]{128}"].prop_map(|s| Name::new(s).unwrap());
    let name = || {
        prop_oneof!["[A-Za-z0-9._:-]{1,12}", "[a-z0-9]{1,6}/[a-z0-9]{1,6}", "[a-z]{128}"]
            .prop_map(|s| Name::new(s).unwrap())
    };
    let principal = prop_oneof![
        any::<u8>().prop_map(|n| Principal::Agent(CredentialId::from_parts(u64::from(n), [n; 10]))),
        Just(Principal::Human),
        Just(Principal::Module(ModuleName::new("mod-x").unwrap())),
        Just(Principal::System),
    ];
    let target = prop_oneof![
        (
            prop::sample::select(vec![Action::ModelCall, Action::CountTokens]),
            provider(),
            name()
        )
            .prop_map(|(a, provider, model)| (a, Resource::Model { provider, model })),
        (prop::sample::select(vec![Action::ToolCall, Action::Exec]), name()).prop_map(|(a, n)| (a, Resource::Tool(n))),
        any::<u8>().prop_map(|n| (
            Action::BudgetTransfer,
            Resource::Pool(PoolId::from_parts(u64::from(n), [n; 10]))
        )),
        name().prop_map(|n| (Action::ConfigChange, Resource::ConfigKey(n))),
        (0_u8..2).prop_map(|n| (Action::MemoryRead, Resource::Pocket(pocket(n)))),
    ];
    (
        principal,
        target,
        0_u8..2,
        NOW + 1..NOW + 1_000_000,
        0_u8..4,
        prop::collection::btree_set(name(), 0..=8),
        prop::collection::btree_set("[a-f][a-z0-9._:-]{0,12}", 0..=8),
    )
        .prop_map(
            |(principal, (action, resource), place, expires_at_ms, tier, data_classes, approves)| Grant {
                id: GrantId::from_parts(1, [1; 10]),
                principal,
                action,
                resource,
                pocket: pocket(place),
                expires_at_ms,
                max_risk_tier: RiskTier::new(tier).unwrap(),
                data_classes,
                approves,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Every grant that is valid by construction loads, journals and reloads unchanged, own-pocket
    /// reads included, so `check_grant` refuses nothing it should accept.
    #[test]
    fn every_valid_grant_loads_and_round_trips(grant in any_valid_grant()) {
        prop_assert!(check_grant(&grant).is_ok(), "check_grant refused a valid grant");
        prop_assert!(PolicyEngine::load("", std::slice::from_ref(&grant), NOW).is_ok(), "the engine refused a valid grant");
        let injection = grant_crosses_pockets(&grant).then_some(InjectionPolicy::Ask);
        let issued_at = WallTime::from_unix_nanos(i128::from(NOW) * 1_000_000).unwrap();
        let record = grant_record(&grant, ApprovalId::from_parts(1, [3; 10]), issued_at, injection);
        prop_assert!(record.is_ok(), "a valid grant could not be journaled: {:?}", record);
        // A record that no longer reads back is a grant changed through the wire too.
        prop_assert_eq!(Grant::try_from(&record.unwrap()).ok(), Some(grant), "a grant changed through the wire");
    }
}
