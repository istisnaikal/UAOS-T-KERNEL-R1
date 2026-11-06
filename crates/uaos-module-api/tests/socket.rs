// SPDX-License-Identifier: Apache-2.0

//! The module socket's rules, one test per rule: a manifest is refused whole, admission compares
//! features as a set, state is bounded and all or nothing per call, a cursor only moves forward in
//! its own pocket, and declarations are checked against the manifest and the point. The tests named
//! in `xtask` seeded violations carry the words their negative expects in their failure message.

#![allow(
    clippy::unwrap_used,
    reason = "test harness: a helper's failure fails the test that called it"
)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};

use uaos_contracts::event::{EventType, ModuleName};
use uaos_contracts::id::{OperationId, PocketId, TypedId};
use uaos_contracts::operation::{OperationKind, RiskTier};
use uaos_contracts::wire::Seq;
use uaos_json::{Limits, parse};
use uaos_module_api::{
    CandidateId, ChildBody, ChildKind, ChildOpRequest, Code, ConfigSchema, Decl, DeclError, Decls, DeclsMut,
    EventClass, EventDecl, EventView, GrantDecl, HookCx, HookDecl, HookMode, HookPoint, KernelFeature, KernelOffer,
    MAX_DECLS, MAX_MODULE_TEXT, MAX_RANK, MAX_STATE_BYTES, Manifest, ManifestBuilder, ManifestError, Mask, Module,
    ModuleApiVersion, ModuleEvent, ModuleState, ModuleText, ModuleVersion, OnFailure, OpMeta, PocketCursor, Refusal,
    StateMut, Strike, StructuralView, TextError, check_decls,
};

const V1: ModuleVersion = ModuleVersion::new(1, 0, 0);

fn code(s: &str) -> Code {
    Code::new(s).unwrap()
}

fn builder() -> ManifestBuilder {
    Manifest::builder(ModuleName::new("mod-notes").unwrap(), V1)
}

fn pocket(n: u8) -> PocketId {
    PocketId::from_parts(u64::from(n), [n; 10])
}

fn set<T: Ord>(items: impl IntoIterator<Item = T>) -> BTreeSet<T> {
    items.into_iter().collect()
}

fn event(name: &str, class: EventClass, fields: &[&str]) -> EventDecl {
    fields
        .iter()
        .fold(EventDecl::new(code(name), class), |e, f| e.field(code(f)))
}

fn prompt() -> ChildBody {
    ChildBody::Prompt(ModuleText::new("hello").unwrap())
}

#[test]
fn a_manifest_is_refused_whole_for_each_reason() {
    use HookPoint as P;
    let many = (0..=64).fold(builder(), |b, i| b.reason(code(&format!("r{i}"))));
    let wide = (0..=8).map(|i| format!("f{i}")).collect::<Vec<_>>();
    let wide: Vec<&str> = wide.iter().map(String::as_str).collect();
    let noted = || event("noted", EventClass::Ephemeral, &[]);
    let cases: Vec<(ManifestBuilder, ManifestError)> = vec![
        (
            builder()
                .hook(HookDecl::new(P::Classify, HookMode::Observe))
                .hook(HookDecl::new(P::Classify, HookMode::Act)),
            ManifestError::DuplicateHook(P::Classify),
        ),
        (
            builder().hook(HookDecl::new(P::Classify, HookMode::Act).deadline_us(0)),
            ManifestError::Deadline {
                point: P::Classify,
                ceiling_us: 200,
            },
        ),
        (
            builder().hook(HookDecl::new(P::Classify, HookMode::Act).deadline_us(201)),
            ManifestError::Deadline {
                point: P::Classify,
                ceiling_us: 200,
            },
        ),
        (
            builder().hook(HookDecl::new(P::StreamObserve, HookMode::Observe)),
            ManifestError::FeatureNotRequired(KernelFeature::StreamObserve),
        ),
        (
            builder().hook(HookDecl::new(P::ResponsePost, HookMode::Act)),
            ManifestError::ModeUnavailable(P::ResponsePost),
        ),
        (
            builder()
                .requires(KernelFeature::ChildOperations)
                .action(ChildKind::MemoryRead),
            ManifestError::FeatureNotRequired(KernelFeature::CrossPocketRead),
        ),
        (
            builder().grant(GrantDecl::new(ChildKind::ModelCall, code("rewrite"))),
            ManifestError::GrantWithoutAction,
        ),
        (
            builder()
                .requires(KernelFeature::ChildOperations)
                .action(ChildKind::ModelCall)
                .grant(GrantDecl::new(ChildKind::ModelCall, code("anything"))),
            ManifestError::UndeclaredCode(code("anything")),
        ),
        (
            builder().state_bytes(MAX_STATE_BYTES + 1),
            ManifestError::StateTooLarge { max: MAX_STATE_BYTES },
        ),
        (builder().max_decls(0), ManifestError::Decls { max: MAX_DECLS }),
        (
            builder().max_decls(MAX_DECLS + 1),
            ManifestError::Decls { max: MAX_DECLS },
        ),
        (many, ManifestError::TooManyCodes { max: 64 }),
        (
            builder().event(event("noted", EventClass::Ephemeral, &wide)),
            ManifestError::TooManyCodes { max: 8 },
        ),
        (
            builder().event(noted()).event(noted()),
            ManifestError::DuplicateEvent(code("noted")),
        ),
        (
            builder()
                .requires(KernelFeature::ChildOperations)
                .action(ChildKind::ModelCall)
                .default_enabled(true),
            ManifestError::DefaultOnReachesOutside,
        ),
    ];
    for (b, expected) in cases {
        let refusal = Err(expected);
        assert_eq!(b.build(), refusal, "a manifest that breaks a rule was not refused");
    }
}

#[test]
fn refusal_codes_are_the_documented_ones() {
    // Contract §10: the `module.refused` reasons the host reports.
    let documented = [
        "feature_missing",
        "api_major",
        "api_minor_ahead",
        "bound_exceeded",
        "undeclared_code",
        "point_unavailable",
        "duplicate_hook",
        "feature_not_required",
        "duplicate_event",
        "grant_without_action",
        "default_on_reaches_outside",
        "config_schema",
    ];
    let produced = [
        ManifestError::Deadline {
            point: HookPoint::Classify,
            ceiling_us: 200,
        }
        .code(),
        ManifestError::UndeclaredCode(code("x1")).code(),
        ManifestError::ModeUnavailable(HookPoint::StreamObserve).code(),
        ManifestError::ConfigSchema.code(),
        Refusal::FeatureMissing(KernelFeature::StreamAssert).code(),
    ];
    for c in produced {
        assert!(documented.contains(&c), "undocumented refusal code {c}");
    }
    assert_eq!(produced[0], "bound_exceeded");
}

#[test]
fn the_bounds_themselves_are_accepted() {
    let m = builder()
        .hook(HookDecl::new(HookPoint::ResponsePost, HookMode::Observe).deadline_us(5_000))
        .state_bytes(MAX_STATE_BYTES)
        .max_decls(MAX_DECLS)
        .build()
        .unwrap();
    assert_eq!(m.state_bytes(), MAX_STATE_BYTES);
    assert!(!m.default_enabled(), "a manifest is off by default");
    assert_eq!(
        ModuleState::new(u32::MAX).limit(),
        MAX_STATE_BYTES,
        "the state bound is clamped"
    );
}

#[test]
fn a_config_schema_is_one_bounded_json_object() {
    assert!(ConfigSchema::new(r#"{"type":"object"}"#).is_ok());
    for bad in ["[]", "\"x\"", "{", "{} {}"] {
        assert_eq!(ConfigSchema::new(bad), Err(ManifestError::ConfigSchema), "{bad}");
    }
    let big = format!(r#"{{"k":"{}"}}"#, "x".repeat(16 * 1024));
    assert_eq!(ConfigSchema::new(big), Err(ManifestError::ConfigSchema));
}

#[test]
fn admission_compares_every_required_feature() {
    let m = builder()
        .requires(KernelFeature::StreamAssert)
        .hook(HookDecl::new(HookPoint::StreamAssert, HookMode::Act))
        .build()
        .unwrap();
    let full = KernelOffer::new(ModuleApiVersion::CURRENT, set(KernelFeature::ALL));
    assert_eq!(full.admit(&m), Ok(()));
    let degraded = KernelOffer::new(ModuleApiVersion::CURRENT, set([KernelFeature::StreamObserve]));
    assert_eq!(
        degraded.admit(&m),
        Err(Refusal::FeatureMissing(KernelFeature::StreamAssert)),
        "a missing feature was admitted"
    );
    let bare = KernelOffer::new(ModuleApiVersion::CURRENT, BTreeSet::new());
    assert_eq!(
        bare.admit(&builder().build().unwrap()),
        Ok(()),
        "a module that requires nothing"
    );
}

#[test]
fn admission_refuses_another_major() {
    let m = builder().build().unwrap();
    for major in [0, 2] {
        let offer = KernelOffer::new(ModuleApiVersion::new(major, 9), set(KernelFeature::ALL));
        assert_eq!(offer.admit(&m).unwrap_err().code(), "api_major");
    }
    let newer_kernel = KernelOffer::new(ModuleApiVersion::new(1, 3), set(KernelFeature::ALL));
    assert_eq!(
        newer_kernel.admit(&m),
        Ok(()),
        "a newer minor kernel admits an older module"
    );
}

#[test]
fn state_is_bounded_and_unchanged_on_refusal() {
    let mut state = ModuleState::new(8);
    state.replace(b"abcd").unwrap();
    assert!(!state.exceeded());
    let refused = state.append(b"efghi");
    assert!(refused.is_err(), "state grew past its bound");
    assert_eq!(refused.unwrap_err().wanted, 9);
    assert_eq!(state.as_bytes(), b"abcd");
    assert!(state.exceeded(), "a refused change marks the state");
    assert!(state.replace(b"123456789").is_err());
    assert_eq!(state.as_bytes(), b"abcd");
    state.append(b"efgh").unwrap();
    assert_eq!(state.as_bytes(), b"abcdefgh");
    assert!(state.exceeded(), "the mark stays for the rest of the call");
    assert!(
        ModuleState::restore(8, vec![0; 9]).is_err(),
        "a checkpoint never restores past the bound"
    );
    let restored = ModuleState::restore(8, b"abcdefgh".to_vec()).unwrap();
    assert_eq!(restored.as_bytes(), state.as_bytes());
    assert!(!restored.exceeded());
}

#[test]
fn a_cursor_only_moves_forward_in_its_own_pocket() {
    let mut cursor = PocketCursor::start(pocket(1));
    assert!(cursor.is_after(Seq(0)));
    cursor.advance(pocket(1), Seq(5)).unwrap();
    assert!(cursor.advance(pocket(1), Seq(5)).is_err(), "an event is delivered once");
    assert!(
        cursor.advance(pocket(1), Seq(3)).is_err(),
        "events arrive in journal order"
    );
    assert!(
        cursor.advance(pocket(2), Seq(9)).is_err(),
        "another pocket's event moved the cursor"
    );
    cursor.advance(pocket(1), Seq(6)).unwrap();
    assert_eq!(cursor.through(), Some(Seq(6)));
    assert_eq!(cursor.pocket(), pocket(1));
}

fn acting_manifest() -> Manifest {
    builder()
        .hook(HookDecl::new(HookPoint::ToolResult, HookMode::Act))
        .hook(HookDecl::new(HookPoint::Classify, HookMode::Observe))
        .hook(HookDecl::new(HookPoint::RouteDecide, HookMode::Act))
        .reason(code("secret_found"))
        .label(code("risky"))
        .event(event("noted", EventClass::Journaled, &["count"]))
        .max_decls(2)
        .build()
        .unwrap()
}

#[test]
fn declarations_are_checked_against_the_manifest_and_the_point() {
    use HookPoint as P;
    let m = acting_manifest();
    let veto = Decl::Veto(code("secret_found"));
    let emit = Decl::Emit(ModuleEvent::new(code("noted")).value(code("count"), 3).unwrap());
    let ok: [(Option<P>, &[Decl]); 3] = [
        (Some(P::ToolResult), std::slice::from_ref(&veto)),
        (Some(P::Classify), std::slice::from_ref(&emit)),
        (None, std::slice::from_ref(&emit)),
    ];
    for (point, decls) in ok {
        assert_eq!(check_decls(&m, point, decls), Ok(()), "{point:?}");
    }
    let request = Decl::Request(ChildOpRequest::new(ChildKind::ModelCall, prompt(), 1).unwrap());
    let strikes: [(Option<P>, Vec<Decl>, Strike); 7] = [
        (
            Some(P::ToolResult),
            vec![Decl::Veto(code("other"))],
            Strike::UndeclaredCode,
        ),
        (
            Some(P::Classify),
            vec![Decl::Label(code("risky"))],
            Strike::NotAllowedHere,
        ),
        (None, vec![veto.clone()], Strike::NotAllowedHere),
        (
            Some(P::ToolResult),
            vec![Decl::Emit(ModuleEvent::new(code("unseen")))],
            Strike::UndeclaredCode,
        ),
        (
            Some(P::ToolResult),
            vec![emit.clone(), emit.clone(), emit],
            Strike::TooMany,
        ),
        (Some(P::ToolResult), vec![request], Strike::UndeclaredAction),
        (Some(P::ToolResult), vec![Decl::Checkpoint], Strike::NotAllowedHere),
    ];
    for (point, decls, strike) in strikes {
        assert_eq!(check_decls(&m, point, &decls), Err(strike), "{point:?}");
    }
}

#[test]
fn nothing_is_declared_at_a_point_the_module_did_not_hook() {
    let m = acting_manifest();
    let emit = Decl::Emit(ModuleEvent::new(code("noted")));
    for point in [
        HookPoint::StreamAssert,
        HookPoint::ContextAssemble,
        HookPoint::IngressParsed,
    ] {
        assert_eq!(
            check_decls(&m, Some(point), std::slice::from_ref(&emit)),
            Err(Strike::NotHooked),
            "declarations accepted at an unhooked point {point:?}"
        );
    }
}

#[test]
fn an_event_carries_only_declared_value_names() {
    let m = acting_manifest();
    let declared = ModuleEvent::new(code("noted")).value(code("count"), 7).unwrap();
    assert_eq!(check_decls(&m, None, &[Decl::Emit(declared)]), Ok(()));
    // A wrong module that names a value after a word it saw in a prompt.
    let smuggled = ModuleEvent::new(code("noted")).value(code("password"), 1).unwrap();
    assert_eq!(
        check_decls(&m, None, &[Decl::Emit(smuggled)]),
        Err(Strike::UndeclaredCode),
        "an undeclared value name was emitted"
    );
    let twice = ModuleEvent::new(code("noted")).value(code("count"), 1).unwrap();
    assert!(twice.value(code("count"), 2).is_err(), "a value name twice");
}

#[test]
fn child_operations_name_only_declared_targets() {
    let m = builder()
        .hook(HookDecl::new(HookPoint::ResponsePost, HookMode::Observe))
        .requires(KernelFeature::ChildOperations)
        .requires(KernelFeature::ConfigChangeRequests)
        .action(ChildKind::ToolCall)
        .action(ChildKind::ConfigChange)
        .target(code("lint"))
        .build()
        .unwrap();
    let text = || ModuleText::new("{}").unwrap();
    let tool = |name: &str| ChildBody::ToolCall {
        tool: code(name),
        input: text(),
    };
    let request = |kind, body| Decl::Request(ChildOpRequest::new(kind, body, 9).unwrap());
    let point = Some(HookPoint::ResponsePost);
    assert_eq!(
        check_decls(&m, point, &[request(ChildKind::ToolCall, tool("lint"))]),
        Ok(())
    );
    assert_eq!(
        check_decls(&m, point, &[request(ChildKind::ToolCall, tool("shell"))]),
        Err(Strike::UndeclaredCode)
    );
    let change = ChildBody::ConfigChange {
        key: code("theme"),
        value: text(),
    };
    assert_eq!(
        check_decls(&m, point, &[request(ChildKind::ConfigChange, change)]),
        Err(Strike::UndeclaredCode)
    );
}

#[test]
fn a_ranking_is_bounded_and_names_each_candidate_once() {
    let m = acting_manifest();
    let point = Some(HookPoint::RouteDecide);
    let ids = |n: u16| (0..n).map(CandidateId::new).collect::<Vec<_>>();
    assert_eq!(check_decls(&m, point, &[Decl::Rank(ids(3))]), Ok(()));
    let too_long = u16::try_from(MAX_RANK + 1).unwrap();
    assert_eq!(
        check_decls(&m, point, &[Decl::Rank(ids(too_long))]),
        Err(Strike::BoundExceeded)
    );
    let twice = vec![CandidateId::new(1), CandidateId::new(1)];
    assert_eq!(check_decls(&m, point, &[Decl::Rank(twice)]), Err(Strike::BoundExceeded));
}

#[test]
fn a_checkpoint_needs_its_feature() {
    let observe = HookDecl::new(HookPoint::ResponsePost, HookMode::Observe);
    let m = builder().hook(observe.clone()).build().unwrap();
    assert_eq!(
        check_decls(&m, Some(HookPoint::ResponsePost), &[Decl::Checkpoint]),
        Err(Strike::FeatureNotRequired(KernelFeature::StateCheckpoints))
    );
    let m = builder()
        .requires(KernelFeature::StateCheckpoints)
        .hook(observe)
        .build()
        .unwrap();
    assert_eq!(
        check_decls(&m, Some(HookPoint::ResponsePost), &[Decl::Checkpoint]),
        Ok(())
    );
}

#[test]
fn the_collector_stops_at_its_bound() {
    let mut out = Decls::new(1);
    out.push(Decl::Checkpoint).unwrap();
    assert_eq!(out.push(Decl::Checkpoint), Err(DeclError { max: 1 }));
    assert_eq!(out.as_slice().len(), 1);
    assert_eq!(format!("{out:?}"), "Decls { len: 1, max: 1 }");
}

#[test]
fn a_child_body_must_fit_its_kind() {
    assert!(ChildOpRequest::new(ChildKind::CountTokens, prompt(), 1).is_ok());
    assert_eq!(ChildOpRequest::new(ChildKind::MemoryRead, prompt(), 1), Err(prompt()));
    assert_eq!(ChildKind::MemoryRead.cedar_action(), "memory.read");
    assert!(
        ChildKind::MemoryRead
            .required_features()
            .contains(&KernelFeature::CrossPocketRead)
    );
}

#[test]
fn codes_and_text_have_their_shapes() {
    for good in ["ab", "a_1", "secret_found"] {
        assert!(Code::new(good).is_ok(), "{good}");
    }
    for bad in ["", "a", "A1", "1a", "ab-c", "ab c", &"a".repeat(33)] {
        assert!(Code::new(bad).is_err(), "{bad}");
    }
    assert!(ModuleText::new("a\n\tb").is_ok());
    assert_eq!(ModuleText::new("bell\u{7}"), Err(TextError::Control));
    assert_eq!(
        ModuleText::new("x".repeat(MAX_MODULE_TEXT + 1)),
        Err(TextError::TooLong)
    );
    assert!(ModuleText::new("x".repeat(MAX_MODULE_TEXT)).is_ok());
}

/// A paper module: observes classification and remembers how many requests it saw per pocket.
struct Counter(Manifest);

impl Module for Counter {
    fn manifest(&self) -> &Manifest {
        &self.0
    }

    fn on_hook(&self, cx: &HookCx<'_>, mut state: StateMut<'_>, mut out: DeclsMut<'_>) {
        let seen = state.as_bytes().len();
        // The append is attempted every call; past the bound it is refused and marks the state.
        let grew = state.append(&[1]).is_ok();
        if grew && seen % 2 == 1 && cx.view().is_none() {
            out.push(Decl::Emit(ModuleEvent::new(code("noted")))).unwrap();
        }
    }

    fn on_event(&self, _event: &EventView<'_>, mut state: StateMut<'_>, out: DeclsMut<'_>) {
        // As on a hook: the append is attempted on every event, and past the bound it is refused
        // and marks the state.
        let grew = state.append(&[1]).is_ok();
        let _ = (grew, out);
    }
}

/// A module with no `on_event` of its own.
struct Silent(Manifest);

impl Module for Silent {
    fn manifest(&self) -> &Manifest {
        &self.0
    }

    fn on_hook(&self, _cx: &HookCx<'_>, _state: StateMut<'_>, _out: DeclsMut<'_>) {}
}

fn counter_manifest() -> Manifest {
    builder()
        .hook(HookDecl::new(HookPoint::Classify, HookMode::Observe))
        .event(event("noted", EventClass::Ephemeral, &[]))
        .state_bytes(4)
        .build()
        .unwrap()
}

#[test]
fn a_call_that_outgrows_its_state_is_struck_whole() {
    let manifest = builder()
        .hook(HookDecl::new(HookPoint::Classify, HookMode::Observe))
        .event(event("noted", EventClass::Ephemeral, &[]))
        .state_bytes(4)
        .build()
        .unwrap();
    let module = full_offer().admit_module(Counter(manifest)).unwrap();
    let op = OpMeta::new(
        OperationId::from_parts(1, [1; 10]),
        OperationKind::ModelCall,
        pocket(1),
        RiskTier::new(1).unwrap(),
    );
    let cx = HookCx::new(HookPoint::Classify, op);
    let mut state = ModuleState::new(module.manifest().state_bytes());
    let outcomes: Vec<_> = (0..6).map(|_| module.call_hook(&cx, &mut state)).collect();
    let emitted: usize = outcomes.iter().flatten().map(Vec::len).sum();
    assert_eq!(emitted, 2);
    assert_eq!(outcomes[4], Err(Strike::StateExceeded), "an outgrown call was kept");
    assert_eq!(outcomes[5], Err(Strike::StateExceeded));
    assert_eq!(state.as_bytes().len(), 4, "the state stopped at its bound");
    assert!(!state.exceeded(), "a struck copy never becomes the state");

    // The default `on_event` declares nothing and leaves the state as it was.
    let silent = full_offer().admit_module(Silent(counter_manifest())).unwrap();
    let event_type = EventType::new("op.created").unwrap();
    let before = state.as_bytes().to_vec();
    assert_eq!(
        silent.call_event(&EventView::new(pocket(1), Seq(1), &event_type, None), &mut state),
        Ok(Vec::new()),
        "the default on_event declared something"
    );
    assert_eq!(state.as_bytes(), before.as_slice());
}

/// `call_event` strikes an event that outgrows its state, live and on replay, and the struck copy
/// never becomes the state.
#[test]
fn an_event_that_outgrows_its_state_is_struck_whole() {
    let module = full_offer().admit_module(Counter(counter_manifest())).unwrap();
    let event_type = EventType::new("op.created").unwrap();
    for replay in [false, true] {
        let mut state = ModuleState::new(module.manifest().state_bytes());
        let outcomes: Vec<_> = (1..=6)
            .map(|n| {
                let live = EventView::new(pocket(1), Seq(n), &event_type, None);
                let event = if replay { live.replayed() } else { live };
                module.call_event(&event, &mut state)
            })
            .collect();
        assert_eq!(outcomes[4], Err(Strike::StateExceeded), "an outgrown event was kept");
        assert_eq!(outcomes[5], Err(Strike::StateExceeded));
        assert_eq!(state.as_bytes().len(), 4, "the state stopped at its bound");
        assert!(!state.exceeded(), "a struck copy never becomes the state");
    }
}

#[test]
fn only_acting_points_take_an_acting_hook() {
    let mut observe_only = Vec::new();
    for point in HookPoint::ALL {
        let b = point
            .required_feature()
            .into_iter()
            .fold(builder(), ManifestBuilder::requires)
            .hook(HookDecl::new(point, HookMode::Act));
        match b.build() {
            Ok(_) => assert!(point.acts()),
            Err(e) => {
                assert_eq!(e, ManifestError::ModeUnavailable(point), "{point:?}");
                observe_only.push(point);
            }
        }
    }
    assert_eq!(
        observe_only,
        [
            HookPoint::StreamObserve,
            HookPoint::ResponsePost,
            HookPoint::ErrorTranslate
        ]
    );
}

#[test]
fn every_code_is_one_the_contract_lists() {
    // Contract §10, both lists, exactly.
    let refusals: BTreeSet<&str> = [
        "feature_missing",
        "api_major",
        "api_minor_ahead",
        "bound_exceeded",
        "undeclared_code",
        "point_unavailable",
        "duplicate_hook",
        "feature_not_required",
        "duplicate_event",
        "grant_without_action",
        "default_on_reaches_outside",
        "config_schema",
    ]
    .into_iter()
    .collect();
    let strikes: BTreeSet<&str> = [
        "too_many",
        "not_hooked",
        "not_allowed_here",
        "undeclared_code",
        "undeclared_action",
        "feature_not_required",
        "bound_exceeded",
        "state_exceeded",
        "not_own_child",
        "unknown_candidate",
        "budget_exceeded",
    ]
    .into_iter()
    .collect();
    let p = HookPoint::Classify;
    let f = KernelFeature::StreamAssert;
    let manifest = [
        ManifestError::DuplicateHook(p),
        ManifestError::Deadline {
            point: p,
            ceiling_us: 200,
        },
        ManifestError::FeatureNotRequired(f),
        ManifestError::StateTooLarge { max: 1 },
        ManifestError::Decls { max: 1 },
        ManifestError::TooManyCodes { max: 1 },
        ManifestError::DuplicateEvent(code("x1")),
        ManifestError::GrantWithoutAction,
        ManifestError::UndeclaredCode(code("x1")),
        ManifestError::ModeUnavailable(p),
        ManifestError::FailureUnavailable(p),
        ManifestError::DefaultOnReachesOutside,
        ManifestError::ConfigSchema,
    ];
    let admission = [
        Refusal::ApiMajor {
            kernel_major: 1,
            module_major: 2,
        },
        Refusal::ApiMinorAhead {
            kernel_minor: 0,
            module_minor: 1,
        },
        Refusal::FeatureMissing(f),
    ];
    let produced: BTreeSet<&str> = manifest
        .iter()
        .map(ManifestError::code)
        .chain(admission.iter().map(Refusal::code))
        .collect();
    assert_eq!(produced, refusals, "the refusal codes changed");
    let struck: BTreeSet<&str> = [
        Strike::TooMany,
        Strike::NotHooked,
        Strike::NotAllowedHere,
        Strike::UndeclaredCode,
        Strike::UndeclaredAction,
        Strike::FeatureNotRequired(f),
        Strike::BoundExceeded,
        Strike::StateExceeded,
        Strike::NotOwnChild,
        Strike::UnknownCandidate,
        Strike::BudgetExceeded,
    ]
    .iter()
    .map(Strike::code)
    .collect();
    assert_eq!(struck, strikes, "the strike codes changed");
}

#[test]
fn targets_and_grants_are_bounded() {
    let targets = (0..=64).fold(builder(), |b, i| b.target(code(&format!("t{i}"))));
    assert_eq!(targets.build(), Err(ManifestError::TooManyCodes { max: 64 }));
    let base = builder()
        .requires(KernelFeature::ChildOperations)
        .action(ChildKind::ModelCall)
        .reason(code("rewrite"));
    let grants = (0..=64).fold(base, |b, _| {
        b.grant(GrantDecl::new(ChildKind::ModelCall, code("rewrite")))
    });
    assert_eq!(grants.build(), Err(ManifestError::TooManyCodes { max: 64 }));
}

#[test]
fn an_empty_ranking_is_a_strike() {
    let m = acting_manifest();
    assert_eq!(
        check_decls(&m, Some(HookPoint::RouteDecide), &[Decl::Rank(Vec::new())]),
        Err(Strike::BoundExceeded),
        "an empty ranking vetoed the route without a reason"
    );
}

/// A paper module that asks for a summary whenever an event reaches it, and counts the events.
struct Summarizer(Manifest);

impl Module for Summarizer {
    fn manifest(&self) -> &Manifest {
        &self.0
    }

    fn on_hook(&self, _cx: &HookCx<'_>, _state: StateMut<'_>, _out: DeclsMut<'_>) {}

    fn on_event(&self, _event: &EventView<'_>, mut state: StateMut<'_>, mut out: DeclsMut<'_>) {
        if state.append(&[1]).is_ok() {
            let request = ChildOpRequest::new(ChildKind::ModelCall, prompt(), 1).unwrap();
            out.push(Decl::Request(request)).unwrap();
        }
    }
}

#[test]
fn a_replay_rebuilds_state_and_declares_nothing() {
    let manifest = builder()
        .requires(KernelFeature::ChildOperations)
        .action(ChildKind::ModelCall)
        .state_bytes(8)
        .build()
        .unwrap();
    let module = full_offer().admit_module(Summarizer(manifest)).unwrap();
    let event_type = EventType::new("op.committed").unwrap();
    let live = EventView::new(pocket(1), Seq(1), &event_type, None);
    let mut state = ModuleState::new(8);
    assert_eq!(module.call_event(&live, &mut state).unwrap().len(), 1);

    // After a restart without a checkpoint, the same events are replayed into a fresh state.
    let mut rebuilt = ModuleState::new(8);
    let replayed: Vec<Decl> = (1..=3)
        .flat_map(|n| {
            let event = EventView::new(pocket(1), Seq(n), &event_type, None).replayed();
            module.call_event(&event, &mut rebuilt).unwrap()
        })
        .collect();
    assert!(replayed.is_empty(), "a replay requested a child Operation again");
    assert_eq!(rebuilt.as_bytes().len(), 3, "the replay rebuilt the state");
}

#[test]
fn cancelling_a_child_needs_child_operations() {
    let m = builder()
        .hook(HookDecl::new(HookPoint::ResponsePost, HookMode::Observe))
        .build()
        .unwrap();
    let cancel = Decl::CancelOp(OperationId::from_parts(1, [1; 10]));
    assert_eq!(
        check_decls(&m, Some(HookPoint::ResponsePost), &[cancel]),
        Err(Strike::FeatureNotRequired(KernelFeature::ChildOperations)),
        "a cancellation was accepted without child_operations"
    );
}

fn full_offer() -> KernelOffer {
    KernelOffer::new(ModuleApiVersion::CURRENT, set(KernelFeature::ALL))
}

/// A module whose manifest grows after admission: it asks for child Operations once flipped.
struct Shifty {
    small: Manifest,
    grown: Manifest,
    flipped: AtomicBool,
}

impl Module for Shifty {
    fn manifest(&self) -> &Manifest {
        if self.flipped.load(Ordering::Relaxed) {
            &self.grown
        } else {
            &self.small
        }
    }

    fn on_hook(&self, _cx: &HookCx<'_>, _state: StateMut<'_>, mut out: DeclsMut<'_>) {
        let request = ChildOpRequest::new(ChildKind::ModelCall, prompt(), 1).unwrap();
        out.push(Decl::Request(request)).unwrap();
    }

    fn on_event(&self, _event: &EventView<'_>, _state: StateMut<'_>, mut out: DeclsMut<'_>) {
        let request = ChildOpRequest::new(ChildKind::ModelCall, prompt(), 1).unwrap();
        out.push(Decl::Request(request)).unwrap();
    }
}

/// A module is checked against the manifest it was admitted under, not one it grows later.
#[test]
fn a_module_is_checked_against_its_admitted_manifest() {
    let hook = HookDecl::new(HookPoint::ResponsePost, HookMode::Observe);
    let small = builder().hook(hook.clone()).build().unwrap();
    let grown = builder()
        .hook(hook)
        .requires(KernelFeature::ChildOperations)
        .action(ChildKind::ModelCall)
        .build()
        .unwrap();
    let degraded = KernelOffer::new(ModuleApiVersion::CURRENT, BTreeSet::new());
    let module = degraded
        .admit_module(Shifty {
            small,
            grown,
            flipped: AtomicBool::new(false),
        })
        .unwrap();
    module.module().flipped.store(true, Ordering::Relaxed);
    let op = OpMeta::new(
        OperationId::from_parts(1, [1; 10]),
        OperationKind::ModelCall,
        pocket(1),
        RiskTier::new(1).unwrap(),
    );
    let cx = HookCx::new(HookPoint::ResponsePost, op);
    let mut state = ModuleState::new(0);
    assert_eq!(
        module.call_hook(&cx, &mut state),
        Err(Strike::UndeclaredAction),
        "a module grew its manifest after admission"
    );
    // An event is checked against the same snapshot.
    let event_type = EventType::new("op.committed").unwrap();
    let event = EventView::new(pocket(1), Seq(1), &event_type, None);
    assert_eq!(
        module.call_event(&event, &mut state),
        Err(Strike::UndeclaredAction),
        "an event was checked against a manifest grown after admission"
    );
}

/// A failure at a point that runs after forwarding cannot deny.
#[test]
fn a_failure_cannot_deny_after_the_fact() {
    let deny = |point| {
        builder()
            .hook(HookDecl::new(point, HookMode::Observe).on_failure(OnFailure::Deny))
            .build()
    };
    for point in [HookPoint::ResponsePost, HookPoint::ErrorTranslate] {
        assert_eq!(
            deny(point),
            Err(ManifestError::FailureUnavailable(point)),
            "a failure policy that cannot deny was loaded"
        );
    }
    assert!(deny(HookPoint::Classify).is_ok());
}

/// A hook is shown the view of a seal.
#[test]
fn a_hook_sees_a_sealed_view() {
    let tape = parse(br#"{"k":"v"}"#, &Limits::DEFAULT).unwrap();
    let mask = Mask::new();
    let sealed = mask.seal(&tape).unwrap();
    let op = OpMeta::new(
        OperationId::from_parts(1, [1; 10]),
        OperationKind::ModelCall,
        pocket(1),
        RiskTier::new(1).unwrap(),
    );
    let cx = HookCx::new(HookPoint::Classify, op).with_view(&sealed);
    assert!(
        cx.view().is_some_and(StructuralView::is_sealed),
        "a hook was shown an unsealed view"
    );
}
