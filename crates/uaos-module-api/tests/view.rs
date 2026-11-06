// SPDX-License-Identifier: Apache-2.0

//! The redacted view, selectors, roles and endpoint paths: a mask covers values and keys, a
//! predicate's answer never depends on masked text, selectors resolve to tape ids in document order
//! and are bounded, roles govern their subtree and fail closed outside the view, path patterns
//! match canonical paths by segment, and nothing a `Debug` prints carries content. The tests named
//! in `xtask` seeded violations carry the words their negative expects in their failure message.

#![allow(
    clippy::unwrap_used,
    reason = "test harness: a helper's failure fails the test that called it"
)]

use std::collections::BTreeSet;

use proptest::prelude::*;
use uaos_json::{Kind, Limits, NodeId, parse};
use uaos_module_api::{
    Code, ConfigSchema, EndpointClass, EndpointDecl, MAX_PREDICATE_VALUES, MAX_SELECTOR_TEXT, Mask, MaskError, Method,
    ModuleState, ModuleText, PathPattern, Predicate, Role, RoleMap, Selector, SelectorError, SseEvent, Step,
    StructuralView, UsageReport, ViewText, Visits, classify,
};

const DOC: &str = r#"{"system":[{"type":"text","text":"s0"}],"messages":[
{"role":"user","content":"hi"},
{"role":"assistant","content":[{"type":"thinking","thinking":"t","signature":"sig"},{"type":"text","text":"a"}]},
{"role":"user","content":[{"type":"tool_result","content":"r"},{"type":"text","text":"q"}]}]}"#;

fn sel(steps: Vec<Step>) -> Selector {
    Selector::new(steps).unwrap()
}

fn messages() -> Vec<Step> {
    vec![Step::Key("messages".into()), Step::Each]
}

fn strings(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}

fn member_in(key: &str, values: &[&str]) -> Predicate {
    Predicate::MemberIn {
        key: key.into(),
        values: strings(values),
    }
}

fn texts(view: &StructuralView<'_, '_>, ids: &[NodeId]) -> Vec<String> {
    ids.iter()
        .map(|id| match view.node(*id).unwrap().text().unwrap() {
            Some(ViewText::Plain(t)) => t.into_owned(),
            Some(ViewText::Masked) => "<masked>".to_owned(),
            None => "<not a string>".to_owned(),
        })
        .collect()
}

#[test]
fn selectors_resolve_in_document_order() {
    let tape = parse(DOC.as_bytes(), &Limits::DEFAULT).unwrap();
    let mask = Mask::new();
    let view = StructuralView::new(&tape, &mask);
    assert_eq!(sel(messages()).resolve(&view).unwrap().len(), 3);

    let mut users = messages();
    users.push(Step::Where(member_in("role", &["user"])));
    assert_eq!(sel(users.clone()).resolve(&view).unwrap().len(), 2);
    users.extend([
        Step::Last,
        Step::Key("content".into()),
        Step::Each,
        Step::Key("type".into()),
    ]);
    assert_eq!(
        texts(&view, &sel(users).resolve(&view).unwrap()),
        ["tool_result", "text"]
    );

    let mut others = messages();
    others.push(Step::Where(Predicate::MemberNotIn {
        key: "role".into(),
        values: strings(&["user"]),
    }));
    others.push(Step::Key("role".into()));
    assert_eq!(texts(&view, &sel(others).resolve(&view).unwrap()), ["assistant"]);

    let signatures = sel(vec![Step::AnyDepthKey("signature".into())]).resolve(&view).unwrap();
    assert_eq!(texts(&view, &signatures), ["sig"]);

    let mut with_tool_result = messages();
    with_tool_result.push(Step::Where(Predicate::StringOrArrayWith {
        key: "content".into(),
        element: Box::new(member_in("type", &["tool_result"])),
    }));
    with_tool_result.push(Step::Key("role".into()));
    assert_eq!(
        texts(&view, &sel(with_tool_result).resolve(&view).unwrap()),
        ["user", "user"]
    );
}

#[test]
fn a_selector_is_bounded() {
    assert_eq!(Selector::new(vec![Step::Each; 17]), Err(SelectorError::TooLong));
    assert_eq!(Selector::new(vec![Step::Key(String::new())]), Err(SelectorError::Key));
    let long = "k".repeat(MAX_SELECTOR_TEXT + 1);
    assert_eq!(
        Selector::new(vec![Step::AnyDepthKey(long.clone())]),
        Err(SelectorError::Key)
    );
    let deep = (0..4).fold(member_in("role", &["user"]), |inner, _| Predicate::StringOrArrayWith {
        key: "content".into(),
        element: Box::new(inner),
    });
    assert_eq!(Selector::new(vec![Step::Where(deep)]), Err(SelectorError::TooDeep));
    let many: Vec<String> = (0..=MAX_PREDICATE_VALUES).map(|i| format!("v{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(
        Selector::new(vec![Step::Where(member_in("type", &many))]),
        Err(SelectorError::TooManyValues),
        "an unbounded predicate was accepted"
    );
    assert_eq!(
        Selector::new(vec![Step::Where(member_in("type", &[long.as_str()]))]),
        Err(SelectorError::Key)
    );
    let nested = Predicate::StringOrArrayWith {
        key: "content".into(),
        element: Box::new(member_in("type", &many)),
    };
    assert_eq!(
        Selector::new(vec![Step::Where(nested)]),
        Err(SelectorError::TooManyValues)
    );
}

/// `{"messages":[{"role":"user","content":<content>}]}` with its content string masked.
fn masked_message(content: &str) -> (bool, bool, bool) {
    let body = format!(r#"{{"messages":[{{"role":"user","content":"{content}"}}]}}"#);
    let tape = parse(body.as_bytes(), &Limits::DEFAULT).unwrap();
    let plain = Mask::new();
    let mut content_path = messages();
    content_path.push(Step::Key("content".into()));
    let id = sel(content_path).resolve(&StructuralView::new(&tape, &plain)).unwrap()[0];
    let mut mask = Mask::new();
    mask.value(id);
    let view = StructuralView::new(&tape, &mask);
    let count = |p: Predicate| {
        let mut steps = messages();
        steps.push(Step::Where(p));
        sel(steps).resolve(&view).unwrap().len()
    };
    let is_in = count(member_in("content", &["hi", "secret"]));
    let not_in = count(Predicate::MemberNotIn {
        key: "content".into(),
        values: strings(&["hi", "secret"]),
    });
    let string = count(Predicate::StringOrArrayWith {
        key: "content".into(),
        element: Box::new(member_in("type", &["x1"])),
    });
    (is_in == 1, not_in == 1, string == 1)
}

#[test]
fn a_masked_value_cannot_be_probed() {
    // Whatever the masked text is, every predicate answers the same: it is unknown, never equal.
    let answers = [masked_message("hi"), masked_message("secret"), masked_message("other")];
    assert!(
        answers.iter().all(|a| *a == answers[0]),
        "a predicate's answer depended on masked text"
    );
    assert_eq!(answers[0], (false, true, true));
}

#[test]
fn masked_keys_and_numbers_read_as_masked() {
    let body = br#"{"ghp_secretkey":{"a":1},"n":12345,"k":"v"}"#;
    let tape = parse(body, &Limits::DEFAULT).unwrap();
    let plain = Mask::new();
    let open = StructuralView::new(&tape, &plain);
    let root = open.root();
    let secret = root.member("ghp_secretkey").unwrap().unwrap();
    let number = root.member("n").unwrap().unwrap();
    let mut mask = Mask::new();
    mask.key(secret.id());
    mask.value(number.id());
    let view = StructuralView::new(&tape, &mask);
    let node = view.node(secret.id()).unwrap();
    assert_eq!(node.key().unwrap(), Some(ViewText::Masked), "a masked key was readable");
    assert!(!node.key_is("ghp_secretkey").unwrap(), "a masked key matched its name");
    assert!(
        view.root().member("ghp_secretkey").unwrap().is_none(),
        "a masked key was found by name"
    );
    let any_depth = sel(vec![Step::AnyDepthKey("ghp_secretkey".into())])
        .resolve(&view)
        .unwrap();
    assert!(any_depth.is_empty(), "a masked key was found at any depth");
    assert_eq!(view.node(number.id()).unwrap().number_text(), Some(ViewText::Masked));
    assert_eq!(
        view.root().member("k").unwrap().unwrap().key().unwrap(),
        Some(ViewText::Plain("k".into()))
    );
    let first = view.root().children().next().unwrap();
    assert_eq!(first.kind(), Kind::Object, "structure stays visible");
}

#[test]
fn roles_govern_their_subtree_and_fail_closed_outside_the_view() {
    let tape = parse(DOC.as_bytes(), &Limits::DEFAULT).unwrap();
    let mask = Mask::new();
    let view = StructuralView::new(&tape, &mask);
    let mut thinking = messages();
    thinking.extend([
        Step::Key("content".into()),
        Step::Each,
        Step::Where(member_in("type", &["thinking"])),
    ]);
    let mut roles = RoleMap::new();
    assert_eq!(roles.assign(&view, &sel(thinking), Role::Signed).unwrap(), 1);
    let signature = sel(vec![Step::AnyDepthKey("signature".into())]).resolve(&view).unwrap()[0];
    assert!(roles.roles_of(signature).is_empty());
    assert!(roles.governing(&view, signature).unwrap().contains(&Role::Signed));
    let system = sel(vec![Step::AnyDepthKey("text".into())]).resolve(&view).unwrap()[0];
    assert_eq!(roles.governing(&view, system), Some(BTreeSet::new()));

    let small = parse(b"[1]", &Limits::DEFAULT).unwrap();
    let small_view = StructuralView::new(&small, &mask);
    assert!(small_view.node(signature).is_none());
    assert_eq!(
        roles.governing(&small_view, signature),
        None,
        "a node outside the view got roles"
    );
}

#[test]
fn path_patterns_match_canonical_paths_by_segment() {
    let exact = PathPattern::new("/v1/messages").unwrap();
    assert!(exact.matches("/v1/messages") && !exact.matches("/v1/messages/count_tokens"));
    let models = PathPattern::new("/v1/models*").unwrap();
    for (path, expected) in [
        ("/v1/models", true),
        ("/v1/models/claude", true),
        ("/v1/models-x", false),
        ("/v1/models/../messages", false),
        ("/v1/models/%2e%2e/messages", false),
        ("/v1/models//x", false),
        ("/v1/models/.", false),
        ("/v1/models/..;/messages", false),
        ("/v1/models;x", false),
        ("/v1\\models", false),
    ] {
        assert_eq!(
            models.matches(path),
            expected,
            "path {path} matched a pattern it should not"
        );
    }
    let prefix = PathPattern::new("/v1/*").unwrap();
    assert!(prefix.matches("/v1/messages") && !prefix.matches("/v2/x"));
    for bad in [
        "v1",
        "/v1?x",
        "/v1#x",
        "/a*b",
        "/a**",
        "/a b",
        "/a/../b",
        "/a%2f",
        "//a",
        &format!("/{}", "a".repeat(128)),
    ] {
        assert!(PathPattern::new(bad).is_err(), "{bad}");
    }
}

#[test]
fn debug_output_carries_no_content() {
    let tape = parse(DOC.as_bytes(), &Limits::DEFAULT).unwrap();
    let mask = Mask::new();
    let view = StructuralView::new(&tape, &mask);
    let mut state = ModuleState::new(64);
    state.replace(b"secret-state").unwrap();
    let selector = sel(vec![
        Step::Key("secret-key".into()),
        Step::Where(member_in("secret-member", &["secret-value"])),
    ]);
    let frame = SseEvent::new(Some("secret-event"), br#"{"secret":1}"#);
    let shown = [
        format!("{view:?}"),
        format!("{:?}", view.root()),
        format!("{:?}", ViewText::Plain("secret-text".into())),
        format!("{:?}", ModuleText::new("secret-text").unwrap()),
        format!("{state:?}"),
        format!("{:?}", ConfigSchema::new(r#"{"secret":1}"#).unwrap()),
        format!("{selector:?}"),
        format!("{frame:?}"),
    ];
    for text in shown {
        assert!(
            !text.contains("secret") && !text.contains("sig") && !text.contains("\"hi\""),
            "{text}"
        );
    }
}

/// A JSON value of bounded size: objects with keys from a small set, so names repeat across
/// levels and selectors find several matches.
fn json() -> impl Strategy<Value = String> {
    let key = prop::sample::select(vec!["a", "b", "role", "type", "content"]);
    let leaf = prop_oneof![
        Just("null".to_owned()),
        (0u32..1000).prop_map(|n| n.to_string()),
        prop::sample::select(vec!["\"user\"", "\"text\"", "\"x\""]).prop_map(str::to_owned),
    ];
    leaf.prop_recursive(4, 64, 6, move |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(|items| format!("[{}]", items.join(","))),
            prop::collection::btree_map(key.clone(), inner, 0..5).prop_map(|members| {
                let members: Vec<String> = members.into_iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
                format!("{{{}}}", members.join(","))
            }),
        ]
    })
}

fn steps() -> impl Strategy<Value = Vec<Step>> {
    let key = prop::sample::select(vec!["a", "b", "role", "type", "content"]).prop_map(str::to_owned);
    let step = prop_oneof![
        key.clone().prop_map(Step::Key),
        Just(Step::Each),
        key.clone().prop_map(Step::AnyDepthKey),
        Just(Step::Last),
        key.prop_map(|k| Step::Where(member_in(&k, &["user", "text"]))),
    ];
    prop::collection::vec(step, 0..6)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// On generated tapes, a selector names only nodes of the view, in document order, without
    /// repeats; a key step names only members with that key; a role map names only nodes it was
    /// given.
    #[test]
    fn selectors_stay_inside_the_view(doc in json(), steps in steps(), masked in prop::collection::vec((any::<u16>(), any::<bool>()), 0..4)) {
        let tape = parse(doc.as_bytes(), &Limits::DEFAULT).unwrap();
        // Mask a few nodes, values or keys, so the key checks below also prove a masked key is
        // never selected by name.
        let plain = Mask::new();
        let ids: Vec<NodeId> = StructuralView::new(&tape, &plain).root().descendants().map(|n| n.id()).collect();
        let mut mask = Mask::new();
        for (pick, key) in &masked {
            if let Some(id) = ids.get(usize::from(*pick) % ids.len().max(1)) {
                if *key { mask.key(*id) } else { mask.value(*id) }
            }
        }
        let view = StructuralView::new(&tape, &mask);
        let last_is_key = match steps.last() {
            Some(Step::Key(k) | Step::AnyDepthKey(k)) => Some(k.clone()),
            _ => None,
        };
        let selector = Selector::new(steps).unwrap();
        let ids = selector.resolve(&view).unwrap();
        prop_assert!(ids.windows(2).all(|w| w[0] < w[1]), "not in document order, or repeated");
        for id in &ids {
            let node = view.node(*id);
            prop_assert!(node.is_some(), "a selector named a node outside the view");
            if let (Some(node), Some(key)) = (node, &last_is_key) {
                prop_assert!(node.key_is(key).unwrap());
            }
        }
        let mut roles = RoleMap::new();
        let assigned = roles.assign(&view, &selector, Role::Opaque).unwrap();
        prop_assert_eq!(assigned, ids.len());
        let named: Vec<NodeId> = roles.nodes().map(|(id, _)| id).collect();
        prop_assert_eq!(named, ids);
    }
}

#[test]
fn a_masked_key_cannot_be_probed() {
    // Whatever the masked key spells, even the very name a predicate asks for, the member is
    // absent to every predicate.
    for key in ["content", "secret", "other"] {
        let body = format!(r#"{{"messages":[{{"role":"user","{key}":"hi"}}]}}"#);
        let tape = parse(body.as_bytes(), &Limits::DEFAULT).unwrap();
        let plain = Mask::new();
        let message = sel(messages()).resolve(&StructuralView::new(&tape, &plain)).unwrap()[0];
        let member = StructuralView::new(&tape, &plain)
            .node(message)
            .unwrap()
            .children()
            .nth(1)
            .unwrap()
            .id();
        let mut mask = Mask::new();
        mask.key(member);
        let view = StructuralView::new(&tape, &mask);
        let count = |p: Predicate| {
            let mut steps = messages();
            steps.push(Step::Where(p));
            sel(steps).resolve(&view).unwrap().len()
        };
        assert_eq!(
            count(member_in("content", &["hi"])),
            0,
            "a masked key was probed: {key}"
        );
        let not_in = Predicate::MemberNotIn {
            key: "content".into(),
            values: strings(&["hi"]),
        };
        assert_eq!(count(not_in), 1, "a masked key was probed: {key}");
    }
}

#[test]
fn an_endpoint_s_class_is_the_strictest_match_and_unknown_paths_are_denied() {
    let decl = |path: &str, class| EndpointDecl::new(Method::Post, PathPattern::new(path).unwrap(), class);
    let endpoints = [
        decl("/v1/*", EndpointClass::Metadata),
        decl("/v1/messages", EndpointClass::Governed),
        decl("/v1/files*", EndpointClass::Denied),
    ];
    for (method, path, expected) in [
        (Method::Post, "/v1/messages", EndpointClass::Governed),
        (Method::Post, "/v1/models", EndpointClass::Metadata),
        (Method::Post, "/v1/files/f1", EndpointClass::Denied),
        (Method::Post, "/v2/messages", EndpointClass::Denied),
        (Method::Get, "/v1/messages", EndpointClass::Denied),
        (Method::Post, "/v1//messages", EndpointClass::Denied),
        (Method::Post, "/v1/messages/../files", EndpointClass::Denied),
    ] {
        assert_eq!(
            classify(&endpoints, method, path),
            expected,
            "an endpoint got a weaker class: {path}"
        );
    }
}

#[test]
fn a_masked_container_masks_everything_inside() {
    let body = br#"{"outer":{"k":"v","n":7,"deep":{"x":"y"}},"other":"o"}"#;
    let tape = parse(body, &Limits::DEFAULT).unwrap();
    let plain = Mask::new();
    let outer = StructuralView::new(&tape, &plain)
        .root()
        .member("outer")
        .unwrap()
        .unwrap()
        .id();
    let mut mask = Mask::new();
    mask.value(outer);
    let view = StructuralView::new(&tape, &mask);
    let outer = view.node(outer).unwrap();
    assert!(
        outer.member("k").unwrap().is_none(),
        "a key inside a masked container was found"
    );
    for node in outer.descendants() {
        assert!(
            !matches!(node.key().unwrap(), Some(ViewText::Plain(_))),
            "a key inside a masked container was readable"
        );
        assert!(
            !matches!(node.text().unwrap(), Some(ViewText::Plain(_))),
            "a string inside a masked container was readable"
        );
        assert!(
            !matches!(node.number_text(), Some(ViewText::Plain(_))),
            "a number inside a masked container was readable"
        );
    }
    let other = view.root().member("other").unwrap().unwrap();
    assert_eq!(other.text().unwrap(), Some(ViewText::Plain("o".into())));
}

#[test]
fn a_strip_never_encloses_a_forbidden_role() {
    use uaos_module_api::HookPoint;
    let body =
        br#"{"messages":[{"role":"user","content":[{"type":"thinking","signature":"s"},{"type":"text","text":"t"}]}]}"#;
    let tape = parse(body, &Limits::DEFAULT).unwrap();
    let mask = Mask::new();
    let view = StructuralView::new(&tape, &mask);
    let message = sel(messages()).resolve(&view).unwrap()[0];
    let mut blocks = messages();
    blocks.extend([Step::Key("content".into()), Step::Each]);
    let blocks = sel(blocks).resolve(&view).unwrap();
    let (thinking, text) = (blocks[0], blocks[1]);
    let mut roles = RoleMap::new();
    roles.assign(&view, &sel(messages()), Role::NewestHumanTurn).unwrap();
    let mut signed = messages();
    signed.extend([
        Step::Key("content".into()),
        Step::Each,
        Step::Where(member_in("type", &["thinking"])),
    ]);
    roles.assign(&view, &sel(signed), Role::Signed).unwrap();

    assert!(!roles.governing(&view, message).unwrap().contains(&Role::Signed));
    assert!(
        roles.touching(&view, message).unwrap().contains(&Role::Signed),
        "an edit's roles missed its subtree"
    );
    assert!(
        !roles.may_strip(&view, message, HookPoint::IngressParsed),
        "a strip removed a signed block it encloses"
    );
    assert!(
        !roles.may_strip(&view, thinking, HookPoint::IngressParsed),
        "a strip removed a signed block"
    );
    assert!(roles.may_strip(&view, text, HookPoint::IngressParsed));
    assert!(
        !roles.may_strip(&view, text, HookPoint::ToolResult),
        "a tool.result strip outside the tool result"
    );
    assert!(!roles.may_strip(&view, text, HookPoint::Classify));
}

#[test]
fn nested_any_depth_keys_resolve_once_each() {
    let body = br#"{"a":{"a":{"a":{"b":1}}},"c":{"a":2}}"#;
    let tape = parse(body, &Limits::DEFAULT).unwrap();
    let mask = Mask::new();
    let view = StructuralView::new(&tape, &mask);
    let first = sel(vec![Step::AnyDepthKey("a".into())]).resolve(&view).unwrap();
    assert_eq!(first.len(), 4);
    let second = sel(vec![Step::AnyDepthKey("a".into()), Step::AnyDepthKey("a".into())])
        .resolve(&view)
        .unwrap();
    assert_eq!(second, first[1..3].to_vec(), "nested subtrees changed the answer");
}

/// The naive two-step `AnyDepthKey` walk, as an oracle for the one that skips covered subtrees.
fn naive_any_depth(view: &StructuralView<'_, '_>, first: &str, second: &str) -> Vec<NodeId> {
    let level: Vec<_> = view.root().descendants().filter(|n| n.key_is(first).unwrap()).collect();
    let found: BTreeSet<NodeId> = level
        .iter()
        .flat_map(|n| {
            n.descendants()
                .filter(|d| d.key_is(second).unwrap())
                .map(|d| d.id())
                .collect::<Vec<_>>()
        })
        .collect();
    found.into_iter().collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn any_depth_keys_equal_the_naive_walk(doc in json(), first in prop::sample::select(vec!["a", "b", "content"]), second in prop::sample::select(vec!["a", "b", "type"])) {
        let tape = parse(doc.as_bytes(), &Limits::DEFAULT).unwrap();
        let mask = Mask::new();
        let view = StructuralView::new(&tape, &mask);
        let fast = sel(vec![Step::AnyDepthKey(first.into()), Step::AnyDepthKey(second.into())]).resolve(&view).unwrap();
        prop_assert_eq!(fast, naive_any_depth(&view, first, second));
    }
}

/// `{"messages":[{"role":"user","content":[{"type":"text","text":"t"}]}]}` with the message as the
/// newest human turn: (tape, message id, text block id, text value id).
fn one_turn() -> (uaos_json::Tape<'static>, NodeId, NodeId, NodeId) {
    let body: &'static [u8] = br#"{"messages":[{"role":"user","content":[{"type":"text","text":"t"}]}]}"#;
    let tape = parse(body, &Limits::DEFAULT).unwrap();
    let mask = Mask::new();
    let view = StructuralView::new(&tape, &mask);
    let message = sel(messages()).resolve(&view).unwrap()[0];
    let mut blocks = messages();
    blocks.extend([Step::Key("content".into()), Step::Each]);
    let block = sel(blocks.clone()).resolve(&view).unwrap()[0];
    blocks.push(Step::Key("text".into()));
    let text = sel(blocks).resolve(&view).unwrap()[0];
    (tape, message, block, text)
}

/// A strip never removes its own anchor, and never touches masked content (whose role a codec could
/// not see).
#[test]
fn a_strip_keeps_its_anchor_and_masked_content() {
    use uaos_module_api::HookPoint;
    let (tape, message, block, text) = one_turn();
    let plain = Mask::new();
    let view = StructuralView::new(&tape, &plain);
    let mut roles = RoleMap::new();
    roles.assign(&view, &sel(messages()), Role::NewestHumanTurn).unwrap();
    assert!(roles.may_strip(&view, block, HookPoint::IngressParsed));
    assert!(
        !roles.may_strip(&view, message, HookPoint::IngressParsed),
        "a strip removed its own anchor"
    );
    let mut mask = Mask::new();
    mask.value(text);
    let sealed = mask.seal(&tape).unwrap();
    let masked = sealed.view();
    assert!(
        !roles.may_strip(&masked, block, HookPoint::IngressParsed),
        "a strip touched masked content"
    );
}

#[test]
fn a_mask_naming_a_node_off_the_tape_refuses_to_seal() {
    let big = parse(DOC.as_bytes(), &Limits::DEFAULT).unwrap();
    let mask = Mask::new();
    let last = StructuralView::new(&big, &mask)
        .root()
        .descendants()
        .last()
        .unwrap()
        .id();
    let small = parse(b"[1]", &Limits::DEFAULT).unwrap();
    let mut off = Mask::new();
    off.value(last);
    assert_eq!(off.seal(&small).err(), Some(uaos_module_api::MaskError));
}

/// Every resolution spends a visit budget, and stops when it is spent.
#[test]
fn a_selector_stops_at_its_budget() {
    let tape = parse(DOC.as_bytes(), &Limits::DEFAULT).unwrap();
    let mask = Mask::new();
    let view = StructuralView::new(&tape, &mask);
    let selector = sel(vec![Step::AnyDepthKey("text".into())]);
    let mut tight = Visits::new(3);
    assert_eq!(
        selector.resolve_within(&view, &mut tight),
        Err(SelectorError::Budget),
        "a selector ran past its budget"
    );
    let mut ample = Visits::per_call();
    assert!(selector.resolve_within(&view, &mut ample).is_ok());
    let nodes = view.root().descendants().count();
    assert!(
        Visits::per_call().left() - ample.left() <= nodes,
        "one AnyDepthKey step visited a node twice"
    );
}

/// A usage report names only the dimensions its codec declares, each once.
#[test]
fn usage_reports_name_declared_dimensions_once() {
    let code = |s: &str| Code::new(s).unwrap();
    let report = UsageReport::new().dim(code("input_tokens"), 10).unwrap();
    assert!(
        report.clone().dim(code("input_tokens"), 3).is_err(),
        "a dimension twice"
    );
    assert_eq!(report.check(&[code("input_tokens")]), Ok(()));
    let words = report.dim(code("secret_word"), 1).unwrap();
    assert_eq!(
        words.check(&[code("input_tokens")]),
        Err(uaos_module_api::CodecError::UndeclaredDimension),
        "an undeclared billing dimension was accepted"
    );
}

#[test]
fn an_unlisted_method_is_denied() {
    let endpoints = [EndpointDecl::new(
        Method::Post,
        PathPattern::new("/v1/messages").unwrap(),
        EndpointClass::Governed,
    )];
    for method in [Method::Get, Method::Put, Method::Patch, Method::Options, Method::Delete] {
        assert_eq!(
            classify(&endpoints, method, "/v1/messages"),
            EndpointClass::Denied,
            "{method:?}"
        );
    }
}

/// An object with `n` members, none named `absent`.
fn wide(n: usize) -> String {
    let members: Vec<String> = (0..n).map(|i| format!("\"m{i}\":0")).collect();
    format!("{{{}}}", members.join(","))
}

#[test]
fn a_lookup_spends_a_visit_per_member() {
    // A `Key` step and every predicate's lookup each spend a visit per member examined
    // (`MemberNotIn` and `StringOrArrayWith` included).
    let doc = wide(5_000);
    let tape = parse(doc.as_bytes(), &Limits::DEFAULT).unwrap();
    let none = Mask::new();
    let view = StructuralView::new(&tape, &none);
    let member_in = |key: &str| Predicate::MemberIn {
        key: key.to_owned(),
        values: BTreeSet::from(["x".to_owned()]),
    };
    // Each lookup, and how many nodes it selects in the object, which has no `absent` member.
    let lookups = [
        (Selector::new(vec![Step::Key("absent".to_owned())]).unwrap(), 0),
        (Selector::new(vec![Step::Where(member_in("absent"))]).unwrap(), 0),
        (
            Selector::new(vec![Step::Where(Predicate::MemberNotIn {
                key: "absent".to_owned(),
                values: BTreeSet::from(["x".to_owned()]),
            })])
            .unwrap(),
            1,
        ),
        (
            Selector::new(vec![Step::Where(Predicate::StringOrArrayWith {
                key: "absent".to_owned(),
                element: Box::new(member_in("k")),
            })])
            .unwrap(),
            0,
        ),
    ];
    for (selector, selected) in &lookups {
        assert_eq!(
            selector.resolve_within(&view, &mut Visits::new(1_000)),
            Err(SelectorError::Budget),
            "a member scan was not charged"
        );
        let mut ample = Visits::per_call();
        assert_eq!(
            selector.resolve_within(&view, &mut ample).map(|ids| ids.len()),
            Ok(*selected)
        );
        assert!(
            Visits::per_call().left() - ample.left() >= 5_000,
            "a member scan was not charged"
        );
    }
}

#[test]
fn each_child_and_array_element_spends_a_visit() {
    // `Each` charges every child it selects, and a predicate every node it examines, the elements
    // `StringOrArrayWith` tests included.
    let array = format!("[{}]", vec!["0"; 5_000].join(","));
    let wrapped = format!("{{\"k\":{array}}}");
    let element = Predicate::MemberIn {
        key: "x".to_owned(),
        values: BTreeSet::from(["y".to_owned()]),
    };
    let cases = [
        (array, Selector::new(vec![Step::Each]).unwrap()),
        (
            wrapped,
            Selector::new(vec![Step::Where(Predicate::StringOrArrayWith {
                key: "k".to_owned(),
                element: Box::new(element),
            })])
            .unwrap(),
        ),
    ];
    for (doc, selector) in &cases {
        let tape = parse(doc.as_bytes(), &Limits::DEFAULT).unwrap();
        let none = Mask::new();
        let view = StructuralView::new(&tape, &none);
        assert_eq!(
            selector.resolve_within(&view, &mut Visits::new(1_000)),
            Err(SelectorError::Budget),
            "a child or an element was examined uncharged"
        );
    }
}

#[test]
fn a_value_finding_on_a_literal_refuses_the_seal() {
    // A value finding on `true`, `false` or `null` masks nothing, so it is misplaced and refuses
    // the seal, as a key finding on a keyless node does.
    let tape = parse(br#"{"k":"v","b":true,"f":false,"n":null,"s":"x"}"#, &Limits::DEFAULT).unwrap();
    let none = Mask::new();
    let root = StructuralView::new(&tape, &none).root();
    for name in ["b", "f", "n"] {
        let mut mask = Mask::new();
        mask.value(root.member(name).unwrap().unwrap().id());
        assert_eq!(
            mask.seal(&tape).err(),
            Some(MaskError),
            "a value finding on a literal was sealed: {name}"
        );
    }
    let mut mask = Mask::new();
    mask.value(root.member("s").unwrap().unwrap().id());
    assert!(mask.seal(&tape).is_ok());
}

#[test]
fn a_string_that_decodes_short_enough_still_matches() {
    // The raw-length shortcut refuses only what cannot decode to a value. 256 six-byte escapes are
    // 1,536 raw bytes, exactly the bound, and decode to 256 bytes.
    let escaped = "~u0041".repeat(MAX_SELECTOR_TEXT).replace('~', "\\");
    let doc = format!("{{\"k\":\"{escaped}\"}}");
    let tape = parse(doc.as_bytes(), &Limits::DEFAULT).unwrap();
    let none = Mask::new();
    let view = StructuralView::new(&tape, &none);
    let value = "A".repeat(MAX_SELECTOR_TEXT);
    let selector = Selector::new(vec![Step::Where(Predicate::MemberIn {
        key: "k".to_owned(),
        values: BTreeSet::from([value]),
    })])
    .unwrap();
    assert_eq!(
        selector.resolve(&view).map(|ids| ids.len()),
        Ok(1),
        "an escaped string that decodes to a value was refused"
    );
    // One byte past the bound decodes past any value, and is equal to none.
    let long = format!("{{\"k\":\"{}\"}}", "A".repeat(6 * MAX_SELECTOR_TEXT + 1));
    let tape = parse(long.as_bytes(), &Limits::DEFAULT).unwrap();
    let view = StructuralView::new(&tape, &none);
    assert_eq!(selector.resolve(&view).map(|ids| ids.len()), Ok(0));
}

#[test]
fn a_codecs_roles_share_one_budget() {
    // Every assignment to one `RoleMap` spends from one budget, so `roles()` is bounded however
    // many selectors a codec assigns.
    let doc = wide(4_000);
    let tape = parse(doc.as_bytes(), &Limits::DEFAULT).unwrap();
    let none = Mask::new();
    let view = StructuralView::new(&tape, &none);
    let selector = Selector::new(vec![Step::AnyDepthKey("absent".to_owned())]).unwrap();
    let mut roles = RoleMap::new();
    let mut exhausted = false;
    for _ in 0..1_000 {
        if roles.assign(&view, &selector, Role::SystemMessage) == Err(SelectorError::Budget) {
            exhausted = true;
            break;
        }
    }
    assert!(exhausted, "a codec's roles each got a fresh budget");
    assert_eq!(roles.visits_left(), 0);
}

#[test]
fn a_key_finding_on_a_keyless_node_refuses_the_seal() {
    let tape = parse(br#"{"a":[1,2]}"#, &Limits::DEFAULT).unwrap();
    let none = Mask::new();
    let view = StructuralView::new(&tape, &none);
    let nodes: Vec<(NodeId, bool)> = view
        .root()
        .descendants()
        .map(|n| (n.id(), n.key().unwrap().is_some()))
        .collect();
    let keyed = nodes.iter().find(|(_, has)| *has).unwrap().0;
    let keyless = nodes.iter().find(|(_, has)| !*has).unwrap().0;
    let mut ok = Mask::new();
    ok.key(keyed);
    assert!(ok.seal(&tape).is_ok());
    for id in [keyless, view.root().id()] {
        let mut bad = Mask::new();
        bad.key(id);
        assert_eq!(
            bad.seal(&tape).err(),
            Some(MaskError),
            "a key finding on a keyless node was sealed"
        );
    }
}

#[test]
fn a_sealed_view_reads_its_own_tape_sealed() {
    // The seal holds the tape it was made for and builds the view, so it is never used over another
    // tape: a buffer refilled with another document of the same length cannot be, since the seal
    // borrows it. On its own tape the seal is used and holds.
    let tape = parse(br#"{"a":{"x":"1"},"b":"2"}"#, &Limits::DEFAULT).unwrap();
    let none = Mask::new();
    let ids: Vec<NodeId> = StructuralView::new(&tape, &none)
        .root()
        .descendants()
        .map(|n| n.id())
        .collect();
    let mut mask = Mask::new();
    mask.value(ids[0]);
    assert!(!StructuralView::new(&tape, &mask).is_sealed());
    let sealed = mask.seal(&tape).unwrap();
    let view = sealed.view();
    assert!(view.is_sealed(), "a sealed mask built an unsealed view");
    // Inside the masked container `a`, its member `x` reads masked; `b` outside it reads plain.
    assert_eq!(view.node(ids[1]).unwrap().key().unwrap(), Some(ViewText::Masked));
    let b = view.root().member("b").unwrap().unwrap();
    assert_eq!(b.key().unwrap(), Some(ViewText::Plain("b".into())));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// A sealed mask answers exactly as the unsealed one, on every node.
    #[test]
    fn sealed_and_unsealed_views_agree(doc in json(), masked in prop::collection::vec((any::<u16>(), any::<bool>()), 0..6)) {
        let tape = parse(doc.as_bytes(), &Limits::DEFAULT).unwrap();
        let plain = Mask::new();
        let plain_view = StructuralView::new(&tape, &plain);
        let ids: Vec<NodeId> = plain_view.root().descendants().map(|n| n.id()).collect();
        let mut mask = Mask::new();
        for (pick, key) in &masked {
            if let Some(id) = ids.get(usize::from(*pick) % ids.len().max(1)) {
                // A key finding goes only where a key is: elsewhere it refuses the seal.
                let has_key = plain_view.node(*id).is_some_and(|n| n.key().unwrap().is_some());
                // A value finding goes only on a value: on a literal it refuses the seal.
                let literal = plain_view.node(*id).is_some_and(|n| matches!(n.kind(), Kind::True | Kind::False | Kind::Null));
                if *key && has_key { mask.key(*id) } else if !literal { mask.value(*id) }
            }
        }
        let sealed = mask.seal(&tape).unwrap();
        let (slow, fast) = (StructuralView::new(&tape, &mask), sealed.view());
        for id in &ids {
            let (a, b) = (slow.node(*id).unwrap(), fast.node(*id).unwrap());
            prop_assert_eq!(a.key().unwrap(), b.key().unwrap(), "a sealed view disagreed with an unsealed one");
            prop_assert_eq!(a.text().unwrap(), b.text().unwrap(), "a sealed view disagreed with an unsealed one");
            prop_assert_eq!(a.number_text(), b.number_text(), "a sealed view disagreed with an unsealed one");
            prop_assert_eq!(
                slow.touches_masked(*id),
                fast.touches_masked(*id),
                "a sealed view disagreed with an unsealed one"
            );
        }
    }
}
