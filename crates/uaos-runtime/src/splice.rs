// SPDX-License-Identifier: Apache-2.0

//! The splice plan: the kernel performs every edit of a request, as a span splice on its bytes,
//! after checking each one against the roles the dialect codec assigned.
//!
//! An edit names a node of the tape, never a byte offset. Validation is all or nothing and runs
//! before any byte changes; applying copies every byte outside the edited spans unchanged, and
//! the output is parsed again under the request's limits.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;

use uaos_contracts::error::{ErrorCode, codes};
use uaos_json::{ErrorKind, JsonError, Kind, Limits, Node, NodeId, Tape};
use uaos_module_api::{Mask, ModuleText, Role, RoleMap, StructuralView};

/// The most edits one plan may hold. A module host bounds its declarations long before this; the
/// splicer bounds itself too.
pub const MAX_EDITS: usize = 4_096;

/// The role a live edit must lie inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Anchor {
    /// The newest human turn: tag strips and appends from `ingress.parsed` and
    /// `context.assemble`.
    NewestHumanTurn,
    /// The newest tool result: strips from `tool.result`.
    NewestToolResult,
}

impl Anchor {
    const fn role(self) -> Role {
        match self {
            Self::NewestHumanTurn => Role::NewestHumanTurn,
            Self::NewestToolResult => Role::NewestToolResult,
        }
    }
}

/// Where an edit comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// From this turn's hooks: it must lie strictly inside its anchor.
    Live(Anchor),
    /// Pinned on an earlier turn and replayed: it may lie outside the newest turn, and never in a
    /// role that forbids edits.
    Replayed,
}

/// What an edit does.
#[derive(Clone, PartialEq, Eq)]
enum Change {
    /// Removes an array element, or an object member with its key, and one comma.
    Strip,
    /// Writes the text at the end of a string value, escaped as JSON.
    Append(ModuleText),
}

/// One edit: a node, what to do there, and where the edit comes from.
#[derive(Clone, PartialEq, Eq)]
pub struct Edit {
    node: NodeId,
    change: Change,
    class: Class,
}

impl fmt::Debug for Edit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the text: a module's text is request content (red line 2).
        let change = match &self.change {
            Change::Strip => "strip",
            Change::Append(_) => "append",
        };
        f.debug_struct("Edit")
            .field("node", &self.node.get())
            .field("change", &change)
            .field("class", &self.class)
            .finish()
    }
}

impl Edit {
    /// Removes the element or member at `node`.
    #[must_use]
    pub const fn strip(node: NodeId, class: Class) -> Self {
        Self {
            node,
            change: Change::Strip,
            class,
        }
    }

    /// Appends `text` to the string at `node`.
    #[must_use]
    pub const fn append(node: NodeId, text: ModuleText, class: Class) -> Self {
        Self {
            node,
            change: Change::Append(text),
            class,
        }
    }

    /// The node it names.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Where it comes from.
    #[must_use]
    pub const fn class(&self) -> Class {
        self.class
    }
}

/// The edits for one request, as the module host resolved them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SplicePlan {
    edits: Vec<Edit>,
}

impl SplicePlan {
    /// An empty plan: the request leaves as redaction left it.
    #[must_use]
    pub const fn new() -> Self {
        Self { edits: Vec::new() }
    }

    /// Adds an edit.
    pub fn push(&mut self, edit: Edit) {
        self.edits.push(edit);
    }

    /// Whether it holds no edit.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.edits.is_empty()
    }

    /// Its edits, in the order they were added.
    #[must_use]
    pub fn edits(&self) -> &[Edit] {
        &self.edits
    }
}

impl FromIterator<Edit> for SplicePlan {
    fn from_iter<I: IntoIterator<Item = Edit>>(iter: I) -> Self {
        Self {
            edits: iter.into_iter().collect(),
        }
    }
}

/// Why a plan was refused. Nothing was changed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SpliceError {
    /// More than [`MAX_EDITS`] edits.
    #[error("the plan holds more than 4096 edits")]
    TooManyEdits,
    /// An edit names a node that is not on the tape.
    #[error("an edit names a node that is not on the tape")]
    UnknownNode,
    /// An edit strips the root.
    #[error("an edit strips the whole request")]
    StripsRoot,
    /// An append names a value that is not a string.
    #[error("an append names a value that is not a string")]
    AppendNotString,
    /// Two edits name the same node, or one lies inside what another strips.
    #[error("two edits overlap")]
    Overlap,
    /// A live edit lies outside its anchor.
    #[error("a live edit lies outside its anchor")]
    OutsideAnchor,
    /// An edit touches a role that forbids edits.
    #[error("an edit touches content that is never edited")]
    ForbiddenRole,
    /// An edit touches what redaction masked.
    #[error("an edit touches masked content")]
    Masked,
    /// The body is not JSON, so no node can be named.
    #[error("the body is not JSON")]
    NotJson,
    /// The edited body passes a tokenizer limit.
    #[error("the edited body passes a limit ({0})")]
    TooLarge(&'static str),
    /// The body, or the edited body, does not parse: the kernel's own fault.
    #[error("the edited body does not parse ({0})")]
    Unparsable(&'static str),
    /// Memory for the edited body was refused.
    #[error("out of memory while splicing")]
    OutOfMemory,
}

impl SpliceError {
    /// The registered code that ends the Operation.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::TooLarge(_) => codes::INGRESS_TOO_LARGE,
            Self::OutOfMemory => codes::RUNTIME_OVERLOAD,
            _ => codes::RUNTIME_EDIT_REFUSED,
        }
    }
}

fn parse_refusal(error: JsonError) -> SpliceError {
    match error.kind() {
        ErrorKind::TooLarge | ErrorKind::DepthExceeded | ErrorKind::TooManyNodes | ErrorKind::KeyTooLong => {
            SpliceError::TooLarge(error.kind().code())
        }
        ErrorKind::OutOfMemory => SpliceError::OutOfMemory,
        _ => SpliceError::Unparsable(error.kind().code()),
    }
}

/// Validates `plan` against `body`'s tape, the codec's `roles` and redaction's `mask`, then applies
/// it. `Ok(None)` for an empty plan, which parses nothing.
///
/// # Errors
/// [`SpliceError`] for a refused plan or an edited body that does not parse under `limits`;
/// nothing is changed.
pub fn splice(
    body: &[u8],
    limits: &Limits,
    mask: &Mask,
    roles: &RoleMap,
    plan: &SplicePlan,
) -> Result<Option<Vec<u8>>, SpliceError> {
    if plan.is_empty() {
        return Ok(None);
    }
    let tape = uaos_json::parse(body, limits).map_err(parse_refusal)?;
    let sealed = mask.seal(&tape).map_err(|_| SpliceError::Unparsable("mask-off-tape"))?;
    validate(&sealed.view(), roles, plan)?;
    let out = apply(&tape, plan)?;
    uaos_json::parse(&out, limits).map_err(parse_refusal)?;
    Ok(Some(out))
}

/// Checks every edit, all before any byte changes.
///
/// # Errors
/// The first rule an edit breaks.
pub fn validate(view: &StructuralView<'_, '_>, roles: &RoleMap, plan: &SplicePlan) -> Result<(), SpliceError> {
    if plan.edits.len() > MAX_EDITS {
        return Err(SpliceError::TooManyEdits);
    }
    for edit in &plan.edits {
        let node = view.node(edit.node).ok_or(SpliceError::UnknownNode)?;
        let parent = node.parent();
        match &edit.change {
            Change::Strip if parent.is_none() => return Err(SpliceError::StripsRoot),
            Change::Append(_) if node.kind() != Kind::String => return Err(SpliceError::AppendNotString),
            _ => {}
        }
        if let Class::Live(anchor) = edit.class {
            // Strictly inside the anchor: its parent is governed by the anchor's role.
            let inside = parent
                .and_then(|p| roles.governing(view, p.id()))
                .is_some_and(|governing| governing.contains(&anchor.role()));
            if !inside {
                return Err(SpliceError::OutsideAnchor);
            }
        }
        let touching = roles.touching(view, edit.node).ok_or(SpliceError::UnknownNode)?;
        if touching.iter().any(|role| role.forbids_edit()) {
            return Err(SpliceError::ForbiddenRole);
        }
        if view.touches_masked(edit.node) {
            return Err(SpliceError::Masked);
        }
    }
    // No node twice, and nothing inside a stripped subtree: subtrees are contiguous id ranges
    // that nest or are disjoint, so in id order an edit lies inside an earlier strip exactly when
    // its id is below the furthest end any earlier strip reaches.
    let mut order: Vec<&Edit> = plan.edits.iter().collect();
    order.sort_by_key(|e| e.node);
    let mut previous: Option<NodeId> = None;
    let mut covered_until = 0u32;
    for edit in order {
        if previous == Some(edit.node) || edit.node.get() < covered_until {
            return Err(SpliceError::Overlap);
        }
        previous = Some(edit.node);
        if edit.change == Change::Strip {
            let end = view.node(edit.node).ok_or(SpliceError::UnknownNode)?.subtree_end();
            covered_until = covered_until.max(end.get());
        }
    }
    Ok(())
}

/// One byte operation on the input.
enum Op {
    Remove(Range<usize>),
    Insert(usize, Vec<u8>),
}

impl Op {
    const fn at(&self) -> usize {
        match self {
            Self::Remove(range) => range.start,
            Self::Insert(at, _) => *at,
        }
    }
}

/// Where a child starts: its key's opening quote for a member, else its value.
fn child_start(node: &Node<'_, '_>) -> usize {
    node.key_span()
        .map_or(node.span().range().start, |key| key.range().start)
}

/// The byte operations of a validated plan, then the output.
fn apply(tape: &Tape<'_>, plan: &SplicePlan) -> Result<Vec<u8>, SpliceError> {
    let input = tape.input().as_bytes();
    let mut ops: Vec<Op> = Vec::new();
    let mut stripped: BTreeMap<NodeId, Vec<NodeId>> = BTreeMap::new();
    for edit in &plan.edits {
        let node = tape.node(edit.node).ok_or(SpliceError::UnknownNode)?;
        match &edit.change {
            Change::Strip => {
                let parent = node.parent().ok_or(SpliceError::StripsRoot)?;
                stripped.entry(parent.id()).or_default().push(edit.node);
            }
            Change::Append(text) => {
                let content = node.content_span().ok_or(SpliceError::AppendNotString)?;
                let mut quoted = Vec::new();
                uaos_json::encode_str(text.as_str(), &mut quoted).map_err(|_| SpliceError::OutOfMemory)?;
                let inner = quoted
                    .get(1..quoted.len().saturating_sub(1))
                    .ok_or(SpliceError::Unparsable("encode"))?
                    .to_vec();
                ops.push(Op::Insert(content.range().end, inner));
            }
        }
    }
    // Strips, parent by parent: each maximal run of removed siblings goes with one comma.
    for (parent, removed) in stripped {
        let parent = tape.node(parent).ok_or(SpliceError::UnknownNode)?;
        let children: Vec<Node<'_, '_>> = parent.children().collect();
        let gone = |i: usize| children.get(i).is_some_and(|c| removed.contains(&c.id()));
        let mut i = 0;
        while i < children.len() {
            if !gone(i) {
                i += 1;
                continue;
            }
            let mut j = i;
            while gone(j + 1) {
                j += 1;
            }
            let (first, last) = (children.get(i), children.get(j));
            let (Some(first), Some(last)) = (first, last) else {
                return Err(SpliceError::UnknownNode);
            };
            let range = match (i.checked_sub(1).and_then(|k| children.get(k)), children.get(j + 1)) {
                // After a kept sibling: from its end, so the comma before the run goes.
                (Some(kept), _) => kept.span().range().end..last.span().range().end,
                // First in its parent, before a kept sibling: up to that sibling, comma included.
                (None, Some(kept)) => child_start(first)..child_start(kept),
                // Every child: the container keeps its brackets and the whitespace around.
                (None, None) => child_start(first)..last.span().range().end,
            };
            ops.push(Op::Remove(range));
            i = j + 1;
        }
    }
    ops.sort_by_key(Op::at);
    let removed: usize = ops
        .iter()
        .map(|op| match op {
            Op::Remove(r) => r.len(),
            Op::Insert(..) => 0,
        })
        .sum();
    let inserted: usize = ops
        .iter()
        .map(|op| match op {
            Op::Insert(_, bytes) => bytes.len(),
            Op::Remove(_) => 0,
        })
        .sum();
    let mut out = Vec::new();
    out.try_reserve_exact(input.len().saturating_sub(removed).saturating_add(inserted))
        .map_err(|_| SpliceError::OutOfMemory)?;
    let mut cursor = 0;
    for op in ops {
        let at = op.at();
        // Validation keeps operations apart; a defect here fails closed.
        let before = input.get(cursor..at).ok_or(SpliceError::Overlap)?;
        out.extend_from_slice(before);
        match op {
            Op::Remove(range) => cursor = range.end,
            Op::Insert(_, bytes) => {
                out.extend_from_slice(&bytes);
                cursor = at;
            }
        }
    }
    out.extend_from_slice(input.get(cursor..).ok_or(SpliceError::Overlap)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test harness: a failed fixture fails the test that called it"
    )]

    use std::collections::BTreeSet;

    use proptest::prelude::*;
    use serde_json::{Value, json};
    use uaos_module_api::{Predicate, Selector, Step};

    use super::*;

    fn tape(json: &str) -> Tape<'_> {
        uaos_json::parse(json.as_bytes(), &Limits::DEFAULT).unwrap()
    }

    /// The node at `path` (member names, or element indexes as digits) under the root.
    fn at(tape: &Tape<'_>, path: &[&str]) -> NodeId {
        let mut node = tape.root();
        for step in path {
            node = match step.parse::<usize>() {
                Ok(i) => node.children().nth(i).unwrap(),
                Err(_) => node.member(step).unwrap().unwrap(),
            };
        }
        node.id()
    }

    fn text(s: &str) -> ModuleText {
        ModuleText::new(s).unwrap()
    }

    /// The bytes a plan writes, without validation: the splicer's own arithmetic.
    fn applied(json: &str, edits: &[(&[&str], Option<&str>)]) -> String {
        let t = tape(json);
        let plan: SplicePlan = edits
            .iter()
            .map(|(path, append)| match append {
                None => Edit::strip(at(&t, path), Class::Replayed),
                Some(s) => Edit::append(at(&t, path), text(s), Class::Replayed),
            })
            .collect();
        String::from_utf8(apply(&t, &plan).unwrap()).unwrap()
    }

    /// One comma goes with each run of stripped siblings, wherever the run is; whitespace and
    /// every other byte stay.
    #[test]
    fn strips_take_exactly_one_comma() {
        assert_eq!(applied("[1,2,3]", &[(&["0"], None)]), "[2,3]");
        assert_eq!(applied("[1,2,3]", &[(&["1"], None)]), "[1,3]");
        assert_eq!(applied("[1,2,3]", &[(&["2"], None)]), "[1,2]");
        assert_eq!(applied("[1, 2, 3]", &[(&["0"], None), (&["1"], None)]), "[3]");
        assert_eq!(applied("[1, 2, 3]", &[(&["1"], None), (&["2"], None)]), "[1]");
        assert_eq!(applied("[1, 2, 3]", &[(&["0"], None), (&["2"], None)]), "[2]");
        assert_eq!(applied("[ 1 , 2 ]", &[(&["0"], None), (&["1"], None)]), "[  ]");
        assert_eq!(
            applied(r#"{"a":1, "b":{"c":2}, "d":3}"#, &[(&["b"], None)]),
            r#"{"a":1, "d":3}"#
        );
        assert_eq!(applied(r#"{"a":1,"b":2}"#, &[(&["a"], None)]), r#"{"b":2}"#);
        assert_eq!(
            applied("{\n  \"a\": [\n    1,\n    2\n  ]\n}", &[(&["a", "1"], None)]),
            "{\n  \"a\": [\n    1\n  ]\n}"
        );
    }

    /// An append is escaped by the kernel's one encoder and lands before the closing quote.
    #[test]
    fn appends_are_escaped_and_land_inside_the_string() {
        assert_eq!(
            applied(r#"{"t":"x"}"#, &[(&["t"], Some("a\"b\\c\nİ🙂"))]),
            r#"{"t":"xa\"b\\c\nİ🙂"}"#
        );
        assert_eq!(
            applied(r#"["","y"]"#, &[(&["0"], Some("z")), (&["1"], None)]),
            r#"["z"]"#
        );
    }

    fn view_check(json: &str, edits: Vec<Edit>) -> Result<(), SpliceError> {
        let t = tape(json);
        let mask = Mask::new();
        let sealed = mask.seal(&t).unwrap();
        validate(&sealed.view(), &RoleMap::new(), &edits.into_iter().collect())
    }

    /// The structural refusals, each before any byte changes.
    #[test]
    fn malformed_plans_are_refused() {
        let doc = r#"{"a":[1,"s",{"b":2}]}"#;
        let t = tape(doc);
        let (root, arr, num, s, obj, b) = (
            at(&t, &[]),
            at(&t, &["a"]),
            at(&t, &["a", "0"]),
            at(&t, &["a", "1"]),
            at(&t, &["a", "2"]),
            at(&t, &["a", "2", "b"]),
        );
        let r = Class::Replayed;
        assert_eq!(
            view_check(doc, vec![Edit::strip(root, r)]),
            Err(SpliceError::StripsRoot)
        );
        assert_eq!(
            view_check(doc, vec![Edit::append(num, text("x"), r)]),
            Err(SpliceError::AppendNotString)
        );
        assert_eq!(
            view_check(doc, vec![Edit::strip(NodeId::ROOT, r), Edit::strip(num, r)]),
            Err(SpliceError::StripsRoot)
        );
        let beyond = tape(r"[[[[[[[[[[1]]]]]]]]]]");
        assert_eq!(
            view_check(
                doc,
                vec![Edit::strip(
                    at(&beyond, &["0", "0", "0", "0", "0", "0", "0", "0", "0", "0"]),
                    r
                )]
            ),
            Err(SpliceError::UnknownNode)
        );
        assert_eq!(
            view_check(doc, vec![Edit::strip(s, r), Edit::strip(s, r)]),
            Err(SpliceError::Overlap)
        );
        assert_eq!(
            view_check(doc, vec![Edit::strip(obj, r), Edit::strip(b, r)]),
            Err(SpliceError::Overlap)
        );
        assert_eq!(
            view_check(doc, vec![Edit::strip(arr, r), Edit::append(s, text("x"), r)]),
            Err(SpliceError::Overlap)
        );
        assert_eq!(
            view_check(
                doc,
                vec![Edit::strip(num, r), Edit::append(s, text("x"), r), Edit::strip(b, r)]
            ),
            Ok(())
        );
        let many = vec![Edit::strip(num, r); MAX_EDITS + 1];
        assert_eq!(view_check(doc, many), Err(SpliceError::TooManyEdits));
        assert_eq!(
            view_check(doc, vec![Edit::strip(num, Class::Live(Anchor::NewestHumanTurn))]),
            Err(SpliceError::OutsideAnchor),
            "no roles, so no anchor"
        );
    }

    /// An edit that would push the body past a limit is refused with the limit's code, and an
    /// empty plan parses nothing.
    #[test]
    fn limits_hold_after_splicing() {
        let doc = r#"{"t":"x"}"#;
        let limits = Limits::new(12, 8, 16).unwrap();
        let t = uaos_json::parse(doc.as_bytes(), &limits).unwrap();
        let plan: SplicePlan = [Edit::append(at(&t, &["t"]), text("long text"), Class::Replayed)]
            .into_iter()
            .collect();
        let refused = splice(doc.as_bytes(), &limits, &Mask::new(), &RoleMap::new(), &plan);
        assert_eq!(
            refused.as_ref().map_err(SpliceError::code),
            Err(codes::INGRESS_TOO_LARGE)
        );
        assert_eq!(
            splice(b"not json", &limits, &Mask::new(), &RoleMap::new(), &SplicePlan::new()),
            Ok(None)
        );
    }

    // ---- The role property, over Messages-shaped requests. ----

    fn member_is(key: &str, value: &str) -> Step {
        Step::Where(Predicate::MemberIn {
            key: key.to_owned(),
            values: BTreeSet::from([value.to_owned()]),
        })
    }

    /// The roles a codec would assign, through selectors only.
    fn codec_roles(view: &StructuralView<'_, '_>) -> RoleMap {
        let sel = |steps: Vec<Step>| Selector::new(steps).unwrap();
        let messages = || Step::Key("messages".to_owned());
        let mut roles = RoleMap::new();
        for (selector, role) in [
            (sel(vec![Step::Key("system".to_owned())]), Role::SystemEntry(0)),
            (sel(vec![Step::Key("metadata".to_owned())]), Role::Opaque),
            (
                sel(vec![messages(), Step::Each, member_is("role", "assistant")]),
                Role::ProviderProduced,
            ),
            (sel(vec![Step::AnyDepthKey("signature".to_owned())]), Role::Signed),
            (
                sel(vec![messages(), Step::Each, member_is("role", "user"), Step::Last]),
                Role::NewestHumanTurn,
            ),
        ] {
            roles.assign(view, &selector, role).unwrap();
        }
        roles
    }

    /// A Messages-shaped request: a system prompt, an earlier user turn, an assistant turn with a
    /// signed thinking block, the newest user turn and opaque metadata.
    #[derive(Debug, Clone)]
    struct Doc {
        system: Vec<String>,
        earlier: Vec<String>,
        assistant: Vec<String>,
        newest: Vec<String>,
        pretty: bool,
    }

    fn blocks(texts: &[String]) -> Vec<Value> {
        texts.iter().map(|t| json!({"type": "text", "text": t})).collect()
    }

    impl Doc {
        fn value(&self) -> Value {
            let mut assistant = vec![json!({"type": "thinking", "thinking": "t", "signature": "sig"})];
            assistant.extend(blocks(&self.assistant));
            json!({
                "system": blocks(&self.system),
                "messages": [
                    {"role": "user", "content": blocks(&self.earlier)},
                    {"role": "assistant", "content": assistant},
                    {"role": "user", "content": blocks(&self.newest)},
                ],
                "metadata": {"user_id": "u"},
            })
        }

        fn bytes(&self) -> String {
            if self.pretty {
                serde_json::to_string_pretty(&self.value()).unwrap()
            } else {
                serde_json::to_string(&self.value()).unwrap()
            }
        }
    }

    fn texts() -> impl Strategy<Value = Vec<String>> {
        let ch = prop::sample::select(vec!['a', 'z', ' ', 'é', 'ı', '"', '\\', '\n', '🙂']);
        let one = prop::collection::vec(ch, 0..6).prop_map(String::from_iter);
        prop::collection::vec(one, 1..5)
    }

    fn doc() -> impl Strategy<Value = Doc> {
        (texts(), texts(), texts(), texts(), any::<bool>()).prop_map(|(system, earlier, assistant, newest, pretty)| {
            Doc {
                system,
                earlier,
                assistant,
                newest,
                pretty,
            }
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Permitted edits in the newest human turn: the output's value is the model's, and every
        /// byte outside the newest turn, and every block left unedited, is unchanged.
        #[test]
        fn permitted_edits_change_only_their_spans(
            d in doc(),
            strip in prop::collection::vec(any::<bool>(), 4),
            append in prop::collection::vec(prop::option::of("[a-zé ]{1,4}"), 4),
        ) {
            let input = d.bytes();
            let t = tape(&input);
            let mask = Mask::new();
            let sealed = mask.seal(&t).unwrap();
            let roles = codec_roles(&sealed.view());
            let live = Class::Live(Anchor::NewestHumanTurn);
            let mut plan = SplicePlan::new();
            let mut model = d.value();
            let mut kept_unedited = Vec::new();
            let newest = model["messages"][2]["content"].as_array().unwrap().clone();
            let mut new_content = Vec::new();
            for (i, block) in newest.iter().enumerate() {
                let node = at(&t, &["messages", "2", "content", &i.to_string()]);
                if strip.get(i).copied().unwrap_or(false) {
                    plan.push(Edit::strip(node, live));
                } else if let Some(Some(extra)) = append.get(i) {
                    let s = at(&t, &["messages", "2", "content", &i.to_string(), "text"]);
                    plan.push(Edit::append(s, text(extra), live));
                    let mut b = block.clone();
                    b["text"] = Value::String(format!("{}{extra}", b["text"].as_str().unwrap()));
                    new_content.push(b);
                } else {
                    kept_unedited.push(t.node(node).unwrap().raw().to_owned());
                    new_content.push(block.clone());
                }
            }
            model["messages"][2]["content"] = Value::Array(new_content);
            let out = splice(input.as_bytes(), &Limits::DEFAULT, &mask, &roles, &plan).unwrap();
            let out = out.map_or(input.clone(), |b| String::from_utf8(b).unwrap());
            prop_assert_eq!(serde_json::from_str::<Value>(&out).unwrap(), model);
            let message = t.node(at(&t, &["messages", "2"])).unwrap().span().range();
            prop_assert_eq!(&out[..message.start], &input[..message.start]);
            prop_assert!(out.ends_with(&input[message.end..]));
            let mut from = message.start;
            for raw in kept_unedited {
                let found = out[from..].find(&raw);
                prop_assert!(found.is_some(), "an unedited block changed");
                from += found.unwrap_or(0) + raw.len();
            }
        }

        /// A plan with one edit that touches a forbidding role, lies outside its anchor or
        /// touches masked content is refused whole, beside any number of permitted edits.
        #[test]
        fn a_forbidden_edit_refuses_the_whole_plan(d in doc(), target in 0usize..9, permitted in any::<bool>()) {
            let input = d.bytes();
            let t = tape(&input);
            let live = Class::Live(Anchor::NewestHumanTurn);
            let mut mask = Mask::new();
            let (bad, expected) = match target {
                0 => (Edit::strip(at(&t, &["system", "0"]), Class::Replayed), SpliceError::ForbiddenRole),
                1 => (Edit::append(at(&t, &["system", "0", "text"]), text("x"), Class::Replayed), SpliceError::ForbiddenRole),
                2 => (Edit::strip(at(&t, &["messages", "1", "content", "1"]), Class::Replayed), SpliceError::ForbiddenRole),
                3 => (Edit::append(at(&t, &["messages", "1", "content", "0", "signature"]), text("x"), Class::Replayed), SpliceError::ForbiddenRole),
                4 => (Edit::strip(at(&t, &["metadata", "user_id"]), Class::Replayed), SpliceError::ForbiddenRole),
                5 => (Edit::strip(at(&t, &["messages", "0", "content", "0"]), live), SpliceError::OutsideAnchor),
                6 => (Edit::strip(at(&t, &["messages", "2"]), live), SpliceError::OutsideAnchor),
                7 => {
                    mask.value(at(&t, &["messages", "2", "content", "0", "text"]));
                    (Edit::strip(at(&t, &["messages", "2", "content", "0"]), live), SpliceError::Masked)
                }
                // A forbidding role inside what the strip removes, on no ancestor of it.
                _ => (Edit::strip(at(&t, &["messages"]), Class::Replayed), SpliceError::ForbiddenRole),
            };
            let sealed = mask.seal(&t).unwrap();
            let roles = codec_roles(&sealed.view());
            let mut plan = SplicePlan::new();
            if permitted && d.newest.len() > 1 {
                let last = (d.newest.len() - 1).to_string();
                plan.push(Edit::append(at(&t, &["messages", "2", "content", &last, "text"]), text("ok"), live));
            }
            plan.push(bad);
            prop_assert_eq!(validate(&sealed.view(), &roles, &plan), Err(expected));
            let refused = splice(input.as_bytes(), &Limits::DEFAULT, &mask, &roles, &plan);
            prop_assert_eq!(refused.map_err(|e| e.code()), Err(codes::RUNTIME_EDIT_REFUSED));
        }
    }

    /// A replayed edit may lie outside the newest turn, where a live one may not.
    #[test]
    fn replayed_edits_reach_earlier_turns() {
        let d = Doc {
            system: vec!["s".into()],
            earlier: vec!["a".into(), "b".into()],
            assistant: vec!["c".into()],
            newest: vec!["n".into()],
            pretty: false,
        };
        let input = d.bytes();
        let t = tape(&input);
        let mask = Mask::new();
        let sealed = mask.seal(&t).unwrap();
        let roles = codec_roles(&sealed.view());
        let node = at(&t, &["messages", "0", "content", "0"]);
        let replayed: SplicePlan = [Edit::strip(node, Class::Replayed)].into_iter().collect();
        assert_eq!(validate(&sealed.view(), &roles, &replayed), Ok(()));
        let live: SplicePlan = [Edit::strip(node, Class::Live(Anchor::NewestHumanTurn))]
            .into_iter()
            .collect();
        assert_eq!(validate(&sealed.view(), &roles, &live), Err(SpliceError::OutsideAnchor));
        let out = splice(input.as_bytes(), &Limits::DEFAULT, &mask, &roles, &replayed)
            .unwrap()
            .unwrap();
        let value: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["messages"][0]["content"], json!([{"type": "text", "text": "b"}]));
    }
}
