// SPDX-License-Identifier: Apache-2.0

//! Selectors: the only way a codec or a module names parts of a request. These primitives and no
//! more; growing them needs amended.
//!
//! A selector resolves to node ids taken from the tape itself, in document order and without
//! repeats, so it can never name anything outside the view. Its size is bounded (steps, nesting,
//! keys, the values a predicate lists), and each step selects a node at most once, even when the
//! nodes selected so far are nested inside one another. Every node a step or a predicate examines
//! spends one visit from a [`Visits`] budget, each member a lookup examines included, so a node
//! examined twice in one step spends twice: the budget counts examinations, not nodes. No
//! comparison decodes more than six times [`MAX_SELECTOR_TEXT`] bytes. With each visit O(log
//! ranges) against a sealed mask, one call costs at most [`MAX_VISITS`] visits, each
//! O(`MAX_SELECTOR_TEXT` + log ranges).
//!
//! **Masked content is unknown, never probed.** A masked string equals no value and a masked key
//! is no name, so a predicate's answer is the same whatever the masked text is.

use std::collections::BTreeSet;
use std::fmt;

use uaos_json::{Kind, NodeId};

use crate::view::{StructuralView, ViewNode, ViewText};

/// The most steps a selector may have.
pub const MAX_SELECTOR_STEPS: usize = 16;
/// The deepest a predicate may nest.
pub const MAX_PREDICATE_DEPTH: usize = 4;
/// The most values one predicate may list.
pub const MAX_PREDICATE_VALUES: usize = 32;
/// The longest key or value a selector names, in bytes.
pub const MAX_SELECTOR_TEXT: usize = 256;
/// The node visits one resolution may make, and the budget the host gives all of one call's
/// selectors together.
pub const MAX_VISITS: usize = 1 << 20;

/// A budget of node visits. Resolving a selector spends one visit per node it examines, and stops
/// with [`SelectorError::Budget`] when the budget is spent; for a module's call that is a strike.
/// Not `Copy` and not `Clone`: a budget is spent once, never duplicated.
#[derive(Debug, PartialEq, Eq)]
pub struct Visits(usize);

impl Visits {
    /// A budget of `n` visits.
    #[must_use]
    pub const fn new(n: usize) -> Self {
        Self(n)
    }

    /// The budget for one call's selectors, or one resolution: [`MAX_VISITS`].
    #[must_use]
    pub const fn per_call() -> Self {
        Self(MAX_VISITS)
    }

    /// The visits left.
    #[must_use]
    pub const fn left(&self) -> usize {
        self.0
    }

    fn spend(&mut self, n: usize) -> Result<(), SelectorError> {
        self.0 = self.0.checked_sub(n).ok_or(SelectorError::Budget)?;
        Ok(())
    }
}

/// The raw length past which a string decodes to more than [`MAX_SELECTOR_TEXT`] bytes: an escape
/// shrinks at most six raw bytes to one (`\\u0041` is `A`), so a longer one equals no value a
/// selector names, without being decoded.
const MAX_RAW_TEXT: usize = 6 * MAX_SELECTOR_TEXT;

/// `node`'s member `key`, spending one visit per member examined. A member whose key is masked is
/// never found, as for [`ViewNode::member`].
fn member_within<'v, 'a>(
    node: &ViewNode<'v, 'a>,
    key: &str,
    visits: &mut Visits,
) -> Result<Option<ViewNode<'v, 'a>>, SelectorError> {
    if node.kind() != Kind::Object {
        return Ok(None);
    }
    for child in node.children() {
        visits.spend(1)?;
        // A key compares as it decodes and stops at the first difference: O(key) at most.
        if child.key_is(key).map_err(|_| SelectorError::Undecodable)? {
            return Ok(Some(child));
        }
    }
    Ok(None)
}

/// Whether `member` is a string in `values`. A masked or non-string member is in no set, and a
/// string too long to decode to any value is in none without being decoded.
fn in_values(member: Option<ViewNode<'_, '_>>, values: &BTreeSet<String>) -> Result<bool, SelectorError> {
    let Some(member) = member else {
        return Ok(false);
    };
    if member.raw_text_len().is_some_and(|len| len > MAX_RAW_TEXT) {
        return Ok(false);
    }
    match member.text().map_err(|_| SelectorError::Undecodable)? {
        Some(ViewText::Plain(text)) => Ok(values.contains(text.as_ref())),
        Some(ViewText::Masked) | None => Ok(false),
    }
}

/// A selector that is too long, nests too deep, or names an empty or overlong key or value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SelectorError {
    /// More than [`MAX_SELECTOR_STEPS`] steps.
    #[error("a selector has at most {MAX_SELECTOR_STEPS} steps")]
    TooLong,
    /// A predicate nested deeper than [`MAX_PREDICATE_DEPTH`].
    #[error("predicates nest at most {MAX_PREDICATE_DEPTH} deep")]
    TooDeep,
    /// An empty key, or a key or value over [`MAX_SELECTOR_TEXT`] bytes.
    #[error("a selector key is 1 to {MAX_SELECTOR_TEXT} bytes, and a value at most {MAX_SELECTOR_TEXT}")]
    Key,
    /// More than [`MAX_PREDICATE_VALUES`] values in one predicate.
    #[error("a predicate lists at most {MAX_PREDICATE_VALUES} values")]
    TooManyValues,
    /// The visit budget ran out ([`Visits`]).
    #[error("the selector ran past its visit budget")]
    Budget,
    /// A key or string in the view that does not decode, which a tape never holds.
    #[error("the view holds content that does not decode")]
    Undecodable,
}

/// A test of one node.
#[derive(Clone, PartialEq, Eq)]
pub enum Predicate {
    /// An object whose member `key` is a string in `values`.
    MemberIn {
        /// The member.
        key: String,
        /// The accepted values.
        values: BTreeSet<String>,
    },
    /// An object whose member `key` is not a string in `values` (absent or masked counts as not
    /// in).
    MemberNotIn {
        /// The member.
        key: String,
        /// The refused values.
        values: BTreeSet<String>,
    },
    /// An object whose member `key` is a string, or an array with an element that matches
    /// `element`.
    StringOrArrayWith {
        /// The member.
        key: String,
        /// The test an element must pass.
        element: Box<Predicate>,
    },
}

impl Predicate {
    fn depth(&self) -> usize {
        match self {
            Self::MemberIn { .. } | Self::MemberNotIn { .. } => 1,
            Self::StringOrArrayWith { element, .. } => 1 + element.depth(),
        }
    }

    /// Checks its keys and values, at every level.
    fn check(&self) -> Result<(), SelectorError> {
        let key_ok = |key: &str| !key.is_empty() && key.len() <= MAX_SELECTOR_TEXT;
        match self {
            Self::MemberIn { key, values } | Self::MemberNotIn { key, values } => {
                if !key_ok(key) || values.iter().any(|v| v.len() > MAX_SELECTOR_TEXT) {
                    return Err(SelectorError::Key);
                }
                if values.len() > MAX_PREDICATE_VALUES {
                    return Err(SelectorError::TooManyValues);
                }
                Ok(())
            }
            Self::StringOrArrayWith { key, element } => {
                if !key_ok(key) {
                    return Err(SelectorError::Key);
                }
                element.check()
            }
        }
    }

    fn matches(&self, node: &ViewNode<'_, '_>, visits: &mut Visits) -> Result<bool, SelectorError> {
        visits.spend(1)?;
        if node.kind() != Kind::Object {
            return Ok(false);
        }
        match self {
            Self::MemberIn { key, values } => in_values(member_within(node, key, visits)?, values),
            Self::MemberNotIn { key, values } => Ok(!in_values(member_within(node, key, visits)?, values)?),
            Self::StringOrArrayWith { key, element } => match member_within(node, key, visits)? {
                Some(m) if m.kind() == Kind::String => Ok(true),
                Some(m) if m.kind() == Kind::Array => {
                    for item in m.children() {
                        if element.matches(&item, visits)? {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }
                _ => Ok(false),
            },
        }
    }
}

impl fmt::Debug for Predicate {
    // Sizes only: a module may have copied keys and values from content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemberIn { key, values } => f
                .debug_struct("MemberIn")
                .field("key_len", &key.len())
                .field("values", &values.len())
                .finish(),
            Self::MemberNotIn { key, values } => f
                .debug_struct("MemberNotIn")
                .field("key_len", &key.len())
                .field("values", &values.len())
                .finish(),
            Self::StringOrArrayWith { key, element } => f
                .debug_struct("StringOrArrayWith")
                .field("key_len", &key.len())
                .field("element", element)
                .finish(),
        }
    }
}

/// One step of a selector, applied to every node selected so far.
#[derive(Clone, PartialEq, Eq)]
pub enum Step {
    /// Each object's member `key`.
    Key(String),
    /// Each container's elements (or members).
    Each,
    /// Keeps the nodes that pass the predicate.
    Where(Predicate),
    /// Every member named `key` anywhere below, at any depth.
    AnyDepthKey(String),
    /// Keeps only the last node selected so far, in document order.
    Last,
}

impl fmt::Debug for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(key) => f.debug_struct("Key").field("len", &key.len()).finish(),
            Self::Each => f.write_str("Each"),
            Self::Where(predicate) => f.debug_tuple("Where").field(predicate).finish(),
            Self::AnyDepthKey(key) => f.debug_struct("AnyDepthKey").field("len", &key.len()).finish(),
            Self::Last => f.write_str("Last"),
        }
    }
}

/// A bounded path through a request's structure.
#[derive(Clone, PartialEq, Eq)]
pub struct Selector {
    steps: Vec<Step>,
}

impl fmt::Debug for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Selector").field("steps", &self.steps).finish()
    }
}

impl Selector {
    /// A selector from its steps.
    ///
    /// # Errors
    /// [`SelectorError`] if it has too many steps, nests too deep, or names a bad key or value,
    /// or too many values.
    pub fn new(steps: Vec<Step>) -> Result<Self, SelectorError> {
        if steps.len() > MAX_SELECTOR_STEPS {
            return Err(SelectorError::TooLong);
        }
        let key_ok = |key: &str| !key.is_empty() && key.len() <= MAX_SELECTOR_TEXT;
        for step in &steps {
            match step {
                Step::Key(key) | Step::AnyDepthKey(key) if !key_ok(key) => return Err(SelectorError::Key),
                Step::Where(predicate) => {
                    if predicate.depth() > MAX_PREDICATE_DEPTH {
                        return Err(SelectorError::TooDeep);
                    }
                    predicate.check()?;
                }
                _ => {}
            }
        }
        Ok(Self { steps })
    }

    /// Its steps.
    #[must_use]
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// The nodes it selects in `view`: ids from the tape itself, in document order, no repeats,
    /// within one [`Visits::per_call`] budget.
    ///
    /// # Errors
    /// [`SelectorError::Budget`] past the budget; [`SelectorError::Undecodable`] for content that
    /// does not decode, which a tape never holds.
    pub fn resolve(&self, view: &StructuralView<'_, '_>) -> Result<Vec<NodeId>, SelectorError> {
        self.resolve_within(view, &mut Visits::per_call())
    }

    /// As [`Selector::resolve`], spending `visits`: the host passes one budget for all of a module
    /// call's selectors, so the call's cost is bounded.
    ///
    /// # Errors
    /// As [`Selector::resolve`].
    pub fn resolve_within(
        &self,
        view: &StructuralView<'_, '_>,
        visits: &mut Visits,
    ) -> Result<Vec<NodeId>, SelectorError> {
        let mut current: BTreeSet<NodeId> = BTreeSet::from([view.root().id()]);
        for step in &self.steps {
            let nodes: Vec<ViewNode<'_, '_>> = current.iter().filter_map(|id| view.node(*id)).collect();
            current = match step {
                Step::Key(key) => {
                    let mut next = BTreeSet::new();
                    for node in nodes.iter().filter(|n| n.kind() == Kind::Object) {
                        visits.spend(1)?;
                        if let Some(m) = member_within(node, key, visits)? {
                            next.insert(m.id());
                        }
                    }
                    next
                }
                Step::Each => {
                    let mut next = BTreeSet::new();
                    for node in nodes.iter().filter(|n| n.kind().is_container()) {
                        for child in node.children() {
                            visits.spend(1)?;
                            next.insert(child.id());
                        }
                    }
                    next
                }
                Step::Where(predicate) => {
                    let mut kept = BTreeSet::new();
                    for node in &nodes {
                        if predicate.matches(node, visits)? {
                            kept.insert(node.id());
                        }
                    }
                    kept
                }
                Step::AnyDepthKey(key) => {
                    let mut found = BTreeSet::new();
                    // Nodes come in document order: one inside a subtree already walked adds
                    // nothing, so it is skipped and no node is visited twice.
                    let mut walked_to: Option<NodeId> = None;
                    for node in &nodes {
                        if walked_to.is_some_and(|end| node.id() < end) {
                            continue;
                        }
                        walked_to = Some(node.subtree_end());
                        for below in node.descendants() {
                            visits.spend(1)?;
                            if below.key_is(key).map_err(|_| SelectorError::Undecodable)? {
                                found.insert(below.id());
                            }
                        }
                    }
                    found
                }
                Step::Last => current.last().copied().into_iter().collect(),
            };
        }
        Ok(current.into_iter().collect())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test: a failed fixture fails the test")]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeSet;

    use uaos_json::{Limits, parse};

    use super::{MAX_RAW_TEXT, MAX_SELECTOR_TEXT, in_values};
    use crate::view::{DECODED, Mask, StructuralView};

    #[test]
    fn a_string_past_the_raw_bound_is_never_decoded() {
        // Past `MAX_RAW_TEXT` raw bytes a string equals no value and is not decoded; at the bound
        // it is decoded and compared. 256 six-byte escapes are exactly the bound and decode to the
        // value; one byte more decodes past it.
        let values = BTreeSet::from(["A".repeat(MAX_SELECTOR_TEXT)]);
        let escapes = "~u0041".repeat(MAX_SELECTOR_TEXT).replace('~', "\\");
        for (tail, expected, decodes) in [("", true, 1), ("A", false, 0)] {
            let doc = format!("{{\"k\":\"{escapes}{tail}\"}}");
            let tape = parse(doc.as_bytes(), &Limits::DEFAULT).unwrap();
            let none = Mask::new();
            let view = StructuralView::new(&tape, &none);
            let member = view.root().member("k").unwrap();
            assert_eq!(member.and_then(|m| m.raw_text_len()), Some(MAX_RAW_TEXT + tail.len()));
            let before = DECODED.with(Cell::get);
            assert_eq!(in_values(member, &values), Ok(expected));
            assert_eq!(
                DECODED.with(Cell::get) - before,
                decodes,
                "a string past the raw bound was decoded"
            );
        }
    }
}
