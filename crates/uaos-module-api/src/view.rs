// SPDX-License-Identifier: Apache-2.0

//! The structural view a codec or a module reads: the request's tape, with everything detection
//! flagged read as masked. No raw view exists in this release.
//!
//! Detection scans keys as well as values (`uaos-redact`), so the [`Mask`] covers both: a masked
//! string or number reads as [`ViewText::Masked`], and a masked key reads as masked, never
//! matches a name and is never found by [`ViewNode::member`].

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt;

use uaos_json::{JsonError, Kind, Node, NodeId, Tape};

/// A finding names a node that is not on the tape, a key finding names a node with no key, or a
/// value finding names `true`, `false` or `null`: the view is refused (fail closed).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a finding names a node that is not on the tape, a key no node has, or a literal")]
pub struct MaskError;

#[cfg(test)]
thread_local! {
    /// Strings [`ViewNode::text`] decoded on this thread, so a test can prove the comparison bound.
    pub(crate) static DECODED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// What detection flagged in one request, by node: values (strings and numbers) and object keys.
/// The host builds it from the findings. A finding it cannot place on a value or a key refuses
/// the view (fail closed); a raw view never exists.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Mask {
    values: BTreeSet<NodeId>,
    keys: BTreeSet<NodeId>,
}

impl Mask {
    /// Nothing masked.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            values: BTreeSet::new(),
            keys: BTreeSet::new(),
        }
    }

    /// Masks the value at `id`: a string or a number. Masking a container masks everything inside
    /// it, keys included, so a finding placed on the wrong node fails closed.
    pub fn value(&mut self, id: NodeId) {
        self.values.insert(id);
    }

    /// Masks the key of the object member at `id`.
    pub fn key(&mut self, id: NodeId) {
        self.keys.insert(id);
    }

    /// Seals the mask against `tape`: every finding must name a node on it, a key finding a node
    /// that has a key, and masked containers become id ranges, so the view's cost no longer grows
    /// with depth. The [`Sealed`] holds `tape` and the mask and builds the view itself, so a seal
    /// is never used over another tape, and the mask cannot change while it lives (a fingerprint of
    /// the tape could match a refilled buffer). An unsealed view cannot refuse: a finding it cannot
    /// place masks nothing in it, so a host hands modules and codecs views from seals.
    ///
    /// # Errors
    /// [`MaskError`] if a finding names a node that is not on `tape`, or a key finding a node
    /// with no key.
    pub fn seal<'v, 'a>(&'v self, tape: &'v Tape<'a>) -> Result<Sealed<'v, 'a>, MaskError> {
        let mut covered: Vec<(NodeId, NodeId)> = Vec::new();
        for id in &self.values {
            let node = tape.node(*id).ok_or(MaskError)?;
            // A value finding names a string, a number or a container. On `true`, `false` or `null`
            // it would mask nothing: the finding is misplaced.
            if matches!(node.kind(), Kind::True | Kind::False | Kind::Null) {
                return Err(MaskError);
            }
            // Ids come in document order, so a container inside the last range adds nothing.
            let inside_last = covered.last().is_some_and(|(_, end)| *id < *end);
            if node.kind().is_container() && !inside_last {
                covered.push((*id, node.subtree_end()));
            }
        }
        if self
            .keys
            .iter()
            .any(|id| tape.node(*id).and_then(|node| node.key_span()).is_none())
        {
            return Err(MaskError);
        }
        Ok(Sealed {
            tape,
            mask: self,
            covered,
        })
    }

    /// Whether the value at `id` is masked.
    #[must_use]
    pub fn masks_value(&self, id: NodeId) -> bool {
        self.values.contains(&id)
    }

    /// Whether the key of the member at `id` is masked.
    #[must_use]
    pub fn masks_key(&self, id: NodeId) -> bool {
        self.keys.contains(&id)
    }
}

impl fmt::Debug for Mask {
    // Counts only: which nodes hold a finding is itself a hint about content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mask")
            .field("values", &self.values.len())
            .field("keys", &self.keys.len())
            .finish()
    }
}

/// A mask sealed against one tape ([`Mask::seal`]): the tape, the mask, and the masked
/// containers as disjoint `[start, end)` id ranges, so "inside a masked container" is a binary
/// search. It borrows both, so neither can change while it lives.
#[derive(Clone)]
#[must_use = "a seal is used only through its view (`Sealed::view`); dropped, the view reads unsealed"]
pub struct Sealed<'v, 'a> {
    tape: &'v Tape<'a>,
    mask: &'v Mask,
    covered: Vec<(NodeId, NodeId)>,
}

impl<'a> Sealed<'_, 'a> {
    /// The view over the sealed tape: each visit costs O(log ranges).
    #[must_use]
    pub fn view(&self) -> StructuralView<'_, 'a> {
        StructuralView {
            tape: self.tape,
            mask: self.mask,
            covered: Some(&self.covered),
        }
    }
}

impl fmt::Debug for Sealed<'_, '_> {
    // Counts only, as for the mask.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealed")
            .field("mask", self.mask)
            .field("ranges", &self.covered.len())
            .finish()
    }
}

/// A read-only view over a parsed request, with the detection overlay.
#[derive(Clone, Copy)]
pub struct StructuralView<'v, 'a> {
    tape: &'v Tape<'a>,
    mask: &'v Mask,
    /// The sealed mask's ranges, when the view came from [`Sealed::view`].
    covered: Option<&'v [(NodeId, NodeId)]>,
}

impl<'v, 'a> StructuralView<'v, 'a> {
    /// A view over `tape` in which what `mask` names reads as masked, each visit O(depth). It
    /// cannot refuse: a finding off the tape, or a key finding on a node with no key, masks nothing
    /// in it. A host hands modules and codecs the view of a seal ([`Sealed::view`]), which refuses
    /// those and costs O(log ranges) a visit; this one serves tests and views with nothing
    /// masked.
    #[must_use]
    pub const fn new(tape: &'v Tape<'a>, mask: &'v Mask) -> Self {
        Self {
            tape,
            mask,
            covered: None,
        }
    }

    /// Whether the view reads a sealed mask, each visit O(log ranges).
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.covered.is_some()
    }

    /// The root value.
    #[must_use]
    pub const fn root(&self) -> ViewNode<'v, 'a> {
        ViewNode {
            node: self.tape.root(),
            mask: self.mask,
            covered: self.covered,
        }
    }

    /// Whether removing `id` would touch masked content: a masked value or key in its subtree,
    /// its own key included, or a masked container around it. True outside the view.
    #[must_use]
    pub fn touches_masked(&self, id: NodeId) -> bool {
        let Some(node) = self.node(id) else {
            return true;
        };
        let end = node.subtree_end();
        node.inside_masked()
            || self.mask.values.range(id..end).next().is_some()
            || self.mask.keys.range(id..end).next().is_some()
    }

    /// The node at `id`, if it is in this view.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<ViewNode<'v, 'a>> {
        self.tape.node(id).map(|node| ViewNode {
            node,
            mask: self.mask,
            covered: self.covered,
        })
    }
}

impl fmt::Debug for StructuralView<'_, '_> {
    // Counts only: the view is content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StructuralView")
            .field("nodes", &self.tape.stats().nodes)
            .field("mask", self.mask)
            .field("sealed", &self.covered.is_some())
            .finish()
    }
}

/// A string, a number or a key as a view shows it.
#[derive(Clone, PartialEq, Eq)]
pub enum ViewText<'a> {
    /// The decoded text.
    Plain(Cow<'a, str>),
    /// Text detection flagged: only the fact that it is masked is visible.
    Masked,
}

impl fmt::Debug for ViewText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(text) => f.debug_struct("Plain").field("len", &text.len()).finish(),
            Self::Masked => f.write_str("Masked"),
        }
    }
}

/// One value in a view.
#[derive(Clone, Copy)]
pub struct ViewNode<'v, 'a> {
    node: Node<'v, 'a>,
    mask: &'v Mask,
    covered: Option<&'v [(NodeId, NodeId)]>,
}

impl<'v, 'a> ViewNode<'v, 'a> {
    const fn wrap(&self, node: Node<'v, 'a>) -> Self {
        Self {
            node,
            mask: self.mask,
            covered: self.covered,
        }
    }

    /// Whether a container around it was masked whole: everything inside reads as masked.
    /// O(log ranges) in a view from [`Sealed::view`], O(depth) otherwise; free when
    /// nothing is masked.
    fn inside_masked(&self) -> bool {
        if self.mask.values.is_empty() {
            return false;
        }
        let id = self.node.id();
        match self.covered {
            Some(covered) => {
                let after = covered.partition_point(|(start, _)| *start < id);
                after
                    .checked_sub(1)
                    .and_then(|i| covered.get(i))
                    .is_some_and(|(_, end)| id < *end)
            }
            None => self.node.ancestors().any(|a| self.mask.masks_value(a.id())),
        }
    }

    /// Whether its value is masked: flagged itself, or inside a masked container.
    fn value_masked(&self) -> bool {
        self.mask.masks_value(self.node.id()) || self.inside_masked()
    }

    /// Whether its key is masked: flagged itself, or inside a masked container.
    fn key_masked(&self) -> bool {
        self.mask.masks_key(self.node.id()) || self.inside_masked()
    }

    /// The first node after its subtree: its subtree is the ids from its own up to this one.
    #[must_use]
    pub const fn subtree_end(&self) -> NodeId {
        self.node.subtree_end()
    }

    /// Its id on the tape.
    #[must_use]
    pub const fn id(&self) -> NodeId {
        self.node.id()
    }

    /// Its kind.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.node.kind()
    }

    /// Its parent, if it is not the root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        self.node.parent().map(|n| self.wrap(n))
    }

    /// Its children, in order.
    pub fn children(&self) -> impl Iterator<Item = Self> + use<'v, 'a> {
        let (mask, covered) = (self.mask, self.covered);
        self.node.children().map(move |node| Self { node, mask, covered })
    }

    /// Every value below it, in pre-order, itself excluded.
    pub fn descendants(&self) -> impl Iterator<Item = Self> + use<'v, 'a> {
        let (mask, covered) = (self.mask, self.covered);
        self.node.descendants().map(move |node| Self { node, mask, covered })
    }

    /// Its key, if it is an object member: masked if detection flagged it.
    ///
    /// # Errors
    /// A key that does not decode, which a tape never holds.
    pub fn key(&self) -> Result<Option<ViewText<'a>>, JsonError> {
        let masked = self.key_masked();
        Ok(self
            .node
            .key()?
            .map(|key| if masked { ViewText::Masked } else { ViewText::Plain(key) }))
    }

    /// Whether its key is `name`. A masked key is never any name.
    ///
    /// # Errors
    /// As [`ViewNode::key`].
    pub fn key_is(&self, name: &str) -> Result<bool, JsonError> {
        if self.key_masked() {
            return Ok(false);
        }
        self.node.key_is(name)
    }

    /// For an object, its member `name`. A member whose key is masked is never found by name.
    ///
    /// # Errors
    /// As [`ViewNode::key`].
    pub fn member(&self, name: &str) -> Result<Option<Self>, JsonError> {
        Ok(self
            .node
            .member(name)?
            .filter(|n| !self.wrap(*n).key_masked())
            .map(|n| self.wrap(n)))
    }

    /// For a string, its value, masked if detection flagged it.
    ///
    /// # Errors
    /// Content that does not decode, which a tape never holds.
    pub fn text(&self) -> Result<Option<ViewText<'a>>, JsonError> {
        if self.node.kind() != Kind::String {
            return Ok(None);
        }
        if self.value_masked() {
            return Ok(Some(ViewText::Masked));
        }
        #[cfg(test)]
        DECODED.with(|decoded| decoded.set(decoded.get() + 1));
        Ok(self.node.str_value()?.map(ViewText::Plain))
    }

    /// For a string, the length of its raw text, escapes undecoded: what a comparison can bound
    /// without decoding it.
    pub(crate) fn raw_text_len(&self) -> Option<usize> {
        self.node.str_raw().map(str::len)
    }

    /// For a number, its text, masked if detection flagged it.
    #[must_use]
    pub fn number_text(&self) -> Option<ViewText<'a>> {
        let text = self.node.number_text()?;
        if self.value_masked() {
            return Some(ViewText::Masked);
        }
        Some(ViewText::Plain(Cow::Borrowed(text)))
    }

    /// Whether it is the string `value`, unmasked. A masked string is never any value.
    ///
    /// # Errors
    /// As [`ViewNode::text`].
    pub fn is_string(&self, value: &str) -> Result<bool, JsonError> {
        Ok(matches!(self.text()?, Some(ViewText::Plain(text)) if text == value))
    }
}

impl fmt::Debug for ViewNode<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewNode")
            .field("id", &self.node.id().get())
            .field("kind", &self.node.kind())
            .finish()
    }
}
