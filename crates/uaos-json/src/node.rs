// SPDX-License-Identifier: Apache-2.0

//! Reading a tape: a [`Node`] is a copyable view of one value, with its kind, span, key and
//! links to its parent, children and subtree. Every accessor is total or returns an `Option` or
//! a `Result`; none panics and none hands out input bytes it was not asked for.

use std::borrow::Cow;
use std::fmt;
use std::iter::FusedIterator;
use std::ops::Range;

use crate::decode::{Decoded, Unescape, decode, decode_mapped};
use crate::error::JsonError;
use crate::tape::{HAS_KEY, KEY_ESCAPED, NONE, RawNode, STR_ESCAPED, Tape};
use crate::{parse_i64, parse_u64, to_usize};

/// The kind of a JSON value. Closed by RFC 8259.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Kind {
    /// `{…}`
    Object,
    /// `[…]`
    Array,
    /// `"…"`
    String,
    /// A number, kept as its text.
    Number,
    /// `true`
    True,
    /// `false`
    False,
    /// `null`
    Null,
}

impl Kind {
    /// Whether values of this kind contain other values.
    #[must_use]
    pub const fn is_container(self) -> bool {
        matches!(self, Self::Object | Self::Array)
    }
}

/// The index of a node on its tape. Node 0 is the root; nodes are in pre-order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(u32);

impl NodeId {
    /// The root value.
    pub const ROOT: Self = Self(0);

    pub(crate) const fn new(index: u32) -> Self {
        Self(index)
    }

    /// The index as a number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The index as a `usize`.
    #[must_use]
    pub fn index(self) -> usize {
        to_usize(self.0)
    }
}

/// A byte range `start..end` of the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Span {
    /// The first byte.
    pub start: u32,
    /// One past the last byte.
    pub end: u32,
}

impl Span {
    /// The span as a range of `usize`, for slicing.
    #[must_use]
    pub fn range(self) -> Range<usize> {
        to_usize(self.start)..to_usize(self.end)
    }

    /// The length in bytes.
    #[must_use]
    pub const fn len(self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    /// Whether the span covers no byte.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.end <= self.start
    }

    /// Whether `other` lies within this span.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

/// One value on a tape.
#[derive(Clone, Copy)]
pub struct Node<'t, 'a> {
    tape: &'t Tape<'a>,
    id: u32,
    raw: RawNode,
}

impl<'t, 'a> Node<'t, 'a> {
    pub(crate) const fn new(tape: &'t Tape<'a>, id: u32, raw: RawNode) -> Self {
        Self { tape, id, raw }
    }

    /// Its index on the tape.
    #[must_use]
    pub const fn id(&self) -> NodeId {
        NodeId(self.id)
    }

    /// Its kind.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.raw.kind
    }

    /// Its raw byte span; a string's includes its quotes.
    #[must_use]
    pub const fn span(&self) -> Span {
        Span {
            start: self.raw.start,
            end: self.raw.end,
        }
    }

    /// Its raw text.
    #[must_use]
    pub fn raw(&self) -> &'a str {
        self.tape.slice(self.span())
    }

    /// The value that contains it; `None` for the root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        (self.raw.parent != NONE)
            .then(|| self.tape.node(NodeId(self.raw.parent)))
            .flatten()
    }

    /// Its ancestors, nearest first.
    #[must_use]
    pub fn ancestors(&self) -> Ancestors<'t, 'a> {
        Ancestors { next: self.parent() }
    }

    /// The values it contains directly, in order. Empty for a scalar.
    #[must_use]
    pub fn children(&self) -> Children<'t, 'a> {
        Children {
            tape: self.tape,
            next: self.id + 1,
            end: self.raw.after,
        }
    }

    /// Every value inside it, in pre-order.
    #[must_use]
    pub fn descendants(&self) -> Descendants<'t, 'a> {
        Descendants {
            tape: self.tape,
            next: self.id + 1,
            end: self.raw.after,
        }
    }

    /// The next value in the same container.
    #[must_use]
    pub fn next_sibling(&self) -> Option<Self> {
        let parent = self.parent()?;
        (self.raw.after < parent.raw.after)
            .then(|| self.tape.node(NodeId(self.raw.after)))
            .flatten()
    }

    /// Its position among its siblings, counted from 0 (0 for the root). O(siblings).
    #[must_use]
    pub fn ordinal(&self) -> u32 {
        self.parent().map_or(0, |parent| {
            let before = parent.children().take_while(|child| child.id != self.id).count();
            crate::to_u32(before)
        })
    }

    /// The first node after its subtree.
    #[must_use]
    pub const fn subtree_end(&self) -> NodeId {
        NodeId(self.raw.after)
    }

    /// The span of its member key, quotes included; `None` outside an object.
    #[must_use]
    pub fn key_span(&self) -> Option<Span> {
        if self.raw.flags & HAS_KEY == 0 {
            return None;
        }
        Some(Span {
            start: self.raw.key_start,
            end: self
                .raw
                .key_start
                .saturating_add(u32::from(self.raw.key_len))
                .saturating_add(2),
        })
    }

    /// The raw text of its member key, between the quotes.
    #[must_use]
    pub fn key_raw(&self) -> Option<&'a str> {
        let span = self.key_span()?;
        Some(self.tape.slice(Span {
            start: span.start.saturating_add(1),
            end: span.end.saturating_sub(1),
        }))
    }

    /// Whether its member key holds an escape.
    #[must_use]
    pub const fn key_has_escape(&self) -> bool {
        self.raw.flags & KEY_ESCAPED != 0
    }

    /// Its member key, decoded; borrowed when it holds no escape.
    ///
    /// # Errors
    ///
    /// A key that does not decode, which a tape never holds.
    pub fn key(&self) -> Result<Option<Cow<'a, str>>, JsonError> {
        let (Some(raw), Some(span)) = (self.key_raw(), self.key_span()) else {
            return Ok(None);
        };
        if !self.key_has_escape() {
            return Ok(Some(Cow::Borrowed(raw)));
        }
        decode(raw)
            .map(Some)
            .map_err(|e| e.shifted(span.start.saturating_add(1)))
    }

    /// Whether its member key, decoded, is `name`. Does not allocate.
    ///
    /// # Errors
    ///
    /// A key that does not decode, which a tape never holds.
    pub fn key_is(&self, name: &str) -> Result<bool, JsonError> {
        let Some(raw) = self.key_raw() else {
            return Ok(false);
        };
        if !self.key_has_escape() {
            return Ok(raw == name);
        }
        let mut decoded = Unescape::new(raw.as_bytes());
        let equal = decoded.by_ref().eq(name.bytes());
        if decoded.broken() {
            return self.key().map(|_| false);
        }
        Ok(equal)
    }

    /// The member of this object whose key, decoded, is `name`. `None` when there is none or
    /// this is not an object; keys are unique on a tape.
    ///
    /// # Errors
    ///
    /// A key that does not decode, which a tape never holds.
    pub fn member(&self, name: &str) -> Result<Option<Self>, JsonError> {
        if self.raw.kind != Kind::Object {
            return Ok(None);
        }
        for child in self.children() {
            if child.key_is(name)? {
                return Ok(Some(child));
            }
        }
        Ok(None)
    }

    /// For a string, the span of its content between the quotes.
    #[must_use]
    pub const fn content_span(&self) -> Option<Span> {
        if !matches!(self.raw.kind, Kind::String) {
            return None;
        }
        Some(Span {
            start: self.raw.start.saturating_add(1),
            end: self.raw.end.saturating_sub(1),
        })
    }

    /// For a string, the raw text of its content.
    #[must_use]
    pub fn str_raw(&self) -> Option<&'a str> {
        self.content_span().map(|span| self.tape.slice(span))
    }

    /// Whether this string's content holds an escape.
    #[must_use]
    pub const fn str_has_escape(&self) -> bool {
        self.raw.flags & STR_ESCAPED != 0
    }

    /// For a string, its decoded value; borrowed when it holds no escape.
    ///
    /// # Errors
    ///
    /// Content that does not decode, which a tape never holds.
    pub fn str_value(&self) -> Result<Option<Cow<'a, str>>, JsonError> {
        let (Some(raw), Some(span)) = (self.str_raw(), self.content_span()) else {
            return Ok(None);
        };
        if !self.str_has_escape() {
            return Ok(Some(Cow::Borrowed(raw)));
        }
        decode(raw).map(Some).map_err(|e| e.shifted(span.start))
    }

    /// For a string, its decoded value and the map back to raw content offsets.
    ///
    /// # Errors
    ///
    /// Content that does not decode, which a tape never holds.
    pub fn str_value_mapped(&self) -> Result<Option<Decoded<'a>>, JsonError> {
        let (Some(raw), Some(span)) = (self.str_raw(), self.content_span()) else {
            return Ok(None);
        };
        decode_mapped(raw).map(Some).map_err(|e| e.shifted(span.start))
    }

    /// For a number, its text exactly as written.
    #[must_use]
    pub fn number_text(&self) -> Option<&'a str> {
        (self.raw.kind == Kind::Number).then(|| self.raw())
    }

    /// For a number written as an integer that fits, its value. See [`parse_u64`].
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        self.number_text().and_then(parse_u64)
    }

    /// For a number written as an integer that fits, its value. See [`parse_i64`].
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        self.number_text().and_then(parse_i64)
    }

    /// For `true` or `false`, its value.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self.raw.kind {
            Kind::True => Some(true),
            Kind::False => Some(false),
            _ => None,
        }
    }

    /// Whether it is `null`.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self.raw.kind, Kind::Null)
    }
}

impl fmt::Debug for Node<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Positions only: the content may be a secret.
        f.debug_struct("Node")
            .field("id", &self.id)
            .field("kind", &self.raw.kind)
            .field("span", &(self.raw.start..self.raw.end))
            .finish_non_exhaustive()
    }
}

/// The values a container holds directly. See [`Node::children`].
#[derive(Clone)]
pub struct Children<'t, 'a> {
    tape: &'t Tape<'a>,
    next: u32,
    end: u32,
}

impl<'t, 'a> Iterator for Children<'t, 'a> {
    type Item = Node<'t, 'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.end {
            return None;
        }
        let node = self.tape.node(NodeId(self.next))?;
        // `after` always moves forward on a tape; the guard keeps a broken one from looping.
        self.next = node.raw.after.max(self.next + 1);
        Some(node)
    }
}

impl FusedIterator for Children<'_, '_> {}

impl fmt::Debug for Children<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Children")
            .field("next", &self.next)
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
}

/// Values in pre-order. See [`Node::descendants`] and [`Tape::nodes`].
#[derive(Clone)]
pub struct Descendants<'t, 'a> {
    tape: &'t Tape<'a>,
    next: u32,
    end: u32,
}

impl<'t, 'a> Descendants<'t, 'a> {
    pub(crate) const fn new(tape: &'t Tape<'a>, next: u32, end: u32) -> Self {
        Self { tape, next, end }
    }
}

impl<'t, 'a> Iterator for Descendants<'t, 'a> {
    type Item = Node<'t, 'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.end {
            return None;
        }
        let node = self.tape.node(NodeId(self.next));
        self.next += 1;
        node
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = to_usize(self.end.saturating_sub(self.next));
        (left, Some(left))
    }
}

impl ExactSizeIterator for Descendants<'_, '_> {}

impl FusedIterator for Descendants<'_, '_> {}

impl fmt::Debug for Descendants<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Descendants")
            .field("next", &self.next)
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
}

/// A node's ancestors, nearest first. See [`Node::ancestors`].
#[derive(Clone)]
pub struct Ancestors<'t, 'a> {
    next: Option<Node<'t, 'a>>,
}

impl<'t, 'a> Iterator for Ancestors<'t, 'a> {
    type Item = Node<'t, 'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.next.take()?;
        // Parents always come earlier on a tape, so this ends at the root.
        self.next = node.parent().filter(|parent| parent.id < node.id);
        Some(node)
    }
}

impl FusedIterator for Ancestors<'_, '_> {}

impl fmt::Debug for Ancestors<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ancestors")
            .field("next", &self.next.map(|node| node.id))
            .finish()
    }
}
