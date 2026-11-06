// SPDX-License-Identifier: Apache-2.0

//! Errors carry a kind and a byte offset, never input bytes: a body may hold secrets, and an error
//! travels to logs and to the agent.

use std::fmt;

use crate::node::NodeId;
use crate::to_u32;

/// Why a document, a string or a limit was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The input is longer than the limit allows.
    TooLarge,
    /// The input starts with a UTF-8 byte-order mark.
    ByteOrderMark,
    /// The input is not UTF-8.
    InvalidUtf8,
    /// The input is empty or whitespace only.
    Empty,
    /// A raw byte below 0x20 inside a string.
    ControlCharacter,
    /// A backslash followed by anything but a JSON escape.
    InvalidEscape,
    /// `\u` not followed by four hexadecimal digits.
    InvalidUnicodeEscape,
    /// A surrogate escape that is not part of a high-low pair.
    LoneSurrogate,
    /// A string with no closing quote.
    UnterminatedString,
    /// A raw quote inside string content handed to [`crate::decode`].
    UnescapedQuote,
    /// A number that breaks the RFC 8259 grammar.
    InvalidNumber,
    /// Anything but `true`, `false` or `null` where a literal starts.
    InvalidLiteral,
    /// A value was expected.
    ExpectedValue,
    /// A member key was expected.
    ExpectedKey,
    /// A colon after a member key was expected.
    ExpectedColon,
    /// A comma or the container's closing bracket was expected.
    ExpectedCommaOrClose,
    /// The input ended inside the document.
    UnexpectedEnd,
    /// Something other than whitespace follows the root value.
    TrailingData,
    /// Two members of one object have the same key once decoded.
    DuplicateKey,
    /// More containers are open at once than the limit allows.
    DepthExceeded,
    /// The document has more values than the limit allows.
    TooManyNodes,
    /// A member key longer than [`crate::MAX_KEY_LEN`].
    KeyTooLong,
    /// The tape could not get the memory it needed.
    OutOfMemory,
}

impl ErrorKind {
    /// A stable `snake_case` label, for metrics and explanations.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::ByteOrderMark => "byte_order_mark",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::Empty => "empty",
            Self::ControlCharacter => "control_character",
            Self::InvalidEscape => "invalid_escape",
            Self::InvalidUnicodeEscape => "invalid_unicode_escape",
            Self::LoneSurrogate => "lone_surrogate",
            Self::UnterminatedString => "unterminated_string",
            Self::UnescapedQuote => "unescaped_quote",
            Self::InvalidNumber => "invalid_number",
            Self::InvalidLiteral => "invalid_literal",
            Self::ExpectedValue => "expected_value",
            Self::ExpectedKey => "expected_key",
            Self::ExpectedColon => "expected_colon",
            Self::ExpectedCommaOrClose => "expected_comma_or_close",
            Self::UnexpectedEnd => "unexpected_end",
            Self::TrailingData => "trailing_data",
            Self::DuplicateKey => "duplicate_key",
            Self::DepthExceeded => "depth_exceeded",
            Self::TooManyNodes => "too_many_nodes",
            Self::KeyTooLong => "key_too_long",
            Self::OutOfMemory => "out_of_memory",
        }
    }

    /// A short human-readable reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::TooLarge => "input larger than the limit",
            Self::ByteOrderMark => "byte-order mark",
            Self::InvalidUtf8 => "invalid UTF-8",
            Self::Empty => "empty document",
            Self::ControlCharacter => "control character in a string",
            Self::InvalidEscape => "invalid escape",
            Self::InvalidUnicodeEscape => "invalid unicode escape",
            Self::LoneSurrogate => "lone surrogate",
            Self::UnterminatedString => "unterminated string",
            Self::UnescapedQuote => "unescaped quote in string content",
            Self::InvalidNumber => "invalid number",
            Self::InvalidLiteral => "invalid literal",
            Self::ExpectedValue => "value expected",
            Self::ExpectedKey => "member key expected",
            Self::ExpectedColon => "':' expected",
            Self::ExpectedCommaOrClose => "',' or closing bracket expected",
            Self::UnexpectedEnd => "unexpected end of input",
            Self::TrailingData => "data after the root value",
            Self::DuplicateKey => "duplicate key",
            Self::DepthExceeded => "nesting deeper than the limit",
            Self::TooManyNodes => "more values than the limit",
            Self::KeyTooLong => "member key longer than the limit",
            Self::OutOfMemory => "out of memory",
        }
    }
}

/// A refused document or string: what broke, and the byte offset where it broke.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct JsonError {
    kind: ErrorKind,
    offset: u32,
}

impl JsonError {
    pub(crate) fn new(kind: ErrorKind, offset: usize) -> Self {
        Self {
            kind,
            offset: to_u32(offset),
        }
    }

    /// The same error, with an offset relative to a string's content made absolute.
    pub(crate) const fn shifted(self, by: u32) -> Self {
        Self {
            kind: self.kind,
            offset: self.offset.saturating_add(by),
        }
    }

    /// What broke.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The byte offset in the input where it broke.
    #[must_use]
    pub const fn offset(&self) -> u32 {
        self.offset
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "json: {} at byte {}", self.kind.reason(), self.offset)
    }
}

impl std::error::Error for JsonError {}

/// A limit refused by [`crate::Limits::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LimitsError {
    /// `max_bytes` is zero or above its ceiling.
    MaxBytes,
    /// `max_depth` is zero or above its ceiling.
    MaxDepth,
    /// `max_nodes` is zero or above its ceiling.
    MaxNodes,
}

impl fmt::Display for LimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MaxBytes => "json limits: max_bytes must be between 1 and 1 GiB",
            Self::MaxDepth => "json limits: max_depth must be between 1 and 1024",
            Self::MaxNodes => "json limits: max_nodes must be between 1 and 2^24",
        })
    }
}

impl std::error::Error for LimitsError {}

/// A structural invariant that a tape breaks, found by [`crate::Tape::verify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Violation {
    node: NodeId,
    rule: &'static str,
}

impl Violation {
    pub(crate) fn new(node: usize, rule: &'static str) -> Self {
        Self {
            node: NodeId::new(to_u32(node)),
            rule,
        }
    }

    /// The node where the invariant breaks.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// The invariant, in words.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        self.rule
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tape invariant broken at node {}: {}", self.node.get(), self.rule)
    }
}

impl std::error::Error for Violation {}
