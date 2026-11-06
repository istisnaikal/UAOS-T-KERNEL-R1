// SPDX-License-Identifier: Apache-2.0

//! The parser and the tape. One forward pass, no recursion: an explicit stack of open containers,
//! bounded by the depth limit, replaces the call stack. Every value becomes one 24-byte node,
//! appended in pre-order; a container's end and subtree end are filled in when it closes, and an
//! object's keys are checked for duplicates at that moment.

use std::collections::BTreeSet;
use std::fmt;

use crate::decode::{Unescape, hex4, is_high_surrogate, is_low_surrogate, low_surrogate_at};
use crate::error::{ErrorKind, JsonError, Violation};
use crate::node::{Descendants, Kind, Node, NodeId, Span};
use crate::{Limits, to_u32, to_usize};

/// The parent of the root.
pub(crate) const NONE: u32 = u32::MAX;
/// The node is a member of an object; `key_start` and `key_len` hold its key.
pub(crate) const HAS_KEY: u8 = 1;
/// The member key holds an escape.
pub(crate) const KEY_ESCAPED: u8 = 2;
/// The string's content holds an escape.
pub(crate) const STR_ESCAPED: u8 = 4;
const KNOWN_FLAGS: u8 = HAS_KEY | KEY_ESCAPED | STR_ESCAPED;

const BOM: &[u8] = b"\xEF\xBB\xBF";

/// One value on the tape. Private: the layout may change, the invariants may not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RawNode {
    pub(crate) start: u32,
    pub(crate) end: u32,
    pub(crate) parent: u32,
    pub(crate) after: u32,
    pub(crate) key_start: u32,
    pub(crate) key_len: u16,
    pub(crate) kind: Kind,
    pub(crate) flags: u8,
}

const _: () = assert!(
    std::mem::size_of::<RawNode>() == 24 && std::mem::align_of::<RawNode>() == 4,
    "the tape's node is 24 bytes"
);

/// A member key, read before its value.
#[derive(Clone, Copy)]
struct Key {
    start: u32,
    len: u16,
    escaped: bool,
    /// Of the key's decoded bytes (`fingerprint`).
    fingerprint: u32,
}

impl RawNode {
    fn new(kind: Kind, start: usize, parent: u32, key: Option<Key>, flags: u8) -> Self {
        let (key_start, key_len, key_flags) = key.map_or((0, 0, 0), |key| {
            let escaped = if key.escaped { KEY_ESCAPED } else { 0 };
            (key.start, key.len, HAS_KEY | escaped)
        });
        Self {
            start: to_u32(start),
            end: to_u32(start),
            parent,
            after: 0,
            key_start,
            key_len,
            kind,
            flags: flags | key_flags,
        }
    }
}

/// A parsed document: every value, in pre-order, over the input it borrows.
pub struct Tape<'a> {
    input: &'a str,
    nodes: Vec<RawNode>,
    root: RawNode,
    deepest: u16,
    limits: Limits,
}

/// What a tape holds, for callers to report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TapeStats {
    /// Values on the tape.
    pub nodes: u32,
    /// The most containers open at once.
    pub max_depth: u16,
    /// The input's length in bytes.
    pub input_bytes: u32,
    /// Heap the tape holds, in bytes.
    pub heap_bytes: usize,
}

/// Parses one complete JSON document: a single value, optionally surrounded by whitespace.
///
/// # Errors
///
/// The first rule the input breaks, with the byte offset where it breaks. The checks run in order:
/// size, byte-order mark, UTF-8, then structure. A repeated key is found when its object closes:
/// the first object to close with one is reported, at the earliest second occurrence, unless the
/// parser meets another error before that close.
pub fn parse<'a>(raw: &'a [u8], limits: &Limits) -> Result<Tape<'a>, JsonError> {
    if raw.len() > to_usize(limits.max_bytes()) {
        return Err(JsonError::new(ErrorKind::TooLarge, to_usize(limits.max_bytes())));
    }
    reject_bom(raw)?;
    let input = std::str::from_utf8(raw).map_err(|e| JsonError::new(ErrorKind::InvalidUtf8, e.valid_up_to()))?;
    let mut parser = Parser::new(input.as_bytes(), *limits)?;
    parser.run()?;
    Tape::new(input, parser.nodes, parser.deepest, *limits)
}

fn reject_bom(raw: &[u8]) -> Result<(), JsonError> {
    if raw.starts_with(BOM) {
        return Err(JsonError::new(ErrorKind::ByteOrderMark, 0));
    }
    Ok(())
}

/// What the parser does next.
enum Step {
    /// A value starts here; inside an object, after this key.
    Value(usize, Option<Key>),
    /// A value ended just before here (or an empty container's closing bracket is here).
    After(usize),
}

struct Parser<'a> {
    bytes: &'a [u8],
    limits: Limits,
    nodes: Vec<RawNode>,
    /// The open containers, innermost last.
    stack: Vec<u32>,
    /// One entry per member key of the objects still open, innermost last: the key's fingerprint in
    /// the high half, the member's node id in the low half.
    keys: Vec<u64>,
    /// Where each open object's entries begin in `keys`, innermost last.
    marks: Vec<u32>,
    /// Reused by every run of members that share a fingerprint.
    run: RunScratch,
    deepest: u16,
}

/// Scratch for comparing one run of members that share a fingerprint, reused for every run. Each
/// escaped key is decoded once; keys without escapes are read in place.
#[derive(Default)]
struct RunScratch {
    /// The run's escaped keys, decoded. At most their raw length, so at most the input's.
    decoded: Vec<u8>,
    /// Per member of the run, where its decoded key is: `(start, len)`, with [`IN_DECODED`] set
    /// in `start` when it points into `decoded` rather than the input.
    spans: Vec<(u32, u32)>,
    /// Positions in the run, sorted by key, then by where the key starts.
    order: Vec<u32>,
}

/// Marks a span in [`RunScratch::decoded`]; the input and the scratch stay below 2^31 bytes.
const IN_DECODED: u32 = 1 << 31;

const _: () = assert!(
    Limits::MAX_BYTES_CEILING < IN_DECODED,
    "spans mark the run scratch with bit 31, so inputs must stay below 2^31 bytes"
);

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8], limits: Limits) -> Result<Self, JsonError> {
        // About one node per 128 input bytes for real transcripts (12,280 nodes in 1.70 MB),
        // rounded up to a power of two and never above the limit.
        let max = to_usize(limits.max_nodes());
        let initial = (bytes.len() / 128 + 1).next_power_of_two().max(16).min(max);
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(initial)
            .map_err(|_| JsonError::new(ErrorKind::OutOfMemory, 0))?;
        Ok(Self {
            bytes,
            limits,
            nodes,
            stack: Vec::with_capacity(usize::from(limits.max_depth())),
            keys: Vec::new(),
            marks: Vec::with_capacity(usize::from(limits.max_depth())),
            run: RunScratch::default(),
            deepest: 0,
        })
    }

    fn run(&mut self) -> Result<(), JsonError> {
        let start = skip_ws(self.bytes, 0);
        if start == self.bytes.len() {
            return Err(JsonError::new(ErrorKind::Empty, self.bytes.len()));
        }
        let mut step = Step::Value(start, None);
        loop {
            step = match step {
                Step::Value(at, key) => self.value(at, key)?,
                Step::After(at) => match self.after_value(at)? {
                    Some(next) => next,
                    None => return Ok(()),
                },
            };
        }
    }

    /// Records the value starting at `at`.
    fn value(&mut self, at: usize, key: Option<Key>) -> Result<Step, JsonError> {
        let Some(&byte) = self.bytes.get(at) else {
            return Err(JsonError::new(ErrorKind::UnexpectedEnd, at));
        };
        // A byte that cannot start a value is that grammar error, whatever the node count: the
        // limit never hides the first byte that cannot continue the document.
        if !matches!(byte, b'{' | b'[' | b'"' | b'-' | b'0'..=b'9' | b't' | b'f' | b'n') {
            return Err(JsonError::new(ErrorKind::ExpectedValue, at));
        }
        if self.nodes.len() >= to_usize(self.limits.max_nodes()) {
            return Err(JsonError::new(ErrorKind::TooManyNodes, at));
        }
        let parent = self.stack.last().copied().unwrap_or(NONE);
        let (kind, end, flags) = match byte {
            b'{' | b'[' => return self.open(at, byte, parent, key),
            b'"' => {
                let (end, escaped) = scan_string(self.bytes, at)?;
                (Kind::String, end, if escaped { STR_ESCAPED } else { 0 })
            }
            b'-' | b'0'..=b'9' => (Kind::Number, scan_number(self.bytes, at)?, 0),
            b't' => (Kind::True, literal(self.bytes, at, b"true")?, 0),
            b'f' => (Kind::False, literal(self.bytes, at, b"false")?, 0),
            b'n' => (Kind::Null, literal(self.bytes, at, b"null")?, 0),
            _ => return Err(JsonError::new(ErrorKind::ExpectedValue, at)),
        };
        let mut node = RawNode::new(kind, at, parent, key, flags);
        node.end = to_u32(end);
        node.after = to_u32(self.nodes.len() + 1);
        self.push(node, at)?;
        Ok(Step::After(end))
    }

    /// Opens the object or array whose bracket is at `at`.
    fn open(&mut self, at: usize, byte: u8, parent: u32, key: Option<Key>) -> Result<Step, JsonError> {
        if self.stack.len() >= usize::from(self.limits.max_depth()) {
            return Err(JsonError::new(ErrorKind::DepthExceeded, at));
        }
        let (kind, close) = if byte == b'{' {
            (Kind::Object, b'}')
        } else {
            (Kind::Array, b']')
        };
        let id = to_u32(self.nodes.len());
        // `end` and `after` are filled in when the container closes.
        self.push(RawNode::new(kind, at, parent, key, 0), at)?;
        self.stack.push(id);
        if kind == Kind::Object {
            self.marks.push(to_u32(self.keys.len()));
        }
        let depth = u16::try_from(self.stack.len()).unwrap_or(u16::MAX);
        self.deepest = self.deepest.max(depth);
        let next = skip_ws(self.bytes, at + 1);
        if self.bytes.get(next) == Some(&close) {
            return Ok(Step::After(next));
        }
        if kind == Kind::Object {
            let (key, value_at) = self.read_key(next)?;
            self.remember_key(key)?;
            return Ok(Step::Value(value_at, Some(key)));
        }
        Ok(Step::Value(next, None))
    }

    /// After a value: a comma leads to the next one, a closing bracket closes its container.
    /// `None` once the root is complete.
    fn after_value(&mut self, mut at: usize) -> Result<Option<Step>, JsonError> {
        loop {
            let Some(&open) = self.stack.last() else {
                if skip_ws(self.bytes, at) != self.bytes.len() {
                    return Err(JsonError::new(ErrorKind::TrailingData, skip_ws(self.bytes, at)));
                }
                return Ok(None);
            };
            at = skip_ws(self.bytes, at);
            let kind = self.nodes.get(to_usize(open)).map_or(Kind::Array, |node| node.kind);
            let close = if kind == Kind::Object { b'}' } else { b']' };
            match self.bytes.get(at) {
                Some(b',') => {
                    let next = skip_ws(self.bytes, at + 1);
                    if kind == Kind::Object {
                        let (key, value_at) = self.read_key(next)?;
                        self.remember_key(key)?;
                        return Ok(Some(Step::Value(value_at, Some(key))));
                    }
                    return Ok(Some(Step::Value(next, None)));
                }
                Some(&byte) if byte == close => {
                    self.stack.pop();
                    self.close(open, at)?;
                    at += 1;
                }
                Some(_) => return Err(JsonError::new(ErrorKind::ExpectedCommaOrClose, at)),
                None => return Err(JsonError::new(ErrorKind::UnexpectedEnd, at)),
            }
        }
    }

    /// Closes the container `open` at its closing bracket `at`.
    fn close(&mut self, open: u32, at: usize) -> Result<(), JsonError> {
        let after = to_u32(self.nodes.len());
        let kind = match self.nodes.get_mut(to_usize(open)) {
            Some(node) => {
                node.end = to_u32(at + 1);
                node.after = after;
                node.kind
            }
            None => return Err(JsonError::new(ErrorKind::UnexpectedEnd, at)),
        };
        if kind == Kind::Object {
            self.check_duplicate_keys()?;
        }
        Ok(())
    }

    /// Reads a member key and its colon at `at`; returns the key and where its value starts.
    fn read_key(&self, at: usize) -> Result<(Key, usize), JsonError> {
        match self.bytes.get(at) {
            Some(b'"') => {}
            Some(_) => return Err(JsonError::new(ErrorKind::ExpectedKey, at)),
            None => return Err(JsonError::new(ErrorKind::UnexpectedEnd, at)),
        }
        let (end, escaped) = scan_string(self.bytes, at)?;
        let len = u16::try_from(end.saturating_sub(at + 2)).map_err(|_| JsonError::new(ErrorKind::KeyTooLong, at))?;
        let colon = skip_ws(self.bytes, end);
        match self.bytes.get(colon) {
            Some(b':') => {}
            Some(_) => return Err(JsonError::new(ErrorKind::ExpectedColon, colon)),
            None => return Err(JsonError::new(ErrorKind::UnexpectedEnd, colon)),
        }
        // Fingerprinted now, while the bytes are hot, over what the key decodes to.
        let content = self.bytes.get(at + 1..end.saturating_sub(1)).unwrap_or_default();
        let fingerprint = if escaped {
            fingerprint_decoded(content).ok_or(JsonError::new(ErrorKind::InvalidEscape, at))?
        } else {
            fingerprint(content)
        };
        let key = Key {
            start: to_u32(at),
            len,
            escaped,
            fingerprint,
        };
        Ok((key, skip_ws(self.bytes, colon + 1)))
    }

    /// Records the key of the member about to be pushed: the next node is that member.
    fn remember_key(&mut self, key: Key) -> Result<(), JsonError> {
        if self.keys.len() == self.keys.capacity() {
            // Grown like the tape: doubling, never beyond one entry per node.
            let max = to_usize(self.limits.max_nodes());
            let target = self.keys.capacity().saturating_mul(2).max(16).min(max);
            let additional = target.saturating_sub(self.keys.len()).max(1);
            self.keys
                .try_reserve_exact(additional)
                .map_err(|_| JsonError::new(ErrorKind::OutOfMemory, to_usize(key.start)))?;
        }
        let member = to_u32(self.nodes.len());
        self.keys.push((u64::from(key.fingerprint) << 32) | u64::from(member));
        Ok(())
    }

    /// Appends a node, growing the tape by doubling up to the node limit.
    fn push(&mut self, node: RawNode, at: usize) -> Result<(), JsonError> {
        if self.nodes.len() == self.nodes.capacity() {
            let max = to_usize(self.limits.max_nodes());
            let target = self.nodes.capacity().saturating_mul(2).max(16).min(max);
            let additional = target.saturating_sub(self.nodes.len()).max(1);
            self.nodes
                .try_reserve_exact(additional)
                .map_err(|_| JsonError::new(ErrorKind::OutOfMemory, at))?;
        }
        self.nodes.push(node);
        Ok(())
    }

    /// Refuses the closing object if its members share a key once decoded. Its members are the
    /// top segment of `keys`, fingerprinted as they were read: O(m log m), allocating only into
    /// the reused side stack and run scratch.
    fn check_duplicate_keys(&mut self) -> Result<(), JsonError> {
        let mark = self.marks.pop().map_or(self.keys.len(), to_usize);
        let found = self.keys.get_mut(mark..).map_or(Ok(()), |members| {
            find_duplicate(self.bytes, &self.nodes, members, &mut self.run)
        });
        self.keys.truncate(mark);
        found
    }
}

/// Finds a repeated key among an object's members, given as `keys` entries (fingerprint, node
/// id). Equal decoded keys always share a fingerprint, so only members that share one are
/// compared exactly (`repeat_in_run`).
fn find_duplicate(
    bytes: &[u8],
    nodes: &[RawNode],
    members: &mut [u64],
    scratch: &mut RunScratch,
) -> Result<(), JsonError> {
    if members.len() < 2 || (members.len() <= PAIRWISE_MEMBERS && !any_shared_fingerprint(members)) {
        return Ok(());
    }
    // By fingerprint, then node id: members sharing a fingerprint are adjacent.
    members.sort_unstable();
    // Report the duplicate a streaming reader meets first: the earliest second occurrence.
    let mut first_repeat: Option<u32> = None;
    for run in members.chunk_by(|x, y| x >> 32 == y >> 32) {
        if run.len() < 2 {
            continue;
        }
        if let Some(later) = repeat_in_run(bytes, nodes, run, scratch)? {
            first_repeat = Some(first_repeat.map_or(later, |seen| seen.min(later)));
        }
    }
    match first_repeat {
        Some(at) => Err(JsonError::new(ErrorKind::DuplicateKey, to_usize(at))),
        None => Ok(()),
    }
}

/// The earliest second occurrence of a key among one run of members that share a fingerprint, if
/// any. Each escaped key is decoded once into the scratch and every key is then compared as bytes,
/// so a run crafted to collide costs one decode per key plus O(m log m) byte comparisons, never a
/// decode per comparison.
fn repeat_in_run(
    bytes: &[u8],
    nodes: &[RawNode],
    run: &[u64],
    scratch: &mut RunScratch,
) -> Result<Option<u32>, JsonError> {
    let RunScratch { decoded, spans, order } = scratch;
    decoded.clear();
    spans.clear();
    order.clear();
    let node = |position: u32| {
        run.get(to_usize(position))
            .and_then(|&member| nodes.get(to_usize(member_id(member))))
    };
    let oom = |at: u32| JsonError::new(ErrorKind::OutOfMemory, to_usize(at));
    let first_key = node(0).map_or(0, |n| n.key_start);
    // Exact reservations, one per run after `clear`: the scratch holds at most what the largest run
    // needs, 12 B per member plus its escaped keys, which decode to at most their raw length.
    let escaped: usize = (0..to_u32(run.len()))
        .filter_map(node)
        .filter(|member| member.flags & KEY_ESCAPED != 0)
        .map(|member| usize::from(member.key_len))
        .sum();
    spans.try_reserve_exact(run.len()).map_err(|_| oom(first_key))?;
    order.try_reserve_exact(run.len()).map_err(|_| oom(first_key))?;
    decoded.try_reserve_exact(escaped).map_err(|_| oom(first_key))?;
    for position in 0..to_u32(run.len()) {
        let Some(member) = node(position) else {
            spans.push((0, 0));
            order.push(position);
            continue;
        };
        let content = key_content(bytes, member);
        if member.flags & KEY_ESCAPED == 0 {
            spans.push((member.key_start + 1, u32::from(member.key_len)));
        } else {
            // Within the reservation above: an escaped key decodes to at most its raw length.
            let start = decoded.len();
            let mut unescaped = Unescape::new(content);
            decoded.extend(unescaped.by_ref());
            if unescaped.broken() {
                // The scan already ruled this out: kept fail-closed.
                return Err(JsonError::new(ErrorKind::InvalidEscape, to_usize(member.key_start)));
            }
            spans.push((to_u32(start) | IN_DECODED, to_u32(decoded.len() - start)));
        }
        order.push(position);
    }
    let key = |position: u32| -> &[u8] {
        let (start, len) = spans.get(to_usize(position)).copied().unwrap_or((0, 0));
        let (source, start) = if start & IN_DECODED == 0 {
            (bytes, start)
        } else {
            (decoded.as_slice(), start & !IN_DECODED)
        };
        source
            .get(to_usize(start)..to_usize(start) + to_usize(len))
            .unwrap_or_default()
    };
    let key_start = |position: u32| node(position).map_or(0, |n| n.key_start);
    order.sort_unstable_by(|&a, &b| key(a).cmp(key(b)).then(key_start(a).cmp(&key_start(b))));
    let mut first_repeat: Option<u32> = None;
    for pair in order.windows(2) {
        if let [a, b] = pair
            && key(*a) == key(*b)
        {
            let later = key_start(*a).max(key_start(*b));
            first_repeat = Some(first_repeat.map_or(later, |seen| seen.min(later)));
        }
    }
    Ok(first_repeat)
}

/// Up to this many members, fingerprints are compared pairwise in place (at most 28 integer
/// comparisons) instead of sorted: most objects in agent traffic have two to four members, and
/// sorting cost about 0.26 ms of the reference transcript's parse.
const PAIRWISE_MEMBERS: usize = 8;

/// Whether two of a small object's members share a fingerprint. Only then can two of its keys be
/// equal, and the exact path decides.
fn any_shared_fingerprint(members: &[u64]) -> bool {
    let mut rest = members;
    while let Some((first, others)) = rest.split_first() {
        if others.iter().any(|other| first >> 32 == other >> 32) {
            return true;
        }
        rest = others;
    }
    false
}

/// The member's node id: the low half of a `keys` entry.
fn member_id(member: u64) -> u32 {
    u32::try_from(member & u64::from(u32::MAX)).unwrap_or(NONE)
}

const FINGERPRINT_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
const FINGERPRINT_MULTIPLIER: u64 = 0x517C_C1B7_2722_0A95;
/// murmur3's `fmix64` multipliers.
const FMIX_FIRST: u64 = 0xFF51_AFD7_ED55_8CCD;
const FMIX_SECOND: u64 = 0xC4CE_B9FE_1A85_EC53;

/// A 32-bit fingerprint of a key's decoded bytes, taken eight bytes at a time: multiply, then
/// fold the high bits back down, and finish with murmur3's `fmix64`. On structured key sets
/// (`key-N`, `tool_use_N`, shared prefixes, short binary keys) it collides at the ideal rate for
/// 32 bits, within 11%; a plain multiply collided about 200 times more often on `key-N`.
/// Equal byte sequences always get equal fingerprints, and a collision only costs an exact
/// comparison. Not a security boundary, and not a hash table: nothing is ever accepted or
/// refused on a fingerprint alone.
struct Fingerprint {
    hash: u64,
    word: u64,
    filled: u32,
    len: u64,
}

impl Fingerprint {
    const fn new() -> Self {
        Self {
            hash: FINGERPRINT_SEED,
            word: 0,
            filled: 0,
            len: 0,
        }
    }

    fn push(&mut self, byte: u8) {
        self.word |= u64::from(byte) << (8 * self.filled);
        self.filled += 1;
        self.len += 1;
        if self.filled == 8 {
            self.mix();
        }
    }

    const fn mix(&mut self) {
        let mixed = (self.hash ^ self.word).wrapping_mul(FINGERPRINT_MULTIPLIER);
        self.hash = mixed ^ (mixed >> 29);
        self.word = 0;
        self.filled = 0;
    }

    fn finish(mut self) -> u32 {
        if self.filled > 0 {
            self.mix();
        }
        // murmur3's 64-bit finalizer.
        let mut k = self.hash ^ self.len;
        k ^= k >> 33;
        k = k.wrapping_mul(FMIX_FIRST);
        k ^= k >> 33;
        k = k.wrapping_mul(FMIX_SECOND);
        k ^= k >> 33;
        u32::try_from(k >> 32).unwrap_or(0)
    }
}

/// The fingerprint of a key without escapes: its raw bytes are its decoded bytes. Whole words
/// first, exactly as `Fingerprint::push` would fold them.
fn fingerprint(content: &[u8]) -> u32 {
    let mut fp = Fingerprint::new();
    let (words, rest) = content.as_chunks::<8>();
    for &word in words {
        fp.word = u64::from_le_bytes(word);
        fp.len += 8;
        fp.mix();
    }
    for &byte in rest {
        fp.push(byte);
    }
    fp.finish()
}

/// The fingerprint of an escaped key, over the bytes it decodes to, without allocating. `None`
/// if an escape fails to decode, which the scan already ruled out: kept fail-closed.
fn fingerprint_decoded(content: &[u8]) -> Option<u32> {
    let mut fp = Fingerprint::new();
    let mut decoded = Unescape::new(content);
    for byte in decoded.by_ref() {
        fp.push(byte);
    }
    if decoded.broken() {
        return None;
    }
    Some(fp.finish())
}

fn key_content<'b>(bytes: &'b [u8], node: &RawNode) -> &'b [u8] {
    let start = to_usize(node.key_start) + 1;
    bytes.get(start..start + usize::from(node.key_len)).unwrap_or_default()
}

fn skip_ws(bytes: &[u8], mut at: usize) -> usize {
    while matches!(bytes.get(at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        at += 1;
    }
    at
}

fn literal(bytes: &[u8], at: usize, text: &[u8]) -> Result<usize, JsonError> {
    if bytes.get(at..at + text.len()) == Some(text) {
        Ok(at + text.len())
    } else {
        Err(JsonError::new(ErrorKind::InvalidLiteral, at))
    }
}

/// Scans the string whose opening quote is at `open`. Returns the offset after its closing
/// quote and whether it holds an escape.
fn scan_string(bytes: &[u8], open: usize) -> Result<(usize, bool), JsonError> {
    let mut at = open + 1;
    let mut escaped = false;
    loop {
        // Jump to the next quote or backslash, then prove the run between holds no raw
        // control byte (one vectorizable pass).
        let rest = bytes.get(at..).unwrap_or_default();
        let next = memchr::memchr2(b'"', b'\\', rest).map_or(bytes.len(), |found| at + found);
        let run = bytes.get(at..next).unwrap_or_default();
        // Branch-free over the whole run, so it vectorizes; the position is searched only once a
        // control byte is known to be there.
        let control = run.iter().fold(0_u8, |seen, &byte| seen | u8::from(byte < 0x20));
        if control != 0
            && let Some(found) = run.iter().position(|&byte| byte < 0x20)
        {
            return Err(JsonError::new(ErrorKind::ControlCharacter, at + found));
        }
        at = next;
        match bytes.get(at) {
            None => return Err(JsonError::new(ErrorKind::UnterminatedString, open)),
            Some(b'"') => return Ok((at + 1, escaped)),
            Some(_) => {
                escaped = true;
                at = scan_escape(bytes, open, at)?;
            }
        }
    }
}

/// Checks the escape whose backslash is at `at`; returns the offset after it.
fn scan_escape(bytes: &[u8], open: usize, at: usize) -> Result<usize, JsonError> {
    match bytes.get(at + 1) {
        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => Ok(at + 2),
        Some(b'u') => {
            let unit = hex4(bytes, at + 2).ok_or(JsonError::new(ErrorKind::InvalidUnicodeEscape, at))?;
            let paired = is_high_surrogate(unit) && low_surrogate_at(bytes, at + 6).is_some();
            if paired {
                return Ok(at + 12);
            }
            let lone = is_high_surrogate(unit) || is_low_surrogate(unit);
            if lone {
                return Err(JsonError::new(ErrorKind::LoneSurrogate, at));
            }
            Ok(at + 6)
        }
        Some(_) => Err(JsonError::new(ErrorKind::InvalidEscape, at)),
        None => Err(JsonError::new(ErrorKind::UnterminatedString, open)),
    }
}

/// Scans the number starting at `start` (RFC 8259 §6, grammar only); returns its end.
fn scan_number(bytes: &[u8], start: usize) -> Result<usize, JsonError> {
    let invalid = || JsonError::new(ErrorKind::InvalidNumber, start);
    let mut j = start;
    if bytes.get(j) == Some(&b'-') {
        j += 1;
    }
    match bytes.get(j) {
        Some(b'0') => j += 1,
        Some(b'1'..=b'9') => j = skip_digits(bytes, j),
        _ => return Err(invalid()),
    }
    // Only a leading zero can be followed by a digit here: `01`.
    if is_digit(bytes.get(j)) {
        return Err(invalid());
    }
    if bytes.get(j) == Some(&b'.') {
        j += 1;
        if !is_digit(bytes.get(j)) {
            return Err(invalid());
        }
        j = skip_digits(bytes, j);
    }
    if matches!(bytes.get(j), Some(b'e' | b'E')) {
        j += 1;
        if matches!(bytes.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        if !is_digit(bytes.get(j)) {
            return Err(invalid());
        }
        j = skip_digits(bytes, j);
    }
    Ok(j)
}

fn skip_digits(bytes: &[u8], mut at: usize) -> usize {
    while is_digit(bytes.get(at)) {
        at += 1;
    }
    at
}

fn is_digit(byte: Option<&u8>) -> bool {
    byte.is_some_and(u8::is_ascii_digit)
}

impl<'a> Tape<'a> {
    fn new(input: &'a str, nodes: Vec<RawNode>, deepest: u16, limits: Limits) -> Result<Self, JsonError> {
        let root = nodes
            .first()
            .copied()
            .ok_or(JsonError::new(ErrorKind::Empty, input.len()))?;
        Ok(Self {
            input,
            nodes,
            root,
            deepest,
            limits,
        })
    }

    /// The limits the tape was parsed under. A reader that writes a changed copy of the input
    /// checks the copy against these, so the next parse of it accepts what this one did.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// The input, validated as UTF-8.
    #[must_use]
    pub const fn input(&self) -> &'a str {
        self.input
    }

    /// The root value.
    #[must_use]
    pub const fn root(&self) -> Node<'_, 'a> {
        Node::new(self, 0, self.root)
    }

    /// The node at `id`.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<Node<'_, 'a>> {
        self.nodes.get(id.index()).map(|raw| Node::new(self, id.get(), *raw))
    }

    /// Every node, in pre-order (the root first).
    #[must_use]
    pub fn nodes(&self) -> Descendants<'_, 'a> {
        Descendants::new(self, 0, to_u32(self.nodes.len()))
    }

    /// Counts and sizes, for callers to report.
    #[must_use]
    pub fn stats(&self) -> TapeStats {
        TapeStats {
            nodes: to_u32(self.nodes.len()),
            max_depth: self.deepest,
            input_bytes: to_u32(self.input.len()),
            heap_bytes: self.nodes.capacity().saturating_mul(std::mem::size_of::<RawNode>()),
        }
    }

    /// The text a span covers; empty if the span lies outside the input.
    pub(crate) fn slice(&self, span: Span) -> &'a str {
        self.input.get(span.range()).unwrap_or_default()
    }

    /// Re-checks every structural invariant of the contract from scratch. For tests and fuzzing; a
    /// tape [`parse`] returns always passes.
    ///
    /// # Errors
    ///
    /// The first invariant broken, and the node where it breaks.
    pub fn verify(&self) -> Result<(), Violation> {
        let count = self.nodes.len();
        if count == 0 || count > to_usize(Limits::MAX_NODES_CEILING) {
            return Err(Violation::new(0, "node count out of range"));
        }
        if self.root.parent != NONE
            || self.root.flags & (HAS_KEY | KEY_ESCAPED) != 0
            || self.root.key_start != 0
            || self.root.key_len != 0
        {
            return Err(Violation::new(0, "the root has a parent or a key"));
        }
        if to_usize(self.root.after) != count {
            return Err(Violation::new(0, "the root's subtree is not the whole tape"));
        }
        let mut levels: Vec<u16> = Vec::with_capacity(count);
        let mut deepest = 0_u16;
        for (index, node) in self.nodes.iter().enumerate() {
            self.verify_node(index, node)?;
            let level = if index == 0 {
                0
            } else {
                levels
                    .get(to_usize(node.parent))
                    .map_or(0, |parent| parent.saturating_add(1))
            };
            levels.push(level);
            if node.kind.is_container() {
                deepest = deepest.max(level.saturating_add(1));
                self.verify_children(index, node)?;
            }
            if node.kind == Kind::Object {
                self.verify_unique_keys(index)?;
            }
        }
        if deepest != self.deepest {
            return Err(Violation::new(0, "the recorded depth is not the deepest nesting"));
        }
        Ok(())
    }

    /// Invariants 1 and 3 to 6 for one node.
    fn verify_node(&self, index: usize, node: &RawNode) -> Result<(), Violation> {
        let bytes = self.input.as_bytes();
        let fail = |rule| Err(Violation::new(index, rule));
        if node.flags & !KNOWN_FLAGS != 0 {
            return fail("unknown flag bits set");
        }
        if node.start >= node.end || to_usize(node.end) > bytes.len() {
            return fail("span empty or outside the input");
        }
        let after = to_usize(node.after);
        if after <= index || after > self.nodes.len() {
            return fail("subtree end out of range");
        }
        if !node.kind.is_container() && after != index + 1 {
            return fail("a scalar's subtree is not itself");
        }
        if !self.kind_matches_bytes(node) {
            return fail("kind does not match the bytes");
        }
        let content = Span {
            start: node.start.saturating_add(1),
            end: node.end.saturating_sub(1),
        };
        let escaped = node.kind == Kind::String && self.slice(content).contains('\\');
        if (node.flags & STR_ESCAPED != 0) != escaped {
            return fail("string escape flag does not match the content");
        }
        if index == 0 {
            return Ok(());
        }
        let Some(parent) = self.nodes.get(to_usize(node.parent)) else {
            return fail("parent out of range");
        };
        if to_usize(node.parent) >= index || !parent.kind.is_container() {
            return fail("parent is not an earlier container");
        }
        if node.start <= parent.start || node.end >= parent.end || node.after > parent.after {
            return fail("not inside its parent");
        }
        self.verify_key(index, node, parent)
    }

    /// Invariant 5 and the key half of invariant 6.
    fn verify_key(&self, index: usize, node: &RawNode, parent: &RawNode) -> Result<(), Violation> {
        let fail = |rule| Err(Violation::new(index, rule));
        let has_key = node.flags & HAS_KEY != 0;
        if has_key != (parent.kind == Kind::Object) {
            return fail("a member key exactly when the parent is an object");
        }
        if !has_key {
            if node.key_start != 0 || node.key_len != 0 || node.flags & KEY_ESCAPED != 0 {
                return fail("key fields set outside an object");
            }
            return Ok(());
        }
        let quoted = Span {
            start: node.key_start,
            end: node.key_start.saturating_add(u32::from(node.key_len)).saturating_add(2),
        };
        if quoted.start <= parent.start || quoted.end > node.start {
            return fail("key not between its parent's bracket and its value");
        }
        let text = self.slice(quoted);
        let is_quoted = text.len() >= 2 && text.starts_with('"') && text.ends_with('"');
        if !is_quoted {
            return fail("key not quoted");
        }
        let content = Span {
            start: quoted.start.saturating_add(1),
            end: quoted.end.saturating_sub(1),
        };
        if (node.flags & KEY_ESCAPED != 0) != self.slice(content).contains('\\') {
            return fail("key escape flag does not match the key");
        }
        Ok(())
    }

    /// Invariant 4.
    fn kind_matches_bytes(&self, node: &RawNode) -> bool {
        let text = self.slice(Span {
            start: node.start,
            end: node.end,
        });
        let bytes = text.as_bytes();
        let (first, last) = (bytes.first(), bytes.last());
        match node.kind {
            Kind::Object => first == Some(&b'{') && last == Some(&b'}'),
            Kind::Array => first == Some(&b'[') && last == Some(&b']'),
            Kind::String => bytes.len() >= 2 && first == Some(&b'"') && last == Some(&b'"'),
            Kind::Number => matches!(first, Some(b'-' | b'0'..=b'9')) && last.is_some_and(u8::is_ascii_digit),
            Kind::True => text == "true",
            Kind::False => text == "false",
            Kind::Null => text == "null",
        }
    }

    /// Invariants 2 and 3 for a container's children: they chain through `after`, in order,
    /// disjoint, and end exactly at the container's subtree end.
    fn verify_children(&self, index: usize, node: &RawNode) -> Result<(), Violation> {
        let fail = |at: usize, rule| Err(Violation::new(at, rule));
        let mut child = index + 1;
        let mut free_from = node.start.saturating_add(1);
        while child < to_usize(node.after) {
            let Some(raw) = self.nodes.get(child) else {
                return fail(child, "child out of range");
            };
            if to_usize(raw.parent) != index {
                return fail(child, "child's parent is not its container");
            }
            let begins = if raw.flags & HAS_KEY != 0 {
                raw.key_start
            } else {
                raw.start
            };
            if begins < free_from {
                return fail(child, "siblings overlap or are out of order");
            }
            free_from = raw.end;
            let next = to_usize(raw.after);
            if next <= child {
                return fail(child, "subtree end does not move forward");
            }
            child = next;
        }
        if child != to_usize(node.after) {
            return fail(index, "children do not end at the subtree end");
        }
        Ok(())
    }

    /// Invariant 7, independently of the parser's sort: a set of decoded keys.
    fn verify_unique_keys(&self, index: usize) -> Result<(), Violation> {
        let Some(object) = self.node(NodeId::new(to_u32(index))) else {
            return Err(Violation::new(index, "object out of range"));
        };
        let mut seen = BTreeSet::new();
        for member in object.children() {
            let at = member.id().index();
            let key = member
                .key()
                .map_err(|_| Violation::new(at, "a key does not decode"))?
                .ok_or(Violation::new(at, "a member has no key"))?;
            if !seen.insert(key) {
                return Err(Violation::new(at, "duplicate key"));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Tape<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Sizes only: the input may hold secrets.
        f.debug_struct("Tape")
            .field("input_len", &self.input.len())
            .field("nodes", &self.nodes.len())
            .field("max_depth", &self.deepest)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests: a failed fixture must abort the test")]
mod tests {
    use std::fmt::Write as _;

    use super::{Fingerprint, Parser, fingerprint, fingerprint_decoded};
    use crate::decode::UNESCAPED;
    use crate::error::ErrorKind;
    use crate::fingerprint_copy;
    use crate::{Limits, parse, to_u32};

    /// `tests/grammar.rs` (`distinct_keys_sharing_a_fingerprint_are_accepted`) relies on these
    /// two distinct keys sharing a fingerprint. If the fingerprint changes, find a new pair
    /// (any two distinct keys whose fingerprints are equal) and update both tests.
    #[test]
    fn the_grammar_tests_colliding_keys_collide() {
        assert_eq!(fingerprint(b"k4312"), fingerprint(b"k27385"));
        assert_eq!(fingerprint(b"k4312"), 0xd14d_3837);
    }

    fn bytes_of(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes().first().copied().unwrap_or(0)
            })
            .collect()
    }

    fn bytewise(content: &[u8]) -> u32 {
        let mut fp = Fingerprint::new();
        for &byte in content {
            fp.push(byte);
        }
        fp.finish()
    }

    /// Writes `content` as JSON string content: the bytes listed in `escape` (by position) as
    /// a backslash-u escape, the others raw. Every byte must be ASCII.
    fn spell(content: &[u8], escape: impl Fn(usize, u8) -> bool, out: &mut String) {
        let backslash = "\\";
        for (i, &byte) in content.iter().enumerate() {
            if escape(i, byte) || byte < 0x20 || byte == b'"' || byte == b'\\' {
                write!(out, "{backslash}u{byte:04x}").unwrap();
            } else {
                out.push(char::from(byte));
            }
        }
    }

    /// Raw keys are fingerprinted a word at a time and escaped ones a byte at a time; an object is
    /// accepted when its fingerprints differ, so the two paths must agree on every length, whole
    /// words and remainders alike.
    #[test]
    fn the_word_path_equals_the_byte_path() {
        for len in 0..=40 {
            for seed in 0..64 {
                let content = bytes_of(seed * 41 + u64::try_from(len).unwrap(), len);
                assert_eq!(
                    fingerprint(&content),
                    bytewise(&content),
                    "word path differs from the byte path at length {len}"
                );
            }
        }
    }

    /// Every spelling of a key, raw or escaped in any mix, gets the raw key's fingerprint.
    #[test]
    fn escaped_spellings_share_the_raw_fingerprint() {
        for len in 0..=40 {
            for seed in 0..16 {
                let ascii: Vec<u8> = bytes_of(seed * 97 + u64::try_from(len).unwrap(), len)
                    .into_iter()
                    .map(|b| b & 0x7F)
                    .collect();
                let expected = fingerprint(&ascii);
                for style in 0..4_usize {
                    let mut spelled = String::new();
                    spell(
                        &ascii,
                        |i, _| style == 0 || (style == 1 && i == 0) || (style == 2 && i % 3 == 1),
                        &mut spelled,
                    );
                    if style == 3 {
                        spelled.clear();
                        spell(&ascii, |i, _| i + 1 == len, &mut spelled);
                    }
                    assert_eq!(
                        fingerprint_decoded(spelled.as_bytes()),
                        Some(expected),
                        "an escaped spelling of a {len}-byte key differs from the raw fingerprint"
                    );
                }
            }
        }
    }

    /// The bench crafts its collision rows with a copy of the fingerprint: the copy must be the
    /// fingerprint, raw and decoded, at every length.
    #[test]
    fn the_bench_copy_is_the_fingerprint() {
        for len in 0..=40 {
            for seed in 0..32 {
                let content = bytes_of(seed * 53 + u64::try_from(len).unwrap(), len);
                assert_eq!(
                    fingerprint_copy::of(&content),
                    fingerprint(&content),
                    "the bench's fingerprint copy drifted at length {len}"
                );
            }
        }
    }

    /// Keys crafted to share one fingerprint are accepted, and a repeat among them, spelled
    /// differently, is found where it starts.
    #[test]
    fn crafted_collisions_are_compared_exactly() {
        let target = 0x5eed_0019;
        let prefix = [b'p'; 40];
        let suffixes = fingerprint_copy::colliding_suffixes(&prefix, target, 2_000);
        let mut text = String::from("{");
        for (i, suffix) in suffixes.iter().enumerate() {
            if i > 0 {
                text.push(',');
            }
            let mut key = String::new();
            let decoded: Vec<u8> = prefix.iter().chain(suffix.iter()).copied().collect();
            spell(&decoded, |_, _| true, &mut key);
            assert_eq!(
                fingerprint_decoded(key.as_bytes()),
                Some(target),
                "crafted key {i} does not collide"
            );
            write!(text, "\"{key}\":{i}").unwrap();
        }
        text.push('}');
        // Each key is decoded once to fingerprint it and once in its run. Decoding again at every
        // comparison would cost about log2(2,000) = 11 times
        // as much.
        UNESCAPED.with(|n| n.set(0));
        assert!(
            parse(text.as_bytes(), &Limits::DEFAULT).is_ok(),
            "crafted colliding keys refused"
        );
        let decoded_bytes = 2_000 * u64::try_from(prefix.len() + 8).unwrap();
        let produced = UNESCAPED.with(std::cell::Cell::get);
        assert!(
            produced <= 3 * decoded_bytes,
            "a crafted run decoded {produced} bytes, more than once per key ({decoded_bytes})"
        );

        text.pop();
        text.push(',');
        let at = to_u32(text.len());
        text.push('"');
        let repeat: Vec<u8> = prefix
            .iter()
            .chain(suffixes.get(1000).unwrap().iter())
            .copied()
            .collect();
        spell(&repeat, |_, _| false, &mut text);
        text.push_str("\":0}");
        assert_eq!(
            parse(text.as_bytes(), &Limits::DEFAULT)
                .err()
                .map(|e| (e.kind(), e.offset())),
            Some((ErrorKind::DuplicateKey, at)),
            "a repeat among crafted colliding keys was accepted, or reported elsewhere"
        );
    }

    /// The side stack holds one entry per key of the open objects and grows like the tape, so its
    /// capacity never passes the node limit.
    #[test]
    fn the_side_stack_never_outgrows_the_node_limit() {
        let mut wide = String::from("{");
        for i in 0..1_000_000 {
            write!(wide, "\"k{i}\":0,").unwrap();
        }
        wide.push_str("\"end\":0}");
        let limits = Limits::DEFAULT;
        let mut parser = Parser::new(wide.as_bytes(), limits).unwrap();
        parser.run().unwrap();
        let entries = parser.keys.capacity();
        assert!(entries >= 1_000_001, "the side stack held {entries} entries");
        assert!(
            entries <= crate::to_usize(limits.max_nodes()),
            "the side stack reached {entries} entries"
        );

        let small = Limits::new(1 << 20, 128, 1_000).unwrap();
        let mut narrow = String::from("{");
        for i in 0..998 {
            write!(narrow, "\"k{i}\":0,").unwrap();
        }
        narrow.push_str("\"end\":0}");
        let mut parser = Parser::new(narrow.as_bytes(), small).unwrap();
        parser.run().unwrap();
        assert!(
            parser.keys.capacity() <= 1_000,
            "the side stack passed a node limit of 1,000"
        );
    }

    /// The run scratch holds at most what the largest run needs: one exact reservation per run,
    /// never doubling past the escaped keys' raw length.
    #[test]
    fn the_run_scratch_stays_within_its_bound() {
        let target = 0x5eed_0020;
        let prefix = [b'p'; 4096];
        let suffixes = fingerprint_copy::colliding_suffixes(&prefix, target, 33);
        let mut text = String::from("{");
        let mut raw_escaped = 0;
        for (i, suffix) in suffixes.iter().enumerate() {
            if i > 0 {
                text.push(',');
            }
            let mut key = String::new();
            let decoded: Vec<u8> = prefix.iter().chain(suffix.iter()).copied().collect();
            // Only the first byte escaped: the raw key is barely longer than its decoded form.
            spell(&decoded, |position, _| position == 0, &mut key);
            raw_escaped += key.len();
            write!(text, "\"{key}\":{i}").unwrap();
        }
        text.push('}');
        let mut parser = Parser::new(text.as_bytes(), Limits::DEFAULT).unwrap();
        parser.run().unwrap();
        let scratch = &parser.run;
        assert!(
            scratch.decoded.capacity() <= raw_escaped,
            "run scratch {} bytes, its escaped keys {raw_escaped}",
            scratch.decoded.capacity()
        );
        assert!(
            scratch.spans.capacity() <= 33 && scratch.order.capacity() <= 33,
            "run scratch grew past the run"
        );
    }
}
