// SPDX-License-Identifier: Apache-2.0

//! The event-stream splitter.
//!
//! It finds where each event ends in a stream that arrives in arbitrary pieces, and reads an
//! event's fields. It follows WHATWG `text/event-stream`:
//! - a line ends in CRLF, LF or CR;
//! - a CRLF split across two pieces is one line ending;
//! - an event ends at a blank line;
//! - a leading byte-order mark is not part of the first line.
//!
//! Each event is shown to a check, in order, as its exact bytes, final line ending included. What
//! one piece clears for the client comes back as at most two runs of exact bytes, so the bytes
//! forwarded are the bytes received and nothing is kept per event.

use std::borrow::Cow;
use std::fmt;

use bytes::{Bytes, BytesMut};

/// UTF-8 byte-order mark.
const BOM: &[u8] = b"\xEF\xBB\xBF";

/// One event as a check sees it: its exact bytes, of which the first `skip` (the stream's
/// byte-order mark) are forwarded but not parsed.
#[derive(Clone, Copy)]
pub(crate) struct Event<'a> {
    raw: &'a [u8],
    skip: usize,
}

impl fmt::Debug for Event<'_> {
    // Lengths only: the bytes are upstream content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Event")
            .field("len", &self.raw.len())
            .field("skip", &self.skip)
            .finish()
    }
}

impl<'a> Event<'a> {
    /// The bytes an event-stream parser reads.
    pub(crate) fn parsed(&self) -> &'a [u8] {
        self.raw.get(self.skip..).unwrap_or_default()
    }

    /// Its exact bytes.
    #[cfg(test)]
    pub(crate) const fn raw(&self) -> &'a [u8] {
        self.raw
    }
}

/// What one piece cleared for the client, in order: the event completed from earlier pieces
/// (copied once, as its start was held), then one run of the piece's own bytes, a slice of it.
#[derive(Default)]
pub(crate) struct Cleared {
    pub(crate) copied: Option<Bytes>,
    pub(crate) run: Option<Bytes>,
    /// Events and comment blocks in `copied` and `run`.
    pub(crate) events: u64,
}

impl fmt::Debug for Cleared {
    // Lengths only: the bytes are upstream content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cleared")
            .field("copied", &self.copied.as_ref().map(Bytes::len))
            .field("run", &self.run.as_ref().map(Bytes::len))
            .field("events", &self.events)
            .finish()
    }
}

/// Why a piece was not cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PushError<E> {
    /// An event passed the bound.
    TooLarge,
    /// The check refused an event.
    Refused(E),
}

/// Splits a byte stream into events.
pub(crate) struct Splitter {
    /// The start of an event whose end has not arrived yet.
    pending: BytesMut,
    /// The first bytes of a stream whose first piece was shorter than three bytes, held until
    /// three have arrived to tell a byte-order mark. `None` once that is decided.
    prelude: Option<BytesMut>,
    /// Bytes at the front of the next event the parser skips (the byte-order mark).
    skip: usize,
    /// Nothing is on the current line yet.
    at_line_start: bool,
    /// The last byte seen was a CR with nothing after it yet: an LF next belongs to it. Holds
    /// whether the line it ended was blank.
    pending_cr: Option<bool>,
    max_event: usize,
}

impl fmt::Debug for Splitter {
    // Lengths only: the held bytes are upstream content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Splitter")
            .field("pending", &self.pending.len())
            .field("prelude", &self.prelude.as_ref().map(BytesMut::len))
            .field("max_event", &self.max_event)
            .finish_non_exhaustive()
    }
}

impl Splitter {
    pub(crate) fn new(max_event: usize) -> Self {
        Self {
            pending: BytesMut::new(),
            prelude: Some(BytesMut::new()),
            skip: 0,
            at_line_start: true,
            pending_cr: None,
            max_event,
        }
    }

    /// Splits `chunk`. Every event that ends in it is shown to `check`, in order; what remains
    /// is kept for the next chunk. Returns what the chunk cleared.
    ///
    /// # Errors
    /// [`PushError::TooLarge`] once an event passes the bound, or [`PushError::Refused`] with
    /// the check's error. Either way nothing of the chunk is cleared.
    pub(crate) fn push<E>(
        &mut self,
        chunk: &Bytes,
        check: impl FnMut(Event<'_>) -> Result<(), E>,
    ) -> Result<Cleared, PushError<E>> {
        let Some(prelude) = &mut self.prelude else {
            return self.split(chunk, 0, check);
        };
        // The byte-order mark is told in place when the first piece holds three bytes, so the first
        // piece is not copied.
        let first = if prelude.is_empty() && chunk.len() >= BOM.len() {
            chunk.clone()
        } else {
            prelude.extend_from_slice(chunk);
            if prelude.len() < BOM.len() {
                return if prelude.len() > self.max_event {
                    Err(PushError::TooLarge)
                } else {
                    Ok(Cleared::default())
                };
            }
            prelude.split().freeze()
        };
        self.prelude = None;
        let from = if first.starts_with(BOM) { BOM.len() } else { 0 };
        self.skip = from;
        self.split(&first, from, check)
    }

    /// At the end of the stream: whatever remains, as one last event. A lenient client may act
    /// on an event that no blank line ended, so the relay classifies it too. Returns its bytes
    /// and how many at the front the parser skips.
    pub(crate) fn finish(&mut self) -> Option<(Bytes, usize)> {
        if let Some(prelude) = self.prelude.take() {
            // Fewer than three bytes ever arrived: no byte-order mark fits.
            return (!prelude.is_empty()).then(|| (prelude.freeze(), 0));
        }
        self.pending_cr = None;
        if self.pending.is_empty() {
            return None;
        }
        Some((self.pending.split().freeze(), std::mem::take(&mut self.skip)))
    }

    fn split<E>(
        &mut self,
        chunk: &Bytes,
        from: usize,
        mut check: impl FnMut(Event<'_>) -> Result<(), E>,
    ) -> Result<Cleared, PushError<E>> {
        // `start` is where the chunk's not yet emitted bytes begin; `scan` is where to look;
        // `run` is the span of this chunk's own cleared events.
        let mut cleared = Cleared::default();
        let mut run: Option<(usize, usize)> = None;
        let mut start = 0;
        let mut scan = from;
        loop {
            let Some(end) = self.find_end(chunk, scan) else {
                let held = self.pending.len() + (chunk.len() - start);
                if held > self.max_event {
                    return Err(PushError::TooLarge);
                }
                self.pending.extend_from_slice(&chunk[start..]);
                break;
            };
            if self.pending.len() + (end - start) > self.max_event {
                return Err(PushError::TooLarge);
            }
            let skip = std::mem::take(&mut self.skip);
            if self.pending.is_empty() {
                check(Event {
                    raw: &chunk[start..end],
                    skip,
                })
                .map_err(PushError::Refused)?;
                run = Some((run.map_or(start, |(begin, _)| begin), end));
            } else {
                // Only the first event of a chunk can have started in an earlier one.
                self.pending.extend_from_slice(&chunk[start..end]);
                let copied = self.pending.split().freeze();
                check(Event { raw: &copied, skip }).map_err(PushError::Refused)?;
                cleared.copied = Some(copied);
            }
            cleared.events += 1;
            start = end;
            scan = end;
        }
        cleared.run = run.map(|(begin, end)| chunk.slice(begin..end));
        Ok(cleared)
    }

    /// The offset just past the blank line that ends the current event, looking from `from`, or
    /// `None` if `bytes` ends first. Carries the line state across calls.
    fn find_end(&mut self, bytes: &[u8], from: usize) -> Option<usize> {
        let mut i = from;
        if let Some(blank) = self.pending_cr {
            let next = *bytes.get(i)?;
            self.pending_cr = None;
            if next == b'\n' {
                i += 1;
            }
            self.at_line_start = true;
            if blank {
                return Some(i);
            }
        }
        loop {
            let rest = bytes.get(i..)?;
            let Some(k) = memchr::memchr2(b'\n', b'\r', rest) else {
                if !rest.is_empty() {
                    self.at_line_start = false;
                }
                return None;
            };
            let at = i + k;
            let blank = self.at_line_start && k == 0;
            self.at_line_start = true;
            let end = if bytes[at] == b'\r' {
                match bytes.get(at + 1) {
                    // Whether an LF follows is not known yet.
                    None => {
                        self.pending_cr = Some(blank);
                        return None;
                    }
                    Some(b'\n') => at + 2,
                    Some(_) => at + 1,
                }
            } else {
                at + 1
            };
            if blank {
                return Some(end);
            }
            i = end;
        }
    }
}

/// The fields of one event that the relay reads.
pub(crate) struct Fields<'a> {
    /// The last `event` field's value, if any.
    pub(crate) event: Option<&'a [u8]>,
    /// The `data` lines joined with LF, if there is at least one. Without one, no event is
    /// dispatched.
    pub(crate) data: Option<Cow<'a, [u8]>>,
}

impl fmt::Debug for Fields<'_> {
    // Lengths only: the fields are upstream content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fields")
            .field("event", &self.event.map(<[u8]>::len))
            .field("data", &self.data.as_ref().map(|d| d.len()))
            .finish()
    }
}

/// Reads one event's fields from its bytes (the byte-order mark already skipped).
pub(crate) fn fields(raw: &[u8]) -> Fields<'_> {
    let mut event = None;
    let mut data: Option<Cow<'_, [u8]>> = None;
    let mut rest = raw;
    while !rest.is_empty() {
        let (line, next) = match memchr::memchr2(b'\n', b'\r', rest) {
            Some(at) => {
                let len = if rest[at] == b'\r' && rest.get(at + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                (&rest[..at], &rest[at + len..])
            }
            None => (rest, &rest[rest.len()..]),
        };
        rest = next;
        if line.is_empty() {
            break;
        }
        if line[0] == b':' {
            continue;
        }
        let (name, value) = match memchr::memchr(b':', line) {
            Some(colon) => {
                let value = &line[colon + 1..];
                (&line[..colon], value.strip_prefix(b" ").unwrap_or(value))
            }
            None => (line, &line[line.len()..]),
        };
        // Of the fields, the relay reads `event` and `data`; `id`, `retry` and any other name
        // set nothing it uses.
        if name == b"event" {
            event = Some(value);
        } else if name == b"data" {
            data = Some(match data.take() {
                None => Cow::Borrowed(value),
                Some(Cow::Borrowed(first)) => {
                    // Sized once: the joined lines are never longer than the event, so the copy
                    // holds at most `raw.len()` and never grows by doubling.
                    let mut joined = Vec::with_capacity(raw.len());
                    joined.extend_from_slice(first);
                    joined.push(b'\n');
                    joined.extend_from_slice(value);
                    Cow::Owned(joined)
                }
                Some(Cow::Owned(mut joined)) => {
                    joined.push(b'\n');
                    joined.extend_from_slice(value);
                    Cow::Owned(joined)
                }
            });
        }
    }
    Fields { event, data }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;

    /// Every event's exact bytes, and everything cleared, piece by piece.
    fn split_all(pieces: &[&[u8]]) -> (Vec<Vec<u8>>, Vec<u8>) {
        let mut s = Splitter::new(1 << 20);
        let (mut events, mut cleared) = (Vec::new(), Vec::new());
        for p in pieces {
            let out = s
                .push(&Bytes::copy_from_slice(p), |e| {
                    events.push(e.raw().to_vec());
                    Ok::<(), Infallible>(())
                })
                .unwrap();
            for part in [out.copied, out.run].into_iter().flatten() {
                cleared.extend_from_slice(&part);
            }
        }
        if let Some((tail, _)) = s.finish() {
            events.push(tail.to_vec());
            cleared.extend_from_slice(&tail);
        }
        (events, cleared)
    }

    #[test]
    fn events_end_at_blank_lines_in_every_line_ending() {
        let body: &[u8] = b"data: a\n\ndata: b\r\n\r\ndata: c\r\rdata: d";
        let (events, cleared) = split_all(&[body]);
        assert_eq!(
            events,
            vec![
                b"data: a\n\n".to_vec(),
                b"data: b\r\n\r\n".to_vec(),
                b"data: c\r\r".to_vec(),
                b"data: d".to_vec()
            ]
        );
        assert_eq!(cleared, body.to_vec());
    }

    #[test]
    fn a_crlf_split_across_pieces_is_one_line_ending() {
        // `\r` | `\n\r` | `\ndata`: one line "data: a", then a CRLF blank line.
        assert_eq!(
            split_all(&[b"data: a\r", b"\n\r", b"\ndata: b\n\n"]).0,
            vec![b"data: a\r\n\r\n".to_vec(), b"data: b\n\n".to_vec()]
        );
        // A blank line ended by a lone CR at the end of a piece waits for the next byte.
        assert_eq!(
            split_all(&[b"data: a\r\r", b"\ndata: b\n\n"]).0,
            vec![b"data: a\r\r\n".to_vec(), b"data: b\n\n".to_vec()]
        );
    }

    #[test]
    fn a_byte_order_mark_is_not_line_content() {
        // Split across pieces, and whole in a first piece of three bytes or more.
        for pieces in [
            &[&b"\xEF"[..], b"\xBB\xBF\ndata: a\n\n"][..],
            &[&b"\xEF\xBB\xBF\ndata: a\n\n"[..]][..],
        ] {
            let (events, _) = split_all(pieces);
            assert_eq!(events, vec![b"\xEF\xBB\xBF\n".to_vec(), b"data: a\n\n".to_vec()]);
        }
    }

    #[test]
    fn one_piece_clears_at_most_two_runs() {
        // An event completed from an earlier piece, then the piece's own events.
        let mut s = Splitter::new(1 << 20);
        let ok = |_: Event<'_>| Ok::<(), Infallible>(());
        let first = s.push(&Bytes::from_static(b"data: a"), ok).unwrap();
        assert!(first.copied.is_none() && first.run.is_none());
        let blank_lines = "\n".repeat(10_000);
        let second = Bytes::from(format!("\n\n{blank_lines}data: b\n\ndata: c"));
        let out = s.push(&second, ok).unwrap();
        assert_eq!(out.copied.as_deref(), Some(&b"data: a\n\n"[..]));
        assert_eq!(out.run.map(|r| r.len()), Some(10_000 + "data: b\n\n".len()));
        assert_eq!(out.events, 1 + 10_000 + 1);
    }

    #[test]
    fn fields_follow_the_event_stream_rules() {
        let f = fields(b": comment\nevent: usage\ndata: {\"a\":\ndata:1}\nid: 7\n\n");
        assert_eq!(f.event, Some(&b"usage"[..]));
        assert_eq!(f.data.as_deref(), Some(&b"{\"a\":\n1}"[..]));
        assert_eq!(fields(b": ping\n\n").data, None);
        assert_eq!(fields(b"data\n\n").data.as_deref(), Some(&b""[..]));
        assert_eq!(
            fields(b"data:  two spaces\n\n").data.as_deref(),
            Some(&b" two spaces"[..])
        );
    }

    #[test]
    fn an_event_past_the_bound_is_refused_and_nothing_clears() {
        let mut s = Splitter::new(12);
        let mut seen = 0;
        let out = s.push(&Bytes::from_static(b"data: 1\n\ndata: 123456789"), |_| {
            seen += 1;
            Ok::<(), Infallible>(())
        });
        assert_eq!(out.map(|_| ()), Err(PushError::TooLarge));
        assert_eq!(seen, 1, "the event before the oversized one was checked");
    }
}
