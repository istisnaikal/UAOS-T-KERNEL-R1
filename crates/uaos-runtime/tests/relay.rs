// SPDX-License-Identifier: Apache-2.0

//! The relay: byte-exact forwarding for any chunking, metering against the reservation, and every
//! way a stream is cut.
//!
//! The streams are synthetic, shaped like the Anthropic Messages stream and the `OpenAI` Responses
//! and chat streams. The codec here is a test codec.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use http::header::{CONTENT_ENCODING, HeaderValue};
use http_body_util::BodyExt as _;
use hyper::body::{Body, Frame};
use proptest::prelude::*;
use tokio::sync::mpsc;
use uaos_contracts::error::codes;
use uaos_contracts::event::Actor;
use uaos_contracts::id::{CorrelationId, PoolId, ReservationId, TypedId};
use uaos_contracts::money::NanoUsd;
use uaos_ledger::{InFlight, Ledger, MemorySink, Reservation, Usage};
use uaos_module_api::{
    Code, CodecError, DialectCodec, EndpointDecl, FrameKind, RoleMap, SseEvent, StructuralView, UsageReport, ViewNode,
    ViewText,
};
use uaos_runtime::{
    CutReason, DeclaredPrice, EngagedBy, Relay, RelayEnd, RelayError, RelayLimits, RelayReport, Stop, StopReason,
};

/// 50 input tokens at 100 and 100 output tokens at 1,000 nano-USD: exactly the reservation.
const CEILING: i64 = 105_000;

/// A test codec: the Anthropic and `OpenAI` frame names, usage under `usage`, `message.usage` or
/// `response.usage`. It records every event it is shown.
#[derive(Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "test codec: each flag is one independent misbehaviour a test injects"
)]
struct Dialect {
    dims: Vec<Code>,
    seen: Mutex<Vec<(Option<String>, Vec<u8>)>>,
    /// Report a dimension it does not declare.
    rogue: bool,
    /// Classify every event as content: read best effort, metered only where a report is found.
    content_only: bool,
    /// Return a report even when it names no dimension, as a codec that adds only the fields it
    /// finds would.
    empty_reports: bool,
    /// Classify `message_start`, which carries the input tokens, as other: that mislabel would
    /// fail open.
    start_as_other: bool,
}

impl Dialect {
    fn new() -> Self {
        Self {
            dims: vec![code("input_tokens"), code("output_tokens")],
            seen: Mutex::new(Vec::new()),
            rogue: false,
            content_only: false,
            empty_reports: false,
            start_as_other: false,
        }
    }

    fn seen(&self) -> Vec<(Option<String>, Vec<u8>)> {
        self.seen.lock().unwrap().clone()
    }
}

fn code(s: &str) -> Code {
    Code::new(s).unwrap()
}

fn usage_node<'v, 'a>(root: ViewNode<'v, 'a>) -> Option<ViewNode<'v, 'a>> {
    if let Some(usage) = root.member("usage").ok()? {
        return Some(usage);
    }
    for wrapper in ["message", "response"] {
        if let Some(inner) = root.member(wrapper).ok()?
            && let Some(usage) = inner.member("usage").ok()?
        {
            return Some(usage);
        }
    }
    None
}

fn count(node: ViewNode<'_, '_>, key: &str) -> Option<u64> {
    match node.member(key).ok()??.number_text()? {
        ViewText::Plain(text) => text.parse().ok(),
        ViewText::Masked => None,
    }
}

impl DialectCodec for Dialect {
    fn endpoints(&self) -> &[EndpointDecl] {
        &[]
    }

    fn dimensions(&self) -> &[Code] {
        &self.dims
    }

    fn roles(&self, _view: &StructuralView<'_, '_>, _out: &mut RoleMap) -> Result<(), CodecError> {
        Ok(())
    }

    fn frame(&self, event: &SseEvent<'_>) -> FrameKind {
        self.seen
            .lock()
            .unwrap()
            .push((event.event.map(str::to_owned), event.data.to_vec()));
        if self.content_only {
            return FrameKind::Content;
        }
        if self.start_as_other && event.event == Some("message_start") {
            return FrameKind::Other;
        }
        match event.event {
            Some("message_start" | "message_delta") => FrameKind::Usage,
            Some("ping") => FrameKind::Ping,
            Some("message_stop" | "response.completed") => FrameKind::End,
            Some("error") => FrameKind::Error,
            None if event.data == b"[DONE]" => FrameKind::End,
            None if event.data.windows(9).any(|w| w == b"\"usage\":{") => FrameKind::Usage,
            Some(_) | None => FrameKind::Content,
        }
    }

    fn usage(&self, view: &StructuralView<'_, '_>) -> Option<UsageReport> {
        let node = usage_node(view.root())?;
        let mut report = UsageReport::new();
        for (key, dim) in [("input_tokens", "input_tokens"), ("output_tokens", "output_tokens")] {
            if let Some(n) = count(node, key) {
                report = report.dim(code(dim), n).ok()?;
            }
        }
        if self.rogue {
            report = report.dim(code("cache_tokens"), 1).ok()?;
        }
        (self.empty_reports || !report.dims().is_empty()).then_some(report)
    }
}

/// An upstream body fed through a bounded channel; it records being dropped.
struct Upstream {
    rx: mpsc::Receiver<Result<Bytes, io::Error>>,
    dropped: Arc<AtomicBool>,
}

impl Body for Upstream {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        self.rx.poll_recv(cx).map(|item| item.map(|r| r.map(Frame::data)))
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

/// What a test sends the upstream after the start.
type Feed = mpsc::Sender<Result<Bytes, io::Error>>;

/// An upstream that sends `chunks`, then ends unless `keep_open`.
fn upstream(chunks: &[&[u8]], keep_open: bool) -> (Upstream, Arc<AtomicBool>, Option<Feed>) {
    // Room for what a test sends after the start, such as an upstream error.
    let (tx, rx) = mpsc::channel(chunks.len() + 4);
    for chunk in chunks {
        tx.try_send(Ok(Bytes::copy_from_slice(chunk))).unwrap();
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let body = Upstream {
        rx,
        dropped: Arc::clone(&dropped),
    };
    (body, dropped, keep_open.then_some(tx))
}

fn reservation(amount: i64) -> Reservation<InFlight> {
    let mut ledger = Ledger::default();
    let mut sink = MemorySink::default();
    let pool = PoolId::from_parts(1, [1; 10]);
    ledger
        .allocate(
            &mut sink,
            pool,
            NanoUsd::new(amount.saturating_mul(10)),
            &Actor::System,
            uaos_contracts::budget::IdempotencyKey::new("fund").unwrap(),
        )
        .unwrap();
    ledger
        .reserve(
            &mut sink,
            pool,
            ReservationId::from_parts(1, [2; 10]),
            NanoUsd::new(amount),
            &Actor::System,
        )
        .unwrap()
        .begin()
}

fn price() -> Arc<DeclaredPrice> {
    Arc::new(
        DeclaredPrice::new([
            (code("input_tokens"), NanoUsd::new(100)),
            (code("output_tokens"), NanoUsd::new(1_000)),
        ])
        .unwrap(),
    )
}

fn relay(codec: &Arc<Dialect>, stop: &Stop, limits: RelayLimits) -> Relay {
    relay_at(codec, stop, limits, CEILING)
}

fn relay_at(codec: &Arc<Dialect>, stop: &Stop, limits: RelayLimits, reserved: i64) -> Relay {
    let codec: Arc<dyn DialectCodec> = codec.clone();
    Relay::new(codec, price(), &reservation(reserved), stop.clone(), by(), limits)
}

/// The system, under the Operation's correlation: who a relay engages the stop as.
fn by() -> EngagedBy {
    EngagedBy {
        actor: Actor::System,
        correlation_id: CorrelationId::from_parts(1, [3; 10]),
        config_version: uaos_contracts::wire::ConfigVersion(1),
    }
}

/// Everything the client receives, and the error the body ended in, if any.
async fn drain<B>(body: &mut B) -> (Vec<u8>, Option<RelayError>)
where
    B: Body<Data = Bytes, Error = RelayError> + Unpin,
{
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    out.extend_from_slice(&data);
                }
            }
            Err(error) => return (out, Some(error)),
        }
    }
    (out, None)
}

async fn report(rx: tokio::sync::oneshot::Receiver<RelayReport>) -> RelayReport {
    tokio::time::timeout(Duration::from_secs(5), rx).await.unwrap().unwrap()
}

const START: &[u8] = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":50,\"output_tokens\":1}}}\n\n";
const DELTA: &[u8] = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"\u{130}stanbul'da \u{131}l\u{131}k bir g\u{fc}n\"}}\n\n".as_bytes();
const PING: &[u8] = b"event: ping\ndata: {\"type\":\"ping\"}\n\n";
const DELTA_100: &[u8] = b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":100}}\n\n";
const DELTA_101: &[u8] = b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":101}}\n\n";
const STOP: &[u8] = b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

// ── Within budget ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_stream_within_its_reservation_is_relayed_byte_for_byte() {
    let codec = Arc::new(Dialect::new());
    let stop = Stop::running();
    let parts = [START, DELTA, PING, DELTA_100, STOP];
    let (up, _dropped, _) = upstream(&parts, false);
    let (mut body, rx) = relay(&codec, &stop, RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert_eq!(error, None);
    assert_eq!(out, concat(&parts), "the relay changed the stream's bytes");
    let report = report(rx).await;
    assert_eq!(report.end, RelayEnd::Completed);
    assert_eq!(report.forwarded_bytes, u64::try_from(out.len()).unwrap());
    assert_eq!(report.segments, 5);
    assert_eq!(
        report.usage,
        vec![(code("input_tokens"), 50), (code("output_tokens"), 100)]
    );
    assert_eq!(
        report.cost,
        Some(NanoUsd::new(CEILING)),
        "a cost equal to the ceiling is within budget"
    );
    assert!(report.usage_final, "the dialect's end came after the last report");
    assert_eq!(report.settlement(), Usage::Reported(NanoUsd::new(CEILING)));
    assert!(!stop.is_engaged());
}

#[tokio::test]
async fn openai_shaped_streams_are_relayed_and_metered() {
    let responses: [&[u8]; 3] = [
        b"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"r1\"}}\n\n",
        "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"\u{c7}a a \u{e9}t\u{e9}\"}\n\n".as_bytes(),
        b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"usage\":{\"input_tokens\":50,\"output_tokens\":100}}}\n\n",
    ];
    let chat: [&[u8]; 3] = [
        // With `include_usage`, every chunk carries `"usage":null`.
        "data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"Stra\u{df}e\"}}],\"usage\":null}\n\n".as_bytes(),
        b"data: {\"id\":\"c1\",\"choices\":[],\"usage\":{\"input_tokens\":50,\"output_tokens\":100}}\n\n",
        b"data: [DONE]\n\n",
    ];
    for parts in [&responses[..], &chat[..]] {
        let codec = Arc::new(Dialect::new());
        let (up, _, _) = upstream(parts, false);
        let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
            .sse(up, &HeaderMap::new())
            .unwrap();
        let (out, error) = drain(&mut body).await;
        assert_eq!((out, error), (concat(parts), None));
        let report = report(rx).await;
        assert_eq!(report.cost, Some(NanoUsd::new(CEILING)));
        assert!(report.usage_final);
        assert_eq!(report.settlement(), Usage::Reported(NanoUsd::new(CEILING)));
    }
}

// ── Over budget ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn one_unit_over_the_ceiling_is_never_forwarded() {
    let codec = Arc::new(Dialect::new());
    let stop = Stop::running();
    let (up, _dropped, _) = upstream(&[START, DELTA, DELTA_101, STOP], false);
    let (mut body, rx) = relay(&codec, &stop, RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert!(
        !out.windows(19).any(|w| w == b"\"output_tokens\":101"),
        "a usage report over the ceiling was forwarded"
    );
    assert_eq!(
        out,
        concat(&[START, DELTA]),
        "a usage report over the ceiling was forwarded"
    );
    assert_eq!(error, Some(RelayError::Cut(CutReason::BudgetOverrun)));
    let report = report(rx).await;
    assert_eq!(report.end, RelayEnd::Cut(CutReason::BudgetOverrun));
    assert_eq!(report.cost, Some(NanoUsd::new(CEILING + 1_000)));
    assert_eq!(
        report.usage,
        vec![(code("input_tokens"), 50), (code("output_tokens"), 101)]
    );
}

#[tokio::test]
async fn one_nano_usd_over_the_ceiling_is_never_forwarded() {
    // The reservation is one nano-USD short of the stream's cost.
    let codec = Arc::new(Dialect::new());
    let (up, _, _) = upstream(&[START, DELTA, DELTA_100, STOP], false);
    let (mut body, rx) = relay_at(&codec, &Stop::running(), RelayLimits::default(), CEILING - 1)
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert_eq!(
        out,
        concat(&[START, DELTA]),
        "a usage report over the ceiling was forwarded"
    );
    assert_eq!(error, Some(RelayError::Cut(CutReason::BudgetOverrun)));
    assert_eq!(report(rx).await.cost, Some(NanoUsd::new(CEILING)));
}

#[tokio::test]
async fn usage_on_an_end_frame_is_metered() {
    // Usage is read from an end frame, not only from a usage frame.
    let completed: &[u8] = b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"usage\":{\"input_tokens\":50,\"output_tokens\":101}}}\n\n";
    let codec = Arc::new(Dialect::new());
    let (up, _, _) = upstream(&[START, completed], false);
    let (mut body, _rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert_eq!(
        (out, error),
        (START.to_vec(), Some(RelayError::Cut(CutReason::BudgetOverrun))),
        "usage on an end frame went unmetered"
    );
}

#[tokio::test]
async fn usage_on_a_mislabelled_frame_is_still_metered() {
    // A content or other frame is read best effort, so the input tokens of a `message_start` the
    // codec calls other are still metered, and settle as final.
    let codec = Arc::new(Dialect {
        start_as_other: true,
        ..Dialect::new()
    });
    let (up, _, _) = upstream(&[START, DELTA, DELTA_100, STOP], false);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    assert_eq!(drain(&mut body).await.1, None);
    let report = report(rx).await;
    assert_eq!(
        (report.cost, report.settlement()),
        (Some(NanoUsd::new(CEILING)), Usage::Reported(NanoUsd::new(CEILING))),
        "usage on a mislabelled frame went unmetered"
    );
}

#[tokio::test]
async fn usage_on_a_frame_the_codec_calls_content_is_metered() {
    // A codec that calls every frame content, as one might default a nameless chat usage chunk,
    // still has its reports metered.
    let codec = Arc::new(Dialect {
        content_only: true,
        ..Dialect::new()
    });
    let (up, _, _) = upstream(&[START, DELTA, DELTA_100, STOP], false);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    assert_eq!(drain(&mut body).await.1, None);
    let report = report(rx).await;
    assert_eq!(
        report.cost,
        Some(NanoUsd::new(CEILING)),
        "usage on a frame the codec calls content went unmetered"
    );
    // No end frame was seen, so the cost is not final and the reservation settles in full.
    assert_eq!(report.settlement(), Usage::Unknown);
}

#[tokio::test]
async fn a_large_end_frame_within_the_bounds_is_metered() {
    // An end frame that echoes a long output, 2^20 - 64 values and about 2 MiB with text in every
    // GA locale, stays inside both read bounds, so it is metered and not cut.
    let values = vec!["0"; (1 << 20) - 64].join(",");
    let text = "\u{130}stanbul \u{df} \u{e9}t\u{e9} \u{f1} \u{e8} \u{645}\u{64e}\u{631}\u{652}\u{62d}\u{64e}\u{628}\u{64b}\u{627}";
    let completed = format!(
        "event: response.completed\ndata: {{\"type\":\"response.completed\",\"response\":{{\"usage\":{{\"input_tokens\":50,\"output_tokens\":100}},\"text\":\"{text}\",\"logprobs\":[{values}]}}}}\n\n"
    );
    let codec = Arc::new(Dialect::new());
    let (up, _, _) = upstream(&[completed.as_bytes()], false);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert_eq!(
        (error, out.len(), report(rx).await.cost),
        (None, completed.len(), Some(NanoUsd::new(CEILING))),
        "a large end frame within the bounds was cut"
    );
}

#[tokio::test]
async fn a_content_frame_never_cuts_for_its_json() {
    // A content frame is the model's output, and its JSON never cuts a stream; it is read best
    // effort. A lone surrogate escape: an emoji split across two text deltas, which `uaos-json`
    // refuses.
    let lone = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"~ud83d\"}}\n\n"
        .replace("~u", "\\u");
    // A server tool's result arrives whole in one event: 2 MiB, past the old 1 MiB bound.
    let document = "A".repeat(2 * 1024 * 1024);
    let tool_result = format!(
        "event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":1,\"content_block\":{{\"type\":\"web_fetch_tool_result\",\"content\":{{\"type\":\"document\",\"source\":{{\"data\":\"{document}\"}}}}}}}}\n\n"
    );
    let parts: [&[u8]; 5] = [START, lone.as_bytes(), tool_result.as_bytes(), DELTA_100, STOP];
    let codec = Arc::new(Dialect::new());
    let (up, _, _) = upstream(&parts, false);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert_eq!(
        (error, out == concat(&parts)),
        (None, true),
        "a content frame was cut for its JSON"
    );
    assert_eq!(report(rx).await.cost, Some(NanoUsd::new(CEILING)));
}

#[tokio::test]
async fn one_upstream_frame_is_forwarded_in_at_most_two_pieces() {
    // An event completed from an earlier frame, then the frame's own events as one slice; nothing
    // is kept per event.
    let head: &[u8] = b"event: content_block_delta\ndata: {}";
    let rest = [&b"\n\n"[..], "\n".repeat(10_000).as_bytes(), DELTA].concat();
    let codec = Arc::new(Dialect::new());
    let (up, _, _) = upstream(&[head, &rest], false);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (mut frames, mut out) = (0, Vec::new());
    while let Some(frame) = body.frame().await {
        out.extend_from_slice(&frame.unwrap().into_data().unwrap());
        frames += 1;
    }
    let report = report(rx).await;
    assert_eq!(
        (frames, out == [head, &rest[..]].concat(), report.segments),
        (2, true, 1 + 10_000 + 1),
        "one upstream frame was forwarded in more than two pieces"
    );
}

#[tokio::test]
async fn a_stream_that_does_not_finish_settles_the_full_reservation() {
    // A running total is a lower bound on the bill unless the dialect's end follows it.
    let codec = Arc::new(Dialect::new());
    let (up, _, _keep) = upstream(&[START, DELTA], true);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let _first = body.frame().await.unwrap().unwrap();
    drop(body);
    let gone = report(rx).await;
    assert_eq!(
        (gone.end, gone.cost, gone.usage_final),
        (RelayEnd::ClientGone, Some(NanoUsd::new(6_000)), false),
        "a stream that did not finish settled at its running total"
    );
    assert_eq!(
        gone.settlement(),
        Usage::Unknown,
        "a stream that did not finish settled at its running total"
    );
    // The upstream ends without the dialect's end.
    let (up, _, _) = upstream(&[START, DELTA, DELTA_100], false);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    assert_eq!(drain(&mut body).await.1, None);
    let unfinished = report(rx).await;
    assert_eq!(
        (unfinished.end, unfinished.usage_final),
        (RelayEnd::Completed, false),
        "a stream that did not finish settled at its running total"
    );
    assert_eq!(
        unfinished.settlement(),
        Usage::Unknown,
        "a stream that did not finish settled at its running total"
    );
    // A stop cuts it.
    let stop = Stop::running();
    let (up, _, _keep) = upstream(&[START], true);
    let (mut body, rx) = relay(&codec, &stop, RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let _first = body.frame().await.unwrap().unwrap();
    let _engaged = stop.engage(StopReason::Operator, by());
    let cut = tokio::time::timeout(Duration::from_secs(5), drain(&mut body))
        .await
        .unwrap();
    assert_eq!(cut.1, Some(RelayError::Cut(CutReason::Stopped(StopReason::Operator))));
    assert_eq!(report(rx).await.settlement(), Usage::Unknown);
}

#[tokio::test]
async fn a_report_after_the_end_is_not_final() {
    // The dialect's end must come at or after the last report.
    let codec = Arc::new(Dialect::new());
    let (up, _, _) = upstream(&[START, STOP, DELTA_100], false);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    assert_eq!(drain(&mut body).await.1, None);
    let report = report(rx).await;
    assert_eq!(
        (report.end, report.usage_final, report.settlement()),
        (RelayEnd::Completed, false, Usage::Unknown),
        "a report after the dialect's end counted as final"
    );
}

#[tokio::test]
async fn an_empty_usage_report_is_no_report() {
    // A report naming no dimension never settles as a final cost of zero.
    let empty: &[u8] = b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{}}\n\n";
    let renamed: &[u8] =
        b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"renamed_tokens\":5}}\n\n";
    for frame in [empty, renamed] {
        let codec = Arc::new(Dialect {
            empty_reports: true,
            ..Dialect::new()
        });
        let (up, _, _) = upstream(&[frame, STOP], false);
        let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
            .sse(up, &HeaderMap::new())
            .unwrap();
        assert_eq!(
            drain(&mut body).await,
            (Vec::new(), Some(RelayError::Cut(CutReason::UnreadableUsage))),
            "an empty usage report counted as a report"
        );
        assert_eq!(report(rx).await.settlement(), Usage::Unknown);
    }
    // On an end frame it is no report either: the stream completes, unmetered, and settles the
    // full reservation.
    let completed: &[u8] =
        b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{}}}\n\n";
    let codec = Arc::new(Dialect {
        empty_reports: true,
        ..Dialect::new()
    });
    let (up, _, _) = upstream(&[completed], false);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    assert_eq!(drain(&mut body).await.1, None);
    let report = report(rx).await;
    assert_eq!(
        (report.cost, report.settlement()),
        (None, Usage::Unknown),
        "an empty usage report counted as a report"
    );
}

#[tokio::test]
async fn an_event_past_the_node_bound_cuts() {
    // Reading a frame for usage is bounded in nodes, not only in bytes, at the request's own bound.
    let zeros = vec!["0"; (1 << 20) + 16].join(",");
    let wide = format!("event: message_delta\ndata: {{\"usage\":{{\"output_tokens\":1}},\"a\":[{zeros}]}}\n\n");
    assert!(wide.len() < RelayLimits::default().max_event_bytes);
    assert_eq!(
        cut_reason(&[wide.as_bytes()], Dialect::new(), RelayLimits::default()).await,
        Some(RelayError::Cut(CutReason::UnreadableUsage)),
        "an event past its node bound was parsed"
    );
}

#[tokio::test]
async fn an_overrun_settles_at_least_its_cost() {
    let codec = Arc::new(Dialect::new());
    let (up, _, _) = upstream(&[START, DELTA_101], false);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let _drained = drain(&mut body).await;
    let report = report(rx).await;
    assert!(!report.usage_final);
    assert_eq!(report.settlement(), Usage::Reported(NanoUsd::new(CEILING + 1_000)));
}

#[tokio::test]
async fn a_cost_out_of_range_cuts_and_stops_the_kernel() {
    let huge: &[u8] =
        b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":18446744073709551615}}\n\n";
    let codec = Arc::new(Dialect::new());
    let stop = Stop::running();
    let (up, _, _) = upstream(&[START, huge], false);
    let (mut body, rx) = relay(&codec, &stop, RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert_eq!(
        (out, error),
        (START.to_vec(), Some(RelayError::Cut(CutReason::CostOutOfRange)))
    );
    assert_eq!(stop.reason(), Some(StopReason::BudgetOverrun));
    let report = report(rx).await;
    assert_eq!(
        report.cost,
        Some(NanoUsd::new(6_000)),
        "the report keeps the last cost in range"
    );
    assert_eq!(
        report.usage,
        vec![(code("input_tokens"), 50), (code("output_tokens"), 1)],
        "the report's usage and cost disagree"
    );
    assert_eq!(report.settlement(), Usage::Unknown);
    assert_eq!(CutReason::CostOutOfRange.error_code(), codes::BUDGET_STREAM_OVERRUN);
}

#[tokio::test]
async fn an_overrun_stops_the_kernel() {
    let codec = Arc::new(Dialect::new());
    let stop = Stop::running();
    let (up, _, _) = upstream(&[START, DELTA_101], false);
    let (mut body, _rx) = relay(&codec, &stop, RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let _drained = drain(&mut body).await;
    assert_eq!(
        stop.reason(),
        Some(StopReason::BudgetOverrun),
        "an overrun left the kernel running"
    );
    assert_eq!(stop.unrecorded().map(|e| e.reason()), Some(StopReason::BudgetOverrun));
    // The relay engages as the system, under the Operation's correlation, as it was told to.
    assert_eq!(
        stop.unrecorded().unwrap().by(),
        Some(&by()),
        "the overrun engaged the stop as someone else"
    );
}

#[tokio::test]
async fn a_trailing_event_without_a_blank_line_is_metered_too() {
    let codec = Arc::new(Dialect::new());
    let tail = &DELTA_101[..DELTA_101.len() - 2];
    let (up, _, _) = upstream(&[START, tail], false);
    let (mut body, _rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert_eq!(out, START.to_vec());
    assert_eq!(error, Some(RelayError::Cut(CutReason::BudgetOverrun)));
}

#[tokio::test]
async fn a_cut_drops_the_upstream_at_once() {
    let codec = Arc::new(Dialect::new());
    let (up, dropped, _keep) = upstream(&[START, DELTA_101], true);
    let (mut body, _rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let first = body.frame().await.unwrap().unwrap();
    assert_eq!(first.into_data().unwrap(), Bytes::from_static(START));
    assert!(!dropped.load(Ordering::SeqCst));
    let cut = body.frame().await.unwrap();
    assert!(cut.is_err());
    assert!(dropped.load(Ordering::SeqCst), "a cut kept the upstream");
}

#[tokio::test]
async fn a_cut_without_a_terminal_frame_ends_in_an_error() {
    let codec = Arc::new(Dialect::new());
    let (up, _, _) = upstream(&[START, DELTA_101], false);
    let (mut body, _rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (_, error) = drain(&mut body).await;
    assert!(error.is_some(), "a cut ended cleanly, as if the answer were complete");
    assert!(body.is_end_stream());
}

#[tokio::test]
async fn a_cut_with_a_terminal_frame_ends_with_it() {
    let codec = Arc::new(Dialect::new());
    let terminal =
        Bytes::from_static(b"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"uaos_cut\"}}\n\n");
    let (up, _, _) = upstream(&[START, DELTA_101], false);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .terminal(terminal.clone())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert_eq!(error, None);
    assert_eq!(out, [START, &terminal[..]].concat());
    let report = report(rx).await;
    assert_eq!(
        report.forwarded_bytes,
        u64::try_from(START.len()).unwrap(),
        "the terminal frame was counted as upstream bytes"
    );
}

// ── The stop ────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_stop_cuts_a_waiting_stream() {
    let codec = Arc::new(Dialect::new());
    let stop = Stop::running();
    let (up, dropped, _keep) = upstream(&[START], true);
    let (mut body, rx) = relay(&codec, &stop, RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let first = body.frame().await.unwrap().unwrap();
    assert_eq!(first.into_data().unwrap(), Bytes::from_static(START));
    let (next, ()) = tokio::join!(tokio::time::timeout(Duration::from_secs(5), body.frame()), async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _engaged = stop.engage(StopReason::Operator, by());
    });
    let next = next.expect("a stop did not cut a waiting stream");
    assert_eq!(
        next.map(|f| f.map(|_| ())),
        Some(Err(RelayError::Cut(CutReason::Stopped(StopReason::Operator))))
    );
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(
        report(rx).await.end,
        RelayEnd::Cut(CutReason::Stopped(StopReason::Operator))
    );
    assert_eq!(
        CutReason::Stopped(StopReason::BudgetOverrun).error_code(),
        codes::RUNTIME_STOPPED,
        "a stream another one's overrun stopped was reported as overrunning"
    );
}

#[tokio::test]
async fn a_stop_engaged_first_forwards_nothing() {
    let codec = Arc::new(Dialect::new());
    let stop = Stop::running();
    let _engaged = stop.engage(StopReason::DiskFull, by());
    let (up, _, _) = upstream(&[START, DELTA], false);
    let (mut body, _rx) = relay(&codec, &stop, RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert!(out.is_empty(), "a stopped kernel forwarded a byte");
    assert_eq!(error, Some(RelayError::Cut(CutReason::Stopped(StopReason::DiskFull))));
}

// ── Bounds and failures ─────────────────────────────────────────────────────────────────────

async fn cut_reason(parts: &[&[u8]], codec: Dialect, limits: RelayLimits) -> Option<RelayError> {
    let codec = Arc::new(codec);
    let (up, _, _) = upstream(parts, false);
    let (mut body, _rx) = relay(&codec, &Stop::running(), limits)
        .sse(up, &HeaderMap::new())
        .unwrap();
    drain(&mut body).await.1
}

#[tokio::test]
async fn an_event_past_its_bound_cuts() {
    let limits = RelayLimits {
        max_event_bytes: 64,
        ..RelayLimits::default()
    };
    // Data that is not object-shaped and an event no blank line ends, so only the splitter's bound
    // can stop it.
    let text = "x".repeat(100);
    let parts: [&[u8]; 2] = [b"event: content_block_delta\ndata: ", text.as_bytes()];
    let codec = Arc::new(Dialect::new());
    let (up, _, _) = upstream(&parts, false);
    let (mut body, _rx) = relay(&codec, &Stop::running(), limits)
        .sse(up, &HeaderMap::new())
        .unwrap();
    assert_eq!(
        drain(&mut body).await,
        (Vec::new(), Some(RelayError::Cut(CutReason::EventTooLarge))),
        "an event past its bound was forwarded"
    );
}

#[tokio::test]
async fn a_body_past_its_bound_cuts() {
    let limits = RelayLimits {
        max_body_bytes: 200,
        ..RelayLimits::default()
    };
    assert_eq!(
        cut_reason(&[START, DELTA, PING], Dialect::new(), limits).await,
        Some(RelayError::Cut(CutReason::BodyTooLarge))
    );
}

#[tokio::test(start_paused = true)]
async fn an_idle_upstream_cuts() {
    let codec = Arc::new(Dialect::new());
    let (up, dropped, _keep) = upstream(&[PING], true);
    let (mut body, _rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let drained = tokio::time::timeout(Duration::from_secs(3_600), drain(&mut body)).await;
    let (out, error) = drained.expect("the idle cut never fired");
    assert_eq!(out, PING.to_vec());
    assert_eq!(error, Some(RelayError::Cut(CutReason::Idle)));
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn upstream_activity_resets_the_idle_deadline() {
    // A ping every 100 s keeps a 120 s idle timeout from firing.
    let limits = RelayLimits {
        idle_timeout: Duration::from_secs(120),
        ..RelayLimits::default()
    };
    let codec = Arc::new(Dialect::new());
    let (up, _, keep) = upstream(&[], true);
    let tx = keep.unwrap();
    let (mut body, _rx) = relay(&codec, &Stop::running(), limits)
        .sse(up, &HeaderMap::new())
        .unwrap();
    let feeder = async move {
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(100)).await;
            // A cut drops the upstream; the assertion below then says why.
            if tx.send(Ok(Bytes::from_static(PING))).await.is_err() {
                break;
            }
        }
    };
    let ((out, error), ()) = tokio::join!(drain(&mut body), feeder);
    assert_eq!(error, None, "upstream activity did not reset the idle deadline");
    assert_eq!(out, PING.repeat(3));
}

#[tokio::test(start_paused = true)]
async fn a_slow_client_never_causes_an_idle_cut() {
    // The deadline runs from when the relay waits, not from the last frame.
    let limits = RelayLimits {
        idle_timeout: Duration::from_secs(10),
        ..RelayLimits::default()
    };
    let codec = Arc::new(Dialect::new());
    let (up, _, keep) = upstream(&[], true);
    let tx = keep.unwrap();
    let (mut body, _rx) = relay(&codec, &Stop::running(), limits)
        .sse(up, &HeaderMap::new())
        .unwrap();
    let send = |tx: Feed| async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        tx.send(Ok(Bytes::from_static(PING))).await.unwrap();
        tx
    };
    let (first, tx) = tokio::join!(body.frame(), send(tx));
    assert!(matches!(first, Some(Ok(_))));
    // The client reads nothing for three timeouts.
    tokio::time::sleep(Duration::from_secs(30)).await;
    let (next, _tx) = tokio::join!(body.frame(), send(tx));
    assert!(matches!(next, Some(Ok(_))), "a slow client caused an idle cut");
}

#[tokio::test(start_paused = true)]
async fn a_huge_idle_timeout_disables_the_cut_without_a_panic() {
    // Tokio's timer adds to a deadline itself. The largest timeout the clock can still add makes
    // that addition overflow, so it must not arm a timer.
    let now = tokio::time::Instant::now();
    let mut secs = 0_u64;
    for bit in (0..64).rev() {
        let more = secs | (1 << bit);
        if now.checked_add(Duration::from_secs(more)).is_some() {
            secs = more;
        }
    }
    let mut nanos = 0_u32;
    for bit in (0..30).rev() {
        let more = nanos | (1 << bit);
        if more < 1_000_000_000 && now.checked_add(Duration::new(secs, more)).is_some() {
            nanos = more;
        }
    }
    let limits = RelayLimits {
        idle_timeout: Duration::new(secs, nanos),
        ..RelayLimits::default()
    };
    let codec = Arc::new(Dialect::new());
    let (up, _, keep) = upstream(&[], true);
    let tx = keep.unwrap();
    let (body, _rx) = relay(&codec, &Stop::running(), limits)
        .sse(up, &HeaderMap::new())
        .unwrap();
    // Its own task, so a panic inside the body is caught here rather than failing the test.
    #[allow(
        clippy::disallowed_methods,
        reason = "a test task, so a panic in the body is observed"
    )]
    let relayed = tokio::spawn(async move {
        let mut body = body;
        drain(&mut body).await
    });
    tokio::time::sleep(Duration::from_secs(10)).await;
    // Fails only if the body is gone, which the assertion below explains.
    let _sent = tx.send(Ok(Bytes::from_static(PING))).await;
    drop(tx);
    let relayed = relayed.await;
    assert!(
        relayed
            .as_ref()
            .is_ok_and(|(out, error)| out == PING && error.is_none()),
        "a huge idle timeout panicked"
    );
}

#[tokio::test]
async fn an_empty_event_name_is_no_name() {
    // WHATWG reads an empty event type as the default, as no `event` field.
    let chat: &[u8] = b"event:\ndata: {\"choices\":[],\"usage\":{\"input_tokens\":50,\"output_tokens\":100}}\n\n";
    let codec = Arc::new(Dialect::new());
    let (up, _, _) = upstream(&[chat], false);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let _drained = drain(&mut body).await;
    let seen = codec.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, None, "an empty event name reached the codec as a name");
    assert_eq!(report(rx).await.cost, Some(NanoUsd::new(CEILING)));
}

#[tokio::test]
async fn usage_that_cannot_be_read_or_priced_cuts() {
    let duplicate: &[u8] =
        b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":1,\"output_tokens\":1}}\n\n";
    assert_eq!(
        cut_reason(&[duplicate], Dialect::new(), RelayLimits::default()).await,
        Some(RelayError::Cut(CutReason::UnreadableUsage)),
        "a duplicated usage key was metered"
    );
    let not_json: &[u8] = b"event: message_delta\ndata: {\"usage\":\n\n";
    assert_eq!(
        cut_reason(&[not_json], Dialect::new(), RelayLimits::default()).await,
        Some(RelayError::Cut(CutReason::UnreadableUsage))
    );
    let rogue = Dialect {
        rogue: true,
        ..Dialect::new()
    };
    assert_eq!(
        cut_reason(&[START], rogue, RelayLimits::default()).await,
        Some(RelayError::Cut(CutReason::UnreadableUsage)),
        "an undeclared dimension was metered"
    );
    let no_report: &[u8] = b"event: message_delta\ndata: {\"type\":\"message_delta\"}\n\n";
    assert_eq!(
        cut_reason(&[no_report], Dialect::new(), RelayLimits::default()).await,
        Some(RelayError::Cut(CutReason::UnreadableUsage))
    );
    let broken_end: &[u8] = b"event: message_stop\ndata: {\"type\":\n\n";
    assert_eq!(
        cut_reason(&[broken_end], Dialect::new(), RelayLimits::default()).await,
        Some(RelayError::Cut(CutReason::UnreadableUsage)),
        "a broken JSON object slipped past metering"
    );
    let bad_name: &[u8] = b"event: \xFF\ndata: {}\n\n";
    assert_eq!(
        cut_reason(&[bad_name], Dialect::new(), RelayLimits::default()).await,
        Some(RelayError::Cut(CutReason::Malformed))
    );
}

#[tokio::test]
async fn an_unpriced_dimension_cuts() {
    let codec: Arc<dyn DialectCodec> = Arc::new(Dialect::new());
    let only_output = Arc::new(DeclaredPrice::new([(code("output_tokens"), NanoUsd::new(1_000))]).unwrap());
    let (up, _, _) = upstream(&[START], false);
    let (mut body, rx) = Relay::new(
        codec,
        only_output,
        &reservation(CEILING),
        Stop::running(),
        by(),
        RelayLimits::default(),
    )
    .sse(up, &HeaderMap::new())
    .unwrap();
    assert_eq!(drain(&mut body).await.1, Some(RelayError::Cut(CutReason::Unpriced)));
    let report = report(rx).await;
    assert_eq!(
        (report.usage.is_empty(), report.cost),
        (true, None),
        "the report's usage and cost disagree"
    );
    assert_eq!(
        CutReason::Unpriced.error_code(),
        uaos_contracts::error::codes::BUDGET_UNKNOWN_PRICING
    );
}

#[tokio::test]
async fn a_failed_upstream_cuts() {
    let codec = Arc::new(Dialect::new());
    let (up, _, keep) = upstream(&[START], true);
    keep.unwrap().try_send(Err(io::Error::other("reset"))).unwrap();
    let (mut body, _rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let (out, error) = drain(&mut body).await;
    assert_eq!(out, START.to_vec());
    assert_eq!(error, Some(RelayError::Cut(CutReason::UpstreamFailed)));
}

#[test]
fn a_compressed_event_stream_is_refused_before_any_byte() {
    let codec = Arc::new(Dialect::new());
    for coding in ["gzip", "br", "identity, gzip"] {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static(coding));
        let (up, _, _) = upstream(&[START], false);
        let refused = relay(&codec, &Stop::running(), RelayLimits::default()).sse(up, &headers);
        assert_eq!(refused.err(), Some(RelayError::Compressed), "{coding}");
    }
    let mut identity = HeaderMap::new();
    identity.insert(CONTENT_ENCODING, HeaderValue::from_static("Identity"));
    let (up, _, _) = upstream(&[START], false);
    assert!(
        relay(&codec, &Stop::running(), RelayLimits::default())
            .sse(up, &identity)
            .is_ok()
    );
}

#[tokio::test]
async fn a_dropped_client_body_drops_the_upstream() {
    let codec = Arc::new(Dialect::new());
    let (up, dropped, _keep) = upstream(&[START], true);
    let (mut body, rx) = relay(&codec, &Stop::running(), RelayLimits::default())
        .sse(up, &HeaderMap::new())
        .unwrap();
    let _first = body.frame().await.unwrap().unwrap();
    drop(body);
    assert!(dropped.load(Ordering::SeqCst), "a client that left kept the upstream");
    let report = report(rx).await;
    assert_eq!(report.end, RelayEnd::ClientGone);
    assert_eq!(report.forwarded_bytes, u64::try_from(START.len()).unwrap());
}

#[tokio::test]
async fn bytes_mode_relays_untouched_under_the_same_stop() {
    let codec = Arc::new(Dialect::new());
    let stop = Stop::running();
    let parts: [&[u8]; 2] = [b"{\"id\":\"msg_1\",", b"\"usage\":{\"output_tokens\":999999}}"];
    let (up, _, _) = upstream(&parts, false);
    let (mut body, rx) = relay(&codec, &stop, RelayLimits::default()).bytes(up);
    let (out, error) = drain(&mut body).await;
    assert_eq!((out, error), (concat(&parts), None));
    let report = report(rx).await;
    assert_eq!(
        (report.end, report.cost),
        (RelayEnd::Completed, None),
        "bytes mode metered"
    );
    let _engaged = stop.engage(StopReason::Operator, by());
    let (up, _, _) = upstream(&parts, false);
    let (mut body, _rx) = relay(&codec, &stop, RelayLimits::default())
        .terminal(Bytes::from_static(b"event: error\ndata: {}\n\n"))
        .bytes(up);
    let (out, error) = drain(&mut body).await;
    assert!(out.is_empty(), "bytes mode appended a terminal frame to a body");
    assert_eq!(error, Some(RelayError::Cut(CutReason::Stopped(StopReason::Operator))));
}

// ── Any chunking, the seven-locale corpus ───────────────────────────────────────────────────

/// Content in the seven GA locales, chosen for the classic byte hazards: Turkish dotted and dotless
/// i, German sharp s, precomposed and decomposed accents, Arabic tashkeel and implicit direction
/// marks.
const CORPUS: [&str; 9] = [
    "The quick brown fox",
    "\u{130}stanbul'da \u{131}l\u{131}k: I\u{131} \u{130}i",
    "Stra\u{df}e \u{b7} STRASSE \u{b7} \u{1e9e}",
    "\u{c7}a a \u{e9}t\u{e9} d\u{e9}j\u{e0} vu",
    "e\u{301}te\u{301} (NFD)",
    "\u{bf}A\u{f1}adir? \u{a1}S\u{ed}!",
    "Perch\u{e9} \u{e8} cos\u{ec}",
    "\u{645}\u{64e}\u{631}\u{652}\u{62d}\u{64e}\u{628}\u{64b}\u{627} \u{200f}\u{61c}",
    // Not shaped like a JSON object, so it reports no usage. JSON events are generated on their
    // own line (`JSON_EVENT`), which keeps each one a single document.
    "emoji \u{1f600} and {\"braces\":1}",
];

const ENDINGS: [&str; 3] = ["\n", "\r\n", "\r"];

/// One JSON document, read for usage under any chunking: content in every GA locale, no usage.
const JSON_EVENT: &str = "{\"type\":\"content_block_delta\",\"delta\":{\"text\":\"\u{130}stanbul \u{df} \u{e9}t\u{e9} e\u{301} \u{f1} \u{e8} \u{645}\u{64e}\u{631}\u{652}\u{62d}\u{64e}\u{628}\u{64b}\u{627} \u{1f600}\"}}";

#[derive(Debug, Clone)]
struct GenEvent {
    comment: bool,
    /// Data is one JSON object, on one line, instead of corpus lines.
    json: bool,
    name: Option<&'static str>,
    data: Vec<usize>,
    id: bool,
}

fn gen_event() -> impl Strategy<Value = GenEvent> {
    (
        any::<bool>(),
        any::<bool>(),
        prop::option::of(prop::sample::select(vec!["content_block_delta", "ping", "x", ""])),
        prop::collection::vec(0..CORPUS.len(), 0..3),
        any::<bool>(),
    )
        .prop_map(|(comment, json, name, data, id)| GenEvent {
            comment,
            json,
            name,
            data,
            id,
        })
}

/// Serializes events with a line ending drawn per line, a byte-order mark maybe, and maybe a
/// last event that no blank line ends.
fn serialize(events: &[GenEvent], endings: &[usize], bom: bool, open_tail: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if bom {
        out.extend_from_slice(b"\xEF\xBB\xBF");
    }
    let mut n = 0;
    let mut line = |out: &mut Vec<u8>, text: &str| {
        let mut ending = ENDINGS[endings[n % endings.len()]];
        // A blank line ended by LF right after a CR would read as one CRLF, so the event would not
        // end and would run into the next one, and the events seen would merge. The blank line
        // takes CRLF here, so every generated event stays itself.
        if text.is_empty() && ending == "\n" && out.last() == Some(&b'\r') {
            ending = "\r\n";
        }
        out.extend_from_slice(text.as_bytes());
        out.extend_from_slice(ending.as_bytes());
        n += 1;
    };
    for (i, event) in events.iter().enumerate() {
        if event.comment {
            line(&mut out, ": keep-alive");
        }
        if let Some(name) = event.name {
            line(&mut out, &format!("event: {name}"));
        }
        if event.json {
            line(&mut out, &format!("data: {JSON_EVENT}"));
        } else {
            for d in &event.data {
                line(&mut out, &format!("data: {}", CORPUS[*d]));
            }
        }
        if event.id {
            line(&mut out, "id: 7");
        }
        if !(open_tail && i + 1 == events.len()) {
            line(&mut out, "");
        }
    }
    out
}

/// The WHATWG event-stream algorithm over a whole body: an independent reading to compare the
/// relay with. A last event that no blank line ends is dispatched, as a lenient client would.
fn reference(body: &[u8]) -> Vec<(Option<String>, Vec<u8>)> {
    let body = body.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(body);
    let mut lines: Vec<&[u8]> = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < body.len() {
        match body[i] {
            b'\n' => {
                lines.push(&body[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                lines.push(&body[start..i]);
                i += if body.get(i + 1) == Some(&b'\n') { 2 } else { 1 };
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < body.len() {
        lines.push(&body[start..]);
    }
    let mut out = Vec::new();
    let mut event: Option<String> = None;
    let mut data: Option<Vec<u8>> = None;
    for line in lines {
        if line.is_empty() {
            if let Some(d) = data.take() {
                out.push((event.take(), d));
            }
            event = None;
            continue;
        }
        if line[0] == b':' {
            continue;
        }
        let (name, value) = match line.iter().position(|b| *b == b':') {
            Some(c) => (&line[..c], line[c + 1..].strip_prefix(b" ").unwrap_or(&line[c + 1..])),
            None => (line, &line[line.len()..]),
        };
        // `id`, `retry` and any other field set nothing compared here.
        if name == b"event" {
            // An empty event type is the default, as no `event` field.
            event = (!value.is_empty()).then(|| String::from_utf8(value.to_vec()).unwrap());
        } else if name == b"data" {
            match data.as_mut() {
                Some(d) => {
                    d.push(b'\n');
                    d.extend_from_slice(value);
                }
                None => data = Some(value.to_vec()),
            }
        }
    }
    if let Some(d) = data {
        out.push((event, d));
    }
    out
}

fn chunked(body: &[u8], sizes: &[usize]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let (mut at, mut n) = (0, 0);
    while at < body.len() {
        let size = sizes[n % sizes.len()].min(body.len() - at);
        out.push(body[at..at + size].to_vec());
        at += size;
        n += 1;
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// For any events, line endings and chunking (CRLF split across chunks, a byte-order mark
    /// split across chunks, comments, multi-line data, the seven-locale corpus): the bytes the
    /// client receives are the bytes the provider sent, and the events the codec is shown are
    /// the ones an event-stream parser reads from the whole body.
    #[test]
    fn any_chunking_relays_the_same_bytes_and_events(
        events in prop::collection::vec(gen_event(), 0..8),
        endings in prop::collection::vec(0..ENDINGS.len(), 1..6),
        bom in any::<bool>(),
        open_tail in any::<bool>(),
        sizes in prop::collection::vec(1_usize..12, 1..6),
    ) {
        let body = serialize(&events, &endings, bom, open_tail);
        let pieces = chunked(&body, &sizes);
        let parts: Vec<&[u8]> = pieces.iter().map(Vec::as_slice).collect();
        let codec = Arc::new(Dialect { content_only: true, ..Dialect::new() });
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        let (out, error) = runtime.block_on(async {
            let (up, _, _) = upstream(&parts, false);
            let (mut body, _rx) = relay(&codec, &Stop::running(), RelayLimits::default())
                .sse(up, &HeaderMap::new())
                .unwrap();
            drain(&mut body).await
        });
        prop_assert_eq!(error, None);
        prop_assert_eq!(out, body.clone(), "the relay changed the stream's bytes");
        prop_assert_eq!(codec.seen(), reference(&body), "the relay saw different events than an event-stream parser");
    }
}
