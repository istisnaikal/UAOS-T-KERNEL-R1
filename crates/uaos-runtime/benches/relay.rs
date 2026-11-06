// SPDX-License-Identifier: Apache-2.0

//! The relay's per-event cost (≤ 1 ms of kernel overhead per event).
//!
//! Run: `cargo bench -p uaos-runtime --bench relay`. An in-memory upstream that is always ready
//! feeds a deterministic Anthropic-shaped stream, so what is timed is the kernel's own work: the
//! split, classification, the parse and the codec's read of every event, and for usage events the
//! price. Each chunk holds one event, so each timed poll is one event's work; one chunk in four
//! also takes the next event's first 7 bytes, so the copy of an incomplete event is timed too. It
//! prints p50, p95, p99 and the maximum per event, for content events and for usage events, after a
//! warm-up. `UAOS_BENCH_ENV` labels the environment. Dependency-free on purpose
//! (`harness = false`); nothing leaves the machine.

#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::disallowed_methods,
    reason = "benchmark binary: measures wall time and prints results"
)]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::HeaderMap;
use http_body_util::BodyExt as _;
use hyper::body::{Body, Frame};
use uaos_contracts::event::Actor;
use uaos_contracts::id::{CorrelationId, PoolId, ReservationId, TypedId};
use uaos_contracts::money::NanoUsd;
use uaos_contracts::wire::ConfigVersion;
use uaos_ledger::{Ledger, MemorySink};
use uaos_module_api::{
    Code, CodecError, DialectCodec, EndpointDecl, FrameKind, RoleMap, SseEvent, StructuralView, UsageReport, ViewText,
};
use uaos_runtime::{DeclaredPrice, EngagedBy, Relay, RelayLimits, Stop};

const EVENTS: usize = 2_000;
const WARMUP: usize = 5;
const ROUNDS: usize = 20;

/// Text in the seven GA locales, as content deltas carry it.
const TEXT: [&str; 7] = [
    "The quick brown fox jumps over the lazy dog while the build runs",
    "\u{130}stanbul'da \u{131}l\u{131}k bir g\u{fc}n, derleme s\u{fc}r\u{fc}yor",
    "Die Stra\u{df}e ist gro\u{df}, der Test l\u{e4}uft gerade",
    "\u{c7}a a \u{e9}t\u{e9} d\u{e9}j\u{e0} vu pendant la compilation",
    "\u{bf}A\u{f1}adir el ni\u{f1}o a la lista? \u{a1}S\u{ed}!",
    "Perch\u{e9} \u{e8} cos\u{ec} lento il test di oggi",
    "\u{645}\u{64e}\u{631}\u{652}\u{62d}\u{64e}\u{628}\u{64b}\u{627} \u{628}\u{650}\u{627}\u{644}\u{652}\u{639}\u{64e}\u{627}\u{644}\u{64e}\u{645}",
];

#[derive(Debug)]
struct Codec {
    dims: Vec<Code>,
}

impl DialectCodec for Codec {
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
        match event.event {
            Some("message_delta") => FrameKind::Usage,
            Some("ping") => FrameKind::Ping,
            _ => FrameKind::Content,
        }
    }

    fn usage(&self, view: &StructuralView<'_, '_>) -> Option<UsageReport> {
        let usage = view.root().member("usage").ok()??;
        let ViewText::Plain(text) = usage.member("output_tokens").ok()??.number_text()? else {
            return None;
        };
        UsageReport::new().dim(self.dims[0].clone(), text.parse().ok()?).ok()
    }
}

/// An upstream that is always ready.
struct Ready(VecDeque<Bytes>);

impl Body for Ready {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.pop_front().map(|b| Ok(Frame::data(b))))
    }
}

/// The stream's events, and whether each is a usage event: every 20th is one, cumulative.
fn events() -> Vec<(Vec<u8>, bool)> {
    (0..EVENTS)
        .map(|i| {
            if i % 20 == 19 {
                let event = format!(
                    "event: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{}},\"usage\":{{\"output_tokens\":{i}}}}}\n\n"
                );
                (event.into_bytes(), true)
            } else {
                let event = format!(
                    "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{}\"}}}}\n\n",
                    TEXT[i % TEXT.len()]
                );
                (event.into_bytes(), false)
            }
        })
        .collect()
}

/// One event per chunk; one chunk in four ends 7 bytes into the next event.
fn chunks(events: &[(Vec<u8>, bool)]) -> VecDeque<Bytes> {
    let body: Vec<u8> = events.iter().flat_map(|(e, _)| e.iter().copied()).collect();
    let ends: Vec<usize> = events
        .iter()
        .scan(0, |at, (e, _)| {
            *at += e.len();
            Some(*at)
        })
        .collect();
    let mut out = VecDeque::new();
    let (mut at, mut i, mut n) = (0, 0, 0);
    while at < body.len() {
        let next = (i + 1).min(ends.len());
        let mut end = ends[next - 1];
        if n % 4 == 3 {
            end += 7;
        }
        let end = end.clamp(at + 1, body.len());
        out.push_back(Bytes::copy_from_slice(&body[at..end]));
        at = end;
        i = next;
        n += 1;
    }
    out
}

fn percentile(sorted: &[Duration], p: usize) -> Duration {
    let i = (sorted.len() * p / 100).min(sorted.len() - 1);
    sorted[i]
}

fn print_row(label: &str, mut samples: Vec<Duration>) {
    samples.sort();
    println!(
        "{label:<8} n={:<6} p50={:>8.2?} p95={:>8.2?} p99={:>8.2?} max={:>8.2?}",
        samples.len(),
        percentile(&samples, 50),
        percentile(&samples, 95),
        percentile(&samples, 99),
        samples.last().copied().unwrap_or_default()
    );
}

fn main() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let dims = vec![Code::new("output_tokens").unwrap()];
    let codec: Arc<dyn DialectCodec> = Arc::new(Codec { dims: dims.clone() });
    let price = Arc::new(DeclaredPrice::new([(dims[0].clone(), NanoUsd::new(1))]).unwrap());
    let events = events();
    let body_len: usize = events.iter().map(|(e, _)| e.len()).sum();
    let (mut content, mut usage) = (Vec::new(), Vec::new());
    let mut total = Duration::ZERO;
    for round in 0..WARMUP + ROUNDS {
        let mut ledger = Ledger::default();
        let mut sink = MemorySink::default();
        let pool = PoolId::from_parts(1, [1; 10]);
        let key = uaos_contracts::budget::IdempotencyKey::new("fund").unwrap();
        ledger
            .allocate(&mut sink, pool, NanoUsd::new(1 << 40), &Actor::System, key)
            .unwrap();
        let reservation = ledger
            .reserve(
                &mut sink,
                pool,
                ReservationId::from_parts(1, [2; 10]),
                NanoUsd::new(1 << 39),
                &Actor::System,
            )
            .unwrap()
            .begin();
        let relay = Relay::new(
            Arc::clone(&codec),
            price.clone(),
            &reservation,
            Stop::running(),
            EngagedBy {
                actor: Actor::System,
                correlation_id: CorrelationId::from_parts(1, [3; 10]),
                config_version: ConfigVersion(1),
            },
            RelayLimits::default(),
        );
        let (mut body, _report) = relay.sse(Ready(chunks(&events)), &HeaderMap::new()).unwrap();
        runtime.block_on(async {
            let mut i = 0;
            let started = Instant::now();
            loop {
                let t = Instant::now();
                let Some(frame) = body.frame().await else { break };
                let took = t.elapsed();
                assert!(frame.unwrap().is_data());
                if round >= WARMUP {
                    if events[i].1 {
                        usage.push(took);
                    } else {
                        content.push(took);
                    }
                }
                i += 1;
            }
            assert_eq!(i, EVENTS, "the bench stream was cut");
            if round >= WARMUP {
                total += started.elapsed();
            }
        });
    }
    let env = std::env::var("UAOS_BENCH_ENV").unwrap_or_else(|_| "unlabelled".to_owned());
    println!(
        "relay bench: {EVENTS} events, {body_len} bytes per round, {ROUNDS} rounds; env={env}; {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    print_row("content", content);
    print_row("usage", usage);
    let rounds = u32::try_from(ROUNDS).unwrap();
    let per_round = total / rounds;
    println!(
        "per round {per_round:.2?}; {:.0} MB/s through the relay",
        f64::from(u32::try_from(body_len).unwrap()) / per_round.as_secs_f64() / 1e6
    );
}
