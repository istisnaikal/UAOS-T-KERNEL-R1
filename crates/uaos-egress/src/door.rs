// SPDX-License-Identifier: Apache-2.0

//! The door: the single outbound client.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::uri::{Authority, PathAndQuery};
use http::{Method, Request, StatusCode, Uri};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::rt::Executor;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioTimer;
use rustls::crypto::aws_lc_rs;
use rustls::{ClientConfig, RootCertStore};
use uaos_contracts::id::OperationId;
use uaos_platform::Clock;

use crate::EgressError;
use crate::connect::{Connector, CounterSnapshot, Counters, MAX_ADDRESSES_TRIED, Target, bump};
use crate::resolve::Resolve;
use crate::upstream::{Scheme, Trust, Upstream, UpstreamError, UpstreamId};

/// Operations remembered by the replay guard (bounded).
pub const REPLAY_WINDOW: usize = 65_536;
/// Idle pooled connections kept per upstream (bounded).
pub const MAX_IDLE_PER_UPSTREAM: usize = 8;
/// The `retry_after` hint while a probe is in flight: how soon to look again, not a promise. The
/// probe may settle sooner or take up to the response timeout.
pub const PROBE_RECHECK: Duration = Duration::from_secs(1);

/// Time and failure limits of the door.
///
/// What the door does not bound, and the runtime does: how many requests are in flight at once
/// (admission control and the per-upstream concurrency limit), and how long and how large a
/// response body may stream (the relay's idle watchdog and byte limits).
#[derive(Debug, Clone, Copy)]
pub struct DoorLimits {
    /// Name resolution, the TCP connect to each address, and the TLS handshake, each.
    pub connect_timeout: Duration,
    /// From handing the request to the client to receiving the response headers; it includes
    /// the connect phase, which [`Door::new`] requires it to exceed. Streaming bodies are timed
    /// by the runtime's idle watchdog, never here.
    pub response_timeout: Duration,
    /// Consecutive transport failures (unreachable, timed out, or cut off after the request was
    /// sent) that open an upstream's circuit.
    pub breaker_threshold: u32,
    /// How long an open circuit refuses attempts. After it, exactly one probe is let through;
    /// the rest are refused until the probe settles.
    pub breaker_cooldown: Duration,
    /// Largest request body the door sends.
    pub max_request_body: usize,
    /// How long an idle pooled connection is kept; at most a day ([`Door::new`] refuses more:
    /// hyper-util's idle timer overflows on `Duration::MAX`).
    pub idle_timeout: Duration,
}

impl Default for DoorLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(600),
            breaker_threshold: 5,
            breaker_cooldown: Duration::from_secs(30),
            max_request_body: 32 * 1024 * 1024,
            idle_timeout: Duration::from_secs(60),
        }
    }
}

/// One request through the door. Built by the runtime from a scanned, authorized Operation.
#[derive(Debug)]
pub struct EgressRequest {
    /// The Operation the request belongs to; must equal the binding passed to [`Door::send`].
    pub op_id: OperationId,
    /// Declared destination.
    pub upstream: UpstreamId,
    /// Method: one of GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS; any other is refused.
    pub method: Method,
    /// Path and query on the upstream; must start with `/`.
    pub path: PathAndQuery,
    /// Headers to forward. Hop-by-hop headers, `host` and `content-length` are removed (the door
    /// frames the body itself); credential-bearing headers are refused; nothing is added except
    /// the credential.
    pub headers: HeaderMap,
    /// The scanned body, sent byte for byte.
    pub body: Bytes,
}

/// The methods the door sends. TRACE answers with the request it received, so it would echo the
/// credential back to the caller, and CONNECT turns the connection into a tunnel; neither, nor an
/// extension method, is a provider call.
const SENT_METHODS: [Method; 7] = [
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
    Method::OPTIONS,
];

/// The provider credential the door injects last, after the final scan.
///
/// Its value is marked sensitive when the credential is built and is never printed: `Debug`
/// shows only the header name.
pub struct Credential {
    header: HeaderName,
    value: HeaderValue,
}

impl Credential {
    /// A credential carried in `header` (for example `x-api-key` or `authorization`).
    #[must_use]
    pub fn new(header: HeaderName, mut value: HeaderValue) -> Self {
        value.set_sensitive(true);
        Self { header, value }
    }

    /// The header that carries it.
    #[must_use]
    pub fn header(&self) -> &HeaderName {
        &self.header
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("header", &self.header)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// The upstream's response; the body streams frame by frame.
///
/// It means the provider received the request and answered. A body that fails after this (the
/// connection drops mid-stream) is an answer cut short, not a request that may not have arrived;
/// the caller settles it as delivered.
#[derive(Debug)]
pub struct EgressResponse {
    /// Status.
    pub status: StatusCode,
    /// Headers, hop-by-hop headers removed.
    pub headers: HeaderMap,
    /// Body, not yet read.
    pub body: Incoming,
}

/// Longest idle time a pooled connection is kept ([`DoorLimits::idle_timeout`]).
const MAX_IDLE_TIMEOUT: Duration = Duration::from_hours(24);

/// Headers that describe one connection, not the message (RFC 9110 §7.6.1).
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Headers known to carry credentials. A request from the runtime never carries one of them: the
/// client's own key to UAOS (a `uaos_sk_` sub-key in `authorization`), cookies and provider keys
/// would otherwise reach the provider. Credentials in other headers or in the query string are not
/// caught here; the runtime's final scan covers the body, and the request is built from the
/// client's own request.
pub const CREDENTIAL_HEADERS: [&str; 9] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "openai-organization",
    "x-amz-security-token",
    "ocp-apim-subscription-key",
];

/// Makes the response's framing headers describe the body the caller receives, which hyper has
/// already de-framed:
/// * `transfer-encoding` must be exactly what hyper decodes, one field whose value is `chunked`;
///   anything else is an error. The door asks for no coding (it strips `te`), and another
///   coding, `chunked` twice, an empty element after it or a second field would leave the body
///   still coded or still framed once `transfer-encoding` is stripped as hop-by-hop;
/// * a `content-length` beside `transfer-encoding` is dropped (RFC 9112 §6.3);
/// * a `204 No Content` keeps no `content-length`;
/// * otherwise `content-length` is forwarded as one value when all its values (as a list or as
///   several fields) are the same digits, and dropped when not. hyper checks them only where it
///   reads a body; for a HEAD request or a `304` they describe the resource, unchecked.
fn frame_for_caller(headers: &mut HeaderMap, status: StatusCode) -> Result<(), EgressError> {
    if headers.contains_key(header::TRANSFER_ENCODING) {
        let mut fields = headers.get_all(header::TRANSFER_ENCODING).iter();
        let chunked_only = match (fields.next(), fields.next()) {
            (Some(only), None) => only.to_str().is_ok_and(|v| v.trim().eq_ignore_ascii_case("chunked")),
            _ => false,
        };
        if !chunked_only {
            return Err(EgressError::Unusable(
                "the upstream used a transfer coding the door does not decode",
            ));
        }
        headers.remove(header::CONTENT_LENGTH);
        return Ok(());
    }
    if status == StatusCode::NO_CONTENT {
        headers.remove(header::CONTENT_LENGTH);
        return Ok(());
    }
    let lengths: Vec<String> = headers
        .get_all(header::CONTENT_LENGTH)
        .iter()
        .flat_map(|v| v.to_str().unwrap_or_default().split(','))
        .map(|l| l.trim().to_owned())
        .collect();
    let Some(first) = lengths.first() else {
        return Ok(());
    };
    let one = !first.is_empty() && first.bytes().all(|b| b.is_ascii_digit()) && lengths.iter().all(|l| l == first);
    match HeaderValue::from_str(first).ok().filter(|_| one) {
        Some(single) => {
            headers.insert(header::CONTENT_LENGTH, single);
        }
        None => {
            headers.remove(header::CONTENT_LENGTH);
        }
    }
    Ok(())
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// An upstream's circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Breaker {
    /// Attempts pass; `failures` consecutive transport failures so far, counted only from attempts
    /// admitted in this `epoch`. An epoch begins whenever the circuit closes after an outage.
    Closed { failures: u32, epoch: u64 },
    /// Attempts are refused until the monotonic instant `until`.
    Open { until: u64 },
    /// Numbered `generation`, is in flight after a cooldown; every other attempt is refused.
    Probing { generation: u64 },
}

impl Default for Breaker {
    fn default() -> Self {
        Self::Closed { failures: 0, epoch: 0 }
    }
}

/// What the breaker admitted an attempt as; its settlement is judged against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ticket {
    /// An ordinary attempt, admitted while the circuit was closed in `epoch`.
    Ordinary { epoch: u64 },
    /// The single attempt let through after a cooldown, numbered `generation`.
    Probe { generation: u64 },
}

/// How an admitted attempt ended, for the breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// A response arrived (any status).
    Answered,
    /// Unreachable, timed out, or cut off after the request was sent: evidence the upstream is
    /// down.
    TransportFailure,
    /// Refused or blocked by the door's own rules: no evidence about the upstream.
    NotAttempted,
}

impl Outcome {
    fn of(error: &EgressError) -> Self {
        match error {
            EgressError::Unreachable(_) | EgressError::Timeout | EgressError::Interrupted(_) => Self::TransportFailure,
            // An answer that could not be parsed is still an answer, as for one the door refuses
            // after the headers.
            EgressError::Unusable(_) => Self::Answered,
            _ => Self::NotAttempted,
        }
    }
}

/// An attempt the breaker admitted. It is settled exactly once: by [`Admitted::settle`] or, if the
/// caller drops the future while the request is in flight, on drop as not attempted, so a cancelled
/// probe can never leave the circuit probing forever.
struct Admitted<'a> {
    door: &'a Door,
    upstream: &'a UpstreamId,
    ticket: Ticket,
    settled: bool,
}

impl Admitted<'_> {
    fn settle(mut self, outcome: Outcome) {
        self.settled = true;
        self.door.breaker_record(self.upstream, self.ticket, outcome);
    }
}

impl Drop for Admitted<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.door
                .breaker_record(self.upstream, self.ticket, Outcome::NotAttempted);
        }
    }
}

#[derive(Debug, Default)]
struct Replay {
    seen: BTreeSet<OperationId>,
    order: VecDeque<OperationId>,
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // Each guarded value is updated by single statements; a panicking holder leaves it whole.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The egress door. Exactly one exists per daemon and only the runtime holds it. The runtime builds
/// it in one private module.
#[derive(Debug)]
pub struct Door {
    client: Client<Connector, Full<Bytes>>,
    upstreams: BTreeMap<UpstreamId, Upstream>,
    counters: Arc<Counters>,
    clock: Arc<dyn Clock>,
    limits: DoorLimits,
    breakers: Breakers,
    replay: Mutex<Replay>,
}

impl Door {
    /// Builds the door. Makes no network contact: resolution and connections happen per
    /// request. With [`Trust::System`] it reads the operating system's root certificates from
    /// the local store.
    ///
    /// `executor` drives connection tasks; the runtime passes its supervisor's, so the
    /// supervisor stays the only spawner.
    ///
    /// # Errors
    /// [`EgressError::Upstream`] for an invalid or duplicate declaration; [`EgressError::Tls`] if
    /// the TLS configuration cannot be built or no system root can be read; [`EgressError::Limits`]
    /// if the response timeout does not exceed the whole connect phase (resolution,
    /// [`MAX_ADDRESSES_TRIED`] connects and the handshake), which would report a request that never
    /// left as possibly received.
    pub fn new<E>(
        upstreams: Vec<Upstream>,
        resolver: Arc<dyn Resolve>,
        clock: Arc<dyn Clock>,
        executor: E,
        limits: DoorLimits,
    ) -> Result<Self, EgressError>
    where
        E: Executor<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> + Send + Sync + Clone + 'static,
    {
        let connect_phase = limits
            .connect_timeout
            .saturating_mul(u32::try_from(MAX_ADDRESSES_TRIED + 2).unwrap_or(u32::MAX));
        if limits.response_timeout <= connect_phase {
            return Err(EgressError::Limits(
                "the response timeout must exceed the connect phase, (MAX_ADDRESSES_TRIED + 2) connect timeouts",
            ));
        }
        // hyper-util adds the idle timeout to an `Instant`; `Duration::MAX` panics a connection
        // task when the first connection goes idle.
        if limits.idle_timeout > MAX_IDLE_TIMEOUT {
            return Err(EgressError::Limits("the idle timeout must not exceed a day"));
        }
        let mut system_roots = None;
        let mut by_id = BTreeMap::new();
        let mut targets = BTreeMap::new();
        for up in upstreams {
            up.validate().map_err(EgressError::Upstream)?;
            let tls = match up.scheme {
                Scheme::Https => Some(Connector::tls_for(tls_config(&up.trust, &mut system_roots)?)),
                Scheme::Http => None,
            };
            let key = (up.host.as_str().to_owned(), up.port);
            let target = Arc::new(Target {
                upstream: up.clone(),
                tls,
            });
            if targets.insert(key, target).is_some() || by_id.insert(up.id.clone(), up).is_some() {
                return Err(EgressError::Upstream(UpstreamError::Duplicate));
            }
        }
        let counters = Arc::new(Counters::default());
        let connector = Connector {
            targets: Arc::new(targets),
            resolver,
            counters: Arc::clone(&counters),
            connect_timeout: limits.connect_timeout,
        };
        let client = Client::builder(executor)
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(limits.idle_timeout)
            .pool_max_idle_per_host(MAX_IDLE_PER_UPSTREAM)
            // The door never retries, not even a request hyper-util considers unsent: the breaker
            // must see each attempt, and the runtime decides about retries.
            .retry_canceled_requests(false)
            .build(connector);
        Ok(Self {
            client,
            upstreams: by_id,
            counters,
            clock,
            limits,
            breakers: Breakers::default(),
            replay: Mutex::new(Replay::default()),
        })
    }

    /// External-contact counters.
    #[must_use]
    pub fn counters(&self) -> CounterSnapshot {
        self.counters.snapshot()
    }

    /// Sends one request for the Operation `binding`.
    ///
    /// Refused before any contact when the request belongs to another Operation, the upstream
    /// is undeclared, the body is too large, the path does not start with `/`, the method is
    /// not GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS, the request carries a
    /// credential-bearing header, the upstream's circuit is open, or the Operation
    /// already sent. Only the last consumes the Operation: once a request is handed to the
    /// client, even a failed one, a retry needs a new Operation. The URI is built from the
    /// upstream's own name and port, so nothing in the request can redirect it. The credential
    /// is inserted last. Redirects are returned, never followed. A `101 Switching Protocols`
    /// answer and any `transfer-encoding` but one `chunked` field are errors; the response's
    /// framing headers are made to describe the de-framed body (see `frame_for_caller`).
    ///
    /// # Errors
    /// [`EgressError`].
    pub async fn send(
        &self,
        binding: OperationId,
        request: EgressRequest,
        credential: Option<Credential>,
    ) -> Result<EgressResponse, EgressError> {
        let refuse = |why| {
            bump(&self.counters.refused);
            Err(EgressError::Refused(why))
        };
        if request.op_id != binding {
            return refuse("the request belongs to another Operation");
        }
        let Some(up) = self.upstreams.get(&request.upstream) else {
            return refuse("unknown upstream");
        };
        if request.body.len() > self.limits.max_request_body {
            return refuse("request body larger than the door's limit");
        }
        if !request.path.as_str().starts_with('/') {
            return refuse("request path must start with /");
        }
        if !SENT_METHODS.contains(&request.method) {
            return refuse("request method is not one the door sends");
        }
        let mut headers = request.headers;
        // Checked before anything is stripped, so a credential header that is also hop-by-hop
        // (`proxy-authorization`) or listed in `connection` is refused, not silently dropped.
        if CREDENTIAL_HEADERS.iter().any(|name| headers.contains_key(*name)) {
            return refuse("the request carries a credential-bearing header");
        }
        strip_hop_by_hop(&mut headers);
        headers.remove(header::HOST);
        headers.remove(header::CONTENT_LENGTH);
        let Ok(authority) = Authority::try_from(format!("{}:{}", up.host, up.port)) else {
            return refuse("upstream name does not form an authority");
        };
        let uri = Uri::builder()
            .scheme(match up.scheme {
                Scheme::Https => "https",
                Scheme::Http => "http",
            })
            .authority(authority)
            .path_and_query(request.path)
            .build();
        let Ok(uri) = uri else {
            return refuse("request path does not form a URI");
        };
        let Ok(mut outbound) = Request::builder()
            .method(request.method)
            .uri(uri)
            .body(Full::new(request.body))
        else {
            return refuse("request could not be built");
        };
        *outbound.headers_mut() = headers;
        let admitted = match self.breaker_admits(&request.upstream) {
            Ok(ticket) => Admitted {
                door: self,
                upstream: &request.upstream,
                ticket,
                settled: false,
            },
            Err(retry_after) => {
                bump(&self.counters.refused);
                return Err(EgressError::CircuitOpen { retry_after });
            }
        };
        if !self.first_send(binding) {
            admitted.settle(Outcome::NotAttempted);
            return refuse("the Operation already sent a request");
        }
        if let Some(c) = credential {
            outbound.headers_mut().insert(c.header, c.value);
        }

        bump(&self.counters.sent);
        // hyper-util records the connection when it hands the request to it, so a timeout tells a
        // request still waiting for its connection (a connect phase or connection task that ran
        // late) from one that may have been sent.
        let handed_over = hyper_util::client::legacy::connect::capture_connection(&mut outbound);
        let result = tokio::time::timeout(self.limits.response_timeout, self.client.request(outbound)).await;
        let response = match result {
            Err(_) => {
                admitted.settle(Outcome::TransportFailure);
                if handed_over.connection_metadata().is_none() {
                    return Err(EgressError::Timeout);
                }
                return Err(EgressError::Interrupted("no answer within the response timeout"));
            }
            Ok(Err(e)) => {
                let error = EgressError::from_client(&e);
                admitted.settle(Outcome::of(&error));
                return Err(error);
            }
            Ok(Ok(r)) => r,
        };
        admitted.settle(Outcome::Answered);
        let (parts, body) = response.into_parts();
        // The client returns a 1xx only for `101 Switching Protocols`, which nothing the door sends
        // asks for (it strips `upgrade`); passed on, it would let a relay switch its client's
        // connection.
        if parts.status.is_informational() {
            return Err(EgressError::Unusable("the upstream switched protocols unasked"));
        }
        let mut headers = parts.headers;
        frame_for_caller(&mut headers, parts.status)?;
        strip_hop_by_hop(&mut headers);
        Ok(EgressResponse {
            status: parts.status,
            headers,
            body,
        })
    }

    /// Records `op` as sent; `false` if it already was (within [`REPLAY_WINDOW`]).
    fn first_send(&self, op: OperationId) -> bool {
        let mut replay = locked(&self.replay);
        if !replay.seen.insert(op) {
            return false;
        }
        replay.order.push_back(op);
        if replay.order.len() > REPLAY_WINDOW
            && let Some(oldest) = replay.order.pop_front()
        {
            replay.seen.remove(&oldest);
        }
        true
    }

    fn breaker_admits(&self, id: &UpstreamId) -> Result<Ticket, Duration> {
        self.breakers
            .admits(id, self.clock.mono().0, self.limits.breaker_cooldown)
    }

    fn breaker_record(&self, id: &UpstreamId, ticket: Ticket, outcome: Outcome) {
        self.breakers.record(
            id,
            ticket,
            outcome,
            self.clock.mono().0,
            self.limits.breaker_threshold,
            self.limits.breaker_cooldown,
        );
    }
}

/// Every upstream's circuit, keyed by id (bounded by the declared upstreams), and the counter
/// that numbers every probe and every epoch, so no two are equal until it wraps after 2^64.
#[derive(Debug, Default)]
struct Breakers(Mutex<(BTreeMap<UpstreamId, Breaker>, u64)>);

impl Breakers {
    /// `Ok(ticket)` if the attempt may go: an ordinary attempt in the circuit's current epoch, or
    /// the single probe let through after a cooldown. `Err(retry_after)` while the circuit is
    /// open (the time left) or a probe is in flight ([`PROBE_RECHECK`], a hint). `now` is
    /// monotonic nanoseconds.
    fn admits(&self, id: &UpstreamId, now: u64, cooldown: Duration) -> Result<Ticket, Duration> {
        let mut state = locked(&self.0);
        let (breakers, issued) = &mut *state;
        let breaker = breakers.entry(id.clone()).or_default();
        match *breaker {
            Breaker::Closed { epoch, .. } => Ok(Ticket::Ordinary { epoch }),
            Breaker::Open { until } if until > now => Err(Duration::from_nanos(until - now)),
            Breaker::Open { .. } => {
                *issued = issued.wrapping_add(1);
                *breaker = Breaker::Probing { generation: *issued };
                Ok(Ticket::Probe { generation: *issued })
            }
            Breaker::Probing { .. } => Err(PROBE_RECHECK.min(cooldown)),
        }
    }

    /// Settles an admitted attempt. Only transport failures count against the upstream, and any
    /// answer closes the circuit; closing after an outage begins a new epoch. A probe that fails
    /// reopens it for another cooldown; a probe that never reached the upstream (refused or blocked
    /// by the door, or dropped by its caller) lets the next attempt probe instead. Evidence from
    /// before the circuit last moved on changes nothing unless it is an answer: a probe whose
    /// generation is no longer in flight, or an ordinary attempt admitted in an earlier epoch, such
    /// as one sent during an outage a probe has since ended.
    fn record(&self, id: &UpstreamId, ticket: Ticket, outcome: Outcome, now: u64, threshold: u32, cooldown: Duration) {
        let cooldown = u64::try_from(cooldown.as_nanos()).unwrap_or(u64::MAX);
        let mut state = locked(&self.0);
        let (breakers, issued) = &mut *state;
        let breaker = breakers.entry(id.clone()).or_default();
        *breaker = match (outcome, ticket, *breaker) {
            (Outcome::Answered, _, Breaker::Closed { epoch, .. }) => Breaker::Closed { failures: 0, epoch },
            (Outcome::Answered, _, _) => {
                *issued = issued.wrapping_add(1);
                Breaker::Closed {
                    failures: 0,
                    epoch: *issued,
                }
            }
            (Outcome::TransportFailure, Ticket::Probe { generation }, Breaker::Probing { generation: current })
                if generation == current =>
            {
                Breaker::Open {
                    until: now.saturating_add(cooldown),
                }
            }
            (Outcome::NotAttempted, Ticket::Probe { generation }, Breaker::Probing { generation: current })
                if generation == current =>
            {
                Breaker::Open { until: now }
            }
            (
                Outcome::TransportFailure,
                Ticket::Ordinary { epoch },
                Breaker::Closed {
                    failures,
                    epoch: current,
                },
            ) if epoch == current => {
                let failures = failures.saturating_add(1);
                if failures >= threshold {
                    Breaker::Open {
                        until: now.saturating_add(cooldown),
                    }
                } else {
                    Breaker::Closed { failures, epoch }
                }
            }
            // Stale evidence, or a failure while open or probing: nothing changes.
            (_, _, current) => current,
        };
    }
}

/// TLS 1.2+ on aws-lc-rs, HTTP/1.1 only, with the upstream's certificate trust. The system's
/// roots are read once per door and shared by every upstream that uses them.
fn tls_config(trust: &Trust, system_roots: &mut Option<Arc<RootCertStore>>) -> Result<ClientConfig, EgressError> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| EgressError::Tls("no safe protocol versions"))?;
    let roots = match trust {
        Trust::System => {
            if let Some(roots) = system_roots {
                Arc::clone(roots)
            } else {
                let roots = Arc::new(load_system_roots()?);
                *system_roots = Some(Arc::clone(&roots));
                roots
            }
        }
        Trust::Roots(roots) => {
            if roots.is_empty() {
                return Err(EgressError::Tls("an upstream declares no root certificate to trust"));
            }
            let mut store = RootCertStore::empty();
            for root in roots {
                store
                    .add(root.clone())
                    .map_err(|_| EgressError::Tls("a configured root certificate is invalid"))?;
            }
            Arc::new(store)
        }
    };
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The operating system's root certificates, read from its local store. Certificates that do
/// not parse are skipped; none at all is an error.
fn load_system_roots() -> Result<RootCertStore, EgressError> {
    let found = rustls_native_certs::load_native_certs();
    let mut store = RootCertStore::empty();
    let (_added, _unparsable) = store.add_parsable_certificates(found.certs);
    if store.is_empty() {
        return Err(EgressError::Tls(
            "no root certificate could be read from the system store",
        ));
    }
    Ok(store)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures abort on failure")]

    use super::*;
    use crate::addr::Blocked;

    /// Only an unreachable upstream, a timeout or a request cut off after it was sent counts
    /// against it; an answer counts as one, parsable or not.
    #[test]
    fn only_transport_failures_count_against_an_upstream() {
        assert_eq!(Outcome::of(&EgressError::Unreachable("x")), Outcome::TransportFailure);
        assert_eq!(Outcome::of(&EgressError::Timeout), Outcome::TransportFailure);
        assert_eq!(Outcome::of(&EgressError::Interrupted("x")), Outcome::TransportFailure);
        for e in [
            EgressError::Refused("x"),
            EgressError::Blocked(Blocked::Loopback),
            EgressError::CircuitOpen {
                retry_after: Duration::ZERO,
            },
            EgressError::Tls("x"),
            EgressError::Limits("x"),
        ] {
            assert_eq!(Outcome::of(&e), Outcome::NotAttempted, "{e:?}");
        }
        assert_eq!(Outcome::of(&EgressError::Unusable("x")), Outcome::Answered);
    }

    fn ordinary(admitted: Result<Ticket, Duration>) -> bool {
        matches!(admitted, Ok(Ticket::Ordinary { .. }))
    }

    fn probe(admitted: Result<Ticket, Duration>) -> Ticket {
        let ticket = admitted.unwrap();
        assert!(
            matches!(ticket, Ticket::Probe { .. }),
            "expected a probe, got {ticket:?}"
        );
        ticket
    }

    const AFTER_COOLDOWN: u64 = 31_000_000_000;

    /// The breaker's states: closed, open until its cooldown ends, one probe, and back.
    #[test]
    fn the_breaker_lets_one_probe_through_and_settles_it() {
        let breakers = Breakers::default();
        let id = UpstreamId::new("x");
        let cooldown = Duration::from_secs(30);
        let (threshold, mut now) = (2, 1_000_u64);
        let admit = |now| breakers.admits(&id, now, cooldown);
        breakers.record(
            &id,
            admit(now).unwrap(),
            Outcome::TransportFailure,
            now,
            threshold,
            cooldown,
        );
        assert!(ordinary(admit(now)), "one failure keeps it closed");
        breakers.record(
            &id,
            admit(now).unwrap(),
            Outcome::NotAttempted,
            now,
            threshold,
            cooldown,
        );
        breakers.record(
            &id,
            admit(now).unwrap(),
            Outcome::TransportFailure,
            now,
            threshold,
            cooldown,
        );
        assert!(admit(now).is_err(), "the threshold opens it");
        now += AFTER_COOLDOWN;
        let p = probe(admit(now)); // the first attempt after the cooldown probes
        assert_eq!(admit(now), Err(PROBE_RECHECK), "only one probe at a time");
        breakers.record(&id, p, Outcome::NotAttempted, now, threshold, cooldown);
        let p = probe(admit(now)); // a probe that never reached it lets the next one probe
        breakers.record(&id, p, Outcome::TransportFailure, now, threshold, cooldown);
        assert!(admit(now).is_err(), "a failed probe reopens it");
        now += AFTER_COOLDOWN;
        let p = probe(admit(now));
        breakers.record(&id, p, Outcome::Answered, now, threshold, cooldown);
        assert!(ordinary(admit(now)), "an answered probe closes it");
    }

    /// A stale probe that gives up does not undo a circuit a later answer closed.
    #[test]
    fn a_stale_probe_cannot_reopen_a_closed_circuit() {
        let breakers = Breakers::default();
        let id = UpstreamId::new("x");
        let cooldown = Duration::from_secs(30);
        let mut now = 1_000_u64;
        let admit = |now| breakers.admits(&id, now, cooldown);
        let x = admit(now).unwrap(); // long-running
        breakers.record(&id, admit(now).unwrap(), Outcome::TransportFailure, now, 1, cooldown); // opens
        now += AFTER_COOLDOWN;
        let p = probe(admit(now));
        breakers.record(&id, x, Outcome::Answered, now, 1, cooldown); // X answers: closed
        breakers.record(&id, p, Outcome::NotAttempted, now, 1, cooldown); // the probe gives up
        assert!(
            ordinary(admit(now)) && ordinary(admit(now)),
            "a healthy circuit became probe-only"
        );
    }

    /// Nor does a stale probe that fails.
    #[test]
    fn a_stale_probe_failure_cannot_reopen_a_closed_circuit() {
        let breakers = Breakers::default();
        let id = UpstreamId::new("x");
        let cooldown = Duration::from_secs(30);
        let mut now = 1_000_u64;
        let admit = |now| breakers.admits(&id, now, cooldown);
        let x = admit(now).unwrap(); // long-running
        breakers.record(&id, admit(now).unwrap(), Outcome::TransportFailure, now, 1, cooldown); // opens
        now += AFTER_COOLDOWN;
        let p = probe(admit(now));
        breakers.record(&id, x, Outcome::Answered, now, 1, cooldown); // X answers: closed
        breakers.record(&id, p, Outcome::TransportFailure, now, 1, cooldown); // the stale probe fails
        assert!(
            ordinary(admit(now)),
            "a stale probe's failure reopened a healthy circuit"
        );
    }

    /// One probe in flight at a time, even when an older probe settles late.
    #[test]
    fn a_late_probe_settlement_does_not_admit_a_second_probe() {
        let breakers = Breakers::default();
        let id = UpstreamId::new("x");
        let cooldown = Duration::from_secs(30);
        let mut now = 1_000_u64;
        let admit = |now| breakers.admits(&id, now, cooldown);
        let x = admit(now).unwrap(); // long-running
        breakers.record(&id, admit(now).unwrap(), Outcome::TransportFailure, now, 1, cooldown); // opens
        now += AFTER_COOLDOWN;
        let first = probe(admit(now)); // P1
        breakers.record(&id, x, Outcome::Answered, now, 1, cooldown); // X answers: closed
        let w = admit(now).unwrap();
        assert!(matches!(w, Ticket::Ordinary { .. }));
        breakers.record(&id, w, Outcome::TransportFailure, now, 1, cooldown); // W fails: open
        now += AFTER_COOLDOWN;
        let second = probe(admit(now)); // P2, in flight
        assert_ne!(second, first);
        breakers.record(&id, first, Outcome::NotAttempted, now, 1, cooldown); // P1 settles late
        assert!(admit(now).is_err(), "a second probe was admitted while P2 is in flight");
    }

    /// Every close after an outage begins a new epoch, also when an ordinary attempt's late answer,
    /// not a probe, closes it.
    #[test]
    fn a_close_by_a_late_answer_begins_a_new_epoch() {
        let breakers = Breakers::default();
        let id = UpstreamId::new("x");
        let cooldown = Duration::from_secs(30);
        let now = 1_000_u64;
        let admit = |now| breakers.admits(&id, now, cooldown);
        let (c, d, x) = (admit(now).unwrap(), admit(now).unwrap(), admit(now).unwrap());
        breakers.record(&id, c, Outcome::TransportFailure, now, 1, cooldown); // opens
        breakers.record(&id, x, Outcome::Answered, now, 1, cooldown); // a late answer closes it
        breakers.record(&id, d, Outcome::TransportFailure, now, 1, cooldown); // sent before the close
        assert!(
            ordinary(admit(now)),
            "a failure sent before the close reopened the circuit"
        );
    }

    /// An answer while closed resets the count but keeps the epoch, so failures of attempts sent in
    /// the same epoch still count.
    #[test]
    fn failures_after_an_answer_in_the_same_epoch_still_count() {
        let breakers = Breakers::default();
        let id = UpstreamId::new("x");
        let cooldown = Duration::from_secs(30);
        let (threshold, now) = (2, 1_000_u64);
        let admit = |now| breakers.admits(&id, now, cooldown);
        let (a, b, x) = (admit(now).unwrap(), admit(now).unwrap(), admit(now).unwrap());
        breakers.record(&id, x, Outcome::Answered, now, threshold, cooldown);
        breakers.record(&id, a, Outcome::TransportFailure, now, threshold, cooldown);
        breakers.record(&id, b, Outcome::TransportFailure, now, threshold, cooldown);
        assert!(admit(now).is_err(), "two consecutive failures did not open the circuit");
    }

    /// Attempts sent during an outage that fail after a probe closed the circuit do not reopen it;
    /// failures of attempts sent since still count.
    #[test]
    fn failures_sent_during_an_outage_do_not_reopen_the_circuit_a_probe_closed() {
        let breakers = Breakers::default();
        let id = UpstreamId::new("x");
        let cooldown = Duration::from_secs(30);
        let (threshold, mut now) = (2, 1_000_u64);
        let admit = |now| breakers.admits(&id, now, cooldown);
        let sent: Vec<Ticket> = (0..4).map(|_| admit(now).unwrap()).collect(); // A, B, C, D
        breakers.record(&id, sent[2], Outcome::TransportFailure, now, threshold, cooldown);
        breakers.record(&id, sent[3], Outcome::TransportFailure, now, threshold, cooldown); // opens
        assert!(admit(now).is_err());
        now += AFTER_COOLDOWN;
        let p = probe(admit(now));
        breakers.record(&id, p, Outcome::Answered, now, threshold, cooldown); // healthy again
        let fresh = admit(now).unwrap();
        // A and B were sent during the outage and time out only now.
        breakers.record(&id, sent[0], Outcome::TransportFailure, now, threshold, cooldown);
        breakers.record(&id, sent[1], Outcome::TransportFailure, now, threshold, cooldown);
        assert!(
            ordinary(admit(now)),
            "a circuit a probe had just closed was reopened by attempts sent before the probe"
        );
        breakers.record(&id, fresh, Outcome::TransportFailure, now, threshold, cooldown);
        breakers.record(
            &id,
            admit(now).unwrap(),
            Outcome::TransportFailure,
            now,
            threshold,
            cooldown,
        );
        assert!(admit(now).is_err(), "failures in the new epoch did not open it");
    }
}
