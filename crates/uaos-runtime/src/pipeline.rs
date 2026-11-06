// SPDX-License-Identifier: Apache-2.0

//! The request pipeline's typestate.
//!
//! An Operation moves through stages in order, one type per state.
//!
//! `Received → Parsed → Detected → Hooked → Routed → Authorized → Reserved → Spliced → Scanned →`
//! [`Ready`]
//!
//! Each transition is a method on the state before it. It takes that state by value and performs
//! exactly one stage, or ends the Operation with an [`Exit`]. Every field and constructor is
//! private to this module, so the transitions are the only way from one state to the next, and the
//! only way to a [`Ready`], the value the door accepts. The types are public so that ingress and
//! these tests can name them.
//!
//! **S2.** The body is parsed once into the tape, redacted on that tape, and scanned on the exact
//! outbound bytes, which [`Ready`] then carries unchanged. An Operation borrows its request from
//! ingress, which owns it, so the tape borrows the body without a copy (A-16). `Hooked` is the
//! identity with zero modules (`runtime-requires-module`); the stages between `Hooked` and
//! `Scanned` still pass through, until S3 and S4 give them their work.
//!
//! # The only way through
//!
//! The whole chain, stage by stage, compiles:
//!
//! ```
//! use uaos_redact::{FinalScanner, Redactor};
//! use uaos_runtime::pipeline::{Exit, Operation, Ready, Received, Route};
//!
//! fn through(
//!     op: Operation<'_, Received>,
//!     route: Route,
//!     redactor: &Redactor,
//!     scanner: &FinalScanner,
//! ) -> Result<Ready, Exit> {
//!     op.parse()?
//!         .detect(redactor)?
//!         .hook()?
//!         .route(route)?
//!         .authorize()?
//!         .reserve()?
//!         .splice()?
//!         .scan(scanner)?
//!         .ready()
//! }
//! ```
//!
//! A stage cannot be skipped: the final scan exists only after the splice (seeded violation
//! `stage-skipped`).
//!
//! ```compile_fail
//! use uaos_redact::FinalScanner;
//! use uaos_runtime::pipeline::{Operation, Received};
//!
//! fn skip(op: Operation<'_, Received>, scanner: &FinalScanner) {
//!     let _ = op.scan(scanner);
//! }
//! ```
//!
//! A [`Ready`] cannot be assembled outside this module, even from a scanned Operation: its fields
//! are private, and so are the types of what every Operation carries (seeded violation
//! `ready-outside-pipeline`, which makes them public).
//!
//! ```compile_fail
//! use uaos_runtime::pipeline::{Operation, Ready, Scanned};
//!
//! fn forge(op: Operation<'_, Scanned>) -> Ready {
//!     Ready { ids: op.core.ids, stage: op.stage }
//! }
//! ```
//!
//! rustdoc does not check a `compile_fail` block's error code on a stable compiler, so each block
//! has a seeded violation that removes exactly its guards. The seed makes the block compile, which
//! shows they are the only reason it fails.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http::uri::PathAndQuery;
use http::{HeaderMap, Method, header};
use uaos_contracts::error::{ErrorCode, codes};
use uaos_contracts::id::{CorrelationId, OperationId};
use uaos_json::{ErrorKind, Limits, Tape};
use uaos_module_api::{Mask, RoleMap};
use uaos_platform::Clock;
use uaos_redact::{DataClass, FinalScanner, Redactor};

use crate::admission::Permit;
use crate::config::{ConfigSnapshot, LocaleTag};
use crate::splice::{self, SplicePlan};

/// The tokenizer's limits for a request body: the default, until redaction's memory is bounded for
/// higher ones.
const LIMITS: Limits = Limits::DEFAULT;

/// Headers that never leave: hop-by-hop headers, the framing the door writes for its upstream, and
/// the client's own credentials. Names are compared as `http` stores them, in lowercase ASCII.
const NEVER_SENT: [&str; 13] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "cookie",
];

/// A pipeline stage: each state's name, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Stage {
    /// Admitted, holding the request as it arrived.
    Received,
    /// Parsed once into the tape.
    Parsed,
    /// Redacted on the tape.
    Detected,
    /// After module hooks; the identity with zero modules.
    Hooked,
    /// The upstream chosen.
    Routed,
    /// Authorized by policy.
    Authorized,
    /// The reservation and its intent acknowledged.
    Reserved,
    /// The splice plan validated.
    Spliced,
    /// The exact outbound bytes scanned.
    Scanned,
    /// Ready for the door.
    Ready,
}

impl Stage {
    /// Every stage, in order.
    pub const ALL: [Self; 10] = [
        Self::Received,
        Self::Parsed,
        Self::Detected,
        Self::Hooked,
        Self::Routed,
        Self::Authorized,
        Self::Reserved,
        Self::Spliced,
        Self::Scanned,
        Self::Ready,
    ];

    /// The stage's stable name, for counters and traces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Parsed => "parsed",
            Self::Detected => "detected",
            Self::Hooked => "hooked",
            Self::Routed => "routed",
            Self::Authorized => "authorized",
            Self::Reserved => "reserved",
            Self::Spliced => "spliced",
            Self::Scanned => "scanned",
            Self::Ready => "ready",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Received => 0,
            Self::Parsed => 1,
            Self::Detected => 2,
            Self::Hooked => 3,
            Self::Routed => 4,
            Self::Authorized => 5,
            Self::Reserved => 6,
            Self::Spliced => 7,
            Self::Scanned => 8,
            Self::Ready => 9,
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How an Operation leaves the pipeline before the door. Leaving drops the Operation, and with
/// it the admission permit it held.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Exit {
    /// A stage refused the request; the code says why. Nothing was sent.
    #[error("refused at the {stage} stage ({code})")]
    Refused {
        /// The stage that refused.
        stage: Stage,
        /// The registered error code.
        code: ErrorCode,
    },
}

/// The request as it arrived: what the client sent, before any stage. Its `Debug` output shows
/// sizes, never content (red line 2).
#[derive(Clone)]
pub struct Request {
    /// The client's method.
    pub method: Method,
    /// The client's path and query.
    pub path: PathAndQuery,
    /// The client's headers.
    pub headers: HeaderMap,
    /// The client's body, byte for byte.
    pub body: Bytes,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("headers", &self.headers.len())
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Where a request goes. Until pricing and routing, one declared upstream by name; the door module
/// maps it to its upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    upstream: String,
}

impl Route {
    /// A route to the declared upstream `upstream`.
    #[must_use]
    pub fn declared(upstream: impl Into<String>) -> Self {
        Self {
            upstream: upstream.into(),
        }
    }

    /// The declared upstream's name.
    #[must_use]
    pub fn upstream(&self) -> &str {
        &self.upstream
    }
}

/// What every state carries, and [`Ready`] keeps. Private to this module.
struct Ids {
    op_id: OperationId,
    correlation: CorrelationId,
    config: Arc<ConfigSnapshot>,
    permit: Permit,
    counters: Arc<Counters>,
}

/// What every state before [`Ready`] carries: the ids, and the request, borrowed from the
/// ingress that owns it (A-16). Private to this module.
struct Core<'r> {
    ids: Ids,
    request: &'r Request,
}

impl<'r> Core<'r> {
    /// Moves the Operation into `stage`, counting it and the transition's duration.
    fn advance<T>(self, stage: T, reached: Stage, started: u64) -> Operation<'r, T> {
        self.ids.counters.timed(reached, started);
        self.ids.counters.reached(reached);
        Operation { core: self, stage }
    }

    /// Ends the Operation at `stage` with `code`. Dropping it gives its permit back.
    fn refuse(self, stage: Stage, code: ErrorCode, started: u64) -> Exit {
        self.ids.counters.timed(stage, started);
        self.ids.counters.refused(stage);
        Exit::Refused { stage, code }
    }
}

/// An Operation in the state `S`, borrowing its request for `'r`. Only the transitions below
/// move it on.
pub struct Operation<'r, S> {
    core: Core<'r>,
    stage: S,
}

impl<S> fmt::Debug for Operation<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ids and sizes only: the request's content never reaches a log (red line 2).
        f.debug_struct("Operation")
            .field("op_id", &self.core.ids.op_id)
            .field("correlation", &self.core.ids.correlation)
            .field("body_len", &self.core.request.body.len())
            .finish_non_exhaustive()
    }
}

impl<S> Operation<'_, S> {
    /// The Operation's id.
    #[must_use]
    pub fn op_id(&self) -> OperationId {
        self.core.ids.op_id
    }

    /// The correlation id it carries from `Received` on.
    #[must_use]
    pub fn correlation(&self) -> CorrelationId {
        self.core.ids.correlation
    }

    /// The configuration snapshot pinned for it at admission.
    #[must_use]
    pub fn config(&self) -> &ConfigSnapshot {
        &self.core.ids.config
    }

    /// The locale pinned for it: its configuration snapshot's. Text a stage injects is rendered in
    /// it, once.
    #[must_use]
    pub fn locale(&self) -> &LocaleTag {
        self.core.ids.config.locale()
    }
}

/// What the parse found.
enum Body<'r> {
    /// A JSON document, on its tape.
    Json(Tape<'r>),
    /// UTF-8 text that is not JSON.
    Text(&'r str),
    /// Anything else, and an empty body.
    Bytes,
}

/// The body on its way out, after redaction: one shared buffer from `Detected` to [`Ready`].
struct Outbound {
    body: Bytes,
    json: bool,
    classes: BTreeSet<DataClass>,
}

impl fmt::Debug for Outbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outbound")
            .field("body_len", &self.body.len())
            .field("json", &self.json)
            .field("classes", &self.classes)
            .finish()
    }
}

/// The state before the parse.
#[derive(Debug)]
pub struct Received(());

/// Parsed once: the tape of a JSON body, or the body as text or bytes.
pub struct Parsed<'r> {
    body: Body<'r>,
}

impl fmt::Debug for Parsed<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Parsed");
        match &self.body {
            Body::Json(tape) => d.field("json_nodes", &tape.stats().nodes),
            Body::Text(text) => d.field("text_len", &text.len()),
            Body::Bytes => d.field("bytes", &true),
        };
        d.finish()
    }
}

/// Redacted on the tape: the body that leaves, its classes, and the [`Mask`] of what redaction
/// replaced.
pub struct Detected {
    out: Outbound,
    mask: Mask,
}

impl fmt::Debug for Detected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Detected")
            .field("out", &self.out)
            .finish_non_exhaustive()
    }
}

/// What the hooks hand to `splice`: the plan their declarations resolved to, the dialect codec's
/// roles, and redaction's mask.
struct Edits {
    plan: SplicePlan,
    roles: RoleMap,
    mask: Mask,
}

impl fmt::Debug for Edits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Edits")
            .field("edits", &self.plan.edits().len())
            .finish_non_exhaustive()
    }
}

/// After module hooks.
#[derive(Debug)]
pub struct Hooked {
    out: Outbound,
    edits: Edits,
}
/// Routed to an upstream.
#[derive(Debug)]
pub struct Routed {
    out: Outbound,
    edits: Edits,
    route: Route,
}
/// Authorized by policy.
#[derive(Debug)]
pub struct Authorized {
    out: Outbound,
    edits: Edits,
    route: Route,
}
/// Reserved, its intent acknowledged.
#[derive(Debug)]
pub struct Reserved {
    out: Outbound,
    edits: Edits,
    route: Route,
}
/// Spliced, the plan validated.
#[derive(Debug)]
pub struct Spliced {
    out: Outbound,
    route: Route,
}
/// The exact outbound request, scanned.
#[derive(Debug)]
pub struct Scanned {
    request: Request,
    json: bool,
    classes: BTreeSet<DataClass>,
    route: Route,
}

impl<'r> Operation<'r, Received> {
    /// Parses the body once: into the tape when it is JSON, else as text or bytes.
    ///
    /// # Errors
    /// [`Exit::Refused`] at [`Stage::Parsed`]: `INGRESS_TOO_LARGE` past a tokenizer limit,
    /// whatever the content type; `RUNTIME_OVERLOAD` when the tokenizer runs out of memory;
    /// `INGRESS_MALFORMED` for a body that does not parse although a `Content-Type` names JSON.
    pub fn parse(self) -> Result<Operation<'r, Parsed<'r>>, Exit> {
        let started = self.core.ids.counters.now();
        let request: &'r Request = self.core.request;
        let raw: &'r [u8] = &request.body;
        let body = if raw.is_empty() {
            Body::Bytes
        } else {
            match uaos_json::parse(raw, &LIMITS) {
                Ok(tape) => Body::Json(tape),
                Err(e) => {
                    let refusal = match e.kind() {
                        ErrorKind::TooLarge
                        | ErrorKind::DepthExceeded
                        | ErrorKind::TooManyNodes
                        | ErrorKind::KeyTooLong => Some(codes::INGRESS_TOO_LARGE),
                        ErrorKind::OutOfMemory => Some(codes::RUNTIME_OVERLOAD),
                        _ if declares_json(&request.headers) => Some(codes::INGRESS_MALFORMED),
                        _ => None,
                    };
                    if let Some(code) = refusal {
                        return Err(self.core.refuse(Stage::Parsed, code, started));
                    }
                    std::str::from_utf8(raw).map_or(Body::Bytes, Body::Text)
                }
            }
        };
        Ok(self.core.advance(Parsed { body }, Stage::Parsed, started))
    }
}

/// Whether a `Content-Type` names JSON: `application/json`, or a subtype ending in `+json`,
/// compared in ASCII without case. Any one such header is enough (fail closed).
fn declares_json(headers: &HeaderMap) -> bool {
    headers.get_all(header::CONTENT_TYPE).iter().any(|value| {
        let essence = value
            .as_bytes()
            .split(|b| *b == b';')
            .next()
            .unwrap_or_default()
            .trim_ascii();
        let suffix = essence.get(essence.len().saturating_sub(5)..).unwrap_or_default();
        essence.eq_ignore_ascii_case(b"application/json")
            || (essence.contains(&b'/') && essence.len() > 5 && suffix.eq_ignore_ascii_case(b"+json"))
    })
}

impl<'r> Operation<'r, Parsed<'r>> {
    /// Redacts the body with the pocket's `redactor`: on the tape for JSON, as text for text; bytes
    /// are left to the final scan. The secrets it replaced are wiped when it returns.
    ///
    /// # Errors
    /// [`Exit::Refused`] at [`Stage::Detected`] with the redaction error's code: every error
    /// blocks.
    pub fn detect(self, redactor: &Redactor) -> Result<Operation<'r, Detected>, Exit> {
        let started = self.core.ids.counters.now();
        let Operation { core, stage } = self;
        let original = &core.request.body;
        let redacted = match &stage.body {
            Body::Json(tape) => redactor.redact_tape(tape).map(|redaction| {
                let mut mask = Mask::new();
                for edited in redaction.edited() {
                    if edited.is_key() {
                        mask.key(edited.node());
                    } else {
                        mask.value(edited.node());
                    }
                }
                let classes = redaction.classes();
                let body = match redaction.into_output() {
                    // Redaction borrows its whole input when it changes nothing.
                    Cow::Borrowed(_) => original.clone(),
                    Cow::Owned(bytes) => Bytes::from(bytes),
                };
                (
                    Outbound {
                        body,
                        json: true,
                        classes,
                    },
                    mask,
                )
            }),
            Body::Text(text) => redactor.redact_text(text).map(|redaction| {
                let classes = redaction.classes();
                let body = match redaction.into_output() {
                    Cow::Borrowed(_) => original.clone(),
                    Cow::Owned(text) => Bytes::from(text.into_bytes()),
                };
                (
                    Outbound {
                        body,
                        json: false,
                        classes,
                    },
                    Mask::new(),
                )
            }),
            Body::Bytes => Ok((
                Outbound {
                    body: original.clone(),
                    json: false,
                    classes: BTreeSet::new(),
                },
                Mask::new(),
            )),
        };
        drop(stage);
        match redacted {
            Ok((out, mask)) => Ok(core.advance(Detected { out, mask }, Stage::Detected, started)),
            Err(e) => Err(core.refuse(Stage::Detected, e.code(), started)),
        }
    }
}

impl<'r> Operation<'r, Detected> {
    /// What redaction replaced, by node, for a module's view (A-6; the module host).
    #[must_use]
    pub fn mask(&self) -> &Mask {
        &self.stage.mask
    }

    /// The classes redaction found: the policy context's data classes.
    #[must_use]
    pub fn classes(&self) -> &BTreeSet<DataClass> {
        &self.stage.out.classes
    }

    /// Runs the module hooks. With zero modules this is the identity, and the kernel needs no
    /// module to pass (`runtime-requires-module`).
    ///
    /// # Errors
    /// [`Exit::Refused`] when a hook refuses.
    pub fn hook(self) -> Result<Operation<'r, Hooked>, Exit> {
        Ok(self.hook_with(SplicePlan::new(), RoleMap::new()))
    }

    /// The hooks' result as the module host will hand it over: the plan its modules' declarations
    /// resolved to, and the dialect codec's roles. `splice` validates and applies the plan.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "the module host calls it; until then, only the tests do")
    )]
    pub(crate) fn hook_with(self, plan: SplicePlan, roles: RoleMap) -> Operation<'r, Hooked> {
        let started = self.core.ids.counters.now();
        let Operation { core, stage } = self;
        let edits = Edits {
            plan,
            roles,
            mask: stage.mask,
        };
        core.advance(Hooked { out: stage.out, edits }, Stage::Hooked, started)
    }
}

impl<'r> Operation<'r, Hooked> {
    /// Routes the request to `route`.
    ///
    /// # Errors
    /// [`Exit::Refused`] for an undeclared upstream.
    pub fn route(self, route: Route) -> Result<Operation<'r, Routed>, Exit> {
        let started = self.core.ids.counters.now();
        let Operation { core, stage } = self;
        let Hooked { out, edits } = stage;
        Ok(core.advance(Routed { out, edits, route }, Stage::Routed, started))
    }
}

impl<'r> Operation<'r, Routed> {
    /// Authorizes the request. It passes through until then.
    ///
    /// # Errors
    /// [`Exit::Refused`]; S4 adds the denial and the approval exits.
    pub fn authorize(self) -> Result<Operation<'r, Authorized>, Exit> {
        let started = self.core.ids.counters.now();
        let Operation { core, stage } = self;
        let Routed { out, edits, route } = stage;
        Ok(core.advance(Authorized { out, edits, route }, Stage::Authorized, started))
    }
}

impl<'r> Operation<'r, Authorized> {
    /// Reserves the budget behind an acknowledged critical intent (with record). It passes through
    /// until then.
    ///
    /// # Errors
    /// [`Exit::Refused`] when the reservation or its record fails.
    pub fn reserve(self) -> Result<Operation<'r, Reserved>, Exit> {
        let started = self.core.ids.counters.now();
        let Operation { core, stage } = self;
        let Authorized { out, edits, route } = stage;
        Ok(core.advance(Reserved { out, edits, route }, Stage::Reserved, started))
    }
}

impl<'r> Operation<'r, Reserved> {
    /// Validates the hooks' splice plan against the roles and the mask, then applies it. With zero
    /// modules the plan is empty: nothing changes, and nothing more is parsed.
    ///
    /// # Errors
    /// [`Exit::Refused`] at [`Stage::Spliced`]: `RUNTIME_EDIT_REFUSED` for a refused plan, a plan
    /// on a body that is not JSON, or an edited body that does not parse; `INGRESS_TOO_LARGE`
    /// when the edited body passes a limit. Nothing is changed.
    pub fn splice(self) -> Result<Operation<'r, Spliced>, Exit> {
        let started = self.core.ids.counters.now();
        let Operation { core, stage } = self;
        let Reserved { mut out, edits, route } = stage;
        let spliced = if edits.plan.is_empty() {
            Ok(None)
        } else if out.json {
            splice::splice(&out.body, &LIMITS, &edits.mask, &edits.roles, &edits.plan)
        } else {
            Err(splice::SpliceError::NotJson)
        };
        match spliced {
            Ok(None) => {}
            Ok(Some(bytes)) => out.body = Bytes::from(bytes),
            Err(e) => return Err(core.refuse(Stage::Spliced, e.code(), started)),
        }
        Ok(core.advance(Spliced { out, route }, Stage::Spliced, started))
    }
}

/// How the final scan reads one part of the outbound request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// A JSON body: `check_json`.
    Json,
    /// Anything else: `check_bytes`.
    Bytes,
}

impl<'r> Operation<'r, Spliced> {
    /// Builds the outbound request and runs the installation's final `scanner` on its exact bytes:
    /// `check_json` on a JSON body, `check_bytes` on any other body, on the path and query, and on
    /// each header's name and value. [`Ready`] carries these bytes, moved.
    ///
    /// # Errors
    /// [`Exit::Refused`] at [`Stage::Scanned`] with the block's code, on any detection or known
    /// secret; S4 releases the reservation first.
    pub fn scan(self, scanner: &FinalScanner) -> Result<Operation<'r, Scanned>, Exit> {
        self.scan_with(|part, bytes| {
            match part {
                Part::Json => scanner.check_json(bytes),
                Part::Bytes => scanner.check_bytes(bytes),
            }
            .map_err(|blocked| blocked.code())
        })
    }

    /// The scan, with the check as an argument, so the call-site test can record what the check
    /// saw. Private: outside this module, only [`FinalScanner`] can check.
    fn scan_with(
        self,
        mut check: impl FnMut(Part, &[u8]) -> Result<(), ErrorCode>,
    ) -> Result<Operation<'r, Scanned>, Exit> {
        let started = self.core.ids.counters.now();
        let Operation { core, stage } = self;
        let Spliced { out, route } = stage;
        let request = Request {
            method: core.request.method.clone(),
            path: core.request.path.clone(),
            headers: outbound_headers(&core.request.headers),
            body: out.body,
        };
        let blocked = {
            let body = if out.json { Part::Json } else { Part::Bytes };
            let headers = request
                .headers
                .iter()
                .flat_map(|(name, value)| [(Part::Bytes, name.as_str().as_bytes()), (Part::Bytes, value.as_bytes())]);
            std::iter::once((body, request.body.as_ref()))
                .chain(std::iter::once((Part::Bytes, request.path.as_str().as_bytes())))
                .chain(headers)
                .find_map(|(part, bytes)| check(part, bytes).err())
        };
        if let Some(code) = blocked {
            return Err(core.refuse(Stage::Scanned, code, started));
        }
        let scanned = Scanned {
            request,
            json: out.json,
            classes: out.classes,
            route,
        };
        Ok(core.advance(scanned, Stage::Scanned, started))
    }
}

/// The client's headers that leave: all but [`NEVER_SENT`] and the headers `Connection` names
/// (RFC 9110 §7.6.1), in order.
fn outbound_headers(headers: &HeaderMap) -> HeaderMap {
    let named: Vec<Vec<u8>> = headers
        .get_all(header::CONNECTION)
        .iter()
        .flat_map(|value| value.as_bytes().split(|b| *b == b','))
        .map(|token| token.trim_ascii().to_ascii_lowercase())
        .collect();
    let mut out = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let lower = name.as_str();
        if !NEVER_SENT.contains(&lower) && !named.iter().any(|t| t.as_slice() == lower.as_bytes()) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

impl Operation<'_, Scanned> {
    /// The Operation, ready for the door.
    ///
    /// # Errors
    /// None yet; the signature keeps every stage's shape.
    pub fn ready(self) -> Result<Ready, Exit> {
        let Operation { core, stage } = self;
        core.ids.counters.reached(Stage::Ready);
        Ok(Ready { ids: core.ids, stage })
    }
}

/// An Operation that passed every stage: its id, its route and the request the final scan read.
/// Only [`Operation::<Scanned>::ready`] builds one; the door takes it by value and checks its
/// `op_id` binding (`door-op-id-mismatch`).
pub struct Ready {
    ids: Ids,
    stage: Scanned,
}

impl fmt::Debug for Ready {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ready")
            .field("op_id", &self.ids.op_id)
            .field("route", &self.stage.route)
            .field("body_len", &self.stage.request.body.len())
            .finish_non_exhaustive()
    }
}

impl Ready {
    /// The Operation's id, which the door binds the request to.
    #[must_use]
    pub fn op_id(&self) -> OperationId {
        self.ids.op_id
    }

    /// The correlation id.
    #[must_use]
    pub fn correlation(&self) -> CorrelationId {
        self.ids.correlation
    }

    /// The locale pinned for the Operation.
    #[must_use]
    pub fn locale(&self) -> &LocaleTag {
        self.ids.config.locale()
    }

    /// The authorized route.
    #[must_use]
    pub fn route(&self) -> &Route {
        &self.stage.route
    }

    /// The outbound request, exactly as the final scan read it; the door sends it byte for byte,
    /// adding only framing and the provider's key.
    #[must_use]
    pub fn request(&self) -> &Request {
        &self.stage.request
    }

    /// Whether the body is JSON, which the final scan read as such.
    #[must_use]
    pub fn is_json(&self) -> bool {
        self.stage.json
    }

    /// The classes redaction replaced.
    #[must_use]
    pub fn classes(&self) -> &BTreeSet<DataClass> {
        &self.stage.classes
    }

    /// The admission permit the Operation holds until it ends.
    #[must_use]
    pub fn permit(&self) -> &Permit {
        &self.ids.permit
    }
}

/// Buckets of a stage's duration histogram: one per bound in [`DURATION_BOUNDS_NANOS`], and one
/// above the last.
pub const DURATION_BUCKETS: usize = 17;

/// The upper bound of each duration bucket but the last, in nanoseconds: 1 µs, doubling to 32.768
/// ms.
pub const DURATION_BOUNDS_NANOS: [u64; DURATION_BUCKETS - 1] = [
    1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000, 256_000, 512_000, 1_024_000, 2_048_000, 4_096_000,
    8_192_000, 16_384_000, 32_768_000,
];

/// The bucket for a duration of `nanos`.
fn bucket(nanos: u64) -> usize {
    DURATION_BOUNDS_NANOS
        .iter()
        .position(|bound| nanos <= *bound)
        .unwrap_or(DURATION_BOUNDS_NANOS.len())
}

/// How many Operations reached each stage, how many each stage refused, and how long each stage
/// took, on the kernel's monotonic clock.
struct Counters {
    clock: Arc<dyn Clock>,
    reached: [AtomicU64; 10],
    refused: [AtomicU64; 10],
    timed: [AtomicU64; 10],
    total_nanos: [AtomicU64; 10],
    max_nanos: [AtomicU64; 10],
    buckets: [[AtomicU64; DURATION_BUCKETS]; 10],
}

impl Counters {
    fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            reached: Default::default(),
            refused: Default::default(),
            timed: Default::default(),
            total_nanos: Default::default(),
            max_nanos: Default::default(),
            buckets: Default::default(),
        }
    }

    fn now(&self) -> u64 {
        self.clock.mono().0
    }

    fn reached(&self, stage: Stage) {
        if let Some(c) = self.reached.get(stage.index()) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn refused(&self, stage: Stage) {
        if let Some(c) = self.refused.get(stage.index()) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records one transition into `stage`, begun at `started`.
    fn timed(&self, stage: Stage, started: u64) {
        let nanos = self.now().saturating_sub(started);
        let i = stage.index();
        if let Some(c) = self.timed.get(i) {
            c.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(c) = self.total_nanos.get(i) {
            c.fetch_add(nanos, Ordering::Relaxed);
        }
        if let Some(c) = self.max_nanos.get(i) {
            c.fetch_max(nanos, Ordering::Relaxed);
        }
        if let Some(c) = self.buckets.get(i).and_then(|b| b.get(bucket(nanos))) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl fmt::Debug for Counters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Counters").finish_non_exhaustive()
    }
}

/// How long one stage's transitions took, passing or refusing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct StageDurations {
    /// Transitions measured.
    pub count: u64,
    /// Their total, in nanoseconds.
    pub total_nanos: u64,
    /// The longest, in nanoseconds.
    pub max_nanos: u64,
    /// The histogram: bucket `i` counts durations up to [`DURATION_BOUNDS_NANOS`]`[i]` and above
    /// the bound before it; the last bucket, those above every bound.
    pub buckets: [u64; DURATION_BUCKETS],
}

/// The counters at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PipelineStats {
    reached: [u64; 10],
    refused: [u64; 10],
    durations: [StageDurations; 10],
}

impl PipelineStats {
    /// How many Operations reached `stage`.
    #[must_use]
    pub fn reached(&self, stage: Stage) -> u64 {
        self.reached.get(stage.index()).copied().unwrap_or(0)
    }

    /// How many Operations `stage` refused.
    #[must_use]
    pub fn refused(&self, stage: Stage) -> u64 {
        self.refused.get(stage.index()).copied().unwrap_or(0)
    }

    /// How long `stage`'s transitions took. `Received` and `Ready` are reached without work, so
    /// theirs stay empty.
    #[must_use]
    pub fn durations(&self, stage: Stage) -> StageDurations {
        self.durations.get(stage.index()).copied().unwrap_or_default()
    }
}

/// The pipeline's entry: one per kernel. It admits nothing itself; it takes an admitted
/// Operation's permit and starts the Operation at `Received`.
#[derive(Debug, Clone)]
pub struct Pipeline {
    counters: Arc<Counters>,
}

impl Pipeline {
    /// A pipeline with its counters at zero, timing its stages on `clock`'s monotonic reading.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            counters: Arc::new(Counters::new(clock)),
        }
    }

    /// Starts an admitted Operation over `request`, which the caller owns and keeps until the
    /// Operation reaches [`Ready`] or exits (A-16). The `permit` is the proof of admission
    /// ([`crate::Admission::admit`]); the Operation holds it until it ends, at an [`Exit`] or
    /// after the door.
    #[must_use]
    pub fn receive<'r>(
        &self,
        permit: Permit,
        op_id: OperationId,
        correlation: CorrelationId,
        config: Arc<ConfigSnapshot>,
        request: &'r Request,
    ) -> Operation<'r, Received> {
        self.counters.reached(Stage::Received);
        Operation {
            core: Core {
                ids: Ids {
                    op_id,
                    correlation,
                    config,
                    permit,
                    counters: Arc::clone(&self.counters),
                },
                request,
            },
            stage: Received(()),
        }
    }

    /// The counters now.
    #[must_use]
    pub fn stats(&self) -> PipelineStats {
        let c = &self.counters;
        let read = |a: &[AtomicU64; 10]| std::array::from_fn(|i| a.get(i).map_or(0, |v| v.load(Ordering::Relaxed)));
        let (timed, total, max) = (read(&c.timed), read(&c.total_nanos), read(&c.max_nanos));
        PipelineStats {
            reached: read(&c.reached),
            refused: read(&c.refused),
            durations: std::array::from_fn(|i| StageDurations {
                count: timed.get(i).copied().unwrap_or(0),
                total_nanos: total.get(i).copied().unwrap_or(0),
                max_nanos: max.get(i).copied().unwrap_or(0),
                buckets: c.buckets.get(i).map_or([0; DURATION_BUCKETS], |b| {
                    std::array::from_fn(|j| b.get(j).map_or(0, |v| v.load(Ordering::Relaxed)))
                }),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test harness: a failed fixture fails the test that called it"
    )]

    use http::HeaderValue;
    use uaos_contracts::id::TypedId;
    use uaos_contracts::time::WallTime;
    use uaos_contracts::wire::ConfigVersion;
    use uaos_platform::crypto::SecretKey;
    use uaos_platform::sim::SimClock;
    use uaos_redact::DetectorVersion;

    use super::*;
    use crate::{Admission, AdmissionLimits, Stop};

    /// One call of the check: how it read the part, where the bytes lived, and what they were.
    type Seen = (Part, usize, Vec<u8>);

    fn spliced<'r>(admission: &Admission, pipeline: &Pipeline, request: &'r Request) -> Operation<'r, Spliced> {
        let permit = admission.admit(1).unwrap();
        let config = Arc::new(ConfigSnapshot::new(ConfigVersion(1), LocaleTag::new("en").unwrap()));
        let redactor = Redactor::new(DetectorVersion::V1, SecretKey::from_bytes([7; 32])).unwrap();
        pipeline
            .receive(
                permit,
                OperationId::from_parts(1, [1; 10]),
                CorrelationId::from_parts(1, [1; 10]),
                config,
                request,
            )
            .parse()
            .unwrap()
            .detect(&redactor)
            .unwrap()
            .hook()
            .unwrap()
            .route(Route::declared("mock"))
            .unwrap()
            .authorize()
            .unwrap()
            .reserve()
            .unwrap()
            .splice()
            .unwrap()
    }

    /// The call-site test: the bytes `Ready` carries for the door are, part by part, the bytes the
    /// final scan read, in the same buffers, for a JSON, a text and a bytes body. This is the
    /// proof; no gate checks the call site statically.
    #[test]
    fn the_door_gets_exactly_the_bytes_the_scan_read() {
        let admission = Admission::new(AdmissionLimits::default(), Stop::running());
        let clock = Arc::new(SimClock::new(WallTime::from_unix_nanos(0).unwrap()));
        let pipeline = Pipeline::new(clock);
        let token = format!("ghp_{}", "a".repeat(36));
        let bodies: [(&str, Vec<u8>, Part); 3] = [
            (
                "application/json",
                format!(r#"{{"m":"{token}","n":"ok"}}"#).into_bytes(),
                Part::Json,
            ),
            (
                "text/plain",
                format!("say {token} twice {token}").into_bytes(),
                Part::Bytes,
            ),
            ("application/octet-stream", b"\xff\x00raw".to_vec(), Part::Bytes),
        ];
        for (content_type, body, read_as) in bodies {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
            headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer client"));
            let request = Request {
                method: Method::POST,
                path: PathAndQuery::from_static("/v1/messages?beta=true"),
                headers,
                body: Bytes::from(body),
            };
            let mut seen: Vec<Seen> = Vec::new();
            let scanned = spliced(&admission, &pipeline, &request)
                .scan_with(|part, bytes| {
                    seen.push((part, bytes.as_ptr().addr(), bytes.to_vec()));
                    Ok(())
                })
                .unwrap();
            let ready = scanned.ready().unwrap();
            let out = ready.request();
            let mut sent: Vec<Seen> = vec![
                (read_as, out.body.as_ptr().addr(), out.body.to_vec()),
                (
                    Part::Bytes,
                    out.path.as_str().as_ptr().addr(),
                    out.path.as_str().as_bytes().to_vec(),
                ),
            ];
            for (name, value) in &out.headers {
                sent.push((
                    Part::Bytes,
                    name.as_str().as_ptr().addr(),
                    name.as_str().as_bytes().to_vec(),
                ));
                sent.push((Part::Bytes, value.as_bytes().as_ptr().addr(), value.as_bytes().to_vec()));
            }
            assert_eq!(seen, sent, "{content_type}: what the scan read is what the door gets");
            assert!(!out.headers.contains_key(header::AUTHORIZATION), "{content_type}");
            assert!(
                !out.body.windows(token.len()).any(|w| w == token.as_bytes()),
                "{content_type}: the scan read the redacted body"
            );
        }
    }

    /// A refusal from the check ends the Operation at `Scanned` with the check's code.
    #[test]
    fn a_blocked_part_refuses_at_the_scan() {
        let admission = Admission::new(AdmissionLimits::default(), Stop::running());
        let pipeline = Pipeline::new(Arc::new(SimClock::new(WallTime::from_unix_nanos(0).unwrap())));
        let request = Request {
            method: Method::POST,
            path: PathAndQuery::from_static("/v1/messages"),
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"{}"),
        };
        let mut calls = 0;
        let exit = spliced(&admission, &pipeline, &request)
            .scan_with(|_, _| {
                calls += 1;
                Err(codes::REDACT_BLOCKED)
            })
            .map(drop);
        assert_eq!(
            exit,
            Err(Exit::Refused {
                stage: Stage::Scanned,
                code: codes::REDACT_BLOCKED
            })
        );
        assert_eq!(calls, 1, "the first block ends the scan");
        assert_eq!(admission.in_flight(), (0, 0));
        assert_eq!(pipeline.stats().refused(Stage::Scanned), 1);
    }

    /// The roles a Messages codec would assign: the newest user message and the assistant's.
    fn codec_roles(tape: &Tape<'_>) -> RoleMap {
        use std::collections::BTreeSet;

        use uaos_module_api::{Predicate, Role, Selector, Step};

        let mask = Mask::new();
        let sealed = mask.seal(tape).unwrap();
        let mut roles = RoleMap::new();
        let messages = || Step::Key("messages".to_owned());
        let role_is = |r: &str| {
            Step::Where(Predicate::MemberIn {
                key: "role".to_owned(),
                values: BTreeSet::from([r.to_owned()]),
            })
        };
        for (steps, role) in [
            (
                vec![messages(), Step::Each, role_is("user"), Step::Last],
                Role::NewestHumanTurn,
            ),
            (
                vec![messages(), Step::Each, role_is("assistant")],
                Role::ProviderProduced,
            ),
        ] {
            roles
                .assign(&sealed.view(), &Selector::new(steps).unwrap(), role)
                .unwrap();
        }
        roles
    }

    fn request(content_type: &'static str, body: &str) -> Request {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        Request {
            method: Method::POST,
            path: PathAndQuery::from_static("/v1/messages"),
            headers,
            body: Bytes::copy_from_slice(body.as_bytes()),
        }
    }

    /// The splice plan through the pipeline: the hooks hand it over with the codec's roles;
    /// `splice` applies a permitted plan, refuses a forbidden one or one on a body that is not
    /// JSON, and the final scan reads what it wrote.
    #[test]
    fn the_plan_is_applied_or_refused_at_splice() {
        use uaos_module_api::ModuleText;

        use crate::splice::{Anchor, Class, Edit};

        let admission = Admission::new(AdmissionLimits::default(), Stop::running());
        let pipeline = Pipeline::new(Arc::new(SimClock::new(WallTime::from_unix_nanos(0).unwrap())));
        let redactor = Redactor::new(DetectorVersion::V1, SecretKey::from_bytes([7; 32])).unwrap();
        let vault = "vault-provider-key-7f3a9c2e5b1d4086";
        let scanner = FinalScanner::new(DetectorVersion::V1, [vault.as_bytes()]).unwrap();
        let body = r#"{"system":"s","messages":[{"role":"assistant","content":"a"},{"role":"user","content":[{"type":"text","text":"hi"},{"type":"text","text":"tag"}]}]}"#;
        let tape = uaos_json::parse(body.as_bytes(), &LIMITS).unwrap();
        let node = |path: &[&str]| {
            let mut n = tape.root();
            for step in path {
                n = match step.parse::<usize>() {
                    Ok(i) => n.children().nth(i).unwrap(),
                    Err(_) => n.member(step).unwrap().unwrap(),
                };
            }
            n.id()
        };
        let roles = codec_roles(&tape);
        let live = Class::Live(Anchor::NewestHumanTurn);
        let run = |req: &Request, plan: SplicePlan| {
            pipeline
                .receive(
                    admission.admit(1).unwrap(),
                    OperationId::from_parts(1, [1; 10]),
                    CorrelationId::from_parts(1, [1; 10]),
                    Arc::new(ConfigSnapshot::new(ConfigVersion(1), LocaleTag::new("en").unwrap())),
                    req,
                )
                .parse()
                .unwrap()
                .detect(&redactor)
                .unwrap()
                .hook_with(plan, roles.clone())
                .route(Route::declared("mock"))
                .unwrap()
                .authorize()
                .unwrap()
                .reserve()
                .unwrap()
                .splice()
                .and_then(|op| op.scan(&scanner))
                .and_then(Operation::ready)
        };
        let json = request("application/json", body);

        let permitted: SplicePlan = [
            Edit::strip(node(&["messages", "1", "content", "1"]), live),
            Edit::append(
                node(&["messages", "1", "content", "0", "text"]),
                ModuleText::new(" there").unwrap(),
                live,
            ),
        ]
        .into_iter()
        .collect();
        let ready = run(&json, permitted).unwrap();
        assert_eq!(
            ready.request().body,
            br#"{"system":"s","messages":[{"role":"assistant","content":"a"},{"role":"user","content":[{"type":"text","text":"hi there"}]}]}"#.as_slice()
        );

        let refused = |exit: Result<Ready, Exit>, stage: Stage, code| {
            assert_eq!(exit.map(drop), Err(Exit::Refused { stage, code }));
        };
        let forbidden: SplicePlan = [Edit::strip(node(&["messages", "0"]), Class::Replayed)]
            .into_iter()
            .collect();
        refused(run(&json, forbidden), Stage::Spliced, codes::RUNTIME_EDIT_REFUSED);
        let outside: SplicePlan = [Edit::strip(node(&["system"]), live)].into_iter().collect();
        refused(run(&json, outside.clone()), Stage::Spliced, codes::RUNTIME_EDIT_REFUSED);
        refused(
            run(&request("text/plain", "plain words"), outside),
            Stage::Spliced,
            codes::RUNTIME_EDIT_REFUSED,
        );
        let leaks: SplicePlan = [Edit::append(
            node(&["messages", "1", "content", "0", "text"]),
            ModuleText::new(vault).unwrap(),
            live,
        )]
        .into_iter()
        .collect();
        refused(run(&json, leaks), Stage::Scanned, codes::REDACT_BLOCKED);
        assert_eq!(pipeline.stats().refused(Stage::Spliced), 3);
        assert_eq!(admission.in_flight().0, 1, "only the Ready holds a permit");
        drop(ready);
        assert_eq!(admission.in_flight(), (0, 0));
    }

    /// The histogram's bounds: 1 µs, doubling to 32.768 ms, and one bucket above.
    #[test]
    fn durations_fall_in_their_buckets() {
        assert_eq!(bucket(0), 0);
        assert_eq!(bucket(1_000), 0);
        assert_eq!(bucket(1_001), 1);
        assert_eq!(bucket(2_000), 1);
        assert_eq!(bucket(32_768_000), 15);
        assert_eq!(bucket(32_768_001), 16);
        assert_eq!(bucket(u64::MAX), DURATION_BUCKETS - 1);
        assert!(
            DURATION_BOUNDS_NANOS
                .windows(2)
                .all(|w| w.get(1) == w.first().map(|b| b * 2).as_ref())
        );
    }

    /// The labels that declare JSON, compared in ASCII without case; anything else does not.
    #[test]
    fn content_types_that_name_json() {
        let says = |values: &[&'static str]| {
            let mut headers = HeaderMap::new();
            for v in values {
                headers.append(header::CONTENT_TYPE, HeaderValue::from_static(v));
            }
            declares_json(&headers)
        };
        assert!(says(&["application/json"]));
        assert!(says(&["Application/JSON; charset=utf-8"]));
        assert!(says(&["  application/json  ;x=y"]));
        assert!(says(&["application/vnd.api+json"]));
        assert!(says(&["text/plain", "application/json"]), "any one is enough");
        assert!(!says(&[]));
        assert!(!says(&["text/plain"]));
        assert!(!says(&["application/jsonp"]));
        assert!(!says(&["+json"]));
        assert!(!says(&["application/json-seq"]));
    }
}
