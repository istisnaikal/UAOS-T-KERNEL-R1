// SPDX-License-Identifier: Apache-2.0

//! The request pipeline:
//! - Every stage in order, with zero modules, and the admission permit held to the end;
//! - The body parsed once, redacted on the tape and masked by node, the final scan on the exact
//!   outbound bytes, the headers that never leave, the stage durations, and the seven-locale corpus
//!   from `Received` to `Ready` with 0 byte differences.
//!
//! The compile-time half, that no stage can be skipped and no `Ready` forged, is in the module's
//! own doctests (`src/pipeline.rs`); so is the call-site test, which needs the module's private
//! scan seam.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

use std::sync::Arc;

use bytes::Bytes;
use http::uri::PathAndQuery;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use uaos_contracts::error::{ErrorCode, codes};
use uaos_contracts::id::{CorrelationId, OperationId, TypedId};
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::ConfigVersion;
use uaos_module_api::Mask;
use uaos_platform::crypto::SecretKey;
use uaos_platform::sim::SimClock;
use uaos_redact::{DataClass, DetectorVersion, FinalScanner, Redactor};
use uaos_runtime::pipeline::{DURATION_BUCKETS, Exit, Operation, Pipeline, Ready, Received, Request, Route, Stage};
use uaos_runtime::{Admission, AdmissionLimits, ConfigCell, ConfigSnapshot, LocaleTag, Stop};

const BODY: &[u8] = b"{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"merhaba, \xc3\xa7ok iyi\"}]}";

/// A key the vault holds: the final scan blocks it wherever it appears.
const VAULT_KEY: &str = "vault-provider-key-7f3a9c2e5b1d4086";

/// The seven GA locales, around the classic hazards: the same corpus as the module socket's
/// language-neutrality test (`uaos-module-api/tests/language_neutrality.rs`).
const CORPUS: [(&str, &str); 7] = [
    (
        "en",
        "Continue where we stopped: the build is green 🙂, the 𝔘AOS tests are not.",
    ),
    ("tr", "İstanbul'da ılık bir gün: IŞIK ile ışık aynı değil, İ ile i de."),
    ("de", "Straße, STRASSE und Maß: ẞ ist der Großbuchstabe von ß."),
    (
        "fr",
        "Élève à l'école, déjà là; E\u{301}le\u{300}ve s'écrit aussi ainsi.",
    ),
    ("es", "¿Año nuevo? ¡Señor, mañana! Tambie\u{301}n an\u{303}o."),
    (
        "it",
        "Perché è così? Più caffè, già; perche\u{301} con un accento a parte.",
    ),
    ("ar", "مَرْحَبًا بِالعَالَم\u{200F} ١٢٣ \u{61C}نص\u{200E} done"),
];

/// A GitHub token, built at run time so the repository holds none.
fn github_token() -> String {
    format!("ghp_{}", "a".repeat(36))
}

fn request_with(body: &[u8], content_type: Option<&'static str>) -> Request {
    let mut headers = HeaderMap::new();
    if let Some(ct) = content_type {
        headers.insert("content-type", HeaderValue::from_static(ct));
    }
    Request {
        method: Method::POST,
        path: PathAndQuery::from_static("/v1/messages"),
        headers,
        body: Bytes::copy_from_slice(body),
    }
}

fn request() -> Request {
    request_with(BODY, Some("application/json"))
}

struct Fixture {
    admission: Admission,
    config: ConfigCell,
    pipeline: Pipeline,
    redactor: Redactor,
    scanner: FinalScanner,
}

fn fixture_in(locale: &str) -> Fixture {
    let clock = Arc::new(SimClock::new(
        WallTime::from_unix_nanos(1_793_923_200_000_000_000).unwrap(),
    ));
    Fixture {
        admission: Admission::new(AdmissionLimits::default(), Stop::running()),
        config: ConfigCell::new(ConfigSnapshot::new(ConfigVersion(1), LocaleTag::new(locale).unwrap())),
        pipeline: Pipeline::new(clock),
        redactor: Redactor::new(DetectorVersion::V1, SecretKey::from_bytes([7; 32])).unwrap(),
        scanner: FinalScanner::new(DetectorVersion::V1, [VAULT_KEY.as_bytes()]).unwrap(),
    }
}

fn fixture() -> Fixture {
    fixture_in("en")
}

fn receive<'r>(f: &Fixture, op_id: OperationId, request: &'r Request) -> Operation<'r, Received> {
    let permit = f.admission.admit(u64::try_from(request.body.len()).unwrap()).unwrap();
    let correlation = CorrelationId::from_parts(2, [2; 10]);
    f.pipeline.receive(permit, op_id, correlation, f.config.pin(), request)
}

fn through(f: &Fixture, op: Operation<'_, Received>) -> Result<Ready, Exit> {
    op.parse()?
        .detect(&f.redactor)?
        .hook()?
        .route(Route::declared("mock"))?
        .authorize()?
        .reserve()?
        .splice()?
        .scan(&f.scanner)?
        .ready()
}

fn run(f: &Fixture, request: &Request) -> Result<Ready, Exit> {
    through(f, receive(f, OperationId::from_parts(9, [9; 10]), request))
}

fn refused(stage: Stage, code: ErrorCode) -> Result<(), Exit> {
    Err(Exit::Refused { stage, code })
}

/// The kernel builds and passes with zero modules. A clean body reaches `Ready` as the client sent
/// it, in the same buffer.
#[test]
fn a_request_reaches_ready_with_zero_modules() {
    let f = fixture();
    let op_id = OperationId::from_parts(1, [1; 10]);
    let sent = request();
    let ready = through(&f, receive(&f, op_id, &sent));
    assert!(
        ready.is_ok(),
        "the kernel must pass with zero modules: {:?}",
        ready.err()
    );
    let ready = ready.unwrap();
    assert_eq!(ready.op_id(), op_id);
    assert_eq!(ready.route().upstream(), "mock");
    assert_eq!(ready.request().body, Bytes::from_static(BODY));
    assert_eq!(
        ready.request().body.as_ptr(),
        sent.body.as_ptr(),
        "the same buffer, not a copy"
    );
    assert_eq!(ready.request().method, Method::POST);
    assert_eq!(ready.request().path.as_str(), "/v1/messages");
    assert!(ready.is_json());
    assert!(ready.classes().is_empty());

    let stats = f.pipeline.stats();
    for stage in Stage::ALL {
        assert_eq!(stats.reached(stage), 1, "{stage}");
        assert_eq!(stats.refused(stage), 0, "{stage}");
    }

    // `Ready` holds the admission permit until it ends.
    assert_eq!(f.admission.in_flight().0, 1);
    drop(ready);
    assert_eq!(f.admission.in_flight(), (0, 0));
}

/// An Operation that ends before the door, wherever it ends, gives its admission back: the
/// permit lives in the Operation, not beside it.
#[test]
fn an_operation_dropped_at_any_stage_releases_its_permit() {
    let f = fixture();
    let sent = request();
    let op = |n: u64| receive(&f, OperationId::from_parts(n, [3; 10]), &sent);
    let free = |f: &Fixture| f.admission.in_flight() == (0, 0);

    drop(op(1));
    assert!(free(&f), "received");
    drop(op(2).parse().unwrap());
    assert!(free(&f), "parsed");
    drop(op(3).parse().unwrap().detect(&f.redactor).unwrap().hook().unwrap());
    assert!(free(&f), "hooked");
    let routed = op(4).parse().unwrap().detect(&f.redactor).unwrap().hook().unwrap();
    drop(
        routed
            .route(Route::declared("mock"))
            .unwrap()
            .authorize()
            .unwrap()
            .reserve()
            .unwrap(),
    );
    assert!(free(&f), "reserved");
    assert_eq!(f.pipeline.stats().reached(Stage::Received), 4);
    assert_eq!(f.pipeline.stats().reached(Stage::Ready), 0);
}

/// Stages are named in order, for counters and traces.
#[test]
fn stages_have_stable_names_in_order() {
    let names: Vec<&str> = Stage::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        names,
        [
            "received",
            "parsed",
            "detected",
            "hooked",
            "routed",
            "authorized",
            "reserved",
            "spliced",
            "scanned",
            "ready"
        ]
    );
    assert!(Stage::ALL.windows(2).all(|w| w.first() < w.get(1)));
}

/// Parse once, redact on the tape: a secret in a value and one in a key are replaced by their
/// placeholders, and nothing else in the body changes; the mask names the value's node and the
/// member whose key held one (A-6).
#[test]
fn a_secret_is_redacted_on_the_tape_and_masked_by_node() {
    let f = fixture();
    let token = github_token();
    let body = format!(r#"{{"content":"use {token} here","{token}":true,"n":1}}"#);
    let sent = request_with(body.as_bytes(), Some("application/json"));
    let detected = receive(&f, OperationId::from_parts(5, [5; 10]), &sent)
        .parse()
        .unwrap()
        .detect(&f.redactor)
        .unwrap();
    let tape = uaos_json::parse(body.as_bytes(), &uaos_json::Limits::DEFAULT).unwrap();
    let mut expected = Mask::new();
    for node in tape.nodes() {
        if node.content_span().is_some_and(|s| body[s.range()].contains(&token)) {
            expected.value(node.id());
        }
        if node.key_span().is_some_and(|s| body[s.range()].contains(&token)) {
            expected.key(node.id());
        }
    }
    assert_eq!(detected.mask(), &expected);
    assert_ne!(detected.mask(), &Mask::new());
    assert!(detected.classes().contains(&DataClass::GithubToken));

    let ready = detected
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
        .scan(&f.scanner)
        .unwrap()
        .ready()
        .unwrap();
    let placeholder = f.redactor.placeholder(DataClass::GithubToken, &token);
    assert_eq!(
        ready.request().body,
        body.replace(&token, &placeholder).into_bytes(),
        "only the secret changed"
    );
    assert!(ready.classes().contains(&DataClass::GithubToken));
}

/// The final scan reads the exact outbound bytes: a vault key in the body, the path or a header
/// that leaves blocks the request, and nothing reaches `Ready`.
#[test]
fn the_final_scan_blocks_a_vault_key_anywhere_it_would_leave() {
    let f = fixture();
    let in_body = request_with(format!(r#"{{"k":"{VAULT_KEY}"}}"#).as_bytes(), Some("application/json"));
    assert_eq!(
        run(&f, &in_body).map(drop),
        refused(Stage::Scanned, codes::REDACT_BLOCKED)
    );
    let mut in_path = request();
    in_path.path = PathAndQuery::try_from(format!("/v1/messages?key={VAULT_KEY}")).unwrap();
    assert_eq!(
        run(&f, &in_path).map(drop),
        refused(Stage::Scanned, codes::REDACT_BLOCKED)
    );
    let mut in_header = request();
    in_header
        .headers
        .insert("x-trace", HeaderValue::try_from(VAULT_KEY).unwrap());
    assert_eq!(
        run(&f, &in_header).map(drop),
        refused(Stage::Scanned, codes::REDACT_BLOCKED)
    );
    let text = request_with(format!("plain {VAULT_KEY}").as_bytes(), Some("text/plain"));
    assert_eq!(run(&f, &text).map(drop), refused(Stage::Scanned, codes::REDACT_BLOCKED));
    assert_eq!(f.pipeline.stats().refused(Stage::Scanned), 4);
    assert_eq!(f.pipeline.stats().reached(Stage::Ready), 0);
    assert_eq!(f.admission.in_flight(), (0, 0), "every permit given back");
}

/// The client's credentials, hop-by-hop headers and framing never leave (A-18), so they are not
/// what the scan reads; every other header leaves in order.
#[test]
fn only_the_headers_that_leave_are_scanned_and_kept() {
    let f = fixture();
    let mut sent = request();
    let h = &mut sent.headers;
    h.insert(
        "authorization",
        HeaderValue::try_from(format!("Bearer {VAULT_KEY}")).unwrap(),
    );
    h.insert("x-api-key", HeaderValue::try_from(VAULT_KEY).unwrap());
    h.insert("proxy-authorization", HeaderValue::from_static("Basic eA=="));
    h.insert("cookie", HeaderValue::from_static("session=1"));
    h.insert("connection", HeaderValue::from_static("close, X-Hop"));
    h.insert("x-hop", HeaderValue::from_static("1"));
    h.insert("te", HeaderValue::from_static("trailers"));
    h.insert("upgrade", HeaderValue::from_static("h2c"));
    h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
    h.insert("content-length", HeaderValue::from_static("999"));
    h.insert("host", HeaderValue::from_static("client.example"));
    h.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
    h.append("x-repeat", HeaderValue::from_static("a"));
    h.append("x-repeat", HeaderValue::from_static("b"));
    let ready = run(&f, &sent).unwrap();
    let left: Vec<(String, String)> = ready
        .request()
        .headers
        .iter()
        .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap().to_owned()))
        .collect();
    assert_eq!(
        left,
        [
            ("content-type", "application/json"),
            ("anthropic-version", "2023-06-01"),
            ("x-repeat", "a"),
            ("x-repeat", "b"),
        ]
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
    );
    assert!(
        !ready
            .request()
            .headers
            .contains_key(HeaderName::from_static("authorization"))
    );
}

/// What a body is (A-17): a limit refuses whatever the content type; a body that does not parse
/// is refused when it says it is JSON, and is text or bytes when it does not.
#[test]
fn a_body_is_json_text_or_bytes_and_limits_always_refuse() {
    let f = fixture();
    let broken = request_with(br#"{"a": 1,}"#, Some("application/json; charset=utf-8"));
    assert_eq!(
        run(&f, &broken).map(drop),
        refused(Stage::Parsed, codes::INGRESS_MALFORMED)
    );
    let vendor = request_with(br#"{"a": 1,}"#, Some("Application/Vnd.Example+JSON"));
    assert_eq!(
        run(&f, &vendor).map(drop),
        refused(Stage::Parsed, codes::INGRESS_MALFORMED)
    );
    let deep = "[".repeat(200) + &"]".repeat(200);
    for ct in [Some("application/json"), Some("text/plain"), None] {
        assert_eq!(
            run(&f, &request_with(deep.as_bytes(), ct)).map(drop),
            refused(Stage::Parsed, codes::INGRESS_TOO_LARGE),
            "{ct:?}"
        );
    }

    let token = github_token();
    let text = request_with(format!("not json: {token}").as_bytes(), Some("text/plain"));
    let ready = run(&f, &text).unwrap();
    assert!(!ready.is_json());
    let placeholder = f.redactor.placeholder(DataClass::GithubToken, &token);
    assert_eq!(ready.request().body, format!("not json: {placeholder}").into_bytes());

    let binary = request_with(b"\xff\xfe\x00 binary", Some("application/octet-stream"));
    let ready = run(&f, &binary).unwrap();
    assert!(!ready.is_json());
    assert_eq!(ready.request().body, Bytes::from_static(b"\xff\xfe\x00 binary"));

    let empty = request_with(b"", None);
    assert_eq!(run(&f, &empty).unwrap().request().body.len(), 0);
}

/// A body of bytes cannot be redacted, so a secret in it is blocked by the final scan rather
/// than sent.
#[test]
fn a_secret_in_bytes_is_blocked_not_sent() {
    let f = fixture();
    let mut body = b"\xff\xfe".to_vec();
    body.extend_from_slice(github_token().as_bytes());
    let binary = request_with(&body, Some("application/octet-stream"));
    assert_eq!(
        run(&f, &binary).map(drop),
        refused(Stage::Scanned, codes::REDACT_BLOCKED)
    );
}

/// Every transition is timed for its stage, passing or refusing.
#[test]
fn every_stage_is_timed() {
    let f = fixture();
    let _ready = run(&f, &request()).unwrap();
    let broken = request_with(b"{", Some("application/json"));
    let _refused = run(&f, &broken);
    let stats = f.pipeline.stats();
    for stage in Stage::ALL {
        let d = stats.durations(stage);
        let expected = match stage {
            Stage::Received | Stage::Ready => 0,
            Stage::Parsed => 2,
            _ => 1,
        };
        assert_eq!(d.count, expected, "{stage}");
        assert_eq!(d.buckets.iter().sum::<u64>(), expected, "{stage}");
        assert_eq!(d.buckets.len(), DURATION_BUCKETS);
    }
    assert_eq!(stats.refused(Stage::Parsed), 1);
}

/// As JSON, as text and next to a redacted secret, every sample reaches `Ready` with 0 byte
/// differences, and the Operation keeps the locale pinned for it.
#[test]
fn every_locale_crosses_the_pipeline_byte_for_byte() {
    let token = github_token();
    for (locale, sample) in CORPUS {
        let f = fixture_in(locale);
        let json = serde_json::to_string(&serde_json::json!({ "content": sample })).unwrap();
        let ready = run(&f, &request_with(json.as_bytes(), Some("application/json"))).unwrap();
        assert_eq!(ready.request().body, json.as_bytes(), "{locale}: as JSON");
        assert_eq!(ready.locale().as_str(), locale);

        let text = request_with(sample.as_bytes(), Some("text/plain; charset=utf-8"));
        assert_eq!(
            run(&f, &text).unwrap().request().body,
            sample.as_bytes(),
            "{locale}: as text"
        );

        let mixed =
            serde_json::to_string(&serde_json::json!({ "content": format!("{sample} {token} {sample}") })).unwrap();
        let ready = run(&f, &request_with(mixed.as_bytes(), Some("application/json"))).unwrap();
        let placeholder = f.redactor.placeholder(DataClass::GithubToken, &token);
        assert_eq!(
            ready.request().body,
            mixed.replace(&token, &placeholder).into_bytes(),
            "{locale}: next to a redacted secret"
        );
    }
}
