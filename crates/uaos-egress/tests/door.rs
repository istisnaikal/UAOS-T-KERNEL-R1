// SPDX-License-Identifier: Apache-2.0

//! The egress door against a loopback TLS mock provider.
//!
//! The mock presents a certificate from a throwaway test authority for `mock.provider.test`;
//! the door trusts only that authority and dials the pinned loopback address, which the
//! upstream declares private. Every test reads what the mock actually received.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "test harness: fixtures abort on failure; the mock server needs real sockets and tasks, and the door an executor"
)]

use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use uaos_contracts::id::{OperationId, TypedId};
use uaos_contracts::time::WallTime;
use uaos_egress::addr::Blocked;
use uaos_egress::resolve::Resolution;
use uaos_egress::{
    CREDENTIAL_HEADERS, Credential, Door, DoorLimits, EgressError, EgressRequest, HostName, MAX_ADDRESSES_TRIED,
    Resolve, Scheme, Trust, Upstream, UpstreamError, UpstreamId,
};
use uaos_platform::sim::SimClock;

const MOCK_HOST: &str = "mock.provider.test";

#[derive(Debug, Clone)]
struct Seen {
    path: String,
    headers: HeaderMap,
    body: Bytes,
}

struct Mock {
    port: u16,
    authority: CertificateDer<'static>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

/// A TLS server for `mock.provider.test` on 127.0.0.1 that records requests and answers
/// with `status` and, for redirects, a `location`.
async fn mock(status: StatusCode) -> Mock {
    let issued = rcgen::generate_simple_self_signed(vec![MOCK_HOST.to_owned()]).unwrap();
    let cert = issued.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der()));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let (acceptor, log) = (acceptor.clone(), Arc::clone(&log));
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let service = service_fn(move |req: Request<Incoming>| {
                    let log = Arc::clone(&log);
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body
                            .collect()
                            .await
                            .map(http_body_util::Collected::to_bytes)
                            .unwrap_or_default();
                        log.lock().unwrap().push(Seen {
                            path: parts.uri.path().to_owned(),
                            headers: parts.headers,
                            body,
                        });
                        let mut response = Response::builder().status(status);
                        if status.is_redirection() {
                            response = response.header("location", "https://elsewhere.example/v1/messages");
                        }
                        Ok::<_, std::convert::Infallible>(
                            response
                                .header("connection", "keep-alive")
                                .header("x-request-id", "req_mock")
                                .body(Full::new(Bytes::from_static(b"event: ping\ndata: {}\n\n")))
                                .unwrap(),
                        )
                    }
                });
                let _done = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    Mock {
        port,
        authority: cert,
        seen,
    }
}

/// A resolver answering from a fixed table.
#[derive(Debug, Default)]
struct Table(BTreeMap<String, Vec<IpAddr>>);

impl Resolve for Table {
    fn resolve<'a>(&'a self, host: &'a HostName, _port: u16) -> Resolution<'a> {
        let found = self.0.get(host.as_str()).cloned().unwrap_or_default();
        Box::pin(async move { Ok(found) })
    }
}

fn mock_upstream(port: u16, authority: CertificateDer<'static>) -> Upstream {
    Upstream {
        id: UpstreamId::new("mock"),
        host: HostName::parse(MOCK_HOST).unwrap(),
        port,
        scheme: Scheme::Https,
        pinned: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        allow_private: true,
        trust: Trust::Roots(vec![authority]),
    }
}

fn clock() -> Arc<SimClock> {
    Arc::new(SimClock::new(
        WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
    ))
}

fn door(upstreams: Vec<Upstream>, resolver: Table, limits: DoorLimits) -> Door {
    Door::new(upstreams, Arc::new(resolver), clock(), TokioExecutor::new(), limits).unwrap()
}

fn op(n: u64) -> OperationId {
    OperationId::from_parts(n, [n.to_le_bytes()[0]; 10])
}

fn request(op_id: OperationId, upstream: &str) -> EgressRequest {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
    headers.insert("connection", HeaderValue::from_static("x-hop"));
    headers.insert("x-hop", HeaderValue::from_static("per-connection"));
    headers.insert("host", HeaderValue::from_static("evil.example"));
    headers.insert("te", HeaderValue::from_static("trailers"));
    EgressRequest {
        op_id,
        upstream: UpstreamId::new(upstream),
        method: Method::POST,
        path: "/v1/messages?beta=true".parse().unwrap(),
        headers,
        body: Bytes::from_static(br#"{"model":"m","messages":[]}"#),
    }
}

const CREDENTIAL_VALUE: &str = "provider-credential-for-tests";

fn credential() -> Credential {
    Credential::new(
        HeaderName::from_static("x-api-key"),
        HeaderValue::from_static(CREDENTIAL_VALUE),
    )
}

/// Trust in an authority nothing presents: for upstreams that are never reached.
fn throwaway_root() -> Trust {
    Trust::Roots(vec![
        rcgen::generate_simple_self_signed(vec![MOCK_HOST.to_owned()])
            .unwrap()
            .cert
            .der()
            .clone(),
    ])
}

/// A port nothing listens on.
fn closed_port() -> u16 {
    let l = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    l.local_addr().unwrap().port()
}

/// A plain HTTP server on 127.0.0.1 (a local model server) that records requests.
async fn plain_mock() -> (u16, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let log = Arc::clone(&log);
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body
                            .collect()
                            .await
                            .map(http_body_util::Collected::to_bytes)
                            .unwrap_or_default();
                        log.lock().unwrap().push(Seen {
                            path: parts.uri.path().to_owned(),
                            headers: parts.headers,
                            body,
                        });
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                    }
                });
                let _done = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service)
                    .await;
            });
        }
    });
    (port, seen)
}

#[tokio::test]
async fn a_request_reaches_the_declared_upstream_with_only_its_credential_added() {
    let mock = mock(StatusCode::OK).await;
    let door = door(
        vec![mock_upstream(mock.port, mock.authority.clone())],
        Table::default(),
        DoorLimits::default(),
    );
    let response = door
        .send(op(1), request(op(1), "mock"), Some(credential()))
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode::OK);
    assert!(
        response.headers.get("connection").is_none(),
        "hop-by-hop response headers are removed"
    );
    assert_eq!(response.headers.get("x-request-id").unwrap(), "req_mock");
    let body = response.body.collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"event: ping\ndata: {}\n\n");

    let seen = mock.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let got = &seen[0];
    assert_eq!(got.path, "/v1/messages");
    assert_eq!(
        &got.body[..],
        br#"{"model":"m","messages":[]}"#,
        "the body is sent byte for byte"
    );
    assert_eq!(got.headers.get("x-api-key").unwrap(), CREDENTIAL_VALUE);
    assert_eq!(got.headers.get("anthropic-version").unwrap(), "2023-06-01");
    assert_eq!(
        got.headers.get("host").unwrap(),
        format!("{MOCK_HOST}:{}", mock.port).as_str()
    );
    for gone in ["x-hop", "te"] {
        assert!(
            got.headers.get(gone).is_none(),
            "hop-by-hop header {gone} reached the provider"
        );
    }
    assert!(
        got.headers.keys().all(|k| !k.as_str().contains("uaos")),
        "the door added a UAOS header"
    );
    let counters = door.counters();
    assert_eq!((counters.resolves, counters.connects, counters.sent), (0, 1, 1));
}

#[tokio::test]
async fn one_operation_sends_once_and_only_its_own_request() {
    let mock = mock(StatusCode::OK).await;
    let door = door(
        vec![mock_upstream(mock.port, mock.authority.clone())],
        Table::default(),
        DoorLimits::default(),
    );
    door.send(op(1), request(op(1), "mock"), None).await.unwrap();
    assert_eq!(
        door.send(op(1), request(op(1), "mock"), None).await.unwrap_err(),
        EgressError::AlreadySent
    );
    assert_eq!(
        door.send(op(2), request(op(3), "mock"), None).await.unwrap_err(),
        EgressError::Refused("the request belongs to another Operation")
    );
    let mut carrying = request(op(4), "mock");
    carrying
        .headers
        .insert("x-api-key", HeaderValue::from_static("agent-supplied"));
    assert_eq!(
        door.send(op(4), carrying, Some(credential())).await.unwrap_err(),
        EgressError::Refused("the request carries a credential-bearing header")
    );
    assert_eq!(
        door.send(op(5), request(op(5), "nowhere"), None).await.unwrap_err(),
        EgressError::Refused("unknown upstream")
    );
    assert_eq!(mock.seen.lock().unwrap().len(), 1, "refusals happen before any contact");
    assert_eq!(door.counters().refused, 4);
}

#[tokio::test]
async fn a_redirect_is_returned_never_followed() {
    let mock = mock(StatusCode::FOUND).await;
    let door = door(
        vec![mock_upstream(mock.port, mock.authority.clone())],
        Table::default(),
        DoorLimits::default(),
    );
    let response = door.send(op(1), request(op(1), "mock"), None).await.unwrap();
    assert_eq!(response.status, StatusCode::FOUND);
    assert_eq!(
        response.headers.get("location").unwrap(),
        "https://elsewhere.example/v1/messages"
    );
    assert_eq!(mock.seen.lock().unwrap().len(), 1, "the door followed a redirect");
    assert_eq!(door.counters().connects, 1);
}

#[tokio::test]
async fn private_answers_are_refused_unless_the_upstream_is_declared_private() {
    let mut table = Table::default();
    table
        .0
        .insert("localhost".into(), vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    table.0.insert(
        "rebind.example".into(),
        vec!["10.0.0.7".parse().unwrap(), "169.254.169.254".parse().unwrap()],
    );
    let named = |id: &str, host: &str| Upstream {
        id: UpstreamId::new(id),
        host: HostName::parse(host).unwrap(),
        port: 443,
        scheme: Scheme::Https,
        pinned: Vec::new(),
        allow_private: false,
        trust: throwaway_root(),
    };
    let door = door(
        vec![named("loop", "localhost"), named("rebind", "rebind.example")],
        table,
        DoorLimits::default(),
    );
    assert_eq!(
        door.send(op(1), request(op(1), "loop"), None).await.unwrap_err(),
        EgressError::Blocked(Blocked::Loopback),
        "the door dialled a private range"
    );
    assert_eq!(
        door.send(op(2), request(op(2), "rebind"), None).await.unwrap_err(),
        EgressError::Blocked(Blocked::Private)
    );
    let c = door.counters();
    assert_eq!(
        (c.resolves, c.blocked, c.connects),
        (2, 3, 0),
        "blocked answers are never dialled"
    );
}

#[test]
fn building_the_door_contacts_nothing() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    let upstream = Upstream::https("anthropic", HostName::parse("api.anthropic.com").unwrap());
    let door = door(vec![upstream], Table::default(), DoorLimits::default());
    let c = door.counters();
    assert_eq!((c.resolves, c.connects, c.blocked, c.sent), (0, 0, 0, 0));
}

#[test]
fn plain_http_is_declared_only_toward_pinned_local_addresses() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    let declare = |pinned: Vec<IpAddr>| {
        let up = Upstream {
            id: UpstreamId::new("local"),
            host: HostName::parse("ollama.lan").unwrap(),
            port: 11434,
            scheme: Scheme::Http,
            pinned,
            allow_private: true,
            trust: Trust::System,
        };
        Door::new(
            vec![up],
            Arc::new(Table::default()),
            clock(),
            TokioExecutor::new(),
            DoorLimits::default(),
        )
        .map(|_| ())
    };
    // Plain HTTP is never resolved, and never dialled at anything but pinned loopback, private or
    // unique-local addresses.
    assert_eq!(
        declare(Vec::new()),
        Err(EgressError::Upstream(UpstreamError::PlaintextNeedsPinned)),
        "a plain-HTTP upstream would be resolved"
    );
    for refused in ["8.8.8.8", "2606:4700::1111", "169.254.169.254", "3fff::1", "224.0.0.1"] {
        assert_eq!(
            declare(vec![refused.parse().unwrap()]),
            Err(EgressError::Upstream(UpstreamError::PlaintextToPublic)),
            "plain HTTP was allowed toward {refused}"
        );
    }
    for allowed in ["127.0.0.1", "10.0.0.5", "192.168.1.20", "fd00::5"] {
        assert_eq!(declare(vec![allowed.parse().unwrap()]), Ok(()), "{allowed}");
    }
}

#[test]
fn plaintext_and_duplicate_upstreams_are_refused_at_declaration() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    let mut plain = Upstream::https("p", HostName::parse("api.example.com").unwrap());
    plain.scheme = Scheme::Http;
    let refused = Door::new(
        vec![plain],
        Arc::new(Table::default()),
        clock(),
        TokioExecutor::new(),
        DoorLimits::default(),
    );
    assert_eq!(
        refused.unwrap_err(),
        EgressError::Upstream(UpstreamError::PlaintextToPublic)
    );
    let twice = Door::new(
        vec![
            Upstream::https("a", HostName::parse("api.example.com").unwrap()),
            Upstream::https("a", HostName::parse("other.example.com").unwrap()),
        ],
        Arc::new(Table::default()),
        clock(),
        TokioExecutor::new(),
        DoorLimits::default(),
    );
    assert_eq!(twice.unwrap_err(), EgressError::Upstream(UpstreamError::Duplicate));
}

#[tokio::test]
async fn the_circuit_opens_after_repeated_failures() {
    let closed = closed_port();
    let issued = rcgen::generate_simple_self_signed(vec![MOCK_HOST.to_owned()]).unwrap();
    let limits = DoorLimits {
        connect_timeout: Duration::from_secs(2),
        breaker_threshold: 2,
        ..DoorLimits::default()
    };
    let door = door(
        vec![mock_upstream(closed, issued.cert.der().clone())],
        Table::default(),
        limits,
    );
    for n in 1..=2 {
        assert!(matches!(
            door.send(op(n), request(op(n), "mock"), None).await.unwrap_err(),
            EgressError::Unreachable(_)
        ));
    }
    let connects = door.counters().connects;
    assert!(matches!(
        door.send(op(3), request(op(3), "mock"), None).await.unwrap_err(),
        EgressError::CircuitOpen { .. }
    ));
    assert_eq!(door.counters().connects, connects, "an open circuit makes no contact");
}

#[tokio::test]
async fn a_certificate_from_another_authority_is_refused() {
    let mock = mock(StatusCode::OK).await;
    let stranger = rcgen::generate_simple_self_signed(vec![MOCK_HOST.to_owned()]).unwrap();
    let door = door(
        vec![mock_upstream(mock.port, stranger.cert.der().clone())],
        Table::default(),
        DoorLimits::default(),
    );
    assert_eq!(
        door.send(op(1), request(op(1), "mock"), Some(credential()))
            .await
            .unwrap_err(),
        EgressError::Unreachable("TLS handshake or certificate check failed")
    );
    assert!(
        mock.seen.lock().unwrap().is_empty(),
        "nothing, credential included, reached an unverified peer"
    );
}

/// DER length octets.
fn der_len(n: usize) -> Vec<u8> {
    if n < 128 {
        vec![u8::try_from(n).unwrap()]
    } else if n < 256 {
        vec![0x81, u8::try_from(n).unwrap()]
    } else {
        vec![0x82, u8::try_from(n >> 8).unwrap(), u8::try_from(n & 0xff).unwrap()]
    }
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(der_len(body.len()));
    v.extend_from_slice(body);
    v
}

/// One `AccessDescription`: method `id-ad-<method_last>`, location a URI.
fn access(method_last: u8, url: &str) -> Vec<u8> {
    let mut body = vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, method_last];
    body.extend(tlv(0x86, url.as_bytes()));
    tlv(0x30, &body)
}

/// A server's certificate cannot make UAOS fetch anything. The leaf, from an authority the system
/// does not trust, names issuer, OCSP and CRL URLs on a listener standing in for an internal
/// service; with the default trust the handshake fails and the listener hears nothing.
#[tokio::test]
async fn the_system_trust_fetches_nothing_a_certificate_names() {
    let internal = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let internal_port = internal.local_addr().unwrap().port();
    let hits: Arc<Mutex<Vec<String>>> = Arc::default();
    let heard = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, peer)) = internal.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 4096];
            let n = tcp.read(&mut buf).await.unwrap_or(0);
            heard
                .lock()
                .unwrap()
                .push(format!("{peer}: {}", String::from_utf8_lossy(&buf[..n])));
            let _closed = tcp
                .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
                .await;
        }
    });

    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(rcgen::DnType::CommonName, "UAOS test authority nobody trusts");
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let mut leaf = rcgen::CertificateParams::new(vec![MOCK_HOST.to_owned()]).unwrap();
    leaf.crl_distribution_points = vec![rcgen::CrlDistributionPoint {
        uris: vec![format!("http://127.0.0.1:{internal_port}/crl")],
    }];
    let aia = tlv(
        0x30,
        &[
            access(
                0x02,
                &format!("http://127.0.0.1:{internal_port}/latest/meta-data/ca-issuers"),
            ),
            access(0x01, &format!("http://127.0.0.1:{internal_port}/ocsp")),
        ]
        .concat(),
    );
    leaf.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
        &[1, 3, 6, 1, 5, 5, 7, 1, 1],
        aia,
    )];
    let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let _handshake = acceptor.accept(tcp).await;
        }
    });

    let mut up = Upstream::https("provider", HostName::parse(MOCK_HOST).unwrap());
    up.port = port;
    up.pinned = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
    up.allow_private = true;
    let door = door(vec![up], Table::default(), DoorLimits::default());
    assert_eq!(
        door.send(op(1), request(op(1), "provider"), Some(credential()))
            .await
            .unwrap_err(),
        EgressError::Unreachable("TLS handshake or certificate check failed")
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        hits.lock().unwrap().is_empty(),
        "the handshake made the machine fetch a URL the certificate named: {:?}",
        hits.lock().unwrap()
    );
    assert_eq!(door.counters().connects, 1);
}

/// A private upstream reaches this machine and the local network, never link-local (the metadata
/// service) or another special-purpose range, whatever its name resolves to.
#[tokio::test]
async fn a_private_upstream_never_reaches_link_local_or_special_ranges() {
    let mut table = Table::default();
    table.0.insert(
        "gpu-box.lan".into(),
        vec![
            "169.254.169.254".parse().unwrap(),
            "3fff::1".parse().unwrap(),
            "fe80::1".parse().unwrap(),
        ],
    );
    let up = Upstream {
        id: UpstreamId::new("gpu"),
        host: HostName::parse("gpu-box.lan").unwrap(),
        port: 8443,
        scheme: Scheme::Https,
        pinned: Vec::new(),
        allow_private: true,
        trust: throwaway_root(),
    };
    // Short, so a door that wrongly dials these addresses fails fast instead of waiting.
    let limits = DoorLimits {
        connect_timeout: Duration::from_millis(300),
        ..DoorLimits::default()
    };
    let door = door(vec![up], table, limits);
    assert_eq!(
        door.send(op(1), request(op(1), "gpu"), None).await.unwrap_err(),
        EgressError::Blocked(Blocked::LinkLocal),
        "a private upstream dialled the metadata range"
    );
    let c = door.counters();
    assert_eq!((c.blocked, c.connects), (3, 0));
}

/// Plain HTTP to a pinned loopback server works and resolves nothing.
#[tokio::test]
async fn plain_http_reaches_a_pinned_local_server_without_resolving() {
    let (port, seen) = plain_mock().await;
    let up = Upstream {
        id: UpstreamId::new("local"),
        host: HostName::parse("ollama.lan").unwrap(),
        port,
        scheme: Scheme::Http,
        pinned: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        allow_private: true,
        trust: Trust::System,
    };
    let door = door(vec![up], Table::default(), DoorLimits::default());
    let response = door.send(op(1), request(op(1), "local"), None).await.unwrap();
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert_eq!(door.counters().resolves, 0, "a plain-HTTP upstream was resolved");
}

/// The credential's value never appears in its `Debug` output.
#[test]
fn the_credential_is_never_printed() {
    let shown = format!("{:?}", credential());
    assert!(
        !shown.contains(CREDENTIAL_VALUE),
        "Debug printed the credential: {shown}"
    );
    assert!(shown.contains("x-api-key"));
}

/// After the cooldown exactly one probe is let through; the rest are refused and counted.
#[tokio::test]
async fn after_the_cooldown_exactly_one_probe_goes_through() {
    let closed = closed_port();
    let issued = rcgen::generate_simple_self_signed(vec![MOCK_HOST.to_owned()]).unwrap();
    let clock = clock();
    let limits = DoorLimits {
        connect_timeout: Duration::from_secs(2),
        breaker_threshold: 1,
        breaker_cooldown: Duration::from_secs(30),
        ..DoorLimits::default()
    };
    let shared: Arc<dyn uaos_platform::Clock> = clock.clone();
    let door = Door::new(
        vec![mock_upstream(closed, issued.cert.der().clone())],
        Arc::new(Table::default()),
        shared,
        TokioExecutor::new(),
        limits,
    )
    .unwrap();
    assert!(matches!(
        door.send(op(1), request(op(1), "mock"), None).await,
        Err(EgressError::Unreachable(_))
    ));
    assert!(matches!(
        door.send(op(2), request(op(2), "mock"), None).await,
        Err(EgressError::CircuitOpen { .. })
    ));
    clock.advance(31_000_000_000);
    let before = door.counters();
    let (a, b, c, d) = tokio::join!(
        door.send(op(3), request(op(3), "mock"), None),
        door.send(op(4), request(op(4), "mock"), None),
        door.send(op(5), request(op(5), "mock"), None),
        door.send(op(6), request(op(6), "mock"), None),
    );
    let outcomes = [a, b, c, d];
    let after = door.counters();
    assert_eq!(
        after.connects - before.connects,
        1,
        "more than one probe after the cooldown"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| matches!(r, Err(EgressError::CircuitOpen { .. })))
            .count(),
        3
    );
    assert_eq!(
        after.refused - before.refused,
        3,
        "refusals by an open circuit are counted"
    );
    // The probe failed: the circuit is open again for a full cooldown.
    assert!(matches!(
        door.send(op(7), request(op(7), "mock"), None).await,
        Err(EgressError::CircuitOpen { .. })
    ));
}

/// The path cannot change the destination, and a malformed one is refused before contact without
/// consuming the Operation.
#[tokio::test]
async fn a_path_without_a_leading_slash_is_refused_before_contact() {
    let mock = mock(StatusCode::OK).await;
    let door = door(
        vec![mock_upstream(mock.port, mock.authority.clone())],
        Table::default(),
        DoorLimits::default(),
    );
    let mut star = request(op(1), "mock");
    star.path = "*".parse().unwrap();
    assert_eq!(
        door.send(op(1), star, None).await.unwrap_err(),
        EgressError::Refused("request path must start with /")
    );
    assert_eq!(door.counters().connects, 0);
    // The Operation was not consumed by the refusal.
    door.send(op(1), request(op(1), "mock"), None).await.unwrap();
    assert_eq!(mock.seen.lock().unwrap()[0].path, "/v1/messages");
}

/// TRACE would echo the request, the credential included, back to the caller, and CONNECT would
/// open a tunnel; they and extension methods are refused before contact, without consuming the
/// Operation.
#[tokio::test]
async fn methods_the_door_does_not_send_are_refused_before_contact() {
    let mock = mock(StatusCode::OK).await;
    let door = door(
        vec![mock_upstream(mock.port, mock.authority.clone())],
        Table::default(),
        DoorLimits::default(),
    );
    for method in [Method::TRACE, Method::CONNECT, Method::from_bytes(b"PROPFIND").unwrap()] {
        let mut sent = request(op(1), "mock");
        sent.method = method.clone();
        let refused = door.send(op(1), sent, Some(credential())).await;
        assert!(
            matches!(
                refused,
                Err(EgressError::Refused("request method is not one the door sends"))
            ),
            "{method} was not refused before contact"
        );
    }
    assert_eq!(door.counters().connects, 0);
    door.send(op(1), request(op(1), "mock"), Some(credential()))
        .await
        .unwrap();
    assert_eq!(mock.seen.lock().unwrap().len(), 1);
}

/// A plain loopback upstream, pinned and declared private, that answers every request with
/// `raw`, whatever it asked.
async fn raw_upstream(raw: &'static [u8]) -> Door {
    raw_upstream_with(raw, DoorLimits::default()).await
}

/// [`raw_upstream`] with the door's limits given.
async fn raw_upstream_with(raw: &'static [u8], limits: DoorLimits) -> Door {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = vec![0u8; 8192];
                let _read = tcp.read(&mut request).await;
                let _written = tcp.write_all(raw).await;
                let mut rest = vec![0u8; 64];
                let _closed = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut rest)).await;
            });
        }
    });
    let up = Upstream {
        id: UpstreamId::new("local"),
        host: HostName::parse("ollama.lan").unwrap(),
        port,
        scheme: Scheme::Http,
        pinned: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        allow_private: true,
        trust: Trust::System,
    };
    door(vec![up], Table::default(), limits)
}

/// An executor like a busy supervisor's: it runs each connection task a little later, so a
/// connection can fail before hyper takes the request.
#[derive(Debug, Clone)]
struct LateExecutor(Duration);

impl hyper::rt::Executor<Pin<Box<dyn Future<Output = ()> + Send>>> for LateExecutor {
    fn execute(&self, fut: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let late = self.0;
        tokio::spawn(async move {
            tokio::time::sleep(late).await;
            fut.await;
        });
    }
}

/// A plain loopback upstream that, on accept, writes `greet` before reading anything (and then
/// closes at once if `close`), and counts every byte it receives afterwards.
async fn early_upstream(greet: &'static [u8], close: bool) -> (Door, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&received);
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let count = Arc::clone(&count);
            tokio::spawn(async move {
                let _written = tcp.write_all(greet).await;
                if close {
                    return;
                }
                let mut buf = vec![0u8; 8192];
                while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(1), tcp.read(&mut buf)).await {
                    if n == 0 {
                        break;
                    }
                    count.fetch_add(n, Ordering::SeqCst);
                }
            });
        }
    });
    let up = Upstream {
        id: UpstreamId::new("local"),
        host: HostName::parse("ollama.lan").unwrap(),
        port,
        scheme: Scheme::Http,
        pinned: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        allow_private: true,
        trust: Trust::System,
    };
    let door = Door::new(
        vec![up],
        Arc::new(Table::default()),
        clock(),
        LateExecutor(Duration::from_millis(200)),
        DoorLimits::default(),
    )
    .unwrap();
    (door, received)
}

/// A connection that fails while hyper sets it up, before it takes the request (the upstream speaks
/// first, or accepts and closes at once), sent nothing: `Unreachable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_lost_before_the_request_left_is_unreachable() {
    for (greet, close) in [
        (&b"HTTP/1.1 503 Busy\r\ncontent-length: 0\r\n\r\n"[..], false),
        (&b""[..], true),
    ] {
        let (door, received) = early_upstream(greet, close).await;
        let e = door.send(op(1), request(op(1), "local"), None).await.unwrap_err();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(received.load(Ordering::SeqCst), 0, "the request reached the upstream");
        assert!(
            matches!(e, EgressError::Unreachable(_)),
            "nothing was sent, but the door reported {e:?}"
        );
    }
}

/// A plain loopback upstream that never speaks first and counts every byte it receives.
async fn counting_upstream() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&received);
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let count = Arc::clone(&count);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf)).await {
                    if n == 0 {
                        break;
                    }
                    count.fetch_add(n, Ordering::SeqCst);
                }
            });
        }
    });
    (port, received)
}

fn local_upstream(port: u16) -> Upstream {
    Upstream {
        id: UpstreamId::new("local"),
        host: HostName::parse("ollama.lan").unwrap(),
        port,
        scheme: Scheme::Http,
        pinned: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        allow_private: true,
        trust: Trust::System,
    }
}

/// The response timeout runs out while hyper-util still waits for the connection task (a busy
/// executor): the request never left, so it is `Timeout`, not `Interrupted`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timeout_before_the_request_was_handed_over_is_not_interrupted() {
    let (port, received) = counting_upstream().await;
    let limits = DoorLimits {
        connect_timeout: Duration::from_millis(100),
        response_timeout: Duration::from_millis(1000),
        ..DoorLimits::default()
    };
    let door = Door::new(
        vec![local_upstream(port)],
        Arc::new(Table::default()),
        clock(),
        LateExecutor(Duration::from_millis(1500)),
        limits,
    )
    .unwrap();
    let e = door.send(op(1), request(op(1), "local"), None).await.unwrap_err();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(received.load(Ordering::SeqCst), 0, "the request reached the upstream");
    assert_eq!(
        e,
        EgressError::Timeout,
        "a request that never left was reported as possibly received"
    );
}

/// Polls each connection task once at once, then waits before polling it again: hyper takes the
/// request into its queue while the dispatcher sleeps, and the upstream's greeting arrives first.
#[derive(Debug, Clone)]
struct SlowSecondPoll(Duration);

impl hyper::rt::Executor<Pin<Box<dyn Future<Output = ()> + Send>>> for SlowSecondPoll {
    fn execute(&self, fut: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let late = self.0;
        tokio::spawn(async move {
            let mut fut = fut;
            let done = std::future::poll_fn(|cx| std::task::Poll::Ready(fut.as_mut().poll(cx).is_ready())).await;
            if done {
                return;
            }
            tokio::time::sleep(late).await;
            fut.await;
        });
    }
}

/// A request queued on a connection but never written is handed back by hyper as canceled, with
/// connection info attached: nothing left, `Unreachable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queued_request_handed_back_is_unreachable() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&received);
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let count = Arc::clone(&count);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(60)).await;
                let _written = tcp.write_all(b"HTTP/1.1 503 Busy\r\ncontent-length: 0\r\n\r\n").await;
                let mut buf = vec![0u8; 8192];
                while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(1), tcp.read(&mut buf)).await {
                    if n == 0 {
                        break;
                    }
                    count.fetch_add(n, Ordering::SeqCst);
                }
            });
        }
    });
    let door = Door::new(
        vec![local_upstream(port)],
        Arc::new(Table::default()),
        clock(),
        SlowSecondPoll(Duration::from_millis(300)),
        DoorLimits::default(),
    )
    .unwrap();
    let e = door.send(op(1), request(op(1), "local"), None).await.unwrap_err();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(received.load(Ordering::SeqCst), 0, "the request reached the upstream");
    assert!(
        matches!(e, EgressError::Unreachable(_)),
        "a request handed back unsent was reported as {e:?}"
    );
}

/// No answer within the response timeout after the request was sent is `Interrupted`: the provider
/// may have received it.
#[tokio::test]
async fn no_answer_within_the_response_timeout_is_interrupted() {
    let limits = DoorLimits {
        connect_timeout: Duration::from_millis(50),
        response_timeout: Duration::from_millis(500),
        ..DoorLimits::default()
    };
    // Reads the request and answers nothing for two seconds.
    let door = raw_upstream_with(b"", limits).await;
    assert_eq!(
        door.send(op(1), request(op(1), "local"), None).await.unwrap_err(),
        EgressError::Interrupted("no answer within the response timeout"),
        "an unanswered request was reported as never sent"
    );
}

/// A response timeout that does not exceed the connect phase is refused when the door is built: it
/// would report a request that never left as possibly received.
#[test]
fn a_response_timeout_inside_the_connect_phase_is_refused() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    let build = |response_timeout: Duration| {
        let limits = DoorLimits {
            connect_timeout: Duration::from_secs(10),
            response_timeout,
            ..DoorLimits::default()
        };
        Door::new(
            Vec::new(),
            Arc::new(Table::default()),
            clock(),
            TokioExecutor::new(),
            limits,
        )
        .map(|_| ())
    };
    assert!(matches!(build(Duration::from_secs(60)), Err(EgressError::Limits(_))));
    assert!(build(Duration::from_secs(61)).is_ok());
    // An idle timeout hyper-util's timer cannot add is refused too.
    let idle = |idle_timeout: Duration| {
        let limits = DoorLimits {
            idle_timeout,
            ..DoorLimits::default()
        };
        Door::new(
            Vec::new(),
            Arc::new(Table::default()),
            clock(),
            TokioExecutor::new(),
            limits,
        )
        .map(|_| ())
    };
    assert!(matches!(idle(Duration::MAX), Err(EgressError::Limits(_))));
    assert!(idle(Duration::from_hours(24)).is_ok());
}

/// An answer hyper cannot parse is an answer: `Unusable`, not a lost connection.
#[tokio::test]
async fn an_unparsable_answer_is_unusable() {
    for raw in [
        &b"HTTP/1.1 200 OK\r\ncontent-length: abc\r\n\r\nabc"[..],
        &b"HTTP/1.1 2000 Odd\r\n\r\n"[..],
        &b"NOT HTTP AT ALL\r\n\r\n"[..],
    ] {
        let door = raw_upstream(raw).await;
        let e = door.send(op(1), request(op(1), "local"), None).await.unwrap_err();
        assert!(
            matches!(e, EgressError::Unusable(_)),
            "an unparsable answer was reported as {e:?} for {:?}",
            String::from_utf8_lossy(raw)
        );
    }
}

/// An upstream that answers `101 Switching Protocols` to a request that asked for no upgrade gets
/// an error, not a response a relay could pass on to its client.
#[tokio::test]
async fn a_switching_protocols_answer_is_an_error() {
    let door = raw_upstream(
        b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\n\r\nRAW-TUNNEL-BYTES",
    )
    .await;
    let got = door.send(op(1), request(op(1), "local"), None).await;
    assert!(
        matches!(
            got,
            Err(EgressError::Unusable("the upstream switched protocols unasked"))
        ),
        "a 101 reached the caller: {:?}",
        got.map(|r| r.status)
    );
}

/// A body framed by `transfer-encoding` reaches the caller decoded, without the `content-length`
/// the upstream sent beside it.
#[tokio::test]
async fn a_content_length_beside_transfer_encoding_is_dropped() {
    let door = raw_upstream(
        b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\n\r\n1a\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\n\r\n",
    )
    .await;
    let got = door.send(op(1), request(op(1), "local"), None).await.unwrap();
    assert!(
        got.headers.get("content-length").is_none(),
        "a content-length contradicting the decoded body was forwarded"
    );
    assert!(got.headers.get("transfer-encoding").is_none());
    assert_eq!(
        &got.body.collect().await.unwrap().to_bytes()[..],
        b"abcdefghijklmnopqrstuvwxyz"
    );
}

/// Anything but exactly what hyper de-frames, one field whose value is `chunked`, would reach the
/// caller still coded or still framed once `transfer-encoding` is stripped; it is an error.
#[tokio::test]
async fn a_transfer_coding_other_than_chunked_is_an_error() {
    for raw in [
        &b"HTTP/1.1 200 OK\r\ntransfer-encoding: gzip, chunked\r\n\r\n5\r\nabcde\r\n0\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked,\r\n\r\n5\r\nabcde\r\n0\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntransfer-encoding:\r\n\r\n5\r\nabcde\r\n0\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked, chunked\r\n\r\n5\r\nabcde\r\n0\r\n\r\n"[..],
    ] {
        let door = raw_upstream(raw).await;
        let got = door.send(op(1), request(op(1), "local"), None).await;
        assert!(
            matches!(
                got,
                Err(EgressError::Unusable(
                    "the upstream used a transfer coding the door does not decode"
                ))
            ),
            "a coded body reached the caller unmarked: {:?} for {:?}",
            got.map(|r| r.headers),
            String::from_utf8_lossy(raw)
        );
    }
}

/// Hyper checks `content-length` only where it reads a body. A `204` keeps none, and for a HEAD
/// request or a `304` it is forwarded only as one length in digits.
#[tokio::test]
async fn content_length_on_answers_without_a_body() {
    let head = |raw: &'static [u8]| async move {
        let door = raw_upstream(raw).await;
        let mut sent = request(op(1), "local");
        sent.method = Method::HEAD;
        let got = door.send(op(1), sent, None).await.unwrap();
        got.headers
            .get_all("content-length")
            .iter()
            .cloned()
            .collect::<Vec<_>>()
    };
    let get = |raw: &'static [u8]| async move {
        let door = raw_upstream(raw).await;
        let got = door.send(op(1), request(op(1), "local"), None).await.unwrap();
        got.headers
            .get_all("content-length")
            .iter()
            .cloned()
            .collect::<Vec<_>>()
    };
    assert!(
        get(b"HTTP/1.1 204 No Content\r\ncontent-length: 100\r\n\r\n")
            .await
            .is_empty(),
        "a 204 kept its content-length"
    );
    assert!(
        head(b"HTTP/1.1 200 OK\r\ncontent-length: 5, 7\r\n\r\n")
            .await
            .is_empty()
    );
    assert!(
        get(b"HTTP/1.1 304 Not Modified\r\ncontent-length: abc, 9\r\n\r\n")
            .await
            .is_empty()
    );
    assert_eq!(
        head(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\ncontent-length: 5\r\n\r\n").await,
        vec![HeaderValue::from_static("5")]
    );
}

/// A repeated `content-length`, as a list or as several fields, is forwarded once.
#[tokio::test]
async fn a_repeated_content_length_is_forwarded_once() {
    for raw in [
        &b"HTTP/1.1 200 OK\r\ncontent-length: 5, 5\r\n\r\nabcde"[..],
        &b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\ncontent-length: 5\r\n\r\nabcde"[..],
    ] {
        let door = raw_upstream(raw).await;
        let got = door.send(op(1), request(op(1), "local"), None).await.unwrap();
        let lengths: Vec<_> = got.headers.get_all("content-length").iter().cloned().collect();
        assert_eq!(
            lengths,
            vec![HeaderValue::from_static("5")],
            "a repeated content-length was forwarded"
        );
        assert_eq!(&got.body.collect().await.unwrap().to_bytes()[..], b"abcde");
    }
}

/// The error says whether the request may have reached the provider. Answered but unusable, and cut
/// off after it was sent, are not retryable and say the provider may have received it; a connection
/// that never opened is `Unreachable`, retryable, nothing sent.
#[tokio::test]
async fn errors_say_whether_the_request_may_have_reached_the_provider() {
    let retryable = |e: &EgressError| uaos_contracts::error::spec(e.code()).map(|s| s.retryable);
    let unusable = raw_upstream(b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\n\r\n").await;
    let e = unusable.send(op(1), request(op(1), "local"), None).await.unwrap_err();
    assert!(matches!(e, EgressError::Unusable(_)), "{e:?}");
    assert_eq!(retryable(&e), Some(false));
    // Reads the request, then closes without answering.
    let cut = raw_upstream(b"").await;
    let e = cut.send(op(1), request(op(1), "local"), None).await.unwrap_err();
    assert!(
        matches!(e, EgressError::Interrupted(_)),
        "a request the provider received was reported as never sent: {e:?}"
    );
    assert_eq!(retryable(&e), Some(false));
    let up = Upstream {
        id: UpstreamId::new("local"),
        host: HostName::parse("ollama.lan").unwrap(),
        port: closed_port(),
        scheme: Scheme::Http,
        pinned: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        allow_private: true,
        trust: Trust::System,
    };
    let refused = door(vec![up], Table::default(), DoorLimits::default());
    let e = refused.send(op(1), request(op(1), "local"), None).await.unwrap_err();
    assert!(matches!(e, EgressError::Unreachable(_)), "{e:?}");
    assert_eq!(retryable(&e), Some(true));
}

/// A caller's `content-length` cannot truncate the body; the door frames it.
#[tokio::test]
async fn a_caller_content_length_is_dropped() {
    let mock = mock(StatusCode::OK).await;
    let door = door(
        vec![mock_upstream(mock.port, mock.authority.clone())],
        Table::default(),
        DoorLimits::default(),
    );
    let mut short = request(op(1), "mock");
    short.headers.insert("content-length", HeaderValue::from_static("5"));
    door.send(op(1), short, None).await.unwrap();
    assert_eq!(
        &mock.seen.lock().unwrap()[0].body[..],
        br#"{"model":"m","messages":[]}"#,
        "a caller-supplied content-length truncated the body"
    );
}

/// No credential but the door's own reaches a provider: the client's key to UAOS, cookies and
/// provider keys in the request are refused.
#[tokio::test]
async fn credential_bearing_headers_from_the_caller_are_refused() {
    let mock = mock(StatusCode::OK).await;
    let door = door(
        vec![mock_upstream(mock.port, mock.authority.clone())],
        Table::default(),
        DoorLimits::default(),
    );
    for (n, name) in CREDENTIAL_HEADERS.iter().enumerate() {
        let n = u64::try_from(n).unwrap() + 1;
        let mut carrying = request(op(n), "mock");
        carrying.headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static("client-value-for-tests"),
        );
        assert_eq!(
            door.send(op(n), carrying, Some(credential())).await.unwrap_err(),
            EgressError::Refused("the request carries a credential-bearing header"),
            "{name} would have reached the provider"
        );
    }
    assert!(mock.seen.lock().unwrap().is_empty());
}

/// An oversized body is refused before any connection, and a certificate for another name from the
/// trusted authority is refused before any request.
#[tokio::test]
async fn an_oversized_body_and_a_wrong_name_are_refused() {
    let mock = mock(StatusCode::OK).await;
    let small = door(
        vec![mock_upstream(mock.port, mock.authority.clone())],
        Table::default(),
        DoorLimits {
            max_request_body: 4,
            ..DoorLimits::default()
        },
    );
    assert_eq!(
        small.send(op(1), request(op(1), "mock"), None).await.unwrap_err(),
        EgressError::Refused("request body larger than the door's limit")
    );
    assert_eq!(small.counters().connects, 0);

    let mut renamed = mock_upstream(mock.port, mock.authority.clone());
    renamed.host = HostName::parse("other.provider.test").unwrap();
    let wrong = door(vec![renamed], Table::default(), DoorLimits::default());
    assert_eq!(
        wrong
            .send(op(2), request(op(2), "mock"), Some(credential()))
            .await
            .unwrap_err(),
        EgressError::Unreachable("TLS handshake or certificate check failed")
    );
    assert!(
        mock.seen.lock().unwrap().is_empty(),
        "a request reached a peer with the wrong name"
    );
}

/// One connection attempt tries a bounded number of addresses.
#[tokio::test]
async fn a_connection_attempt_tries_a_bounded_number_of_addresses() {
    let closed = closed_port();
    let issued = rcgen::generate_simple_self_signed(vec![MOCK_HOST.to_owned()]).unwrap();
    let mut up = mock_upstream(closed, issued.cert.der().clone());
    up.pinned = vec![IpAddr::V4(Ipv4Addr::LOCALHOST); MAX_ADDRESSES_TRIED + 3];
    let door = door(vec![up], Table::default(), DoorLimits::default());
    assert!(matches!(
        door.send(op(1), request(op(1), "mock"), None).await,
        Err(EgressError::Unreachable(_))
    ));
    assert_eq!(door.counters().connects, u64::try_from(MAX_ADDRESSES_TRIED).unwrap());
}

/// A probe whose caller gives up does not leave the circuit refusing forever; the next attempt
/// probes again.
#[tokio::test]
async fn a_cancelled_probe_lets_the_next_attempt_probe() {
    // Accepts TCP and never speaks, so every TLS handshake hangs until the connect timeout.
    let silent = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = silent.local_addr().unwrap().port();
    let held = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::clone(&held);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = silent.accept().await {
            keep.lock().unwrap().push(tcp);
        }
    });
    let issued = rcgen::generate_simple_self_signed(vec![MOCK_HOST.to_owned()]).unwrap();
    let clock = clock();
    let shared: Arc<dyn uaos_platform::Clock> = clock.clone();
    let limits = DoorLimits {
        connect_timeout: Duration::from_millis(300),
        breaker_threshold: 1,
        breaker_cooldown: Duration::from_secs(30),
        ..DoorLimits::default()
    };
    let door = Door::new(
        vec![mock_upstream(port, issued.cert.der().clone())],
        Arc::new(Table::default()),
        shared,
        TokioExecutor::new(),
        limits,
    )
    .unwrap();
    assert_eq!(
        door.send(op(1), request(op(1), "mock"), None).await.unwrap_err(),
        EgressError::Timeout
    );
    assert!(matches!(
        door.send(op(2), request(op(2), "mock"), None).await,
        Err(EgressError::CircuitOpen { .. })
    ));
    clock.advance(31_000_000_000);
    let cancelled = tokio::time::timeout(
        Duration::from_millis(50),
        door.send(op(3), request(op(3), "mock"), None),
    )
    .await;
    assert!(cancelled.is_err(), "the probe was expected to still be in flight");
    let before = door.counters().connects;
    let next = door.send(op(4), request(op(4), "mock"), None).await;
    assert!(
        !matches!(next, Err(EgressError::CircuitOpen { .. })),
        "a cancelled probe left the circuit refusing: {next:?}"
    );
    assert_eq!(door.counters().connects, before + 1, "the next attempt probed");
}

/// An upstream that trusts no root at all is refused when the door is built, not discovered as a
/// stream of handshake failures.
#[test]
fn an_upstream_with_no_root_to_trust_is_refused() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    let mut up = Upstream::https("p", HostName::parse("api.example.com").unwrap());
    up.trust = Trust::Roots(Vec::new());
    assert_eq!(
        Door::new(
            vec![up],
            Arc::new(Table::default()),
            clock(),
            TokioExecutor::new(),
            DoorLimits::default()
        )
        .unwrap_err(),
        EgressError::Tls("an upstream declares no root certificate to trust")
    );
}
