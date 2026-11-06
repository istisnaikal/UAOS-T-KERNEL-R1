// SPDX-License-Identifier: Apache-2.0

//! Opening connections: resolve, classify, pin, dial, then TLS with the upstream's own name.
//!
//! The door's connections are opened here, and the entry points that open sockets or resolve
//! names elsewhere are banned in `clippy.toml` with this crate as their owner. The connector
//! never dials an address it has not classified, it dials the classified address itself (no
//! second lookup a rebinding attacker could answer differently), and it connects only to
//! declared upstreams.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::EgressError;
use crate::resolve::Resolve;
use crate::upstream::{Scheme, Upstream};

/// Addresses tried per connection attempt, each with its own connect timeout.
pub const MAX_ADDRESSES_TRIED: usize = 4;

/// Counters of external contact, for the zero-egress check and observability.
#[derive(Debug, Default)]
pub(crate) struct Counters {
    /// Name resolutions started.
    pub resolves: AtomicU64,
    /// TCP connections attempted.
    pub connects: AtomicU64,
    /// Addresses refused by classification.
    pub blocked: AtomicU64,
    /// Requests handed to the client once every check passed (a connection may still fail).
    pub sent: AtomicU64,
    /// Requests refused by the door's own rules before any contact (an open circuit included).
    pub refused: AtomicU64,
}

/// A point-in-time copy of [`Counters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CounterSnapshot {
    /// Name resolutions started.
    pub resolves: u64,
    /// TCP connections attempted.
    pub connects: u64,
    /// Addresses refused by classification.
    pub blocked: u64,
    /// Requests handed to the client once every check passed (a connection may still fail).
    pub sent: u64,
    /// Requests refused by the door's own rules before any contact (an open circuit included).
    pub refused: u64,
}

impl Counters {
    /// Reads every counter.
    #[must_use]
    pub(crate) fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            resolves: self.resolves.load(Ordering::Relaxed),
            connects: self.connects.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            sent: self.sent.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
        }
    }
}

pub(crate) fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// A connection, plain or TLS.
#[derive(Debug)]
pub enum Stream {
    /// Plain TCP (pinned local addresses of a declared private upstream only).
    Plain(TcpStream),
    /// TLS over TCP.
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

impl Connection for Stream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

/// What the connector knows about one declared upstream.
pub(crate) struct Target {
    pub(crate) upstream: Upstream,
    pub(crate) tls: Option<TlsConnector>,
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Target")
            .field("upstream", &self.upstream.id)
            .field("tls", &self.tls.is_some())
            .finish()
    }
}

/// The hyper connector: maps a request's authority to a declared upstream and connects to it.
#[derive(Debug, Clone)]
pub(crate) struct Connector {
    pub(crate) targets: Arc<BTreeMap<(String, u16), Arc<Target>>>,
    pub(crate) resolver: Arc<dyn Resolve>,
    pub(crate) counters: Arc<Counters>,
    pub(crate) connect_timeout: Duration,
}

impl Connector {
    pub(crate) fn tls_for(config: ClientConfig) -> TlsConnector {
        TlsConnector::from(Arc::new(config))
    }

    async fn connect(self, uri: http::Uri) -> Result<TokioIo<Stream>, EgressError> {
        let (Some(host), Some(port)) = (uri.host(), uri.port_u16()) else {
            return Err(EgressError::Refused("request authority has no host or port"));
        };
        let target = self
            .targets
            .get(&(host.to_owned(), port))
            .cloned()
            .ok_or(EgressError::Refused("connection to an undeclared upstream"))?;
        let up = &target.upstream;

        // Plain HTTP is never resolved: `Upstream::validate` requires pinned local addresses.
        let candidates: Vec<IpAddr> = if up.pinned.is_empty() && up.scheme == Scheme::Https {
            bump(&self.counters.resolves);
            match tokio::time::timeout(self.connect_timeout, self.resolver.resolve(&up.host, up.port)).await {
                Ok(Ok(found)) => found,
                Ok(Err(_)) => return Err(EgressError::Unreachable("name resolution failed")),
                Err(_) => return Err(EgressError::Timeout),
            }
        } else {
            up.pinned.clone()
        };
        let mut first_block = None;
        let allowed: Vec<IpAddr> = candidates
            .into_iter()
            .filter(|ip| match up.admits(*ip) {
                Ok(()) => true,
                Err(why) => {
                    bump(&self.counters.blocked);
                    first_block.get_or_insert(why);
                    false
                }
            })
            .take(MAX_ADDRESSES_TRIED)
            .collect();
        if allowed.is_empty() {
            return Err(first_block.map_or(
                EgressError::Unreachable("the name has no addresses"),
                EgressError::Blocked,
            ));
        }

        for ip in allowed {
            bump(&self.counters.connects);
            let addr = SocketAddr::new(ip, up.port);
            #[allow(
                clippy::disallowed_methods,
                reason = "uaos-egress owns outbound sockets: the one door"
            )]
            let attempt = tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr)).await;
            let Ok(Ok(tcp)) = attempt else { continue };
            // Small request bodies are written in one go; never wait for more data.
            let _nodelay_is_best_effort = tcp.set_nodelay(true);
            let stream = match (&up.scheme, &target.tls) {
                (Scheme::Http, _) => Stream::Plain(tcp),
                (Scheme::Https, Some(tls)) => {
                    let name = ServerName::try_from(up.host.as_str().to_owned())
                        .map_err(|_| EgressError::Refused("upstream name is not a TLS server name"))?;
                    let handshake = tokio::time::timeout(self.connect_timeout, tls.connect(name, tcp)).await;
                    match handshake {
                        Ok(Ok(tls_stream)) => Stream::Tls(Box::new(tls_stream)),
                        Ok(Err(_)) => {
                            return Err(EgressError::Unreachable("TLS handshake or certificate check failed"));
                        }
                        Err(_) => return Err(EgressError::Timeout),
                    }
                }
                (Scheme::Https, None) => return Err(EgressError::Refused("HTTPS upstream without TLS configuration")),
            };
            return Ok(TokioIo::new(stream));
        }
        Err(EgressError::Unreachable("no address accepted a connection"))
    }
}

impl tower_service::Service<http::Uri> for Connector {
    type Response = TokioIo<Stream>;
    type Error = EgressError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        Box::pin(self.clone().connect(uri))
    }
}
