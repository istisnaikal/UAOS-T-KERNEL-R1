// SPDX-License-Identifier: Apache-2.0

//! # UAOS egress: the one door
//!
//! Every outbound byte UAOS sends on a user's behalf leaves through [`Door::send`]. The standard
//! and tokio entry points that open sockets, send UDP, resolve names or build another HTTP client
//! are banned elsewhere in `clippy.toml`, with this crate as their only owner, and `arch.toml` lets
//! only the runtime depend on it. Those bans cover the listed entry points; a dependency that opens
//! sockets on its own is kept out by `arch.toml` and supply-chain review, not by the bans.
//!
//! What the door guarantees:
//! * **Declared destinations only.** It connects to configured upstreams, named by DNS names;
//!   address literals in any spelling are refused ([`host`]).
//! * **It owns DNS.** It resolves, classifies every answer, and dials the classified address
//!   itself. Private, loopback, link-local, metadata and other special-purpose ranges are
//!   refused, including inside IPv4-mapped, NAT64 and 6to4 forms ([`addr`]). An upstream
//!   declared private may also reach loopback, private and unique-local addresses, never
//!   link-local; plain HTTP is dialled only at pinned local addresses and never resolved.
//! * **No fetches during TLS.** Certificates are verified against the system's roots by rustls
//!   itself, so a server's certificate cannot make UAOS fetch an issuer or revocation URL of its
//!   choosing ([`Trust::System`]).
//! * **No redirects.** A redirect is returned to the caller as a response, never followed.
//! * **Nothing added.** Hop-by-hop headers, `host` and `content-length` are removed, a request that
//!   carries a credential-bearing header is refused, and no UAOS header is added. The only
//!   insertion is the provider credential, placed last, after the runtime's final scan, and marked
//!   sensitive so it is never printed.
//! * **One send per Operation.** A request bound to another Operation, or a second request for the
//!   same Operation, is refused before any contact (binding check).
//! * **No contact by default.** Building the door contacts nothing; [`Door::counters`] lets a test
//!   prove zero resolutions and connections.
//! * **Bounded.** Idle connections per upstream, the replay window, resolution, connect, handshake
//!   and response-header timeouts, addresses tried and request body size are limited. Concurrent
//!   requests and response bodies are bounded by the runtime ([`DoorLimits`]).
//!
//! What it does not do: retries (hyper-util's transparent retry is switched off), routing,
//! pricing and redaction belong to the runtime and its stages; the door carries out one
//! authorized, scanned request.

pub mod addr;
mod connect;
mod door;
pub mod host;
pub mod resolve;
pub mod upstream;

pub use connect::{CounterSnapshot, MAX_ADDRESSES_TRIED, Stream};
pub use door::{
    CREDENTIAL_HEADERS, Credential, Door, DoorLimits, EgressRequest, EgressResponse, MAX_IDLE_PER_UPSTREAM,
    PROBE_RECHECK, REPLAY_WINDOW,
};
pub use host::{HostError, HostName};
pub use resolve::{Resolve, SystemResolver};
pub use upstream::{Scheme, Trust, Upstream, UpstreamError, UpstreamId};

use std::time::Duration;

use uaos_contracts::error::{ErrorCode, codes};

/// Egress failure. Every variant maps to a registered code ([`EgressError::code`]); none carries
/// request content, paths or credentials.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EgressError {
    /// Every address the name resolved to was refused.
    #[error("destination refused: it resolved only to {0:?} addresses")]
    Blocked(addr::Blocked),
    /// Resolution, connection or TLS failed, or the connection closed before the request was
    /// sent: nothing reached the provider.
    #[error("provider unreachable: {0}")]
    Unreachable(&'static str),
    /// Name resolution or the TLS handshake timed out, or the response timeout ran out before
    /// hyper handed the request to a connection: nothing was sent. (A connect that times out
    /// moves on to the next address; when none accepts, the door reports `Unreachable`.)
    #[error("provider could not be reached in time")]
    Timeout,
    /// The connection failed, or no answer came within the response timeout, after the request was
    /// sent: the provider may have received it.
    #[error("no answer after the request was sent: {0}")]
    Interrupted(&'static str),
    /// The provider answered in a form the door does not pass on, or that could not be parsed; it
    /// may have processed the request.
    #[error("unusable answer from the provider: {0}")]
    Unusable(&'static str),
    /// The door's limits are inconsistent.
    #[error("invalid door limits: {0}")]
    Limits(&'static str),
    /// The upstream's circuit is open.
    #[error("recent attempts failed; retry after {retry_after:?}")]
    CircuitOpen {
        /// A hint, not a promise: the time left in the cooldown, or, while a probe is in flight,
        /// [`PROBE_RECHECK`].
        retry_after: Duration,
    },
    /// The door's own rules refused the request before any contact.
    #[error("refused by the egress door: {0}")]
    Refused(&'static str),
    /// An upstream declaration is invalid.
    #[error("invalid upstream: {0}")]
    Upstream(UpstreamError),
    /// The TLS configuration could not be built.
    #[error("TLS configuration: {0}")]
    Tls(&'static str),
}

impl EgressError {
    /// The registered error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Blocked(_) => codes::EGRESS_BLOCKED,
            Self::Unreachable(_) => codes::EGRESS_UNREACHABLE,
            Self::Timeout => codes::EGRESS_TIMEOUT,
            Self::CircuitOpen { .. } => codes::EGRESS_CIRCUIT_OPEN,
            Self::Refused(_) => codes::EGRESS_REFUSED,
            Self::Interrupted(_) => codes::EGRESS_INTERRUPTED,
            Self::Unusable(_) => codes::EGRESS_UNUSABLE_RESPONSE,
            Self::Upstream(_) | Self::Tls(_) | Self::Limits(_) => codes::CONFIG_INVALID,
        }
    }

    /// Maps a client failure, keeping a connector's own verdict (for example `Blocked`), and
    /// telling a request that never left from one the provider may have received:
    /// * hyper-util attaches connection info only to errors from sending on a connection it
    ///   holds, so an error without it came from setting the connection up (the upstream spoke
    ///   first, or closed at once): nothing was sent;
    /// * hyper reports a request it handed back unsent as canceled;
    /// * an answer hyper could not parse is an answer, not a lost connection.
    fn from_client(e: &hyper_util::client::legacy::Error) -> Self {
        let mut unsent = e.is_connect() || e.connect_info().is_none();
        let mut unparsable = false;
        let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
        while let Some(s) = source {
            if let Some(own) = s.downcast_ref::<Self>() {
                return own.clone();
            }
            if let Some(h) = s.downcast_ref::<hyper::Error>() {
                unsent |= h.is_canceled();
                // `is_parse` covers every parse error, a head too large included. Its narrower
                // `is_parse_too_large` exists only with hyper's `server` feature, which this
                // client enables for its tests alone.
                unparsable |= h.is_parse() || h.is_parse_status();
            }
            source = s.source();
        }
        if e.is_connect() {
            Self::Unreachable("connection failed")
        } else if unsent {
            Self::Unreachable("the connection closed before the request was sent")
        } else if unparsable {
            Self::Unusable("the upstream's answer could not be parsed")
        } else {
            Self::Interrupted("the connection failed after the request was sent")
        }
    }
}
