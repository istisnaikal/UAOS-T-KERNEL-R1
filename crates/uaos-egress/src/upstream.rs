// SPDX-License-Identifier: Apache-2.0

//! Upstreams: the destinations the door may contact, declared in configuration and never
//! derived from request content.

use std::fmt;
use std::net::IpAddr;

use rustls_pki_types::CertificateDer;

use crate::addr::{Blocked, Reach, classify, is_local_network};
use crate::host::HostName;

/// The name routes use for an upstream (for example `anthropic`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UpstreamId(String);

impl UpstreamId {
    /// Wraps a configured name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UpstreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Transport to the upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// TLS. The only scheme allowed toward public addresses.
    Https,
    /// Plain TCP, for a server on this machine or the local network that the user chose to
    /// trust. It is dialled only at pinned loopback, private or unique-local addresses and never
    /// resolved, so no DNS answer, LLMNR or mDNS reply can send it anywhere else.
    Http,
}

/// Which certificates the door accepts for an HTTPS upstream.
#[derive(Debug, Clone)]
pub enum Trust {
    /// The roots in the operating system's trust store, read locally when the door is built, so
    /// corporate interception roots work. Chains are verified by rustls itself: nothing is fetched
    /// during a handshake (no issuer download, no revocation lookup), so a server's certificate can
    /// never make UAOS contact an address of its choosing. Revocation is not checked.
    System,
    /// Only these roots. For tests and for private upstreams with their own authority.
    Roots(Vec<CertificateDer<'static>>),
}

/// One destination the door may contact.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// The name routes use.
    pub id: UpstreamId,
    /// DNS name: the SNI and certificate name, and what is resolved unless addresses are pinned.
    pub host: HostName,
    /// TCP port.
    pub port: u16,
    /// Transport.
    pub scheme: Scheme,
    /// Addresses to dial instead of resolving `host`. They are classified like resolved ones.
    /// Required for plain HTTP.
    pub pinned: Vec<IpAddr>,
    /// Permit addresses on this machine or the local network: loopback, private (RFC 1918) and
    /// unique-local (`fc00::/7`), whether pinned or resolved. Link-local (which holds the cloud
    /// metadata service), unspecified, multicast and every other special-purpose range stay
    /// refused. Off by default; it must be declared, and plain HTTP requires it.
    pub allow_private: bool,
    /// Accepted certificates.
    pub trust: Trust,
}

/// Why an upstream declaration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamError {
    /// Plain HTTP toward an address that is not on this machine or the local network, or
    /// without `allow_private`.
    #[error("plain HTTP is allowed only toward pinned loopback, private or unique-local addresses")]
    PlaintextToPublic,
    /// Plain HTTP without pinned addresses: it would depend on name resolution.
    #[error("plain HTTP needs pinned addresses; its name is never resolved")]
    PlaintextNeedsPinned,
    /// Port 0.
    #[error("port 0 is not a destination")]
    Port,
    /// Two upstreams share an id, or a host and port.
    #[error("two upstreams share an id, or a host and port")]
    Duplicate,
}

impl Upstream {
    /// An HTTPS upstream on port 443, verified against the system's roots.
    #[must_use]
    pub fn https(id: impl Into<String>, host: HostName) -> Self {
        Self {
            id: UpstreamId::new(id),
            host,
            port: 443,
            scheme: Scheme::Https,
            pinned: Vec::new(),
            allow_private: false,
            trust: Trust::System,
        }
    }

    /// Whether the door may dial `ip` for this upstream, and if not, why.
    ///
    /// # Errors
    /// The reason the address is refused.
    pub(crate) fn admits(&self, ip: IpAddr) -> Result<(), Blocked> {
        match classify(ip) {
            Reach::Public if self.scheme == Scheme::Https => Ok(()),
            // Unreachable after `validate`, which pins plain HTTP to local addresses; kept so the
            // dial path never depends on that check alone.
            Reach::Public => Err(Blocked::PublicOverPlaintext),
            Reach::Blocked(_) if self.allow_private && is_local_network(ip) => Ok(()),
            Reach::Blocked(why) => Err(why),
        }
    }

    /// Checks the declaration's own rules.
    ///
    /// # Errors
    /// [`UpstreamError`].
    pub fn validate(&self) -> Result<(), UpstreamError> {
        if self.port == 0 {
            return Err(UpstreamError::Port);
        }
        if self.scheme == Scheme::Http {
            if !self.allow_private {
                return Err(UpstreamError::PlaintextToPublic);
            }
            if self.pinned.is_empty() {
                return Err(UpstreamError::PlaintextNeedsPinned);
            }
            let local = |ip: &IpAddr| is_local_network(*ip);
            if !self.pinned.iter().all(local) {
                return Err(UpstreamError::PlaintextToPublic);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(pinned: &str) -> Upstream {
        Upstream {
            id: UpstreamId::new("local"),
            host: HostName::parse("ollama.lan").unwrap(),
            port: 11434,
            scheme: Scheme::Http,
            pinned: vec![pinned.parse().unwrap()],
            allow_private: true,
            trust: Trust::System,
        }
    }

    /// The dial path refuses a public address for plain HTTP on its own, whatever `validate` would
    /// have said.
    #[test]
    fn the_dial_path_refuses_public_addresses_over_plaintext() {
        let up = plain("127.0.0.1");
        assert_eq!(up.admits("8.8.8.8".parse().unwrap()), Err(Blocked::PublicOverPlaintext));
        assert_eq!(
            up.admits("2606:4700::1111".parse().unwrap()),
            Err(Blocked::PublicOverPlaintext)
        );
        assert_eq!(up.admits("127.0.0.1".parse().unwrap()), Ok(()));
        assert_eq!(up.admits("169.254.169.254".parse().unwrap()), Err(Blocked::LinkLocal));
        assert_eq!(up.admits("64:ff9b::7f00:1".parse().unwrap()), Err(Blocked::Loopback));
    }

    /// Embedded IPv6 forms and IPv6 metadata endpoints are refused for plain HTTP.
    #[test]
    fn plaintext_is_refused_toward_embedded_forms_and_ipv6_metadata() {
        for refused in [
            "2002:7f00:1::1",
            "64:ff9b::7f00:1",
            "::7f00:1",
            "2002:c0a8:101::1",
            "64:ff9b::a00:5",
            "fd00:ec2::254",
            "fd20:ce::254",
        ] {
            assert_eq!(
                plain(refused).validate(),
                Err(UpstreamError::PlaintextToPublic),
                "{refused}"
            );
        }
        for allowed in ["::1", "::ffff:127.0.0.1", "fd12:3456::1", "192.168.1.20"] {
            assert_eq!(plain(allowed).validate(), Ok(()), "{allowed}");
        }
    }
}
