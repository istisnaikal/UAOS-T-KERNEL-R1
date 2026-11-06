// SPDX-License-Identifier: Apache-2.0

//! Where an address may be dialled from.
//!
//! Every resolved address is classified before the door connects to it. Anything that is not
//! globally routable unicast is refused, including addresses that *embed* a private IPv4 address
//! (IPv4-mapped, NAT64, 6to4, Teredo): an attacker who controls DNS for a public name could
//! otherwise point it at the loopback interface, the cloud metadata service or the LAN.
//! The ranges follow the IANA special-purpose registries (RFC 6890 and updates).
//!
//! **Residuals, by design.** Some special endpoints sit on ordinary public unicast and cannot be
//! told apart by address: network-specific NAT64 prefixes (RFC 6052 §2.2) and cloud host
//! endpoints such as Azure's `WireServer` (`168.63.129.16`). They are reachable only over HTTPS
//! with a verified certificate for the declared name, because plain HTTP is dialled only at
//! pinned local addresses ([`crate::Upstream`]).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why an address is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Blocked {
    /// `0.0.0.0/8`, `::`.
    Unspecified,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// `10/8`, `172.16/12`, `192.168/16`.
    Private,
    /// `100.64.0.0/10` (carrier-grade NAT).
    SharedAddressSpace,
    /// `169.254.0.0/16` (includes the `169.254.169.254` metadata service), `fe80::/10`.
    LinkLocal,
    /// `192.0.0.0/24`, `2001::/23` (IETF protocol assignments, Teredo included).
    ProtocolAssignment,
    /// `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `3fff::/20`.
    Documentation,
    /// `198.18.0.0/15`.
    Benchmarking,
    /// `192.88.99.0/24` (6to4 relay anycast).
    Relay,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `240.0.0.0/4`, `255.255.255.255`.
    Reserved,
    /// `fc00::/7`.
    UniqueLocal,
    /// `fec0::/10` (deprecated site-local).
    SiteLocal,
    /// `100::/64` (discard-only).
    Discard,
    /// A public address toward a plain-HTTP upstream, which may only reach this machine or the
    /// local network.
    PublicOverPlaintext,
    /// A cloud provider's metadata service on an IPv6 unique-local address (`fd00:ec2::254`,
    /// `fd20:ce::254`).
    CloudMetadata,
}

/// Whether `ip` is on this machine or the local network: IPv4 loopback or private (RFC 1918),
/// `::1`, unique-local IPv6 (`fc00::/7`) other than cloud metadata endpoints, and IPv4-mapped
/// forms of those IPv4 addresses. Only these may be admitted by a declared private upstream;
/// link-local stays refused because it holds the cloud metadata service.
///
/// IPv6 forms that only *embed* an IPv4 address (IPv4-compatible, NAT64, 6to4) are never local,
/// whatever the inner address: their traffic leaves the machine through a relay, a translator or
/// the default route. [`classify`] still reports the inner range for them.
#[must_use]
pub fn is_local_network(ip: IpAddr) -> bool {
    if let IpAddr::V6(v6) = ip
        && embeds_ipv4(v6)
    {
        return false;
    }
    matches!(
        classify(ip),
        Reach::Blocked(Blocked::Loopback | Blocked::Private | Blocked::UniqueLocal)
    )
}

/// IPv4-compatible (`::a.b.c.d`, not `::` or `::1`), NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`)
/// and 6to4 (`2002::/16`) addresses.
fn embeds_ipv4(ip: Ipv6Addr) -> bool {
    (in_v6(ip, [0; 8], 96) && !ip.is_unspecified() && !ip.is_loopback())
        || in_v6(ip, [0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96)
        || in_v6(ip, [0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48)
        || in_v6(ip, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16)
}

/// The verdict for one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Globally routable unicast: may be dialled.
    Public,
    /// Must not be dialled unless the upstream is declared private.
    Blocked(Blocked),
}

/// Classifies an address, looking through every IPv6 form that embeds an IPv4 address.
#[must_use]
pub fn classify(ip: IpAddr) -> Reach {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn in_v4(ip: Ipv4Addr, net: [u8; 4], prefix: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    (u32::from(ip) & mask) == (u32::from(Ipv4Addr::from(net)) & mask)
}

fn classify_v4(ip: Ipv4Addr) -> Reach {
    // 192.0.0.9 and.10 are globally reachable anycast exceptions inside 192.0.0.0/24, but no model
    // provider lives there; refusing the whole block costs nothing.
    const RULES: [([u8; 4], u32, Blocked); 16] = [
        ([0, 0, 0, 0], 8, Blocked::Unspecified),
        ([10, 0, 0, 0], 8, Blocked::Private),
        ([100, 64, 0, 0], 10, Blocked::SharedAddressSpace),
        ([127, 0, 0, 0], 8, Blocked::Loopback),
        ([169, 254, 0, 0], 16, Blocked::LinkLocal),
        ([172, 16, 0, 0], 12, Blocked::Private),
        ([192, 0, 0, 0], 24, Blocked::ProtocolAssignment),
        ([192, 0, 2, 0], 24, Blocked::Documentation),
        ([192, 88, 99, 0], 24, Blocked::Relay),
        ([192, 168, 0, 0], 16, Blocked::Private),
        ([198, 18, 0, 0], 15, Blocked::Benchmarking),
        ([198, 51, 100, 0], 24, Blocked::Documentation),
        ([203, 0, 113, 0], 24, Blocked::Documentation),
        ([224, 0, 0, 0], 4, Blocked::Multicast),
        ([240, 0, 0, 0], 4, Blocked::Reserved),
        ([255, 255, 255, 255], 32, Blocked::Reserved),
    ];
    RULES
        .iter()
        .find(|(net, prefix, _)| in_v4(ip, *net, *prefix))
        .map_or(Reach::Public, |(_, _, why)| Reach::Blocked(*why))
}

fn in_v6(ip: Ipv6Addr, net: [u16; 8], prefix: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
    (u128::from(ip) & mask) == (u128::from(Ipv6Addr::from(net)) & mask)
}

/// The IPv4 address in the low 32 bits.
fn low_v4(ip: Ipv6Addr) -> Ipv4Addr {
    let bits = u128::from(ip);
    Ipv4Addr::from(u32::try_from(bits & 0xFFFF_FFFF).unwrap_or(u32::MAX))
}

/// The worse of an embedded IPv4 address's verdict and the given fallback.
fn embedded(v4: Ipv4Addr, otherwise: Blocked) -> Reach {
    match classify_v4(v4) {
        Reach::Public => Reach::Blocked(otherwise),
        blocked @ Reach::Blocked(_) => blocked,
    }
}

fn classify_v6(ip: Ipv6Addr) -> Reach {
    const RULES: [([u16; 8], u32, Blocked); 10] = [
        // Cloud metadata services inside fc00::/7, before the unique-local rule.
        ([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254], 128, Blocked::CloudMetadata),
        ([0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x254], 128, Blocked::CloudMetadata),
        ([0x100, 0, 0, 0, 0, 0, 0, 0], 64, Blocked::Discard),
        ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32, Blocked::Documentation),
        // RFC 9637: inside 2000::/3, but not globally reachable.
        ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20, Blocked::Documentation),
        // Covers Teredo (2001::/32), whose server and client addresses are attacker-chosen.
        ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23, Blocked::ProtocolAssignment),
        ([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7, Blocked::UniqueLocal),
        ([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10, Blocked::LinkLocal),
        ([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10, Blocked::SiteLocal),
        ([0xff00, 0, 0, 0, 0, 0, 0, 0], 8, Blocked::Multicast),
    ];
    if ip.is_unspecified() {
        return Reach::Blocked(Blocked::Unspecified);
    }
    if ip.is_loopback() {
        return Reach::Blocked(Blocked::Loopback);
    }
    // IPv4-mapped (ffff:a.b.c.d): the socket reaches the IPv4 address itself.
    if in_v6(ip, [0, 0, 0, 0, 0, 0xffff, 0, 0], 96) {
        return classify_v4(low_v4(ip));
    }
    // IPv4-compatible (deprecated::a.b.c.d): never routed; refuse, reporting the inner range.
    if in_v6(ip, [0; 8], 96) {
        return embedded(low_v4(ip), Blocked::Reserved);
    }
    // NAT64 well-known prefix (64:ff9b::/96): a translator forwards to the inner address. It
    // carries only global IPv4 addresses (RFC 6052 §3.1), which is how DNS64 lets an IPv6-only
    // network reach an IPv4-only provider, so a public inner address is public; any other inner
    // address is refused with its own range.
    if in_v6(ip, [0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96) {
        return classify_v4(low_v4(ip));
    }
    // Local-use NAT64 prefix (64:ff9b:1::/48, RFC 8215). Its IPv4 bits depend on the operator's
    // prefix length, so it is refused as a whole rather than decoded.
    if in_v6(ip, [0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48) {
        return Reach::Blocked(Blocked::ProtocolAssignment);
    }
    // 6to4 (2002::/16): the IPv4 address sits in bits 16..48.
    if in_v6(ip, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16) {
        let inner = u32::try_from((u128::from(ip) >> 80) & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        return embedded(Ipv4Addr::from(inner), Blocked::Relay);
    }
    if let Some((_, _, why)) = RULES.iter().find(|(net, prefix, _)| in_v6(ip, *net, *prefix)) {
        return Reach::Blocked(*why);
    }
    // Global unicast lives inside 2000::/3; everything else is unassigned or special.
    if in_v6(ip, [0x2000, 0, 0, 0, 0, 0, 0, 0], 3) {
        Reach::Public
    } else {
        Reach::Blocked(Blocked::Reserved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn v(s: &str) -> Reach {
        classify(s.parse().unwrap())
    }

    #[test]
    fn special_purpose_ipv4_ranges_are_refused() {
        for (addr, why) in [
            ("0.0.0.0", Blocked::Unspecified),
            ("10.1.2.3", Blocked::Private),
            ("100.64.0.1", Blocked::SharedAddressSpace),
            ("127.0.0.1", Blocked::Loopback),
            ("127.255.255.254", Blocked::Loopback),
            ("169.254.169.254", Blocked::LinkLocal),
            ("172.16.0.1", Blocked::Private),
            ("172.31.255.255", Blocked::Private),
            ("192.0.0.1", Blocked::ProtocolAssignment),
            ("192.0.2.1", Blocked::Documentation),
            ("192.88.99.1", Blocked::Relay),
            ("192.168.1.1", Blocked::Private),
            ("198.18.0.1", Blocked::Benchmarking),
            ("198.51.100.7", Blocked::Documentation),
            ("203.0.113.9", Blocked::Documentation),
            ("224.0.0.251", Blocked::Multicast),
            ("240.0.0.1", Blocked::Reserved),
            ("255.255.255.255", Blocked::Reserved),
        ] {
            assert_eq!(v(addr), Reach::Blocked(why), "{addr}");
        }
    }

    #[test]
    fn cloud_metadata_on_ipv6_is_refused_and_never_local() {
        for addr in ["fd00:ec2::254", "fd20:ce::254"] {
            assert_eq!(v(addr), Reach::Blocked(Blocked::CloudMetadata), "{addr}");
            assert!(!is_local_network(addr.parse().unwrap()), "{addr}");
        }
        assert!(is_local_network("fd12:3456::1".parse().unwrap()));
        assert!(is_local_network("::1".parse().unwrap()));
        for embedded in [
            "2002:7f00:1::1",
            "64:ff9b::7f00:1",
            "::7f00:1",
            "2002:c0a8:101::1",
            "64:ff9b::a00:5",
        ] {
            assert!(
                !is_local_network(embedded.parse().unwrap()),
                "{embedded} counted as local"
            );
        }
    }

    #[test]
    fn public_addresses_are_allowed() {
        for addr in [
            "1.1.1.1",
            "8.8.8.8",
            "160.79.104.10",
            "172.32.0.1",
            "100.128.0.1",
            "2606:4700::1111",
        ] {
            assert_eq!(v(addr), Reach::Public, "{addr}");
        }
    }

    #[test]
    fn ipv6_forms_that_embed_a_private_ipv4_address_are_refused() {
        for (addr, why) in [
            ("::", Blocked::Unspecified),
            ("::1", Blocked::Loopback),
            ("::ffff:127.0.0.1", Blocked::Loopback),
            ("::ffff:169.254.169.254", Blocked::LinkLocal),
            ("::ffff:10.0.0.1", Blocked::Private),
            ("::127.0.0.1", Blocked::Loopback),
            ("64:ff9b::7f00:1", Blocked::Loopback),
            ("64:ff9b::a9fe:a9fe", Blocked::LinkLocal),
            ("64:ff9b:1::a00:1", Blocked::ProtocolAssignment),
            ("64:ff9b:1:abcd::1", Blocked::ProtocolAssignment),
            ("3fff::1", Blocked::Documentation),
            ("3fff:fff:ffff::1", Blocked::Documentation),
            ("2002:7f00:1::", Blocked::Loopback),
            ("2002:a9fe:a9fe::1", Blocked::LinkLocal),
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", Blocked::ProtocolAssignment),
            ("2001:db8::1", Blocked::Documentation),
            ("fc00::1", Blocked::UniqueLocal),
            ("fd12:3456::1", Blocked::UniqueLocal),
            ("fe80::1", Blocked::LinkLocal),
            ("fec0::1", Blocked::SiteLocal),
            ("ff02::1", Blocked::Multicast),
            ("100::1", Blocked::Discard),
            ("4000::1", Blocked::Reserved),
        ] {
            assert_eq!(v(addr), Reach::Blocked(why), "{addr}");
        }
        // A DNS64 answer for a public IPv4-only provider is public; 6to4 of a public address is
        // still refused (the relay is deprecated, RFC 7526).
        assert_eq!(v("64:ff9b::808:808"), Reach::Public);
        assert_eq!(v("64:ff9b::a29f:8c0a"), Reach::Public);
        assert!(matches!(v("2002:808:808::1"), Reach::Blocked(_)));
        // IPv4-mapped public addresses behave like the IPv4 address.
        assert_eq!(v("::ffff:8.8.8.8"), Reach::Public);
    }

    proptest! {
        /// An IPv4-mapped address always gets exactly its IPv4 address's verdict.
        #[test]
        fn mapped_addresses_follow_their_ipv4_address(bits in any::<u32>()) {
            let v4 = Ipv4Addr::from(bits);
            prop_assert_eq!(classify(IpAddr::V6(v4.to_ipv6_mapped())), classify(IpAddr::V4(v4)));
        }

        /// Outside global unicast (2000::/3), nothing is public, except IPv4-mapped and well-known
        /// NAT64 addresses, which take their IPv4 address's verdict.
        #[test]
        fn nothing_outside_global_unicast_is_public(bits in any::<u128>()) {
            let v6 = Ipv6Addr::from(bits);
            let mapped = v6.to_ipv4_mapped().is_some();
            let nat64 = bits >> 32 == (0x64_u128 << 80) | (0xff9b_u128 << 64);
            if !mapped && !nat64 && (bits >> 125) != 0b001 {
                prop_assert!(matches!(classify(IpAddr::V6(v6)), Reach::Blocked(_)));
            }
        }

        /// A NAT64 well-known address gets exactly its IPv4 address's verdict.
        #[test]
        fn nat64_well_known_follows_its_ipv4_address(inner in any::<u32>()) {
            let ip = (0x64_u128 << 112) | (0xff9b_u128 << 96) | u128::from(inner);
            prop_assert_eq!(classify(IpAddr::V6(Ipv6Addr::from(ip))), classify(IpAddr::V4(Ipv4Addr::from(inner))));
        }

        /// Every other form that embeds an IPv4 address is refused whatever the inner address.
        #[test]
        fn embedding_forms_are_never_public(inner in any::<u32>(), tail in any::<u64>()) {
            let v4 = u128::from(inner);
            for ip in [
                v4,                                                   // IPv4-compatible
                (0x64_u128 << 112) | (0xff9b_u128 << 96) | (1_u128 << 80) | u128::from(tail), // NAT64 local-use
                (0x2002_u128 << 112) | (v4 << 80) | u128::from(tail), // 6to4
                (0x2001_u128 << 112) | u128::from(tail),              // Teredo
            ] {
                prop_assert!(matches!(classify(IpAddr::V6(Ipv6Addr::from(ip))), Reach::Blocked(_)), "{}", Ipv6Addr::from(ip));
            }
        }

        /// Only loopback and private IPv4 ranges count as the local network, and an IPv4-mapped
        /// address counts exactly when its IPv4 address does.
        #[test]
        fn the_local_network_is_exactly_loopback_private_and_unique_local(bits in any::<u32>()) {
            let v4 = Ipv4Addr::from(bits);
            let local = v4.is_loopback() || v4.is_private();
            prop_assert_eq!(is_local_network(IpAddr::V4(v4)), local);
            prop_assert_eq!(is_local_network(IpAddr::V6(v4.to_ipv6_mapped())), local);
        }

        /// IPv6 forms that embed an IPv4 address are never the local network, whatever the inner
        /// address.
        #[test]
        fn embedding_forms_are_never_local(inner in any::<u32>(), tail in any::<u64>()) {
            let v4 = u128::from(inner);
            for ip in [
                (0x64_u128 << 112) | (0xff9b_u128 << 96) | v4,
                (0x64_u128 << 112) | (0xff9b_u128 << 96) | (1_u128 << 80) | u128::from(tail),
                (0x2002_u128 << 112) | (v4 << 80) | u128::from(tail),
            ] {
                prop_assert!(!is_local_network(IpAddr::V6(Ipv6Addr::from(ip))), "{}", Ipv6Addr::from(ip));
            }
            if inner > 1 {
                prop_assert!(!is_local_network(IpAddr::V6(Ipv6Addr::from(v4))), "IPv4-compatible");
            }
        }

        /// The standard library's own classifications are never contradicted.
        #[test]
        fn never_allows_what_std_calls_special(bits in any::<u32>()) {
            let v4 = Ipv4Addr::from(bits);
            if v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_multicast()
                || v4.is_broadcast() || v4.is_documentation() || v4.is_unspecified()
            {
                prop_assert!(matches!(classify(IpAddr::V4(v4)), Reach::Blocked(_)));
            }
        }
    }
}
