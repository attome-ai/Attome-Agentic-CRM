//! The one IP-network parser and matcher (cleanup 3.6).
//!
//! Config uses it for `security.trusted_proxy_cidrs` (boot validation there
//! still insists on `address/prefix`, see `sections::auth::parse_cidr`), and
//! attome-server's per-role/per-API-key IP allow-list uses it for both
//! admin-time validation and request-time matching. Pure `std::net` bit
//! arithmetic: no `ipnetwork`/`cidr` crate (guidelines §1).

use std::net::IpAddr;

/// Parse an IP network: conventional `address/prefix` CIDR notation, or a
/// bare address, which is a full-length prefix (`/32` for IPv4, `/128` for
/// IPv6). Surrounding whitespace is ignored. `None` for anything malformed,
/// including a prefix longer than the address family allows.
pub fn parse_ip_network(value: &str) -> Option<(IpAddr, u8)> {
    let value = value.trim();
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let address: IpAddr = address.trim().parse().ok()?;
    let max_prefix = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let prefix = match prefix {
        Some(prefix) => prefix.trim().parse::<u8>().ok()?,
        None => max_prefix,
    };
    (prefix <= max_prefix).then_some((address, prefix))
}

/// Whether `candidate` falls inside `network` (`address/prefix`, or a bare
/// address that matches only itself). A malformed `network` never matches
/// (fail closed), and the two address families never cross-match: an
/// IPv4-mapped IPv6 caller is not widened into an IPv4 entry or vice versa.
pub fn cidr_contains(network: &str, candidate: IpAddr) -> bool {
    let Some((network, prefix)) = parse_ip_network(network) else {
        return false;
    };
    match (network, candidate) {
        (IpAddr::V4(network), IpAddr::V4(candidate)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            (u32::from(network) & mask) == (u32::from(candidate) & mask)
        }
        (IpAddr::V6(network), IpAddr::V6(candidate)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            (u128::from(network) & mask) == (u128::from(candidate) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address")
    }

    #[test]
    fn a_bare_ipv4_address_is_a_slash_32() {
        assert_eq!(
            parse_ip_network("203.0.113.4"),
            Some((ip("203.0.113.4"), 32))
        );
        assert!(cidr_contains("203.0.113.4", ip("203.0.113.4")));
        assert!(!cidr_contains("203.0.113.4", ip("203.0.113.5")));
    }

    #[test]
    fn a_bare_ipv6_address_is_a_slash_128() {
        assert_eq!(
            parse_ip_network("2001:db8::1"),
            Some((ip("2001:db8::1"), 128))
        );
        assert!(cidr_contains("::1", ip("::1")));
        assert!(!cidr_contains("::1", ip("::2")));
    }

    #[test]
    fn ipv4_prefixes_match_their_range() {
        assert_eq!(
            parse_ip_network(" 10.0.0.0 / 8 "),
            Some((ip("10.0.0.0"), 8))
        );
        assert!(cidr_contains("10.0.0.0/8", ip("10.255.255.255")));
        assert!(!cidr_contains("10.0.0.0/8", ip("11.0.0.1")));
        assert!(cidr_contains("0.0.0.0/0", ip("255.255.255.255")));
        assert!(cidr_contains("203.0.113.4/32", ip("203.0.113.4")));
        assert!(!cidr_contains("203.0.113.4/32", ip("203.0.113.5")));
    }

    #[test]
    fn ipv6_prefixes_match_their_range() {
        assert_eq!(
            parse_ip_network("2001:db8::/32"),
            Some((ip("2001:db8::"), 32))
        );
        assert!(cidr_contains("2001:db8::/32", ip("2001:db8::1")));
        assert!(!cidr_contains("2001:db8::/32", ip("2001:db9::1")));
        assert!(cidr_contains("::/0", ip("2001:db9::1")));
        assert!(!cidr_contains("::1/128", ip("::2")));
    }

    #[test]
    fn malformed_networks_parse_to_none_and_never_match() {
        for bad in [
            "",
            "not-an-ip",
            "not-an-ip/24",
            "10.0.0.0/33",
            "::1/129",
            "1.2.3.4/-1",
            "1.2.3.4/",
        ] {
            assert_eq!(parse_ip_network(bad), None, "{bad}");
            assert!(!cidr_contains(bad, ip("1.2.3.4")), "{bad}");
        }
    }

    #[test]
    fn address_families_never_cross_match() {
        assert!(!cidr_contains("::/0", ip("1.2.3.4")));
        assert!(!cidr_contains("0.0.0.0/0", ip("::1")));
    }
}
