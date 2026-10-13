use attome_config::AppConfig;
use axum::{
    extract::{ConnectInfo, Request},
    http::HeaderMap,
};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// Resolve a client address without trusting an arbitrary caller-supplied
/// forwarding header. `X-Forwarded-For` is considered only when the immediate
/// TCP peer is in `security.trusted_proxy_cidrs`; then walk from the right so a
/// forged left-most value cannot select the rate-limit bucket.
///
/// BSV-F17 (B6): every address is canonicalised, so an IPv4-mapped IPv6 peer
/// (`::ffff:a.b.c.d`, a dual-stack bind) is the IPv4 address it carries.
/// BSV-F18 (B7): the walk covers every `X-Forwarded-For` header line, last
/// line first — a proxy that appends its own line after a forged one must not
/// leave the forged line in charge.
pub fn client_ip(req: &Request, config: &AppConfig) -> Option<IpAddr> {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>()?.0.ip();
    Some(client_ip_from_parts(peer, req.headers(), config))
}

/// Same resolution as [`client_ip`], for a handler that already extracted
/// `ConnectInfo<SocketAddr>`/`HeaderMap` itself (e.g. because it also needs a
/// body-consuming extractor like `Json<T>` in the same signature, which rules
/// out taking a whole `Request`). Both this function and [`client_ip`] share
/// one trusted-proxy walk (`forwarded_client_ip`) so the two call shapes can
/// never disagree about which address is trusted.
pub fn client_ip_from_parts(peer: IpAddr, headers: &HeaderMap, config: &AppConfig) -> IpAddr {
    forwarded_client_ip(peer, headers, |ip| config.is_trusted_proxy(ip))
}

/// BSV-F16 (B6): the per-IP rate-limit subject. IPv4 is bucketed per address;
/// IPv6 by its `ipv6_prefix`-bit network (default /64, one host's usual
/// allocation), so rotating addresses inside it shares one bucket.
pub(crate) fn rate_limit_subject(ip: IpAddr, ipv6_prefix: u8) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let prefix = u32::from(ipv6_prefix.min(128));
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            let network = Ipv6Addr::from(u128::from(v6) & mask);
            format!("{network}/{prefix}")
        }
    }
}

fn forwarded_client_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    is_trusted_proxy: impl Fn(IpAddr) -> bool,
) -> IpAddr {
    let peer = peer.to_canonical();
    if !is_trusted_proxy(peer) {
        return peer;
    }

    let mut lines = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let Ok(line) = value.to_str() else {
            // A malformed trusted-proxy header must never create a spoofable
            // fallback. Keep the known socket peer instead.
            return peer;
        };
        lines.push(line);
    }

    for candidate in lines.iter().rev().flat_map(|line| line.split(',').rev()) {
        let Ok(candidate) = candidate.trim().parse::<IpAddr>() else {
            return peer;
        };
        let candidate = candidate.to_canonical();
        if !is_trusted_proxy(candidate) {
            return candidate;
        }
    }

    peer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(forwarded_for: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(forwarded_for) = forwarded_for {
            headers.insert("x-forwarded-for", forwarded_for.parse().unwrap());
        }
        headers
    }

    #[test]
    fn ignores_forwarded_for_from_an_untrusted_socket_peer() {
        let peer = "198.51.100.8".parse().unwrap();
        assert_eq!(
            forwarded_client_ip(peer, &headers(Some("1.2.3.4")), |_| false),
            peer
        );
    }

    #[test]
    fn selects_the_rightmost_untrusted_hop_from_a_trusted_proxy() {
        let peer = "10.0.0.10".parse().unwrap();
        assert_eq!(
            forwarded_client_ip(
                peer,
                &headers(Some("1.2.3.4, 203.0.113.9, 10.0.0.5")),
                |ip| ip.to_string().starts_with("10."),
            ),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn mapped_ipv4_peer_matches_an_ipv4_trusted_proxy_cidr() {
        let peer: IpAddr = "::ffff:10.0.0.10".parse().unwrap();
        let is_v4_proxy = |ip: IpAddr| matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 10);
        assert_eq!(
            forwarded_client_ip(peer, &headers(Some("203.0.113.9")), is_v4_proxy),
            "203.0.113.9".parse::<IpAddr>().unwrap(),
            "a mapped peer must be trusted as the IPv4 proxy it is"
        );
        assert_eq!(
            forwarded_client_ip(peer, &headers(None), |_| false),
            "10.0.0.10".parse::<IpAddr>().unwrap(),
            "the socket peer itself is reported canonically"
        );
    }

    #[test]
    fn a_forged_first_forwarded_for_line_is_ignored_when_the_proxy_appends_a_second() {
        let peer = "10.0.0.10".parse().unwrap();
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", "1.2.3.4".parse().unwrap());
        h.append("x-forwarded-for", "203.0.113.9".parse().unwrap());
        assert_eq!(
            forwarded_client_ip(peer, &h, |ip| ip.to_string().starts_with("10.")),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn ipv6_addresses_in_one_slash_64_share_a_rate_limit_bucket() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:fffe".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(rate_limit_subject(a, 64), rate_limit_subject(b, 64));
        assert_eq!(rate_limit_subject(a, 64), "2001:db8:1:2::/64");
        assert_ne!(rate_limit_subject(a, 64), rate_limit_subject(other, 64));
        assert_ne!(rate_limit_subject(a, 128), rate_limit_subject(b, 128));
    }

    #[test]
    fn ipv4_mapped_ipv6_buckets_as_its_ipv4_address() {
        let mapped: IpAddr = "::ffff:198.51.100.8".parse().unwrap();
        assert_eq!(rate_limit_subject(mapped, 64), "198.51.100.8");
        assert_eq!(
            rate_limit_subject("198.51.100.8".parse().unwrap(), 64),
            "198.51.100.8"
        );
    }

    #[test]
    fn fails_closed_on_a_malformed_forwarded_for_header() {
        let peer = "10.0.0.10".parse().unwrap();
        assert_eq!(
            forwarded_client_ip(peer, &headers(Some("not-an-ip")), |_| true),
            peer
        );
    }
}
