//! Address screening for server-initiated HTTP (moved here from
//! `attome_server::ssrf_guard` by Q21-T1, so every crate that calls out,
//! foundation crates included, screens with the same code;
//! `attome_server::ssrf_guard` re-exports all of it).
//!
//! 1. [`is_globally_routable`] screens one address: loopback, private,
//!    link-local (the cloud metadata addresses among them), unspecified,
//!    multicast, the special-purpose blocks, and an IPv6 address that embeds
//!    an IPv4 address any of those.
//! 2. [`validate_url`] resolves a URL's host and screens every answer, the
//!    pre-flight check that also covers an IP-literal host.
//! 3. [`GuardedResolver`] screens the answer the connector actually dials,
//!    so a second, rebound DNS answer cannot slip past a pre-flight check.
//! 4. [`build_client`] wires the resolver into a `reqwest::Client` with
//!    environment proxies off and redirects off.
//!
//! A host an operator configured as private (see
//! [`super::Purpose::with_private_hosts`]) may resolve to a private or
//! loopback address; a cloud metadata address ([`is_metadata_address`]) is
//! refused for every host.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Loopback, private (RFC1918/ULA), link-local (including the
/// `169.254.169.254`/`fd00:ec2::254` cloud metadata addresses), unspecified,
/// multicast, and the IPv4 special-purpose blocks that are not private but
/// are equally never a legitimate target for a server-initiated fetch —
/// CGNAT shared space, `192.0.0.0/24`, benchmarking, and the reserved
/// `240.0.0.0/4` (B14). An IPv6 address that *embeds* an IPv4 address —
/// IPv4-mapped (`::ffff:a.b.c.d`), NAT64 well-known prefix (`64:ff9b::/96`),
/// or 6to4 (`2002::/16`) — is unwrapped and re-checked as the IPv4 address it
/// actually represents, since each of those is a route to that IPv4 host.
pub fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_globally_routable_v4(v4),
        IpAddr::V6(v6) => match embedded_ipv4(v6) {
            Some(v4) => is_globally_routable_v4(v4),
            None => is_globally_routable_v6(v6),
        },
    }
}

/// Q21-T1: an address no purpose may reach, allow-listed or not: link-local
/// (`169.254.0.0/16`, `fe80::/10`, which hold the AWS, GCP and Azure
/// metadata endpoints and the ECS task endpoint), AWS's IPv6 endpoint
/// `fd00:ec2::254` and Alibaba's `100.100.100.200`, including through an
/// IPv4-embedding IPv6 address.
pub fn is_metadata_address(ip: IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => embedded_ipv4(v6),
    };
    if let Some(v4) = v4 {
        return v4.is_link_local() || v4 == Ipv4Addr::new(100, 100, 100, 200);
    }
    match ip {
        IpAddr::V6(v6) => {
            v6.is_unicast_link_local() || v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
        }
        IpAddr::V4(_) => false,
    }
}

/// Whether `ip` may be dialed: a globally routable address always, any other
/// non-metadata address only for a host the purpose allows to be private.
pub fn is_permitted(ip: IpAddr, allow_private: bool) -> bool {
    if allow_private {
        !is_metadata_address(ip)
    } else {
        is_globally_routable(ip)
    }
}

/// The IPv4 address an IPv6 address is a transport for, if it is one:
/// IPv4-mapped (RFC 4291 §2.5.5.2), the NAT64 well-known prefix (RFC 6052
/// §2.1, IPv4 in the low 32 bits), or 6to4 (RFC 3056, IPv4 in bits 16-47).
/// A NAT64 gateway or 6to4 relay would deliver the packet to exactly that
/// IPv4 host, so it must be screened as that host — `64:ff9b::7f00:1` is
/// `127.0.0.1` with extra steps.
fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return Some(mapped);
    }
    let s = v6.segments();
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return Some(Ipv4Addr::from((u32::from(s[6]) << 16) | u32::from(s[7])));
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::from((u32::from(s[1]) << 16) | u32::from(s[2])));
    }
    None
}

fn is_globally_routable_v4(v4: Ipv4Addr) -> bool {
    let [a, b, c, _] = v4.octets();
    // RFC 6598 shared address space (carrier-grade NAT) — 100.64.0.0/10.
    let shared = a == 100 && (64..=127).contains(&b);
    // RFC 6890 IETF protocol assignments — 192.0.0.0/24, which includes the
    // PCP anycast and NAT64/DNS64 discovery addresses.
    let ietf_protocol_assignments = a == 192 && b == 0 && c == 0;
    // RFC 2544 benchmarking — 198.18.0.0/15.
    let benchmarking = a == 198 && (b == 18 || b == 19);
    // RFC 1112 §4 reserved — 240.0.0.0/4 (also covers the broadcast address,
    // kept explicit below for the reader).
    let reserved = a >= 240;
    // BSV-F08b: RFC 1122 "this network" — all of 0.0.0.0/8, not only the
    // unspecified address (Linux routes 0.x.y.z to the local host).
    let this_network = a == 0;
    !(v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_documentation()
        || shared
        || ietf_protocol_assignments
        || benchmarking
        || reserved
        || this_network)
}

fn is_globally_routable_v6(v6: Ipv6Addr) -> bool {
    let s = v6.segments();
    // BSV-F08b: none of these special-purpose blocks is a legitimate target.
    // Deprecated IPv4-compatible `::a.b.c.d` (RFC 4291 §2.5.5.1), ::/96.
    let ipv4_compatible = s[..6] == [0; 6];
    // RFC 8215 local-use NAT64, 64:ff9b:1::/48.
    let local_nat64 = s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1;
    // RFC 6666 discard-only, 100::/64.
    let discard_only = s[..4] == [0x100, 0, 0, 0];
    // RFC 4380 Teredo, 2001::/32 (tunnels to an IPv4 endpoint).
    let teredo = s[0] == 0x2001 && s[1] == 0;
    // RFC 5180 benchmarking, 2001:2::/48.
    let benchmarking = s[0] == 0x2001 && s[1] == 2 && s[2] == 0;
    // RFC 4843 ORCHID, 2001:10::/28.
    let orchid = s[0] == 0x2001 && (s[1] & 0xfff0) == 0x10;
    // RFC 3849 documentation, 2001:db8::/32.
    let documentation = s[0] == 0x2001 && s[1] == 0xdb8;
    // RFC 3879 deprecated site-local, fec0::/10.
    let site_local = (s[0] & 0xffc0) == 0xfec0;
    !(v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || v6.is_unique_local()
        || v6.is_unicast_link_local()
        || ipv4_compatible
        || local_nat64
        || discard_only
        || teredo
        || benchmarking
        || orchid
        || documentation
        || site_local)
}

#[derive(Debug, thiserror::Error)]
pub enum SsrfGuardError {
    #[error("unsupported URL scheme (only http/https may be dialed)")]
    UnsupportedScheme,
    #[error("URL has no host")]
    NoHost,
    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),
    #[error("resolved address is not publicly routable — refusing to connect")]
    AddressNotRoutable,
}

/// Screens a completed DNS answer, failing closed if any single address in
/// it is not globally routable — a hostname that round-robins between a
/// public and an internal address is still a hostname the guard refuses,
/// not a 50/50 chance per request. An empty answer is a resolution failure,
/// not a pass.
///
/// The whole answer is returned on success so a caller that is about to
/// *connect* uses exactly these addresses rather than resolving again; see
/// [`GuardedResolver`].
fn screen_answer(
    host: &str,
    addrs: Vec<SocketAddr>,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, SsrfGuardError> {
    if addrs.is_empty() {
        return Err(SsrfGuardError::DnsResolution(
            "no addresses returned".into(),
        ));
    }
    for addr in &addrs {
        if !is_permitted(addr.ip(), allow_private) {
            tracing::warn!(
                host,
                blocked_ip = %addr.ip(),
                "ssrf guard: refusing to connect, host resolved to a non-routable address"
            );
            return Err(SsrfGuardError::AddressNotRoutable);
        }
    }
    Ok(addrs)
}

/// Resolves `host` and screens every address through [`screen_answer`].
async fn resolve_and_check(host: &str, port: u16) -> Result<(), SsrfGuardError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| SsrfGuardError::DnsResolution(e.to_string()))?
        .collect();
    screen_answer(host, addrs, false).map(|_| ())
}

pub fn validate_scheme_and_host(url: &Url) -> Result<(&str, u16), SsrfGuardError> {
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(SsrfGuardError::UnsupportedScheme);
    }
    let host = url.host_str().ok_or(SsrfGuardError::NoHost)?;
    let port = url
        .port_or_known_default()
        .ok_or(SsrfGuardError::UnsupportedScheme)?;
    Ok((host, port))
}

/// Validates `url` (scheme + DNS/IP-range check) without connecting — the
/// pre-flight check every caller should run before opening a socket. Not a
/// substitute for [`GuardedResolver`] being installed on the client that
/// actually connects: DNS can answer differently between this call and the
/// real connect (rebinding), which is exactly the window `GuardedResolver`
/// closes.
pub async fn validate_url(url: &Url) -> Result<(), SsrfGuardError> {
    let (host, port) = validate_scheme_and_host(url)?;
    resolve_and_check(host, port).await
}

// ── DNS-rebinding pin ─────────────────────────────────────────────

/// The name lookup a [`GuardedResolver`] screens. Abstracted for exactly one
/// reason: so a test can substitute a lookup that returns a public address
/// on its first call and a private one on its second — the shape of a DNS
/// rebinding attack, which cannot be reproduced against the real resolver.
///
/// Production always uses [`SystemLookup`].
pub trait HostLookup: Send + Sync + 'static {
    fn lookup(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;
}

/// `getaddrinfo` on Tokio's blocking pool — the same call hyper-util's
/// default resolver makes, including its port-`0` convention (the connector
/// overwrites the port from the URL, so the resolver never needs to know it).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemLookup;

impl HostLookup for SystemLookup {
    fn lookup(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
        Box::pin(async move {
            tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map(|addrs| addrs.collect())
        })
    }
}

/// A `reqwest` DNS resolver that screens its own answer through
/// [`screen_answer`] and fails the connection when any address is not
/// globally routable.
///
/// This is the pin that closes the DNS-rebinding window. A pre-flight
/// [`validate_url`] runs *before* the request and resolves the host itself;
/// the connector then resolves the host *again* to open the socket. Those
/// are two independent lookups unless the same screening runs on both, so an
/// attacker controlling the authoritative server for a hostname could answer
/// the first one `93.184.216.34` and the second one `127.0.0.1` and reach a
/// loopback service — the pre-flight check passing says nothing about where
/// the socket actually goes.
///
/// Installing this resolver collapses the two into one: the answer the
/// connector dials is the answer that was screened, so there is no window
/// between the check and the connect for a second answer to arrive in. The
/// pre-flight [`validate_url`] still matters — it is not redundant, because
/// a URL whose host is an IP literal never reaches a resolver at all, and
/// because it lets an admin API reject an obviously-unsafe URL without
/// opening a socket.
pub struct GuardedResolver<L = SystemLookup> {
    lookup: L,
    /// Q21-T1: hosts (lower case) an operator configured as private.
    private_hosts: Arc<[String]>,
}

impl<L> std::fmt::Debug for GuardedResolver<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardedResolver").finish_non_exhaustive()
    }
}

impl GuardedResolver<SystemLookup> {
    pub fn new() -> Self {
        Self::with_lookup(SystemLookup)
    }
}

impl Default for GuardedResolver<SystemLookup> {
    fn default() -> Self {
        Self::new()
    }
}

impl<L: HostLookup> GuardedResolver<L> {
    /// Test-only seam — see [`HostLookup`].
    pub fn with_lookup(lookup: L) -> Self {
        Self::with_private_hosts(lookup, Arc::from([]))
    }

    /// Q21-T1: also lets `private_hosts` resolve to a private or loopback
    /// address (never a metadata address). The names come from operator
    /// configuration, never from a request.
    pub fn with_private_hosts(lookup: L, private_hosts: Arc<[String]>) -> Self {
        Self {
            lookup,
            private_hosts,
        }
    }
}

impl<L: HostLookup> Resolve for GuardedResolver<L> {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let allow_private = host_is_listed(&self.private_hosts, &host);
        let pending = self.lookup.lookup(host.clone());
        Box::pin(async move {
            let addrs = pending
                .await
                .map_err(|e| SsrfGuardError::DnsResolution(e.to_string()))?;
            let screened = screen_answer(&host, addrs, allow_private)?;
            Ok(Box::new(screened.into_iter()) as Addrs)
        })
    }
}

/// Whether `host` is one of `listed`, ignoring case and IPv6 brackets.
pub fn host_is_listed(listed: &[String], host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    listed.iter().any(|h| h.eq_ignore_ascii_case(bare))
}

/// Builds a `reqwest::Client` with [`GuardedResolver`] installed so no
/// connection can reach an address the routability check did not clear,
/// environment proxy discovery off (see the module doc), redirects
/// disabled (a caller that needs to follow one re-validates each hop
/// itself), and a bounded connect timeout so one unresponsive host can't
/// stall the caller. `request_timeout_secs` bounds the whole request.
pub fn build_client(request_timeout_secs: u64) -> Result<reqwest::Client, reqwest::Error> {
    build_client_with_lookup(request_timeout_secs, SystemLookup)
}

/// The body of [`build_client`], parameterised over the lookup so a test can
/// build a client with the identical configuration and a controllable
/// resolver. Keep every builder setting here, not in the caller.
pub fn build_client_with_lookup<L: HostLookup>(
    request_timeout_secs: u64,
    lookup: L,
) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        // B14: an HTTP_PROXY/HTTPS_PROXY/ALL_PROXY in the environment would
        // otherwise make reqwest hand the target hostname to the proxy
        // unresolved, skipping `GuardedResolver` entirely.
        .no_proxy()
        .dns_resolver(Arc::new(GuardedResolver::with_lookup(lookup)))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(request_timeout_secs))
        .build()
}

/// Scheme check plus, for an IP-literal host, the routability check the
/// resolver would otherwise never see. A hostname passes here and is screened
/// when it is resolved.
pub fn refuse_non_routable_literal(url: &Url) -> Result<(), SsrfGuardError> {
    let (host, _) = validate_scheme_and_host(url)?;
    // The WHATWG parser has already normalised integer/hex IPv4 forms to
    // dotted quads; an IPv6 literal arrives bracketed.
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let Ok(literal) = bare.parse::<IpAddr>() else {
        return Ok(());
    };
    if is_globally_routable(literal) {
        return Ok(());
    }
    tracing::warn!(
        blocked_ip = %literal,
        "ssrf guard: refusing to dial a non-routable IP literal"
    );
    Err(SsrfGuardError::AddressNotRoutable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const PUBLIC: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 0);
    const LOOPBACK: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    const METADATA: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 0);

    /// A lookup that hands out a different answer on each call — the DNS
    /// rebinding attack, which is otherwise unreproducible in a unit test.
    struct ScriptedLookup {
        answers: Vec<Vec<SocketAddr>>,
        calls: AtomicUsize,
    }

    impl ScriptedLookup {
        fn new(answers: Vec<Vec<SocketAddr>>) -> Self {
            Self {
                answers,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl HostLookup for ScriptedLookup {
        fn lookup(
            &self,
            _host: String,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            // Past the end of the script, keep serving the last answer.
            let addrs = self
                .answers
                .get(n)
                .or_else(|| self.answers.last())
                .cloned()
                .unwrap_or_default();
            Box::pin(async move { Ok(addrs) })
        }
    }

    /// `Addrs` is a boxed iterator and therefore not `Debug`, so collect it
    /// before asserting on the result.
    async fn resolve_screened<L: HostLookup>(
        resolver: &GuardedResolver<L>,
        host: &str,
    ) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
        resolver
            .resolve(Name::from_str(host).unwrap())
            .await
            .map(|addrs| addrs.collect())
    }

    fn chain_mentions(err: &dyn std::error::Error, needle: &str) -> bool {
        let mut cur = Some(err);
        while let Some(e) = cur {
            if e.to_string().contains(needle) {
                return true;
            }
            cur = e.source();
        }
        false
    }

    #[test]
    fn every_bsv_f08b_special_purpose_range_is_blocked() {
        for v4 in [Ipv4Addr::new(0, 0, 0, 1), Ipv4Addr::new(0, 255, 255, 255)] {
            assert!(!is_globally_routable(IpAddr::V4(v4)), "{v4}");
        }
        for v6 in [
            "::8.8.8.8",
            "::7f00:1",
            "64:ff9b:1::7f00:1",
            "64:ff9b:1:ffff::1",
            "2001::1",
            "2001:0:ffff::1",
            "2001:db8::1",
            "fec0::1",
            "feff::1",
            "100::1",
            "100::ffff:ffff:ffff:ffff",
            "2001:2::1",
            "2001:10::1",
            "2001:1f::1",
        ] {
            let ip: Ipv6Addr = v6.parse().unwrap();
            assert!(!is_globally_routable(IpAddr::V6(ip)), "{v6}");
        }
    }

    #[test]
    fn the_new_ranges_leave_their_neighbours_routable() {
        assert!(is_globally_routable(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1))));
        for v6 in [
            "64:ff9b:2::1",
            "100:0:0:1::1",
            "2001:3::1",
            "2001:20::1",
            "2001:db9::1",
            "2001:4860::8888",
            "fe00::1",
        ] {
            let ip: Ipv6Addr = v6.parse().unwrap();
            assert!(is_globally_routable(IpAddr::V6(ip)), "{v6}");
        }
    }

    #[test]
    fn public_ipv4_is_routable() {
        assert!(is_globally_routable(IpAddr::V4(Ipv4Addr::new(
            93, 184, 216, 34
        ))));
    }

    #[test]
    fn loopback_v4_is_blocked() {
        assert!(!is_globally_routable(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
    }

    #[test]
    fn private_ranges_v4_are_blocked() {
        for addr in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 5, 5),
            Ipv4Addr::new(192, 168, 1, 1),
        ] {
            assert!(
                !is_globally_routable(IpAddr::V4(addr)),
                "{addr} should be blocked"
            );
        }
    }

    #[test]
    fn cloud_metadata_address_is_blocked() {
        assert!(!is_globally_routable(IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
    }

    #[test]
    fn unspecified_and_multicast_v4_are_blocked() {
        assert!(!is_globally_routable(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!is_globally_routable(IpAddr::V4(Ipv4Addr::new(
            224, 0, 0, 1
        ))));
    }

    #[test]
    fn loopback_v6_is_blocked() {
        assert!(!is_globally_routable(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn unique_local_v6_is_blocked() {
        assert!(!is_globally_routable(IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn link_local_v6_is_blocked() {
        assert!(!is_globally_routable(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn ipv4_mapped_ipv6_wrapping_a_private_address_is_blocked() {
        let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001); // ::ffff:10.0.0.1
        assert!(!is_globally_routable(IpAddr::V6(mapped)));
    }

    #[test]
    fn ipv4_mapped_ipv6_wrapping_a_public_address_is_routable() {
        let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x5db8, 0xd822); // ::ffff:93.184.216.34
        assert!(is_globally_routable(IpAddr::V6(mapped)));
    }

    #[test]
    fn public_ipv6_is_routable() {
        assert!(is_globally_routable(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946
        ))));
    }

    // ── B14 residual ranges ─────────────────────────────────────────
    //
    // Each block is pinned from both sides: an address inside it (both
    // ends where the boundary is not obvious from the notation) must be
    // blocked, and the address immediately outside it must still be
    // routable, so a check that is off by one bit in either direction
    // fails here rather than in production.

    fn blocked(addrs: &[Ipv4Addr]) {
        for addr in addrs {
            assert!(
                !is_globally_routable(IpAddr::V4(*addr)),
                "{addr} should be blocked"
            );
        }
    }

    fn routable(addrs: &[Ipv4Addr]) {
        for addr in addrs {
            assert!(
                is_globally_routable(IpAddr::V4(*addr)),
                "{addr} should be routable"
            );
        }
    }

    /// RFC 6598 shared address space, 100.64.0.0/10 — a CGNAT-side host is
    /// as internal to a cloud tenant as RFC 1918 space is.
    #[test]
    fn cgnat_shared_space_is_blocked_and_its_neighbours_are_not() {
        blocked(&[
            Ipv4Addr::new(100, 64, 0, 0),
            Ipv4Addr::new(100, 100, 1, 1),
            Ipv4Addr::new(100, 127, 255, 255),
        ]);
        routable(&[
            Ipv4Addr::new(100, 63, 255, 255),
            Ipv4Addr::new(100, 128, 0, 0),
        ]);
    }

    /// RFC 6890 IETF protocol assignments, 192.0.0.0/24 (PCP anycast,
    /// NAT64/DNS64 discovery, DS-Lite).
    #[test]
    fn ietf_protocol_assignment_block_is_blocked_and_its_neighbours_are_not() {
        blocked(&[
            Ipv4Addr::new(192, 0, 0, 0),
            Ipv4Addr::new(192, 0, 0, 9),
            Ipv4Addr::new(192, 0, 0, 255),
        ]);
        routable(&[
            Ipv4Addr::new(191, 255, 255, 255),
            Ipv4Addr::new(192, 0, 1, 0),
        ]);
    }

    /// RFC 2544 benchmarking, 198.18.0.0/15 — two /16s, so both the
    /// 198.18 and 198.19 halves are pinned, plus the neighbour on each side.
    #[test]
    fn benchmarking_block_is_blocked_and_its_neighbours_are_not() {
        blocked(&[
            Ipv4Addr::new(198, 18, 0, 0),
            Ipv4Addr::new(198, 18, 255, 255),
            Ipv4Addr::new(198, 19, 0, 0),
            Ipv4Addr::new(198, 19, 255, 255),
        ]);
        routable(&[
            Ipv4Addr::new(198, 17, 255, 255),
            Ipv4Addr::new(198, 20, 0, 0),
        ]);
    }

    /// RFC 1112 reserved, 240.0.0.0/4 — everything from 240.0.0.0 up to and
    /// including the limited broadcast address.
    #[test]
    fn reserved_class_e_block_is_blocked_and_its_neighbour_is_not() {
        blocked(&[
            Ipv4Addr::new(240, 0, 0, 0),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::new(250, 1, 2, 3),
            Ipv4Addr::new(255, 255, 255, 254),
            Ipv4Addr::BROADCAST,
        ]);
        // 239.255.255.255 is the top of multicast, already blocked for its
        // own reason — the nearest *unicast* neighbour below the block is
        // the top of 223.0.0.0/8.
        routable(&[Ipv4Addr::new(223, 255, 255, 255)]);
    }

    /// NAT64 well-known prefix, 64:ff9b::/96 — the embedded IPv4 address is
    /// what a NAT64 gateway would deliver to, so it is what gets screened.
    #[test]
    fn nat64_embedding_a_private_address_is_blocked() {
        for v6 in [
            // 64:ff9b::7f00:1 → 127.0.0.1
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x7f00, 0x0001),
            // 64:ff9b::a00:1 → 10.0.0.1
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x0001),
            // 64:ff9b::a9fe:a9fe → 169.254.169.254
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xa9fe, 0xa9fe),
            // 64:ff9b::6440:1 → 100.64.0.1 (CGNAT, itself a B14 range)
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x6440, 0x0001),
        ] {
            assert!(
                !is_globally_routable(IpAddr::V6(v6)),
                "{v6} should be blocked"
            );
        }
    }

    #[test]
    fn nat64_embedding_a_public_address_is_routable() {
        // 64:ff9b::5db8:d822 → 93.184.216.34
        let v6 = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x5db8, 0xd822);
        assert!(is_globally_routable(IpAddr::V6(v6)));
    }

    /// The /96 is exact: 64:ff9b:1::/48 (RFC 8215 local-use NAT64) is a
    /// different prefix and must not be mistaken for an embedding — it is
    /// screened as a plain IPv6 address, not unwrapped.
    #[test]
    fn nat64_unwrap_is_limited_to_the_well_known_slash_96() {
        // 64:ff9b:1::7f00:1 — segment 2 is nonzero, so no unwrap happens
        // and the loopback-shaped tail is not what decides the answer.
        let not_the_prefix = Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0x7f00, 0x0001);
        assert_eq!(embedded_ipv4(not_the_prefix), None);
    }

    /// 6to4, 2002::/16 — the IPv4 address in bits 16-47 is the relay
    /// endpoint the packet is delivered to.
    #[test]
    fn six_to_four_embedding_a_private_address_is_blocked() {
        for v6 in [
            // 2002:7f00:1:: → 127.0.0.1
            Ipv6Addr::new(0x2002, 0x7f00, 0x0001, 0, 0, 0, 0, 0),
            // 2002:a00:1:: → 10.0.0.1
            Ipv6Addr::new(0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 0),
            // 2002:c0a8:101:: → 192.168.1.1
            Ipv6Addr::new(0x2002, 0xc0a8, 0x0101, 0, 0, 0, 0, 0),
            // 2002:a9fe:a9fe:: → 169.254.169.254
            Ipv6Addr::new(0x2002, 0xa9fe, 0xa9fe, 0, 0, 0, 0, 0),
            // 2002:c612:1:: → 198.18.0.1 (benchmarking, itself a B14 range)
            Ipv6Addr::new(0x2002, 0xc612, 0x0001, 0, 0, 0, 0, 0),
        ] {
            assert!(
                !is_globally_routable(IpAddr::V6(v6)),
                "{v6} should be blocked"
            );
        }
    }

    #[test]
    fn six_to_four_embedding_a_public_address_is_routable() {
        // 2002:5db8:d822:: → 93.184.216.34
        let v6 = Ipv6Addr::new(0x2002, 0x5db8, 0xd822, 0, 0, 0, 0, 1);
        assert!(is_globally_routable(IpAddr::V6(v6)));
    }

    /// The 6to4 match is on the first 16 bits only — 2001::/16 and
    /// 2003::/16 are ordinary global unicast and must not be unwrapped.
    #[test]
    fn six_to_four_unwrap_is_limited_to_2002_slash_16() {
        let neighbours = [
            Ipv6Addr::new(0x2001, 0x7f00, 0x0001, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2003, 0x7f00, 0x0001, 0, 0, 0, 0, 1),
        ];
        for v6 in neighbours {
            assert_eq!(embedded_ipv4(v6), None, "{v6} is not 6to4");
            assert!(
                is_globally_routable(IpAddr::V6(v6)),
                "{v6} is global unicast"
            );
        }
    }

    /// The unwrap decodes the IPv4 octets exactly — a byte-order slip would
    /// turn 10.0.0.1 into 1.0.0.10 and let it through.
    #[test]
    fn embedded_ipv4_decodes_the_expected_octets() {
        assert_eq!(
            embedded_ipv4(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001)),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(
            embedded_ipv4(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xc0a8, 0x0102)),
            Some(Ipv4Addr::new(192, 168, 1, 2))
        );
        assert_eq!(
            embedded_ipv4(Ipv6Addr::new(0x2002, 0xc0a8, 0x0102, 0, 0, 0, 0, 0)),
            Some(Ipv4Addr::new(192, 168, 1, 2))
        );
        assert_eq!(embedded_ipv4(Ipv6Addr::LOCALHOST), None);
    }

    // ── DNS-rebinding pin (SEC-4) ─────────────────────────────────

    /// The attack, exactly: the pre-flight lookup answers public, the
    /// connect-time lookup answers loopback. The resolver must refuse the
    /// second answer even though the first one passed.
    #[tokio::test]
    async fn resolver_refuses_an_answer_that_rebinds_to_loopback() {
        let resolver =
            GuardedResolver::with_lookup(ScriptedLookup::new(vec![vec![PUBLIC], vec![LOOPBACK]]));

        let first = resolve_screened(&resolver, "rebind.example")
            .await
            .expect("the public answer must resolve");
        assert_eq!(first, vec![PUBLIC]);

        let err = resolve_screened(&resolver, "rebind.example")
            .await
            .expect_err("the rebound loopback answer must be refused");
        assert!(
            err.to_string().contains("not publicly routable"),
            "unexpected error: {err}"
        );
    }

    /// The same, rebinding to the cloud metadata endpoint rather than
    /// loopback — the payload an SSRF against a cloud deployment is after.
    #[tokio::test]
    async fn resolver_refuses_a_rebind_to_the_cloud_metadata_address() {
        let resolver =
            GuardedResolver::with_lookup(ScriptedLookup::new(vec![vec![PUBLIC], vec![METADATA]]));
        assert!(resolve_screened(&resolver, "rebind.example").await.is_ok());
        assert!(resolve_screened(&resolver, "rebind.example").await.is_err());
    }

    /// Fail-closed on a mixed answer: one bad address poisons the whole
    /// resolution, matching `resolve_and_check`'s posture rather than
    /// filtering the bad address out and connecting to the rest.
    #[tokio::test]
    async fn resolver_refuses_an_answer_mixing_public_and_private_addresses() {
        let resolver =
            GuardedResolver::with_lookup(ScriptedLookup::new(vec![vec![PUBLIC, LOOPBACK]]));
        let err = resolve_screened(&resolver, "mixed.example")
            .await
            .expect_err("a mixed answer must be refused whole");
        assert!(
            err.to_string().contains("not publicly routable"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn resolver_refuses_an_empty_answer_rather_than_passing_it_through() {
        let resolver = GuardedResolver::with_lookup(ScriptedLookup::new(vec![vec![]]));
        let err = resolve_screened(&resolver, "empty.example")
            .await
            .expect_err("an empty answer is a failure, not a pass");
        assert!(
            err.to_string().contains("no addresses returned"),
            "unexpected error: {err}"
        );
    }

    /// Proves the resolver is actually installed on the client
    /// `build_client_with_lookup` returns, not merely defined: a request to
    /// a hostname that resolves to a live local listener must fail to
    /// connect. Without the pin this test gets a `200`.
    #[tokio::test]
    async fn the_built_client_cannot_connect_to_a_host_that_resolves_to_loopback() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind a local listener");
        let local = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK
Content-Length: 2

hi",
                    )
                    .await;
            }
        });

        let client = build_client_with_lookup(5, ScriptedLookup::new(vec![vec![local]]))
            .expect("build client");
        let err = client
            .get(format!("http://internal.example:{}/", local.port()))
            .send()
            .await
            .expect_err("the guarded resolver must refuse the loopback answer");
        assert!(
            chain_mentions(&err, "not publicly routable"),
            "unexpected error chain: {err:?}"
        );
    }

    /// The mirror of the above — the same client configuration hands a public
    /// answer through to the connector, so the guard is refusing an address
    /// rather than refusing everything. What happens on the wire afterwards is
    /// not this test's business — a 1s timeout bounds it, and the only
    /// assertion is that the failure, if there is one, did not come from the
    /// guard.
    ///
    /// The answer has to be a genuinely public unicast address, because every
    /// non-global special-purpose block is now something the guard blocks:
    /// 240.0.0.1 (this test's original choice, reserved space that answers
    /// nothing) fell to B14's `240.0.0.0/4` check, and 192.0.2.1/TEST-NET-1 is
    /// documentation space. `PUBLIC` is the same address the rebinding tests
    /// use as their "good" answer.
    #[tokio::test]
    async fn the_built_client_passes_a_public_answer_through_to_the_connector() {
        let public: SocketAddr = SocketAddr::new(PUBLIC.ip(), 80);
        assert!(
            is_globally_routable(public.ip()),
            "test premise: this address must pass the routability check"
        );

        let client = build_client_with_lookup(1, ScriptedLookup::new(vec![vec![public]]))
            .expect("build client");
        if let Err(err) = client.get("http://passthrough.example/").send().await {
            assert!(
                !chain_mentions(&err, "not publicly routable"),
                "the guard rejected a public address: {err:?}"
            );
        }
    }

    #[test]
    fn validate_scheme_and_host_rejects_a_non_http_scheme() {
        let url = Url::parse("ftp://example.com/file").unwrap();
        assert!(matches!(
            validate_scheme_and_host(&url),
            Err(SsrfGuardError::UnsupportedScheme)
        ));
    }

    /// An IP-literal host never reaches a resolver at all — the pre-flight
    /// check is what covers it. Loopback here proves `validate_url` screens
    /// a literal exactly the way it screens a resolved hostname.
    #[tokio::test]
    async fn validate_url_rejects_a_loopback_ip_literal() {
        let url = Url::parse("http://127.0.0.1/").unwrap();
        let err = validate_url(&url)
            .await
            .expect_err("a loopback literal must be rejected");
        assert!(matches!(err, SsrfGuardError::AddressNotRoutable));
    }

    // ── Q21-T1: metadata and per-purpose private hosts ────────────────

    #[test]
    fn metadata_addresses_are_never_permitted() {
        for ip in [
            "169.254.169.254",
            "169.254.170.2",
            "100.100.100.200",
            "fd00:ec2::254",
            "fe80::1",
            "::ffff:169.254.169.254",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_metadata_address(ip), "{ip}");
            assert!(!is_permitted(ip, true), "{ip}");
        }
        let private: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!is_metadata_address(private));
        assert!(is_permitted(private, true));
        assert!(!is_permitted(private, false));
    }

    #[tokio::test]
    async fn a_listed_host_may_resolve_privately_but_never_to_metadata() {
        let listed: Arc<[String]> = Arc::from(vec!["db.internal".to_owned()]);
        let resolver = GuardedResolver::with_private_hosts(
            ScriptedLookup::new(vec![vec![LOOPBACK], vec![METADATA]]),
            listed.clone(),
        );
        assert!(resolve_screened(&resolver, "DB.internal").await.is_ok());
        assert!(resolve_screened(&resolver, "db.internal").await.is_err());
        let other =
            GuardedResolver::with_private_hosts(ScriptedLookup::new(vec![vec![LOOPBACK]]), listed);
        assert!(resolve_screened(&other, "other.internal").await.is_err());
    }
}
