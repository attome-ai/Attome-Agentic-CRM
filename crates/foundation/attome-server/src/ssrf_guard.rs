//! Generic SSRF-safe outbound networking primitives — address-class
//! screening plus a connect-time IP-pinning DNS resolver for any engine that
//! makes a server-initiated HTTP request to an admin/caller-supplied URL.
//!
//! T1-11 (TECHNICAL-DUE-DILIGENCE-2026-08-24 §8, closes finding B12): this
//! module used to be private to `xrm-webcrawl::safety`, built for the web
//! crawler. `xrm-workflow`'s Webhook node dialed a bare `reqwest::Client`
//! with no address screening at all — a workflow author (an admin-level
//! role, but a lower-trust one than the deployment operator) could point a
//! webhook at `169.254.169.254` (cloud metadata) or an internal-only
//! service. Rather than duplicate the screening logic or give `xrm-workflow`
//! a dependency on `xrm-webcrawl` (a sibling engine crate with no other
//! reason to know about workflow), this crate is where both meet: `xrm-*`
//! already depends on `attome-server` for other reasons (`SecurityContext`,
//! `XrmState`-adjacent plumbing), so lifting the guard here adds no new
//! dependency edge for either consumer and keeps it below the layering
//! boundary (`base-*` has zero `xrm-*` knowledge — this module has none).
//!
//! What this module owns, and what it deliberately does not:
//!
//! 1. [`is_globally_routable`] screens a resolved address: rejects loopback,
//!    private (RFC1918/ULA), link-local (including the
//!    `169.254.169.254`/`fd00:ec2::254` cloud metadata addresses),
//!    unspecified, multicast, the B14 special-purpose blocks (CGNAT shared
//!    space, `192.0.0.0/24`, benchmarking, reserved `240.0.0.0/4`), and an
//!    IPv6 address that *embeds* an IPv4 address (IPv4-mapped, NAT64, 6to4)
//!    any of the above.
//! 2. [`validate_url`] resolves a URL's host itself and screens every
//!    returned address — the pre-flight check a caller runs before opening
//!    any connection, and what covers a URL whose host is an IP *literal*
//!    (which never reaches a resolver at all).
//! 3. [`GuardedResolver`] is a `reqwest` DNS resolver that re-screens its own
//!    answer, so the lookup whose answer the connector actually dials is the
//!    same lookup that was screened — without this, a pre-flight check and
//!    the real connection are two independent lookups, and a hostile
//!    authoritative server can answer the first with a public address and
//!    the second with `127.0.0.1` (DNS rebinding).
//! 4. [`build_client`]/[`build_client_with_lookup`] wire [`GuardedResolver`]
//!    into a `reqwest::Client`, with environment proxy discovery off
//!    (`no_proxy()`) — an `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` in the
//!    process environment would otherwise make the *proxy* resolve and dial
//!    the target host, bypassing this module entirely — and redirects
//!    disabled, since following one safely (re-validating each hop, capping
//!    the count) is caller-shape-specific.
//!
//! What stays with each caller: response handling. A redirect-following
//! loop with a hop cap, a streamed body-size cap, content-type filtering,
//! robots.txt — all of that is specific to the web crawler's fetch shape and
//! lives in `xrm-webcrawl::safety`. A workflow webhook's response handling
//! (status-code check, no body streaming needed) is specific to
//! `xrm-workflow::scheduler`. Callers should still run the connection
//! through [`build_client`]/[`validate_url`] rather than reinventing address
//! screening.
//!
//! No test-only bypass of any of the above lives in this module — a caller
//! that needs to test its own dispatch logic against a fake network should
//! do so against an injected trait/fake, not by weakening this guard.
//!
//! Q21-T1 moved the screening itself (items 1-4 above) to
//! `attome_outbound::http::guard`, below every crate that calls out, and
//! added `attome_outbound::http::client`, the one constructor for an outbound
//! client. This module re-exports the screening and keeps [`GuardedClient`],
//! which adds the request-correlation headers.

pub use attome_outbound::http::guard::{
    GuardedResolver, HostLookup, SsrfGuardError, SystemLookup, build_client,
    build_client_with_lookup, build_client_with_private_hosts, host_is_listed,
    is_globally_routable, is_metadata_address, refuse_non_routable_literal,
    validate_scheme_and_host, validate_url,
};
use reqwest::Url;

/// BSV-F08a (B5) — a client that refuses a non-routable IP **literal** before
/// dialing. hyper-util's connector short-circuits an IP-literal host without
/// calling the resolver, so a plain [`build_client`] relies on every caller
/// having run [`validate_url`] first. `GuardedClient` checks the literal on
/// every request itself; hostnames are still screened at dial time by the
/// installed [`GuardedResolver`].
#[derive(Clone, Debug)]
pub struct GuardedClient {
    inner: reqwest::Client,
    /// K6-T8: hosts this client may reach on a private address.
    private_hosts: std::sync::Arc<[String]>,
}

#[derive(Debug, thiserror::Error)]
pub enum GuardedRequestError {
    #[error(transparent)]
    Refused(#[from] SsrfGuardError),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

impl GuardedClient {
    pub fn new(request_timeout_secs: u64) -> Result<Self, reqwest::Error> {
        Self::with_lookup(request_timeout_secs, SystemLookup)
    }

    /// Test seam — see [`HostLookup`].
    pub fn with_lookup<L: HostLookup>(
        request_timeout_secs: u64,
        lookup: L,
    ) -> Result<Self, reqwest::Error> {
        Self::with_private_hosts(request_timeout_secs, lookup, std::sync::Arc::from([]))
    }

    /// K6-T8: a client that may also reach `private_hosts` (exact names, an
    /// administrator's choice) on a private address; a metadata address and
    /// every other private host stay refused.
    pub fn with_private_hosts<L: HostLookup>(
        request_timeout_secs: u64,
        lookup: L,
        private_hosts: std::sync::Arc<[String]>,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self {
            inner: build_client_with_private_hosts(
                request_timeout_secs,
                lookup,
                private_hosts.clone(),
            )?,
            private_hosts,
        })
    }

    /// The literal check, letting a listed host's private literal through
    /// (never a metadata address).
    fn refuse_literal(&self, url: &Url) -> Result<(), SsrfGuardError> {
        let (host, _) = validate_scheme_and_host(url)?;
        if host_is_listed(&self.private_hosts, host) {
            let bare = host.trim_start_matches('[').trim_end_matches(']');
            return match bare.parse::<std::net::IpAddr>() {
                Ok(ip) if is_metadata_address(ip) => Err(SsrfGuardError::AddressNotRoutable),
                _ => Ok(()),
            };
        }
        refuse_non_routable_literal(url)
    }

    /// Z5-T9: the request carries the current trace (`traceparent`) and the
    /// id of the request that caused it (`x-request-id`) when there are
    /// ones, so a webhook or connector call can be followed back to it. A job
    /// worker restores its producer's trace, so this holds for work done in
    /// the background too.
    pub fn request(
        &self,
        method: reqwest::Method,
        url: Url,
    ) -> Result<reqwest::RequestBuilder, SsrfGuardError> {
        self.refuse_literal(&url)?;
        let mut builder = self.inner.request(method, url);
        for (name, value) in correlation_headers() {
            builder = builder.header(name, value);
        }
        Ok(builder)
    }

    pub fn get(&self, url: Url) -> Result<reqwest::RequestBuilder, SsrfGuardError> {
        self.request(reqwest::Method::GET, url)
    }

    pub fn post(&self, url: Url) -> Result<reqwest::RequestBuilder, SsrfGuardError> {
        self.request(reqwest::Method::POST, url)
    }

    /// Re-checks the literal, because a built `Request`'s URL is mutable.
    pub async fn execute(
        &self,
        request: reqwest::Request,
    ) -> Result<reqwest::Response, GuardedRequestError> {
        self.refuse_literal(request.url())?;
        Ok(self.inner.execute(request).await?)
    }
}

/// Z5-T9: the trace and request-id headers for an outbound call made now.
fn correlation_headers() -> Vec<(&'static str, String)> {
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let mut headers = Vec::new();
    if let Some(traceparent) =
        attome_types::w3c_trace::format_current_traceparent(&tracing::Span::current().context())
    {
        headers.push(("traceparent", traceparent));
    }
    if let Some(request_id) = attome_types::request_scope::current() {
        headers.push(("x-request-id", request_id));
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Z5-T9: an outbound call names the request that caused it, and adds
    /// nothing when there is none.
    #[tokio::test]
    async fn guarded_request_carries_the_request_id() {
        let client = GuardedClient::new(5).expect("client");
        let url = Url::parse("https://example.com/hook").unwrap();
        let outside = client.post(url.clone()).unwrap().build().unwrap();
        assert!(outside.headers().get("x-request-id").is_none());
        let inside = attome_types::request_scope::scope("req-77".to_owned(), async {
            client.post(url).unwrap().build().unwrap()
        })
        .await;
        assert_eq!(inside.headers().get("x-request-id").unwrap(), "req-77");
    }

    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const PUBLIC: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 0);

    /// Counts lookups, so a test can show a literal never reaches one.
    struct CountingLookup {
        calls: AtomicUsize,
    }

    struct SharedLookup(Arc<CountingLookup>);

    impl HostLookup for SharedLookup {
        fn lookup(
            &self,
            _host: String,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
            self.0.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(vec![PUBLIC]) })
        }
    }

    #[tokio::test]
    async fn a_guarded_client_refuses_a_loopback_literal_without_validate_url() {
        let lookup = Arc::new(CountingLookup {
            calls: AtomicUsize::new(0),
        });
        let client = GuardedClient::with_lookup(1, SharedLookup(lookup.clone())).expect("client");
        for url in [
            "http://127.0.0.1:1/",
            "http://[::1]:1/",
            "http://169.254.169.254/latest/meta-data",
            "http://0.0.0.0:1/",
            "http://2130706433/",
        ] {
            let url = Url::parse(url).unwrap();
            assert!(
                matches!(
                    client.get(url.clone()),
                    Err(SsrfGuardError::AddressNotRoutable)
                ),
                "{url} must be refused before dialing"
            );
            let request = reqwest::Request::new(reqwest::Method::GET, url.clone());
            assert!(
                matches!(
                    client.execute(request).await,
                    Err(GuardedRequestError::Refused(
                        SsrfGuardError::AddressNotRoutable
                    ))
                ),
                "{url} must be refused by execute too"
            );
        }
        assert_eq!(
            lookup.calls.load(Ordering::SeqCst),
            0,
            "a literal never reaches the resolver"
        );
        assert!(
            client
                .get(Url::parse("http://example.com/").unwrap())
                .is_ok()
        );
        assert!(matches!(
            client.get(Url::parse("ftp://93.184.216.34/").unwrap()),
            Err(SsrfGuardError::UnsupportedScheme)
        ));
    }

    /// K6-T8: only the listed host's private literal passes; the metadata
    /// address never does.
    #[test]
    fn a_listed_private_host_is_the_only_private_literal_let_through() {
        let client =
            GuardedClient::with_private_hosts(1, SystemLookup, Arc::from(["10.0.0.5".to_owned()]))
                .expect("client");
        assert!(
            client
                .get(Url::parse("http://10.0.0.5/wiki").unwrap())
                .is_ok()
        );
        assert!(matches!(
            client.get(Url::parse("http://10.0.0.6/").unwrap()),
            Err(SsrfGuardError::AddressNotRoutable)
        ));
        let metadata = GuardedClient::with_private_hosts(
            1,
            SystemLookup,
            Arc::from(["169.254.169.254".to_owned()]),
        )
        .expect("client");
        assert!(matches!(
            metadata.get(Url::parse("http://169.254.169.254/").unwrap()),
            Err(SsrfGuardError::AddressNotRoutable)
        ));
    }
}
