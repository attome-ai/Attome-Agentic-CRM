//! SSRF-safe outbound fetch — the platform's first feature that makes an
//! HTTP request to an arbitrary, user-supplied URL. Every request the crawl
//! job makes goes through [`fetch_safely`], which:
//!
//! 1. Accepts only `http`/`https`.
//! 2. Resolves DNS itself and rejects any resolved address that is not
//!    globally routable (`attome_server::ssrf_guard::is_globally_routable`) —
//!    loopback, private, link-local (including the `169.254.169.254` cloud
//!    metadata address), unspecified, multicast, the B14 special-purpose
//!    blocks, or an IPv6 address embedding (IPv4-mapped, NAT64, 6to4) any of
//!    the above. This pre-flight check ([`validate_url`]) is also what
//!    covers a URL whose host is an IP *literal*, which never reaches a
//!    resolver at all.
//! 3. **Connects only to an address that check actually cleared.** The
//!    client is built with `attome_server::ssrf_guard::GuardedResolver`
//!    installed as its DNS resolver, so the lookup whose answer hyper dials
//!    is the same lookup that is screened — there is no second, unscreened
//!    resolution. Without this the pre-flight check in (2) and the
//!    connection were two independent lookups, and a hostile authoritative
//!    server could answer the first with a public address and the second
//!    with `127.0.0.1` (DNS rebinding).
//! 4. Never follows a redirect automatically (`redirect::Policy::none()`) —
//!    each `Location` is re-validated through the same checks before being
//!    followed, capped at [`MAX_REDIRECTS`] hops.
//! 5. Caps the response body at `max_page_bytes`, streamed — never buffers
//!    an attacker-controlled, potentially unbounded body.
//! 6. Only treats `text/html`/`text/plain` responses as a page to parse.
//! 7. Ignores any egress proxy the process environment advertises
//!    (`build_client` calls `no_proxy()`). With reqwest's default discovery
//!    left on, an `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` variable makes the
//!    *proxy* resolve and dial the target host, so the guarded resolver is
//!    never consulted and every check above is bypassed for the connection
//!    that actually happens (B14). A deployment that must egress through a
//!    proxy needs that proxy to enforce the same address policy; this crate
//!    will not silently hand it the job.
//!
//! T1-11 (TECHNICAL-DUE-DILIGENCE-2026-08-24 §8, closes finding B12): the
//! address-screening core (routability check, `GuardedResolver`,
//! `build_client`) used to live entirely in this module. It moved to
//! `attome_server::ssrf_guard` so `attome-workflow`'s Webhook node — which had no
//! SSRF protection at all — could reuse it without this crawler-specific
//! crate depending on `attome-workflow`, or vice versa. What stays here is
//! crawler-shape-specific: the redirect-following loop, the body-size cap,
//! content-type filtering, and robots.txt.
//!
//! **K6-T8: one intranet host per source.** A source may name `allow_host`:
//! exactly that host (an administrator's choice, audited) may resolve to a
//! private address, through the same guarded resolver; a metadata address
//! and every other private host stay refused, and each redirect hop is
//! checked again, so a hop off the allowed host to another private address
//! is refused. The source's credential headers ([`SourceAccess`]) go only to
//! the source's own host and are never logged.
//!
//! No test-only bypass of any of the above lives in this module — the crawl
//! algorithm in `crate::crawl` is tested against a fake in-memory `Fetcher`
//! instead (see that module), so nothing here needs an escape hatch.

use attome_server::ssrf_guard::{self, SsrfGuardError};
use reqwest::{StatusCode, Url};

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("unsupported URL scheme (only http/https are crawled)")]
    UnsupportedScheme,
    #[error("URL has no host")]
    NoHost,
    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),
    #[error("resolved address is not publicly routable — refusing to fetch")]
    AddressNotRoutable,
    #[error("too many redirects")]
    TooManyRedirects,
    #[error("redirect had no or an invalid Location header")]
    InvalidRedirect,
    #[error("response exceeded the {0} byte cap")]
    TooLarge(usize),
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("HTTP {0}")]
    HttpStatus(StatusCode),
}

impl From<SsrfGuardError> for FetchError {
    fn from(e: SsrfGuardError) -> Self {
        match e {
            SsrfGuardError::UnsupportedScheme => FetchError::UnsupportedScheme,
            SsrfGuardError::NoHost => FetchError::NoHost,
            SsrfGuardError::DnsResolution(msg) => FetchError::DnsResolution(msg),
            SsrfGuardError::AddressNotRoutable => FetchError::AddressNotRoutable,
        }
    }
}

#[derive(Default)]
pub struct FetchedPage {
    pub content_type: String,
    pub body: String,
    /// K6-T2: the validators to send next time (`ETag`, `Last-Modified`).
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// K6-T2: the server answered 304, so `body` is empty and the stored
    /// page is still current.
    pub not_modified: bool,
}

impl std::fmt::Debug for FetchedPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchedPage").finish_non_exhaustive()
    }
}

const MAX_REDIRECTS: u8 = 5;

/// K6-T8: what one source may reach and sign in with.
#[derive(Clone, Default)]
pub struct SourceAccess {
    /// The one host this source may reach on a private address.
    pub allow_host: Option<String>,
    /// Sign-in headers, sent only to `credential_host`.
    pub headers: Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
    /// The source's own host.
    pub credential_host: Option<String>,
}

impl std::fmt::Debug for SourceAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceAccess")
            .field("allow_host", &self.allow_host)
            .finish_non_exhaustive()
    }
}

impl SourceAccess {
    fn host_is(expected: Option<&str>, url: &Url) -> bool {
        match (expected, url.host_str()) {
            (Some(expected), Some(host)) => {
                ssrf_guard::host_is_listed(&[expected.to_owned()], host)
            }
            _ => false,
        }
    }

    /// Whether `url` is on the allowed intranet host.
    pub fn allows_private(&self, url: &Url) -> bool {
        Self::host_is(self.allow_host.as_deref(), url)
    }

    /// Whether `url` gets the sign-in headers.
    pub fn signs(&self, url: &Url) -> bool {
        !self.headers.is_empty() && Self::host_is(self.credential_host.as_deref(), url)
    }
}

/// K6-T8: [`validate_url`], except that the source's allowed host passes
/// with only its scheme and host checked; the client's resolver and literal
/// check still refuse a metadata address there.
pub async fn validate_url_for(url: &Url, access: &SourceAccess) -> Result<(), FetchError> {
    if access.allows_private(url) {
        ssrf_guard::validate_scheme_and_host(url)?;
        return Ok(());
    }
    validate_url(url).await
}

/// K6-T8: the client for a source: [`build_client`], also letting the
/// source's allowed host resolve to a private address.
pub fn build_client_for(
    request_timeout_secs: u64,
    access: &SourceAccess,
) -> Result<ssrf_guard::GuardedClient, reqwest::Error> {
    let hosts: std::sync::Arc<[String]> = access.allow_host.iter().cloned().collect();
    ssrf_guard::GuardedClient::with_private_hosts(
        request_timeout_secs,
        ssrf_guard::SystemLookup,
        hosts,
    )
}

/// A redirect's next URL.
fn redirect_target(current: &Url, location: &str) -> Result<Url, FetchError> {
    current
        .join(location)
        .map_err(|_| FetchError::InvalidRedirect)
}

/// Validates `url` (scheme + DNS/IP-range check) without fetching it — used
/// both by [`fetch_safely`] before every hop and by the admin API's
/// `POST /targets` handler for fast client feedback on an obviously-unsafe
/// URL (the job re-validates regardless, since DNS can change between
/// submission and crawl). Delegates to the shared guard's
/// `attome_server::ssrf_guard::validate_url` — see this module's doc comment.
pub async fn validate_url(url: &Url) -> Result<(), FetchError> {
    ssrf_guard::validate_url(url)
        .await
        .map_err(FetchError::from)
}

/// Fetches `url` under the full SSRF-safe contract described in this
/// module's doc comment. `max_bytes` bounds the streamed response body.
pub async fn fetch_safely(
    client: &ssrf_guard::GuardedClient,
    url: &Url,
    max_bytes: usize,
    user_agent: &str,
) -> Result<FetchedPage, FetchError> {
    fetch_conditional(
        client,
        url,
        max_bytes,
        user_agent,
        None,
        None,
        &SourceAccess::default(),
    )
    .await
}

/// [`fetch_safely`] with the validators from the last crawl (K6-T2): a 304
/// answer comes back as `not_modified` with no body.
pub async fn fetch_conditional(
    client: &ssrf_guard::GuardedClient,
    url: &Url,
    max_bytes: usize,
    user_agent: &str,
    etag: Option<&str>,
    last_modified: Option<&str>,
    access: &SourceAccess,
) -> Result<FetchedPage, FetchError> {
    let mut current = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        validate_url_for(&current, access).await?;

        let mut request = client
            .get(current.clone())?
            .header(reqwest::header::USER_AGENT, user_agent);
        if access.signs(&current) {
            for (name, value) in &access.headers {
                request = request.header(name.clone(), value.clone());
            }
        }
        if let Some(tag) = etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, tag);
        }
        if let Some(since) = last_modified {
            request = request.header(reqwest::header::IF_MODIFIED_SINCE, since);
        }
        let resp = request.send().await?;

        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(FetchedPage {
                not_modified: true,
                etag: etag.map(str::to_owned),
                last_modified: last_modified.map(str::to_owned),
                ..FetchedPage::default()
            });
        }

        if resp.status().is_redirection() {
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or(FetchError::InvalidRedirect)?;
            current = redirect_target(&current, location)?;
            continue;
        }

        if !resp.status().is_success() {
            return Err(FetchError::HttpStatus(resp.status()));
        }

        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let header = |name: reqwest::header::HeaderName| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let etag = header(reqwest::header::ETAG);
        let last_modified = header(reqwest::header::LAST_MODIFIED);
        let body = read_capped_body(resp, max_bytes).await?;
        return Ok(FetchedPage {
            content_type,
            body,
            etag,
            last_modified,
            not_modified: false,
        });
    }
    Err(FetchError::TooManyRedirects)
}

async fn read_capped_body(resp: reqwest::Response, max_bytes: usize) -> Result<String, FetchError> {
    use futures_util::StreamExt;

    let mut buf = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if buf.len() + chunk.len() > max_bytes {
            return Err(FetchError::TooLarge(max_bytes));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Builds the client every crawl uses: `attome_server::ssrf_guard::GuardedClient`
/// — see this module's doc comment for what that gives every caller (literal
/// check per request, guarded resolver, no redirects, no environment proxy,
/// bounded timeouts).
pub fn build_client(
    request_timeout_secs: u64,
) -> Result<ssrf_guard::GuardedClient, reqwest::Error> {
    ssrf_guard::GuardedClient::new(request_timeout_secs)
}

// ── robots.txt ───────────────────────────────────────────────────────────────

/// Best-effort `Disallow` rule set for our user-agent and `*`. A fetch
/// failure (no robots.txt, network error, non-2xx) means allow-all, never
/// deny-all — the same "absence is not a signal" posture the rest of the
/// crawler takes toward missing metadata.
#[derive(Debug, Default, Clone)]
pub struct RobotsRules {
    disallow: Vec<String>,
    /// K6-T2: the `Crawl-delay` of the `*` block, in seconds.
    crawl_delay: Option<f64>,
}

impl RobotsRules {
    /// The `Crawl-delay` the site asks for, capped at a minute.
    pub fn crawl_delay(&self) -> Option<std::time::Duration> {
        self.crawl_delay
            .filter(|d| d.is_finite() && *d > 0.0)
            .map(|d| std::time::Duration::from_secs_f64(d.min(60.0)))
    }

    pub fn allows(&self, path: &str) -> bool {
        !self
            .disallow
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()))
    }

    /// Parses the subset of the robots.txt format this crawler needs:
    /// `User-agent: *` / `Disallow: <path>` blocks, case-insensitive
    /// directive names, blank/`#`-comment lines ignored. Only the `*`
    /// block's rules are collected — a crawler this narrow (same-origin,
    /// admin-triggered, capped pages) has no distinct identity worth a
    /// dedicated `User-agent` stanza.
    pub fn parse(body: &str) -> Self {
        let mut disallow = Vec::new();
        let mut crawl_delay = None;
        let mut in_wildcard_block = false;
        for line in body.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let Some((directive, value)) = line.split_once(':') else {
                continue;
            };
            let directive = directive.trim().to_ascii_lowercase();
            let value = value.trim();
            match directive.as_str() {
                "user-agent" => in_wildcard_block = value == "*",
                "disallow" if in_wildcard_block && !value.is_empty() => {
                    disallow.push(value.to_string());
                }
                "crawl-delay" if in_wildcard_block => {
                    crawl_delay = value.parse::<f64>().ok();
                }
                _ => {}
            }
        }
        Self {
            disallow,
            crawl_delay,
        }
    }
}

pub async fn fetch_robots_rules(
    client: &ssrf_guard::GuardedClient,
    origin: &Url,
    user_agent: &str,
    access: &SourceAccess,
) -> RobotsRules {
    let Ok(robots_url) = origin.join("/robots.txt") else {
        return RobotsRules::default();
    };
    match fetch_conditional(
        client,
        &robots_url,
        1_000_000,
        user_agent,
        None,
        None,
        access,
    )
    .await
    {
        Ok(page) => RobotsRules::parse(&page.body),
        Err(_) => RobotsRules::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Address-class screening, `GuardedResolver`, and `build_client` are
    // tested once, in `attome_server::ssrf_guard`, which now owns them (T1-11).
    // What is left here is crawler-shape-specific: robots.txt parsing, and a
    // smoke test that this module's `validate_url`/`build_client` wrappers
    // actually delegate rather than silently drifting from the shared guard.

    /// `validate_url` must be a real delegation, not a stub: a loopback URL
    /// is rejected the same way `attome_server::ssrf_guard::validate_url`
    /// rejects it, and the error converts through `FetchError` intact.
    #[tokio::test]
    async fn validate_url_delegates_to_the_shared_guard() {
        let url = Url::parse("http://127.0.0.1/").unwrap();
        let err = validate_url(&url)
            .await
            .expect_err("a loopback literal must be rejected");
        assert!(matches!(err, FetchError::AddressNotRoutable));
    }

    /// BSV-F08a (B5): the crawl client itself refuses a loopback literal, so
    /// a path that skipped `validate_url` still cannot dial it.
    #[test]
    fn the_crawl_client_refuses_a_loopback_literal_without_validate_url() {
        let client = build_client(5).expect("client builds");
        let url = Url::parse("http://127.0.0.1/").unwrap();
        let err = client
            .get(url)
            .expect_err("a loopback literal must be refused");
        assert!(matches!(
            FetchError::from(err),
            FetchError::AddressNotRoutable
        ));
    }

    #[test]
    fn robots_disallow_blocks_matching_prefix_only_in_wildcard_block() {
        let rules = RobotsRules::parse(
            "User-agent: SomeOtherBot\nDisallow: /public\n\nUser-agent: *\nDisallow: /private\nDisallow: /admin\n",
        );
        assert!(rules.allows("/public"));
        assert!(!rules.allows("/private"));
        assert!(!rules.allows("/private/sub"));
        assert!(!rules.allows("/admin"));
        assert!(rules.allows("/"));
    }

    #[test]
    fn robots_crawl_delay_is_read_and_capped() {
        let rules = RobotsRules::parse("User-agent: *\nCrawl-delay: 2.5\n");
        assert_eq!(
            rules.crawl_delay(),
            Some(std::time::Duration::from_millis(2500))
        );
        let greedy = RobotsRules::parse("User-agent: *\nCrawl-delay: 3600\n");
        assert_eq!(
            greedy.crawl_delay(),
            Some(std::time::Duration::from_secs(60))
        );
        assert_eq!(RobotsRules::parse("User-agent: *\n").crawl_delay(), None);
    }

    #[test]
    fn robots_with_no_wildcard_block_allows_everything() {
        let rules = RobotsRules::parse("User-agent: SomeOtherBot\nDisallow: /everything\n");
        assert!(rules.allows("/everything"));
    }

    #[test]
    fn robots_comments_and_blank_lines_are_ignored() {
        let rules =
            RobotsRules::parse("# a comment\n\nUser-agent: *\n# another comment\nDisallow: /x\n");
        assert!(!rules.allows("/x"));
        assert!(rules.allows("/y"));
    }

    fn intranet() -> SourceAccess {
        SourceAccess {
            allow_host: Some("10.0.0.5".to_owned()),
            headers: vec![(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_static("Basic c2VjcmV0"),
            )],
            credential_host: Some("10.0.0.5".to_owned()),
        }
    }

    #[tokio::test]
    async fn allow_host_only_named_host_reachable() {
        let access = intranet();
        let url = Url::parse("http://10.0.0.5/wiki/start").unwrap();
        assert!(validate_url_for(&url, &access).await.is_ok());
        let client = build_client_for(1, &access).expect("client");
        assert!(client.get(url.clone()).is_ok());
        assert!(access.signs(&url), "the source's own host gets its sign-in");
        let none = SourceAccess::default();
        assert!(matches!(
            validate_url_for(&url, &none).await,
            Err(FetchError::AddressNotRoutable)
        ));
    }

    #[tokio::test]
    async fn allow_host_other_private_refused() {
        let access = intranet();
        for other in [
            "http://10.0.0.6/",
            "http://127.0.0.1/",
            "http://169.254.169.254/",
        ] {
            let url = Url::parse(other).unwrap();
            assert!(
                matches!(
                    validate_url_for(&url, &access).await,
                    Err(FetchError::AddressNotRoutable)
                ),
                "{other} stays refused"
            );
            let client = build_client_for(1, &access).expect("client");
            assert!(
                client.get(url).is_err(),
                "{other} is refused by the client too"
            );
        }
    }

    #[tokio::test]
    async fn allow_host_redirect_off_host_refused() {
        let access = intranet();
        let current = Url::parse("http://10.0.0.5/wiki").unwrap();
        let hop = redirect_target(&current, "http://10.0.0.9/admin").unwrap();
        assert!(matches!(
            validate_url_for(&hop, &access).await,
            Err(FetchError::AddressNotRoutable)
        ));
        assert!(
            !access.signs(&hop),
            "credentials never follow a hop off the host"
        );
        let same = redirect_target(&current, "/wiki/next").unwrap();
        assert!(validate_url_for(&same, &access).await.is_ok());
    }
}
