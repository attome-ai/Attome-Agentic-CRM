//! Q21-T1: the one way a server-side component builds an HTTP client.
//!
//! Every call out (a model provider, a payment gateway, a customer's
//! webhook, a vendor API, the CLI talking to its server) goes through a
//! client from [`client`], which names a [`Purpose`]. That client:
//!
//! - dials only globally routable addresses, except hosts the purpose lists
//!   as private (operator configuration: an on-prem system, a local model
//!   server); a cloud metadata address is refused for every purpose;
//! - screens what it actually dials: a host name when it resolves
//!   ([`guard::GuardedResolver`]), an IP-literal host on every request
//!   ([`Outbound`]), and each redirect hop;
//! - ignores `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, which would resolve the
//!   host outside the guard. A proxy the operator configured
//!   (`deployment.outbound_proxy`, set at boot with [`configure_proxy`])
//!   carries the calls to public hosts; a host the purpose lists as private
//!   is reached directly. Through a proxy the guard still refuses a private
//!   or metadata IP literal and screens every redirect, but the proxy, not
//!   the guard, resolves host names: its own egress rules apply to them.
//!
//! `crates/apps/attome/tests/outbound_client_guard.rs` fails when code
//! outside this module builds a `reqwest` client itself.

pub mod guard;

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use reqwest::{Method, RequestBuilder, Url, redirect};

use guard::{
    GuardedResolver, HostLookup, SsrfGuardError, SystemLookup, host_is_listed, is_permitted,
};

/// The scheme a refused request is rewritten to, so it fails in `send()`
/// with reqwest's "URL scheme is not allowed" and names the refused host,
/// without ever dialing.
pub const REFUSED_SCHEME: &str = "refused-by-ssrf-guard";

/// Q21-T1: the operator's proxy for calls to public hosts, if any.
static PROXY: OnceLock<Option<Url>> = OnceLock::new();

/// Sets the proxy every client built after this uses for public hosts
/// (`deployment.outbound_proxy`). Call once at boot, before the first client;
/// answers false when it was already set. `None` means no proxy.
pub fn configure_proxy(proxy: Option<Url>) -> bool {
    PROXY.set(proxy).is_ok()
}

/// How many redirects a purpose follows unless it says otherwise.
const DEFAULT_REDIRECTS: usize = 10;

/// Why a component calls out, and which hosts it may reach privately.
#[derive(Clone, Debug)]
pub struct Purpose {
    name: &'static str,
    private_hosts: Arc<[String]>,
    redirects: usize,
}

impl Purpose {
    /// Reaches globally routable addresses only, following up to ten
    /// redirects (each one screened).
    pub fn public(name: &'static str) -> Self {
        Self {
            name,
            private_hosts: Arc::from([]),
            redirects: DEFAULT_REDIRECTS,
        }
    }

    /// Also lets `hosts` resolve to a private or loopback address. The names
    /// come from operator configuration or one connector's own settings,
    /// never from a request, and each purpose lists its own: there is no
    /// global allow-list. A metadata address stays refused.
    pub fn with_private_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut all: Vec<String> = self.private_hosts.iter().cloned().collect();
        all.extend(
            hosts
                .into_iter()
                .map(|h| {
                    let h: String = h.into();
                    h.trim_start_matches('[')
                        .trim_end_matches(']')
                        .to_ascii_lowercase()
                })
                .filter(|h| !h.is_empty()),
        );
        self.private_hosts = all.into();
        self
    }

    /// The host of each of `urls` that parses, as [`Self::with_private_hosts`]:
    /// for a purpose whose configuration names a base URL.
    pub fn with_private_urls<'a>(self, urls: impl IntoIterator<Item = &'a str>) -> Self {
        let hosts: Vec<String> = urls
            .into_iter()
            .filter_map(|u| Url::parse(u).ok()?.host_str().map(str::to_owned))
            .collect();
        self.with_private_hosts(hosts)
    }

    /// Follows no redirect (a token exchange, say, where one is an error).
    pub fn no_redirects(self) -> Self {
        self.max_redirects(0)
    }

    /// Follows at most `n` redirects, each one screened.
    pub fn max_redirects(mut self, n: usize) -> Self {
        self.redirects = n;
        self
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Whether this purpose lists `host` as private (reached directly, never
    /// through the proxy).
    fn lists(&self, host: &str) -> bool {
        host_is_listed(
            &self.private_hosts,
            host.trim_start_matches('[').trim_end_matches(']'),
        )
    }

    /// Whether `url` may be dialed as far as its host is an IP literal; a
    /// host name is decided when it resolves.
    pub fn allows_literal(&self, url: &Url) -> bool {
        let Some(host) = url.host_str() else {
            return true;
        };
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        match bare.parse::<IpAddr>() {
            Ok(ip) => is_permitted(ip, host_is_listed(&self.private_hosts, bare)),
            Err(_) => true,
        }
    }
}

/// Builds the client for `purpose`. `configure` sets what the caller needs
/// (timeouts, a user agent, default headers, a TLS identity); the guard's
/// settings are applied after it, so it cannot undo them. A connect timeout
/// of ten seconds applies unless `configure` sets another.
pub fn client(
    purpose: Purpose,
    configure: impl FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
) -> Result<Outbound, reqwest::Error> {
    client_with_lookup(purpose, SystemLookup, configure)
}

/// [`client`] for a process-lifetime client kept in a `OnceLock`. When the
/// configured client cannot be built it logs why and builds one with the
/// guard's settings only; when that fails too the TLS backend cannot start,
/// and it panics as `reqwest::Client::new()` does in the same case.
pub fn shared(
    purpose: Purpose,
    configure: impl FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
) -> Outbound {
    let name = purpose.name;
    client(purpose.clone(), configure)
        .or_else(|error| {
            tracing::error!(purpose = name, %error, "outbound: the configured HTTP client could not be built; using the defaults");
            client(purpose, |b| b)
        })
        .unwrap_or_else(|error| panic!("outbound: no HTTP client can be built for {name}: {error}"))
}

/// [`client`] with the name lookup replaced, for a test.
pub fn client_with_lookup<L: HostLookup>(
    purpose: Purpose,
    lookup: L,
    configure: impl FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
) -> Result<Outbound, reqwest::Error> {
    let purpose = Arc::new(purpose);
    let resolver = GuardedResolver::with_private_hosts(lookup, purpose.private_hosts.clone());
    let mut builder =
        configure(reqwest::Client::builder().connect_timeout(Duration::from_secs(10)))
            .no_proxy()
            .dns_resolver(Arc::new(resolver))
            .redirect(redirect_policy(purpose.clone()));
    if let Some(proxy) = PROXY.get().cloned().flatten() {
        let direct = purpose.clone();
        builder = builder.proxy(reqwest::Proxy::custom(move |url| {
            let host = url.host_str().unwrap_or_default();
            (!direct.lists(host)).then(|| proxy.clone())
        }));
    }
    let inner = builder.build()?;
    Ok(Outbound { inner, purpose })
}

/// Follows up to the purpose's limit, refusing a hop to a non-http scheme or
/// a refused IP literal; a hop to a host name is screened when it resolves.
fn redirect_policy(purpose: Arc<Purpose>) -> redirect::Policy {
    if purpose.redirects == 0 {
        return redirect::Policy::none();
    }
    redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= purpose.redirects {
            attempt.error("too many redirects")
        } else if !matches!(attempt.url().scheme(), "http" | "https") {
            attempt.error(SsrfGuardError::UnsupportedScheme)
        } else if !purpose.allows_literal(attempt.url()) {
            tracing::warn!(
                purpose = purpose.name,
                host = attempt.url().host_str().unwrap_or_default(),
                "outbound: refusing a redirect to a non-routable address"
            );
            attempt.error(SsrfGuardError::AddressNotRoutable)
        } else {
            attempt.follow()
        }
    })
}

/// A `reqwest::Client` behind the guard. The request methods take what
/// reqwest's do and return its `RequestBuilder`; a URL whose IP-literal host
/// is refused comes back as a request that fails in `send()` without
/// dialing.
#[derive(Clone, Debug)]
pub struct Outbound {
    inner: reqwest::Client,
    purpose: Arc<Purpose>,
}

impl Outbound {
    pub fn purpose(&self) -> &Purpose {
        &self.purpose
    }

    pub fn request(&self, method: Method, url: impl AsRef<str>) -> RequestBuilder {
        let raw = url.as_ref();
        match Url::parse(raw) {
            Ok(parsed) if !self.purpose.allows_literal(&parsed) => self.refused(method, &parsed),
            Ok(parsed) => self.inner.request(method, parsed),
            // reqwest reports the parse error itself, in `send()`.
            Err(_) => self.inner.request(method, raw),
        }
    }

    pub fn get(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    pub fn post(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    pub fn put(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::PUT, url)
    }

    pub fn patch(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }

    pub fn delete(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }

    pub fn head(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }

    /// Re-checks the literal, because a built `Request`'s URL is mutable.
    pub async fn execute(&self, request: reqwest::Request) -> reqwest::Result<reqwest::Response> {
        if !self.purpose.allows_literal(request.url()) {
            let url = request.url().clone();
            return self.refused(request.method().clone(), &url).send().await;
        }
        self.inner.execute(request).await
    }

    fn refused(&self, method: Method, url: &Url) -> RequestBuilder {
        let host = url.host_str().unwrap_or_default();
        tracing::warn!(
            purpose = self.purpose.name,
            host,
            "outbound: refusing to dial a non-routable IP literal"
        );
        self.inner
            .request(method, format!("{REFUSED_SCHEME}://{host}/").as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn a_public_purpose_refuses_private_and_metadata_literals() {
        let p = Purpose::public("test");
        for s in [
            "http://127.0.0.1/",
            "http://10.1.2.3/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data",
            "http://2130706433/",
        ] {
            assert!(!p.allows_literal(&url(s)), "{s}");
        }
        assert!(p.allows_literal(&url("https://93.184.216.34/")));
        assert!(p.allows_literal(&url("https://example.com/")));
    }

    #[test]
    fn a_listed_host_may_be_private_but_never_metadata() {
        let p =
            Purpose::public("test").with_private_hosts(["10.1.2.3", "[::1]", "169.254.169.254"]);
        assert!(p.allows_literal(&url("http://10.1.2.3:8080/")));
        assert!(p.allows_literal(&url("http://[::1]:8080/")));
        assert!(!p.allows_literal(&url("http://10.1.2.4/")));
        assert!(!p.allows_literal(&url("http://169.254.169.254/")));
    }

    #[test]
    fn private_urls_list_their_hosts() {
        let p =
            Purpose::public("test").with_private_urls(["http://LocalHost:8080/v1", "not a url"]);
        assert!(host_is_listed(&p.private_hosts, "localhost"));
        assert_eq!(p.private_hosts.len(), 1);
    }

    #[tokio::test]
    async fn a_refused_literal_fails_in_send_without_dialing() {
        let client = client(Purpose::public("test"), |b| {
            b.timeout(Duration::from_secs(1))
        })
        .unwrap();
        let err = client
            .get("http://169.254.169.254/latest/meta-data")
            .send()
            .await
            .expect_err("refused");
        assert!(err.is_builder(), "{err:?}");
        assert!(err.to_string().contains(REFUSED_SCHEME), "{err}");
    }
}
