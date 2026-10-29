//! AA7-T1: every API response says how it may be cached. Each route has a
//! [`CacheClass`]; after the handler, this layer sets `Cache-Control` from
//! it unless the handler set its own:
//!
//! - **NoStore** (`no-store`): anything that changes state, and every read
//!   of credentials, tokens, keys, sessions, secrets or exports. Also every
//!   route that matched nothing, and any route the rules cannot place.
//! - **PrivateRevalidate** (`private, no-cache` and `Vary: Authorization,
//!   Cookie`): ordinary API reads (records, lists, queries, schema). A
//!   browser may keep them for this user only and must ask again (an ETag
//!   makes that cheap) before reuse; no shared cache may keep them.
//! - **Immutable** (`public, max-age=31536000, immutable`): only the routes
//!   [`CACHE_CLASSES`] names, and only public artefacts whose bytes never
//!   change under one URL. Nothing an authenticated session reads is
//!   public otherwise.
//! - **PrivateImmutable** (`private, max-age=31536000, immutable` and
//!   `Vary: Authorization, Cookie`): a signed-in read of bytes whose URL
//!   names their content hash (AA7-T5's cooked artefacts). The browser keeps
//!   it for a year without asking again; no shared cache keeps it.
//!
//! The class comes from [`CACHE_CLASSES`] when a route is listed there, and
//! from [`class_for`]'s rules otherwise. A test walks the API document and
//! checks every operation lands in a class.

use axum::extract::{MatchedPath, Request};
use axum::http::{HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::Response;

/// How a route's responses may be cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheClass {
    NoStore,
    PrivateRevalidate,
    Immutable,
    /// AA7-T5: content-addressed bytes a signed-in caller reads: kept by
    /// the browser for a year without asking again, by no shared cache.
    PrivateImmutable,
}

/// Routes whose class is not the one [`class_for`]'s rules give, as
/// `(method, route template, class)`.
pub static CACHE_CLASSES: &[(&str, &str, CacheClass)] = &[
    // The API document changes only with a release, but it is fetched under
    // one URL across releases, so it revalidates rather than being
    // immutable.
    ("GET", "/api/v1/openapi.json", CacheClass::PrivateRevalidate),
    // AA7-T5: an artefact's URL names its content hash.
    (
        "GET",
        "/api/v1/cooked/{kind}/{hash}",
        CacheClass::PrivateImmutable,
    ),
];

/// Path words that make a read `NoStore`: what a shared or browser cache must
/// never keep.
const NO_STORE_WORDS: &[&str] = &[
    "auth",
    "token",
    "tokens",
    "api-key",
    "api-keys",
    "apikey",
    "session",
    "sessions",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "password",
    "mfa",
    "passkey",
    "passkeys",
    "keys",
    "export",
    "exports",
    "s2s",
    "oauth",
    "oidc",
    "login",
    "logout",
    "me",
];

/// The class of `method` on `template`.
pub fn class_for(method: &Method, template: &str) -> CacheClass {
    if let Some((_, _, class)) = CACHE_CLASSES
        .iter()
        .find(|(m, t, _)| *t == template && method.as_str().eq_ignore_ascii_case(m))
    {
        return *class;
    }
    if method != Method::GET && method != Method::HEAD {
        return CacheClass::NoStore;
    }
    // A path parameter counts by its name: `/pay/{token}` carries a token.
    let sensitive = template
        .split(['/', '-', '_', '.'])
        .chain(template.split('/'))
        .map(|word| word.trim_matches(['{', '}']))
        .any(|word| NO_STORE_WORDS.contains(&word));
    if sensitive {
        return CacheClass::NoStore;
    }
    if template.starts_with("/api/") {
        CacheClass::PrivateRevalidate
    } else {
        CacheClass::NoStore
    }
}

/// The header values a class sets.
fn header_values(class: CacheClass) -> (&'static str, Option<&'static str>) {
    match class {
        CacheClass::NoStore => ("no-store", None),
        CacheClass::PrivateRevalidate => ("private, no-cache", Some("Authorization, Cookie")),
        CacheClass::Immutable => ("public, max-age=31536000, immutable", None),
        CacheClass::PrivateImmutable => (
            "private, max-age=31536000, immutable",
            Some("Authorization, Cookie"),
        ),
    }
}

/// The layer itself; see the module doc. AA7-T9: it also counts conditional
/// reads per route and the response bytes per API area before compression.
pub async fn cache_policy(req: Request, next: Next) -> Response {
    let template = req
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned());
    let class = match &template {
        Some(path) => class_for(req.method(), path),
        None => CacheClass::NoStore,
    };
    let conditional = req.headers().contains_key(header::IF_NONE_MATCH);
    let mut response = next.run(req).await;
    if let Some(template) = &template {
        if conditional {
            crate::metrics::record_conditional(
                template,
                response.status() == axum::http::StatusCode::NOT_MODIFIED,
            );
        }
        if let Some(bytes) = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
        {
            crate::metrics::record_response_bytes(
                &crate::metrics::route_area(template),
                "identity",
                bytes,
            );
        }
    }
    let headers = response.headers_mut();
    if headers.contains_key(header::CACHE_CONTROL) {
        return response;
    }
    let (cache_control, vary) = header_values(class);
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    if let Some(vary) = vary {
        let value = match headers.get(header::VARY).and_then(|v| v.to_str().ok()) {
            Some(existing) if !existing.is_empty() => format!("{existing}, {vary}"),
            _ => vary.to_owned(),
        };
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(header::VARY, value);
        }
    }
    response
}

/// AA7-T9: outside the compression layer, counts a compressed response's
/// bytes as they are sent (a compressed body is streamed, so it has no
/// length up front) under its area and encoding.
pub async fn count_encoded_bytes(req: Request, next: Next) -> Response {
    let area = req
        .extensions()
        .get::<MatchedPath>()
        .map(|path| crate::metrics::route_area(path.as_str()));
    let response = next.run(req).await;
    let encoding = response
        .headers()
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| match v {
            "gzip" => Some("gzip"),
            "br" => Some("br"),
            "zstd" => Some("zstd"),
            "deflate" => Some("deflate"),
            _ => None,
        });
    let (Some(area), Some(encoding)) = (area, encoding) else {
        return response;
    };
    let (parts, body) = response.into_parts();
    let counted = Counted {
        inner: body.into_data_stream(),
        bytes: 0,
        area,
        encoding,
        recorded: false,
    };
    Response::from_parts(parts, axum::body::Body::from_stream(counted))
}

/// A body stream that records how many bytes went through it, once, when it
/// ends or is dropped.
struct Counted<S> {
    inner: S,
    bytes: u64,
    area: String,
    encoding: &'static str,
    recorded: bool,
}

impl<S> Counted<S> {
    fn record(&mut self) {
        if !self.recorded {
            self.recorded = true;
            crate::metrics::record_response_bytes(&self.area, self.encoding, self.bytes);
        }
    }
}

impl<S> futures_util::Stream for Counted<S>
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, axum::Error>> + Unpin,
{
    type Item = Result<bytes::Bytes, axum::Error>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let polled = std::pin::Pin::new(&mut this.inner).poll_next(cx);
        match &polled {
            std::task::Poll::Ready(Some(Ok(chunk))) => {
                this.bytes = this.bytes.saturating_add(chunk.len() as u64);
            }
            std::task::Poll::Ready(None) => this.record(),
            _ => {}
        }
        polled
    }
}

impl<S> Drop for Counted<S> {
    fn drop(&mut self) {
        self.record();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_store_route_sets_no_store() {
        assert_eq!(
            class_for(&Method::GET, "/api/v1/auth/session"),
            CacheClass::NoStore
        );
        assert_eq!(
            class_for(&Method::GET, "/api/v1/admin/api-keys"),
            CacheClass::NoStore
        );
        assert_eq!(
            class_for(&Method::GET, "/api/v1/{entity}/export"),
            CacheClass::NoStore
        );
        assert_eq!(
            class_for(&Method::POST, "/api/v1/{entity}"),
            CacheClass::NoStore,
            "a write is never cached"
        );
        assert_eq!(
            class_for(&Method::GET, "/api/v1/pay/{token}"),
            CacheClass::NoStore,
            "a path parameter named for a secret"
        );
        assert_eq!(header_values(CacheClass::NoStore).0, "no-store");
    }

    #[test]
    fn revalidate_route_sets_private_no_cache_and_vary() {
        assert_eq!(
            class_for(&Method::GET, "/api/v1/{entity}/{id}"),
            CacheClass::PrivateRevalidate
        );
        assert_eq!(
            class_for(&Method::GET, "/api/v1/{entity}"),
            CacheClass::PrivateRevalidate
        );
        let (cache_control, vary) = header_values(CacheClass::PrivateRevalidate);
        assert_eq!(cache_control, "private, no-cache");
        assert_eq!(vary, Some("Authorization, Cookie"));
    }

    #[test]
    fn a_cooked_artefact_is_private_and_immutable() {
        assert_eq!(
            class_for(&Method::GET, "/api/v1/cooked/{kind}/{hash}"),
            CacheClass::PrivateImmutable
        );
        assert_eq!(
            class_for(&Method::GET, "/api/v1/cooked/{kind}"),
            CacheClass::PrivateRevalidate,
            "the list changes with every publish"
        );
        assert_eq!(
            header_values(CacheClass::PrivateImmutable),
            (
                "private, max-age=31536000, immutable",
                Some("Authorization, Cookie")
            )
        );
    }

    #[test]
    fn unknown_route_defaults_to_no_store() {
        assert_eq!(class_for(&Method::GET, "/metrics"), CacheClass::NoStore);
        assert_eq!(
            class_for(&Method::GET, "/health/ready"),
            CacheClass::NoStore
        );
    }
}
