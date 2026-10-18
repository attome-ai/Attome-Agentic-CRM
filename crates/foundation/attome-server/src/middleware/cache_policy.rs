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
}

/// Routes whose class is not the one [`class_for`]'s rules give, as
/// `(method, route template, class)`.
pub static CACHE_CLASSES: &[(&str, &str, CacheClass)] = &[
    // The API document changes only with a release, but it is fetched under
    // one URL across releases, so it revalidates rather than being
    // immutable.
    ("GET", "/api/v1/openapi.json", CacheClass::PrivateRevalidate),
];

/// Path words that make a read `NoStore`: what a shared or browser cache must
/// never keep.
const NO_STORE_WORDS: &[&str] = &[
    "auth",
    "token",
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
    let sensitive = template
        .split(['/', '-', '_', '.'])
        .chain(template.split('/'))
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
    }
}

/// The layer itself; see the module doc.
pub async fn cache_policy(req: Request, next: Next) -> Response {
    let class = match req.extensions().get::<MatchedPath>() {
        Some(path) => class_for(req.method(), path.as_str()),
        None => CacheClass::NoStore,
    };
    let mut response = next.run(req).await;
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
    fn unknown_route_defaults_to_no_store() {
        assert_eq!(class_for(&Method::GET, "/metrics"), CacheClass::NoStore);
        assert_eq!(
            class_for(&Method::GET, "/health/ready"),
            CacheClass::NoStore
        );
    }
}
