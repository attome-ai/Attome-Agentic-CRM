//! Z5-T4: a basic web firewall, before rate limiting and authentication.
//!
//! Refuses with `400 request_rejected` a request that no route can want:
//!
//! - more than [`MAX_HEADERS`] headers, or a header value over
//!   [`MAX_HEADER_VALUE`] bytes;
//! - a path and query over [`MAX_URI`] bytes;
//! - a path with a `..` segment, plain or percent-encoded (`%2e%2e`,
//!   `.%2e`, `%2e.`, any case): directory traversal;
//! - a path with `%00` (a NUL) or a raw backslash anywhere;
//! - a double-encoded dot, slash, backslash or NUL (`%252e`, `%252f`,
//!   `%255c`, `%2500`), which decodes into one of the above a layer later.
//!
//! The traversal and double-encoding rules match the attack, not the
//! character: `/api/v1/{entity}/key/{keyspec}` carries user values in its
//! path, so a value with a literal `%` (`%25` followed by anything else) or
//! with `..` inside a segment (`J..Smith`) passes.
//!
//! A request to `/api/` without a `User-Agent` is counted
//! (`http_waf_signal_total{signal="no_ua"}`) but never refused. Each refusal
//! counts in `http_rejections_total{layer="waf", reason}` and logs its reason
//! only: the rejected URL can carry a token and is never logged.

use attome_types::AppError;
use axum::extract::Request;
use axum::http::header::USER_AGENT;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// The most headers a request may carry.
pub const MAX_HEADERS: usize = 100;
/// The longest header value, in bytes.
pub const MAX_HEADER_VALUE: usize = 8 * 1024;
/// The longest path and query, in bytes.
pub const MAX_URI: usize = 8 * 1024;

/// Why a path is refused, or `None`.
pub fn path_refusal(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    if lower.contains("%00") {
        return Some("null_byte");
    }
    if path.contains('\\') {
        return Some("backslash");
    }
    if ["%252e", "%252f", "%255c", "%2500"]
        .iter()
        .any(|encoded| lower.contains(encoded))
    {
        return Some("double_encoded");
    }
    if lower
        .split('/')
        .any(|segment| matches!(segment, ".." | "%2e%2e" | ".%2e" | "%2e."))
    {
        return Some("dot_dot_segment");
    }
    None
}

/// Why a request is refused, or `None`.
pub fn refusal(req: &Request) -> Option<&'static str> {
    let headers = req.headers();
    if headers.len() > MAX_HEADERS {
        return Some("too_many_headers");
    }
    if headers.values().any(|v| v.len() > MAX_HEADER_VALUE) {
        return Some("header_too_large");
    }
    let uri_len = req.uri().path_and_query().map_or(0, |pq| pq.as_str().len());
    if uri_len > MAX_URI {
        return Some("uri_too_long");
    }
    path_refusal(req.uri().path())
}

/// The layer itself; see the module doc.
pub async fn basic_waf(req: Request, next: Next) -> Response {
    if req.uri().path().starts_with("/api/") && !req.headers().contains_key(USER_AGENT) {
        metrics::counter!("http_waf_signal_total", "signal" => "no_ua").increment(1);
    }
    if let Some(reason) = refusal(&req) {
        crate::metrics::record_rejection("waf", reason);
        tracing::warn!(reason, "web firewall: request refused");
        return AppError::RequestRejected(reason).into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn get(uri: &str) -> Request {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    #[test]
    fn dotdot_path_is_refused() {
        assert_eq!(
            refusal(&get("/api/v1/../admin/settings")),
            Some("dot_dot_segment")
        );
        assert_eq!(refusal(&get("/api/v1/x/..")), Some("dot_dot_segment"));
    }

    #[test]
    fn encoded_dotdot_is_refused() {
        for uri in [
            "/api/v1/%2e%2e/admin",
            "/api/v1/%2E%2E/admin",
            "/api/v1/.%2e/admin",
            "/api/v1/%2e./admin",
        ] {
            assert_eq!(refusal(&get(uri)), Some("dot_dot_segment"), "{uri}");
        }
        assert_eq!(
            refusal(&get("/api/v1/%252e%252e/admin")),
            Some("double_encoded")
        );
    }

    #[test]
    fn null_byte_is_refused() {
        assert_eq!(refusal(&get("/api/v1/account%00.json")), Some("null_byte"));
    }

    #[test]
    fn normal_path_passes() {
        for uri in [
            "/api/v1/account/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
            "/api/v1/search?q=acme%20trading",
            // A user value in a path segment: a literal `%` and `..` inside it.
            "/api/v1/product/key/code=50%25off",
            "/api/v1/contact/key/name=J..Smith",
            "/health/ready",
        ] {
            assert_eq!(refusal(&get(uri)), None, "{uri}");
        }
    }

    #[test]
    fn too_many_headers_is_refused() {
        let mut builder = Request::builder().uri("/api/v1/account");
        for n in 0..=MAX_HEADERS {
            builder = builder.header(format!("x-filler-{n}"), "1");
        }
        let req = builder.body(Body::empty()).unwrap();
        assert_eq!(refusal(&req), Some("too_many_headers"));
    }

    #[test]
    fn oversized_header_and_uri_are_refused() {
        let req = Request::builder()
            .uri("/api/v1/account")
            .header("x-big", "a".repeat(MAX_HEADER_VALUE + 1))
            .body(Body::empty())
            .unwrap();
        assert_eq!(refusal(&req), Some("header_too_large"));
        let long = format!("/api/v1/search?q={}", "a".repeat(MAX_URI));
        assert_eq!(refusal(&get(&long)), Some("uri_too_long"));
    }
}
