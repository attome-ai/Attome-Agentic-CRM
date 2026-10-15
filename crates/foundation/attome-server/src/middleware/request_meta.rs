//! Ambient per-request metadata (request id, client IP, user agent), read by
//! anything downstream that needs it without threading it through every
//! function signature — same `tokio::task_local!` shape `attome_profiler::scope`
//! already uses in this codebase (`crates/base/attome-profiler/src/lib.rs`).
//!
//! Applied inside [`crate::app::apply_outer_layers`], right after
//! `SetRequestIdLayer` sets the `RequestId` extension, so it wraps everything
//! that runs after it in that chain (Trace, CORS, panic-catch, body-limit,
//! and eventually the handler) in the scope — pure capture, no request
//! rejection, no header/response change, so it does not alter this repo's
//! documented security-sensitive middleware ordering (coding-guidelines §3),
//! it only observes what earlier layers in the same chain already produced.
//!
//! `xrm-audit` (an `xrm-*` crate; `attome-server` cannot depend on it, see
//! CLAUDE.md's layer direction) reads [`current`] to backfill an audit
//! event's `correlation_id`/IP/user-agent — see
//! `xrm_audit::request_ctx`'s module doc.

use attome_config::AppConfig;
use axum::{
    extract::{ConnectInfo, Request},
    http::header::USER_AGENT,
    middleware::Next,
    response::Response,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::request_id::RequestId;

use super::client_ip::client_ip_from_parts;

/// Ambient per-request metadata. All-`None` outside an active [`scope`].
#[derive(Clone, Debug, Default)]
pub struct RequestMeta {
    /// The `x-request-id` value (`tower_http::request_id::MakeRequestUuid`
    /// generates a UUID string by default, but `SetRequestIdLayer` keeps a
    /// well-formed client-supplied value too per `drop_unsafe_request_id`'s
    /// doc — a non-UUID client-supplied id parses to `None` here).
    pub request_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

tokio::task_local! {
    static CURRENT: RequestMeta;
}

/// The ambient metadata set by the enclosing scope, or all-`None` outside
/// one (a background job, a test, boot-time code) — callers never need to
/// guard "am I inside a request" themselves.
pub fn current() -> RequestMeta {
    CURRENT.try_with(Clone::clone).unwrap_or_default()
}

/// Test-only seam for a downstream crate (`xrm-audit`) that wants to exercise
/// its own reader of [`current`] without standing up the full HTTP middleware
/// chain. Not used by [`capture_request_meta`] itself, which sets the scope
/// via `next.run(req)` directly.
pub async fn scope_for_test<F: std::future::Future>(meta: RequestMeta, f: F) -> F::Output {
    CURRENT.scope(meta, f).await
}

/// Captures request id / client IP / user agent from `req` and runs the rest
/// of the middleware chain with them as the ambient [`RequestMeta`].
pub(crate) async fn capture_request_meta(
    config: Arc<AppConfig>,
    req: Request,
    next: Next,
) -> Response {
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .and_then(|id| id.header_value().to_str().ok())
        .map(str::to_owned);
    let ip_address = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| {
            client_ip_from_parts(peer.ip(), req.headers(), &config).to_string()
        });
    let user_agent = req
        .headers()
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    let meta = RequestMeta {
        request_id: request_id.clone(),
        ip_address,
        user_agent,
    };
    // U4-T5: the id also goes where `attome-jobs` can read it, so a job
    // queued by this request names it.
    match request_id {
        Some(id) => {
            attome_types::request_scope::scope(id, CURRENT.scope(meta, next.run(req))).await
        }
        None => CURRENT.scope(meta, next.run(req)).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_op_outside_a_scope() {
        assert!(current().request_id.is_none());
        assert!(current().ip_address.is_none());
    }

    #[tokio::test]
    async fn reads_back_the_ambient_scope() {
        let meta = RequestMeta {
            request_id: Some("11111111-1111-1111-1111-111111111111".to_string()),
            ip_address: Some("203.0.113.7".to_string()),
            user_agent: Some("curl/8.0".to_string()),
        };
        CURRENT
            .scope(meta, async {
                let got = current();
                assert_eq!(
                    got.request_id.as_deref(),
                    Some("11111111-1111-1111-1111-111111111111")
                );
                assert_eq!(got.ip_address.as_deref(), Some("203.0.113.7"));
                assert_eq!(got.user_agent.as_deref(), Some("curl/8.0"));
            })
            .await;
    }
}
