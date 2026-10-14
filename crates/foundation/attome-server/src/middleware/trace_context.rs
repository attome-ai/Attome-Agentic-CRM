//! P-observability-completion — W3C `traceparent` propagation (inbound half).
//! Extracts an inbound `traceparent` header (when a caller — an S2S client,
//! an integration webhook — already sends one), records it as a field on the
//! request's tracing span (so a caller citing a trace id gives an operator
//! something to grep structured logs for, with or without a live OTel export
//! pipeline), and — only for a trusted caller — restores it as the request
//! span's OTel parent via `OpenTelemetrySpanExt::set_parent`, so the caller's
//! trace and this request's span link up in the collector as one trace.
//!
//! BSV-F22 / BSV-D10 (A8) — the trust policy. A `traceparent` is restored as
//! the parent only when the immediate TCP peer is inside
//! `security.trusted_proxy_cidrs`: the edge proxy is expected to set or strip
//! the header (see the `trusted_proxy_cidrs` doc). From any other peer the
//! value is still recorded on the span (capped at the fixed 55-byte W3C
//! length), but the request starts a fresh trace and no `TraceParent`
//! extension is inserted, so an internet client can neither attach its
//! requests to a trace id of its choosing nor have that id forwarded onward.
//! An authenticated S2S caller that dials the node directly is not trusted
//! here: S2S authentication runs inside this layer, after the span's parent
//! is already fixed.
//!
//! `tracestate` is not extracted (no consumer needs it yet), and this layer
//! never *originates* a `traceparent` — that is the tracer's job
//! (`server::observability`). With no `tracing-opentelemetry` layer installed
//! (`observability.enable_distributed_tracing = false`),
//! `OpenTelemetrySpanExt::set_parent` is a documented safe no-op. A request
//! with no `traceparent`, or one that fails to parse, passes through
//! unaffected — never rejected over a header this middleware does not require.

use attome_config::AppConfig;
use axum::{
    extract::{ConnectInfo, Request},
    middleware::Next,
    response::Response,
};
use opentelemetry::trace::{SpanContext, TraceContextExt};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub(crate) const TRACEPARENT_HEADER: &str = "traceparent";

/// The fixed length of a version-00 W3C `traceparent`
/// (`2 + 1 + 32 + 1 + 16 + 1 + 2`); anything longer is truncated before it is
/// recorded, so a caller cannot put an arbitrarily long value into every log.
pub(crate) const TRACEPARENT_MAX_RECORDED_LEN: usize = 55;

/// Request-extension carrying the inbound `traceparent` value — present only
/// when it came from a trusted peer (see the module doc), for any handler or
/// downstream call that forwards it onward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceParent(pub String);

/// The production entry point: trust is decided by
/// `security.trusted_proxy_cidrs` against the immediate TCP peer.
pub async fn trace_context(config: Arc<AppConfig>, req: Request, next: Next) -> Response {
    trace_context_with(|ip| config.is_trusted_proxy(ip), req, next).await
}

/// Must run INSIDE `TraceLayer` (layered after it in `apply_outer_layers`), so
/// it executes within the span `TraceLayer` created — see
/// `app::request_span`'s `traceparent = tracing::field::Empty` field.
pub(crate) async fn trace_context_with(
    is_trusted_peer: impl Fn(IpAddr) -> bool,
    mut req: Request,
    next: Next,
) -> Response {
    let trusted = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|ci| is_trusted_peer(ci.0.ip().to_canonical()));
    if let Some(value) = req
        .headers()
        .get(TRACEPARENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    {
        let recorded = bounded(&value);
        tracing::Span::current().record("traceparent", tracing::field::display(recorded));
        if let Some(span_context) = parent_to_restore(trusted, &value) {
            let parent_cx = opentelemetry::Context::new().with_remote_span_context(span_context);
            // `LayerNotFound` is the expected `enable_distributed_tracing =
            // false` path and `SpanDisabled` means a filter dropped the span;
            // neither is worth more than a `debug`, and neither aborts the
            // request.
            if let Err(err) = tracing::Span::current().set_parent(parent_cx) {
                tracing::debug!(
                    error = %err,
                    "traceparent parsed but could not be restored as the request span's OTel parent — continuing without a linked parent span"
                );
            }
            req.extensions_mut().insert(TraceParent(value));
        }
    }
    next.run(req).await
}

/// The remote parent to restore: only for a trusted peer, and only when the
/// value parses as W3C Trace Context.
fn parent_to_restore(trusted: bool, value: &str) -> Option<SpanContext> {
    if !trusted {
        return None;
    }
    attome_types::w3c_trace::parse_traceparent(value)
}

fn bounded(value: &str) -> &str {
    if value.len() <= TRACEPARENT_MAX_RECORDED_LEN {
        return value;
    }
    let mut end = TRACEPARENT_MAX_RECORDED_LEN;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router, body::Body, http::Request as HttpRequest, middleware::from_fn, routing::get,
    };
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;
    use tracing::Instrument;
    use tracing_subscriber::layer::SubscriberExt;

    async fn echo_traceparent(ext: axum::extract::Extension<Option<TraceParent>>) -> String {
        ext.0.map(|tp| tp.0).unwrap_or_default()
    }

    const TRUSTED_PEER: &str = "10.0.0.5:443";
    const UNTRUSTED_PEER: &str = "198.51.100.7:50000";
    const VALID: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    fn from_peer(peer: &str, traceparent: Option<&str>) -> HttpRequest<Body> {
        let mut builder = HttpRequest::builder().uri("/");
        if let Some(tp) = traceparent {
            builder = builder.header(TRACEPARENT_HEADER, tp);
        }
        let mut req = builder.body(Body::empty()).unwrap();
        let addr: SocketAddr = peer.parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        req
    }

    fn app() -> Router {
        // The extractor above needs `Option<TraceParent>` to be insertable
        // even when absent — axum's `Extension<T>` extractor only succeeds
        // when `T` itself is present, so wrap with a tiny adapter middleware
        // that always inserts `Option<TraceParent>` from whatever (if
        // anything) `trace_context` inserted.
        async fn normalize(mut req: Request, next: Next) -> Response {
            let tp = req.extensions().get::<TraceParent>().cloned();
            req.extensions_mut().insert(tp);
            next.run(req).await
        }

        Router::new()
            .route("/", get(echo_traceparent))
            .layer(from_fn(normalize))
            .layer(from_fn(|req, next| {
                trace_context_with(|ip: IpAddr| ip.to_string().starts_with("10."), req, next)
            }))
    }

    #[tokio::test]
    async fn a_request_with_no_traceparent_header_passes_through_unaffected() {
        let req = HttpRequest::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app().oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes, "");
    }

    #[tokio::test]
    async fn a_trusted_proxy_traceparent_is_restored() {
        assert!(parent_to_restore(true, VALID).is_some());
        let resp = app()
            .oneshot(from_peer(TRUSTED_PEER, Some(VALID)))
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes, VALID.as_bytes());
    }

    #[tokio::test]
    async fn an_untrusted_traceparent_never_becomes_the_parent() {
        assert!(parent_to_restore(false, VALID).is_none());
        let resp = app()
            .oneshot(from_peer(UNTRUSTED_PEER, Some(VALID)))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            bytes, "",
            "an untrusted traceparent must not be forwarded onward"
        );
    }

    #[tokio::test]
    async fn a_request_without_connect_info_is_untrusted() {
        let req = HttpRequest::builder()
            .uri("/")
            .header(TRACEPARENT_HEADER, VALID)
            .body(Body::empty())
            .unwrap();
        let bytes = axum::body::to_bytes(app().oneshot(req).await.unwrap().into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes, "");
    }

    #[test]
    fn the_recorded_value_is_capped_at_the_w3c_length() {
        assert_eq!(bounded(VALID), VALID);
        let long = format!("{VALID}{}", "x".repeat(4000));
        assert_eq!(bounded(&long).len(), TRACEPARENT_MAX_RECORDED_LEN);
        assert_eq!(bounded(&"é".repeat(40)).len(), 54);
    }

    #[tokio::test]
    async fn a_malformed_non_utf8_traceparent_header_is_ignored_not_rejected() {
        // to_str() fails on non-ASCII header bytes -- the middleware must
        // degrade to "no traceparent" rather than error the request over a
        // header it doesn't even validate the shape of.
        let req = HttpRequest::builder()
            .uri("/")
            .header(TRACEPARENT_HEADER, [0xffu8, 0xfe, 0xfd].as_slice())
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn a_traceparent_that_fails_w3c_parsing_still_passes_through_unaffected() {
        // Well-formed UTF-8, but not valid W3C Trace Context (bad field
        // count) — must not panic `set_parent`/reject the request; same
        // degrade-to-no-parent posture as the non-UTF8 case above.
        let req = HttpRequest::builder()
            .uri("/")
            .header(TRACEPARENT_HEADER, "not-a-real-traceparent")
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    /// P-observability-completion redaction test (guidelines §11's never-log
    /// list: passwords, hashes, JWTs, cookies, API keys, S2S secrets). This
    /// middleware's only `Span::record` call site takes exactly one input —
    /// the `traceparent` header value — and records it under exactly one
    /// field name (`"traceparent"`). This test proves that structurally: a
    /// request carrying a secret-shaped value in an unrelated header
    /// (`authorization`) never has that value show up in ANY span/event
    /// field recorded during the request, while the real `traceparent`
    /// header's value does — a custom `tracing_subscriber::Layer` captures
    /// every field value recorded on every span for the request's duration
    /// (a static assertion over what the code actually records, not a
    /// runtime redaction/scrubbing filter — matching this plan's testing
    /// design in `P-observability-completion.md` §6).
    #[derive(Default, Clone)]
    struct FieldCapture(Arc<Mutex<Vec<String>>>);

    struct CaptureVisitor<'a>(&'a mut Vec<String>);

    impl tracing::field::Visit for CaptureVisitor<'_> {
        fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push(format!("{value:?}"));
        }

        fn record_str(&mut self, _field: &tracing::field::Field, value: &str) {
            self.0.push(value.to_string());
        }
    }

    impl<S> tracing_subscriber::Layer<S> for FieldCapture
    where
        S: tracing::Subscriber,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut values = self.0.lock().unwrap();
            attrs.record(&mut CaptureVisitor(&mut values));
        }

        fn on_record(
            &self,
            _id: &tracing::span::Id,
            values_record: &tracing::span::Record<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut values = self.0.lock().unwrap();
            values_record.record(&mut CaptureVisitor(&mut values));
        }

        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut values = self.0.lock().unwrap();
            event.record(&mut CaptureVisitor(&mut values));
        }
    }

    #[tokio::test]
    async fn traceparent_recording_never_captures_an_unrelated_secret_header() {
        let capture = FieldCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let secret = "Bearer sk-super-secret-do-not-log-me";
        let traceparent = VALID;
        let mut req = from_peer(UNTRUSTED_PEER, Some(traceparent));
        req.headers_mut()
            .insert("authorization", secret.parse().unwrap());

        // Mirrors production's span shape (`app::request_span`'s declared
        // `traceparent = tracing::field::Empty` field) rather than relying
        // on axum-test-internal defaults — `.instrument()` (not a manually
        // held `.enter()` guard) so the span is correctly entered/exited
        // around each poll, including across the `.await` inside `oneshot`.
        let span = tracing::info_span!("http_request", traceparent = tracing::field::Empty);
        let resp = app().oneshot(req).instrument(span).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let captured = capture.0.lock().unwrap().clone();
        assert!(
            captured.iter().any(|v| v.contains(traceparent)),
            "expected the real traceparent value to be recorded somewhere: {captured:?}"
        );
        assert!(
            !captured.iter().any(|v| v.contains(secret)),
            "the authorization header's secret value must never be recorded as a span/event \
             field: {captured:?}"
        );
    }
}
