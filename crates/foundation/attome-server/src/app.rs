use attome_config::AppConfig;
use attome_types::AppError;
use axum::{
    Router,
    error_handling::HandleErrorLayer,
    extract::Request,
    http::{Extensions, HeaderMap, HeaderName, Method, StatusCode, Version, header},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use tower::{BoxError, ServiceBuilder, timeout::TimeoutLayer};
use tower_http::{
    CompressionLevel,
    catch_panic::CatchPanicLayer,
    compression::{
        CompressionLayer,
        predicate::{NotForContentType, Predicate, SizeAbove},
    },
    cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::Span;

use crate::{
    health,
    middleware::{
        auth, authoring_gate, body_limit, csrf, deprecation, idempotency, json_shape,
        mutation_gate, rate_limit, request_id_body, request_meta, security_headers, trace_context,
    },
    state::AppState,
};

/// Version routes — no middleware. `/health` and `/health/ready` are
/// deliberately NOT here; see `liveness_routes` for why probes are
/// mounted separately. Generic over S so callers (e.g.
/// `XrmSystem::core_routes`) can merge it in before their own state is resolved.
pub fn health_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: axum::extract::FromRef<S>,
{
    Router::new().route("/version", get(health::version))
}

/// Orchestrator probes (`GET /health` and `GET /health/ready`) — no middleware, and NOT part of
/// `health_routes`/`ServerBuilder::add_bundle`. It's mounted via
/// `ServerBuilder::with_liveness_routes` instead, which merges it in after
/// `apply_pre_auth_rate_limit`/`apply_mutation_gate`/`apply_authoring_gate`
/// (all Redis/state dependent) rather than before, so a Redis outage can never turn a
/// liveness probe into a 500. Without this split, `pre_auth_rate_limit`
/// (`middleware::rate_limit::pre_auth_rate_limit`) wraps `/health` like
/// every other route, calls Redis unconditionally, and fails closed on a
/// Redis error/timeout — meaning every node's liveness check fails at the
/// same moment Redis blips, and the orchestrator restarts the whole fleet
/// into the same still-recovering Redis. Readiness still checks Redis/DB in
/// its handler and returns 503, but bypasses the Redis-backed limiter so a
/// coordination outage cannot mask that diagnostic behind a generic 500.
/// `/health/dependencies` remains in `system_health::routes`.
pub fn liveness_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: axum::extract::FromRef<S>,
{
    Router::new()
        .route("/health", get(health::health_check))
        .route("/health/ready", get(health::health_ready))
        .route("/health/startup", get(health::health_startup))
}

/// Explicit CORS allow-list built from `config.cors.allowed_origins` (falls back to
/// a dev-only default derived from `app.frontend_host`/`app.frontend_port` — see
/// `AppConfig::allowed_origins`). Replaces the old `AllowOrigin::mirror_request()` +
/// `allow_credentials(true)` combination, which reflected any origin and is a
/// recorded security hole (Plan 1.3a) — never reintroduce mirror-origin alongside
/// credentials.
///
/// Every entry has already passed `AppConfig::validate`'s
/// `check_cors_origin` at boot, so `.parse()` below is expected to always
/// succeed — `validate` is what turns a typo'd/malformed origin into a boot
/// failure instead of this silently narrowing the allow-list (the bug this
/// used to have: a bare `.filter_map(|o| o.parse().ok())` dropped bad entries
/// with no signal at all). The `tracing::warn!` below is defense-in-depth for
/// the only way a bad entry could still reach here — a config built directly
/// (e.g. in a test) that skipped `validate()` — so that case stays visible
/// instead of silently reproducing the original bug.
pub fn cors_layer(config: &AppConfig) -> CorsLayer {
    let origins: Vec<_> = config
        .allowed_origins()
        .iter()
        .filter_map(|o| match o.parse() {
            Ok(value) => Some(value),
            Err(error) => {
                tracing::warn!(
                    origin = %o,
                    %error,
                    "dropping CORS origin that failed to parse as a header value — this should \
                     be unreachable once AppConfig::validate() has run"
                );
                None
            }
        })
        .collect();

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_credentials(true)
        .allow_methods(AllowMethods::list(ALLOWED_METHODS))
        .allow_headers(AllowHeaders::list(allowed_request_headers()))
        .expose_headers(exposed_response_headers())
        .max_age(CORS_MAX_AGE)
}

/// Y8-T7 — the response header naming the metadata version a node serves.
pub const METADATA_VERSION_HEADER: &str = "attome-metadata-version";

/// A2 (BSV-F06) — how long a browser may cache the preflight. Ten minutes is
/// below most browsers' 2 h clamp and turns a per-request preflight on a
/// non-simple cross-origin call into one per ten minutes.
const CORS_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(600);

/// A2 (BSV-F06) — the response headers a cross-origin browser client may read.
/// Without an explicit list the CORS safelist hides all of them, so a
/// cross-origin SDK caller cannot read `x-request-id` (its only correlation id)
/// or `Retry-After` (its backoff) and has to guess at both. Named explicitly,
/// like `allowed_request_headers`, so a header a middleware starts emitting is
/// one deliberate edit away from being readable. `pub` for the same reason as
/// `allowed_request_headers`: a test in another crate can assert against the
/// real contract rather than a copy that can drift.
pub(crate) fn exposed_response_headers() -> [HeaderName; 12] {
    [
        HeaderName::from_static("x-request-id"),
        HeaderName::from_static(METADATA_VERSION_HEADER),
        header::RETRY_AFTER,
        HeaderName::from_static("x-ratelimit-limit"),
        HeaderName::from_static("x-ratelimit-remaining"),
        HeaderName::from_static("x-ratelimit-reset"),
        header::ETAG,
        header::LOCATION,
        HeaderName::from_static("deprecation"),
        HeaderName::from_static("sunset"),
        // S9-T4: a replayed idempotent response says so, and names the
        // request that ran.
        HeaderName::from_static(crate::middleware::idempotency::REPLAYED_HEADER),
        HeaderName::from_static(crate::middleware::idempotency::ORIGINAL_REQUEST_ID_HEADER),
    ]
}

/// The exact verbs this router mounts (`.route(..., get/post/put/patch/
/// delete/head(..))` across every bundle), plus `OPTIONS` for the preflight
/// itself. Replaces `AllowMethods::mirror_request()`, which echoed whatever
/// `Access-Control-Request-Method` the caller asked for and therefore
/// preflight-approved verbs this service does not implement.
///
/// Not exploitable on its own — the origin allow-list above is what actually
/// gates a credentialed cross-origin request, and an approved preflight for
/// an unrouted verb still 405s at the router. This is defense-in-depth that
/// costs nothing: keep it in sync when a bundle starts mounting a new verb.
const ALLOWED_METHODS: [Method; 7] = [
    Method::GET,
    Method::POST,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
    Method::HEAD,
    Method::OPTIONS,
];

/// The request headers a browser client legitimately sends, replacing
/// `AllowHeaders::mirror_request()` (which echoed any
/// `Access-Control-Request-Headers` value back, approving arbitrary
/// attacker-chosen headers on a credentialed preflight).
///
/// Derived from what this workspace actually reads, not from a generic list:
/// - `accept`/`accept-language`/`content-type` — CORS-safelisted anyway, but
///   `content-type: application/json` is only safelisted for a subset of
///   values, so it must be named explicitly.
/// - `authorization` — `middleware::auth::extract_api_key`'s `ApiKey <pub>:<secret>`.
/// - `if-match` — the entity `row_version` OCC contract; the Angular client
///   sends it on every PATCH (`angular/projects/base/src/lib/api.service.ts`).
/// - `x-idempotency-key` — `middleware::idempotency`'s `HEADER`, and
///   `idempotency-key`, its standard name (S9-T1).
/// - `traceparent` — `middleware::trace_context` (W3C trace context).
/// - `x-request-id` — client-supplied correlation id, echoed by
///   `PropagateRequestIdLayer`.
/// - `x-attome-changeset` — names the open changeset a metadata admin write
///   records into (`xrm_foundation::changeset::CHANGESET_HEADER`, D-785).
/// - `x-override-reason` — why a caller holding the override privilege saves
///   a record a business-rule check refuses (A3-T4, `middleware::request_meta`).
///
/// A header added to a middleware or handler without being added here fails
/// only in a real browser, never in a Rust test — so treat this list as part
/// of the request contract, and cover new ones in the e2e suite.
/// `pub` so a test in another crate can assert against the real contract
/// rather than a transcribed copy (SEC-10): `xrm-s2s`'s
/// `signed_header_coverage.rs` checks every header here is classified against
/// the S2S canonical message. A copy of this list would drift, and a drifted
/// copy is a test that silently stops testing.
pub fn allowed_request_headers() -> [HeaderName; 11] {
    [
        header::ACCEPT,
        header::ACCEPT_LANGUAGE,
        header::AUTHORIZATION,
        header::CONTENT_TYPE,
        header::IF_MATCH,
        HeaderName::from_static("traceparent"),
        HeaderName::from_static("x-idempotency-key"),
        HeaderName::from_static("idempotency-key"),
        HeaderName::from_static("x-request-id"),
        HeaderName::from_static("x-attome-changeset"),
        HeaderName::from_static("x-override-reason"),
    ]
}

/// Builds the per-request span for `TraceLayer` (`apply_outer_layers`), tagged
/// with the same `x-request-id` value `SetRequestIdLayer` just generated for
/// this request — that layer runs immediately outside this one, so the
/// `RequestId` extension is already populated by the time this runs. Without
/// this, `request_id` only ever reached the response (the header via
/// `PropagateRequestIdLayer`, the error body via `request_id_body`) and never
/// a log line: `tracing::error!("internal error: {e}")` in
/// `attome-types::error::AppError::into_response` had no request_id field and
/// no enclosing span carrying one, so a customer citing a request ID gave an
/// operator nothing to grep for in production logs. `tracing_subscriber`'s
/// `.json()` formatter (`main.rs`) includes the current span's fields on
/// every event by default, so tagging the span is enough to fix that for
/// every event emitted anywhere during the request, not just this one.
///
/// `uri` records `.path()` only, never the full URI — query strings can
/// carry secrets (e.g. `oidc_callback`'s `code`/`state` params, auth.rs) and
/// this span's fields are attached to every log line/event for the request's
/// lifetime, so a full URI here would put those secrets in every log store,
/// backup, and SIEM export downstream.
pub fn request_span(request: &Request) -> Span {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .and_then(|id| id.header_value().to_str().ok())
        .unwrap_or("unknown");

    tracing::info_span!(
        "http_request",
        method = %request.method(),
        uri = %request.uri().path(),
        request_id = %request_id,
        // P-observability-completion — declared empty, filled in by
        // `middleware::trace_context::trace_context` (layered immediately
        // after `TraceLayer` below, i.e. inside this span) only when the
        // request actually carries a `traceparent` header. `tracing`
        // requires every field a span will ever record to be declared up
        // front at span-creation time.
        traceparent = tracing::field::Empty,
    )
}

/// Applies the outer, pre-auth cross-cutting stack (outermost first):
/// SecurityHeaders → RequestIdGuard (`drop_unsafe_request_id`) → RequestId →
/// RequestIdBody → Deprecation → Trace →
/// TraceContext → Propagate → CORS → CatchPanic → ContentLengthGuard →
/// BodyLimit → Timeout → Compression.
///
/// `CatchPanic` sits directly inside CORS so a panic's 500 still passes back
/// through CORS, Trace, RequestIdBody and SecurityHeaders — see
/// `panic_response` for why it must never move inside the gates.
///
/// The two body guards sit inside that envelope too, so their 413 carries
/// `request_id`, a JSON body and CORS headers like every other framework
/// error — and still ahead of every gate and auth layer.
///
/// `TraceContext` (`middleware::trace_context::trace_context`,
/// P-observability-completion) extracts an inbound W3C `traceparent` header
/// (if present) and records it on the span `Trace` (the layer immediately
/// above this one) just created/entered — hence its placement directly after
/// `TraceLayer`, not beside `RequestId` outside it: it needs the span to
/// already be current, which is only true once `Trace` has run. A complete
/// no-op today for every request that doesn't send a `traceparent` header
/// (every request, since nothing in this deployment sends one yet) — see
/// that module's doc comment for what this plumbing does and does not cover.
///
/// `Deprecation` (`middleware::deprecation::deprecation_headers`,
/// P-api-contract Phase 5) adds `Deprecation`/`Sunset` response headers for
/// the small compile-time registry of retiring paths
/// (`deprecation::DEPRECATED_PATHS`) — stateless, same shape and placement
/// rationale as `RequestIdBody` right above it: both only ever add
/// headers/fields to whatever response comes back, success or error alike,
/// so ordering relative to the rest of this stack doesn't matter for
/// correctness, only for grouping with the other response-decorating layers.
///
/// `SecurityHeaders` (P-frontend-hardening §4(d)/step 7) is added as the
/// true outermost layer — the last `.layer()` call below — specifically so
/// it decorates every response regardless of which inner layer produced it
/// (a handler's 2xx, `authn`'s 401, `body_limit`'s 413, `mutation_gate`'s
/// 503, ...). It sets CSP (or its report-only variant, gated by
/// `config.security.csp_enforce`)/X-Content-Type-Options/Referrer-Policy/
/// Strict-Transport-Security (gated by `config.security.hsts_max_age_secs`),
/// the same CSP string `deploy/frontend/nginx.conf` sets for the Angular
/// SPA's own page load — see `middleware::security_headers`'s module doc
/// for why the two are kept in lockstep even though this process never
/// renders HTML.
///
/// `RequestBodyLimitLayer` sits above the timeout and compression layers, so
/// `CompressionLayer`'s requirement that the body type directly beneath it
/// implement `Default` (which `tower_http::limit::ResponseBody<Body>` does not)
/// never applies to it. Both body guards still run before any auth/business
/// logic (`apply_inner_layers`, applied separately) — the fix for the old
/// "body-limit runs after auth" ordering bug (Plan 1.3c).
///
/// `body_limit::reject_declared_oversized_body` is layered directly outside
/// `RequestBodyLimitLayer` (P1.8 finding, 2026-07-07): the streaming limit only
/// errors when something actually reads the body, so a request a downstream
/// layer rejects without reading it (e.g. `authn` returning 401) never
/// triggers it. The header-only guard catches an honest oversized
/// `Content-Length` first; the streaming limit remains for a body that lies
/// about or omits `Content-Length`, and its overflow surfaces in whatever reads
/// the body (see `middleware::body_limit`'s module doc).
/// Must be the LAST call in the assembly sequence — see `system.rs` / `main.rs`
/// for why (Router::layer's last call becomes outermost).
pub fn apply_outer_layers(router: Router, config: &AppConfig) -> Router {
    let max_bytes = config.app.max_body_size_bytes;
    let request_timeout = config.request_timeout();
    let request_meta_config = std::sync::Arc::new(config.clone());
    let trace_context_config = request_meta_config.clone();
    // Q21-T4: wraps the router itself, so it runs inside every layer below
    // (the body it reads is already bounded by the body limit) and before
    // the auth and handler layers `apply_inner_layers` put on the router.
    let router = router.layer(middleware::from_fn(json_shape::reject_oversized_json_shape));
    let router = router.layer(
        ServiceBuilder::new()
            .layer(middleware::from_fn(drop_unsafe_request_id))
            .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
            // Pure capture (request id/IP/UA into an ambient task-local for
            // `xrm_audit::request_ctx` to read, see request_meta's module
            // doc) — placed right after `SetRequestIdLayer` sets the
            // `RequestId` extension this reads, and before anything that
            // could reject the request, so it never changes what a caller
            // observes.
            .layer(middleware::from_fn(move |req, next| {
                request_meta::capture_request_meta(request_meta_config.clone(), req, next)
            }))
            .layer(middleware::from_fn(
                request_id_body::attach_request_id_to_error_body,
            ))
            .layer(middleware::from_fn(deprecation::deprecation_headers))
            .layer(TraceLayer::new_for_http().make_span_with(request_span))
            .layer(middleware::from_fn(move |req, next| {
                trace_context::trace_context(trace_context_config.clone(), req, next)
            }))
            .layer(PropagateRequestIdLayer::x_request_id())
            .layer(cors_layer(config))
            .layer(CatchPanicLayer::custom(panic_response))
            .layer(middleware::from_fn(move |req, next| {
                body_limit::reject_declared_oversized_body(max_bytes, req, next)
            }))
            .layer(RequestBodyLimitLayer::new(max_bytes))
            .layer(HandleErrorLayer::new(timeout_response))
            .layer(TimeoutLayer::new(config.request_timeout()))
            // AB6-T2: inside the timeout, so the deadline outside calls see
            // always ends before it.
            .layer(crate::middleware::deadline::DeadlineLayer::new(
                request_timeout,
            ))
            .layer(compression_layer()),
    );

    let header_values = security_headers::SecurityHeaderValues::new(
        config.security.csp_enforce,
        config.security.hsts_max_age_secs,
        config.security.hsts_include_subdomains,
    );
    router.layer(middleware::from_fn(move |req, next| {
        security_headers::security_headers(header_values.clone(), req, next)
    }))
}

const X_REQUEST_ID: &str = "x-request-id";

/// Bodies at or under this many bytes go out raw: compressing them costs
/// more than it saves (AA7-T6).
const COMPRESS_MIN_BYTES: u64 = 1024;

/// AA7-T6: Brotli when the client accepts it (tower-http prefers `br` over
/// `gzip` at equal q-values), gzip otherwise, both at the default level. A
/// body under 1 KB, an already-compressed type (images, video, zip, PDF,
/// octet-stream), gRPC, server-sent events and every non-2xx response go out
/// raw.
fn compression_layer() -> CompressionLayer<impl Predicate> {
    let predicate = SizeAbove::new(COMPRESS_MIN_BYTES)
        .and(NotForContentType::GRPC)
        .and(NotForContentType::SSE)
        .and(NotForContentType::IMAGES)
        .and(NotForContentType::const_new("video/"))
        .and(NotForContentType::const_new("application/zip"))
        .and(NotForContentType::const_new("application/pdf"))
        .and(NotForContentType::const_new("application/octet-stream"))
        .and(compress_only_success);
    CompressionLayer::new()
        .quality(CompressionLevel::Default)
        .compress_when(predicate)
}

/// Removes a client-supplied `x-request-id` unless it is exactly one value of
/// 1–64 characters from `[A-Za-z0-9._-]`; `SetRequestIdLayer`, directly
/// inside this layer, then generates one. The id is written into every log
/// line for the request and echoed in the response header and error bodies.
/// Holding it to that grammar and length keeps caller-chosen text, and
/// unbounded identifiers, out of every log record and trace for the request.
async fn drop_unsafe_request_id(mut req: Request, next: middleware::Next) -> Response {
    let mut values = req.headers().get_all(X_REQUEST_ID).iter();
    let acceptable = match (values.next(), values.next()) {
        (None, _) => true,
        (Some(only), None) => is_acceptable_request_id(only.as_bytes()),
        (Some(_), Some(_)) => false,
    };
    if !acceptable {
        req.headers_mut().remove(X_REQUEST_ID);
    }
    next.run(req).await
}

/// A1 (BSV-F01) — `CompressionLayer` is the innermost outer layer, so on the
/// way out it compressed every error body *before*
/// `request_id_body::attach_request_id_to_error_body` (one layer outside it)
/// could parse it: `serde_json::from_slice` failed and the body went out as
/// valid gzip with no `request_id`, defeating the request-id contract for every
/// caller that sends `Accept-Encoding` — which a browser always does. The error
/// envelope is the observable contract and is small; the large success bodies
/// worth compressing are unaffected.
fn compress_only_success(
    status: StatusCode,
    _version: Version,
    _headers: &HeaderMap,
    _extensions: &Extensions,
) -> bool {
    !(status.is_client_error() || status.is_server_error())
}

fn is_acceptable_request_id(value: &[u8]) -> bool {
    (1..=64).contains(&value.len())
        && value
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `CatchPanicLayer`'s handler: a panic anywhere beneath the outer stack
/// becomes the standard masked `internal_error` 500 instead of a dropped
/// connection. The payload is logged once, by `AppError::into_response`, inside
/// the request span (so it carries `request_id`), and never returned.
///
/// The layer must stay outside every gate and `apply_inner_layers`. Inside the
/// idempotency gate, a panic after a committed write would surface to the gate
/// as an ordinary 500 instead of leaving its in-flight marker untouched.
fn panic_response(panic: Box<dyn std::any::Any + Send + 'static>) -> Response {
    let detail = panic
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_owned());
    // BTY-5: `into_response` logs the masked detail once; logging here too
    // would make every panic two error lines.
    AppError::Internal(format!("request handler panicked: {detail}")).into_response()
}

/// `HandleErrorLayer`'s handler for the request deadline. When `TimeoutLayer`
/// fires it drops the in-flight request future — the idempotency gate's
/// post-handler bookkeeping included — so the response makes no claim about
/// whether a write happened (`AppError::ServerTimeout`). The inner router is
/// infallible, so `Elapsed` is the only error expected here.
async fn timeout_response(err: BoxError) -> Response {
    if err.is::<tower::timeout::error::Elapsed>() {
        AppError::ServerTimeout.into_response()
    } else {
        AppError::internal(err).into_response()
    }
}

/// Applies the inner, identity-aware stack (outermost first): CachePolicy
/// (AA7-T1) → authn → CSRF → authz → RateLimit → Shed (AB5-T7) →
/// Idempotency → MetadataPin (Y8-T6) → ApiVersion (S8-T1). CSRF (`csrf::csrf_protect`,
/// P-cookie-csrf-hardening) sits right after authn because it needs to know
/// whether the request carries a session cookie at all — the same signal
/// `authn` already resolved into `SessionClaims`/a rejection — and must run
/// before any handler (hence ahead of authz, not after). RateLimit/Idempotency
/// key on `SessionClaims`, which `authn` writes into request extensions —
/// hence they must sit inside authn, not outside it. Must be the FIRST
/// `.layer()` call in the assembly sequence, applied to the bare merged router
/// before `apply_s2s_layer`/`apply_outer_layers`.
pub fn apply_inner_layers(router: Router, state: AppState) -> Router {
    router.layer(
        ServiceBuilder::new()
            // AA7-T1: outermost of this stack, so a rejection by any layer
            // below also says how it may be cached.
            .layer(middleware::from_fn(
                crate::middleware::cache_policy::cache_policy,
            ))
            .layer(middleware::from_fn_with_state(state.clone(), auth::authn))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                csrf::csrf_protect,
            ))
            .layer(middleware::from_fn_with_state(state.clone(), auth::authz))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                rate_limit::rate_limit,
            ))
            // AB5-T7: after authentication and rate limiting, so a shed
            // request has already been counted against its caller.
            .layer(middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::shed::shed,
            ))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                idempotency::idempotency,
            ))
            // Y8-T6: innermost, so a throttled or replayed request never
            // waits on a catch-up.
            .layer(middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::metadata_pin::metadata_pin,
            ))
            // S8-T1: the caller is known here, so its pinned version is too.
            .layer(middleware::from_fn_with_state(
                state,
                crate::middleware::api_version::api_version,
            )),
    )
}

/// Applies the coarse, IP-only pre-auth rate limit (`rate_limit::pre_auth_rate_limit`)
/// — kept as its own function rather than folded into `apply_outer_layers` (which
/// only takes `config`, not `state`) or `apply_inner_layers` (which is keyed on
/// `SessionClaims`, not available yet at this point). Must be composed AFTER
/// `apply_s2s_layer` (so it wraps/runs before s2s_authn) and BEFORE
/// `apply_outer_layers` (so RequestId/Trace/CORS/Timeout/BodyLimit still wrap/run
/// before this) — see `main.rs` for the exact sequence.
pub fn apply_pre_auth_rate_limit(router: Router, state: AppState) -> Router {
    router.layer(middleware::from_fn_with_state(
        state,
        rate_limit::pre_auth_rate_limit,
    ))
}

/// P-audit-chain-hardening item (e) — the ingest circuit breaker
/// (`mutation_gate::mutation_gate`). Composed as its own step (`builder.rs`,
/// right after `apply_pre_auth_rate_limit`, before `apply_outer_layers`) for
/// the same reason `apply_pre_auth_rate_limit` is its own function: it needs
/// `state` (an atomic-load, not config), and it must run ahead of
/// `apply_inner_layers`' identity-aware stack — the breaker is a
/// system-protective check that applies uniformly, before authn does any
/// work, not a per-user policy. A cheap `Ordering::Relaxed` atomic load, so
/// placement relative to `apply_pre_auth_rate_limit` doesn't matter for
/// cost. It is layered outside that limiter, so it runs first: while the
/// breaker is tripped, a write is answered 503 `overloaded` even from a
/// client whose pre-auth budget is spent, and no rate-limit budget is
/// consumed by a request the breaker refuses. Pinned by
/// `middleware_pipeline.rs`'s
/// `the_mutation_gate_and_the_pre_auth_limiter_both_answer_before_authn`.
pub fn apply_mutation_gate(router: Router, state: AppState) -> Router {
    router.layer(middleware::from_fn_with_state(
        state,
        mutation_gate::mutation_gate,
    ))
}

/// P-environment-promotion Phase 0 — the metadata authoring gate
/// (`authoring_gate::authoring_gate`): on `app.deployment_profile =
/// "production"` a mutating request to a metadata-authoring prefix is refused
/// with 403 `metadata_authoring_locked` unless an approved break-glass window
/// is open; on `development` it is a no-op. Composed as its own step in
/// `builder.rs`, directly after `apply_mutation_gate` and for the same
/// reasons that one is where it is: it needs `state` (the profile lives on
/// `state.config`; the break-glass window is a Redis `EXISTS` on
/// `state.redis_coordination`), and it is a deployment-wide policy that
/// applies uniformly before authn does any work, not a per-user privilege —
/// a locked deployment answers "nobody authors here" identically to every
/// caller, so there is nothing for authn/authz to add first. The common
/// path (development profile, or any read, or any non-authoring path) is
/// decided with zero I/O; Redis is touched only for a request that would
/// otherwise be rejected.
pub(crate) fn apply_authoring_gate(router: Router, state: AppState) -> Router {
    router.layer(middleware::from_fn_with_state(
        state,
        authoring_gate::authoring_gate,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    // `Method` now comes from the parent module's own import (added for
    // `ALLOWED_METHODS`) via `use super::*` above — importing it again here
    // is redundant.
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    /// Enough `AppConfig` to build the real outer stack — never validated,
    /// nothing in it is connected to. With no `cors.allowed_origins`, the
    /// allow-list falls back to `http://localhost:4200`.
    fn outer_stack_config() -> AppConfig {
        serde_json::from_str(
            r#"{
                "app": {
                    "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                    "frontend_port": 4200, "log_level": "error", "threads": 1,
                    "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
                    "enable_session": true, "max_connection_num": 64,
                    "max_connection_num_per_ip": 16, "use_gzip": false,
                    "enable_compression": false, "gzip_level": 1, "br_level": 1,
                    "idle_connection_timeout": 30, "keepalive_requests": 100,
                    "static_files_cache_time": 0, "server_header_field": "attome-test"
                },
                "database": {
                    "host": "localhost", "port": 5555, "dbname": "unused",
                    "user": "unused", "password": "unused", "schema": "public",
                    "connection_number": 5, "timeout": 5.0
                },
                "cache": {
                    "host": "localhost", "port": 6379, "password": "",
                    "db": 0, "connection_pool_size": 4, "timeout": 2000,
                    "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                    "metadata_registry_enabled": true
                },
                "storage": {
                    "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                    "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                    "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
                },
                "auth": {
                    "jwt_secret": "test-only-throwaway-secret", "jwt_issuer": "attome-test",
                    "jwt_expiry_hours": 1, "oauth_google_client_id": "", "oauth_google_client_secret": ""
                },
                "rate_limit": { "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {} },
                "observability": {
                    "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                    "enable_distributed_tracing": false
                },
                "email": {
                    "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                    "smtp_password": "", "smtp_from_address": "test@test.local",
                    "smtp_from_name": "test", "smtp_use_tls": false,
                    "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1
                },
                "google_ai": {
                    "api_key": "", "base_url": "https://example.invalid",
                    "default_model": "none", "timeout_seconds": 1
                },
                "llm_api": {},
                "external_api": {},
                "s2s": { "enabled": false },
                "security": { "bootstrap_admin_email": null }
            }"#,
        )
        .expect("outer_stack_config JSON must deserialize into AppConfig")
    }

    use axum::http::StatusCode;

    const ALLOWED_ORIGIN: &str = "http://localhost:4200";

    /// P1.5. A declared-oversized body is rejected by the Content-Length guard
    /// inside the standard envelope — JSON `payload_too_large`, `request_id`
    /// in header and body, security headers, CORS — instead of a bare 413
    /// produced outside RequestId/Trace/CORS.
    #[tokio::test]
    async fn a_declared_oversized_body_returns_the_json_413_envelope() {
        use tower::ServiceExt;

        let config = outer_stack_config();
        let app = apply_outer_layers(
            Router::new().route("/upload", axum::routing::post(|| async { "ok" })),
            &config,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/upload")
                    .header(header::ORIGIN, ALLOWED_ORIGIN)
                    .header(
                        header::CONTENT_LENGTH,
                        (config.app.max_body_size_bytes + 1).to_string(),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router is infallible");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let headers = response.headers().clone();
        let request_id = headers
            .get("x-request-id")
            .expect("x-request-id header")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(
            headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            ALLOWED_ORIGIN
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON body");
        assert_eq!(body["error"], "payload_too_large");
        assert_eq!(body["request_id"], request_id);
    }

    /// AA7-T6: one GET through the outer stack for a body of `len` bytes of
    /// `content_type`, accepting gzip and br; returns the `content-encoding`.
    async fn encoding_for(content_type: &'static str, len: usize) -> Option<String> {
        use tower::ServiceExt;

        let body = "a".repeat(len);
        let app = apply_outer_layers(
            Router::new().route(
                "/x",
                get(move || {
                    let body = body.clone();
                    async move { ([(header::CONTENT_TYPE, content_type)], body).into_response() }
                }),
            ),
            &outer_stack_config(),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header(header::ACCEPT_ENCODING, "gzip, br")
                    .header(header::ORIGIN, ALLOWED_ORIGIN)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router is infallible");
        assert_eq!(response.status(), StatusCode::OK);
        response
            .headers()
            .get(header::CONTENT_ENCODING)
            .map(|v| v.to_str().unwrap().to_owned())
    }

    #[tokio::test]
    async fn compression_skips_body_under_1kb() {
        assert_eq!(encoding_for("application/json", 900).await, None);
    }

    #[tokio::test]
    async fn compression_uses_br_for_large_json() {
        assert_eq!(
            encoding_for("application/json", 4096).await.as_deref(),
            Some("br")
        );
    }

    #[tokio::test]
    async fn compression_skips_png() {
        assert_eq!(encoding_for("image/png", 4096).await, None);
        assert_eq!(encoding_for("application/pdf", 4096).await, None);
    }

    /// P0.1 / A1 (BSV-F01) — an error produced *inside* `CompressionLayer` must
    /// still carry `request_id` in its JSON body when the client accepts gzip.
    /// `CompressionLayer` sits inside `request_id_body` in the outer stack, so
    /// it compressed the body before the request-id middleware could parse it,
    /// and the id was silently lost for every cross-origin SDK caller that
    /// sends `Accept-Encoding` (the header the browser always sends).
    #[tokio::test]
    async fn an_error_body_carries_request_id_when_the_client_accepts_gzip() {
        use tower::ServiceExt;

        let app = apply_outer_layers(
            Router::new().route("/x", get(|| async { AppError::NotFound.into_response() })),
            &outer_stack_config(),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header(header::ACCEPT_ENCODING, "gzip, br")
                    .header(header::ORIGIN, ALLOWED_ORIGIN)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router is infallible");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let request_id = response
            .headers()
            .get("x-request-id")
            .expect("x-request-id header")
            .to_str()
            .unwrap()
            .to_owned();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!(
                "an error body must stay JSON even when the client accepts gzip, got {e}; \
                 content-encoding was set by CompressionLayer: raw={:?}",
                String::from_utf8_lossy(&bytes)
            )
        });
        assert_eq!(body["error"], "not_found");
        assert_eq!(body["request_id"], request_id);
    }

    /// A2 (BSV-F06) — an allowed origin must be able to **read** the headers
    /// the SDK needs (its correlation id, its backoff). The CORS safelist hides
    /// everything else, so this list is the contract.
    #[tokio::test]
    async fn an_allowed_origin_sees_the_exposed_headers() {
        use tower::ServiceExt;

        let app = apply_outer_layers(
            Router::new().route("/x", get(|| async { "ok" })),
            &outer_stack_config(),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header(header::ORIGIN, ALLOWED_ORIGIN)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router is infallible");
        let exposed = response
            .headers()
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .expect("an allowed origin must get Access-Control-Expose-Headers")
            .to_str()
            .unwrap()
            .to_ascii_lowercase();
        let exposed: Vec<&str> = exposed.split(',').map(str::trim).collect();
        for required in exposed_response_headers() {
            assert!(
                exposed.contains(&required.as_str()),
                "Access-Control-Expose-Headers must name {required}, got {exposed:?}"
            );
        }
    }

    /// A2 (BSV-F06) — the preflight is cacheable rather than re-sent before
    /// every non-simple cross-origin call.
    #[tokio::test]
    async fn a_preflight_carries_max_age() {
        use tower::ServiceExt;

        let app = apply_outer_layers(
            Router::new().route("/x", get(|| async { "ok" })),
            &outer_stack_config(),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/x")
                    .header(header::ORIGIN, ALLOWED_ORIGIN)
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router is infallible");
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            ALLOWED_ORIGIN
        );
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_MAX_AGE)
                .expect("a preflight must carry Access-Control-Max-Age")
                .to_str()
                .unwrap(),
            CORS_MAX_AGE.as_secs().to_string()
        );
    }

    #[test]
    fn a_request_id_must_be_one_short_token_of_safe_characters() {
        assert!(is_acceptable_request_id(
            b"0190c3a5-7b2e-7c1d-9f00-1234567890ab"
        ));
        assert!(is_acceptable_request_id(b"trace.abc_DEF-9"));
        assert!(is_acceptable_request_id(&[b'a'; 64]));
        assert!(!is_acceptable_request_id(b""));
        assert!(!is_acceptable_request_id(&[b'a'; 65]));
        assert!(!is_acceptable_request_id(b"has space"));
        // A tab is the one control character a header value may carry.
        assert!(!is_acceptable_request_id(b"tab\tinside"));
        assert!(!is_acceptable_request_id(b"brace{quote\""));
        assert!(!is_acceptable_request_id("ünïcode".as_bytes()));
    }

    /// A valid client-supplied id survives the outer stack unchanged; an absent,
    /// invalid, over-long or repeated one is replaced by a generated id.
    #[tokio::test]
    async fn an_unsafe_client_request_id_is_replaced_and_a_safe_one_is_kept() {
        use tower::ServiceExt;

        let app = apply_outer_layers(Router::new(), &outer_stack_config());
        let echoed = |ids: Vec<String>| {
            let app = app.clone();
            async move {
                let mut request = Request::builder().uri("/missing");
                for id in &ids {
                    request = request.header(X_REQUEST_ID, id.as_str());
                }
                let response = app
                    .oneshot(request.body(Body::empty()).unwrap())
                    .await
                    .expect("router is infallible");
                response
                    .headers()
                    .get(X_REQUEST_ID)
                    .expect("x-request-id header")
                    .to_str()
                    .unwrap()
                    .to_owned()
            }
        };

        assert_eq!(
            echoed(vec!["client-trace.42_A".to_owned()]).await,
            "client-trace.42_A"
        );
        for ids in [
            Vec::new(),
            vec!["has space".to_owned()],
            vec!["tab\tinside".to_owned()],
            vec!["x".repeat(65)],
            vec!["brace{}".to_owned()],
            vec!["first".to_owned(), "second".to_owned()],
        ] {
            let generated = echoed(ids.clone()).await;
            assert!(
                uuid::Uuid::parse_str(&generated).is_ok(),
                "{ids:?} must be replaced by a generated id, got {generated}"
            );
        }
    }

    async fn slow_handler() -> &'static str {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        "too late"
    }

    /// P1.4. A request that outlives `request_timeout` gets the JSON
    /// `server_timeout` 503 with the same envelope as every other framework
    /// error, not a bare 408. The assembled-router version, with an
    /// idempotency key, is in `crates/server/tests/middleware_pipeline.rs`.
    #[tokio::test]
    async fn a_request_past_the_deadline_returns_the_json_503_server_timeout_envelope() {
        use tower::ServiceExt;

        let mut config = outer_stack_config();
        config.app.request_timeout_secs = 1;
        let app = apply_outer_layers(
            Router::new()
                .route("/slow", get(slow_handler))
                .route("/ok", get(|| async { "ok" })),
            &config,
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/slow")
                    .header(header::ORIGIN, ALLOWED_ORIGIN)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router is infallible");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let headers = response.headers().clone();
        let request_id = headers
            .get("x-request-id")
            .expect("x-request-id header")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(
            headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            ALLOWED_ORIGIN
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON body");
        assert_eq!(body["error"], "server_timeout");
        assert_eq!(body["request_id"], request_id);

        let fast = app
            .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
            .await
            .expect("router is infallible");
        assert_eq!(fast.status(), StatusCode::OK);
    }

    async fn panicking_handler() -> &'static str {
        panic!("secret-panic-detail")
    }

    /// P1.3. A panic beneath the outer stack must come back as the standard
    /// envelope — status, error code, `request_id` in header and body,
    /// security headers, CORS — never a dropped connection, and never with the
    /// panic text in the body. The same router must keep serving afterwards.
    #[tokio::test]
    async fn a_panic_returns_the_masked_500_envelope_and_the_server_keeps_serving() {
        use tower::ServiceExt;

        let app = apply_outer_layers(
            Router::new()
                .route("/boom", get(panicking_handler))
                .route("/ok", get(|| async { "ok" })),
            &outer_stack_config(),
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/boom")
                    .header(header::ORIGIN, ALLOWED_ORIGIN)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router is infallible");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let headers = response.headers().clone();
        let request_id = headers
            .get("x-request-id")
            .expect("x-request-id header")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(
            headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            ALLOWED_ORIGIN
        );

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes).contains("secret-panic-detail"),
            "the panic payload must never reach the client"
        );
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON body");
        assert_eq!(body["error"], "internal_error");
        assert_eq!(body["request_id"], request_id);

        let after = app
            .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
            .await
            .expect("router is infallible");
        assert_eq!(after.status(), StatusCode::OK);
    }

    /// Minimal `Subscriber` that records the fields a span was created with,
    /// so `request_span`'s output can be asserted on without pulling in a
    /// full tracing-subscriber test harness.
    struct RecordingSubscriber {
        captured: Arc<Mutex<Vec<(String, String)>>>,
    }

    struct FieldVisitor<'a>(&'a mut Vec<(String, String)>);

    impl Visit for FieldVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .push((field.name().to_string(), format!("{value:?}")));
        }
    }

    impl Subscriber for RecordingSubscriber {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, attrs: &Attributes<'_>) -> Id {
            let mut fields = self.captured.lock().unwrap();
            attrs.record(&mut FieldVisitor(&mut fields));
            Id::from_u64(1)
        }

        fn record(&self, _span: &Id, _values: &Record<'_>) {}
        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
        fn event(&self, _event: &Event<'_>) {}
        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
    }

    /// Regression test for the OAuth code/state logging leak: `oidc_callback`
    /// (crates/server/src/auth.rs) receives `code`/`state` as query params,
    /// and this span used to record the full URI via `%request.uri()`,
    /// putting those secrets in every log line for the request. Asserts the
    /// `uri` field the span is created with never contains `?` (or the query
    /// values themselves) — i.e. it's path-only.
    #[test]
    fn request_span_uri_field_excludes_query_string() {
        let captured: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
        let subscriber = RecordingSubscriber {
            captured: captured.clone(),
        };

        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/auth/oidc/okta/callback?code=super-secret-code&state=abc123")
            .body(Body::empty())
            .unwrap();

        tracing::subscriber::with_default(subscriber, || {
            let _span = request_span(&request);
        });

        let fields = captured.lock().unwrap();
        let uri_field = fields
            .iter()
            .find(|(name, _)| name == "uri")
            .map(|(_, value)| value.clone())
            .expect("request_span must record a `uri` field");

        assert!(
            !uri_field.contains('?'),
            "span `uri` field must be path-only, no query string: {uri_field}"
        );
        assert!(!uri_field.contains("super-secret-code"));
        assert!(!uri_field.contains("abc123"));
        // `%field` records via `Display`, not `Debug` — no surrounding quotes.
        assert_eq!(uri_field, "/api/v1/auth/oidc/okta/callback");
    }

    /// `HeaderName::from_static` panics on a non-lowercase or otherwise
    /// invalid name, and `cors_layer` runs at boot — so a typo in
    /// `allowed_request_headers` would take the process down on startup
    /// rather than fail anything earlier. Calling it here converts that into
    /// a test failure. Also guards against a duplicate entry, which would
    /// silently suggest the list is longer than it is.
    #[test]
    fn allowed_request_headers_are_valid_lowercase_and_unique() {
        let headers = allowed_request_headers();

        for h in &headers {
            let name = h.as_str();
            assert_eq!(
                name,
                name.to_ascii_lowercase(),
                "CORS request header must be lowercase: {name}"
            );
        }

        let mut seen: Vec<&str> = headers.iter().map(|h| h.as_str()).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "duplicate CORS header");

        // D-785: a browser client names its open changeset with this header;
        // without it a cross-origin metadata write cannot pick a changeset.
        assert!(
            seen.contains(&"x-attome-changeset"),
            "X-Attome-Changeset must be preflight-approvable"
        );
    }

    /// Every method `middleware::is_mutating` treats as state-changing (the
    /// predicate CSRF, idempotency and both gates share) must be
    /// preflight-approvable, or a legitimate cross-origin mutation from an
    /// allow-listed origin is blocked by the browser before it reaches
    /// `csrf_protect`. `GET` and the `OPTIONS` preflight itself are the safe
    /// methods the API needs on top.
    #[test]
    fn allowed_methods_cover_every_mutating_method_plus_the_safe_ones() {
        let candidates = [
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
            Method::CONNECT,
            Method::TRACE,
        ];
        for m in candidates
            .iter()
            .filter(|m| crate::middleware::is_mutating(m))
            .chain([&Method::GET, &Method::OPTIONS])
        {
            assert!(
                ALLOWED_METHODS.contains(m),
                "{m} is mutating or required for preflight but is not CORS-approved"
            );
        }
    }
}
