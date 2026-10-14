//! P-health-readiness (extended by P-observability-completion) — `GET
//! /health/dependencies`: read-only diagnostic coverage for object storage,
//! apalis job workers, email/SMTP and the audit chainer.
//! Deliberately separate from `attome_server::health_routes`'s `/health/ready`
//! (readiness — gates load-balancer/Kubernetes traffic routing on DB/Redis/
//! registry) and `attome_server::liveness_routes`'s `/health` (liveness — must
//! never depend on anything, including Redis; see that function's doc
//! comment): a down SMTP relay, a stalled job worker, or a lagging audit
//! chainer must never pull an otherwise-healthy, DB-serving node out of
//! rotation. This endpoint therefore **always returns 200** — a
//! diagnostic-only endpoint that can return a non-200 status is one careless
//! `livenessProbe:` edit away from becoming a second, accidental readiness
//! gate. **Administrators only** (U9-T2): unlike `/health` and `/health/ready`,
//! which a load balancer polls, this one describes the deployment's
//! internals (which relays and workers exist, their lag), so a monitor reads
//! it with an administrator API key. It no longer reports which modules are
//! on.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::ErrorResponse;
use axum::{Json, Router, extract::State, routing::get};
use serde_json::{Value, json};

#[utoipa::path(
    get,
    path = "/health/dependencies",
    tag = "operations",
    responses(
        (status = 200, description = "Success", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn dependencies(State(state): State<EngineState>, _ctx: Authorized<Admin>) -> Json<Value> {
    let (storage, email) = tokio::join!(
        attome_storage::health_check(&state.base.storage),
        attome_email::health_check_with_timeout(
            &state.base.config.email,
            attome_email::CAPABILITY_PROBE_TIMEOUT,
        ),
    );

    // P-production-safety-profile follow-up — `storage.clamd_address` empty
    // is a deliberate "malware scanning disabled" configuration (fails
    // closed on upload instead, see `AppConfig::validate_production_profile`'s
    // `check_not_placeholder` doc comment), never attempt a connection in
    // that case.
    let clamd_address = state.base.config.storage.clamd_address.trim();
    let clamav = if clamd_address.is_empty() {
        json!({ "enabled": false })
    } else {
        let health = attome_storage::clamav_health_check(clamd_address).await;
        json!({ "enabled": true, "reachable": health.reachable, "latency_ms": health.latency_ms, "error": health.error })
    };
    let (fast_age, batch_age) = tokio::join!(
        attome_jobs::worker_last_seen_age_seconds(&state.base.db, false),
        attome_jobs::worker_last_seen_age_seconds(&state.base.db, true),
    );

    let audit = if state.base.config.audit.chainer_enabled {
        match attome_audit::chainer::aggregate_lag(&state.base.db).await {
            Ok(agg) => json!({
                "enabled": true,
                "organizations_pending": agg.organizations_pending,
                "total_pending_ingest": agg.total_pending_ingest,
                "max_lag_seconds": agg.max_lag_seconds,
            }),
            Err(e) => json!({ "enabled": true, "error": e.to_string() }),
        }
    } else {
        // D-029: no automatic fallback to the sync path — a disabled
        // chainer is a deliberate deployment choice, not a failure.
        json!({ "enabled": false })
    };

    // D-344 (amends D-167) — the enforceable half. Everything above is a
    // *live* probe run for this request; this block is what the route-level
    // gate (`attome_server::capability`) is currently enforcing, as maintained
    // by `crate::capability_probe::spawn_capability_refresh`.
    //
    // The two can legitimately disagree for up to one probe interval — a
    // relay that came back thirty seconds ago reads `reachable: true` above
    // and still `unavailable` here, because the gate has not re-probed yet.
    // That difference is exactly what an operator asking "why am I still
    // getting 503s, it's back up" needs to see, so both are reported rather
    // than one being derived from the other.
    //
    // `audit_ingest` is listed alongside them but is deliberately NOT a
    // `Capability`: its breaker predates this mechanism, gates *all*
    // mutating verbs globally through `attome_server::middleware::
    // mutation_gate` rather than a named set of routes, and reusing the
    // existing flag keeps one source of truth instead of adding a second
    // one that could drift.
    let capabilities = state.base.capabilities.snapshot();
    let audit_ingest_tripped = state
        .base
        .audit_ingest_backlog_exceeded
        .load(std::sync::atomic::Ordering::Relaxed);

    Json(json!({
        "storage": storage,
        "email": email,
        "clamav": clamav,
        "jobs": {
            "fast":  { "worker_last_seen_age_seconds": fast_age.ok().flatten() },
            "batch": { "worker_last_seen_age_seconds": batch_age.ok().flatten() },
        },
        "audit_chainer": audit,
        "capabilities": {
            "gated_routes": capabilities,
            "audit_ingest": {
                "breaker_tripped": audit_ingest_tripped,
                "scope": "all mutating verbs (global), see D-167/P-audit-chain-hardening",
            },
        },
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/health/dependencies", get(dependencies))
        .route("/api/v1/admin/latency", get(latency))
}

/// `GET /api/v1/admin/latency`.
#[derive(serde::Serialize, utoipa::ToSchema)]
struct LatencyReport {
    /// Metrics are on in this process (`observability.metrics_port` set).
    enabled: bool,
    /// Every route seen since this process started, slowest p95 first.
    routes: Vec<attome_server::metrics::RouteLatency>,
}

/// AA1-T6: per-route p50, p95 and p99 latency on this node since it started,
/// from the same request-duration histogram `/metrics` exposes. Administrators
/// only. Empty, with `enabled: false`, when metrics are off.
#[utoipa::path(
    get,
    path = "/api/v1/admin/latency",
    tag = "operations",
    responses(
        (status = 200, description = "Per-route latency on this node", body = LatencyReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn latency(_ctx: Authorized<Admin>) -> Json<LatencyReport> {
    let text = attome_server::metrics::render_current();
    Json(LatencyReport {
        enabled: text.is_some(),
        routes: text
            .as_deref()
            .map(attome_server::metrics::route_latencies)
            .unwrap_or_default(),
    })
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(dependencies, latency))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
