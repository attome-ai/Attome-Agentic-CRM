//! Profiler Admin API — the read side of the "Profiler" dashboard: aggregate
//! call count/avg/min/max/total-since-start per `measure!()` probe
//! (`attome-profiler`), grouped into API + sub-part trees, plus a recent-trace
//! waterfall sample per top-level probe — and the operator's `DELETE` reset
//! that clears the profiler keyspace without flushing the store the security
//! controls live on (BPR-31).
//!
//! All routes are under /api/v1/admin/profiler/ and require `system.admin`
//! (mounted with `strict_authz` in `system.rs`, same as `s2s_admin`).
//!
//! Z3-T9: the cache numbers live here too, as the other half of "where does
//! the time go" (a new `attome-api` module would grow the module-inventory
//! ratchet). `GET /api/v1/admin/caches` lists every declared cache built on
//! this node with its entries, hits, misses, evictions and hit rate;
//! `POST /api/v1/admin/caches/{name}/purge` drops one key, or everything,
//! from the cache on this node and, through the Postgres notification
//! [`CACHE_PURGE_CHANNEL`] sent in the audit event's transaction, on every
//! other node.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::AppError;
use attome_types::ErrorResponse;
use attome_types::{OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

fn map_err(op: &'static str) -> impl Fn(attome_profiler::ProfilerError) -> AppError {
    move |e| AppError::internal(format!("profiler {op} failed: {e}"))
}

#[derive(Serialize, ToSchema)]
struct StatOut {
    name: String,
    count: u64,
    total_ms: f64,
    avg_ms: f64,
    min_ms: f64,
    max_ms: f64,
}

impl From<attome_profiler::StatRow> for StatOut {
    fn from(r: attome_profiler::StatRow) -> Self {
        Self {
            name: r.name,
            count: r.count,
            total_ms: r.total_ms,
            avg_ms: r.avg_ms,
            min_ms: r.min_ms,
            max_ms: r.max_ms,
        }
    }
}

#[derive(Serialize, ToSchema)]
struct ApiGroupOut {
    api: StatOut,
    parts: Vec<StatOut>,
}

/// Profiler statistics
///
/// Profiler statistics. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/profiler/stats",
    tag = "admin",
    responses(
        (status = 200, description = "Success", body = Vec<ApiGroupOut>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn stats(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Deployment>>,
) -> Result<Json<Vec<ApiGroupOut>>, AppError> {
    let rows = attome_profiler::read_stats(&state.base.redis)
        .await
        .map_err(map_err("read_stats"))?;

    Ok(Json(
        attome_profiler::group_hierarchy(rows)
            .into_iter()
            .map(|g| ApiGroupOut {
                api: g.api.into(),
                parts: g.parts.into_iter().map(Into::into).collect(),
            })
            .collect(),
    ))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct TraceQuery {
    /// Top-level probe name, e.g. `"entity.create"` or `"GET /api/v1/entities/{logicalname}"`
    /// — a query param, not a path segment, since probe names routinely
    /// contain `/` and spaces that a path segment can't carry unencoded.
    name: String,
    /// The most rows to return.
    #[serde(default = "default_trace_limit")]
    limit: i64,
}

fn default_trace_limit() -> i64 {
    20
}

#[derive(Serialize, ToSchema)]
struct TracePartOut {
    name: String,
    ms: f64,
}

#[derive(Serialize, ToSchema)]
struct TraceSampleOut {
    ts: i64,
    total_ms: f64,
    parts: Vec<TracePartOut>,
}

impl From<attome_profiler::TraceSample> for TraceSampleOut {
    fn from(s: attome_profiler::TraceSample) -> Self {
        Self {
            ts: s.ts,
            total_ms: s.total_ms,
            parts: s
                .parts
                .into_iter()
                .map(|p| TracePartOut {
                    name: p.name,
                    ms: p.ms,
                })
                .collect(),
        }
    }
}

/// Profiler trace
///
/// Profiler trace. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/profiler/trace",
    tag = "admin",
    params(TraceQuery),
    responses(
        (status = 200, description = "Success", body = Vec<TraceSampleOut>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn trace(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Deployment>>,
    Query(q): Query<TraceQuery>,
) -> Result<Json<Vec<TraceSampleOut>>, AppError> {
    if q.name.trim().is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    let limit = q.limit.clamp(1, 50);

    let samples = attome_profiler::read_trace(&state.base.redis, &q.name, limit)
        .await
        .map_err(map_err("read_trace"))?;

    Ok(Json(samples.into_iter().map(Into::into).collect()))
}

/// Resets the profiler: unlinks every `attome-profiler:*` key (plus the legacy
/// `profiler:*` namespace that predates the rename and never expired) so an
/// operator can start a clean measurement window without flushing the store
/// the security controls live on. Admin-only, audited (D-542: the `x-audit`
/// declaration below plus the in-transaction event this handler writes), and
/// idempotent — a second call still answers 204 with nothing left to delete.
///
/// The reset itself is a Redis `UNLINK`, not a database mutation, so there is
/// no domain transaction to ride: a transaction is opened solely for the
/// mandatory audit event, and a write failure fails the request (the unlink
/// is idempotent, so retrying is safe).
///
/// BPR-16: every profiler site — the request middleware, the boot and job
/// flushes, and these three routes — uses the general `state.base.redis` pool,
/// never the fail-closed `redis_coordination` one, so the dashboard reads the
/// store the writers write and profiler load cannot compete with the pre-auth
/// limiter or S2S nonces (D-397).
#[utoipa::path(
    delete,
    path = "/api/v1/admin/profiler/stats",
    tag = "admin",
    responses(
        (status = 204, description = "Profiler keys removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(
        attome_audit::AuditCategory::Configuration,
        attome_audit::AuditOperation::HardDelete,
    )])))),
)]
async fn reset_stats(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Deployment>>,
) -> Result<StatusCode, AppError> {
    let deleted = attome_profiler::reset(&state.base.redis)
        .await
        .map_err(map_err("reset"))?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::HardDelete,
            ctx.user_id,
            "attome-profiler",
            None,
        )
        .named("profiler.reset")
        .comment(format!("deleted {deleted} profiler keys")),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Z3-T9: the Postgres channel a cache purge is announced on; its payload is
/// a [`CachePurge`] as JSON. Every node listens and purges its own copy.
pub(crate) const CACHE_PURGE_CHANNEL: &str = "attome_cache_purge";

/// The longest key a purge names (a notification payload is under 8000
/// bytes).
const MAX_PURGE_KEY_BYTES: usize = 512;

/// One declared cache's numbers on one node.
#[derive(Serialize, ToSchema)]
struct CacheStatsRow {
    name: String,
    /// The node these numbers are from (each node counts its own).
    node: String,
    /// Entries in the in-process tier now.
    entries: u64,
    /// Reads the in-process tier answered since this node started.
    hits: u64,
    /// Reads that went on to the shared store or the source.
    misses: u64,
    /// Entries pushed out by the capacity or the quota.
    evictions: u64,
    /// hits / (hits + misses), or `null` before the first read.
    hit_rate: Option<f64>,
}

/// Lists each declared cache built on this node with its numbers (Z3-T9).
#[utoipa::path(
    get,
    path = "/api/v1/admin/caches",
    description = "Each declared cache on the node that answers, with its entries, hits, misses, evictions and hit rate (Z3-T9). Each node counts its own; no cached value is returned.",
    operation_id = "list_caches",
    tag = "admin",
    params(OnePageQuery),
    responses(
        (status = 200, description = "This node's caches, by name", body = PaginatedResponse<CacheStatsRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_caches(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Deployment>>,
    Query(page): Query<OnePageQuery>,
) -> Json<PaginatedResponse<CacheStatsRow>> {
    let window = page.window();
    let node = attome_server::metrics_store::node_name(state.base.config.app.port);
    let all = attome_cache::admin::stats();
    let total = i64::try_from(all.len()).unwrap_or(i64::MAX);
    let items = all
        .into_iter()
        .skip(usize::try_from(window.offset).unwrap_or(usize::MAX))
        .take(usize::try_from(window.page_size).unwrap_or(0))
        .map(|s| {
            let reads = s.hits + s.misses;
            CacheStatsRow {
                name: s.name.to_owned(),
                node: node.clone(),
                entries: s.entries,
                hits: s.hits,
                misses: s.misses,
                evictions: s.evictions,
                hit_rate: (reads > 0).then(|| s.hits as f64 / reads as f64),
            }
        })
        .collect();
    Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    ))
}

/// What to purge: one key (as the cache's readers name it), or everything.
#[derive(Debug, Default, Serialize, Deserialize, ToSchema)]
pub(crate) struct CachePurge {
    /// The cache, by its declared name. Filled from the path.
    #[serde(default)]
    #[schema(read_only)]
    name: String,
    /// The id to drop; omit it to drop every entry.
    #[serde(default)]
    key: Option<String>,
}

/// Purges one key, or every entry, of a cache on every node (Z3-T9). Every
/// node drops it from its in-process tier; one key of a shared cache is also
/// deleted from the shared store. Shared-store copies of a whole-cache purge,
/// or of a partitioned cache's per-reader entries, live out their TTL.
#[utoipa::path(
    post,
    path = "/api/v1/admin/caches/{name}/purge",
    description = "Drops one key, or the whole cache, here and, through a notification sent with the audit event, on every other node (Z3-T9).",
    operation_id = "purge_cache",
    tag = "admin",
    params(("name" = String, Path, description = "The cache's declared name")),
    request_body(content = Option<CachePurge>, description = "`{\"key\": \"...\"}` for one key; empty for everything"),
    responses(
        (status = 204, description = "Purged here; the other nodes purge on the notification"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No cache of that name is built on this node", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(
        attome_audit::AuditCategory::Configuration,
        attome_audit::AuditOperation::Update,
    )])))),
)]
async fn purge_cache(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    Path(name): Path<String>,
    body: Option<Json<CachePurge>>,
) -> Result<StatusCode, AppError> {
    if !attome_cache::admin::known(&name) {
        return Err(AppError::NotFound);
    }
    let key = body.and_then(|Json(b)| b.key).filter(|k| !k.is_empty());
    if key.as_ref().is_some_and(|k| k.len() > MAX_PURGE_KEY_BYTES) {
        return Err(AppError::Validation(format!(
            "key: at most {MAX_PURGE_KEY_BYTES} bytes"
        )));
    }
    let what = key
        .as_deref()
        .map_or_else(|| "every entry".to_owned(), |k| format!("key {k}"));
    let payload = serde_json::to_string(&CachePurge {
        name: name.clone(),
        key: key.clone(),
    })
    .map_err(AppError::internal)?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "attome-cache",
            None,
        )
        .named("cache.purge")
        .comment(format!(
            "purged {what} of {name} from every node's in-process tier"
        )),
    )
    .await?;
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(CACHE_PURGE_CHANNEL)
        .bind(&payload)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;
    // After the commit, so a purge never happens unaudited; the other nodes
    // purge on the notification the commit sent.
    attome_cache::admin::purge(&name, key.as_deref()).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Z3-T9: this node's answer to a purge another node announced.
pub(crate) async fn apply_purge(payload: &str) {
    match serde_json::from_str::<CachePurge>(payload) {
        Ok(purge) => {
            attome_cache::admin::purge(&purge.name, purge.key.as_deref()).await;
        }
        Err(error) => tracing::warn!(%error, "cache purge notification does not parse; ignored"),
    }
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/profiler/stats",
            get(stats).delete(reset_stats),
        )
        .route("/api/v1/admin/profiler/trace", get(trace))
        .route("/api/v1/admin/caches", get(list_caches))
        .route("/api/v1/admin/caches/{name}/purge", post(purge_cache))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(stats, trace, reset_stats, list_caches, purge_cache),
    components(schemas(CacheStatsRow, CachePurge))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
