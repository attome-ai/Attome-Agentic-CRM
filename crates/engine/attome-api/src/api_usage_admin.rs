//! M61 Phase 1 (API Management, D-438) — `GET /api/v1/admin/api-usage/summary`,
//! `system.admin` only. Reads the nightly rollup table `api_usage`
//! (migration `0234_xrm_core_api_usage.sql`, populated by
//! `EngineJob::ApiUsageRollup` off the buffer `attome_server::api_usage`
//! writes on every authenticated request).
//!
//! The module plan's target design also names a dashboard widget
//! (`attome-dashboard`'s widget registry). That registry is built around
//! `dashboard_metric_definition`/`metric_snapshot` — a metric *definition* a
//! customer authors and a scheduled snapshot job evaluates against a stored
//! query or an entity aggregate (see `attome-dashboard/src/metric.rs`) — not an
//! arbitrary read like this one. Wiring API usage into that model would mean
//! teaching the metric engine a whole new data source for a single fixed
//! report, a materially larger change than this admin endpoint. This
//! endpoint is the deliberately smaller substitute the module plan allows
//! for; a real dashboard widget is left for a future pass.
//!
//! S10-T1 adds the per-key view: `GET /api/v1/admin/api-keys` lists every
//! key with its owner, its own quota and its requests over the window, and
//! `PUT /api/v1/admin/api-keys/{id}/quota` sets or clears the quota
//! (`api_key.requests_per_minute`), which `attome_server`'s rate limiter
//! enforces across every route the key calls.
use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, put},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// S10-T1: the largest per-key quota an admin may set, per minute.
pub const MAX_KEY_QUOTA: i32 = 100_000;

const DEFAULT_WINDOW_DAYS: i64 = 7;
const MAX_WINDOW_DAYS: i64 = 90;

#[derive(Deserialize, IntoParams)]
struct SummaryQuery {
    /// How many trailing days (inclusive of today) to aggregate over.
    /// Defaults to 7, clamped to [1, 90].
    days: Option<i64>,
    /// One-based — the first page is `page=1` (D-347).
    page: Option<i64>,
    page_size: Option<i64>,
}

#[derive(sqlx::FromRow, Serialize, ToSchema)]
struct ApiUsageSummaryRow {
    method: String,
    route_template: String,
    identity_kind: String,
    identity_label: String,
    total_requests: i64,
}

/// `GET /api/v1/admin/api-usage/summary` — `system.admin` only. Per-route/
/// per-identity request counts aggregated over the trailing `days` window,
/// most-requested first. Counts only, same posture as the source table —
/// never a request payload, header, or query string.
#[utoipa::path(
    get,
    path = "/api/v1/admin/api-usage/summary",
    tag = "admin",
    params(SummaryQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ApiUsageSummaryRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn summary(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<SummaryQuery>,
) -> Result<Json<PaginatedResponse<ApiUsageSummaryRow>>, AppError> {
    let days = q
        .days
        .unwrap_or(DEFAULT_WINDOW_DAYS)
        .clamp(1, MAX_WINDOW_DAYS);
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    let rows: Vec<ApiUsageSummaryRow> = sqlx::query_as(
        "SELECT method, route_template, identity_kind, identity_label, \
                SUM(request_count)::bigint AS total_requests \
         FROM api_usage \
         WHERE usage_date >= (CURRENT_DATE - $1::int) \
         GROUP BY method, route_template, identity_kind, identity_label \
         ORDER BY total_requests DESC, route_template ASC \
         OFFSET $2 LIMIT $3",
    )
    .bind(days)
    .bind(offset)
    .bind(page_size)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM (\
            SELECT 1 FROM api_usage \
            WHERE usage_date >= (CURRENT_DATE - $1::int) \
            GROUP BY method, route_template, identity_kind, identity_label\
         ) grouped",
    )
    .bind(days)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(rows, total, page, page_size)))
}

#[derive(Deserialize, IntoParams)]
struct KeysQuery {
    /// How many trailing days of requests to count. Defaults to 7, clamped
    /// to [1, 90].
    days: Option<i64>,
    /// One-based — the first page is `page=1` (D-347).
    page: Option<i64>,
    /// Keys per page, up to the platform maximum.
    page_size: Option<i64>,
}

/// S10-T1: one API key as an admin sees it. Never the secret or its hash.
#[derive(sqlx::FromRow, Serialize, ToSchema)]
struct ApiKeyUsageRow {
    id: Uuid,
    name: String,
    public_key: String,
    owner_id: Uuid,
    owner_name: Option<String>,
    is_active: bool,
    expires_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    /// The key's own budget per minute; `None` leaves it under the
    /// deployment's per-category limits only.
    requests_per_minute: Option<i32>,
    /// Requests over the window, from the nightly rollup.
    total_requests: i64,
}

/// Lists API keys with their quotas and use.
///
/// `system.admin` only. Every API key with its owner, its own per-minute
/// quota and its requests over the trailing `days`, most used first; never a
/// secret or its hash.
#[utoipa::path(
    get,
    path = "/api/v1/admin/api-keys",
    tag = "admin",
    params(KeysQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ApiKeyUsageRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_keys(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<KeysQuery>,
) -> Result<Json<PaginatedResponse<ApiKeyUsageRow>>, AppError> {
    let days = q
        .days
        .unwrap_or(DEFAULT_WINDOW_DAYS)
        .clamp(1, MAX_WINDOW_DAYS);
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);
    let rows: Vec<ApiKeyUsageRow> = sqlx::query_as(
        "SELECT k.id, k.name, k.public_key, k.user_ref AS owner_id, u.user_name AS owner_name, \
                k.is_active, k.expires_at, k.last_used_at, k.requests_per_minute, \
                COALESCE(used.total, 0)::bigint AS total_requests \
           FROM api_key k \
           LEFT JOIN user_account u ON u.id = k.user_ref \
           LEFT JOIN ( \
                SELECT identity_label, SUM(request_count) AS total FROM api_usage \
                 WHERE identity_kind = 'api_key' AND usage_date >= (CURRENT_DATE - $1::int) \
                 GROUP BY identity_label \
           ) used ON used.identity_label = k.id::text \
          ORDER BY total_requests DESC, k.created_at DESC, k.id \
          OFFSET $2 LIMIT $3",
    )
    .bind(days)
    .bind(offset)
    .bind(page_size)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_key")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(rows, total, page, page_size)))
}

#[derive(Deserialize, ToSchema)]
struct QuotaBody {
    /// Requests per minute, 1 to 100,000; `null` clears the quota.
    requests_per_minute: Option<i32>,
}

#[derive(Serialize, ToSchema)]
struct QuotaSet {
    id: Uuid,
    requests_per_minute: Option<i32>,
}

/// The quota a body asks for, validated. Pure.
fn validate_quota(requested: Option<i32>) -> Result<Option<i32>, AppError> {
    match requested {
        Some(n) if !(1..=MAX_KEY_QUOTA).contains(&n) => Err(AppError::Validation(format!(
            "requests_per_minute must be between 1 and {MAX_KEY_QUOTA}, or null"
        ))),
        other => Ok(other),
    }
}

/// Sets or clears an API key's own quota.
///
/// `system.admin` only. Sets (or, with `null`, clears) the key's own
/// per-minute budget. Idempotent: the same body twice leaves the same value;
/// the change and its audit event commit together.
#[utoipa::path(
    put,
    path = "/api/v1/admin/api-keys/{id}/quota",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The API key")),
    request_body = QuotaBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Quota set", body = QuotaSet),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such key", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn set_quota(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<QuotaBody>,
) -> Result<Json<QuotaSet>, AppError> {
    let quota = validate_quota(body.requests_per_minute)?;
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "api_key",
            Some(id),
        )
        .named("api_key.quota")
        .comment(match quota {
            Some(n) => format!("api key quota set to {n} requests per minute"),
            None => "api key quota cleared".to_owned(),
        }),
    )
    .await?;
    let updated = sqlx::query("UPDATE api_key SET requests_per_minute = $2 WHERE id = $1")
        .bind(id)
        .bind(quota)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(Json(QuotaSet {
        id,
        requests_per_minute: quota,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/api-usage/summary", get(summary))
        .route("/api/v1/admin/api-keys", get(list_keys))
        .route("/api/v1/admin/api-keys/{id}/quota", put(set_quota))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(summary, list_keys, set_quota))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quota_is_positive_and_bounded() {
        assert_eq!(validate_quota(None).ok(), Some(None));
        assert_eq!(validate_quota(Some(60)).ok(), Some(Some(60)));
        assert_eq!(
            validate_quota(Some(MAX_KEY_QUOTA)).ok(),
            Some(Some(MAX_KEY_QUOTA))
        );
        assert!(validate_quota(Some(0)).is_err());
        assert!(validate_quota(Some(-5)).is_err());
        assert!(validate_quota(Some(MAX_KEY_QUOTA + 1)).is_err());
    }
}
