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
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

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

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/api-usage/summary", get(summary))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(summary))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
