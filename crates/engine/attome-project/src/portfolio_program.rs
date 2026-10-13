//! `GET /api/v1/program/{id}/summary` and `GET /api/v1/portfolio/{id}/summary`
//! — the same D-368 read-time-rollup rule `summary.rs` established for
//! Project, applied one (Program) and two (Portfolio) levels up the
//! Portfolio → Program → Project chain. Nothing here is a stored aggregate;
//! every number is a fresh query against the current child rows.
use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::AccessLevel;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use uuid::Uuid;

use crate::access::{
    authorize_portfolio_access, authorize_program_access, resource_rate_access_level,
};
use crate::auth::{PortfolioRead, ProgramRead};
use crate::model::{PortfolioSummaryResponse, ProgramSummaryResponse};

type ProjectAggregates = (i64, i64, i64, i64, Option<f64>, Option<f64>);

/// Scoped to whichever projects `program_ids_sql` (a fixed `&'static str`
/// SQL fragment this module controls — never request input) resolves to at
/// query time — one program (`program_summary`) or every program under a
/// portfolio (`portfolio_summary`). `pub` (not `pub(crate)`) specifically so
/// this crate's own integration tests can exercise the aggregation SQL
/// directly, the same reason `work_plan::rollup_rows_for_project` is `pub` —
/// see that function's own doc comment.
pub async fn project_aggregates_for_programs(
    db: &DbPool,
    program_ids_sql: &str,
    bind: Uuid,
) -> Result<ProjectAggregates, AppError> {
    sqlx::query_as::<_, ProjectAggregates>(&format!(
        "SELECT \
             COUNT(*)::bigint, \
             COUNT(*) FILTER (WHERE health = 'green')::bigint, \
             COUNT(*) FILTER (WHERE health = 'amber')::bigint, \
             COUNT(*) FILTER (WHERE health = 'red')::bigint, \
             SUM(budget_amount)::double precision, \
             SUM(budget_consumed)::double precision \
         FROM attome_project \
         WHERE program_id IN ({program_ids_sql}) AND (is_active IS NULL OR is_active = true)"
    ))
    .bind(bind)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Same testability reasoning as `project_aggregates_for_programs`.
pub async fn leaf_points_for_programs(
    db: &DbPool,
    program_ids_sql: &str,
    bind: Uuid,
) -> Result<(i64, i64), AppError> {
    sqlx::query_as::<_, (i64, i64)>(&format!(
        "WITH scoped_projects AS ( \
             SELECT id FROM attome_project \
             WHERE program_id IN ({program_ids_sql}) AND (is_active IS NULL OR is_active = true) \
         ), \
         leaves AS ( \
             SELECT w.status, w.points FROM project_work_item w \
             WHERE w.project_id IN (SELECT id FROM scoped_projects) \
               AND (w.is_active IS NULL OR w.is_active = true) \
               AND NOT EXISTS ( \
                 SELECT 1 FROM project_work_item c \
                 WHERE c.parent_work_item_id = w.id AND (c.is_active IS NULL OR c.is_active = true) \
               ) \
         ) \
         SELECT \
             COALESCE(SUM(points) FILTER (WHERE status = 'done'), 0)::bigint, \
             COALESCE(SUM(points), 0)::bigint \
         FROM leaves"
    ))
    .bind(bind)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// The two program-vs-portfolio scope fragments both route handlers below
/// bind `$1` against — `program_summary` binds a program id directly,
/// `portfolio_summary` binds a portfolio id and resolves its programs first.
pub const PROGRAM_SCOPE: &str = "SELECT $1::uuid";
pub const PORTFOLIO_SCOPE: &str = "SELECT id FROM project_program \
    WHERE portfolio_id = $1 AND (is_active IS NULL OR is_active = true)";

async fn actual_cost_for_programs(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    program_ids_sql: &str,
    bind: Uuid,
) -> Result<Option<f64>, AppError> {
    if resource_rate_access_level(state, ctx).await? == AccessLevel::None {
        return Ok(None);
    }

    let cost: f64 = sqlx::query_scalar(&format!(
        "WITH scoped_projects AS ( \
             SELECT id FROM attome_project \
             WHERE program_id IN ({program_ids_sql}) AND (is_active IS NULL OR is_active = true) \
         ) \
         SELECT COALESCE(SUM(te.hours * rr.internal_cost_rate), 0)::double precision \
         FROM project_time_entry te \
         JOIN project_work_item wi ON wi.id = te.work_item_id \
         LEFT JOIN LATERAL ( \
             SELECT internal_cost_rate FROM project_resource_rate \
             WHERE project_id = wi.project_id AND user_id = te.user_id \
               AND (is_active IS NULL OR is_active = true) \
             ORDER BY effective_date DESC NULLS LAST \
             LIMIT 1 \
         ) rr ON true \
         WHERE wi.project_id IN (SELECT id FROM scoped_projects) \
           AND (te.is_active IS NULL OR te.is_active = true) \
           AND (wi.is_active IS NULL OR wi.is_active = true)"
    ))
    .bind(bind)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Some(cost))
}

#[utoipa::path(
    get,
    path = "/api/v1/program/{id}/summary",
    tag = "project",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = ProgramSummaryResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such program, or not visible to this caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn program_summary(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ProgramRead>>,
    Path(program_id): Path<Uuid>,
) -> Result<Json<ProgramSummaryResponse>, AppError> {
    authorize_program_access(&state, &ctx, program_id).await?;

    let (
        project_count,
        health_green,
        health_amber,
        health_red,
        budget_amount_total,
        budget_consumed_total,
    ) = project_aggregates_for_programs(&state.base.db, PROGRAM_SCOPE, program_id).await?;
    let (points_completed, points_total) =
        leaf_points_for_programs(&state.base.db, PROGRAM_SCOPE, program_id).await?;
    let actual_cost_total =
        actual_cost_for_programs(&state, &ctx, PROGRAM_SCOPE, program_id).await?;

    let weighted_progress_pct = if points_total > 0 {
        (points_completed as f64 / points_total as f64) * 100.0
    } else {
        0.0
    };

    Ok(Json(ProgramSummaryResponse {
        program_id,
        project_count,
        weighted_progress_pct,
        points_completed,
        points_total,
        health_green,
        health_amber,
        health_red,
        budget_amount_total,
        budget_consumed_total,
        actual_cost_total,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/portfolio/{id}/summary",
    tag = "project",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = PortfolioSummaryResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such portfolio, or not visible to this caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn portfolio_summary(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<PortfolioRead>>,
    Path(portfolio_id): Path<Uuid>,
) -> Result<Json<PortfolioSummaryResponse>, AppError> {
    authorize_portfolio_access(&state, &ctx, portfolio_id).await?;

    let program_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM project_program \
         WHERE portfolio_id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(portfolio_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let (
        project_count,
        health_green,
        health_amber,
        health_red,
        budget_amount_total,
        budget_consumed_total,
    ) = project_aggregates_for_programs(&state.base.db, PORTFOLIO_SCOPE, portfolio_id).await?;
    let (points_completed, points_total) =
        leaf_points_for_programs(&state.base.db, PORTFOLIO_SCOPE, portfolio_id).await?;
    let actual_cost_total =
        actual_cost_for_programs(&state, &ctx, PORTFOLIO_SCOPE, portfolio_id).await?;

    let weighted_progress_pct = if points_total > 0 {
        (points_completed as f64 / points_total as f64) * 100.0
    } else {
        0.0
    };

    Ok(Json(PortfolioSummaryResponse {
        portfolio_id,
        program_count,
        project_count,
        weighted_progress_pct,
        points_completed,
        points_total,
        health_green,
        health_amber,
        health_red,
        budget_amount_total,
        budget_consumed_total,
        actual_cost_total,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/program/{id}/summary", get(program_summary))
        .route("/api/v1/portfolio/{id}/summary", get(portfolio_summary))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own `openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(program_summary, portfolio_summary))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
