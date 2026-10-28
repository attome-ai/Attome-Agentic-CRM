//! `GET /api/v1/project/{id}/summary` — the Project Control Center tiles
//! (health, weighted progress, budget consumed, open risks, pending
//! approvals). Every number is computed live from the project's own row plus
//! its child work items/issues/change requests — see `model.rs`'s doc
//! comment on why nothing here is a stored rollup.
use attome_core::EngineState;
use attome_security::{RecordAction, resolve_entity_access_level, rls_predicate_by_column};
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::access::{project_entity_id, resource_rate_access_level};
use crate::auth::ProjectRead;
use crate::model::ProjectSummaryResponse;
use crate::variance;

/// Loads the project's own row, enforcing both the entity-level
/// `attome_project.read` privilege (already checked by the `Authorized<
/// Privilege<ProjectRead>>` extractor before this function runs) and
/// record-level RLS scope for this specific record — the same
/// `resolve_entity_access_level` + `rls_predicate_by_column` pattern
/// `attome-api`'s `entity_crud/hierarchy.rs` uses for its own ancestor/
/// descendant walks, reimplemented here on `attome_security`'s public API
/// because this crate does not depend on `attome-api` (see `seed.rs`'s doc
/// comment for why). `AppError::NotFound` covers both "no such project" and
/// "exists, but RLS excludes this caller" — the same non-distinguishing
/// behavior generic entity reads already give an unauthorized caller.
async fn load_project_row(
    state: &EngineState,
    ctx: &SecurityContext,
    project_id: Uuid,
) -> Result<
    (
        Option<String>,
        Option<f64>,
        Option<f64>,
        Option<DateTime<Utc>>,
    ),
    AppError,
> {
    let entity_id = project_entity_id(state)?;
    let access_level = resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        "attome_project",
        RecordAction::Read,
    )
    .await?;
    let rls = rls_predicate_by_column(
        ctx,
        entity_id,
        "p",
        "id",
        access_level,
        RecordAction::Read.share_capability(),
        2,
    );

    let mut sql = "SELECT p.health, p.budget_amount::double precision, \
         p.budget_consumed::double precision, p.target_end_date \
         FROM attome_project p WHERE p.id = $1 AND (p.is_active IS NULL OR p.is_active = true)"
        .to_owned();
    if let Some(pred) = &rls {
        sql.push_str(&pred.sql);
    }

    let mut q = sqlx::query_as::<
        _,
        (
            Option<String>,
            Option<f64>,
            Option<f64>,
            Option<DateTime<Utc>>,
        ),
    >(&sql)
    .bind(project_id);
    if let Some(pred) = &rls {
        q = q
            .bind(pred.binds.entity_ref)
            .bind(pred.binds.caller_id)
            .bind(&pred.binds.team_ids)
            .bind(pred.binds.capability)
            .bind(&pred.binds.accessible_org_ids)
            .bind(&pred.binds.subordinate_user_ids);
    }

    q.fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)
}

/// Leaf-work-item points/counts + the raw ingredients for `forecast_date`.
/// "Leaf" mirrors `work_plan.rs`'s rule: a work item with no children is
/// where real progress lives; a phase/parent row never contributes its own
/// `points`. Scoped to `project_id` only (no per-row RLS beyond the parent
/// project's own record-level check above) — see this module's doc comment
/// in the implementation plan for why child-entity RLS is out of scope for
/// this pass.
async fn leaf_work_item_aggregates(
    state: &EngineState,
    project_id: Uuid,
) -> Result<(i64, i64, i64, i64, i64, Option<DateTime<Utc>>), AppError> {
    sqlx::query_as::<_, (i64, i64, i64, i64, i64, Option<DateTime<Utc>>)>(
        "WITH leaves AS ( \
            SELECT w.status, w.points, w.due_date FROM project_work_item w \
            WHERE w.project_id = $1 AND (w.is_active IS NULL OR w.is_active = true) \
              AND NOT EXISTS ( \
                SELECT 1 FROM project_work_item c \
                WHERE c.parent_work_item_id = w.id \
                  AND (c.is_active IS NULL OR c.is_active = true) \
              ) \
         ) \
         SELECT \
             COALESCE(SUM(points) FILTER (WHERE status = 'done'), 0)::bigint, \
             COALESCE(SUM(points), 0)::bigint, \
             COALESCE(SUM(points) FILTER (WHERE status = 'blocked'), 0)::bigint, \
             COUNT(*) FILTER (WHERE status = 'done')::bigint, \
             COUNT(*)::bigint, \
             MAX(due_date) FILTER (WHERE status <> 'done') \
         FROM leaves",
    )
    .bind(project_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

async fn issue_counts(state: &EngineState, project_id: Uuid) -> Result<(i64, i64), AppError> {
    sqlx::query_as::<_, (i64, i64)>(
        "SELECT \
             COUNT(*) FILTER (WHERE status IN ('open', 'mitigating'))::bigint, \
             COUNT(*) FILTER (WHERE status IN ('open', 'mitigating') AND severity = 'critical')::bigint \
         FROM project_issue \
         WHERE project_id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(project_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

async fn pending_change_request_counts(
    state: &EngineState,
    project_id: Uuid,
) -> Result<(i64, i64), AppError> {
    sqlx::query_as::<_, (i64, i64)>(
        "SELECT \
             COUNT(*) FILTER (WHERE status = 'pending')::bigint, \
             COUNT(*) FILTER (WHERE status = 'pending' AND is_customer_facing = true)::bigint \
         FROM project_change_request \
         WHERE project_id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(project_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Gated on the caller holding *some* read access to
/// `project_resource_rate` — that entity's rate fields are marked
/// `is_sensitive`, and this value is derived from them, so it follows the
/// same visibility rule rather than leaking an aggregate to a plain
/// `ProjectRead` caller who could not read a single `Resource Rate` row.
/// `AccessLevel::None` is exactly what `resolve_entity_access_level`
/// returns when no held role grants `project_resource_rate.read` at
/// all, per that function's own doc comment.
async fn actual_cost(
    state: &EngineState,
    ctx: &SecurityContext,
    project_id: Uuid,
) -> Result<Option<f64>, AppError> {
    if resource_rate_access_level(state, ctx).await? == AccessLevel::None {
        return Ok(None);
    }

    let cost: f64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(te.hours * rr.internal_cost_rate), 0)::double precision \
         FROM project_time_entry te \
         JOIN project_work_item wi ON wi.id = te.work_item_id \
         LEFT JOIN LATERAL ( \
             SELECT internal_cost_rate FROM project_resource_rate \
             WHERE project_id = $1 AND user_id = te.user_id \
               AND (is_active IS NULL OR is_active = true) \
             ORDER BY effective_date DESC NULLS LAST \
             LIMIT 1 \
         ) rr ON true \
         WHERE wi.project_id = $1 \
           AND (te.is_active IS NULL OR te.is_active = true) \
           AND (wi.is_active IS NULL OR wi.is_active = true)",
    )
    .bind(project_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Some(cost))
}

/// Read a project's summary
///
/// The control centre tiles, computed live: health, weighted progress, budget consumed, open risks
/// and pending approvals.
#[utoipa::path(
    get,
    path = "/api/v1/project/{id}/summary",
    tag = "project",
    params(("id" = Uuid, Path, description = "The project")),
    responses(
        (status = 200, description = "Success", body = ProjectSummaryResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such project, or not visible to this caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn project_summary(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ProjectRead>>,
    Path(project_id): Path<Uuid>,
) -> Result<Json<ProjectSummaryResponse>, AppError> {
    let (health, budget_amount, budget_consumed, target_end_date) =
        load_project_row(&state, &ctx, project_id).await?;

    let (
        points_completed,
        points_total,
        points_blocked,
        work_items_done,
        work_items_actionable,
        forecast_date,
    ) = leaf_work_item_aggregates(&state, project_id).await?;
    let (open_risks_total, open_risks_critical) = issue_counts(&state, project_id).await?;
    let (pending_change_requests_total, pending_change_requests_customer_facing) =
        pending_change_request_counts(&state, project_id).await?;
    let actual_cost = actual_cost(&state, &ctx, project_id).await?;

    let weighted_progress_pct = if points_total > 0 {
        (points_completed as f64 / points_total as f64) * 100.0
    } else {
        0.0
    };
    let budget_consumed_pct = match (budget_consumed, budget_amount) {
        (Some(consumed), Some(amount)) if amount > 0.0 => Some((consumed / amount) * 100.0),
        _ => None,
    };
    let forecast_buffer_days = match (target_end_date, forecast_date) {
        (Some(target), Some(forecast)) => Some((target - forecast).num_days()),
        _ => None,
    };

    let baseline = variance::latest_baseline(&state.base.db, project_id).await?;
    let (
        baseline_id,
        baseline_label,
        baseline_captured_at,
        scope_item_count_variance,
        schedule_variance_days,
        planned_value_fraction,
    ) = match &baseline {
        Some(b) => {
            let agg = variance::baseline_aggregate(&state.base.db, b.id).await?;
            let current_count =
                variance::active_work_item_count(&state.base.db, project_id).await?;
            (
                Some(b.id),
                Some(b.label.clone()),
                Some(b.captured_at),
                Some(current_count - agg.item_count),
                variance::schedule_variance_days(agg.planned_finish, forecast_date),
                agg.planned_value_fraction,
            )
        }
        None => (None, None, None, None, None, None),
    };
    let evm = variance::compute_evm(
        budget_amount,
        weighted_progress_pct,
        actual_cost,
        planned_value_fraction,
    );

    Ok(Json(ProjectSummaryResponse {
        project_id,
        health,
        weighted_progress_pct,
        points_completed,
        points_total,
        points_blocked,
        work_items_done,
        work_items_actionable,
        budget_amount,
        budget_consumed,
        budget_consumed_pct,
        actual_cost,
        open_risks_total,
        open_risks_critical,
        pending_change_requests_total,
        pending_change_requests_customer_facing,
        forecast_date,
        forecast_buffer_days,
        baseline_id,
        baseline_label,
        baseline_captured_at,
        scope_item_count_variance,
        schedule_variance_days,
        budget_at_completion: budget_amount,
        planned_value: evm.planned_value,
        earned_value: evm.earned_value,
        cost_performance_index: evm.cost_performance_index,
        schedule_performance_index: evm.schedule_performance_index,
        estimate_at_completion: evm.estimate_at_completion,
        estimate_to_complete: evm.estimate_to_complete,
        variance_at_completion: evm.variance_at_completion,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/project/{id}/summary", get(project_summary))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own `openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(project_summary))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
