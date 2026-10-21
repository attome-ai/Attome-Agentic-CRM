//! V1-T1: what the Gantt chart draws.
//!
//! `GET /api/v1/project/{id}/gantt` answers, in one read, the work items
//! with their dates, critical-path flag and float (the same rows as the WBS
//! rollup, [`crate::work_plan::rollup_rows_for_project`]), the dependencies
//! between them, and the latest baseline's planned dates for the overlay.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::access::authorize_project_access;
use crate::auth::ProjectRead;
use crate::model::WorkItemRollupRow;

/// One dependency.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct GanttDependency {
    pub predecessor_id: Uuid,
    pub successor_id: Uuid,
    /// `finish_to_start`, `start_to_start`, `finish_to_finish` or
    /// `start_to_finish`.
    pub dependency_type: String,
    pub lag_days: Option<f64>,
}

/// One item's planned dates in the baseline.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct GanttBaselineItem {
    pub work_item_id: Uuid,
    pub planned_start: Option<DateTime<Utc>>,
    pub planned_due: Option<DateTime<Utc>>,
}

/// The latest baseline.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct GanttBaseline {
    pub baseline_id: Uuid,
    pub label: Option<String>,
    pub captured_at: Option<DateTime<Utc>>,
    pub items: Vec<GanttBaselineItem>,
}

/// Everything the chart needs.
#[derive(Debug, Serialize, ToSchema)]
pub struct GanttView {
    pub items: Vec<WorkItemRollupRow>,
    pub dependencies: Vec<GanttDependency>,
    pub baseline: Option<GanttBaseline>,
}

async fn gantt(state: &EngineState, project: Uuid) -> Result<GanttView, AppError> {
    let db = &state.base.db;
    let items = crate::work_plan::rollup_rows_for_project(db, project).await?;
    let dependencies: Vec<GanttDependency> = sqlx::query_as(
        "SELECT d.predecessor_id, d.successor_id, d.dependency_type::text AS dependency_type, \
                d.lag_days::float8 AS lag_days \
           FROM project_work_item_dependency d \
           JOIN project_work_item w ON w.id = d.predecessor_id \
          WHERE w.project_id = $1 AND (d.is_active IS NULL OR d.is_active = true)",
    )
    .bind(project)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let latest: Option<(Uuid, Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT id, label, captured_at::timestamptz FROM project_baseline \
          WHERE project_id = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY captured_at DESC NULLS LAST, id DESC LIMIT 1",
    )
    .bind(project)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let baseline = match latest {
        Some((id, label, captured_at)) => {
            let items: Vec<GanttBaselineItem> = sqlx::query_as(
                "SELECT work_item_id, planned_start::timestamptz AS planned_start, \
                        planned_due::timestamptz AS planned_due \
                   FROM project_baseline_item \
                  WHERE baseline_id = $1 AND work_item_id IS NOT NULL \
                    AND (is_active IS NULL OR is_active = true)",
            )
            .bind(id)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
            Some(GanttBaseline {
                baseline_id: id,
                label,
                captured_at,
                items,
            })
        }
        None => None,
    };
    Ok(GanttView {
        items,
        dependencies,
        baseline,
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/project/{id}/gantt",
    operation_id = "get_project_gantt",
    tag = "project",
    params(("id" = Uuid, Path, description = "The project")),
    responses(
        (status = 200, description = "Work items, dependencies and the latest baseline", body = GanttView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such project, or not visible to this caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// What a project's Gantt chart draws.
///
/// The work items with dates and critical-path float, their dependencies,
/// and the latest baseline's planned dates for the overlay.
async fn get_gantt(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ProjectRead>>,
    Path(id): Path<Uuid>,
) -> Result<Json<GanttView>, AppError> {
    authorize_project_access(&state, &ctx, id).await?;
    Ok(Json(gantt(&state, id).await?))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/project/{id}/gantt", get(get_gantt))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_gantt),
    components(schemas(GanttDependency, GanttBaselineItem, GanttBaseline, GanttView))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
