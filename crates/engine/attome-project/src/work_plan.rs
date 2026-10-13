//! `GET /api/v1/project/{id}/work-items/rollup` — the WBS tree with
//! point-weighted progress.
//!
//! This is the load-bearing reason this crate exists as more than a seed:
//! **no engine in this codebase stores a rollup field.** Every computed
//! value elsewhere (`attome-notification`'s unread count, `attome-audit`'s chain
//! lag, `attome-api`'s own ancestor/descendant walk) is computed live, at
//! read time, via SQL — never written back to a parent record on a child's
//! write. This endpoint follows the same convention: a phase's progress is
//! never a stored column, only ever the live sum of its leaf descendants'
//! `points`, computed fresh on every request via a recursive CTE. "Done"
//! leaves contribute 100% of their points, "in progress"/"not started"
//! contribute 0%, and "blocked" points are surfaced as their own count
//! rather than netted out — matching the mockup's own stated rule.
use std::collections::HashMap;

use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::access::authorize_project_access;
use crate::auth::ProjectRead;
use crate::critical_path::{self, DependencyEdge, DependencyType};
use crate::model::WorkItemRollupRow;

/// Same structural-walk depth ceiling `attome-api::entity_mutation::
/// MAX_HIERARCHY_DEPTH` uses for every other self-referencing lookup on this
/// platform — duplicated here (rather than imported) because this crate does
/// not depend on `attome-api` (see `seed.rs`'s doc comment). Keep these two
/// constants in sync if the platform-wide ceiling ever changes.
pub const MAX_HIERARCHY_DEPTH: i32 = 100;

type RollupRow = (
    Uuid,
    String,
    Option<Uuid>,
    String,
    String,
    Option<Uuid>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<f64>,
    Option<f64>,
    i64,
    i64,
    i64,
);

/// The point-weighted WBS rollup for every work item in `project_id`, fully
/// computed (SQL aggregation + `progress_pct`) and ready to serve or assert
/// on — `pub` (not just `pub(crate)`) specifically so this crate's own
/// integration tests can exercise the rollup arithmetic directly, without
/// going through the HTTP/authorization layer `work_item_rollup` wraps it
/// in. Takes a bare `&DbPool` rather than `&EngineState`: unlike
/// `access::authorize_project_access`, nothing here needs the metadata
/// registry.
pub async fn rollup_rows_for_project(
    db: &DbPool,
    project_id: Uuid,
) -> Result<Vec<WorkItemRollupRow>, AppError> {
    let rows = fetch_rollup(db, project_id).await?;

    let node_ids: Vec<Uuid> = rows.iter().map(|r| r.0).collect();
    let durations_days: HashMap<Uuid, i64> = rows
        .iter()
        .filter_map(|r| match (r.6, r.7) {
            (Some(start), Some(due)) if due >= start => Some((r.0, (due - start).num_days())),
            _ => None,
        })
        .collect();
    let dependency_edges = fetch_dependencies(db, project_id).await?;
    let critical_path = critical_path::compute(&node_ids, &durations_days, &dependency_edges);

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                name,
                parent_work_item_id,
                item_type,
                status,
                owner_id,
                start_date,
                due_date,
                sequence,
                points_own,
                points_completed,
                points_total,
                points_blocked,
            )| {
                let progress_pct = if points_total > 0 {
                    (points_completed as f64 / points_total as f64) * 100.0
                } else {
                    0.0
                };
                let cp_result = critical_path.as_ref().and_then(|m| m.get(&id));
                WorkItemRollupRow {
                    id,
                    name,
                    parent_work_item_id,
                    item_type,
                    status,
                    owner_id,
                    start_date,
                    due_date,
                    sequence,
                    points_own: points_own.unwrap_or(0.0),
                    points_completed,
                    points_total,
                    points_blocked,
                    progress_pct,
                    is_critical_path: cp_result.is_some_and(|r| r.is_critical),
                    total_float_days: cp_result.map(|r| r.total_float_days),
                }
            },
        )
        .collect())
}

/// All four dependency types (D-368 originally scoped this to
/// `finish_to_start` only — see `critical_path.rs`'s own module doc for the
/// generalized forward/backward-pass arithmetic each type now drives). A row
/// whose `dependency_type` doesn't parse is skipped rather than guessed at
/// — should not happen given the entity's own choice-field validation, but
/// this makes no assumption about that.
async fn fetch_dependencies(
    db: &DbPool,
    project_id: Uuid,
) -> Result<Vec<DependencyEdge>, AppError> {
    let rows: Vec<(Uuid, Uuid, String, Option<f64>)> = sqlx::query_as(
        "SELECT d.predecessor_id, d.successor_id, d.dependency_type, \
                d.lag_days::double precision \
         FROM project_work_item_dependency d \
         JOIN project_work_item w ON w.id = d.predecessor_id \
         WHERE w.project_id = $1 AND (d.is_active IS NULL OR d.is_active = true)",
    )
    .bind(project_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .filter_map(|(predecessor, successor, dependency_type, lag_days)| {
            Some(DependencyEdge {
                predecessor,
                successor,
                dependency_type: DependencyType::parse(&dependency_type)?,
                lag_days: lag_days.unwrap_or(0.0) as i64,
            })
        })
        .collect())
}

async fn fetch_rollup(db: &DbPool, project_id: Uuid) -> Result<Vec<RollupRow>, AppError> {
    sqlx::query_as::<_, RollupRow>(
        "WITH RECURSIVE tree AS ( \
            SELECT id, parent_work_item_id FROM project_work_item \
            WHERE project_id = $1 AND (is_active IS NULL OR is_active = true) \
         ), \
         closure AS ( \
            SELECT id AS ancestor_id, id AS descendant_id, 0 AS depth FROM tree \
            UNION ALL \
            SELECT c.ancestor_id, t.id, c.depth + 1 \
            FROM closure c JOIN tree t ON t.parent_work_item_id = c.descendant_id \
            WHERE c.depth < $2 \
         ), \
         leaves AS ( \
            SELECT t.id FROM tree t \
            WHERE NOT EXISTS (SELECT 1 FROM tree c2 WHERE c2.parent_work_item_id = t.id) \
         ), \
         rollup AS ( \
            SELECT \
                cl.ancestor_id AS work_item_id, \
                COALESCE(SUM(w.points) FILTER (WHERE w.status = 'done'), 0)::bigint AS points_completed, \
                COALESCE(SUM(w.points), 0)::bigint AS points_total, \
                COALESCE(SUM(w.points) FILTER (WHERE w.status = 'blocked'), 0)::bigint AS points_blocked \
            FROM closure cl \
            JOIN leaves lf ON lf.id = cl.descendant_id \
            JOIN project_work_item w ON w.id = cl.descendant_id \
            GROUP BY cl.ancestor_id \
         ) \
         SELECT \
             w.id, w.name, w.parent_work_item_id, w.item_type, w.status, w.owner_id, \
             w.start_date, w.due_date, w.sequence::double precision, \
             w.points::double precision, \
             COALESCE(r.points_completed, 0), COALESCE(r.points_total, 0), COALESCE(r.points_blocked, 0) \
         FROM project_work_item w \
         LEFT JOIN rollup r ON r.work_item_id = w.id \
         WHERE w.project_id = $1 AND (w.is_active IS NULL OR w.is_active = true) \
         ORDER BY w.sequence NULLS LAST, w.name",
    )
    .bind(project_id)
    .bind(MAX_HIERARCHY_DEPTH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

#[utoipa::path(
    get,
    path = "/api/v1/project/{id}/work-items/rollup",
    tag = "project",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<WorkItemRollupRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such project, or not visible to this caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn work_item_rollup(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ProjectRead>>,
    Path(project_id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<WorkItemRollupRow>>, AppError> {
    authorize_project_access(&state, &ctx, project_id).await?;

    let items = rollup_rows_for_project(&state.base.db, project_id).await?;

    // Same "page 1 of 1, everything returned" convention as
    // `entity_crud/hierarchy.rs`'s ancestor/descendant walk — this endpoint
    // has no `page`/`page_size` request parameter, it always returns the
    // project's whole (depth-bounded) work-item tree in one response.
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        1,
        MAX_HIERARCHY_DEPTH as i64,
    )))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/project/{id}/work-items/rollup",
        get(work_item_rollup),
    )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own `openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(work_item_rollup))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
