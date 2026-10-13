//! `POST /api/v1/project/{id}/baseline` — captures a point-in-time snapshot
//! of the project's work-item schedule into `project_baseline`/
//! `project_baseline_item` (both append-only). This is the first
//! mutation `attome-project` has ever owned — every other write on this
//! module's entities goes through generic entity CRUD (D-368), and this
//! crate's `Cargo.toml`/`seed.rs` doc comments explain why it cannot reuse
//! `attome-api`'s private `entity_crud` mutation helpers, so this follows
//! the same "raw parameterized SQL against a fixed, known table" pattern
//! `access.rs`/`summary.rs`/`work_plan.rs` already use in this crate.
//!
//! **Concurrency and retry (guidelines §2).** Advisory-locked per project
//! (`"attome-project/baseline:{project_id}"`, two-argument
//! `pg_try_advisory_xact_lock`, this crate's own `ADVISORY_LOCK_NAMESPACE`)
//! so two concurrent captures for the same project can't both pass the
//! idempotent-replay check below and both insert. Retry-safe even without
//! an `x-idempotency-key` header: inside the lock, a baseline already
//! captured under this exact `(project_id, label)` is returned as-is
//! (`200 OK`, not `201 Created`) instead of being captured a second time —
//! the same "check, then insert if absent" pattern
//! `utilization.rs::ensure_report_query` already uses in this crate. The
//! platform's `x-idempotency-key` middleware
//! (`attome_server::middleware::idempotency`, wired into every route through
//! the standard central composition point) separately covers an exact
//! request replay; this covers a client retrying with the same label but no
//! key.
//!
//! **`planned_budget` is always `NULL` on every captured item.**
//! `project_work_item` carries no per-item budget field — only
//! `attome_project.budget_amount`/`budget_consumed` exist, at the project
//! level — so there is nothing to snapshot per item. The column stays in
//! `project_baseline_item`'s schema for a future per-item budget/
//! apportionment source; inventing one here would be new business logic
//! this change was not asked to design.
//!
//! **Every active work item is captured, not leaf items only.** Unlike
//! `work_plan.rs`'s rollup (which deliberately treats a phase/parent row as
//! contributing no `points` of its own), a baseline is a plain point-in-time
//! snapshot of what is actually stored on each row — phases included —
//! since a phase's own `start_date`/`due_date` are meaningful schedule
//! inputs even though its `points` value is never rolled up.
use attome_core::EngineState;
use attome_db::DbPool;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::access::authorize_project_access;
use crate::auth::ProjectBaselineCreate;

const VALID_TRIGGERS: &[&str] = &["initial", "change_request", "manual"];

fn default_trigger() -> String {
    "manual".to_owned()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CaptureBaselineRequest {
    /// A human name for this snapshot (e.g. "Sprint 3 baseline"). Capturing
    /// twice with the same label for the same project is safe — see this
    /// module's doc comment — and returns the existing baseline rather than
    /// creating a duplicate.
    pub label: String,
    /// `initial` | `change_request` | `manual` — `project_baseline
    /// .trigger`'s own choice values. Defaults to `manual`.
    #[serde(default = "default_trigger")]
    pub trigger: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CaptureBaselineResponse {
    pub baseline_id: Uuid,
    pub project_id: Uuid,
    pub label: String,
    pub trigger: String,
    pub captured_at: DateTime<Utc>,
    /// Number of `project_baseline_item` rows captured under this
    /// baseline — every active work item on the project at capture time.
    pub item_count: i64,
}

#[derive(sqlx::FromRow)]
struct ExistingBaseline {
    id: Uuid,
    trigger: String,
    captured_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct WorkItemScheduleRow {
    id: Uuid,
    start_date: Option<DateTime<Utc>>,
    due_date: Option<DateTime<Utc>>,
    points: Option<f64>,
}

async fn lock_project_baseline(
    tx: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-project/baseline:{project_id}"))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another baseline capture is already in progress for this project",
        ));
    }
    Ok(())
}

async fn existing_baseline_by_label(
    tx: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    label: &str,
) -> Result<Option<ExistingBaseline>, AppError> {
    sqlx::query_as::<_, ExistingBaseline>(
        "SELECT id, trigger, captured_at FROM project_baseline \
         WHERE project_id = $1 AND label = $2 AND (is_active IS NULL OR is_active = true) \
         ORDER BY captured_at DESC LIMIT 1",
    )
    .bind(project_id)
    .bind(label)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)
}

async fn baseline_item_count(
    tx: &mut Transaction<'_, Postgres>,
    baseline_id: Uuid,
) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM project_baseline_item \
         WHERE baseline_id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(baseline_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)
}

/// `None` when the project doesn't exist or isn't active — the caller
/// already confirmed RLS visibility via `authorize_project_access` before
/// this runs, so this is purely "does the row still exist", not a second
/// authorization check.
async fn project_organization_id(
    tx: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT organization_id FROM attome_project \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(project_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)
}

async fn active_work_items(
    tx: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
) -> Result<Vec<WorkItemScheduleRow>, AppError> {
    sqlx::query_as::<_, WorkItemScheduleRow>(
        "SELECT id, start_date, due_date, points::double precision AS points \
         FROM project_work_item \
         WHERE project_id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(project_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)
}

async fn insert_baseline(
    tx: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    label: &str,
    trigger: &str,
    user_id: Uuid,
    organization_id: Uuid,
) -> Result<(Uuid, DateTime<Utc>), AppError> {
    let baseline_id = Uuid::now_v7();
    let captured_at = Utc::now();
    sqlx::query(
        "INSERT INTO project_baseline \
             (id, project_id, label, captured_at, captured_by, trigger, \
              created_by, organization_ref, owner_ref) \
         VALUES ($1, $2, $3, $4, $5, $6, $5, $7, $5)",
    )
    .bind(baseline_id)
    .bind(project_id)
    .bind(label)
    .bind(captured_at)
    .bind(user_id)
    .bind(trigger)
    .bind(organization_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok((baseline_id, captured_at))
}

async fn insert_baseline_items(
    tx: &mut Transaction<'_, Postgres>,
    baseline_id: Uuid,
    items: &[WorkItemScheduleRow],
    user_id: Uuid,
    organization_id: Uuid,
) -> Result<(), AppError> {
    for item in items {
        sqlx::query(
            "INSERT INTO project_baseline_item \
                 (id, baseline_id, work_item_id, planned_start, planned_due, \
                  planned_points, created_by, organization_ref, owner_ref) \
             VALUES ($1, $2, $3, $4, $5, $6::numeric, $7, $8, $7)",
        )
        .bind(Uuid::now_v7())
        .bind(baseline_id)
        .bind(item.id)
        .bind(item.start_date)
        .bind(item.due_date)
        .bind(item.points)
        .bind(user_id)
        .bind(organization_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

/// Core logic, deliberately taking `&DbPool` rather than `&EngineState` — same
/// convention `capacity.rs::authorize_capacity_scope` uses, so this is
/// directly callable from an integration test with a bare pool (no full
/// `EngineState`/license ceremony), same shape as this crate's other
/// `tests/*.rs` files.
pub async fn capture_baseline(
    db: &DbPool,
    project_id: Uuid,
    user_id: Uuid,
    label: &str,
    trigger: &str,
) -> Result<(CaptureBaselineResponse, bool), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    lock_project_baseline(&mut tx, project_id).await?;

    let organization_id = project_organization_id(&mut tx, project_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if let Some(existing) = existing_baseline_by_label(&mut tx, project_id, label).await? {
        let item_count = baseline_item_count(&mut tx, existing.id).await?;
        tx.commit().await.map_err(AppError::internal)?;
        return Ok((
            CaptureBaselineResponse {
                baseline_id: existing.id,
                project_id,
                label: label.to_owned(),
                trigger: existing.trigger,
                captured_at: existing.captured_at,
                item_count,
            },
            false,
        ));
    }

    let items = active_work_items(&mut tx, project_id).await?;
    let (baseline_id, captured_at) = insert_baseline(
        &mut tx,
        project_id,
        label,
        trigger,
        user_id,
        organization_id,
    )
    .await?;
    insert_baseline_items(&mut tx, baseline_id, &items, user_id, organization_id).await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok((
        CaptureBaselineResponse {
            baseline_id,
            project_id,
            label: label.to_owned(),
            trigger: trigger.to_owned(),
            captured_at,
            item_count: items.len() as i64,
        },
        true,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/project/{id}/baseline",
    tag = "project",
    params(("id" = Uuid, Path)),
    request_body = CaptureBaselineRequest,
    responses(
        (status = 200, description = "A baseline with this label already existed for this project; returned as-is", body = CaptureBaselineResponse),
        (status = 201, description = "Success", body = CaptureBaselineResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such project, or not visible to this caller", body = ErrorResponse),
        (status = 409, description = "Another capture for this project is already in progress", body = ErrorResponse),
        (status = 422, description = "label is empty, or trigger is not one of initial/change_request/manual", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create),
    ])))),
)]
async fn capture_project_baseline(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ProjectBaselineCreate>>,
    Path(project_id): Path<Uuid>,
    Json(body): Json<CaptureBaselineRequest>,
) -> Result<(StatusCode, Json<CaptureBaselineResponse>), AppError> {
    // The route's compile-time policy covers project_baseline.create;
    // this covers the second entity it writes to, same "one compile-time +
    // one manual check" shape `attome-service::convert.rs` already uses for a
    // two-entity write.
    ctx.require_key("project_baseline_item.create")?;

    let label = body.label.trim();
    if label.is_empty() {
        return Err(AppError::Validation("label must not be empty".into()));
    }
    if !VALID_TRIGGERS.contains(&body.trigger.as_str()) {
        return Err(AppError::Validation(format!(
            "trigger must be one of {VALID_TRIGGERS:?}"
        )));
    }

    // Record-level visibility into this specific project — the entity-level
    // project_baseline.create privilege above says nothing about
    // whether this caller may see this particular project.
    authorize_project_access(&state, &ctx, project_id).await?;

    let (response, created) = capture_baseline(
        &state.base.db,
        project_id,
        ctx.user_id,
        label,
        &body.trigger,
    )
    .await?;
    if created {
        // Plan 3.7 (I5): the change-request-approval-triggered capture path
        // (`change_request.rs::do_decide_change_request`) audits its own
        // call the same way.
        attome_audit::write_business_event(
            &state,
            "project_baseline",
            response.baseline_id,
            attome_audit::AuditOperation::Create,
            "project_baseline_captured",
            ctx.user_id,
            None,
            None,
            format!(
                "baseline '{label}' captured ({}), {} item(s)",
                body.trigger, response.item_count
            ),
        )
        .await;
    }
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(response)))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/project/{id}/baseline",
        post(capture_project_baseline),
    )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own `openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(capture_project_baseline))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
