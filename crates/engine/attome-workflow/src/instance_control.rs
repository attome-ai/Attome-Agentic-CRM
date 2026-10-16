//! Run control (roadmap M3-T3): retry a failed run from its failed step,
//! pause and resume a run, and move a waiting or paused run to a newer
//! published version of its flow (with a preview of the mapping first).
//! Cancel lives with the rest of the instance admin (`instance_admin`).
//!
//! Every change is a `row_version` CAS on the instance, written with its
//! business event in one transaction; a run that continues gets a
//! `WorkflowExecute` job enqueued in the same transaction.

use attome_audit::{AuditOperation, BusinessEvent};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::graph::Graph;

/// A control request: the instance's current `row_version`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ControlBody {
    pub row_version: i64,
}

/// Move a run to another version of its flow.
#[derive(Debug, Deserialize, ToSchema)]
pub struct MoveBody {
    pub target_version_id: Uuid,
    pub row_version: i64,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MovePreviewQuery {
    pub target_version_id: Uuid,
}

/// One waiting step and where it lands in the target version.
#[derive(Debug, Serialize, ToSchema)]
pub struct MoveMapping {
    pub node_id: String,
    pub node_type: String,
    /// The node exists in the target version with the same type.
    pub found: bool,
}

/// What moving the run would do.
#[derive(Debug, Serialize, ToSchema)]
pub struct MovePreview {
    pub from_version_id: Uuid,
    pub target_version_id: Uuid,
    /// Every waiting step is found in the target version.
    pub movable: bool,
    pub waiting: Vec<MoveMapping>,
}

/// The instance's state after a control action.
#[derive(Debug, Serialize, ToSchema)]
pub struct ControlResult {
    pub id: Uuid,
    pub status: String,
    pub row_version: i64,
}

type Tx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

async fn event(
    tx: &mut Tx<'_>,
    state: &EngineState,
    instance_id: Uuid,
    operation: AuditOperation,
    name: &str,
    user_id: Uuid,
) -> Result<(), AppError> {
    attome_audit::write_business_event_in_tx(
        tx,
        &attome_audit::audit_service(state),
        BusinessEvent::new("workflow_instance", instance_id, operation, name, user_id),
    )
    .await
    .map(|_| ())
}

async fn enqueue_execute(tx: &mut Tx<'_>, instance_id: Uuid) -> Result<(), AppError> {
    attome_jobs::enqueue_in_tx(
        tx,
        attome_core::jobs::EngineJob::WorkflowExecute { instance_id },
    )
    .await
    .map_err(AppError::internal)
}

/// CAS the instance from one of `from` to `to`; `VersionConflict` when the
/// row moved or is in another state.
async fn transition(
    tx: &mut Tx<'_>,
    instance_id: Uuid,
    row_version: i64,
    from: &[&str],
    to: &str,
) -> Result<i64, AppError> {
    let from: Vec<String> = from.iter().map(|s| (*s).to_owned()).collect();
    sqlx::query_scalar(
        "UPDATE workflow_instance \
            SET status = $4, completed_at = NULL, row_version = row_version + 1 \
          WHERE id = $1 AND row_version = $2 AND status = ANY($3) \
          RETURNING row_version",
    )
    .bind(instance_id)
    .bind(row_version)
    .bind(&from)
    .bind(to)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::VersionConflict)
}

#[utoipa::path(
    post,
    path = "/api/v1/workflow/instances/{id}/retry",
    tag = "workflow",
    operation_id = "workflow_instance_retry",
    params(("id" = Uuid, Path)),
    request_body = ControlBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Activated)])))),
    responses(
        (status = 200, description = "The run continues from its failed step, with the inputs it had", body = ControlResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such run", body = ErrorResponse),
        (status = 409, description = "The run is not failed, or changed since it was read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn retry_instance(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(instance_id): Path<Uuid>,
    Json(body): Json<ControlBody>,
) -> Result<Json<ControlResult>, AppError> {
    retry_run(&state, instance_id, body.row_version, ctx.user_id)
        .await
        .map(Json)
}

/// Retries a failed run from its failed steps, as `user_id`.
pub async fn retry_run(
    state: &EngineState,
    instance_id: Uuid,
    row_version: i64,
    user_id: Uuid,
) -> Result<ControlResult, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row_version = transition(&mut tx, instance_id, row_version, &["failed"], "running").await?;
    // The failed steps run again; everything that succeeded keeps its
    // output, so the failed step sees the same inputs.
    let reset = sqlx::query(
        "UPDATE workflow_node_run \
            SET status = 'pending', attempt_count = 0, last_error = NULL, completed_at = NULL, \
                row_version = row_version + 1 \
          WHERE instance_id = $1 AND status = 'failed'",
    )
    .bind(instance_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if reset == 0 {
        return Err(AppError::Conflict("the run has no failed step to retry"));
    }
    enqueue_execute(&mut tx, instance_id).await?;
    event(
        &mut tx,
        state,
        instance_id,
        AuditOperation::Activated,
        "workflow_instance.retry",
        user_id,
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(ControlResult {
        id: instance_id,
        status: "running".into(),
        row_version,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/workflow/instances/{id}/pause",
    tag = "workflow",
    operation_id = "workflow_instance_pause",
    params(("id" = Uuid, Path)),
    request_body = ControlBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The run is paused; no step runs until it is resumed", body = ControlResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "The run is not running or waiting, or changed since it was read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn pause_instance(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(instance_id): Path<Uuid>,
    Json(body): Json<ControlBody>,
) -> Result<Json<ControlResult>, AppError> {
    pause_run(&state, instance_id, body.row_version, ctx.user_id)
        .await
        .map(Json)
}

/// Pauses a running or waiting run, as `user_id`.
pub async fn pause_run(
    state: &EngineState,
    instance_id: Uuid,
    row_version: i64,
    user_id: Uuid,
) -> Result<ControlResult, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row_version = transition(
        &mut tx,
        instance_id,
        row_version,
        &["running", "waiting"],
        "paused",
    )
    .await?;
    event(
        &mut tx,
        state,
        instance_id,
        AuditOperation::Update,
        "workflow_instance.pause",
        user_id,
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(ControlResult {
        id: instance_id,
        status: "paused".into(),
        row_version,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/workflow/instances/{id}/resume",
    tag = "workflow",
    operation_id = "workflow_instance_resume",
    params(("id" = Uuid, Path)),
    request_body = ControlBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The run continues; a step still waiting keeps waiting", body = ControlResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "The run is not paused, or changed since it was read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn resume_instance(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(instance_id): Path<Uuid>,
    Json(body): Json<ControlBody>,
) -> Result<Json<ControlResult>, AppError> {
    resume_run(&state, instance_id, body.row_version, ctx.user_id)
        .await
        .map(Json)
}

/// Resumes a paused run, as `user_id`.
pub async fn resume_run(
    state: &EngineState,
    instance_id: Uuid,
    row_version: i64,
    user_id: Uuid,
) -> Result<ControlResult, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row_version = transition(&mut tx, instance_id, row_version, &["paused"], "running").await?;
    // The pass settles it back to `waiting` when a step still waits.
    enqueue_execute(&mut tx, instance_id).await?;
    event(
        &mut tx,
        state,
        instance_id,
        AuditOperation::Update,
        "workflow_instance.resume",
        user_id,
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(ControlResult {
        id: instance_id,
        status: "running".into(),
        row_version,
    })
}

/// The mapping of the run's waiting steps onto `target`, which must be a
/// published version of the same flow.
async fn preview(
    db: &sqlx::PgPool,
    instance_id: Uuid,
    target_version_id: Uuid,
) -> Result<MovePreview, AppError> {
    let (from_version_id, from_definition): (Uuid, Uuid) = sqlx::query_as(
        "SELECT i.definition_version_id, v.definition_id FROM workflow_instance i \
           JOIN workflow_definition_version v ON v.id = i.definition_version_id \
          WHERE i.id = $1",
    )
    .bind(instance_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let target: Option<(Uuid, String, Value)> = sqlx::query_as(
        "SELECT definition_id, status, graph FROM workflow_definition_version WHERE id = $1",
    )
    .bind(target_version_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((target_definition, target_status, target_graph)) = target else {
        return Err(AppError::Validation(
            "the target version does not exist".into(),
        ));
    };
    if target_definition != from_definition {
        return Err(AppError::Validation(
            "the target version belongs to another flow".into(),
        ));
    }
    if target_status != "published" {
        return Err(AppError::Validation(
            "the target version is not published".into(),
        ));
    }
    let from_graph: Value =
        sqlx::query_scalar("SELECT graph FROM workflow_definition_version WHERE id = $1")
            .bind(from_version_id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    let from_graph = Graph::parse(&from_graph).map_err(AppError::internal)?;
    let target_graph = Graph::parse(&target_graph).map_err(AppError::internal)?;
    let target_types: HashMap<&str, &str> = target_graph
        .nodes
        .iter()
        .map(|n| (n.id.as_str(), n.node_type.as_str()))
        .collect();

    let waiting: Vec<String> = sqlx::query_scalar(
        "SELECT node_id FROM workflow_node_run WHERE instance_id = $1 AND status = 'waiting' \
          ORDER BY node_id",
    )
    .bind(instance_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let waiting: Vec<MoveMapping> = waiting
        .into_iter()
        .map(|node_id| {
            let node_type = from_graph
                .node(&node_id)
                .map(|n| n.node_type.clone())
                .unwrap_or_default();
            let found = target_types.get(node_id.as_str()) == Some(&node_type.as_str());
            MoveMapping {
                node_id,
                node_type,
                found,
            }
        })
        .collect();
    Ok(MovePreview {
        from_version_id,
        target_version_id,
        movable: waiting.iter().all(|m| m.found),
        waiting,
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/workflow/instances/{id}/move-preview",
    tag = "workflow",
    operation_id = "workflow_instance_move_preview",
    params(("id" = Uuid, Path), MovePreviewQuery),
    responses(
        (status = 200, description = "Where each waiting step lands in the target version", body = MovePreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such run", body = ErrorResponse),
        (status = 422, description = "The target is not a published version of the same flow", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn move_preview(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(instance_id): Path<Uuid>,
    Query(query): Query<MovePreviewQuery>,
) -> Result<Json<MovePreview>, AppError> {
    Ok(Json(
        preview(&state.base.db, instance_id, query.target_version_id).await?,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/workflow/instances/{id}/move",
    tag = "workflow",
    operation_id = "workflow_instance_move",
    params(("id" = Uuid, Path)),
    request_body = MoveBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The run now belongs to the target version", body = ControlResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such run", body = ErrorResponse),
        (status = 409, description = "The run is not waiting or paused, or changed since it was read", body = ErrorResponse),
        (status = 422, description = "A waiting step is missing from the target version", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn move_instance(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(instance_id): Path<Uuid>,
    Json(body): Json<MoveBody>,
) -> Result<Json<ControlResult>, AppError> {
    move_run(&state, instance_id, &body, ctx.user_id)
        .await
        .map(Json)
}

/// Moves a waiting or paused run to `body.target_version_id`, as `user_id`.
pub async fn move_run(
    state: &EngineState,
    instance_id: Uuid,
    body: &MoveBody,
    user_id: Uuid,
) -> Result<ControlResult, AppError> {
    let plan = preview(&state.base.db, instance_id, body.target_version_id).await?;
    if !plan.movable {
        let missing: Vec<&str> = plan
            .waiting
            .iter()
            .filter(|m| !m.found)
            .map(|m| m.node_id.as_str())
            .collect();
        return Err(AppError::Validation(format!(
            "waiting steps missing from the target version: {}",
            missing.join(", ")
        )));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row_version: i64 = sqlx::query_scalar(
        "UPDATE workflow_instance \
            SET definition_version_id = $3, row_version = row_version + 1 \
          WHERE id = $1 AND row_version = $2 AND definition_version_id = $4 \
            AND status IN ('waiting', 'paused') \
          RETURNING row_version",
    )
    .bind(instance_id)
    .bind(body.row_version)
    .bind(body.target_version_id)
    .bind(plan.from_version_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::VersionConflict)?;
    // The run's wait rows follow it, so a resume finds the new version.
    sqlx::query(
        "UPDATE workflow_trigger_index SET definition_version_id = $2 \
          WHERE instance_id = $1 AND role = 'wait'",
    )
    .bind(instance_id)
    .bind(body.target_version_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    event(
        &mut tx,
        state,
        instance_id,
        AuditOperation::Update,
        "workflow_instance.move",
        user_id,
    )
    .await?;
    let status: String = sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = $1")
        .bind(instance_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(ControlResult {
        id: instance_id,
        status,
        row_version,
    })
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/workflow/instances/{id}/retry",
            post(retry_instance),
        )
        .route(
            "/api/v1/workflow/instances/{id}/pause",
            post(pause_instance),
        )
        .route(
            "/api/v1/workflow/instances/{id}/resume",
            post(resume_instance),
        )
        .route(
            "/api/v1/workflow/instances/{id}/move-preview",
            get(move_preview),
        )
        .route("/api/v1/workflow/instances/{id}/move", post(move_instance))
}

/// This file's slice of the workspace OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        retry_instance,
        pause_instance,
        resume_instance,
        move_preview,
        move_instance
    ),
    components(schemas(ControlBody, MoveBody, MovePreview, MoveMapping, ControlResult))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
