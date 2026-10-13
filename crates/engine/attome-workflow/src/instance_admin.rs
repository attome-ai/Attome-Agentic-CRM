//! Instance admin API (P-workflow-engine.md §5 step 8): list/detail/cancel,
//! plus a manual-start endpoint that exercises the same entry mechanism an
//! automatic entity-event trigger uses (entity create/update auto-start runs
//! through the change-event outbox, `entity_trigger::dispatch_pending`).

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, DEFAULT_PAGE_SIZE, PageBase, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;
use uuid::Uuid;

use crate::graph::Graph;
use crate::model::{
    CancelInstanceBody, InstanceDetail, InstanceListItem, NodeRunSummary, StartInstanceBody,
};
use attome_types::ErrorResponse;
use utoipa::IntoParams;

#[derive(sqlx::FromRow)]
struct InstanceListRow {
    id: Uuid,
    definition_version_id: Uuid,
    status: String,
    started_at: chrono::DateTime<chrono::Utc>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    correlation_entity_id: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct InstanceDetailRow {
    id: Uuid,
    definition_version_id: Uuid,
    status: String,
    started_at: chrono::DateTime<chrono::Utc>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    started_by: Option<Uuid>,
    correlation_entity_id: Option<Uuid>,
    context: serde_json::Value,
    node_data: serde_json::Value,
    row_version: i64,
}

#[derive(sqlx::FromRow)]
struct NodeRunSummaryRow {
    node_id: String,
    status: String,
    attempt_count: i32,
    last_error: Option<String>,
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Deserialize, IntoParams)]
struct InstanceListQuery {
    status: Option<String>,
    correlation_entity_id: Option<Uuid>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/workflow/instances",
    tag = "workflow",
    params(InstanceListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<InstanceListItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_instances(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<InstanceListQuery>,
) -> Result<Json<PaginatedResponse<InstanceListItem>>, AppError> {
    let window = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workflow_instance \
         WHERE ($1::text IS NULL OR status = $1) \
           AND ($2::uuid IS NULL OR correlation_entity_id = $2)",
    )
    .bind(&q.status)
    .bind(q.correlation_entity_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let rows: Vec<InstanceListRow> = sqlx::query_as(
        "SELECT id, definition_version_id, status, started_at, completed_at, correlation_entity_id \
         FROM workflow_instance \
         WHERE ($1::text IS NULL OR status = $1) \
           AND ($2::uuid IS NULL OR correlation_entity_id = $2) \
         ORDER BY started_at DESC LIMIT $3 OFFSET $4",
    )
    .bind(&q.status)
    .bind(q.correlation_entity_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|r| InstanceListItem {
            id: r.id,
            definition_version_id: r.definition_version_id,
            status: r.status,
            started_at: r.started_at,
            completed_at: r.completed_at,
            correlation_entity_id: r.correlation_entity_id,
        })
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/workflow/instances/{id}",
    tag = "workflow",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = InstanceDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_instance(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(instance_id): Path<Uuid>,
) -> Result<Json<InstanceDetail>, AppError> {
    let row: InstanceDetailRow = sqlx::query_as(
        "SELECT id, definition_version_id, status, started_at, completed_at, started_by, \
                correlation_entity_id, context, node_data, row_version \
         FROM workflow_instance WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;

    let node_run_rows: Vec<NodeRunSummaryRow> = sqlx::query_as(
        "SELECT node_id, status, attempt_count, last_error, started_at, completed_at \
         FROM workflow_node_run WHERE instance_id = $1 ORDER BY started_at NULLS LAST",
    )
    .bind(instance_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let node_runs = node_run_rows
        .into_iter()
        .map(|r| NodeRunSummary {
            node_id: r.node_id,
            status: r.status,
            attempt_count: r.attempt_count,
            last_error: r.last_error,
            started_at: r.started_at,
            completed_at: r.completed_at,
        })
        .collect();

    Ok(Json(InstanceDetail {
        id: row.id,
        definition_version_id: row.definition_version_id,
        status: row.status,
        started_at: row.started_at,
        completed_at: row.completed_at,
        started_by: row.started_by,
        correlation_entity_id: row.correlation_entity_id,
        context: row.context,
        node_data: row.node_data,
        row_version: row.row_version,
        node_runs,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/workflow/instances/{id}/cancel",
    tag = "workflow",
    params(("id" = Uuid, Path)),
    request_body = CancelInstanceBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Cancelled)])))),
    responses(
        (status = 200, description = "Success", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn cancel_instance(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(instance_id): Path<Uuid>,
    Json(body): Json<CancelInstanceBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let rows = sqlx::query(
        "UPDATE workflow_instance SET status = 'cancelled', completed_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 AND status IN ('running', 'waiting')",
    )
    .bind(instance_id)
    .bind(body.row_version)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if rows == 0 {
        return Err(AppError::VersionConflict);
    }
    sqlx::query("DELETE FROM workflow_trigger_index WHERE role = 'wait' AND instance_id = $1")
        .bind(instance_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    // Already fixed independently on main before this branch rebased onto
    // it (same gap, same shape) -- kept as-is, not re-implemented.
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "workflow_instance",
            instance_id,
            attome_audit::AuditOperation::Cancelled,
            "workflow_instance.cancel",
            ctx.user_id,
        ),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;

    Ok(Json(
        serde_json::json!({ "id": instance_id, "status": "cancelled" }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/workflow/instances",
    tag = "workflow",
    request_body = StartInstanceBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn start_manual(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<StartInstanceBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let instance_id = start_published_instance(
        &state,
        &body.definition_logicalname,
        Some(ctx.user_id),
        body.correlation_entity_id,
        body.context,
    )
    .await?;

    attome_audit::write_business_event(
        &state,
        "workflow_instance",
        instance_id,
        attome_audit::AuditOperation::Create,
        "workflow_instance.start",
        ctx.user_id,
        None,
        None,
        format!(
            "workflow instance started for {:?}",
            body.definition_logicalname
        ),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": instance_id })),
    ))
}

/// Starts the **published, active, not-deleted** version of the workflow
/// named `definition_logicalname` — the whole of a manual start once the
/// caller is authorized. Shared by the `POST /api/v1/workflow/instances`
/// handler above and by [`PublishedWorkflowStarter`], the seam `attome-ai`'s
/// `workflow.start` reaches it through (C5), so the two cannot drift.
/// Authorizes nothing: the handler's `Authorized<Admin>` and the licence gate
/// are the caller's to apply.
pub async fn start_published_instance(
    state: &EngineState,
    definition_logicalname: &str,
    started_by: Option<Uuid>,
    correlation_entity_id: Option<Uuid>,
    context: serde_json::Value,
) -> Result<Uuid, AppError> {
    let version_id: Uuid = sqlx::query_scalar(
        "SELECT v.id FROM workflow_definition_version v \
         JOIN workflow_definition d ON d.id = v.definition_id \
         WHERE d.logicalname = $1 AND v.status = 'published' AND d.is_active = TRUE AND d.is_deleted = FALSE",
    )
    .bind(definition_logicalname)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| {
        AppError::Validation(format!(
            "workflow {definition_logicalname:?} has no published, active version"
        ))
    })?;

    start_instance_internal(
        state,
        version_id,
        None,
        started_by,
        correlation_entity_id,
        context,
    )
    .await
}

/// `attome-workflow`'s implementation of the `attome_core::WorkflowStarter`
/// seam, registered once by the composition root
/// (`EngineSystemBuilder::register_workflow_starter`). It is
/// [`start_published_instance`] and nothing else.
#[derive(Debug)]
pub struct PublishedWorkflowStarter;

impl attome_core::WorkflowStarter for PublishedWorkflowStarter {
    fn start<'a>(
        &'a self,
        state: &'a EngineState,
        request: attome_core::WorkflowStartRequest,
    ) -> attome_core::WorkflowStartFuture<'a> {
        Box::pin(async move {
            start_published_instance(
                state,
                &request.definition_logicalname,
                Some(request.started_by),
                request.correlation_entity_id,
                request.context,
            )
            .await
        })
    }
}

/// Shared entry-start primitive — used by the manual-start HTTP handler
/// above and by `scheduler::execute_sub_workflow` for a `sub_workflow` node.
/// Picks the version's first `Trigger` node as the entry point (the graph
/// validator guarantees at least one exists); a specific `trigger_node_id`
/// can be supplied to disambiguate a multi-trigger graph.
pub async fn start_instance_internal(
    state: &EngineState,
    definition_version_id: Uuid,
    trigger_node_id: Option<&str>,
    started_by: Option<Uuid>,
    correlation_entity_id: Option<Uuid>,
    context: serde_json::Value,
) -> Result<Uuid, AppError> {
    start_instance_inner(
        state,
        definition_version_id,
        trigger_node_id,
        started_by,
        correlation_entity_id,
        context,
        None,
    )
    .await?
    .ok_or_else(|| AppError::internal("instance start without an event id cannot conflict"))
}

/// M06 W1 (plan §4.1, G1) — [`start_instance_internal`] for an entity-trigger
/// start. `trigger_event_id` is the `entity_change_event` row the
/// start came from; migration 0501's partial unique index on
/// `(definition_version_id, trigger_node_id, trigger_event_id)` plus
/// `ON CONFLICT DO NOTHING` make a re-read event a no-op. Returns `None` when
/// this event already started this trigger's instance — the at-least-once
/// dispatch loop re-reads an event after a crash between start and cursor
/// advance, and must not start it twice.
pub async fn start_instance_for_event(
    state: &EngineState,
    definition_version_id: Uuid,
    trigger_node_id: &str,
    started_by: Option<Uuid>,
    correlation_entity_id: Option<Uuid>,
    context: serde_json::Value,
    trigger_event_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    start_instance_inner(
        state,
        definition_version_id,
        Some(trigger_node_id),
        started_by,
        correlation_entity_id,
        context,
        Some(trigger_event_id),
    )
    .await
}

async fn start_instance_inner(
    state: &EngineState,
    definition_version_id: Uuid,
    trigger_node_id: Option<&str>,
    started_by: Option<Uuid>,
    correlation_entity_id: Option<Uuid>,
    context: serde_json::Value,
    trigger_event_id: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    let graph_json: serde_json::Value =
        sqlx::query_scalar("SELECT graph FROM workflow_definition_version WHERE id = $1")
            .bind(definition_version_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let graph = Graph::parse(&graph_json).map_err(AppError::internal)?;

    let entry_node_id = match trigger_node_id {
        Some(id) => id.to_string(),
        None => graph
            .nodes
            .iter()
            .find(|n| {
                crate::node_types::NodeType::parse(&n.node_type)
                    == Some(crate::node_types::NodeType::Trigger)
            })
            .map(|n| n.id.clone())
            .ok_or_else(|| AppError::internal("published graph has no Trigger node"))?,
    };

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // The conflict target names 0501's partial unique index; a NULL
    // `trigger_event_id` (every non-entity start) never matches its predicate,
    // so those inserts behave exactly as before.
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO workflow_instance \
            (definition_version_id, trigger_node_id, correlation_entity_id, status, started_by, \
             context, node_data, trigger_event_id) \
         VALUES ($1, $2, $3, 'running', $4, $5, $6, $7) \
         ON CONFLICT (definition_version_id, trigger_node_id, trigger_event_id) \
             WHERE trigger_event_id IS NOT NULL DO NOTHING \
         RETURNING id",
    )
    .bind(definition_version_id)
    .bind(&entry_node_id)
    .bind(correlation_entity_id)
    .bind(started_by)
    .bind(&context)
    .bind(serde_json::json!({ &entry_node_id: context.clone() }))
    .bind(trigger_event_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(instance_id) = inserted else {
        // Already started by an earlier delivery of the same event. Nothing
        // was written; dropping `tx` rolls back the empty transaction.
        return Ok(None);
    };

    sqlx::query(
        "INSERT INTO workflow_node_run (id, instance_id, node_id, status, attempt_count, started_at, completed_at) \
         VALUES ($1, $2, $3, 'succeeded', 1, NOW(), NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(instance_id)
    .bind(&entry_node_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::WorkflowExecute { instance_id },
    )
    .await
    .map_err(AppError::internal)?;

    // Plan 4.3 (C19): this shared primitive (the manual-start HTTP handler
    // above and `scheduler::execute_sub_workflow` both call it) previously
    // wrote no audit event at all for instance start, despite `x-audit`
    // annotating both routes as covered (D-542) -- the annotation was
    // correct about the category/operation, but nothing actually wrote the
    // event. Fixed here, in this function's own transaction (D-062), so
    // both callers get it atomically with the insert above rather than each
    // needing its own after-the-fact, non-atomic write. `started_by` is
    // `None` for a scheduler-originated instance with no human starter
    // (a sub-workflow whose own parent chain traces back to one, or a
    // future automatic trigger) -- `Initiator::System` there, matching
    // `trd-engine::audit::attribution`'s and this crate's own
    // `scheduler.rs` node-run event's distinction, rather than falsely
    // claiming `Initiator::User` with a nil actor id.
    let audit = attome_audit::audit_service(state);
    let attribution = attome_audit::Attribution {
        acting_user_id: started_by.unwrap_or(Uuid::nil()),
        initiator: if started_by.is_some() {
            attome_audit::Initiator::User
        } else {
            attome_audit::Initiator::System
        },
        agent_session_id: None,
        agent_action_id: None,
    };
    let event = attome_audit::BusinessEvent::new(
        "workflow_instance",
        instance_id,
        attome_audit::AuditOperation::Create,
        "workflow.instance.started",
        started_by.unwrap_or(Uuid::nil()),
    )
    .attributed(attribution);
    attome_audit::write_business_event_in_tx(&mut tx, &audit, event)
        .await
        .map_err(AppError::internal)?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(Some(instance_id))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/workflow/instances",
            get(list_instances).post(start_manual),
        )
        .route("/api/v1/workflow/instances/{id}", get(get_instance))
        .route(
            "/api/v1/workflow/instances/{id}/cancel",
            post(cancel_instance),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_instances, get_instance, cancel_instance, start_manual))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
