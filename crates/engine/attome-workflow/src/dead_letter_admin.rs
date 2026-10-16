//! Entity-trigger dead letters (M06 W1 follow-up, migration 0510): list,
//! replay and discard the change-feed events `entity_trigger::dispatch_pending`
//! gave up on.
//!
//! **Replay** starts the entry triggers the stored event matches, through the
//! dispatcher's own step (`entity_trigger::start_entry_instances`). Entry
//! starts carry the event id under migration 0501's unique index, so a dead
//! letter that failed part-way (some of its triggers already started) starts
//! only the ones it missed, and a repeated replay starts nothing twice.
//!
//! Replay never resumes a Wait-for-Event. The dead letter does not record
//! when the change happened, so replay cannot tell a wait that was pending
//! then from one that began afterwards, and resuming the latter would move a
//! workflow on a change that predates its wait. A wait that missed the event
//! is the operator's to handle on its instance.
//!
//! A successful replay deletes the dead letter in the transaction that writes
//! its audit event. A failed one keeps it, is audited as `Failed`, and
//! returns the error.
//!
//! **Discard** deletes a dead letter the operator has handled another way;
//! the audit event is its only remaining record.

use attome_audit::AuditOutcome;
use attome_audit::security::{MandatoryCategory, SecurityAuditor, SecurityEvent};
use attome_core::EngineState;
use attome_core::change_feed::ChangeEvent;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

const ENTITY: &str = "workflow_trigger_failure";

/// One dead-lettered entity-trigger event.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct TriggerDeadLetter {
    /// The `entity_change_event` id the dispatcher skipped.
    pub event_id: Uuid,
    pub entity_logicalname: String,
    pub record_id: Uuid,
    /// `create`, `update`, … as written to the change feed.
    pub operation: String,
    /// Failed dispatch attempts that were counted.
    pub attempts: i32,
    /// The last counted failure, as the dispatcher logged it.
    pub last_error: String,
    pub first_failed_at: DateTime<Utc>,
    pub last_failed_at: DateTime<Utc>,
    pub dead_lettered_at: DateTime<Utc>,
}

impl std::fmt::Debug for TriggerDeadLetter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TriggerDeadLetter").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct TriggerReplayResult {
    /// Workflow instances this replay newly started; 0 when every trigger
    /// the event matches had already started. Waits are never resumed.
    pub dispatched: u64,
}

impl std::fmt::Debug for TriggerReplayResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TriggerReplayResult")
            .finish_non_exhaustive()
    }
}

#[utoipa::path(
    get,
    operation_id = "workflow_list_trigger_dead_letters",
    path = "/api/v1/workflow/trigger-dead-letters",
    tag = "workflow",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Dead letters, newest first", body = PaginatedResponse<TriggerDeadLetter>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_trigger_dead_letters(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<TriggerDeadLetter>>, AppError> {
    let w = q.window();
    let items = sqlx::query_as::<_, TriggerDeadLetter>(
        "SELECT event_id, entity_logicalname, record_id, operation, attempts, last_error, \
                first_failed_at, last_failed_at, dead_lettered_at \
         FROM workflow_trigger_failure \
         WHERE dead_lettered_at IS NOT NULL \
         ORDER BY dead_lettered_at DESC, event_id \
         LIMIT $1 OFFSET $2",
    )
    .bind(w.page_size)
    .bind(w.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workflow_trigger_failure WHERE dead_lettered_at IS NOT NULL",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: w.page,
        page_size: w.page_size,
    }))
}

/// The dead letter `event_id`, or 404.
async fn load(state: &EngineState, event_id: Uuid) -> Result<TriggerDeadLetter, AppError> {
    sqlx::query_as::<_, TriggerDeadLetter>(
        "SELECT event_id, entity_logicalname, record_id, operation, attempts, last_error, \
                first_failed_at, last_failed_at, dead_lettered_at \
         FROM workflow_trigger_failure \
         WHERE event_id = $1 AND dead_lettered_at IS NOT NULL",
    )
    .bind(event_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

#[utoipa::path(
    post,
    operation_id = "workflow_replay_trigger_dead_letter",
    path = "/api/v1/workflow/trigger-dead-letters/{event_id}/replay",
    tag = "workflow",
    params(("event_id" = Uuid, Path, description = "The dead-lettered change-feed event id")),
    responses(
        (status = 200, description = "Replayed; the dead letter is removed", body = TriggerReplayResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dead letter", body = ErrorResponse),
        (status = 503, description = "Dispatch is overloaded or a dependency is unavailable; the dead letter is kept", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Execute)])))),
)]
async fn replay_trigger_dead_letter(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(event_id): Path<Uuid>,
) -> Result<Json<TriggerReplayResult>, AppError> {
    let dispatched = replay(&state, event_id, ctx.user_id).await?;
    Ok(Json(TriggerReplayResult { dispatched }))
}

/// Replays dead letter `event_id` for `actor_user_id` (module doc) and
/// returns the instances started plus waits resumed. `NotFound` when there is
/// no such dead letter; a dispatch error leaves it in place.
pub async fn replay(
    state: &EngineState,
    event_id: Uuid,
    actor_user_id: Uuid,
) -> Result<u64, AppError> {
    let row = load(state, event_id).await?;
    let event = ChangeEvent {
        id: row.event_id,
        entity_logicalname: row.entity_logicalname,
        record_id: row.record_id,
        operation: row.operation,
        event_name: None,
        created_at: row.first_failed_at,
        changed_attributes: Vec::new(),
    };
    let what = format!(
        "{} {} {}",
        event.entity_logicalname, event.record_id, event.operation
    );
    let audit_event = |outcome: AuditOutcome, detail: String| {
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Execute,
            actor_user_id,
            ENTITY,
            Some(event_id),
        )
        .named("workflow_trigger.replay")
        .outcome(outcome)
        .comment(format!("{what}; {detail}"))
    };

    // The starts commit in their own transactions, as in live dispatch. A
    // failure part-way may leave some started; that attempt is audited too,
    // and the dead letter stays for another try.
    let system_user_id = crate::entity_trigger::ensure_system_user(&state.base.db).await?;
    let dispatched =
        match crate::entity_trigger::start_entry_instances(state, &event, system_user_id).await {
            Ok(n) => n,
            Err(e) => {
                SecurityAuditor::from_state(state)
                    .write(audit_event(AuditOutcome::Failed, format!("error={e}")))
                    .await?;
                return Err(e);
            }
        };

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // Zero rows means a concurrent replay or discard got there first. The
    // starts above are idempotent, so this replay still succeeded; the audit
    // event says whether it was the one that removed the dead letter.
    let removed = sqlx::query(
        "DELETE FROM workflow_trigger_failure \
         WHERE event_id = $1 AND dead_lettered_at IS NOT NULL",
    )
    .bind(event_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        audit_event(
            AuditOutcome::Succeeded,
            format!("started={dispatched} removed={}", removed > 0),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(dispatched)
}

#[utoipa::path(
    delete,
    operation_id = "workflow_discard_trigger_dead_letter",
    path = "/api/v1/workflow/trigger-dead-letters/{event_id}",
    tag = "workflow",
    params(("event_id" = Uuid, Path, description = "The dead-lettered change-feed event id")),
    responses(
        (status = 204, description = "The dead letter was deleted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dead letter", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::HardDelete)])))),
)]
async fn discard_trigger_dead_letter(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(event_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    discard(&state, event_id, ctx.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes dead letter `event_id` for `actor_user_id`, audited in the same
/// transaction. `NotFound` when there is no such dead letter.
pub async fn discard(
    state: &EngineState,
    event_id: Uuid,
    actor_user_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let deleted: Option<(String, Uuid, String)> = sqlx::query_as(
        "DELETE FROM workflow_trigger_failure \
         WHERE event_id = $1 AND dead_lettered_at IS NOT NULL \
         RETURNING entity_logicalname, record_id, operation",
    )
    .bind(event_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // Dropping `tx` rolls back; nothing was deleted, so no event is written.
    let Some((entity, record_id, operation)) = deleted else {
        return Err(AppError::NotFound);
    };
    // The event goes in the delete's own transaction: it is the only record
    // the dead letter existed.
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            attome_audit::AuditOperation::HardDelete,
            actor_user_id,
            ENTITY,
            Some(event_id),
        )
        .named("workflow_trigger.discard")
        .comment(format!("{entity} {record_id} {operation}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/workflow/trigger-dead-letters",
            get(list_trigger_dead_letters),
        )
        .route(
            "/api/v1/workflow/trigger-dead-letters/{event_id}/replay",
            post(replay_trigger_dead_letter),
        )
        .route(
            "/api/v1/workflow/trigger-dead-letters/{event_id}",
            delete(discard_trigger_dead_letter),
        )
}

/// This file's slice of the workspace OpenAPI document, merged by the crate's
/// `openapi()` (the handlers are module-private, as in `instance_admin`).
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_trigger_dead_letters,
    replay_trigger_dead_letter,
    discard_trigger_dead_letter
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
