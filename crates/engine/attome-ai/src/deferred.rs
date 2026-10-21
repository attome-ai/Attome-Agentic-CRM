//! The undo window (roadmap AH8, V2-D693): an action held before it runs, so
//! the person it acts for can cancel it.
//!
//! Any write, including one that cannot be undone once it runs (sending an
//! email, a hard delete, a payment, a call to an outside system), can go
//! through here: the window before it runs is its undo. Two ways in, both
//! decided by the gate (`GateDecision::ExecuteAfterDelay`):
//!
//! - an agent whose autonomy level for the action is `act_with_undo`;
//! - any caller who asks for a window: a person through the invoke API's
//!   `undo_window_seconds`, an agent through the reserved
//!   `_undo_window_seconds` argument. Asking never skips a confirmation or an
//!   approval; it only delays an action that would run now.
//!
//! **Durable.** The row is the queue: `EngineJob::AiDeferredActionSweep` runs
//! due rows every few seconds, so a restart loses nothing. A row is claimed
//! once (`pending` → `running`) and never runs twice: one that stays
//! `running` past [`INTERRUPTED_AFTER`] (the worker died mid-run) ends
//! `failed`, because its side effect may already have happened.
//!
//! **Re-checked before it runs**, exactly like an approved action
//! (`execute::run_deferred`): session, account, licence, kill-switch,
//! privileges, MCP admission, the record unchanged, and, for an agent, the
//! gate again with today's autonomy level. Anything that no longer holds ends
//! the row without running it, or turns it into an approval request.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::ActionDescriptor;

/// The argument an agent adds to any action call to ask for an undo window.
/// Removed before the action sees its arguments.
pub const UNDO_WINDOW_ARG: &str = "_undo_window_seconds";

/// A `running` row older than this was interrupted mid-run.
pub const INTERRUPTED_AFTER: &str = "15 minutes";

/// Rows claimed per batch, and batches per sweep.
const BATCH: i64 = 50;
const MAX_BATCHES: usize = 10;

/// Transient failures before a row gives up.
const MAX_ATTEMPTS: i16 = 5;

/// Where the pending-actions list lives in the app.
const PENDING_ROUTE: &str = "/ai/pending-actions";

/// Removes [`UNDO_WINDOW_ARG`] from an action's arguments: the cleaned
/// arguments, and the window asked for. A value that is not a whole number
/// of seconds is ignored (the action runs as it would without it).
pub fn take_undo_window(args: &Value) -> (Value, Option<u32>) {
    let Some(map) = args.as_object() else {
        return (args.clone(), None);
    };
    if !map.contains_key(UNDO_WINDOW_ARG) {
        return (args.clone(), None);
    }
    let mut map = map.clone();
    let seconds = map
        .remove(UNDO_WINDOW_ARG)
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok());
    (Value::Object(map), seconds)
}

/// A held action.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct DeferredAction {
    pub id: Uuid,
    pub action_id: String,
    /// `user` or `agent`.
    pub initiator: String,
    pub agent_session_id: Option<Uuid>,
    pub acting_user_id: Uuid,
    pub run_at: DateTime<Utc>,
    /// `pending`, `running`, `executed`, `cancelled`, `invalidated`,
    /// `approval_required` or `failed`.
    pub status: String,
    pub reason: Option<String>,
    pub approval_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

const LIST_COLUMNS: &str = "id, action_id, initiator, agent_session_id, acting_user_id, run_at, \
     status, reason, approval_id, created_at";

/// What the sweep needs to run one row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DueAction {
    pub id: Uuid,
    pub action_id: String,
    pub args: Value,
    pub initiator: String,
    pub agent_session_id: Option<Uuid>,
    pub tool_call_id: Option<String>,
    pub acting_user_id: Uuid,
    pub target: Option<Value>,
    pub report_to_owner: bool,
    pub attempts: i16,
}

/// The handle a caller gets back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scheduled {
    pub id: Uuid,
    pub run_at: DateTime<Utc>,
}

/// Holds an action for `seconds`. A retried agent tool call returns the row
/// its first call made rather than holding a second one.
pub async fn enqueue(
    state: &EngineState,
    descriptor: &ActionDescriptor,
    ctx: &ActionContext,
    args: &Value,
    seconds: u32,
    report: bool,
) -> Result<Scheduled, AppError> {
    let target = crate::execute::capture_target(state, ctx, args)
        .await
        .map(|t| serde_json::to_value(t).map_err(AppError::internal))
        .transpose()?;
    let initiator = if ctx.is_agent() { "agent" } else { "user" };
    let tool_call_id = ctx
        .idempotency_key
        .as_deref()
        .filter(|_| ctx.is_agent() && ctx.agent_session_id.is_some());
    let inserted: Option<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        "INSERT INTO ai_deferred_action \
           (action_id, args, initiator, agent_session_id, tool_call_id, acting_user_id, target, \
            report_to_owner, run_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9)) \
         ON CONFLICT (agent_session_id, tool_call_id) WHERE tool_call_id IS NOT NULL DO NOTHING \
         RETURNING id, run_at",
    )
    .bind(descriptor.id.0)
    .bind(args)
    .bind(initiator)
    .bind(ctx.agent_session_id)
    .bind(tool_call_id)
    .bind(ctx.security.user_id)
    .bind(&target)
    .bind(report)
    .bind(f64::from(seconds))
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (id, run_at, fresh) = match inserted {
        Some((id, run_at)) => (id, run_at, true),
        None => {
            let (id, run_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
                "SELECT id, run_at FROM ai_deferred_action \
                 WHERE agent_session_id = $1 AND tool_call_id = $2",
            )
            .bind(ctx.agent_session_id)
            .bind(tool_call_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            (id, run_at, false)
        }
    };
    if fresh && ctx.is_agent() {
        notify(
            state,
            ctx.security.user_id,
            format!(
                "An agent will run {} at {}",
                descriptor.id,
                run_at.format("%H:%M UTC")
            ),
            "You can cancel it until then from your pending actions.".to_owned(),
        )
        .await;
    }
    Ok(Scheduled { id, run_at })
}

/// Tells the person an agent acts for what it did (AH8 level 3, and an
/// undo-window action's end). Best effort, in-app only, after the action's
/// own transaction: a lost note must not fail an action that already ran.
pub async fn notify(state: &EngineState, user_id: Uuid, subject: String, body: String) {
    let req = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale: "en".to_owned(),
        recipient_user_ref: Some(user_id),
        is_global: false,
        organization_ref: None,
        channels: Some(vec!["in_app".to_owned()]),
        subject: Some(subject),
        body_html: None,
        body_text: Some(body),
        route: Some(PENDING_ROUTE.to_owned()),
        variables: std::collections::HashMap::new(),
        priority: "normal".to_owned(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    if let Err(e) = attome_notification::dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        req,
    )
    .await
    {
        tracing::warn!(user_id = %user_id, error = %e, "AH8: failed to notify the owner of an agent action");
    }
}

/// How running one due row ended.
#[derive(Debug)]
pub enum DeferredRun {
    Executed(Value),
    /// A re-check failed for good; nothing ran.
    Invalidated(&'static str),
    /// Today's autonomy level or the gate asks for approval; nothing ran.
    ApprovalRequired(Uuid),
    /// Not now (a paused session, a spent daily limit); tried again later.
    NotNow(&'static str),
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepStats {
    pub executed: u64,
    pub ended: u64,
    pub retried: u64,
    pub interrupted: u64,
}

/// Runs every due row. Called by `EngineJob::AiDeferredActionSweep`.
pub async fn sweep(state: &EngineState) -> Result<SweepStats, AppError> {
    let mut stats = SweepStats::default();
    let interrupted = sqlx::query(&format!(
        "UPDATE ai_deferred_action SET status = 'failed', updated_at = now(), \
           reason = 'interrupted while running; the outcome is unknown, so it is not run again' \
         WHERE status = 'running' AND updated_at < now() - interval '{INTERRUPTED_AFTER}'"
    ))
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    stats.interrupted = interrupted.rows_affected();

    for _ in 0..MAX_BATCHES {
        let due: Vec<DueAction> = sqlx::query_as(
            "UPDATE ai_deferred_action SET status = 'running', attempts = attempts + 1, \
               updated_at = now() \
             WHERE id IN (SELECT id FROM ai_deferred_action \
                          WHERE status = 'pending' AND run_at <= now() \
                          ORDER BY run_at LIMIT $1 FOR UPDATE SKIP LOCKED) \
             RETURNING id, action_id, args, initiator, agent_session_id, tool_call_id, \
               acting_user_id, target, report_to_owner, attempts",
        )
        .bind(BATCH)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if due.is_empty() {
            break;
        }
        for row in due {
            match crate::execute::run_deferred(state, &row).await {
                Ok(DeferredRun::Executed(result)) => {
                    finish(state, row.id, "executed", None, Some(&result), None).await?;
                    stats.executed += 1;
                    if row.report_to_owner {
                        notify(
                            state,
                            row.acting_user_id,
                            format!("An agent ran {}", row.action_id),
                            "The undo window ended and the action ran.".to_owned(),
                        )
                        .await;
                    }
                }
                Ok(DeferredRun::Invalidated(reason)) => {
                    finish(state, row.id, "invalidated", Some(reason), None, None).await?;
                    stats.ended += 1;
                    if row.initiator == "agent" {
                        notify(
                            state,
                            row.acting_user_id,
                            format!("An agent's {} did not run", row.action_id),
                            reason.to_owned(),
                        )
                        .await;
                    }
                }
                Ok(DeferredRun::ApprovalRequired(approval_id)) => {
                    finish(
                        state,
                        row.id,
                        "approval_required",
                        Some("it now needs approval before it runs"),
                        None,
                        Some(approval_id),
                    )
                    .await?;
                    stats.ended += 1;
                }
                Ok(DeferredRun::NotNow(reason)) => {
                    retry_later(state, row.id, reason).await?;
                    stats.retried += 1;
                }
                Err(e) if row.attempts < MAX_ATTEMPTS => {
                    tracing::warn!(deferred_action_id = %row.id, error = %e, "deferred action failed; retrying");
                    retry_later(state, row.id, "a transient failure; it will be tried again")
                        .await?;
                    stats.retried += 1;
                }
                Err(e) => {
                    tracing::error!(deferred_action_id = %row.id, error = %e, "deferred action failed for good");
                    finish(
                        state,
                        row.id,
                        "failed",
                        Some("it failed after several attempts"),
                        None,
                        None,
                    )
                    .await?;
                    stats.ended += 1;
                }
            }
        }
    }
    Ok(stats)
}

async fn finish(
    state: &EngineState,
    id: Uuid,
    status: &str,
    reason: Option<&str>,
    result: Option<&Value>,
    approval_id: Option<Uuid>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE ai_deferred_action SET status = $2, reason = $3, result = $4, approval_id = $5, \
           updated_at = now() WHERE id = $1 AND status = 'running'",
    )
    .bind(id)
    .bind(status)
    .bind(reason)
    .bind(result)
    .bind(approval_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn retry_later(state: &EngineState, id: Uuid, reason: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE ai_deferred_action SET status = 'pending', reason = $2, \
           run_at = now() + interval '1 minute', updated_at = now() \
         WHERE id = $1 AND status = 'running'",
    )
    .bind(id)
    .bind(reason)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

// ── Routes ──────────────────────────────────────────────────────────────────

/// `GET /api/v1/ai/deferred-actions` — the caller's held actions, newest
/// first; an administrator sees everyone's.
#[utoipa::path(
    get,
    path = "/api/v1/ai/deferred-actions",
    operation_id = "list_deferred_actions",
    tag = "action",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Held actions", body = PaginatedResponse<DeferredAction>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_deferred(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<DeferredAction>>, AppError> {
    let w = q.window();
    let everyone = ctx.is_admin;
    let items: Vec<DeferredAction> = sqlx::query_as(&format!(
        "SELECT {LIST_COLUMNS} FROM ai_deferred_action \
         WHERE ($1 OR acting_user_id = $2) \
         ORDER BY (status = 'pending') DESC, created_at DESC LIMIT $3 OFFSET $4"
    ))
    .bind(everyone)
    .bind(ctx.user_id)
    .bind(w.page_size)
    .bind(w.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ai_deferred_action WHERE ($1 OR acting_user_id = $2)",
    )
    .bind(everyone)
    .bind(ctx.user_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        w.page,
        w.page_size,
    )))
}

/// `POST /api/v1/ai/deferred-actions/{id}/cancel` — cancels a held action
/// before it runs. The person it acts for, or an administrator.
#[utoipa::path(
    post,
    path = "/api/v1/ai/deferred-actions/{id}/cancel",
    operation_id = "cancel_deferred_action",
    tag = "action",
    params(("id" = Uuid, Path, description = "The held action")),
    responses(
        (status = 200, description = "Cancelled; it will not run", body = DeferredAction),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such held action", body = ErrorResponse),
        (status = 409, description = "It already ran, or is running", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Ai, AuditOperation::Update)])))),
)]
async fn cancel_deferred(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<DeferredAction>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let cancelled: Option<DeferredAction> = sqlx::query_as(&format!(
        "UPDATE ai_deferred_action SET status = 'cancelled', cancelled_by = $2, \
           reason = 'cancelled before it ran', updated_at = now() \
         WHERE id = $1 AND status = 'pending' AND ($3 OR acting_user_id = $2) \
         RETURNING {LIST_COLUMNS}"
    ))
    .bind(id)
    .bind(ctx.user_id)
    .bind(ctx.is_admin)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(cancelled) = cancelled else {
        let visible: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM ai_deferred_action \
             WHERE id = $1 AND ($3 OR acting_user_id = $2))",
        )
        .bind(id)
        .bind(ctx.user_id)
        .bind(ctx.is_admin)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        return Err(if visible {
            AppError::Conflict("this action already ran or is running")
        } else {
            AppError::NotFound
        });
    };
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Ai,
            AuditOperation::Update,
            ctx.user_id,
            "ai_deferred_action",
            Some(id),
        )
        .named("ai.deferred_action.cancel")
        .comment(format!(
            "{} cancelled in its undo window",
            cancelled.action_id
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(cancelled))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/ai/deferred-actions", get(list_deferred))
        .route(
            "/api/v1/ai/deferred-actions/{id}/cancel",
            post(cancel_deferred),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_deferred, cancel_deferred),
    components(schemas(DeferredAction))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_undo_window_argument_is_taken_out_of_the_arguments() {
        let (args, seconds) = take_undo_window(&json!({"to": "a@b.c", UNDO_WINDOW_ARG: 120}));
        assert_eq!(seconds, Some(120));
        assert_eq!(args, json!({"to": "a@b.c"}));
    }

    #[test]
    fn arguments_without_the_window_are_unchanged() {
        let original = json!({"to": "a@b.c"});
        assert_eq!(take_undo_window(&original), (original.clone(), None));
        assert_eq!(take_undo_window(&json!(null)), (json!(null), None));
    }

    #[test]
    fn a_window_that_is_not_whole_seconds_is_dropped_and_still_removed() {
        let (args, seconds) = take_undo_window(&json!({"x": 1, UNDO_WINDOW_ARG: "soon"}));
        assert_eq!(seconds, None);
        assert_eq!(args, json!({"x": 1}));
    }
}
