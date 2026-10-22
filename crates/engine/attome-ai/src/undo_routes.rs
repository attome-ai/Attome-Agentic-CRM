//! AH1-T5: the undo routes for one agent session.
//!
//! - `GET /api/v1/ai/agent-sessions/{id}/undo-preview`: the planned steps
//!   ([`crate::undo::plan_undo`]) as the caller, writing nothing.
//! - `POST /api/v1/ai/agent-sessions/{id}/undo`: stores the plan and queues
//!   the job ([`crate::undo::start_undo`]); `202` with the run's id. The
//!   `Ai`/`Create` security event is written in the same transaction.
//! - `GET /api/v1/ai/undo-runs/{id}`: the run and a page of its items.
//!
//! - `GET /api/v1/admin/ai/agents/{id}/rollback-preview?since=` and
//!   `POST /api/v1/admin/ai/agents/{id}/rollback` (AH2-T4): the same for
//!   every session of one agent since a time; the post revokes the agent's
//!   live sessions first ([`crate::undo::start_rollback_since`]). Admin or
//!   `ai_agent.supervise` only; `since` must be in the past and within the
//!   audit retention window (`retention.audit_days`), or `422`.
//!
//! The session's owner may undo it, and so may anyone holding
//! `ai_agent.supervise`; anyone else gets `403`. A run is read by whoever
//! asked for it or a supervisor.

use attome_core::EngineState;
use attome_server::authz::{Authorized, PrivilegeKey, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::actions::agent_supervise::AgentSupervise;
use crate::undo::{UndoStep, collect_external_effects, collect_session_changes, plan_undo};

/// Whether `ctx` may undo or read what `owner` started. Pure.
pub fn may_undo(ctx: &SecurityContext, owner: Uuid) -> bool {
    ctx.user_id == owner || ctx.is_admin || ctx.privileges.contains(AgentSupervise::KEY)
}

/// Whether `ctx` may roll back an agent: an admin or a supervisor. Pure.
pub fn may_supervise(ctx: &SecurityContext) -> bool {
    ctx.is_admin || ctx.privileges.contains(AgentSupervise::KEY)
}

/// AH2-T4: a rollback's start must be in the past and, when the audit keeps
/// a bounded window (`retention.audit_days`), inside it. Pure.
pub fn check_since(
    since: DateTime<Utc>,
    now: DateTime<Utc>,
    audit_days: Option<u32>,
) -> Result<(), AppError> {
    if since > now {
        return Err(AppError::Validation("since: a time in the past".into()));
    }
    if let Some(days) = audit_days
        && since < now - chrono::Duration::days(i64::from(days))
    {
        return Err(AppError::Validation(format!(
            "since: within the last {days} days, the audit retention window"
        )));
    }
    Ok(())
}

/// AH2-T4: when to roll an agent back from.
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RollbackSince {
    /// Undo what the agent did at or after this time (UTC, ISO-8601).
    pub since: DateTime<Utc>,
}

/// AH2-T4: what rolling an agent back would do.
#[derive(Debug, Serialize, ToSchema)]
pub struct RollbackPreview {
    /// The agent's sessions since the time.
    pub session_ids: Vec<Uuid>,
    /// The steps, newest record first.
    pub steps: PaginatedResponse<UndoStep>,
}

/// The session's owner, or `404`.
async fn session_owner(state: &EngineState, session: Uuid) -> Result<Uuid, AppError> {
    sqlx::query_scalar("SELECT owner_user_id FROM agent_session WHERE id = $1")
        .bind(session)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)
}

async fn require_session(
    state: &EngineState,
    ctx: &SecurityContext,
    session: Uuid,
) -> Result<(), AppError> {
    if may_undo(ctx, session_owner(state, session).await?) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// A started undo.
#[derive(Debug, Serialize, ToSchema)]
pub struct UndoStarted {
    pub undo_run_id: Uuid,
}

/// One item of an undo run.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct UndoItemView {
    pub seq: i32,
    pub entity: String,
    pub record_id: Uuid,
    pub operation: String,
    /// `pending`, `restored`, `skipped_changed`, `not_undoable` or `failed`.
    pub outcome: String,
    pub changed_attributes: Vec<String>,
    pub detail: Option<String>,
}

/// An undo run and a page of its items.
#[derive(Debug, Serialize, ToSchema)]
pub struct UndoRunView {
    pub id: Uuid,
    /// `planned`, `running`, `done` or `failed`.
    pub status: String,
    pub agent_session_ids: Vec<Uuid>,
    pub requested_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    /// Item counts by outcome, once finished.
    #[schema(value_type = Object)]
    pub summary: Option<Value>,
    pub items: PaginatedResponse<UndoItemView>,
}

#[utoipa::path(
    get,
    path = "/api/v1/ai/agent-sessions/{id}/undo-preview",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The agent session")),
    responses(
        (status = 200, description = "What an undo would do, newest record first; nothing is written", body = PaginatedResponse<UndoStep>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Neither the session's owner nor a supervisor", body = ErrorResponse),
        (status = 404, description = "No such session", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_undo_preview(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(session): Path<Uuid>,
) -> Result<Json<PaginatedResponse<UndoStep>>, AppError> {
    require_session(&state, &ctx, session).await?;
    let changes = collect_session_changes(&state, session).await?;
    let externals = collect_external_effects(&state, session).await?;
    let reader = crate::undo::RecordsReader {
        state: &state,
        ctx: &ctx,
    };
    let steps = plan_undo(&reader, &changes, &externals).await?;
    let total = i64::try_from(steps.len()).map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(steps, total, 1, total.max(1))))
}

#[utoipa::path(
    post,
    path = "/api/v1/ai/agent-sessions/{id}/undo",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The agent session")),
    responses(
        (status = 202, description = "The undo is planned and queued; read its progress at /api/v1/ai/undo-runs/{id}", body = UndoStarted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Neither the session's owner nor a supervisor", body = ErrorResponse),
        (status = 404, description = "No such session", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Ai, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_undo(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(session): Path<Uuid>,
) -> Result<(StatusCode, Json<UndoStarted>), AppError> {
    require_session(&state, &ctx, session).await?;
    let run = crate::undo::start_undo(&state, &ctx, &[session]).await?;
    Ok((StatusCode::ACCEPTED, Json(UndoStarted { undo_run_id: run })))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/agents/{id}/rollback-preview",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The agent (definition or agent object)"), RollbackSince),
    responses(
        (status = 200, description = "The agent's sessions since the time and what undoing them would do; nothing is written", body = RollbackPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Neither an admin nor a supervisor", body = ErrorResponse),
        (status = 422, description = "since is in the future or older than the audit keeps", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_rollback_preview(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(agent): Path<Uuid>,
    Query(query): Query<RollbackSince>,
) -> Result<Json<RollbackPreview>, AppError> {
    if !may_supervise(&ctx) {
        return Err(AppError::Forbidden);
    }
    let audit_days = state.base.config.retention.audit_days;
    check_since(query.since, Utc::now(), audit_days)?;
    let db = &state.base.db;
    let sessions = crate::undo::sessions_of_agent_since(db, agent, query.since).await?;
    let steps = crate::undo::plan_sessions(&state, &ctx, &sessions).await?;
    let total = i64::try_from(steps.len()).map_err(AppError::internal)?;
    Ok(Json(RollbackPreview {
        session_ids: sessions,
        steps: PaginatedResponse::new(steps, total, 1, total.max(1)),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/ai/agents/{id}/rollback",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The agent (definition or agent object)")),
    request_body = RollbackSince,
    responses(
        (status = 202, description = "The agent's live sessions are revoked and the rollback is planned and queued; read its progress at /api/v1/ai/undo-runs/{id}", body = UndoStarted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Neither an admin nor a supervisor", body = ErrorResponse),
        (status = 422, description = "since is in the future or older than the audit keeps, or the agent has no session since then", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Ai, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_rollback(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(agent): Path<Uuid>,
    Json(body): Json<RollbackSince>,
) -> Result<(StatusCode, Json<UndoStarted>), AppError> {
    if !may_supervise(&ctx) {
        return Err(AppError::Forbidden);
    }
    let audit_days = state.base.config.retention.audit_days;
    check_since(body.since, Utc::now(), audit_days)?;
    let run = crate::undo::start_rollback_since(&state, &ctx, agent, body.since).await?;
    Ok((StatusCode::ACCEPTED, Json(UndoStarted { undo_run_id: run })))
}

type RunRow = (
    String,
    Vec<Uuid>,
    Uuid,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<Value>,
);

#[utoipa::path(
    get,
    path = "/api/v1/ai/undo-runs/{id}",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The undo run"), OnePageQuery),
    responses(
        (status = 200, description = "The run, its status and counts, and a page of its items in order", body = UndoRunView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Neither the person who asked nor a supervisor", body = ErrorResponse),
        (status = 404, description = "No such run", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_undo_run(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(run): Path<Uuid>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<UndoRunView>, AppError> {
    let db = &state.base.db;
    let row: Option<RunRow> = sqlx::query_as(
        "SELECT status, agent_session_ids, requested_by, created_at, finished_at, summary \
           FROM ai_undo_run WHERE id = $1",
    )
    .bind(run)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (status, sessions, requested_by, created_at, finished_at, summary) =
        row.ok_or(AppError::NotFound)?;
    if !may_undo(&ctx, requested_by) {
        return Err(AppError::Forbidden);
    }
    let window = page.window();
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM ai_undo_item WHERE undo_run_id = $1")
        .bind(run)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    let items: Vec<UndoItemView> = sqlx::query_as(
        "SELECT seq, entity, record_id, operation, outcome, changed_attributes, detail \
           FROM ai_undo_item WHERE undo_run_id = $1 ORDER BY seq LIMIT $2 OFFSET $3",
    )
    .bind(run)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(UndoRunView {
        id: run,
        status,
        agent_session_ids: sessions,
        requested_by,
        created_at,
        finished_at,
        summary,
        items: PaginatedResponse::new(items, total, window.page, window.page_size),
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/ai/agent-sessions/{id}/undo-preview",
            get(get_undo_preview),
        )
        .route("/api/v1/ai/agent-sessions/{id}/undo", post(post_undo))
        .route("/api/v1/ai/undo-runs/{id}", get(get_undo_run))
        .route(
            "/api/v1/admin/ai/agents/{id}/rollback-preview",
            get(get_rollback_preview),
        )
        .route("/api/v1/admin/ai/agents/{id}/rollback", post(post_rollback))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        get_undo_preview,
        post_undo,
        get_undo_run,
        get_rollback_preview,
        post_rollback
    ),
    components(schemas(
        UndoStep,
        UndoStarted,
        UndoItemView,
        UndoRunView,
        RollbackSince,
        RollbackPreview
    ))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(user: Uuid, privileges: &[&str]) -> SecurityContext {
        let mut ctx = attome_records::entity_crud::admin_security_context(user);
        ctx.is_admin = false;
        ctx.privileges = privileges.iter().map(|p| (*p).to_owned()).collect();
        ctx
    }

    #[test]
    fn undo_routes_the_owner_or_a_supervisor_may_undo() {
        let owner = Uuid::now_v7();
        let other = Uuid::now_v7();
        assert!(may_undo(&ctx(owner, &[]), owner));
        assert!(!may_undo(&ctx(other, &[]), owner), "a stranger gets 403");
        assert!(may_undo(&ctx(other, &[AgentSupervise::KEY]), owner));
    }
}
