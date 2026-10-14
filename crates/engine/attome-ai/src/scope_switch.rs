//! Scoped AI switches (roadmap N31-T1): turn one agent, model, provider,
//! tool or channel off without touching the rest, by hand or automatically.
//!
//! The deployment-wide switch (`runtime_switch`) turns whole surfaces off;
//! this one is finer. A scope is `(kind, key)`: `("tool", "record.delete")`,
//! `("agent", "<agent object id>")`, `("model", "<model id>")`, ...
//!
//! - **Off is easy, on takes two people.** Any administrator turns a scope
//!   off; turning it back on must be done by a different administrator from
//!   the one (or the automatic trip) that turned it off, recorded with who
//!   and why.
//! - **Automatic trips** ([`trip`]) record their cause (`budget`, `quality`,
//!   `injection`, `departure`) and, like any off, need an administrator to
//!   turn the scope back on.
//! - **Fails closed.** [`dispatch`](crate::execute::dispatch) checks the tool
//!   and the agent of every call against a snapshot at most [`STALE_AFTER`]
//!   old; when the snapshot cannot be read, AI actions are refused rather
//!   than run unchecked.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, put},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

/// How old a snapshot may be before the next check reads the table again.
pub const STALE_AFTER: Duration = Duration::from_secs(5);
/// The scope kinds.
pub const KINDS: [&str; 5] = ["agent", "model", "provider", "tool", "channel"];
/// The causes an off records.
pub const CAUSES: [&str; 5] = ["manual", "budget", "quality", "injection", "departure"];
const MAX_REASON_CHARS: usize = 500;

/// The scopes that are off, and when that was read.
static SNAPSHOT: Mutex<Option<(Instant, HashSet<(String, String)>)>> = Mutex::new(None);

async fn read_off(db: &PgPool) -> Result<HashSet<(String, String)>, AppError> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT scope_kind, scope_key FROM ai_scope_switch WHERE NOT enabled")
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
    Ok(rows.into_iter().collect())
}

/// The off scopes, from a fresh-enough snapshot or the table. `Err` when
/// neither is available: the caller refuses (fails closed).
async fn off_scopes(db: &PgPool) -> Result<HashSet<(String, String)>, AppError> {
    let cached = SNAPSHOT
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .filter(|(read_at, _)| read_at.elapsed() < STALE_AFTER)
        .map(|(_, off)| off);
    if let Some(off) = cached {
        return Ok(off);
    }
    match read_off(db).await {
        Ok(off) => {
            if let Ok(mut guard) = SNAPSHOT.lock() {
                *guard = Some((Instant::now(), off.clone()));
            }
            Ok(off)
        }
        Err(error) => {
            tracing::error!(%error, "AI scope switches unreadable; refusing AI actions");
            Err(AppError::CapabilityUnavailable("ai_scope_switch"))
        }
    }
}

fn forget_snapshot() {
    if let Ok(mut guard) = SNAPSHOT.lock() {
        *guard = None;
    }
}

/// Refuses a call whose tool or agent is switched off (`NotFound`, the same
/// answer as an unavailable action, so the switch does not announce itself to
/// a model).
pub async fn check(
    db: &PgPool,
    action_id: &str,
    agent_session: Option<Uuid>,
) -> Result<(), AppError> {
    let off = off_scopes(db).await?;
    if off.is_empty() {
        return Ok(());
    }
    if off.contains(&("tool".to_owned(), action_id.to_owned())) {
        return Err(AppError::NotFound);
    }
    let agents_off = off.iter().any(|(kind, _)| kind == "agent");
    if let (true, Some(session)) = (agents_off, agent_session) {
        let agent: Option<Option<Uuid>> =
            sqlx::query_scalar("SELECT agent_object_ref FROM agent_session WHERE id = $1")
                .bind(session)
                .fetch_optional(db)
                .await
                .map_err(AppError::internal)?;
        if let Some(Some(agent)) = agent
            && off.contains(&("agent".to_owned(), agent.to_string()))
        {
            return Err(AppError::Validation("this agent is switched off".into()));
        }
    }
    Ok(())
}

fn validate(kind: &str, key: &str, reason: Option<&str>) -> Result<(), AppError> {
    if !KINDS.contains(&kind) {
        return Err(AppError::Validation(format!(
            "a scope is one of {}",
            KINDS.join(", ")
        )));
    }
    if key.trim().is_empty() || key.len() > 200 {
        return Err(AppError::Validation(
            "a scope key is 1 to 200 characters".into(),
        ));
    }
    if reason.is_some_and(|r| r.chars().count() > MAX_REASON_CHARS) {
        return Err(AppError::Validation(format!(
            "reason is longer than {MAX_REASON_CHARS} characters"
        )));
    }
    Ok(())
}

/// Sets a scope on or off, audited in the same transaction. Turning a scope
/// on is refused for the actor who turned it off.
async fn set(
    state: &EngineState,
    kind: &str,
    key: &str,
    enabled: bool,
    cause: &str,
    reason: Option<&str>,
    actor: Option<Uuid>,
) -> Result<(), AppError> {
    let reason = reason.map(str::trim).filter(|r| !r.is_empty());
    validate(kind, key, reason)?;
    let event = attome_audit::security::SecurityEvent::new(
        attome_audit::security::MandatoryCategory::Configuration,
        attome_audit::AuditOperation::Update,
        actor.unwrap_or(Uuid::nil()),
        "ai_scope_switch",
        None,
    )
    .named("ai.scope_switch")
    .comment(format!(
        "{kind} {key} {} ({cause}){}",
        if enabled { "on" } else { "off" },
        reason.map(|r| format!(": {r}")).unwrap_or_default()
    ));
    let mut stx = attome_audit::security::SecurityTx::begin(state, event).await?;
    if enabled {
        let turned_off_by: Option<Option<Uuid>> = sqlx::query_scalar(
            "SELECT changed_by FROM ai_scope_switch \
             WHERE scope_kind = $1 AND scope_key = $2 AND NOT enabled FOR UPDATE",
        )
        .bind(kind)
        .bind(key)
        .fetch_optional(&mut *stx)
        .await
        .map_err(AppError::internal)?;
        if let Some(by) = turned_off_by
            && by.is_some()
            && by == actor
        {
            return Err(AppError::Conflict(
                "a different administrator must turn this back on",
            ));
        }
    }
    sqlx::query(
        "INSERT INTO ai_scope_switch (scope_kind, scope_key, enabled, cause, reason, changed_by) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (scope_kind, scope_key) DO UPDATE \
            SET enabled = EXCLUDED.enabled, cause = EXCLUDED.cause, reason = EXCLUDED.reason, \
                changed_by = EXCLUDED.changed_by, changed_at = NOW()",
    )
    .bind(kind)
    .bind(key)
    .bind(enabled)
    .bind(cause)
    .bind(reason)
    .bind(actor)
    .execute(&mut *stx)
    .await
    .map_err(AppError::internal)?;
    stx.commit().await?;
    forget_snapshot();
    Ok(())
}

/// Switches a scope off automatically, recording `cause` (N31-T1). An
/// administrator turns it back on.
pub async fn trip(
    state: &EngineState,
    kind: &str,
    key: &str,
    cause: &str,
    reason: &str,
) -> Result<(), AppError> {
    if !CAUSES.contains(&cause) || cause == "manual" {
        return Err(AppError::internal(format!("unknown trip cause {cause}")));
    }
    tracing::warn!(kind, key, cause, reason, "AI scope tripped off");
    set(state, kind, key, false, cause, Some(reason), None).await
}

/// One scope's state.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct ScopeSwitchView {
    pub scope_kind: String,
    pub scope_key: String,
    pub enabled: bool,
    /// `manual` | `budget` | `quality` | `injection` | `departure`.
    pub cause: String,
    pub reason: Option<String>,
    /// `null` for an automatic trip.
    pub changed_by: Option<Uuid>,
    pub changed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ScopeSwitchRequest {
    pub enabled: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

/// `GET /api/v1/admin/ai/switches` — every scope that has been switched.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/switches",
    tag = "action",
    responses(
        (status = 200, description = "Every switched scope", body = PaginatedResponse<ScopeSwitchView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_switches(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<PaginatedResponse<ScopeSwitchView>>, AppError> {
    let items: Vec<ScopeSwitchView> = sqlx::query_as(
        "SELECT scope_kind, scope_key, enabled, cause, reason, changed_by, changed_at \
         FROM ai_scope_switch ORDER BY enabled, changed_at DESC LIMIT 1000",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: 1,
        page_size: 1000,
    }))
}

/// `PUT /api/v1/admin/ai/switches/{kind}/{key}` — turns one scope off, or
/// back on (by a different administrator from the one who turned it off).
#[utoipa::path(
    put,
    path = "/api/v1/admin/ai/switches/{kind}/{key}",
    tag = "action",
    params(
        ("kind" = String, Path, description = "agent | model | provider | tool | channel"),
        ("key" = String, Path, description = "The scope's key: an id or a tool name"),
    ),
    request_body = ScopeSwitchRequest,
    responses(
        (status = 204, description = "Switched"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 409, description = "The administrator who turned it off cannot turn it on", body = ErrorResponse),
        (status = 422, description = "Unknown kind, empty key or reason too long", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
)]
async fn put_switch(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((kind, key)): Path<(String, String)>,
    Json(body): Json<ScopeSwitchRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    set(
        &state,
        &kind,
        &key,
        body.enabled,
        "manual",
        body.reason.as_deref(),
        Some(ctx.user_id),
    )
    .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/ai/switches", get(list_switches))
        .route("/api/v1/admin/ai/switches/{kind}/{key}", put(put_switch))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_switches, put_switch),
    components(schemas(ScopeSwitchView, ScopeSwitchRequest))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_validated() {
        assert!(validate("tool", "record.delete", None).is_ok());
        assert!(validate("planet", "x", None).is_err());
        assert!(validate("agent", " ", None).is_err());
        assert!(validate("agent", "a", Some(&"x".repeat(501))).is_err());
    }
}
