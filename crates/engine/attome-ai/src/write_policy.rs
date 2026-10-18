//! Per-write approval policies (roadmap N30-T3..T5): an administrator can
//! require that an agent's write of one action (optionally on one entity)
//! waits for a second person, even when the action is only `Reversible`.
//!
//! **Off by default.** With no active policy nothing changes: an agent's
//! reversible write runs once the person it acts for confirms it. With a
//! matching policy, that confirmation submits the write for four-eyes
//! approval instead (`execute::dispatch_confirmed_agent_action`), through the
//! same `attome_approval` request a consequential action raises, so the same
//! rules hold: the person the agent acts for cannot approve it, the request
//! expires, and an approved write is re-checked against its record
//! (N30-T2) before it runs.
//!
//! A policy table that cannot be read refuses the write (fails closed).

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// The most policies one listing returns.
const MAX_POLICIES: i64 = 500;

/// Whether an active policy makes this agent write wait for approval: one
/// naming the action with no entity, or naming the action and the entity
/// the arguments name.
pub async fn requires_approval(
    db: &DbPool,
    action_id: &str,
    args: &Value,
) -> Result<bool, AppError> {
    let entity = args.get("entity").and_then(Value::as_str).map(str::trim);
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM ai_write_approval_policy \
         WHERE is_active AND action_id = $1 AND (entity IS NULL OR entity = $2))",
    )
    .bind(action_id)
    .bind(entity)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct WritePolicy {
    pub id: Uuid,
    pub action_id: String,
    /// `null`: every entity.
    pub entity: Option<String>,
    pub reason: Option<String>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewWritePolicy {
    /// A write action id, such as `record.update`.
    pub action_id: String,
    /// One entity's logical name; omit for every entity.
    #[serde(default)]
    pub entity: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// `GET /api/v1/admin/ai/write-policies` — the active policies.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/write-policies",
    operation_id = "list_write_policies",
    tag = "action",
    responses(
        (status = 200, description = "Active per-write approval policies", body = PaginatedResponse<WritePolicy>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_policies(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<PaginatedResponse<WritePolicy>>, AppError> {
    let items: Vec<WritePolicy> = sqlx::query_as(
        "SELECT id, action_id, entity, reason, created_by, created_at \
         FROM ai_write_approval_policy WHERE is_active \
         ORDER BY action_id, entity NULLS FIRST LIMIT $1",
    )
    .bind(MAX_POLICIES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: 1,
        page_size: MAX_POLICIES,
        warnings: Vec::new(),
    }))
}

/// `POST /api/v1/admin/ai/write-policies` — requires approval for an action.
#[utoipa::path(
    post,
    path = "/api/v1/admin/ai/write-policies",
    operation_id = "create_write_policy",
    tag = "action",
    request_body = NewWritePolicy,
    responses(
        (status = 201, description = "The policy is active", body = WritePolicy),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 422, description = "Not a known write action, or text too long", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
)]
async fn create_policy(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<NewWritePolicy>,
) -> Result<(StatusCode, Json<WritePolicy>), AppError> {
    let action_id = body.action_id.trim().to_owned();
    let is_write = crate::engine::REGISTRY
        .all()
        .any(|d| d.id.as_str() == action_id && d.effect == crate::descriptor::Effect::Write);
    if !is_write {
        return Err(AppError::Validation(format!(
            "{action_id} is not a write action"
        )));
    }
    let entity = body
        .entity
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(str::to_owned);
    if entity.as_ref().is_some_and(|e| e.chars().count() > 100)
        || body
            .reason
            .as_ref()
            .is_some_and(|r| r.chars().count() > 500)
    {
        return Err(AppError::Validation(
            "entity is at most 100 characters and reason at most 500".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let policy: WritePolicy = sqlx::query_as(
        "INSERT INTO ai_write_approval_policy (action_id, entity, reason, created_by) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id, action_id, entity, reason, created_by, created_at",
    )
    .bind(&action_id)
    .bind(&entity)
    .bind(&body.reason)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "ai_write_approval_policy",
            Some(policy.id),
        )
        .named("ai.write_policy.create")
        .comment(format!(
            "agent writes of {action_id} on {} now need approval",
            entity.as_deref().unwrap_or("any entity")
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(policy)))
}

/// `DELETE /api/v1/admin/ai/write-policies/{id}` — deactivates a policy.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/ai/write-policies/{id}",
    tag = "action",
    params(("id" = Uuid, Path, description = "The policy")),
    responses(
        (status = 204, description = "Deactivated"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No active policy with this id", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn deactivate_policy(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let done = sqlx::query(
        "UPDATE ai_write_approval_policy \
         SET is_active = false, deactivated_by = $2, deactivated_at = now() \
         WHERE id = $1 AND is_active",
    )
    .bind(id)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "ai_write_approval_policy",
            Some(id),
        )
        .named("ai.write_policy.deactivate"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/ai/write-policies",
            get(list_policies).post(create_policy),
        )
        .route(
            "/api/v1/admin/ai/write-policies/{id}",
            delete(deactivate_policy),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_policies, create_policy, deactivate_policy),
    components(schemas(WritePolicy, NewWritePolicy))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
