//! Follow-up routes (roadmap AI4-T6): the caller's open follow-ups, dismissing
//! one, and running one rule's scan now.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::{get, post},
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// One follow-up the caller owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AiFollowupItem {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub entity: String,
    pub record_id: Uuid,
    pub reason: String,
    pub status: String,
    pub window_start: NaiveDate,
    pub created_at: DateTime<Utc>,
    pub row_version: i64,
}

type ItemRow = (
    Uuid,
    Uuid,
    String,
    Uuid,
    String,
    String,
    NaiveDate,
    DateTime<Utc>,
    i64,
);

/// The caller's open follow-ups, newest first.
pub async fn my_followups(
    db: &attome_db::DbPool,
    user: Uuid,
    page: &OnePageQuery,
) -> Result<PaginatedResponse<AiFollowupItem>, AppError> {
    let window = page.window();
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ai_followup_item \
         WHERE owner_user_id = $1 AND status IN ('open', 'reminded', 'drafted')",
    )
    .bind(user)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<ItemRow> = sqlx::query_as(
        "SELECT id, rule_ref, entity_logical_name, record_id, reason, status, window_start, \
                created_at, row_version \
         FROM ai_followup_item \
         WHERE owner_user_id = $1 AND status IN ('open', 'reminded', 'drafted') \
         ORDER BY created_at DESC, id LIMIT $2 OFFSET $3",
    )
    .bind(user)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let items = rows
        .into_iter()
        .map(
            |(
                id,
                rule_id,
                entity,
                record_id,
                reason,
                status,
                window_start,
                created_at,
                row_version,
            )| {
                AiFollowupItem {
                    id,
                    rule_id,
                    entity,
                    record_id,
                    reason,
                    status,
                    window_start,
                    created_at,
                    row_version,
                }
            },
        )
        .collect();
    Ok(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/ai/follow-ups",
    tag = "ai",
    params(OnePageQuery),
    responses(
        (status = 200, description = "The caller's open follow-ups", body = PaginatedResponse<AiFollowupItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_my_followups(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<AiFollowupItem>>, AppError> {
    Ok(Json(
        my_followups(&state.base.db, ctx.user_id, &page).await?,
    ))
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers.get(IF_MATCH).ok_or_else(|| {
        AppError::Validation("If-Match: \"<row_version>\" is required to dismiss".into())
    })?;
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

/// Dismisses one of the caller's follow-ups at the expected version.
pub async fn dismiss(
    state: &EngineState,
    user: Uuid,
    item: Uuid,
    expected: i64,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<(i64, String)> = sqlx::query_as(
        "SELECT row_version, status FROM ai_followup_item \
         WHERE id = $1 AND owner_user_id = $2 FOR UPDATE",
    )
    .bind(item)
    .bind(user)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // Someone else's follow-up is not found, the same as a missing one.
    let Some((version, status)) = row else {
        return Err(AppError::NotFound);
    };
    if version != expected {
        return Err(AppError::VersionConflict);
    }
    if matches!(status.as_str(), "dismissed" | "resolved" | "sent") {
        return Err(AppError::Conflict("the follow-up is already closed"));
    }
    sqlx::query(
        "UPDATE ai_followup_item SET status = 'dismissed', updated_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(item)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "ai_followup_item",
            item,
            AuditOperation::Update,
            "ai.followup_dismissed",
            user,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

#[utoipa::path(
    post,
    path = "/api/v1/ai/follow-ups/{id}/dismiss",
    tag = "ai",
    params(
        ("id" = Uuid, Path, description = "The follow-up"),
        ("If-Match" = String, Header, description = "The follow-up's row_version, quoted"),
    ),
    responses(
        (status = 204, description = "Dismissed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such follow-up of the caller's", body = ErrorResponse),
        (status = 409, description = "Stale row_version, or already closed", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn dismiss_followup(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(item): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let expected = if_match(&headers)?;
    dismiss(&state, ctx.user_id, item, expected).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AiFollowupRunQueued {
    pub rule_id: Uuid,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/ai/follow-up-rules/{id}/run",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The follow-up rule")),
    responses(
        (status = 202, description = "The rule's scan is queued", body = AiFollowupRunQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such active rule", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Execute)])))),
)]
async fn run_followup_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(rule): Path<Uuid>,
) -> Result<(StatusCode, Json<AiFollowupRunQueued>), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM ai_followup_rule WHERE id = $1 AND COALESCE(is_active, true))",
    )
    .bind(rule)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::AiFollowupRuleRun { rule_id: rule },
    )
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Execute,
            ctx.user_id,
            "ai_followup_rule",
            Some(rule),
        )
        .comment("follow-up scan queued by hand".to_owned()),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(AiFollowupRunQueued { rule_id: rule }),
    ))
}

/// Runs one rule's scan (the job behind the run route).
pub async fn run_rule(state: &EngineState, rule_id: Uuid) -> Result<u64, AppError> {
    let rules = crate::followup::active_rules(&state.base.db).await?;
    let Some(rule) = rules.into_iter().find(|r| r.id == rule_id) else {
        return Ok(0);
    };
    crate::followup::detect(state, &rule, Utc::now()).await
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/ai/follow-ups", get(list_my_followups))
        .route("/api/v1/ai/follow-ups/{id}/dismiss", post(dismiss_followup))
        .route(
            "/api/v1/admin/ai/follow-up-rules/{id}/run",
            post(run_followup_rule),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_my_followups, dismiss_followup, run_followup_rule),
    components(schemas(AiFollowupItem, AiFollowupRunQueued))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
