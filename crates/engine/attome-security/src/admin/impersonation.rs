//! Q13-T1: the impersonation routes (`crate::impersonation` has the rules).
//!
//! - `POST /api/v1/admin/security/impersonation` starts a view-as or act-as
//!   session; `DELETE .../{id}` ends it; `GET` lists the caller's sessions.
//! - `POST /api/v1/me/impersonation-consents` lets the signed-in person allow
//!   one administrator to act as them until a time; `DELETE .../{id}`
//!   withdraws it; `GET` lists them. `GET /api/v1/me/impersonation-sessions`
//!   lists every session about the person.
//!
//! Every write is a security event in its own transaction.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_server::impersonation::{HEADER, ImpersonationMode};
use attome_server::step_up::StepUpCaller;
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::impersonation::{
    MAX_CONSENT_HOURS, check_start, has_live_session, live_consent, session_end,
};

use super::shared::access_tx;

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct StartBody {
    subject_id: Uuid,
    /// `view` (read only) or `act` (needs the person's consent).
    mode: String,
    /// Why, kept with the session.
    reason: String,
}

/// One session.
#[derive(Debug, Serialize, ToSchema)]
pub struct ImpersonationSessionItem {
    id: Uuid,
    actor_id: Uuid,
    subject_id: Uuid,
    /// `view` or `act`.
    mode: String,
    reason: String,
    started_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    /// Send the session id in this header to work in the session.
    header: &'static str,
}

type SessionRow = (
    Uuid,
    Uuid,
    Uuid,
    String,
    String,
    DateTime<Utc>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
);

const SESSION_COLUMNS: &str =
    "id, actor_ref, subject_ref, mode, reason, started_at, expires_at, ended_at";

fn session_item(
    (id, actor_id, subject_id, mode, reason, started_at, expires_at, ended_at): SessionRow,
) -> ImpersonationSessionItem {
    ImpersonationSessionItem {
        id,
        actor_id,
        subject_id,
        mode,
        reason,
        started_at,
        expires_at,
        ended_at,
        header: HEADER,
    }
}

/// Start an impersonation session
///
/// Starts a 30-minute view-as (read only) or act-as session as another person, with a reason and a fresh step-up (`impersonation`). Act-as needs the person's live consent. Never as an administrator or a machine identity, and one live session at a time. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/impersonation",
    operation_id = "start_impersonation",
    tag = "admin-security",
    request_body = StartBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The session", body = ImpersonationSessionItem),
        (status = 401, description = "Missing or invalid credentials, or no fresh step-up", body = ErrorResponse),
        (status = 403, description = "Not an administrator, not a browser session, or the person is an administrator or a machine identity", body = ErrorResponse),
        (status = 409, description = "A session is already live", body = ErrorResponse),
        (status = 422, description = "No reason, an unknown mode, yourself, or act-as without consent", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn start(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    StepUpCaller(caller): StepUpCaller,
    Json(body): Json<StartBody>,
) -> Result<(StatusCode, Json<ImpersonationSessionItem>), AppError> {
    let mode = ImpersonationMode::parse(body.mode.trim())
        .ok_or_else(|| AppError::Validation("mode is view or act".into()))?;
    if !matches!(caller, attome_auth::step_up::Caller::Session(_)) {
        return Err(AppError::Forbidden);
    }
    attome_auth::step_up::require_recent_auth(
        &state.base.db,
        caller,
        ctx.user_id,
        attome_auth::step_up::Operation::Impersonation,
        state.base.config.refresh_absolute_lifetime_secs(),
    )
    .await?;
    let subject = state.base.security.resolve(body.subject_id).await?;
    let consent = match mode {
        ImpersonationMode::Act => {
            live_consent(&state.base.db, body.subject_id, ctx.user_id).await?
        }
        ImpersonationMode::View => None,
    };
    check_start(
        ctx.user_id,
        &subject,
        mode,
        consent,
        &body.reason,
        has_live_session(&state.base.db, ctx.user_id).await?,
    )?;

    let now = Utc::now();
    let mut tx = access_tx(
        &state,
        AuditOperation::Create,
        ctx.user_id,
        "impersonation_session",
        None,
    )
    .await?;
    let row: SessionRow = sqlx::query_as(&format!(
        "INSERT INTO impersonation_session \
             (actor_ref, subject_ref, mode, reason, consent_ref, started_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {SESSION_COLUMNS}"
    ))
    .bind(ctx.user_id)
    .bind(body.subject_id)
    .bind(mode.as_str())
    .bind(body.reason.trim())
    .bind(consent)
    .bind(now)
    .bind(session_end(now))
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.event_mut().set_record_id(row.0);
    tx.event_mut().set_comment(format!(
        "{} as {} for 30 minutes: {}",
        mode.as_str(),
        body.subject_id,
        body.reason.trim()
    ));
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(session_item(row))))
}

/// End an impersonation session
///
/// Ends the caller's own session at once. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/impersonation/{id}",
    operation_id = "end_impersonation",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The session")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Ended"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator", body = ErrorResponse),
        (status = 404, description = "No live session of yours with this id", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn end(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = access_tx(
        &state,
        AuditOperation::Update,
        ctx.user_id,
        "impersonation_session",
        Some(id),
    )
    .await?;
    let ended = sqlx::query(
        "UPDATE impersonation_session SET ended_at = now() \
         WHERE id = $1 AND actor_ref = $2 AND ended_at IS NULL AND expires_at > now()",
    )
    .bind(id)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if ended == 0 {
        return Err(AppError::NotFound);
    }
    tx.event_mut().set_comment("session ended");
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// List my impersonation sessions
///
/// The caller's own sessions, newest first. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/impersonation",
    operation_id = "list_my_impersonation_sessions",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ImpersonationSessionItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_mine(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ImpersonationSessionItem>>, AppError> {
    sessions_page(&state, "actor_ref", ctx.user_id, page).await
}

/// Sessions about me
///
/// Every view-as or act-as session about the signed-in person: who, how, why and when, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/me/impersonation-sessions",
    operation_id = "list_impersonation_sessions_about_me",
    tag = "auth",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ImpersonationSessionItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_about_me(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ImpersonationSessionItem>>, AppError> {
    sessions_page(&state, "subject_ref", ctx.user_id, page).await
}

async fn sessions_page(
    state: &EngineState,
    column: &'static str,
    user_id: Uuid,
    page: OnePageQuery,
) -> Result<Json<PaginatedResponse<ImpersonationSessionItem>>, AppError> {
    let window = page.window();
    // `column` is one of two literals chosen above, never request data.
    let rows: Vec<SessionRow> = sqlx::query_as(&format!(
        "SELECT {SESSION_COLUMNS} FROM impersonation_session WHERE {column} = $1 \
         ORDER BY started_at DESC, id DESC LIMIT $2 OFFSET $3"
    ))
    .bind(user_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM impersonation_session WHERE {column} = $1"
    ))
    .bind(user_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        rows.into_iter().map(session_item).collect(),
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct ConsentBody {
    /// The administrator who may act as you, by id or (below) by email.
    #[serde(default)]
    actor_id: Option<Uuid>,
    /// The administrator's email, when the id is not known.
    #[serde(default)]
    actor_email: Option<String>,
    /// How long, 1 to 72 hours.
    hours: i64,
}

/// One consent.
#[derive(Debug, Serialize, ToSchema)]
pub struct ImpersonationConsentItem {
    id: Uuid,
    actor_id: Uuid,
    granted_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

type ConsentRow = (
    Uuid,
    Uuid,
    DateTime<Utc>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
);

fn consent_item(
    (id, actor_id, granted_at, expires_at, revoked_at): ConsentRow,
) -> ImpersonationConsentItem {
    ImpersonationConsentItem {
        id,
        actor_id,
        granted_at,
        expires_at,
        revoked_at,
    }
}

/// Let an administrator act as me
///
/// Lets one administrator start act-as sessions as the signed-in person until the time given (1 to 72 hours). Withdraw it at any time. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/me/impersonation-consents",
    operation_id = "grant_impersonation_consent",
    tag = "auth",
    request_body = ConsentBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 201, description = "The consent", body = ImpersonationConsentItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "Hours out of range, yourself, or not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn grant_consent(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<ConsentBody>,
) -> Result<(StatusCode, Json<ImpersonationConsentItem>), AppError> {
    if !(1..=MAX_CONSENT_HOURS).contains(&body.hours) {
        return Err(AppError::Validation(format!(
            "hours is 1 to {MAX_CONSENT_HOURS}"
        )));
    }
    let actor_id = match (body.actor_id, body.actor_email.as_deref().map(str::trim)) {
        (Some(id), _) => id,
        (None, Some(email)) if !email.is_empty() => sqlx::query_scalar(
            "SELECT id FROM user_account WHERE lower(email) = lower($1) AND is_active = true",
        )
        .bind(email)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::Validation("no active user has this email".into()))?,
        _ => {
            return Err(AppError::Validation(
                "name the administrator by actor_id or actor_email".into(),
            ));
        }
    };
    if actor_id == ctx.user_id {
        return Err(AppError::Validation(
            "the administrator is someone else".into(),
        ));
    }
    if !state.base.security.resolve(actor_id).await?.is_admin {
        return Err(AppError::Validation(
            "only an administrator can act as you".into(),
        ));
    }
    let now = Utc::now();
    let mut tx = access_tx(
        &state,
        AuditOperation::Grant,
        ctx.user_id,
        "impersonation_consent",
        None,
    )
    .await?;
    let row: ConsentRow = sqlx::query_as(
        "INSERT INTO impersonation_consent (subject_ref, actor_ref, granted_at, expires_at) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id, actor_ref, granted_at, expires_at, revoked_at",
    )
    .bind(ctx.user_id)
    .bind(actor_id)
    .bind(now)
    .bind(now + Duration::hours(body.hours))
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.event_mut().set_record_id(row.0);
    tx.event_mut().set_comment(format!(
        "{} may act as me for {} hours",
        actor_id, body.hours
    ));
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(consent_item(row))))
}

/// Withdraw a consent
///
/// Ends a consent at once; a live act-as session it allowed ends with it. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/me/impersonation-consents/{id}",
    operation_id = "revoke_impersonation_consent",
    tag = "auth",
    params(("id" = Uuid, Path, description = "The consent")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Withdrawn"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No live consent of yours with this id", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn revoke_consent(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = access_tx(
        &state,
        AuditOperation::Revoke,
        ctx.user_id,
        "impersonation_consent",
        Some(id),
    )
    .await?;
    let revoked = sqlx::query(
        "UPDATE impersonation_consent SET revoked_at = now() \
         WHERE id = $1 AND subject_ref = $2 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if revoked == 0 {
        return Err(AppError::NotFound);
    }
    // The act-as sessions it allowed end with it.
    sqlx::query(
        "UPDATE impersonation_session SET ended_at = now() \
         WHERE consent_ref = $1 AND ended_at IS NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// My impersonation consents
///
/// The signed-in person's consents, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/me/impersonation-consents",
    operation_id = "list_impersonation_consents",
    tag = "auth",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ImpersonationConsentItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_consents(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ImpersonationConsentItem>>, AppError> {
    let window = page.window();
    let rows: Vec<ConsentRow> = sqlx::query_as(
        "SELECT id, actor_ref, granted_at, expires_at, revoked_at FROM impersonation_consent \
         WHERE subject_ref = $1 ORDER BY granted_at DESC, id DESC LIMIT $2 OFFSET $3",
    )
    .bind(ctx.user_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM impersonation_consent WHERE subject_ref = $1")
            .bind(ctx.user_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        rows.into_iter().map(consent_item).collect(),
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    start,
    end,
    list_mine,
    list_about_me,
    grant_consent,
    revoke_consent,
    list_consents
))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/impersonation",
            get(list_mine).post(start),
        )
        .route("/api/v1/admin/security/impersonation/{id}", delete(end))
        .route("/api/v1/me/impersonation-sessions", get(list_about_me))
        .route(
            "/api/v1/me/impersonation-consents",
            get(list_consents).post(grant_consent),
        )
        .route(
            "/api/v1/me/impersonation-consents/{id}",
            delete(revoke_consent),
        )
}
