//! Session revocation (Plan 1.6a) and the administrators' session lists
//! (Q8-T5): every live session per person or deployment-wide (narrowed to a
//! role's holders), and ending one session, all of a person's, or all of a
//! role's holders'.

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::ErrorResponse;
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// A role with more holders than this has its sessions ended by a job, a
/// batch of this many people per transaction (Q8-T5).
pub const ROLE_REVOKE_BATCH: i64 = 500;

#[derive(Deserialize, ToSchema)]
pub(super) struct RevokeSessionBody {
    /// The `jti` of the session to kill — from an audit/access log, or the
    /// incident-response tooling that flagged the session as compromised.
    jti: Uuid,
}

/// Revoke a session
///
/// Denylists `jti` for the max access-token TTL from now: any token carrying
/// that `jti` was minted at most that long ago, so it cannot outlive the
/// denylist entry — see `attome_auth::revocation::revoke`'s doc comment.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/sessions/revoke",
    tag = "admin-security",
    request_body = RevokeSessionBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::SessionRevoked)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn revoke_session(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Json(body): Json<RevokeSessionBody>,
) -> Result<StatusCode, AppError> {
    let ttl_secs = state.base.config.access_token_expiry_secs() as i64;
    // BAU-9 / OD-1 (D-625): the coordination pool, alongside the logout write
    // (`crates/server/src/auth/session.rs`) and the authn read
    // (`attome-server::middleware::auth`) — see that write's comment for why the
    // cache role cannot hold a fail-closed revocation record.
    attome_auth::revocation::revoke(
        attome_auth::revocation::RevocationStore::choose(
            &state.base.redis_coordination,
            &state.base.db,
        ),
        body.jti,
        ttl_secs,
    )
    .await?;

    // Audit plan 3.4 (D-541 rule 7). The revocation is a Redis denylist entry,
    // not a database row, so there is no mutation transaction to share: the
    // event is written right after it, and a failed write fails the request
    // rather than leaving an unaudited revocation reported as a success.
    attome_audit::security::SecurityAuditor::from_state(&state)
        .write(
            attome_audit::security::SecurityEvent::new(
                attome_audit::security::MandatoryCategory::Credential,
                AuditOperation::SessionRevoked,
                ctx.user_id,
                "base_session",
                Some(body.jti),
            )
            .named("admin_session_revoke"),
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Q8-T5: one live session in an administrator's list — the person's own
/// session row (Q8-T4) plus whose it is. Never a token, secret or address.
#[derive(Debug, Serialize, ToSchema)]
pub(super) struct AdminSessionItem {
    /// The session's id, for ending it.
    id: Uuid,
    user_id: Uuid,
    user_email: Option<String>,
    /// The browser family, such as `chrome/windows`.
    device_label: Option<String>,
    user_agent: Option<String>,
    /// How the session signed in, such as `password+totp` or `oidc:okta`.
    sign_in_method: Option<String>,
    /// `web`, `mobile` or `agent`.
    client_kind: String,
    created_at: DateTime<Utc>,
    last_activity_at: Option<DateTime<Utc>>,
}

/// Q8-T5: narrows the deployment-wide list to one role's holders, directly
/// or through a team.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(super) struct SessionsFilter {
    /// Only the sessions of people holding this role, directly or through a team.
    role_id: Option<Uuid>,
}

/// The people holding `$1`, directly or through a team.
const ROLE_HOLDERS: &str = "SELECT ur.user_ref FROM user_account_mm_role ur
      WHERE ur.role_ref = $1 AND NOT ur.is_deleted
     UNION
     SELECT ut.user_ref FROM user_account_mm_team ut
       JOIN role_mm_team rt ON rt.team_ref = ut.team_ref AND NOT rt.is_deleted
      WHERE rt.role_ref = $1 AND NOT ut.is_deleted";

type SessionRow = (
    Uuid,
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
);

/// The live sessions of `user` (or everyone), of `role`'s holders (or
/// anyone), most recently active first.
async fn list(
    state: &EngineState,
    user: Option<Uuid>,
    role: Option<Uuid>,
    query: OnePageQuery,
) -> Result<PaginatedResponse<AdminSessionItem>, AppError> {
    let window = query.window();
    let filter = format!(
        "t.revoked_at IS NULL AND t.used_at IS NULL AND t.expires_at > NOW()
           AND ($1::uuid IS NULL OR t.user_ref = $1)
           AND ($2::uuid IS NULL OR t.user_ref IN ({}))",
        ROLE_HOLDERS.replace("$1", "$2")
    );
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM refresh_token t WHERE {filter}"
    ))
    .bind(user)
    .bind(role)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<SessionRow> = sqlx::query_as(&format!(
        "SELECT t.family_id, t.user_ref, u.email, t.device_label, t.user_agent,
                t.sign_in_method, t.client_kind, t.family_started_at, t.last_activity_at
           FROM refresh_token t
           JOIN user_account u ON u.id = t.user_ref
          WHERE {filter}
          ORDER BY COALESCE(t.last_activity_at, t.family_started_at) DESC, t.family_id DESC
          LIMIT $3 OFFSET $4"
    ))
    .bind(user)
    .bind(role)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items = rows
        .into_iter()
        .map(
            |(
                id,
                user_id,
                user_email,
                device_label,
                user_agent,
                sign_in_method,
                client_kind,
                created_at,
                last_activity_at,
            )| AdminSessionItem {
                id,
                user_id,
                user_email,
                device_label,
                user_agent,
                sign_in_method,
                client_kind,
                created_at,
                last_activity_at,
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

async fn user_exists(state: &EngineState, user_id: Uuid) -> Result<(), AppError> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_account WHERE id = $1)")
            .bind(user_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if exists {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// A person's sessions
///
/// Q8-T5: every live session of one person, most recently active first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/users/{id}/sessions",
    operation_id = "admin_list_user_sessions",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The person"), OnePageQuery),
    responses(
        (status = 200, description = "The person's live sessions", body = PaginatedResponse<AdminSessionItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such person", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_user_sessions(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Users>>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<AdminSessionItem>>, AppError> {
    user_exists(&state, user_id).await?;
    Ok(Json(list(&state, Some(user_id), None, query).await?))
}

/// All sessions
///
/// Q8-T5: every live session in the deployment, most recently active first;
/// `role_id` narrows it to that role's holders (directly or through a team).
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/sessions",
    operation_id = "admin_list_sessions",
    tag = "admin-security",
    params(SessionsFilter, OnePageQuery),
    responses(
        (status = 200, description = "Live sessions", body = PaginatedResponse<AdminSessionItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_sessions(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Users>>,
    Query(filter): Query<SessionsFilter>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<AdminSessionItem>>, AppError> {
    Ok(Json(list(&state, None, filter.role_id, query).await?))
}

/// End a session
///
/// Q8-T5: ends one session of anyone's, and forgets the browser if it was
/// remembered in it. It can no longer be refreshed; its access token lapses
/// at its own short expiry (end it at once by `jti` with
/// `POST /api/v1/admin/security/sessions/revoke`, or end every session of the
/// person, which also stops their access tokens).
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/sessions/{id}",
    operation_id = "admin_end_session",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "Session id from a session list")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::SessionRevoked)])))),
    responses(
        (status = 204, description = "Ended"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such live session", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn end_session(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Path(family_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let event = SecurityEvent::new(
        MandatoryCategory::Credential,
        AuditOperation::SessionRevoked,
        ctx.user_id,
        "user_account",
        None,
    )
    .named("admin ended a session");
    let mut tx = SecurityTx::begin(&state, event).await?;
    let Some(owner) = attome_auth::refresh::end_family_in_tx(tx.tx(), family_id).await? else {
        return Err(AppError::NotFound);
    };
    tx.event_mut().set_record_id(owner);
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Ends every session of `users` started before `cutoff` and moves their
/// auth epochs on, so their access tokens stop at once too. People are
/// locked in id order before their token rows (D-509 rule 6). Returns the
/// people whose sessions ended; the caller drops their cached epochs after
/// the commit.
async fn end_sessions_of(
    tx: &mut attome_db::Tx<'_>,
    users: &[Uuid],
    cutoff: DateTime<Utc>,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query("SELECT id FROM user_account WHERE id = ANY($1) ORDER BY id FOR UPDATE")
        .bind(users)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    let ended = attome_auth::refresh::end_families_started_before_in_tx(tx, users, cutoff).await?;
    for user_id in &ended {
        attome_auth::epoch::bump_in_tx(tx, *user_id).await?;
    }
    Ok(ended)
}

async fn drop_cached_epochs(state: &EngineState, users: &[Uuid]) {
    for user_id in users {
        attome_auth::epoch::invalidate_cache(&state.base.redis, *user_id).await;
    }
}

/// How many people's sessions ended, or that a job is ending them.
#[derive(Debug, Serialize, ToSchema)]
pub(super) struct SessionsEnded {
    /// People whose sessions ended in this request.
    ended_users: usize,
    /// The role had more than 500 holders: a job ends their sessions in
    /// batches, and `ended_users` is 0.
    queued: bool,
}

/// End every session of a person
///
/// Q8-T5: ends all of the person's sessions and moves their auth epoch on in
/// one transaction, so their access tokens stop at once as well, and forgets
/// their remembered browsers.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/users/{id}/sessions/revoke-all",
    operation_id = "admin_revoke_user_sessions",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The person")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::SessionRevoked)])))),
    responses(
        (status = 200, description = "The person's sessions ended", body = SessionsEnded),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such person", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn revoke_user_sessions(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<SessionsEnded>, AppError> {
    user_exists(&state, user_id).await?;
    let event = SecurityEvent::new(
        MandatoryCategory::Credential,
        AuditOperation::SessionRevoked,
        ctx.user_id,
        "user_account",
        Some(user_id),
    )
    .named("admin ended every session of a person");
    let mut tx = SecurityTx::begin(&state, event).await?;
    // The epoch moves even with no live session, so a token minted a moment
    // ago stops too; the account row is locked first (D-509 rule 6).
    attome_auth::epoch::bump_in_tx(tx.tx(), user_id).await?;
    attome_auth::refresh::revoke_all_for_user_in_tx(tx.tx(), user_id).await?;
    tx.commit().await?;
    drop_cached_epochs(&state, &[user_id]).await;
    Ok(Json(SessionsEnded {
        ended_users: 1,
        queued: false,
    }))
}

/// End every session of a role's holders
///
/// Q8-T5: ends the sessions of everyone holding the role (directly or
/// through a team) and moves their auth epochs on. Up to 500 holders this
/// happens in the request, in one transaction; beyond that a job ends them
/// in batches of 500, each its own transaction, and only sessions started
/// before this request, so a retried batch never ends a newer sign-in.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/roles/{id}/sessions/revoke-all",
    operation_id = "admin_revoke_role_sessions",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The role")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::SessionRevoked)])))),
    responses(
        (status = 200, description = "The holders' sessions ended, or a job is ending them", body = SessionsEnded),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such role", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn revoke_role_sessions(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Path(role_id): Path<Uuid>,
) -> Result<Json<SessionsEnded>, AppError> {
    let role_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM role WHERE id = $1 AND NOT is_deleted)")
            .bind(role_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if !role_exists {
        return Err(AppError::NotFound);
    }
    let cutoff: DateTime<Utc> = sqlx::query_scalar("SELECT NOW()")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let event = SecurityEvent::new(
        MandatoryCategory::Credential,
        AuditOperation::SessionRevoked,
        ctx.user_id,
        "role",
        Some(role_id),
    )
    .named("admin ended every session of a role's holders");
    let mut tx = SecurityTx::begin(&state, event).await?;
    let holders: Vec<Uuid> = sqlx::query_scalar(&format!(
        "SELECT user_ref FROM ({ROLE_HOLDERS}) h ORDER BY user_ref LIMIT $2"
    ))
    .bind(role_id)
    .bind(ROLE_REVOKE_BATCH + 1)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if holders.len() as i64 > ROLE_REVOKE_BATCH {
        // The job and its event commit together.
        attome_jobs::enqueue_in_tx(tx.tx(), revoke_role_sessions_job_for(role_id, cutoff))
            .await
            .map_err(AppError::internal)?;
        tx.commit().await?;
        return Ok(Json(SessionsEnded {
            ended_users: 0,
            queued: true,
        }));
    }
    let ended = end_sessions_of(tx.tx(), &holders, cutoff).await?;
    tx.commit().await?;
    drop_cached_epochs(&state, &ended).await;
    Ok(Json(SessionsEnded {
        ended_users: ended.len(),
        queued: false,
    }))
}

/// Q8-T5: the job that ends a large role's holders' sessions in batches.
pub const REVOKE_ROLE_SESSIONS: attome_jobs::JobType =
    attome_jobs::JobType::new("revoke_role_sessions", 1);

/// [`REVOKE_ROLE_SESSIONS`]'s payload: the role, and the request's database
/// time, before which a holder's session started to be ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeRoleSessionsPayload {
    pub role_id: Uuid,
    pub cutoff: DateTime<Utc>,
}

fn revoke_role_sessions_job_for(
    role_id: Uuid,
    cutoff: DateTime<Utc>,
) -> attome_core::jobs::EngineJob {
    attome_core::jobs::EngineJob::Registered(attome_jobs::RegisteredJob {
        name: REVOKE_ROLE_SESSIONS.name.to_owned(),
        version: REVOKE_ROLE_SESSIONS.version,
        payload: serde_json::json!(RevokeRoleSessionsPayload { role_id, cutoff }),
        next: None,
    })
}

/// Q8-T5: the [`REVOKE_ROLE_SESSIONS`] job. Ends the sessions `role_id`'s
/// holders started before `cutoff`, 500 people per transaction in id order.
/// Retry-safe: a batch that committed has nothing left before `cutoff`, so a
/// rerun ends nothing twice and never a sign-in made after the request.
/// Returns how many people's sessions ended.
pub async fn revoke_role_sessions_job(
    state: &EngineState,
    role_id: Uuid,
    cutoff: DateTime<Utc>,
) -> Result<usize, AppError> {
    let mut after = Uuid::nil();
    let mut total = 0;
    loop {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let holders: Vec<Uuid> = sqlx::query_scalar(&format!(
            "SELECT user_ref FROM ({ROLE_HOLDERS}) h WHERE user_ref > $2 \
              ORDER BY user_ref LIMIT $3"
        ))
        .bind(role_id)
        .bind(after)
        .bind(ROLE_REVOKE_BATCH)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = holders.last().copied() else {
            tx.rollback().await.map_err(AppError::internal)?;
            return Ok(total);
        };
        let ended = end_sessions_of(&mut tx, &holders, cutoff).await?;
        tx.commit().await.map_err(AppError::internal)?;
        drop_cached_epochs(state, &ended).await;
        total += ended.len();
        tracing::info!(%role_id, batch = holders.len(), ended = ended.len(), "role sessions ended");
        after = last;
    }
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/sessions/revoke",
            post(revoke_session),
        )
        .route("/api/v1/admin/security/sessions", get(list_sessions))
        .route("/api/v1/admin/security/sessions/{id}", delete(end_session))
        .route(
            "/api/v1/admin/security/users/{id}/sessions",
            get(list_user_sessions),
        )
        .route(
            "/api/v1/admin/security/users/{id}/sessions/revoke-all",
            post(revoke_user_sessions),
        )
        .route(
            "/api/v1/admin/security/roles/{id}/sessions/revoke-all",
            post(revoke_role_sessions),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    revoke_session,
    list_sessions,
    list_user_sessions,
    end_session,
    revoke_user_sessions,
    revoke_role_sessions
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
