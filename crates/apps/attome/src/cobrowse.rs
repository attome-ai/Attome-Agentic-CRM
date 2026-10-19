//! J9-T2: the co-browse session channel and its audit.
//!
//! An agent opens a session and reads its six-digit code to the customer;
//! the customer's page joins with the code (within [`CODE_MINUTES`]
//! minutes) and gets its own token, kept only as a SHA-256. The two sides
//! then pass frames through the session (`cobrowse_message`: a DOM snapshot
//! or change, a pointer, a note; at most [`MAX_PAYLOAD_BYTES`] each), each
//! reading the other's after the last one it saw. Either side ends it.
//!
//! The session's start, join and end are business events with who, when and
//! the record it is about; the frames themselves are relayed, not audited
//! one by one. A session whose code was never used, or that has been quiet
//! for [`IDLE_HOURS`] hours, refuses frames. The agent side needs a signed-in
//! person and only the session's own agent (or an administrator) may use it;
//! the customer side is public and authenticated by its token alone.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// How long a join code works.
pub const CODE_MINUTES: i64 = 10;
/// A session quiet this long refuses frames.
pub const IDLE_HOURS: i64 = 4;
/// Largest frame.
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
/// Most frames one read returns.
pub const READ_LIMIT: i64 = 200;
/// The frame kinds.
pub const KINDS: &[&str] = &[
    "snapshot", "mutation", "pointer", "scroll", "note", "control",
];

/// A six-digit code from a random value. Pure.
pub fn code_from(random: u128) -> String {
    format!("{:06}", random % 1_000_000)
}

/// A token's stored form. Pure.
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// A frame, checked. Pure.
pub fn check_frame(kind: &str, payload: &Value) -> Result<(), AppError> {
    if !KINDS.contains(&kind) {
        return Err(AppError::Validation(format!(
            "kind is one of {}",
            KINDS.join(", ")
        )));
    }
    if payload.to_string().len() > MAX_PAYLOAD_BYTES {
        return Err(AppError::Validation(format!(
            "a frame is at most {MAX_PAYLOAD_BYTES} bytes"
        )));
    }
    Ok(())
}

async fn audit(
    state: &EngineState,
    tx: &mut attome_db::Tx<'_>,
    session_id: Uuid,
    actor: Uuid,
    event: &str,
    comment: String,
) -> Result<(), AppError> {
    attome_audit::write_business_event_in_tx(
        tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "cobrowse_session",
            session_id,
            AuditOperation::Update,
            event,
            actor,
        )
        .comment(comment),
    )
    .await
}

/// `POST /api/v1/cobrowse/sessions`.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct StartSession {
    /// The record the session is about, if any (a case, a contact).
    #[serde(default)]
    pub regarding_entity: Option<String>,
    #[serde(default)]
    pub regarding_id: Option<Uuid>,
}

/// A started session.
#[derive(Debug, Serialize, ToSchema)]
pub struct SessionStarted {
    pub id: Uuid,
    /// Read this to the customer; it works once, for ten minutes.
    pub code: String,
    pub expires_at: DateTime<Utc>,
}

/// Starts a co-browse session (J9-T2).
#[utoipa::path(
    post,
    path = "/api/v1/cobrowse/sessions",
    tag = "omnichannel",
    request_body = StartSession,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 201, description = "The session and its join code", body = SessionStarted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn start(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<StartSession>,
) -> Result<(StatusCode, Json<SessionStarted>), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let id = Uuid::now_v7();
    let mut code = String::new();
    // A code is unique among sessions still waiting to be joined.
    for _ in 0..8 {
        let candidate = code_from(Uuid::new_v4().as_u128());
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM cobrowse_session \
              WHERE code = $1 AND status = 'waiting' \
                AND created_at > NOW() - make_interval(mins => $2))",
        )
        .bind(&candidate)
        .bind(i32::try_from(CODE_MINUTES).unwrap_or(10))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if !taken {
            code = candidate;
            break;
        }
    }
    if code.is_empty() {
        return Err(AppError::Conflict("no join code is free; try again"));
    }
    let created_at: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO cobrowse_session (id, code, agent_id, status, regarding_entity, regarding_id) \
         VALUES ($1, $2, $3, 'waiting', $4, $5) RETURNING created_at",
    )
    .bind(id)
    .bind(&code)
    .bind(ctx.user_id)
    .bind(&body.regarding_entity)
    .bind(body.regarding_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let about = match (&body.regarding_entity, body.regarding_id) {
        (Some(entity), Some(record)) => format!("about {entity} {record}"),
        _ => "about no record".to_owned(),
    };
    audit(&state, &mut tx, id, ctx.user_id, "cobrowse.start", about).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok((
        StatusCode::CREATED,
        Json(SessionStarted {
            id,
            code,
            expires_at: created_at + chrono::Duration::minutes(CODE_MINUTES),
        }),
    ))
}

/// `POST /api/v1/cobrowse/join`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct JoinSession {
    pub code: String,
}

/// The customer's side of a joined session.
#[derive(Debug, Serialize, ToSchema)]
pub struct SessionJoined {
    pub session_id: Uuid,
    /// The customer side's token for its frames.
    pub token: String,
}

/// Joins a co-browse session with its code (J9-T2).
///
/// The code works once, for ten minutes; any other code answers 404.
#[utoipa::path(
    post,
    path = "/api/v1/cobrowse/join",
    tag = "omnichannel",
    request_body = JoinSession,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Joined", body = SessionJoined),
        (status = 404, description = "No session waits for this code", body = ErrorResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
)]
async fn join(
    State(state): State<EngineState>,
    Json(body): Json<JoinSession>,
) -> Result<Json<SessionJoined>, AppError> {
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let joined: Option<(Uuid, Uuid)> = sqlx::query_as(
        "UPDATE cobrowse_session SET status = 'active', joined_at = NOW(), \
                customer_token_hash = $2, last_activity_at = NOW() \
          WHERE id = (SELECT id FROM cobrowse_session \
                       WHERE code = $1 AND status = 'waiting' \
                         AND created_at > NOW() - make_interval(mins => $3) \
                       ORDER BY created_at DESC LIMIT 1 FOR UPDATE) \
          RETURNING id, agent_id",
    )
    .bind(body.code.trim())
    .bind(token_hash(&token))
    .bind(i32::try_from(CODE_MINUTES).unwrap_or(10))
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (session_id, agent_id) = joined.ok_or(AppError::NotFound)?;
    audit(
        &state,
        &mut tx,
        session_id,
        agent_id,
        "cobrowse.join",
        "the customer joined".to_owned(),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(SessionJoined { session_id, token }))
}

/// One frame.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SendFrame {
    pub kind: String,
    #[schema(value_type = Object)]
    pub payload: Value,
}

/// A customer frame, with the side's token.
#[derive(Debug, Deserialize, ToSchema)]
pub struct VisitorFrame {
    pub token: String,
    pub kind: String,
    #[schema(value_type = Object)]
    pub payload: Value,
}

/// A frame as read back.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct Frame {
    pub id: Uuid,
    /// `agent` or `customer`.
    pub sender: String,
    pub kind: String,
    #[schema(value_type = Object)]
    pub payload: Value,
    pub created_at: DateTime<Utc>,
}

/// `?after=` (and the customer's `token=`).
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ReadQuery {
    /// Only frames after this one.
    pub after: Option<Uuid>,
    /// The customer side's token (customer reads only).
    pub token: Option<String>,
}

/// The session an agent may use: its own, or any for an administrator.
async fn agent_session(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<String, AppError> {
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT agent_id, status FROM cobrowse_session WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    match row {
        Some((agent, status)) if agent == ctx.user_id || ctx.is_admin => Ok(status),
        _ => Err(AppError::NotFound),
    }
}

/// The session a customer token belongs to, if it is still open.
async fn visitor_session(state: &EngineState, token: &str) -> Result<Uuid, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM cobrowse_session \
          WHERE customer_token_hash = $1 AND status = 'active'",
    )
    .bind(token_hash(token.trim()))
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

async fn append(
    state: &EngineState,
    session_id: Uuid,
    sender: &str,
    kind: &str,
    payload: &Value,
) -> Result<(), AppError> {
    check_frame(kind, payload)?;
    let updated = sqlx::query(
        "UPDATE cobrowse_session SET last_activity_at = NOW() \
          WHERE id = $1 AND status = 'active' \
            AND last_activity_at > NOW() - make_interval(hours => $2)",
    )
    .bind(session_id)
    .bind(i32::try_from(IDLE_HOURS).unwrap_or(4))
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::Conflict("the session is not active"));
    }
    sqlx::query(
        "INSERT INTO cobrowse_message (session_id, sender, kind, payload) VALUES ($1, $2, $3, $4)",
    )
    .bind(session_id)
    .bind(sender)
    .bind(kind)
    .bind(payload)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn read(
    state: &EngineState,
    session_id: Uuid,
    other: &str,
    after: Option<Uuid>,
) -> Result<Vec<Frame>, AppError> {
    sqlx::query_as(
        "SELECT id, sender, kind, payload, created_at FROM cobrowse_message \
          WHERE session_id = $1 AND sender = $2 AND ($3::uuid IS NULL OR id > $3) \
          ORDER BY id LIMIT $4",
    )
    .bind(session_id)
    .bind(other)
    .bind(after)
    .bind(READ_LIMIT)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Sends an agent frame (J9-T2).
#[utoipa::path(
    post,
    path = "/api/v1/cobrowse/sessions/{id}/messages",
    tag = "omnichannel",
    params(("id" = Uuid, Path)),
    request_body = SendFrame,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Telemetry,
        None,
        "relays co-browse frames; the session's start, join and end are audited"
    )))),
    responses(
        (status = 204, description = "Sent"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such session of yours", body = ErrorResponse),
        (status = 409, description = "The session is not active", body = ErrorResponse),
        (status = 422, description = "An unknown kind or a frame over 256 KB", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn agent_send(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<SendFrame>,
) -> Result<StatusCode, AppError> {
    agent_session(&state, &ctx, id).await?;
    append(&state, id, "agent", &body.kind, &body.payload).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The customer's frames after `after` (J9-T2).
#[utoipa::path(
    get,
    path = "/api/v1/cobrowse/sessions/{id}/messages",
    tag = "omnichannel",
    params(("id" = Uuid, Path), ReadQuery),
    responses(
        (status = 200, description = "The customer's frames, oldest first", body = Vec<Frame>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such session of yours", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn agent_read(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Query(query): Query<ReadQuery>,
) -> Result<Json<Vec<Frame>>, AppError> {
    agent_session(&state, &ctx, id).await?;
    Ok(Json(read(&state, id, "customer", query.after).await?))
}

async fn end_session(state: &EngineState, id: Uuid, actor: Uuid, by: &str) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let ended = sqlx::query(
        "UPDATE cobrowse_session SET status = 'ended', ended_at = NOW(), ended_by = $2 \
          WHERE id = $1 AND status <> 'ended'",
    )
    .bind(id)
    .bind(by)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if ended.rows_affected() == 0 {
        return Ok(());
    }
    audit(
        state,
        &mut tx,
        id,
        actor,
        "cobrowse.end",
        format!("ended by the {by}"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)
}

/// Ends a session from the agent's side (J9-T2).
#[utoipa::path(
    post,
    path = "/api/v1/cobrowse/sessions/{id}/end",
    tag = "omnichannel",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Ended (or already ended)"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such session of yours", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn agent_end(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    agent_session(&state, &ctx, id).await?;
    end_session(&state, id, ctx.user_id, "agent").await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Sends a customer frame (J9-T2).
#[utoipa::path(
    post,
    path = "/api/v1/cobrowse/visitor/messages",
    tag = "omnichannel",
    request_body = VisitorFrame,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Telemetry,
        None,
        "relays co-browse frames; the session's start, join and end are audited"
    )))),
    responses(
        (status = 204, description = "Sent"),
        (status = 404, description = "The token names no open session", body = ErrorResponse),
        (status = 409, description = "The session is not active", body = ErrorResponse),
        (status = 422, description = "An unknown kind or a frame over 256 KB", body = ErrorResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
)]
async fn visitor_send(
    State(state): State<EngineState>,
    Json(body): Json<VisitorFrame>,
) -> Result<StatusCode, AppError> {
    let id = visitor_session(&state, &body.token).await?;
    append(&state, id, "customer", &body.kind, &body.payload).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The agent's frames after `after`, for the customer (J9-T2).
#[utoipa::path(
    get,
    path = "/api/v1/cobrowse/visitor/messages",
    tag = "omnichannel",
    params(ReadQuery),
    responses(
        (status = 200, description = "The agent's frames, oldest first", body = Vec<Frame>),
        (status = 404, description = "The token names no open session", body = ErrorResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
)]
async fn visitor_read(
    State(state): State<EngineState>,
    Query(query): Query<ReadQuery>,
) -> Result<Json<Vec<Frame>>, AppError> {
    let token = query.token.as_deref().ok_or(AppError::NotFound)?;
    let id = visitor_session(&state, token).await?;
    Ok(Json(read(&state, id, "agent", query.after).await?))
}

/// `POST /api/v1/cobrowse/visitor/end`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct VisitorEnd {
    pub token: String,
}

/// Ends a session from the customer's side (J9-T2).
#[utoipa::path(
    post,
    path = "/api/v1/cobrowse/visitor/end",
    tag = "omnichannel",
    request_body = VisitorEnd,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Ended"),
        (status = 404, description = "The token names no open session", body = ErrorResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
)]
async fn visitor_end(
    State(state): State<EngineState>,
    Json(body): Json<VisitorEnd>,
) -> Result<StatusCode, AppError> {
    let id = visitor_session(&state, &body.token).await?;
    let agent: Uuid = sqlx::query_scalar("SELECT agent_id FROM cobrowse_session WHERE id = $1")
        .bind(id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    end_session(&state, id, agent, "customer").await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/cobrowse/sessions", post(start))
        .route(
            "/api/v1/cobrowse/sessions/{id}/messages",
            get(agent_read).post(agent_send),
        )
        .route("/api/v1/cobrowse/sessions/{id}/end", post(agent_end))
        .route("/api/v1/cobrowse/join", post(join))
        .route(
            "/api/v1/cobrowse/visitor/messages",
            get(visitor_read).post(visitor_send),
        )
        .route("/api/v1/cobrowse/visitor/end", post(visitor_end))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    start,
    join,
    agent_send,
    agent_read,
    agent_end,
    visitor_send,
    visitor_read,
    visitor_end
))]
struct ApiDocFragment;

pub fn openapi() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod cobrowse {
    use super::*;
    use serde_json::json;

    #[test]
    fn cobrowse_codes_are_six_digits() {
        assert_eq!(code_from(42), "000042");
        assert_eq!(code_from(1_234_567), "234567");
        assert_eq!(code_from(u128::MAX).len(), 6);
    }

    #[test]
    fn cobrowse_frames_are_checked() {
        assert!(check_frame("snapshot", &json!({"html": "<p>hi</p>"})).is_ok());
        assert!(check_frame("keylogger", &json!({})).is_err());
        let big = json!({"html": "x".repeat(MAX_PAYLOAD_BYTES)});
        assert!(check_frame("snapshot", &big).is_err());
    }

    #[test]
    fn cobrowse_tokens_are_kept_only_as_hashes() {
        assert_eq!(token_hash("abc").len(), 64);
        assert_ne!(token_hash("abc"), token_hash("abd"));
    }
}
