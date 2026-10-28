use crate::NotificationInbox;
use attome_auth::SessionClaims;
use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{
    Json, Router,
    extract::{Extension, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

const POLL_LIMIT: i64 = 50;

#[derive(Serialize, ToSchema)]
struct NotifOut {
    id: Uuid,
    title: String,
    message: String,
    #[serde(rename = "type")]
    kind: i32,
    #[serde(rename = "isRead")]
    is_read: bool,
    timestamp: i64,
    route: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct PollResponse {
    notifications: Vec<NotifOut>,
    unread_count: i64,
}

#[derive(Deserialize, ToSchema)]
struct ReadRequest {
    id: Uuid,
}

/// Read my notifications
///
/// The signed-in person's latest in-app notifications and how many are unread.
#[utoipa::path(
    post,
    path = "/api/v1/notification/poll",
    tag = "notification",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "reads and returns the caller's own inbox rows; persists nothing",
    )))),
    responses(
        (status = 200, description = "Success", body = PollResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn poll(
    State(state): State<EngineState>,
    Extension(claims): Extension<SessionClaims>,
    // Authenticated-only by design: acts solely on the caller's own
    // `claims.sub`. Declared so the route's posture is explicit, and so the
    // extractor still proves the request passed through `authz`.
    _ctx: Authorized<SelfService>,
) -> Result<Json<PollResponse>, AppError> {
    let inbox = NotificationInbox::new(&state.base.db);
    let (rows, unread_count) = inbox.poll(claims.sub, POLL_LIMIT).await?;

    let notifications = rows
        .into_iter()
        .map(|n| NotifOut {
            id: n.id,
            title: n.title.unwrap_or_default(),
            message: n.message.unwrap_or_default(),
            kind: n.notif_type.unwrap_or(0),
            is_read: n.is_read.unwrap_or(false),
            timestamp: n.created_on.map(|t| t.and_utc().timestamp()).unwrap_or(0),
            route: n.route,
        })
        .collect();

    Ok(Json(PollResponse {
        notifications,
        unread_count,
    }))
}

/// Mark a notification read
///
/// Marks one of the caller's notifications read.
#[utoipa::path(
    post,
    path = "/api/v1/notification/read",
    tag = "notification",
    request_body = ReadRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::UserPreference,
        None,
        "marks one of the caller's own bell notifications read; no security, sharing or business effect",
    )))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn mark_read(
    State(state): State<EngineState>,
    Extension(claims): Extension<SessionClaims>,
    // Authenticated-only by design: acts solely on the caller's own
    // `claims.sub`. Declared so the route's posture is explicit, and so the
    // extractor still proves the request passed through `authz`.
    _ctx: Authorized<SelfService>,
    Json(body): Json<ReadRequest>,
) -> Result<(), AppError> {
    let inbox = NotificationInbox::new(&state.base.db);
    inbox.mark_read(claims.sub, body.id).await
}

/// Clear my notifications
///
/// Clears the caller's in-app notifications.
#[utoipa::path(
    post,
    path = "/api/v1/notification/clear",
    tag = "notification",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::UserPreference,
        None,
        "clears the caller's own bell notification inbox; no security, sharing or business effect",
    )))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn clear(
    State(state): State<EngineState>,
    Extension(claims): Extension<SessionClaims>,
    // Authenticated-only by design: acts solely on the caller's own
    // `claims.sub`. Declared so the route's posture is explicit, and so the
    // extractor still proves the request passed through `authz`.
    _ctx: Authorized<SelfService>,
) -> Result<(), AppError> {
    let inbox = NotificationInbox::new(&state.base.db);
    inbox.clear(claims.sub).await
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/notification/poll", post(poll))
        .route("/api/v1/notification/read", post(mark_read))
        .route("/api/v1/notification/clear", post(clear))
        // U5 (D-602): the caller's own notification preferences, always on
        // like the bell itself — they shape every dispatch, licensed or not.
        .merge(crate::preferences::routes())
        // J12-T1: the caller's own push addresses.
        .merge(crate::push::routes())
        // J1-T1: the caller's own email signature.
        .merge(crate::signature::routes())
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(poll, mark_read, clear))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    let mut doc = <ApiDocFragment as utoipa::OpenApi>::openapi();
    doc.merge(crate::preferences::openapi_fragment());
    doc.merge(crate::push::openapi_fragment());
    doc.merge(crate::signature::openapi_fragment());
    doc
}
