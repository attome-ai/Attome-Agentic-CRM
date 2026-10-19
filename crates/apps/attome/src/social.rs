//! J8-T1: Messenger, Instagram and Facebook comments in, replies out; Google
//! reviews in (the adapters are `attome_integration::connector::adapters::
//! social`).
//!
//! - `GET /api/v1/social/meta/{key}` answers Meta's subscription check.
//! - `POST /api/v1/social/meta/{key}` takes Meta's signed events. Each
//!   message or comment is written as an inbound communication on the
//!   system's record through the M52 writer, as the system's service
//!   principal, threaded with earlier ones from the same person or comment.
//! - `POST /api/v1/social/replies` (staff) answers one of them: it sends the
//!   reply through the provider and records it as an outbound communication
//!   in the same thread, as the person replying.
//! - [`sync_reviews`] (the `social_reviews_sync` job, every 15 minutes)
//!   writes each new Google review the same way.
//!
//! The public routes are licensed with the omnichannel module and answer an
//! unknown key, an unlicensed deployment and a bad signature alike.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_integration::connector::adapters::social::{
    self, ReplyTarget, SocialMessage, google_reviews, meta,
};
use attome_integration::system::IntegrationSystem;
use attome_modules::MODULE_OMNICHANNEL;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

fn licensed(state: &EngineState) -> Result<(), AppError> {
    state
        .modules
        .load()
        .require(MODULE_OMNICHANNEL)
        .map_err(|_| AppError::NotFound)
}

/// The latest thread of `address` on `channel`.
async fn thread_of(
    state: &EngineState,
    channel: &str,
    address: &str,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT thread_id FROM communication \
          WHERE channel = $1 AND to_addresses = $2 AND is_active IS NOT FALSE \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(channel)
    .bind(address)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Writes what arrived on `system` as an inbound communication on its record.
async fn record_inbound(
    state: &EngineState,
    system: &IntegrationSystem,
    message: &SocialMessage,
) -> Result<(), AppError> {
    let principal = attome_integration::system::service_principal_id(system)?;
    let ctx = state.base.security.resolve(principal).await?;
    ctx.require("communication", "create")?;
    let thread = thread_of(state, message.channel, &message.address).await?;
    let body = match &message.author {
        Some(author) => format!("{author}: {}", message.text),
        None => message.text.clone(),
    };
    attome_notification::communication::write_communication(
        state,
        &ctx,
        principal,
        "integration_system",
        system.id,
        message.channel,
        "inbound",
        std::slice::from_ref(&message.address),
        &[],
        &message.subject,
        &body,
        None,
        thread,
        None,
        None,
    )
    .await?;
    Ok(())
}

/// Meta's subscription check.
#[utoipa::path(
    get,
    path = "/api/v1/social/meta/{key}",
    tag = "omnichannel",
    params(("key" = String, Path, description = "The Meta system's inbound key")),
    responses(
        (status = 200, description = "The challenge, echoed", body = String),
        (status = 404, description = "Not licensed, no such system, or the wrong verify token", body = ErrorResponse),
    ),
)]
async fn meta_verify(
    State(state): State<EngineState>,
    Path(key): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<String, AppError> {
    licensed(&state)?;
    let system = social::system_by_key(&state, "meta", &key)
        .await?
        .ok_or(AppError::NotFound)?;
    let token = social::config(&system)
        .get("verify_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default();
    meta::verify_challenge(&params, &token).ok_or(AppError::NotFound)
}

/// Meta's signed events: messages and comments.
#[utoipa::path(
    post,
    path = "/api/v1/social/meta/{key}",
    tag = "omnichannel",
    params(("key" = String, Path, description = "The Meta system's inbound key")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Received"),
        (status = 404, description = "Not licensed, no such system, or a bad signature", body = ErrorResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
)]
async fn meta_events(
    State(state): State<EngineState>,
    Path(key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    licensed(&state)?;
    let system = social::system_by_key(&state, "meta", &key)
        .await?
        .ok_or(AppError::NotFound)?;
    let secrets = social::secrets(&state, &system).await?;
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok());
    if !meta::signature_ok(social::secret(&secrets, "app_secret")?, &body, signature) {
        return Err(AppError::NotFound);
    }
    for message in meta::parse_webhook(&body) {
        // One failure does not lose the rest; Meta retries the whole batch
        // only on a non-2xx, which would duplicate the ones written.
        if let Err(error) = record_inbound(&state, &system, &message).await {
            tracing::warn!(system = %system.id, channel = message.channel, %error, "social: message not recorded");
        }
    }
    Ok(StatusCode::OK)
}

/// A reply to a social message, comment or review.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SocialReply {
    /// The inbound communication being answered.
    pub communication_id: Uuid,
    /// The reply, at most 2,000 characters.
    pub body: String,
}

/// The recorded reply.
#[derive(Debug, Serialize, ToSchema)]
pub struct SocialReplySent {
    pub communication_id: Uuid,
    pub thread_id: Uuid,
    /// The provider's id for the reply, when it gives one.
    pub provider_id: Option<String>,
}

/// Answers a social message, comment or review through its provider.
#[utoipa::path(
    post,
    path = "/api/v1/social/replies",
    tag = "omnichannel",
    request_body = SocialReply,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Sent and recorded", body = SocialReplySent),
        (status = 403, description = "No privilege to write communications", body = ErrorResponse),
        (status = 404, description = "No such communication, or not one from a social channel", body = ErrorResponse),
        (status = 422, description = "Empty or too long, or the provider refused it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn post_reply(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(req): Json<SocialReply>,
) -> Result<(StatusCode, Json<SocialReplySent>), AppError> {
    licensed(&state)?;
    ctx.require("communication", "create")?;
    // Read as the caller: a message they cannot see cannot be answered.
    let original = attome_records::entity_crud::read_record(
        &state,
        &ctx,
        "communication",
        req.communication_id,
    )
    .await?;
    let data = original.data();
    let field = |name: &str| data.get(name).and_then(Value::as_str).unwrap_or_default();
    let target = ReplyTarget::parse(field("to_addresses")).ok_or(AppError::NotFound)?;
    if field("direction") != "inbound" || field("entity_name") != "integration_system" {
        return Err(AppError::NotFound);
    }
    let system_id = Uuid::parse_str(field("record_id")).map_err(|_| AppError::NotFound)?;
    let system = attome_integration::system::load(&state.base.db, system_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let thread = Uuid::parse_str(field("thread_id")).ok();
    let provider_id = social::reply(&state, &system, &target, &req.body).await?;
    let user = ctx.user_id;
    let sent = attome_notification::communication::write_communication(
        &state,
        &ctx,
        user,
        "integration_system",
        system.id,
        target.channel(),
        "outbound",
        &[target.address()],
        &[],
        &format!("Re: {}", field("subject")),
        req.body.trim(),
        Some(req.communication_id),
        thread,
        None,
        None,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(SocialReplySent {
            communication_id: sent.id,
            thread_id: sent.thread_id,
            provider_id,
        }),
    ))
}

/// J8-T1: new Google reviews of every reviews system become inbound
/// communications, each once (by its address). Answers how many.
pub async fn sync_reviews(state: &EngineState) -> Result<u32, AppError> {
    if state.modules.load().require(MODULE_OMNICHANNEL).is_err() {
        return Ok(0);
    }
    let mut written = 0;
    for system in social::systems(state, "google_reviews").await? {
        let reviews = match google_reviews::fetch_reviews(state, &system).await {
            Ok(reviews) => reviews,
            Err(error) => {
                tracing::warn!(system = %system.id, %error, "social: reviews not read");
                continue;
            }
        };
        for review in reviews {
            let message = google_reviews::review_message(&review);
            let seen: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM communication \
                  WHERE channel = 'google_review' AND to_addresses = $1)",
            )
            .bind(&message.address)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            if seen {
                continue;
            }
            match record_inbound(state, &system, &message).await {
                Ok(()) => written += 1,
                Err(error) => {
                    tracing::warn!(system = %system.id, %error, "social: review not recorded")
                }
            }
        }
    }
    Ok(written)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/social/meta/{key}",
            get(meta_verify).post(meta_events),
        )
        .route("/api/v1/social/replies", post(post_reply))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(meta_verify, meta_events, post_reply))]
struct ApiDocFragment;

pub fn openapi() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
