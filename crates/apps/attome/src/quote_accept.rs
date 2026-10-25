//! D9-T3: quote acceptance by guest link (transport only; the engine is
//! `attome_sales::quote_accept`).
//!
//! The salesperson's route makes the link; the two public routes are
//! bypass-listed, licence-checked (an unlicensed deployment answers like an
//! unknown link) and take the signed link as their only authority. A
//! decision is rate limited per address.

use std::net::SocketAddr;

use attome_core::EngineState;
use attome_modules::MODULE_SALES;
use attome_sales::quote_accept::{GuestLink, GuestLinkRequest, QuoteDecision, QuoteView};
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, State},
    routing::{get, post},
};
use uuid::Uuid;

/// Decisions one address may send a minute.
const DECISIONS_PER_ADDRESS_PER_MINUTE: i32 = 5;

fn licensed(state: &EngineState) -> Result<(), AppError> {
    state
        .modules
        .load()
        .require(MODULE_SALES)
        .map_err(|_| AppError::NotFound)
}

/// Make a quote's guest link
///
/// Makes a sent quote's guest link.
#[utoipa::path(
    post,
    path = "/api/v1/sales/quotes/{id}/guest-link",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The quote")),
    request_body = GuestLinkRequest,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The link", body = GuestLink),
        (status = 403, description = "No privilege to change quotes", body = ErrorResponse),
        (status = 404, description = "No such quote the caller may see", body = ErrorResponse),
        (status = 409, description = "The quote is not sent, or has expired", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn post_guest_link(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    body: Option<Json<GuestLinkRequest>>,
) -> Result<Json<GuestLink>, AppError> {
    licensed(&state)?;
    let req = body.map(|Json(b)| b).unwrap_or_default();
    Ok(Json(
        attome_sales::quote_accept::create_guest_link(&state, &ctx, id, &req).await?,
    ))
}

/// A quote from its guest link
///
/// The quote a guest link shows.
#[utoipa::path(
    get,
    path = "/api/v1/quote-acceptance/{token}",
    tag = "sales",
    params(("token" = String, Path, description = "The guest link token")),
    responses(
        (status = 200, description = "The quote", body = QuoteView),
        (status = 404, description = "Altered, expired or superseded link", body = ErrorResponse),
    ),
)]
async fn get_quote(
    State(state): State<EngineState>,
    Path(token): Path<String>,
) -> Result<Json<QuoteView>, AppError> {
    licensed(&state)?;
    Ok(Json(
        attome_sales::quote_accept::view(&state, &token).await?,
    ))
}

/// Accept or reject a quote
///
/// Accepts or rejects the quote a guest link shows.
#[utoipa::path(
    post,
    path = "/api/v1/quote-acceptance/{token}",
    tag = "sales",
    params(("token" = String, Path, description = "The guest link token")),
    request_body = QuoteDecision,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Decided", body = QuoteView),
        (status = 404, description = "Altered, expired or superseded link", body = ErrorResponse),
        (status = 409, description = "Already decided, or expired", body = ErrorResponse),
        (status = 422, description = "No name, or not accept or reject", body = ErrorResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
)]
async fn post_decision(
    State(state): State<EngineState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    Json(body): Json<QuoteDecision>,
) -> Result<Json<QuoteView>, AppError> {
    licensed(&state)?;
    let key = format!("sales:rl:quote-decision:ip:{}", addr.ip());
    let outcome = attome_cache::rate_limit::check(
        &state.base.redis_coordination,
        &key,
        DECISIONS_PER_ADDRESS_PER_MINUTE,
    )
    .await?;
    if !outcome.allowed {
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    }
    Ok(Json(
        attome_sales::quote_accept::decide(&state, &token, &body).await?,
    ))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/sales/quotes/{id}/guest-link",
            post(post_guest_link),
        )
        .route(
            "/api/v1/quote-acceptance/{token}",
            get(get_quote).post(post_decision),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_guest_link, get_quote, post_decision))]
struct ApiDocFragment;

pub fn openapi() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
