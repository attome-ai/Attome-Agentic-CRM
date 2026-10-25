//! D20-T2: the public booking routes (transport only; the engine is
//! `attome_sales::booking`).
//!
//! All five are bypass-listed and run their own license check: an
//! unlicensed deployment answers exactly as a page that does not exist. A
//! booking is rate limited per address and per page and passes the
//! deployment's challenge (CAPTCHA or proof-of-work) first. The manage
//! routes take the signed link from the confirmation email as their only
//! authority.

use std::net::SocketAddr;

use attome_core::EngineState;
use attome_modules::MODULE_SALES;
use attome_sales::booking::{
    BookRequest, Booked, ManagedBooking, PublicBookingPage, RescheduleRequest, SlotQuery,
};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};

/// Bookings one address may make a minute.
const BOOK_PER_ADDRESS_PER_MINUTE: i32 = 5;
/// Bookings one page takes a minute, from everyone.
const BOOK_PER_PAGE_PER_MINUTE: i32 = 30;

fn licensed(state: &EngineState) -> Result<(), AppError> {
    state
        .modules
        .load()
        .require(MODULE_SALES)
        .map_err(|_| AppError::NotFound)
}

/// Refuses a booking without a solved challenge, when the deployment uses one.
async fn challenge(
    state: &EngineState,
    token: Option<&str>,
    ip: &str,
) -> Result<Option<Response>, AppError> {
    let captcha = &state.base.config.portal.captcha;
    let sovereign = state.base.config.deployment.sovereign;
    let provider = captcha.effective_provider(sovereign);
    if provider == attome_config::CaptchaProvider::None {
        return Ok(None);
    }
    let pow_secret = state
        .base
        .secrets
        .load()
        .jwt_secret
        .active()
        .map(str::to_owned);
    let solved = attome_auth::captcha::verify_challenge(
        captcha,
        sovereign,
        &state.base.redis_coordination,
        pow_secret.as_deref(),
        token,
        Some(ip),
    )
    .await;
    if solved {
        return Ok(None);
    }
    let mut refused = AppError::TooManyRequests {
        retry_after_secs: None,
    }
    .into_response();
    let kind = match provider {
        attome_config::CaptchaProvider::Pow => "pow",
        attome_config::CaptchaProvider::Turnstile => "turnstile",
        attome_config::CaptchaProvider::Hcaptcha => "hcaptcha",
        attome_config::CaptchaProvider::None => "wait",
    };
    refused
        .headers_mut()
        .insert("attome-challenge", HeaderValue::from_static(kind));
    Ok(Some(refused))
}

/// A booking page
///
/// A booking page: its name and the times that can be booked.
#[utoipa::path(
    get,
    path = "/api/v1/booking/{slug}",
    operation_id = "get_booking_page",
    tag = "sales",
    params(("slug" = String, Path, description = "The booking page's slug"), SlotQuery),
    responses(
        (status = 200, description = "The page and its free times", body = PublicBookingPage),
        (status = 404, description = "No such page", body = ErrorResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
)]
async fn get_page(
    State(state): State<EngineState>,
    Path(slug): Path<String>,
    Query(query): Query<SlotQuery>,
) -> Result<Json<PublicBookingPage>, AppError> {
    licensed(&state)?;
    Ok(Json(
        attome_sales::booking::public_page(&state, &slug, &query).await?,
    ))
}

/// Book a meeting
///
/// Books a meeting at one of the page's free times.
#[utoipa::path(
    post,
    path = "/api/v1/booking/{slug}",
    tag = "sales",
    params(("slug" = String, Path, description = "The booking page's slug")),
    request_body = BookRequest,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Booked; the confirmation email has the manage link", body = Booked),
        (status = 404, description = "No such page", body = ErrorResponse),
        (status = 409, description = "The time is no longer free", body = ErrorResponse),
        (status = 422, description = "Invalid name, email or time", body = ErrorResponse),
        (status = 429, description = "Rate limited, or the challenge is unsolved (`attome-challenge` says which)", body = ErrorResponse),
    ),
)]
async fn post_booking(
    State(state): State<EngineState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(slug): Path<String>,
    Json(body): Json<BookRequest>,
) -> Result<Response, AppError> {
    licensed(&state)?;
    let ip = addr.ip().to_string();
    for (key, limit) in [
        (
            format!("sales:rl:booking:ip:{ip}"),
            BOOK_PER_ADDRESS_PER_MINUTE,
        ),
        (
            format!("sales:rl:booking:page:{}", slug.to_lowercase()),
            BOOK_PER_PAGE_PER_MINUTE,
        ),
    ] {
        let outcome =
            attome_cache::rate_limit::check(&state.base.redis_coordination, &key, limit).await?;
        if !outcome.allowed {
            return Err(AppError::TooManyRequests {
                retry_after_secs: None,
            });
        }
    }
    if let Some(refused) = challenge(&state, body.captcha_token.as_deref(), &ip).await? {
        return Ok(refused);
    }
    let booked = attome_sales::booking::book(&state, &slug, &body).await?;
    Ok((StatusCode::CREATED, Json(booked)).into_response())
}

/// A booking from its manage link
///
/// The booking a manage link names.
#[utoipa::path(
    get,
    path = "/api/v1/booking/manage/{token}",
    tag = "sales",
    params(("token" = String, Path, description = "The signed manage link token")),
    responses(
        (status = 200, description = "The booking", body = ManagedBooking),
        (status = 404, description = "Altered or expired link", body = ErrorResponse),
    ),
)]
async fn get_managed(
    State(state): State<EngineState>,
    Path(token): Path<String>,
) -> Result<Json<ManagedBooking>, AppError> {
    licensed(&state)?;
    Ok(Json(attome_sales::booking::managed(&state, &token).await?))
}

/// Cancel a booking
///
/// Cancels the booking and its meeting.
#[utoipa::path(
    post,
    path = "/api/v1/booking/manage/{token}/cancel",
    operation_id = "cancel_booking",
    tag = "sales",
    params(("token" = String, Path, description = "The signed manage link token")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Cancelled", body = ManagedBooking),
        (status = 404, description = "Altered or expired link", body = ErrorResponse),
        (status = 409, description = "Already cancelled or started", body = ErrorResponse),
    ),
)]
async fn post_cancel(
    State(state): State<EngineState>,
    Path(token): Path<String>,
) -> Result<Json<ManagedBooking>, AppError> {
    licensed(&state)?;
    Ok(Json(attome_sales::booking::cancel(&state, &token).await?))
}

/// Reschedule a booking
///
/// Moves the booking to another free time with the same person.
#[utoipa::path(
    post,
    path = "/api/v1/booking/manage/{token}/reschedule",
    tag = "sales",
    params(("token" = String, Path, description = "The signed manage link token")),
    request_body = RescheduleRequest,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Moved", body = ManagedBooking),
        (status = 404, description = "Altered or expired link", body = ErrorResponse),
        (status = 409, description = "The time is not free, or the booking is cancelled or started", body = ErrorResponse),
        (status = 422, description = "Not a time the page offers", body = ErrorResponse),
    ),
)]
async fn post_reschedule(
    State(state): State<EngineState>,
    Path(token): Path<String>,
    Json(body): Json<RescheduleRequest>,
) -> Result<Json<ManagedBooking>, AppError> {
    licensed(&state)?;
    Ok(Json(
        attome_sales::booking::reschedule(&state, &token, &body).await?,
    ))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/booking/{slug}", get(get_page).post(post_booking))
        .route("/api/v1/booking/manage/{token}", get(get_managed))
        .route("/api/v1/booking/manage/{token}/cancel", post(post_cancel))
        .route(
            "/api/v1/booking/manage/{token}/reschedule",
            post(post_reschedule),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_page, post_booking, get_managed, post_cancel, post_reschedule))]
struct ApiDocFragment;

pub fn openapi() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
