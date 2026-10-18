//! Q20-T3: `GET /api/v1/auth/challenge`, a fresh proof-of-work challenge for
//! a sign-in or sign-up the server has asked to be challenged. Public and
//! bypass-listed: the caller has no session yet. It stores nothing (the
//! challenge is signed, `attome_auth::pow`), so it needs no audit.

use attome_server::AppState;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::State,
    http::header,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

/// A proof-of-work challenge: find an `answer` such that SHA-256 of `nonce`
/// followed by `answer` starts with `difficulty` zero bits, then send
/// `{challenge}:{answer}` as the request's `captcha_token`.
#[derive(Debug, Serialize, ToSchema)]
pub struct PowChallenge {
    pub challenge: String,
    pub nonce: String,
    pub difficulty: u8,
    /// Unix seconds.
    pub expires_at: i64,
}

/// A proof-of-work challenge.
///
/// Issued only when proof-of-work is the challenge in force
/// (`portal.captcha.provider = "pow"`, or a sovereign deployment with no
/// provider); otherwise `404`. A challenge expires after two minutes and an
/// answer is accepted once.
#[utoipa::path(
    get,
    path = "/api/v1/auth/challenge",
    tag = "auth",
    operation_id = "get_pow_challenge",
    responses(
        (status = 200, description = "A fresh challenge", body = PowChallenge),
        (status = 404, description = "Proof-of-work is not the challenge in force", body = ErrorResponse),
    ),
)]
pub(super) async fn get_challenge(State(state): State<AppState>) -> Result<Response, AppError> {
    let captcha = &state.config.portal.captcha;
    if captcha.effective_provider(state.config.deployment.sovereign)
        != attome_config::CaptchaProvider::Pow
    {
        return Err(AppError::NotFound);
    }
    let secret = state
        .secrets
        .load()
        .jwt_secret
        .active()
        .map(str::to_owned)
        .ok_or_else(|| AppError::internal("auth.jwt_secret has no active key configured"))?;
    let issued = attome_auth::pow::issue(
        &secret,
        captcha.pow_difficulty,
        chrono::Utc::now().timestamp(),
    );
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(PowChallenge {
            challenge: issued.challenge,
            nonce: issued.nonce,
            difficulty: issued.difficulty,
            expires_at: issued.expires_at,
        }),
    )
        .into_response())
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_challenge), components(schemas(PowChallenge)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
