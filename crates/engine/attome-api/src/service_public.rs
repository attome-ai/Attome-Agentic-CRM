//! Work Intake self-service portal public routes (M70, D-423) — public
//! offering browsing and request-status-by-token lookup, no auth beyond the
//! token. Same shape as `content_public.rs` (that file's module doc has the
//! full reasoning): both paths are in `bypass::EXACT_BYPASS_PATHS`, merged
//! directly in `system.rs` rather than through `ServiceModel::routes()` (the
//! latter would go through `ModelRegistry`'s automatic per-module license
//! gate, `AppError::FeatureHidden`, which would leak licensing state to an
//! anonymous caller), and each handler runs its own manual license check so
//! an unlicensed deployment and a "just nothing here" state are
//! indistinguishable from outside.
//!
//! All business logic (the actual queries, the anti-enumeration token
//! verification) lives in `attome_service::portal` — this file is transport
//! only: manual license check, call, shape the response.

use std::net::SocketAddr;

use attome_core::EngineState;
use attome_modules::MODULE_SERVICE;
use attome_service::portal::{
    AnonymousRequest, AnonymousRequestAccepted, PortalStatus, PublicOffering,
};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;

/// G2-T1: anonymous requests one address may send a minute, across offerings.
const INTAKE_PER_ADDRESS_PER_MINUTE: i32 = 5;
/// G2-T1: anonymous requests one offering takes a minute, from everyone.
const INTAKE_PER_OFFERING_PER_MINUTE: i32 = 60;

/// Service portal offerings
///
/// Service portal offerings.
#[utoipa::path(
    get,
    path = "/api/v1/service-portal/offerings",
    tag = "service",
    responses(
        (status = 200, description = "Public, active offerings — empty on an unlicensed deployment, same as genuinely having none configured", body = Vec<PublicOffering>),
    ),
)]
async fn list_offerings(
    State(state): State<EngineState>,
) -> Result<Json<Vec<PublicOffering>>, AppError> {
    let active = state.modules.load();
    let licensed = active.require(MODULE_SERVICE).is_ok();
    drop(active);
    if !licensed {
        // Not a 404: a list endpoint's natural "nothing configured" state is
        // an empty array, and it must be indistinguishable from "this
        // deployment isn't licensed for Work Intake" — the same anonymous
        // caller must never learn which is true.
        return Ok(Json(Vec::new()));
    }

    let offerings = attome_service::portal::list_public_offerings(&state.base.db).await?;
    Ok(Json(offerings))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct StatusQuery {
    /// The `{public_id}.{secret}` bearer handed back once, at creation, by
    /// `POST /api/v1/service-offering/{id}/create-work-request`.
    token: String,
}

/// Service portal status
///
/// Service portal status.
#[utoipa::path(
    get,
    path = "/api/v1/service-portal/status",
    tag = "service",
    params(StatusQuery),
    responses(
        (status = 200, description = "Success", body = PortalStatus),
        (status = 404, description = "No such token — identical response whether the token is malformed, unknown, wrong, or the deployment isn't licensed for this module", body = ErrorResponse),
    ),
)]
async fn lookup_status(
    State(state): State<EngineState>,
    Query(q): Query<StatusQuery>,
) -> Result<Json<PortalStatus>, AppError> {
    let active = state.modules.load();
    let licensed = active.require(MODULE_SERVICE).is_ok();
    drop(active);
    if !licensed {
        return Err(AppError::NotFound);
    }

    let status =
        attome_service::portal::lookup_status(&state.base.db, &q.token, &state.base.pepper_ring())
            .await?
            .ok_or(AppError::NotFound)?;
    Ok(Json(status))
}

/// Files an anonymous request on a public offering (G2-T1).
///
/// Off by default: the offering must be listed in
/// `service.anonymous_intake.offerings` and `service.anonymous_intake.user`
/// must name the service account the request is filed as. Every other case
/// (not listed, not public, inactive, unlicensed) is the same 404. At most
/// five requests a minute from one address and sixty a minute to one
/// offering; when the deployment has a challenge (proof-of-work or a CAPTCHA
/// provider), `captcha_token` must carry it solved, or the answer is 429 with
/// `Attome-Challenge` naming the kind. The request goes through the same
/// create path, routing and audit as a staff one; the answer is the status
/// token, shown once.
#[utoipa::path(
    post,
    path = "/api/v1/service-portal/offerings/{id}/requests",
    tag = "service",
    params(("id" = Uuid, Path, description = "The public offering's id")),
    request_body = AnonymousRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("attome_service::offering::create_work_request_from_offering"),
        "anonymous submission recorded as intake: the work request's own Entity audit event and its business event are written by the create path, as the intake service account",
    )))),
    responses(
        (status = 201, description = "The request was filed; the status token is shown once", body = AnonymousRequestAccepted),
        (status = 404, description = "This offering does not take anonymous requests (the same answer for every reason)", body = ErrorResponse),
        (status = 422, description = "A field is missing or too long", body = ErrorResponse),
        (status = 429, description = "Too many requests, or the challenge was not solved (Attome-Challenge names its kind)", body = ErrorResponse),
    ),
)]
async fn submit_request(
    State(state): State<EngineState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(offering_id): Path<Uuid>,
    Json(body): Json<AnonymousRequest>,
) -> Result<Response, AppError> {
    if state.modules.load().require(MODULE_SERVICE).is_err() {
        return Err(AppError::NotFound);
    }
    let ip = attome_server::middleware::client_ip::client_ip_from_parts(
        peer.ip(),
        &headers,
        &state.base.config,
    );
    for (key, limit) in [
        (
            format!("service:rl:intake:address:{ip}"),
            INTAKE_PER_ADDRESS_PER_MINUTE,
        ),
        (
            format!("service:rl:intake:offering:{offering_id}"),
            INTAKE_PER_OFFERING_PER_MINUTE,
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

    let captcha = &state.base.config.portal.captcha;
    let sovereign = state.base.config.deployment.sovereign;
    let provider = captcha.effective_provider(sovereign);
    if provider != attome_config::CaptchaProvider::None {
        let pow_secret = state
            .base
            .secrets
            .load()
            .jwt_secret
            .active()
            .map(str::to_owned);
        let remote_ip = ip.to_string();
        let solved = attome_auth::captcha::verify_challenge(
            captcha,
            sovereign,
            &state.base.redis_coordination,
            pow_secret.as_deref(),
            body.captcha_token.as_deref(),
            Some(remote_ip.as_str()),
        )
        .await;
        if !solved {
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
            return Ok(refused);
        }
    }

    let accepted = attome_service::portal::submit_anonymous(
        &state,
        offering_id,
        &body,
        &state.base.pepper_ring(),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(accepted)).into_response())
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/service-portal/offerings", get(list_offerings))
        .route("/api/v1/service-portal/status", get(lookup_status))
        .route(
            "/api/v1/service-portal/offerings/{id}/requests",
            post(submit_request),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_offerings, lookup_status, submit_request))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
