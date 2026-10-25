//! Step-up routes (D-510 rules 5 and 6; attome-auth hardening 2.1b and 2.1c):
//! start a challenge, verify it locally, or complete it at a federated
//! provider. Thin wiring over `attome_auth::step_up`, which owns the factor
//! rules, the challenge store and the elevation write.
//!
//! The family comes only from the validated token (`StepUpCaller`), the user
//! only from `SessionClaims.sub`, and the operation only from the route. The
//! request body never names any of them. On the federated callback, which no
//! session cookie reaches, all three come from the provider flow's single-use
//! server-side state, bound to the browser that started it. These routes do
//! not guard anything themselves; wiring the guard onto the protected
//! operations is 2.1d.

use attome_auth::session::SessionClaims;
use attome_auth::step_up::{self, FederatedProtocol, Operation, StepUpStores, Submission};
use attome_server::AppState;
use attome_server::authz::{Authorized, SelfService};
use attome_server::middleware::rate_limit::{
    MFA_ATTEMPTS_PER_ACCOUNT_RPM, enforce_account_budget, mfa_account_key,
};
use attome_server::step_up::StepUpCaller;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{AppendHeaders, IntoResponse, Redirect, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::dto::{StepUpFederatedStartQuery, StepUpOidcCallbackQuery};
use super::oidc::{
    IdentityLinkFlow, identity_link_cookie_clear, identity_link_cookie_set,
    redirect_url_query_param, require_identity_link_binding,
};

/// A started step-up challenge.
#[derive(Serialize, ToSchema)]
pub(super) struct StepUpChallengeBody {
    challenge_id: Uuid,
    /// The operation from the route.
    operation: String,
    /// The factors the account may answer with (`totp`, `recovery_code`,
    /// `password`, `federated`). `federated` needs the IdP flow, not the
    /// verify route.
    acceptable_factors: Vec<String>,
    expires_in_secs: i64,
}

/// An answer to a step-up challenge. It carries no family and no operation:
/// those come from the session and the route.
#[derive(Deserialize, ToSchema)]
pub(super) struct StepUpVerifyBody {
    challenge_id: String,
    /// `totp`, `recovery_code` or `password`.
    factor: String,
    /// The TOTP code, recovery code or password.
    credential: String,
}

/// An answer to a step-up challenge with a fresh Google ID token (BAU-8c).
#[derive(Deserialize, ToSchema)]
pub(super) struct StepUpGoogleBody {
    challenge_id: String,
    /// The ID token Google Identity Services just issued. Accepted once.
    credential: String,
}

/// The caller's family is elevated until `elevated_until`.
#[derive(Serialize, ToSchema)]
pub(super) struct StepUpElevationBody {
    operation: String,
    elevated_until: DateTime<Utc>,
}

pub(super) fn stores(state: &AppState) -> StepUpStores<'_> {
    StepUpStores {
        db: &state.db,
        redis: &state.redis_coordination,
        absolute_lifetime_secs: state.config.refresh_absolute_lifetime_secs(),
    }
}

/// Only the operations that need elevation are routes; anything else is 404.
pub(super) fn step_up_operation(segment: &str) -> Result<Operation, AppError> {
    Operation::from_step_up_route(segment).ok_or(AppError::NotFound)
}

/// Whether the caller's own session could perform an operation right now.
#[derive(Serialize, ToSchema)]
pub(super) struct StepUpStatusBody {
    /// The operation from the route.
    operation: String,
    /// Exactly whether the operation's guard passes now.
    elevated: bool,
    /// When the elevation ends, while `elevated`.
    elevated_until: Option<DateTime<Utc>>,
    /// The factors a step-up for this operation accepts (`totp`,
    /// `recovery_code`, `password`, `federated`), or the single
    /// `totp_enrollment_required`.
    acceptable_factors: Vec<String>,
}

/// Whether a step-up is needed
///
/// Reads whether the caller's own session could perform `operation` now, by
/// running the operation's guard without acting on it (D-510 rule 9;
/// attome-auth hardening 2.1d). It starts no challenge and writes nothing. The
/// settings page calls it before a browser navigation such as identity
/// linking, which cannot handle a JSON `reauth_required`.
#[utoipa::path(
    get,
    path = "/api/v1/auth/step-up/{operation}",
    tag = "auth",
    params(
        ("operation" = String, Path, description = "`identity_link` or `api_key_create`."),
    ),
    responses(
        (status = 200, description = "The guard's current decision for the caller's own session", body = StepUpStatusBody),
        (status = 401, description = "No live session with a refresh family", body = ErrorResponse),
        (status = 403, description = "An API-key or S2S caller, which can never step up", body = ErrorResponse),
        (status = 404, description = "Not a step-up operation", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn step_up_status(
    State(state): State<AppState>,
    Extension(claims): Extension<SessionClaims>,
    StepUpCaller(caller): StepUpCaller,
    // Self-scoped by design, as for `start_step_up`.
    _ctx: Authorized<SelfService>,
    Path(operation): Path<String>,
) -> Result<Json<StepUpStatusBody>, AppError> {
    let operation = step_up_operation(&operation)?;
    let status = step_up::elevation_status(
        &state.db,
        caller,
        claims.sub,
        operation,
        state.config.refresh_absolute_lifetime_secs(),
    )
    .await?;
    Ok(Json(StepUpStatusBody {
        operation: status.operation.as_str().to_owned(),
        elevated: status.elevated,
        elevated_until: status.elevated_until,
        acceptable_factors: status
            .acceptable_factors
            .iter()
            .map(|factor| (*factor).to_owned())
            .collect(),
    }))
}

/// Start a step-up challenge
///
/// Starts a single-use step-up challenge for `operation` on the caller's own
/// session. An account with no local factor gets `reauth_required` naming what
/// it needs, such as `totp_enrollment_required`.
#[utoipa::path(
    post,
    path = "/api/v1/auth/step-up/{operation}",
    tag = "auth",
    params(
        ("operation" = String, Path, description = "The operation to step up for: `identity_link` or `api_key_create`."),
    ),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "starts a challenge: one short-lived Redis key naming the caller's session and operation, nothing persistent; the audited change is the verify route's elevation",
    )))),
    responses(
        (status = 201, description = "Challenge started", body = StepUpChallengeBody),
        (status = 401, description = "No live session with a refresh family, or `reauth_required` when the account has no local factor", body = ErrorResponse),
        (status = 403, description = "An API-key or S2S caller, which can never step up", body = ErrorResponse),
        (status = 404, description = "Not a step-up operation", body = ErrorResponse),
        (status = 429, description = "Too many attempts", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn start_step_up(
    State(state): State<AppState>,
    Extension(claims): Extension<SessionClaims>,
    StepUpCaller(caller): StepUpCaller,
    // Self-scoped by design: acts only on the caller's own `claims.sub` and
    // the family from the validated token. Declared so the route's posture is
    // explicit and the extractor proves the request passed through `authz`.
    _ctx: Authorized<SelfService>,
    Path(operation): Path<String>,
) -> Result<(StatusCode, Json<StepUpChallengeBody>), AppError> {
    let operation = step_up_operation(&operation)?;
    let started = step_up::start_challenge(stores(&state), caller, claims.sub, operation).await?;
    Ok((
        StatusCode::CREATED,
        Json(StepUpChallengeBody {
            challenge_id: started.challenge_id,
            operation: started.operation.as_str().to_owned(),
            acceptable_factors: started
                .acceptable_factors
                .iter()
                .map(|factor| factor.as_str().to_owned())
                .collect(),
            expires_in_secs: started.expires_in_secs,
        }),
    ))
}

/// Verify a step-up challenge
///
/// Verifies a step-up challenge and elevates the caller's session. Every
/// failure, including a wrong credential, an expired or reused challenge, or
/// one for another session or operation, is `reauth_required`.
#[utoipa::path(
    post,
    path = "/api/v1/auth/step-up/{operation}/verify",
    tag = "auth",
    params(
        ("operation" = String, Path, description = "The operation the challenge was started for."),
    ),
    request_body = StepUpVerifyBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Login),
        (attome_audit::AuditCategory::Security, attome_audit::AuditOperation::FailedLogin),
    ])))),
    responses(
        (status = 200, description = "Session elevated", body = StepUpElevationBody),
        (status = 401, description = "`reauth_required`, or no live session with a refresh family", body = ErrorResponse),
        (status = 403, description = "An API-key or S2S caller, which can never step up", body = ErrorResponse),
        (status = 404, description = "Not a step-up operation", body = ErrorResponse),
        (status = 429, description = "Too many second-factor attempts for this account", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn verify_step_up(
    State(state): State<AppState>,
    Extension(auditor): Extension<attome_audit::security::SecurityAuditor>,
    Extension(claims): Extension<SessionClaims>,
    StepUpCaller(caller): StepUpCaller,
    // Self-scoped by design, as for `start_step_up`.
    _ctx: Authorized<SelfService>,
    Path(operation): Path<String>,
    Json(body): Json<StepUpVerifyBody>,
) -> Result<Response, AppError> {
    let operation = step_up_operation(&operation)?;
    // Base-auth hardening 1.5: the shared per-account second-factor bucket,
    // charged before any verifier runs; a Redis failure rejects.
    if let Some(rejected) = enforce_account_budget(
        &state.redis_coordination,
        &mfa_account_key(claims.sub),
        MFA_ATTEMPTS_PER_ACCOUNT_RPM,
        "step_up_verify",
    )
    .await?
    {
        return Ok(rejected);
    }
    let mfa_ring = state.secrets.load().mfa_encryption_key.clone();
    // A successful step-up is a re-authentication: `Security` + `Login`, written
    // inside the elevation's transaction (D-062). A refusal
    // (`reauth_required`) is `Security` + `FailedLogin` with outcome `Failed`,
    // written on its own (nothing changed); the account budget charged above
    // bounds how many there can be.
    let hook = attome_audit::security::account_event_hook(
        auditor.service(),
        attome_audit::security::MandatoryCategory::Security,
        attome_audit::AuditOperation::Login,
        "user_account",
        format!("step_up {} {}", operation.as_str(), body.factor),
    );
    let elevated_until = match step_up::verify_challenge_with(
        stores(&state),
        &mfa_ring,
        &state.pepper_ring(),
        caller,
        claims.sub,
        operation,
        Submission {
            challenge_id: &body.challenge_id,
            factor: &body.factor,
            credential: &body.credential,
        },
        &hook,
    )
    .await
    {
        Ok(elevated_until) => elevated_until,
        Err(e @ (AppError::Unauthorized | AppError::ReauthRequired { .. })) => {
            auditor
                .write(
                    attome_audit::security::SecurityEvent::new(
                        attome_audit::security::MandatoryCategory::Security,
                        attome_audit::AuditOperation::FailedLogin,
                        claims.sub,
                        "user_account",
                        Some(claims.sub),
                    )
                    .named(format!("step_up_failed {}", operation.as_str()))
                    .outcome(attome_audit::AuditOutcome::Failed),
                )
                .await?;
            return Err(e);
        }
        Err(e) => return Err(e),
    };
    Ok(Json(StepUpElevationBody {
        operation: operation.as_str().to_owned(),
        elevated_until,
    })
    .into_response())
}

// ── Google step-up (BAU-8c, D-628; owner ruling 2026-09-25) ──────────────────

/// Answers a step-up challenge with a fresh Google re-authentication, for an
/// account whose federated factor is Google (`federated` in the challenge's
/// factors). Google Identity Services is a single POST, so there is no
/// redirect and no callback: the session cookie reaches this route, and the
/// family, user and operation come from it and the route as for `verify`.
///
/// The ID token is verified locally against Google's JWKS and accepted once
/// (a replay or an unreachable single-use store is refused); its `sub` must be
/// the account's own linked Google account and its `auth_time` must be within
/// the operation's max age (D-628). A token that does not verify is 401; a
/// challenge, subject or time refusal is `reauth_required`. Nothing is elevated.
#[utoipa::path(
    post,
    path = "/api/v1/auth/step-up/{operation}/google",
    tag = "auth",
    params(
        ("operation" = String, Path, description = "The operation the challenge was started for."),
    ),
    request_body = StepUpGoogleBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Login),
        (attome_audit::AuditCategory::Security, attome_audit::AuditOperation::FailedLogin),
    ])))),
    responses(
        (status = 200, description = "Session elevated", body = StepUpElevationBody),
        (status = 401, description = "`reauth_required` (a Google token that does not verify, was already used, names another Google account or authenticated too long ago), or no live session with a refresh family", body = ErrorResponse),
        (status = 403, description = "An API-key or S2S caller, which can never step up", body = ErrorResponse),
        (status = 404, description = "Not a step-up operation", body = ErrorResponse),
        (status = 429, description = "Too many second-factor attempts for this account", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn google_step_up(
    State(state): State<AppState>,
    Extension(auditor): Extension<attome_audit::security::SecurityAuditor>,
    Extension(claims): Extension<SessionClaims>,
    StepUpCaller(caller): StepUpCaller,
    // Self-scoped by design, as for `start_step_up`.
    _ctx: Authorized<SelfService>,
    Path(operation): Path<String>,
    Json(body): Json<StepUpGoogleBody>,
) -> Result<Response, AppError> {
    let operation = step_up_operation(&operation)?;
    if let Some(rejected) = enforce_account_budget(
        &state.redis_coordination,
        &mfa_account_key(claims.sub),
        MFA_ATTEMPTS_PER_ACCOUNT_RPM,
        "step_up_google",
    )
    .await?
    {
        return Ok(rejected);
    }
    let hook = attome_audit::security::account_event_hook(
        auditor.service(),
        attome_audit::security::MandatoryCategory::Security,
        attome_audit::AuditOperation::Login,
        "user_account",
        format!("step_up_federated {} google", operation.as_str()),
    );
    let outcome = async {
        // Checked before the credential is verified, so an ineligible session
        // neither contacts Google nor spends the single-use credential.
        step_up::check_google_step_up(
            stores(&state),
            caller,
            claims.sub,
            operation,
            &body.challenge_id,
        )
        .await?;
        let identity = attome_auth::accounts::verify_google_id_token(
            &state.redis,
            &state.redis_coordination,
            &state.config.auth.oauth_google_client_id,
            &body.credential,
        )
        .await?;
        step_up::complete_google_step_up_with(
            stores(&state),
            caller,
            claims.sub,
            operation,
            &body.challenge_id,
            &identity.sub,
            identity.auth_time,
            &hook,
        )
        .await
    }
    .await;
    let elevated_until = match outcome {
        Ok(elevated_until) => elevated_until,
        Err(e @ (AppError::Unauthorized | AppError::ReauthRequired { .. })) => {
            auditor
                .write(
                    attome_audit::security::SecurityEvent::new(
                        attome_audit::security::MandatoryCategory::Security,
                        attome_audit::AuditOperation::FailedLogin,
                        claims.sub,
                        "user_account",
                        Some(claims.sub),
                    )
                    .named(format!("step_up_failed {} google", operation.as_str()))
                    .outcome(attome_audit::AuditOutcome::Failed),
                )
                .await?;
            return Err(e);
        }
        Err(e) => return Err(e),
    };
    Ok(Json(StepUpElevationBody {
        operation: operation.as_str().to_owned(),
        elevated_until,
    })
    .into_response())
}

// ── Federated step-up (2.1c, D-510 rule 5) ───────────────────────────────────

/// Continues a step-up challenge at an OIDC provider the caller's account is
/// linked to. The challenge must accept `federated` for this account (never a
/// TOTP-enrolled one). The provider is asked to re-authenticate the user
/// (`prompt=login`) within the operation's max age (`max_age`); the callback
/// then accepts only the ID token's validated `auth_time`.
///
/// Operational note: the provider's client registration must allow
/// `{frontend_url}/api/v1/auth/step-up-callback/oidc/{provider}` as a redirect
/// URI.
#[utoipa::path(
    get,
    path = "/api/v1/auth/step-up/{operation}/oidc/{provider}",
    tag = "auth",
    params(
        ("operation" = String, Path, description = "The operation the challenge was started for."),
        ("provider" = String, Path, description = "The configured OIDC provider key to re-authenticate at."),
        StepUpFederatedStartQuery,
    ),
    responses(
        (status = 200, description = "Not returned: every accepted request gets the 303 redirect below. Listed because every documented operation declares a 2xx."),
        (status = 303, description = "Redirect to the provider with `prompt=login` and `max_age`"),
        (status = 401, description = "`reauth_required`, or no live session with a refresh family", body = ErrorResponse),
        (status = 403, description = "An API-key or S2S caller, which can never step up", body = ErrorResponse),
        (status = 404, description = "Not a step-up operation, or no such provider", body = ErrorResponse),
        (status = 429, description = "Too many attempts", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn start_oidc_step_up(
    State(state): State<AppState>,
    Extension(claims): Extension<SessionClaims>,
    StepUpCaller(caller): StepUpCaller,
    // Self-scoped by design, as for `start_step_up`.
    _ctx: Authorized<SelfService>,
    Path((operation, provider)): Path<(String, String)>,
    Query(query): Query<StepUpFederatedStartQuery>,
) -> Result<Response, AppError> {
    let operation = step_up_operation(&operation)?;
    let mut provider_config = state
        .config
        .oidc
        .providers
        .get(&provider)
        .cloned()
        .ok_or(AppError::NotFound)?;
    if let Some(secret) = state.secrets.load().oidc_client_secrets.get(&provider) {
        provider_config.client_secret = secret.clone();
    }
    let binding = step_up::begin_federated_step_up(
        stores(&state),
        caller,
        claims.sub,
        operation,
        FederatedProtocol::Oidc,
        &provider,
        &query.challenge_id,
    )
    .await?;
    let redirect_uri = format!(
        "{}/api/v1/auth/step-up-callback/oidc/{provider}",
        state.config.frontend_url()
    );
    let authorize_url = attome_auth::oidc::start_step_up_login(
        &state.redis_coordination,
        &state.redis,
        &provider_config,
        &provider,
        &redirect_uri,
        binding,
    )
    .await?;
    // B3 browser binding, as for identity linking: the callback demands the
    // echoed state as a cookie only this browser holds.
    let state_id = redirect_url_query_param(&authorize_url, "state")
        .ok_or_else(|| AppError::internal("oidc authorize url carries no state parameter"))?;
    let secure = state.config.auth.secure_cookies;
    let binding_cookie = identity_link_cookie_set(IdentityLinkFlow::StepUpOidc, secure, &state_id);
    Ok((
        AppendHeaders([(header::SET_COOKIE, binding_cookie)]),
        Redirect::to(&authorize_url),
    )
        .into_response())
}

/// OIDC step-up callback
///
/// The OIDC provider's redirect back from a federated step-up. Bypass-listed
/// (`/api/v1/auth/step-up-callback/`): no session cookie survives the
/// cross-site redirect, so the user, family and operation come only from the
/// single-use server-side state, and only in the browser that started the flow.
/// Elevates only with the ID token's validated `auth_time`, never callback
/// time, then redirects to the frontend.
#[utoipa::path(
    get,
    path = "/api/v1/auth/step-up-callback/oidc/{provider}",
    tag = "auth",
    params(
        ("provider" = String, Path, description = "The OIDC provider key the step-up was started at."),
        StepUpOidcCallbackQuery,
    ),
    responses(
        (status = 200, description = "Not returned: every request gets the 302 redirect below. Listed because every documented operation declares a 2xx."),
        (status = 302, description = "Redirect to the frontend: `step_up=<operation>` on success, `step_up_error=1` otherwise"),
    ),
)]
pub(super) async fn oidc_step_up_callback(
    State(state): State<AppState>,
    Extension(auditor): Extension<attome_audit::security::SecurityAuditor>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(query): Query<StepUpOidcCallbackQuery>,
) -> Response {
    let secure = state.config.auth.secure_cookies;
    // BAU-25 (finding BAU-F20): a cancelled step-up comes back as `error` with
    // no code. Same shape as the other two callbacks — the route's own error
    // redirect, nothing consumed, and no binding cookie cleared.
    let (Some(code), Some(state_id)) = (query.code.as_deref(), query.state.as_deref()) else {
        if let Some(error) = query.error.as_deref() {
            tracing::warn!(
                "step_up_callback: provider={provider} answered error={error}; nothing consumed"
            );
        } else {
            tracing::warn!(
                "step_up_callback: provider={provider} answered without a code and without an error"
            );
        }
        return step_up_callback_response(
            &state,
            IdentityLinkFlow::StepUpOidc,
            false,
            &provider,
            Err(AppError::Unauthorized),
        );
    };
    // Checked before the single-use state is consumed or the provider
    // contacted, so a request from another browser leaves the flow intact.
    let binding =
        require_identity_link_binding(&headers, IdentityLinkFlow::StepUpOidc, secure, state_id);
    let bound = binding.is_ok();
    let outcome = match binding {
        Ok(bound_state) => {
            oidc_step_up_callback_inner(&state, &auditor, &provider, code, bound_state).await
        }
        Err(e) => Err(e),
    };
    step_up_callback_response(
        &state,
        IdentityLinkFlow::StepUpOidc,
        bound,
        &provider,
        outcome,
    )
}

async fn oidc_step_up_callback_inner(
    state: &AppState,
    auditor: &attome_audit::security::SecurityAuditor,
    provider: &str,
    code: &str,
    bound: attome_auth::oidc::BoundState,
) -> Result<Operation, AppError> {
    let mut provider_config = state
        .config
        .oidc
        .providers
        .get(provider)
        .cloned()
        .ok_or(AppError::NotFound)?;
    if let Some(secret) = state.secrets.load().oidc_client_secrets.get(provider) {
        provider_config.client_secret = secret.clone();
    }

    let identity = attome_auth::oidc::complete_login(
        &state.redis_coordination,
        &state.redis,
        &provider_config,
        provider,
        code,
        bound,
    )
    .await?;
    // A state from any other flow (sign-in, linking) carries no step-up.
    let binding = identity.step_up.ok_or(AppError::Unauthorized)?;
    // BAU-26 (finding BAU-F19): a federated elevation is a re-authentication
    // and must reach the audit trail exactly as the local half does — same
    // `Security` + `Login` event, written inside the elevation's own
    // transaction by the `BeforeCommit` hook (D-062, D-545). Before this, the
    // callback hard-coded `NoHook`, so a federated elevation appeared in no
    // audit trail at all.
    let hook = attome_audit::security::account_event_hook(
        auditor.service(),
        attome_audit::security::MandatoryCategory::Security,
        attome_audit::AuditOperation::Login,
        "user_account",
        format!(
            "step_up_federated {} {}",
            binding.operation.as_str(),
            provider
        ),
    );
    step_up::complete_federated_step_up_with(
        stores(state),
        &binding,
        FederatedProtocol::Oidc,
        provider,
        &identity.sub,
        identity.auth_time,
        &hook,
    )
    .await?;
    Ok(binding.operation)
}

/// The redirect every federated step-up callback ends with. The binding cookie
/// is cleared once it has served its flow, but not after a binding failure: that
/// request did not come from the browser that started the flow.
pub(super) fn step_up_callback_response(
    state: &AppState,
    flow: IdentityLinkFlow,
    bound: bool,
    provider: &str,
    outcome: Result<Operation, AppError>,
) -> Response {
    let frontend = state.config.frontend_url();
    let location = match outcome {
        Ok(operation) => format!(
            "{frontend}/settings/security?step_up={}",
            operation.as_str()
        ),
        Err(e) => {
            tracing::warn!("step_up_callback: provider={provider} failed: {e}");
            format!("{frontend}/settings/security?step_up_error=1")
        }
    };
    let secure = state.config.auth.secure_cookies;
    let mut response_headers = Vec::with_capacity(2);
    if bound {
        response_headers.push((header::SET_COOKIE, identity_link_cookie_clear(flow, secure)));
    }
    response_headers.push((header::LOCATION, location));
    (StatusCode::FOUND, AppendHeaders(response_headers)).into_response()
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    step_up_status,
    start_step_up,
    verify_step_up,
    google_step_up,
    start_oidc_step_up,
    oidc_step_up_callback
))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
