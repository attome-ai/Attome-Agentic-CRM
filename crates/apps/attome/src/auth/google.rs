//! Google OAuth (ID-token credential flow) — sign-in, the public client-id
//! config directory, and self-service account linking.

use attome_auth::{SessionClaims, accounts};
use attome_server::AppState;
use attome_types::AppError;
use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::{AppendHeaders, IntoResponse, Response},
};

use super::LicenseHandle;
use super::dto::{Ack, AuthResponse, GoogleAuthRequest, GoogleConfigInfo, RegistrationConfigInfo};
use super::session::issue_session_cookies_for;
use attome_audit::security::SecurityAuditor;
use attome_auth::auth_context::AuthContext;
use attome_types::ErrorResponse;

#[utoipa::path(
    post,
    path = "/api/v1/auth/google",
    tag = "auth",
    request_body = GoogleAuthRequest,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Login)])))),
    responses(
        (status = 200, description = "Success"),
        (status = 409, description = "Seat limit reached for a first-time account", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn google_login(
    State(state): State<AppState>,
    Extension(license): Extension<LicenseHandle>,
    Extension(auditor): Extension<SecurityAuditor>,
    Json(body): Json<GoogleAuthRequest>,
) -> Result<Response, AppError> {
    // Verified, then consumed: a Google credential is single-use, so a
    // captured token cannot be replayed into a fresh (step-up-capable) session.
    let identity = accounts::verify_google_id_token(
        &state.redis,
        &state.redis_coordination,
        &state.config.auth.oauth_google_client_id,
        &body.credential,
    )
    .await?;

    // M04 Phase 2 (LIC-F2): the seat gate now lives inside
    // `link_google_account`'s own transaction, on the branch that actually
    // inserts a row, under the per-email lock. The read-then-upsert probe that
    // used to sit here (`email_has_existing_account` + a pool-taking seat
    // check) is gone with it: it could not see its own write's uncommitted
    // rows and two concurrent logins could both observe "no existing row"
    // (LIC-F2b). The handler's only remaining job is to hand the engine the
    // current licence.
    let active_license = (*license.load()).clone();

    let user_id = attome_security::accounts::link_google_account(
        &state.db,
        &identity.email,
        &identity.sub,
        &active_license,
    )
    .await?;
    // D-510 rule 2 / BAU-8b: the verified ID token's own `auth_time`, exactly as
    // an OIDC sign-in records it. D-628 (amending D-510 rule 4) lets that
    // locally validated Google time satisfy a step-up, which is what makes a
    // Google-only account able to elevate at all.
    let cookies = issue_session_cookies_for(
        &state,
        user_id,
        &AuthContext::federated(identity.auth_time),
        Some((&auditor, "google")),
    )
    .await?;

    Ok((
        StatusCode::OK,
        AppendHeaders(cookies),
        Json(AuthResponse { user_id }),
    )
        .into_response())
}

/// P-frontend-baseline step 5 (D-071/D-073) — public directory endpoint so the
/// login page can fetch the Google client id at runtime instead of it being
/// duplicated as a hardcoded literal in `environment.ts`. Falls under the
/// `/api/v1/auth/google` bypass entry already in force for `google_login`
/// (prefix match — no bypass-list change needed). Empty config string maps to
/// `None`, same "render no button" handling as an empty OIDC directory.
#[utoipa::path(
    get,
    path = "/api/v1/auth/google/config",
    tag = "auth",
    responses(
        (status = 200, description = "Success", body = GoogleConfigInfo),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn google_config(State(state): State<AppState>) -> Json<GoogleConfigInfo> {
    let client_id = state.config.auth.oauth_google_client_id.clone();
    Json(GoogleConfigInfo {
        client_id: if client_id.is_empty() {
            None
        } else {
            Some(client_id)
        },
    })
}

/// P-registration-gating (D-128) — lets the Angular login page hide the
/// sign-up form/link when `auth.registration_mode` isn't `"public"`, instead
/// of showing it and letting every submission fail with a 403. Falls under
/// the existing `/api/v1/auth/register` bypass-list entry (prefix match — no
/// bypass-list change needed, same reasoning as `google_config` falling under
/// `/api/v1/auth/google`).
#[utoipa::path(
    get,
    path = "/api/v1/auth/register/config",
    tag = "auth",
    responses(
        (status = 200, description = "Success", body = RegistrationConfigInfo),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn register_config(State(state): State<AppState>) -> Json<RegistrationConfigInfo> {
    Json(RegistrationConfigInfo {
        mode: state.config.auth.registration_mode.clone(),
    })
}

/// P-federation-linking-policy §4.3(a) extended to Google — analog of
/// `identity_link_oidc_start`, but Google's
/// credential flow is a single synchronous POST from the Google Identity
/// Services SDK (no authorization-code redirect), so there's no separate
/// start/callback pair to wire: one protected endpoint suffices. Session-gated
/// (`Extension<SessionClaims>`), deliberately NOT under the
/// `/api/v1/auth/google` bypass prefix `google_login`/`google_config` use
/// (guidelines §3: a bypass prefix must never also match a protected route)
/// — mounted at `/api/v1/auth/identity-link/google` instead, alongside the
/// OIDC start routes, for the same reason.
#[utoipa::path(
    post,
    path = "/api/v1/auth/identity-link/google",
    tag = "auth",
    request_body = GoogleAuthRequest,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Credential, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Success"),
        (status = 401, description = "Missing or invalid credentials, a session without a live refresh family, or `reauth_required` when the session has no step-up for `identity_link` within 5 minutes", body = attome_types::UnauthorizedResponse),
        (status = 403, description = "An API-key or S2S caller: only a cookie session may link an identity", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn identity_link_google(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Extension(claims): Extension<SessionClaims>,
    attome_server::step_up::StepUpCaller(caller): attome_server::step_up::StepUpCaller,
    // Self-scoped by design: links only to the caller's own `claims.sub`.
    _ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
    Json(body): Json<GoogleAuthRequest>,
) -> Result<Response, AppError> {
    // Base-auth hardening 2.1d (D-510 rules 3 and 7): checked before the Google
    // token is verified, so an unelevated session contacts nothing.
    attome_auth::step_up::require_recent_auth(
        &state.db,
        caller,
        claims.sub,
        attome_auth::step_up::Operation::IdentityLink,
        state.config.refresh_absolute_lifetime_secs(),
    )
    .await?;
    // Verified, then consumed: a Google credential is single-use, so a
    // captured token cannot be replayed into a fresh (step-up-capable) session.
    let identity = accounts::verify_google_id_token(
        &state.redis,
        &state.redis_coordination,
        &state.config.auth.oauth_google_client_id,
        &body.credential,
    )
    .await?;
    // Same `Credential` + `Create` event the admin identity-link route writes,
    // inside the link's own transaction (D-062).
    let hook = attome_audit::security::account_event_hook(
        auditor.service(),
        attome_audit::security::MandatoryCategory::Credential,
        attome_audit::AuditOperation::Create,
        "user_account",
        "identity_link:google self_service",
    );
    attome_security::accounts::link_google_to_user_with(
        &state.db,
        claims.sub,
        &identity.sub,
        &identity.email,
        &hook,
    )
    .await?;
    Ok((StatusCode::OK, Json(Ack { ok: true })).into_response())
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(google_login, google_config, register_config, identity_link_google))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
