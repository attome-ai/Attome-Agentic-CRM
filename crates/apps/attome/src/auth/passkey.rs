//! Passkey routes (Q6-T1): register, list and remove a person's passkeys, sign
//! in with a passkey alone where a role allows it, finish a password sign-in
//! with a passkey as the second factor, and step up with one. Thin wiring
//! over `attome_auth::webauthn` (the ceremonies), `attome_auth::mfa` (the
//! pending sign-in token) and `attome_auth::step_up` (the elevation).
//!
//! A ceremony is two calls: `.../start` returns the options the browser
//! passes to `navigator.credentials.create` or `get`, and the matching finish
//! route takes the browser's `PublicKeyCredential.toJSON()` as `response`.
//! Adding or removing a passkey needs a fresh step-up (`passkey_manage`), so
//! a stolen session cannot plant a passkey of its own. Every refusal of a
//! passkey is a plain 401; the reason is logged, never returned.

use attome_audit::security::{
    MandatoryCategory, SecurityAuditor, SecurityEvent, account_event_hook, x_audit, x_audit_exempt,
};
use attome_audit::{AuditCategory, AuditOperation, AuditOutcome};
use attome_auth::auth_context::AuthContext;
use attome_auth::session::SessionClaims;
use attome_auth::step_up::{self, Operation};
use attome_auth::webauthn::{self, RelyingParty};
use attome_server::AppState;
use attome_server::authz::{Authorized, SelfService};
use attome_server::middleware::rate_limit::{
    MFA_ATTEMPTS_PER_ACCOUNT_RPM, enforce_account_budget, mfa_account_key,
};
use attome_server::step_up::StepUpCaller;
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{AppendHeaders, IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::dto::AuthResponse;
use super::session::{issue_session_cookies_for, issue_session_for};

/// The relying party passkeys are bound to: `auth.passkey_rp_id` and
/// `auth.passkey_origins`, or else the frontend URL's host and the frontend
/// URL itself. A frontend host that is not a host name (an IP address) with
/// no `auth.passkey_rp_id` leaves passkeys off (503).
pub(super) fn relying_party(state: &AppState) -> Result<RelyingParty, AppError> {
    let frontend = state.config.frontend_url();
    let frontend = frontend.trim_end_matches('/');
    let rp_id = match &state.config.auth.passkey_rp_id {
        Some(rp_id) => rp_id.clone(),
        None => frontend_host(frontend).ok_or(AppError::FeatureUnavailable)?,
    };
    let origins = if state.config.auth.passkey_origins.is_empty() {
        vec![frontend.to_owned()]
    } else {
        state.config.auth.passkey_origins.clone()
    };
    RelyingParty::new(&rp_id, origins).map_err(|_| {
        tracing::warn!(
            rp_id,
            "passkeys are off: the relying party id is not a host name"
        );
        AppError::FeatureUnavailable
    })
}

/// The host of `url` (`https://crm.example.com:8443/x` gives
/// `crm.example.com`). Pure.
fn frontend_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => host,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// One of the caller's passkeys. The key itself never leaves the server.
#[derive(Serialize, ToSchema)]
pub(super) struct PasskeyItem {
    id: Uuid,
    /// The name the person gave it, if any.
    label: Option<String>,
    /// How the browser reaches the authenticator: `internal`, `hybrid`,
    /// `usb`, `nfc`, `ble`, `smart-card`.
    transports: Vec<String>,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

/// The options a ceremony's browser call takes.
#[derive(Serialize, ToSchema)]
pub(super) struct PasskeyOptions {
    /// Pass to `navigator.credentials.create` (registration) or `get`
    /// (sign-in and step-up) after decoding its base64url fields.
    #[schema(value_type = Object)]
    options: serde_json::Value,
}

/// A new passkey: the browser's response to the registration options.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyRegisterBody {
    /// A name for it, such as "Work laptop" (at most 100 characters).
    #[serde(default)]
    label: Option<String>,
    /// `PublicKeyCredential.toJSON()` of `navigator.credentials.create`.
    #[schema(value_type = Object)]
    response: serde_json::Value,
}

/// The registered passkey.
#[derive(Serialize, ToSchema)]
pub(super) struct PasskeyRegistered {
    id: Uuid,
}

/// A passkey assertion: the browser's response to the request options.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyAssertionBody {
    /// `PublicKeyCredential.toJSON()` of `navigator.credentials.get`.
    #[schema(value_type = Object)]
    response: serde_json::Value,
}

/// Starts a passkey second factor for a password sign-in.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyMfaStartBody {
    /// The `pending_token` of the `mfa: "required"` sign-in answer.
    pending_token: String,
}

/// Finishes a password sign-in with a passkey.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyMfaVerifyBody {
    pending_token: String,
    /// `PublicKeyCredential.toJSON()` of `navigator.credentials.get`.
    #[schema(value_type = Object)]
    response: serde_json::Value,
    /// Remember this browser, where the person's policy allows it.
    #[serde(default)]
    remember: bool,
}

/// The caller's session is elevated until `elevated_until`.
#[derive(Serialize, ToSchema)]
pub(super) struct PasskeyElevation {
    operation: String,
    elevated_until: DateTime<Utc>,
}

const LABEL_MAX: usize = 100;

fn response_bytes(response: &serde_json::Value) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(response).map_err(AppError::internal)
}

// ── The caller's own passkeys ───────────────────────────────────────────────

/// My passkeys
///
/// Q6-T1: the caller's passkeys, newest first, with the name, the transports
/// and when each was added and last used.
#[utoipa::path(
    get,
    path = "/api/v1/auth/passkeys",
    operation_id = "list_my_passkeys",
    tag = "auth",
    params(OnePageQuery),
    responses(
        (status = 200, description = "The caller's passkeys", body = PaginatedResponse<PasskeyItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_passkeys(
    State(state): State<AppState>,
    Extension(claims): Extension<SessionClaims>,
    // Self-scoped: the list is keyed on `claims.sub` only.
    _ctx: Authorized<SelfService>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<PasskeyItem>>, AppError> {
    let page = webauthn::list(&state.db, claims.sub, query.window()).await?;
    Ok(Json(PaginatedResponse::new(
        page.items
            .into_iter()
            .map(|passkey| PasskeyItem {
                id: passkey.id,
                label: passkey.label,
                transports: passkey.transports,
                created_at: passkey.created_at,
                last_used_at: passkey.last_used_at,
            })
            .collect(),
        page.total,
        page.page,
        page.page_size,
    )))
}

/// Start adding a passkey
///
/// Q6-T1: the creation options for `navigator.credentials.create`. Needs a
/// fresh step-up for `passkey_manage` (`reauth_required` otherwise). The
/// caller's passkeys are excluded, so one authenticator is not added twice.
#[utoipa::path(
    post,
    path = "/api/v1/auth/passkeys/register/start",
    operation_id = "start_passkey_registration",
    tag = "auth",
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "starts a ceremony: one single-use challenge that expires in 300 seconds, no credential or session changes; the audited change is register/finish",
    )))),
    responses(
        (status = 200, description = "The creation options", body = PasskeyOptions),
        (status = 401, description = "No session, or `reauth_required`: step up for `passkey_manage` first", body = ErrorResponse),
        (status = 403, description = "An API-key or S2S caller", body = ErrorResponse),
        (status = 503, description = "Passkeys are not configured on this deployment", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn start_registration(
    State(state): State<AppState>,
    Extension(claims): Extension<SessionClaims>,
    StepUpCaller(caller): StepUpCaller,
    // Self-scoped: the passkey is the caller's own.
    _ctx: Authorized<SelfService>,
) -> Result<Json<PasskeyOptions>, AppError> {
    step_up::require_recent_auth(
        &state.db,
        caller,
        claims.sub,
        Operation::PasskeyManage,
        state.config.refresh_absolute_lifetime_secs(),
    )
    .await?;
    let rp = relying_party(&state)?;
    let name = attome_auth::accounts::active_account_email(&state.db, claims.sub)
        .await?
        .filter(|email| !email.is_empty())
        .ok_or(AppError::Unauthorized)?;
    let options = webauthn::start_registration(&state.db, &rp, claims.sub, &name, None).await?;
    Ok(Json(PasskeyOptions { options }))
}

/// Finish adding a passkey
///
/// Q6-T1: stores the passkey the browser created. Needs the same fresh
/// step-up as the start. The passkey and its `Credential` + `Create` event
/// commit together.
#[utoipa::path(
    post,
    path = "/api/v1/auth/passkeys/register/finish",
    operation_id = "finish_passkey_registration",
    tag = "auth",
    request_body = PasskeyRegisterBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The passkey is added", body = PasskeyRegistered),
        (status = 401, description = "No session, `reauth_required`, or the response does not answer a live challenge", body = ErrorResponse),
        (status = 403, description = "An API-key or S2S caller", body = ErrorResponse),
        (status = 409, description = "That passkey is already registered", body = ErrorResponse),
        (status = 422, description = "A malformed response or a label over 100 characters", body = ErrorResponse),
        (status = 503, description = "Passkeys are not configured on this deployment", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn finish_registration(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Extension(claims): Extension<SessionClaims>,
    StepUpCaller(caller): StepUpCaller,
    // Self-scoped, as for the start.
    _ctx: Authorized<SelfService>,
    Json(body): Json<PasskeyRegisterBody>,
) -> Result<(StatusCode, Json<PasskeyRegistered>), AppError> {
    step_up::require_recent_auth(
        &state.db,
        caller,
        claims.sub,
        Operation::PasskeyManage,
        state.config.refresh_absolute_lifetime_secs(),
    )
    .await?;
    let label = body
        .label
        .as_deref()
        .map(str::trim)
        .filter(|label| !label.is_empty());
    if label.is_some_and(|label| label.chars().count() > LABEL_MAX) {
        return Err(AppError::Validation(
            "label is at most 100 characters".into(),
        ));
    }
    let rp = relying_party(&state)?;
    let hook = account_event_hook(
        auditor.service(),
        MandatoryCategory::Credential,
        AuditOperation::Create,
        "user_account",
        "passkey added",
    );
    let id = webauthn::finish_registration_with(
        &state.db,
        &rp,
        claims.sub,
        &response_bytes(&body.response)?,
        label,
        &hook,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(PasskeyRegistered { id })))
}

/// Remove a passkey
///
/// Q6-T1: removes one of the caller's passkeys (404 for any other). Needs a
/// fresh step-up for `passkey_manage`. The removal and its `Credential` +
/// `SoftDelete` event commit together.
#[utoipa::path(
    delete,
    path = "/api/v1/auth/passkeys/{id}",
    operation_id = "delete_my_passkey",
    tag = "auth",
    params(("id" = Uuid, Path, description = "The passkey")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "The passkey is removed"),
        (status = 401, description = "No session, or `reauth_required`: step up for `passkey_manage` first", body = ErrorResponse),
        (status = 403, description = "An API-key or S2S caller", body = ErrorResponse),
        (status = 404, description = "The caller has no such passkey", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn delete_passkey(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Extension(claims): Extension<SessionClaims>,
    StepUpCaller(caller): StepUpCaller,
    // Self-scoped: only a passkey of `claims.sub` can match.
    _ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    step_up::require_recent_auth(
        &state.db,
        caller,
        claims.sub,
        Operation::PasskeyManage,
        state.config.refresh_absolute_lifetime_secs(),
    )
    .await?;
    let hook = account_event_hook(
        auditor.service(),
        MandatoryCategory::Credential,
        AuditOperation::SoftDelete,
        "user_account",
        "passkey removed",
    );
    let mut tx = attome_db::tx::begin(&state.db).await?;
    if !webauthn::delete_in_tx(&mut tx, claims.sub, id).await? {
        return Err(AppError::NotFound);
    }
    attome_db::BeforeCommit::before_commit(&hook, &mut tx, &claims.sub).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Signing in with a passkey alone ─────────────────────────────────────────

/// Start a passkey sign-in
///
/// Q6-T1: the request options for `navigator.credentials.get`, naming no
/// person: the browser offers the passkeys it holds for this site.
#[utoipa::path(
    post,
    path = "/api/v1/auth/passkey/start",
    operation_id = "start_passkey_sign_in",
    tag = "auth",
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "starts a ceremony: one single-use challenge that expires in 300 seconds naming no one; the audited sign-in is passkey/verify",
    )))),
    responses(
        (status = 200, description = "The request options", body = PasskeyOptions),
        (status = 503, description = "Passkeys are not configured on this deployment", body = ErrorResponse),
    ),
)]
pub(super) async fn start_sign_in(
    State(state): State<AppState>,
) -> Result<Json<PasskeyOptions>, AppError> {
    let rp = relying_party(&state)?;
    let options = webauthn::start_assertion(&state.db, &rp, None).await?;
    Ok(Json(PasskeyOptions { options }))
}

/// Sign in with a passkey
///
/// Q6-T1: signs in with a passkey alone, when a role the person holds allows
/// it (`passkey_sign_in` on the role's sign-in policy) and no single sign-on
/// rule applies. The passkey verified the person, so a refusal by policy is
/// `403` rather than a disguised `401`. The session's `amr` is `hwk`.
#[utoipa::path(
    post,
    path = "/api/v1/auth/passkey/verify",
    operation_id = "finish_passkey_sign_in",
    tag = "auth",
    request_body = PasskeyAssertionBody,
    extensions(("x-audit" = json!(x_audit(&[
        (AuditCategory::Security, AuditOperation::Login),
        (AuditCategory::Security, AuditOperation::FailedLogin),
    ])))),
    responses(
        (status = 200, description = "Signed in"),
        (status = 401, description = "The response does not answer a live challenge with a live passkey of an active account", body = ErrorResponse),
        (status = 403, description = "No role of the person allows a passkey alone, or the person signs in through single sign-on", body = ErrorResponse),
        (status = 422, description = "A malformed response", body = ErrorResponse),
        (status = 503, description = "Passkeys are not configured on this deployment", body = ErrorResponse),
    ),
)]
pub(super) async fn finish_sign_in(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Json(body): Json<PasskeyAssertionBody>,
) -> Result<Response, AppError> {
    use attome_security::auth_policy::{PasskeySignIn, passkey_sign_in};

    let rp = relying_party(&state)?;
    let asserted =
        webauthn::finish_assertion(&state.db, &rp, None, &response_bytes(&body.response)?).await?;
    let user_id = asserted.user_ref;
    let Some(email) = attome_auth::accounts::active_account_email(&state.db, user_id).await? else {
        tracing::warn!(%user_id, "passkey sign-in refused: the account is not active");
        return Err(AppError::Unauthorized);
    };
    let decision = passkey_sign_in(&state.db, user_id, &email).await?;
    let refusal = match decision {
        PasskeySignIn::Allowed => None,
        PasskeySignIn::NotAllowed => Some("passkey_sign_in_not_allowed"),
        PasskeySignIn::SsoOnly => Some("passkey_sign_in_refused_sso_only"),
    };
    if let Some(name) = refusal {
        auditor
            .write(
                SecurityEvent::new(
                    MandatoryCategory::Security,
                    AuditOperation::FailedLogin,
                    user_id,
                    "user_account",
                    Some(user_id),
                )
                .named(name)
                .outcome(AuditOutcome::Failed),
            )
            .await?;
        return Err(AppError::Forbidden);
    }
    let cookies = issue_session_cookies_for(
        &state,
        user_id,
        &AuthContext::passkey(),
        Some((&auditor, "passkey")),
    )
    .await?;
    Ok((
        StatusCode::OK,
        AppendHeaders(cookies),
        Json(AuthResponse { user_id }),
    )
        .into_response())
}

// ── A passkey as the second factor of a password sign-in ────────────────────

/// Start a passkey second factor
///
/// Q6-T1: with the `mfa: "required"` pending token, the request options for
/// `navigator.credentials.get`, limited to the person's own passkeys. The
/// token stays usable for `mfa/passkey/verify` and the other second factors.
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/passkey/start",
    operation_id = "start_passkey_second_factor",
    tag = "auth",
    request_body = PasskeyMfaStartBody,
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "starts a ceremony: one single-use challenge that expires in 300 seconds; the audited sign-in is mfa/passkey/verify",
    )))),
    responses(
        (status = 200, description = "The request options", body = PasskeyOptions),
        (status = 401, description = "The pending token is not a live sign-in token", body = ErrorResponse),
        (status = 503, description = "Passkeys are not configured on this deployment", body = ErrorResponse),
    ),
)]
pub(super) async fn start_second_factor(
    State(state): State<AppState>,
    Json(body): Json<PasskeyMfaStartBody>,
) -> Result<Json<PasskeyOptions>, AppError> {
    let rp = relying_party(&state)?;
    let user_id = attome_auth::mfa::pending_login_subject(
        &state.redis_coordination,
        &body.pending_token,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
    )
    .await?;
    let options = webauthn::start_assertion(&state.db, &rp, Some(user_id)).await?;
    Ok(Json(PasskeyOptions { options }))
}

/// Finish sign-in with a passkey
///
/// Q6-T1: completes an `mfa: "required"` password sign-in with one of the
/// person's passkeys. Shares the second-factor attempt budget with
/// `mfa/verify`; a refused passkey spends one of the token's attempts. The
/// session's `amr` is `pwd`, `hwk`.
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/passkey/verify",
    operation_id = "finish_passkey_second_factor",
    tag = "auth",
    request_body = PasskeyMfaVerifyBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Login)])))),
    responses(
        (status = 200, description = "Signed in"),
        (status = 401, description = "The pending token or the passkey was refused", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
        (status = 429, description = "Too many second-factor attempts for this account", body = ErrorResponse),
        (status = 503, description = "Passkeys are not configured on this deployment", body = ErrorResponse),
    ),
)]
pub(super) async fn finish_second_factor(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    headers: HeaderMap,
    Json(body): Json<PasskeyMfaVerifyBody>,
) -> Result<Response, AppError> {
    if let Some(user_id) = super::local::pending_token_subject(&body.pending_token)
        && let Some(rejected) = enforce_account_budget(
            &state.redis_coordination,
            &mfa_account_key(user_id),
            MFA_ATTEMPTS_PER_ACCOUNT_RPM,
            "mfa_passkey_verify",
        )
        .await?
    {
        return Ok(rejected);
    }
    let rp = relying_party(&state)?;
    let user_id = match attome_auth::mfa::complete_pending_login_passkey(
        &state.db,
        &rp,
        &state.redis_coordination,
        &body.pending_token,
        &response_bytes(&body.response)?,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
        state.config.auth.mfa_challenge_max_attempts,
    )
    .await
    {
        Ok(user_id) => user_id,
        Err(e) => {
            return Err(super::local::record_failed_second_factor(
                &state,
                &auditor,
                &body.pending_token,
                attome_auth::session::TokenType::MfaPendingLogin,
                "mfa_verify_failed passkey",
                e,
            )
            .await);
        }
    };
    let issued = issue_session_for(
        &state,
        user_id,
        &AuthContext::password_and_passkey(),
        Some((&auditor, "password+passkey")),
    )
    .await?;
    let mut cookies = issued.cookies.to_vec();
    if body.remember
        && let Some(cookie) =
            super::local::remember_browser(&state, &auditor, &headers, user_id, issued.family_id)
                .await?
    {
        cookies.push(cookie);
    }
    Ok((
        StatusCode::OK,
        AppendHeaders(cookies),
        Json(AuthResponse { user_id }),
    )
        .into_response())
}

// ── Step-up with a passkey ──────────────────────────────────────────────────

/// Start a passkey step-up
///
/// Q6-T1: the request options for a passkey step-up for `operation` on the
/// caller's own session, limited to the caller's passkeys. An account with
/// no passkey, or an operation that does not accept one, is `reauth_required`
/// naming what it accepts.
#[utoipa::path(
    post,
    path = "/api/v1/auth/step-up/{operation}/passkey",
    operation_id = "start_passkey_step_up",
    tag = "auth",
    params(("operation" = String, Path, description = "The operation to step up for.")),
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "starts a ceremony: one single-use challenge that expires in 300 seconds; the audited change is the verify route's elevation",
    )))),
    responses(
        (status = 200, description = "The request options", body = PasskeyOptions),
        (status = 401, description = "No live session with a refresh family, or `reauth_required`", body = ErrorResponse),
        (status = 403, description = "An API-key or S2S caller, which can never step up", body = ErrorResponse),
        (status = 404, description = "Not a step-up operation", body = ErrorResponse),
        (status = 503, description = "Passkeys are not configured on this deployment", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn start_step_up(
    State(state): State<AppState>,
    Extension(claims): Extension<SessionClaims>,
    StepUpCaller(caller): StepUpCaller,
    // Self-scoped: the caller's own session and passkeys.
    _ctx: Authorized<SelfService>,
    Path(operation): Path<String>,
) -> Result<Json<PasskeyOptions>, AppError> {
    let operation = super::step_up::step_up_operation(&operation)?;
    let rp = relying_party(&state)?;
    let options = step_up::start_passkey_step_up(
        &state.db,
        &rp,
        caller,
        claims.sub,
        operation,
        state.config.refresh_absolute_lifetime_secs(),
    )
    .await?;
    Ok(Json(PasskeyOptions { options }))
}

/// Verify a passkey step-up
///
/// Q6-T1: answers a passkey step-up and elevates the caller's session for
/// `operation`, with `hwk` as its last `amr`. Every refusal is
/// `reauth_required` and elevates nothing.
#[utoipa::path(
    post,
    path = "/api/v1/auth/step-up/{operation}/passkey/verify",
    operation_id = "verify_passkey_step_up",
    tag = "auth",
    params(("operation" = String, Path, description = "The operation the step-up was started for.")),
    request_body = PasskeyAssertionBody,
    extensions(("x-audit" = json!(x_audit(&[
        (AuditCategory::Security, AuditOperation::Login),
        (AuditCategory::Security, AuditOperation::FailedLogin),
    ])))),
    responses(
        (status = 200, description = "Session elevated", body = PasskeyElevation),
        (status = 401, description = "`reauth_required`, or no live session with a refresh family", body = ErrorResponse),
        (status = 403, description = "An API-key or S2S caller, which can never step up", body = ErrorResponse),
        (status = 404, description = "Not a step-up operation", body = ErrorResponse),
        (status = 429, description = "Too many second-factor attempts for this account", body = ErrorResponse),
        (status = 503, description = "Passkeys are not configured on this deployment", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn verify_step_up(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Extension(claims): Extension<SessionClaims>,
    StepUpCaller(caller): StepUpCaller,
    // Self-scoped, as for the start.
    _ctx: Authorized<SelfService>,
    Path(operation): Path<String>,
    Json(body): Json<PasskeyAssertionBody>,
) -> Result<Response, AppError> {
    let operation = super::step_up::step_up_operation(&operation)?;
    if let Some(rejected) = enforce_account_budget(
        &state.redis_coordination,
        &mfa_account_key(claims.sub),
        MFA_ATTEMPTS_PER_ACCOUNT_RPM,
        "step_up_passkey_verify",
    )
    .await?
    {
        return Ok(rejected);
    }
    let rp = relying_party(&state)?;
    // As for the other step-up factors: a success is `Security` + `Login` in
    // the elevation's transaction; a refusal is `FailedLogin`, on its own.
    let hook = account_event_hook(
        auditor.service(),
        MandatoryCategory::Security,
        AuditOperation::Login,
        "user_account",
        format!("step_up {} passkey", operation.as_str()),
    );
    let elevated_until = match step_up::complete_passkey_step_up(
        &state.db,
        &rp,
        caller,
        claims.sub,
        operation,
        &response_bytes(&body.response)?,
        state.config.refresh_absolute_lifetime_secs(),
        &hook,
    )
    .await
    {
        Ok(elevated_until) => elevated_until,
        Err(e @ (AppError::Unauthorized | AppError::ReauthRequired { .. })) => {
            auditor
                .write(
                    SecurityEvent::new(
                        MandatoryCategory::Security,
                        AuditOperation::FailedLogin,
                        claims.sub,
                        "user_account",
                        Some(claims.sub),
                    )
                    .named(format!("step_up_failed {} passkey", operation.as_str()))
                    .outcome(AuditOutcome::Failed),
                )
                .await?;
            return Err(e);
        }
        Err(e) => return Err(e),
    };
    Ok(Json(PasskeyElevation {
        operation: operation.as_str().to_owned(),
        elevated_until,
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::frontend_host;

    #[test]
    fn frontend_host_takes_the_host_name() {
        assert_eq!(
            frontend_host("https://crm.example.com"),
            Some("crm.example.com".into())
        );
        assert_eq!(
            frontend_host("http://localhost:4199/xrm?x=1"),
            Some("localhost".into())
        );
        assert_eq!(
            frontend_host("https://CRM.Example.com:8443/"),
            Some("crm.example.com".into())
        );
        assert_eq!(frontend_host("https://"), None);
    }
}

/// This file's slice of the workspace OpenAPI document (see
/// `session::openapi_fragment`).
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_passkeys,
    start_registration,
    finish_registration,
    delete_passkey,
    start_sign_in,
    finish_sign_in,
    start_second_factor,
    finish_second_factor,
    start_step_up,
    verify_step_up
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
