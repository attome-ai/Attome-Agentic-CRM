//! Portal account routes (D-588 item 2, plan G-11): self-service signup and
//! its verification, consent, password change, sessions, and the erasure
//! request. A child of [`super`], so it shares the portal resolution,
//! session, origin, budget and audit plumbing there.

use attome_audit::security::{MandatoryCategory, x_audit};
use attome_audit::{AuditCategory, AuditOperation, AuditOutcome};
use attome_core::EngineState;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use utoipa::ToSchema;
use uuid::Uuid;

use super::{
    PortalAck, account_key, authenticate, budget, check_same_origin, email_link, event, link, mint,
    portal_budget, portal_for, secure_cookies, set_cookie, validate_password, write,
};
use crate::account::{self, PasswordChange, PortalSessionItem};
use crate::policy;
use crate::session;
use crate::signup::{self, SignupInput, SignupRequest};

/// Signup requests per address hash, per minute (over budget answers like
/// success, so the throttle says nothing about the address).
const ACCOUNT_SIGNUP_RPM: i32 = 3;
/// Signup requests per client IP, per minute.
const IP_SIGNUP_RPM: i32 = 10;

#[derive(Deserialize, ToSchema)]
pub struct SignupBody {
    pub name: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub terms_version: Option<String>,
    #[serde(default)]
    pub privacy_version: Option<String>,
    /// The CAPTCHA widget's token, when the deployment configures one.
    #[serde(default)]
    pub captcha_token: Option<String>,
}

impl std::fmt::Debug for SignupBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupBody").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct SignupVerifyBody {
    pub token: String,
}

impl std::fmt::Debug for SignupVerifyBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupVerifyBody").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct ConsentBody {
    #[serde(default)]
    pub terms_version: Option<String>,
    #[serde(default)]
    pub privacy_version: Option<String>,
}

impl std::fmt::Debug for ConsentBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentBody").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct ConsentState {
    pub terms_version: Option<String>,
    pub privacy_version: Option<String>,
    /// The signed-in user has accepted the current versions (always true when
    /// the portal requires none).
    pub accepted: bool,
}

impl std::fmt::Debug for ConsentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentState").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct PasswordChangeBody {
    pub current_password: String,
    pub new_password: String,
}

impl std::fmt::Debug for PasswordChangeBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordChangeBody").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct ErasureRequested {
    pub request_id: Uuid,
}

impl std::fmt::Debug for ErasureRequested {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErasureRequested").finish_non_exhaustive()
    }
}

fn email_lower(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// Sign up to a web portal
///
/// Asks for an account with an email, a password and the portal's current consent versions. The
/// answer is 202 whatever happened (a verification link, a notice to an existing account, or nothing),
/// so it reveals no account. A password that fails the policy, a consent that does not match, or a
/// failed CAPTCHA is 422.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/auth/signup",
    operation_id = "portal_signup_request",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = SignupBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 202, description = "Accepted. The same answer whatever happened: a verification link, a notice to an existing account, or nothing", body = PortalAck),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 422, description = "The password fails policy, the consent doesn't match the portal's current versions, or the CAPTCHA failed", body = ErrorResponse),
    ),
)]
async fn signup_request(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    connect: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<SignupBody>,
) -> Result<(StatusCode, Json<PortalAck>), AppError> {
    let portal = portal_for(&state, &keyword).await?;
    check_same_origin(&state, &portal, &headers)?;
    portal_budget(&state, &portal).await?;
    let ip = connect.map(|c| {
        attome_server::middleware::client_ip::client_ip_from_parts(
            c.0.0.ip(),
            &headers,
            &state.base.config,
        )
    });
    if let Some(ip) = ip {
        budget(
            &state,
            format!("attome-portal:rl:signup-ip:{}:{ip}", portal.id),
            IP_SIGNUP_RPM,
        )
        .await?;
    }
    let accepted = (StatusCode::ACCEPTED, Json(PortalAck { ok: true }));
    let email = email_lower(&body.email);
    if budget(
        &state,
        account_key("signup", &portal, &email),
        ACCOUNT_SIGNUP_RPM,
    )
    .await
    .is_err()
    {
        return Ok(accepted);
    }
    let ip_text = ip.map(|i| i.to_string());
    let pow_secret = state
        .base
        .secrets
        .load()
        .jwt_secret
        .active()
        .map(str::to_owned);
    if !attome_auth::captcha::verify_challenge(
        &state.base.config.portal.captcha,
        state.base.config.deployment.sovereign,
        &state.base.redis_coordination,
        pow_secret.as_deref(),
        body.captcha_token.as_deref(),
        ip_text.as_deref(),
    )
    .await
    {
        return Err(AppError::Validation("the CAPTCHA check failed".into()));
    }
    let password = validate_password(&body.password)?;
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(AppError::Validation("name is required".into()));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let policy = policy::load(&mut tx, portal.id).await?;
    if !signup::consent_matches(
        &policy,
        body.terms_version.as_deref(),
        body.privacy_version.as_deref(),
    ) {
        return Err(AppError::Validation(
            "accept the portal's current terms and privacy versions".into(),
        ));
    }
    let hash = attome_auth::hash_password_async(password).await?;
    let outcome = signup::request(
        &mut tx,
        &state.base.pepper_ring(),
        &portal,
        &policy,
        &SignupInput {
            name,
            email_lower: &email,
            password_hash: &hash,
            terms_version: body.terms_version.as_deref(),
            privacy_version: body.privacy_version.as_deref(),
        },
    )
    .await?;
    match outcome {
        SignupRequest::Pending { bearer } => {
            let link = link(&state, &portal, "verify-signup", &bearer);
            email_link(
                &mut tx,
                attome_email::delivery::EmailDeliveryKind::EmailVerification,
                &email,
                crate::email::email_verification(&portal.name, &link),
            )
            .await?;
        }
        SignupRequest::AlreadyRegistered => {
            email_link(
                &mut tx,
                attome_email::delivery::EmailDeliveryKind::Generic,
                &email,
                crate::email::notice(
                    &portal.name,
                    "you already have an account",
                    "Someone asked to create an account with this address, which already \
                     has one. Sign in, or reset your password if you've forgotten it. If this \
                     wasn't you, you can ignore this email.",
                ),
            )
            .await?;
        }
        SignupRequest::Refused => {}
    }
    // One event per request, with no account named: at this point there is
    // none, and naming an existing one would record who has an account.
    write(
        &state,
        &mut tx,
        event(MandatoryCategory::Credential, AuditOperation::Create, None)
            .named("portal signup requested")
            .outcome(AuditOutcome::Succeeded),
    )
    .await?;
    tx.commit().await.map_err(sqlx_err)?;
    Ok(accepted)
}

fn sqlx_err(e: sqlx::Error) -> AppError {
    AppError::internal(e)
}

/// Verify a portal signup
///
/// Creates the account from the emailed verification link; sign in with the password given at signup.
/// An invalid, used or expired link, or a portal whose signup closed, is 422.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/auth/signup/verify",
    operation_id = "portal_signup_verify",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = SignupVerifyBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 204, description = "Account created; sign in with the password given at signup"),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 422, description = "The link is invalid, used or expired, or signup is no longer open", body = ErrorResponse),
    ),
)]
async fn signup_verify(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SignupVerifyBody>,
) -> Result<StatusCode, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    check_same_origin(&state, &portal, &headers)?;
    portal_budget(&state, &portal).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let policy = policy::load(&mut tx, portal.id).await?;
    let Some(user_id) = signup::verify(
        &mut tx,
        &state.base.pepper_ring(),
        &portal,
        &policy,
        &body.token,
    )
    .await?
    else {
        // The link is spent even when no account could be created.
        tx.commit().await.map_err(sqlx_err)?;
        return Err(AppError::Validation(
            "the link is invalid or has expired".into(),
        ));
    };
    write(
        &state,
        &mut tx,
        event(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            Some(user_id),
        )
        .named("portal account created by signup")
        .outcome(AuditOutcome::Succeeded),
    )
    .await?;
    tx.commit().await.map_err(sqlx_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Verify an added email address
///
/// The emailed link that adds an address to a portal account: the address is written, verified, only
/// now, and the address it replaces, if any, is told.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/auth/email/verify",
    operation_id = "portal_email_add_verify",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = SignupVerifyBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "The email is on the account"),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 409, description = "Another account has used this address since the link was sent", body = ErrorResponse),
        (status = 422, description = "The link is invalid, used or expired", body = ErrorResponse),
    ),
)]
async fn email_add_verify(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SignupVerifyBody>,
) -> Result<StatusCode, AppError> {
    use crate::trusted_account::{self, EmailConfirm};
    let portal = portal_for(&state, &keyword).await?;
    check_same_origin(&state, &portal, &headers)?;
    portal_budget(&state, &portal).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let outcome = trusted_account::confirm_email_add(
        &mut tx,
        &state.base.pepper_ring(),
        portal.id,
        &body.token,
    )
    .await?;
    match outcome {
        EmailConfirm::Added {
            user_id, previous, ..
        } => {
            write(
                &state,
                &mut tx,
                event(
                    MandatoryCategory::Credential,
                    AuditOperation::Update,
                    Some(user_id),
                )
                .named("portal account email added")
                .outcome(AuditOutcome::Succeeded),
            )
            .await?;
            if let Some(previous) = previous.filter(|_| state.base.config.email.enabled) {
                email_link(
                    &mut tx,
                    attome_email::delivery::EmailDeliveryKind::Generic,
                    &previous,
                    crate::email::notice(
                        &portal.name,
                        "your email was changed",
                        "The email address of your account was changed to a new one. If this \
                         wasn't you, contact support right away.",
                    ),
                )
                .await?;
            }
            tx.commit().await.map_err(sqlx_err)?;
            Ok(StatusCode::NO_CONTENT)
        }
        EmailConfirm::InUse => {
            // The link is spent either way.
            tx.commit().await.map_err(sqlx_err)?;
            Err(AppError::Conflict(
                "this address is already used by another account",
            ))
        }
        EmailConfirm::Invalid => {
            tx.commit().await.map_err(sqlx_err)?;
            Err(AppError::Validation(
                "the link is invalid or has expired".into(),
            ))
        }
    }
}

#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/me/consent",
    operation_id = "portal_consent_state",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    responses(
        (status = 200, description = "The portal's current versions, and whether they're accepted", body = ConsentState),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn consent_state(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ConsentState>, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, false).await?;
    let mut conn = state.base.db.acquire().await.map_err(sqlx_err)?;
    let policy = policy::load(&mut conn, portal.id).await?;
    let accepted = signup::has_current_consent(&mut conn, &policy, principal.user_id).await?;
    Ok(Json(ConsentState {
        terms_version: policy.terms_version,
        privacy_version: policy.privacy_version,
        accepted,
    }))
}

#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/me/consent",
    operation_id = "portal_consent_accept",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = ConsentBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Accepted"),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 422, description = "Not the portal's current versions", body = ErrorResponse),
    ),
)]
async fn consent_accept(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ConsentBody>,
) -> Result<StatusCode, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, false).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let policy = policy::load(&mut tx, portal.id).await?;
    if !policy.requires_consent()
        || !signup::consent_matches(
            &policy,
            body.terms_version.as_deref(),
            body.privacy_version.as_deref(),
        )
    {
        return Err(AppError::Validation(
            "these are not the portal's current terms and privacy versions".into(),
        ));
    }
    signup::record_consent(
        &mut tx,
        portal.id,
        principal.user_id,
        body.terms_version.as_deref(),
        body.privacy_version.as_deref(),
    )
    .await?;
    write(
        &state,
        &mut tx,
        event(
            MandatoryCategory::Credential,
            AuditOperation::Update,
            Some(principal.user_id),
        )
        .named("portal consent accepted")
        .outcome(AuditOutcome::Succeeded),
    )
    .await?;
    tx.commit().await.map_err(sqlx_err)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/me/password",
    operation_id = "portal_change_password",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = PasswordChangeBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::PasswordReset)])))),
    responses(
        (status = 204, description = "Changed; every other session ended, this one re-issued"),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 422, description = "Wrong current password, or the new one fails policy", body = ErrorResponse),
    ),
)]
async fn change_password(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PasswordChangeBody>,
) -> Result<Response, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, false).await?;
    budget(
        &state,
        format!(
            "attome-portal:rl:password:{}:{}",
            portal.id, principal.user_id
        ),
        super::ACCOUNT_LOGIN_RPM,
    )
    .await?;
    let new_password = validate_password(&body.new_password)?;
    let new_hash = attome_auth::hash_password_async(new_password).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let epoch =
        match account::change_password(&mut tx, &principal, &body.current_password, &new_hash)
            .await?
        {
            PasswordChange::Changed { epoch } => epoch,
            PasswordChange::WrongPassword => {
                write(
                    &state,
                    &mut tx,
                    event(
                        MandatoryCategory::Credential,
                        AuditOperation::PasswordReset,
                        Some(principal.user_id),
                    )
                    .named("portal password change refused: wrong current password")
                    .outcome(AuditOutcome::Failed),
                )
                .await?;
                tx.commit().await.map_err(sqlx_err)?;
                return Err(AppError::Validation("the current password is wrong".into()));
            }
        };
    write(
        &state,
        &mut tx,
        event(
            MandatoryCategory::Credential,
            AuditOperation::PasswordReset,
            Some(principal.user_id),
        )
        .named("portal password changed")
        .outcome(AuditOutcome::Succeeded),
    )
    .await?;
    tx.commit().await.map_err(sqlx_err)?;
    // The epoch moved, so this session's access token is dead too: re-issue
    // it for the same refresh family. The refresh cookie is unchanged.
    let access = mint(
        &state,
        &portal,
        principal.user_id,
        epoch,
        principal.family_id,
    )?;
    let secure = secure_cookies(&state);
    let names = session::cookie_names(&portal.keyword, secure);
    let mut response = StatusCode::NO_CONTENT.into_response();
    set_cookie(
        &mut response,
        attome_auth::cookie::build(
            &names.session,
            &access,
            session::ACCESS_TTL_SECS as u64,
            secure,
            &session::session_cookie_path(&portal.keyword),
        ),
    )?;
    Ok(response)
}

#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/me/sessions",
    operation_id = "portal_list_sessions",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    responses(
        (status = 200, description = "The signed-in user's live sessions", body = [PortalSessionItem]),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn list_sessions(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<PortalSessionItem>>, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, true).await?;
    let mut conn = state.base.db.acquire().await.map_err(sqlx_err)?;
    Ok(Json(account::list_sessions(&mut conn, &principal).await?))
}

#[utoipa::path(
    delete,
    path = "/{keyword}/api/v1/me/sessions/{id}",
    operation_id = "portal_end_session",
    tag = "auth",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("id" = Uuid, Path, description = "Session id from the list"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::SessionRevoked)])))),
    responses(
        (status = 204, description = "Ended"),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal, or no such live session of yours", body = ErrorResponse),
    ),
)]
async fn end_session(
    State(state): State<EngineState>,
    Path((keyword, family_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, true).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if !account::end_session(&mut tx, &principal, family_id).await? {
        return Err(AppError::NotFound);
    }
    write(
        &state,
        &mut tx,
        event(
            MandatoryCategory::Credential,
            AuditOperation::SessionRevoked,
            Some(principal.user_id),
        )
        .named("portal session ended by its user")
        .outcome(AuditOutcome::Succeeded),
    )
    .await?;
    tx.commit().await.map_err(sqlx_err)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/me/sessions/end-others",
    operation_id = "portal_end_other_sessions",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::SessionRevoked)])))),
    responses(
        (status = 204, description = "Every other session ended"),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn end_other_sessions(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, true).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    account::end_other_sessions(&mut tx, &principal).await?;
    write(
        &state,
        &mut tx,
        event(
            MandatoryCategory::Credential,
            AuditOperation::SessionRevoked,
            Some(principal.user_id),
        )
        .named("portal user ended their other sessions")
        .outcome(AuditOutcome::Succeeded),
    )
    .await?;
    tx.commit().await.map_err(sqlx_err)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/me/erasure-request",
    operation_id = "portal_erasure_request",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 202, description = "Staff have the request; an open one is returned rather than duplicated", body = ErasureRequested),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn erasure_request(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<ErasureRequested>), AppError> {
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, true).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let request_id = account::request_erasure(&mut tx, &principal).await?;
    write(
        &state,
        &mut tx,
        event(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            Some(principal.user_id),
        )
        .named("portal account erasure requested")
        .outcome(AuditOutcome::Succeeded),
    )
    .await?;
    tx.commit().await.map_err(sqlx_err)?;
    Ok((StatusCode::ACCEPTED, Json(ErasureRequested { request_id })))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/{keyword}/api/v1/auth/signup", post(signup_request))
        .route("/{keyword}/api/v1/auth/signup/verify", post(signup_verify))
        .route(
            "/{keyword}/api/v1/auth/email/verify",
            post(email_add_verify),
        )
        .route(
            "/{keyword}/api/v1/me/consent",
            get(consent_state).post(consent_accept),
        )
        .route("/{keyword}/api/v1/me/password", post(change_password))
        .route("/{keyword}/api/v1/me/sessions", get(list_sessions))
        .route("/{keyword}/api/v1/me/sessions/{id}", delete(end_session))
        .route(
            "/{keyword}/api/v1/me/sessions/end-others",
            post(end_other_sessions),
        )
        .route(
            "/{keyword}/api/v1/me/erasure-request",
            post(erasure_request),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    signup_request,
    signup_verify,
    email_add_verify,
    consent_state,
    consent_accept,
    change_password,
    list_sessions,
    end_session,
    end_other_sessions,
    erasure_request,
))]
pub(super) struct AccountApiDoc;
