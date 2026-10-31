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
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use utoipa::{IntoParams, ToSchema};
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
    // D1-T3: the verified address links the account to its contact.
    let (email, name): (String, String) =
        sqlx::query_as("SELECT lower(email), name FROM webportal_user WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let link = crate::contact_link::link_verified(&state, &mut tx, &portal, user_id, &email, &name)
        .await?;
    if let crate::contact_link::ContactLink::Linked(contact)
    | crate::contact_link::ContactLink::Created(contact) = &link
    {
        write(
            &state,
            &mut tx,
            event(
                MandatoryCategory::Credential,
                AuditOperation::Update,
                Some(user_id),
            )
            .named(match &link {
                crate::contact_link::ContactLink::Linked(_) => {
                    format!("portal account linked to contact {contact} by its verified email")
                }
                _ => format!("portal account given new contact {contact}, pending review"),
            })
            .outcome(AuditOutcome::Succeeded),
        )
        .await?;
    }
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

/// Read the portal's consent versions
///
/// The portal's current consent versions and whether the signed-in user accepted them.
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

/// Accept the portal's terms
///
/// Records the user's acceptance of the portal's current versions; other versions are 422.
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

/// Change a portal password
///
/// Changes the password given the current one; every other session ends and this one is issued
/// again. A wrong current password, or a new one that fails the policy, is 422.
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

/// List my portal sessions
///
/// The signed-in user's live sessions, to end the ones they do not recognise.
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

/// End one of my portal sessions
///
/// Ends the session at once.
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

/// End my other portal sessions
///
/// Ends every session of the user except this one.
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

/// Ask for my portal account to be erased
///
/// Sends the request to staff, who erase or reject it; an open request is returned rather than a
/// second one made.
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

/// A privacy request (R1-T2).
#[derive(Deserialize, ToSchema)]
pub struct PrivacyRequestBody {
    /// `access`, `erasure`, `portability`, `objection`, `restriction` or `rectification`.
    pub request_type: String,
    /// The current password, again: proof that the person asking is the
    /// account's owner.
    pub password: String,
}

impl std::fmt::Debug for PrivacyRequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivacyRequestBody")
            .field("request_type", &self.request_type)
            .finish_non_exhaustive()
    }
}

/// The signed-in portal user's verified email address, the subject of their
/// privacy requests.
async fn subject_of(state: &EngineState, user_id: Uuid) -> Result<String, AppError> {
    let email: Option<String> =
        sqlx::query_scalar("SELECT lower(email) FROM webportal_user WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    email.ok_or_else(|| {
        AppError::Validation("a privacy request needs an account with an email address".into())
    })
}

/// Ask about my personal data
///
/// R1-T2: a privacy (data subject) request about the signed-in person: a copy of their data,
/// erasure, portability, objection, restriction of processing or rectification. They give their
/// password again to prove who they are; the subject is their verified email address. Staff work
/// it with every other data subject request, by the deadline the deployment's law sets.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/me/privacy-requests",
    operation_id = "portal_privacy_request",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = PrivacyRequestBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::BusinessEvent, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The request, recorded", body = attome_compliance::dsr_admin::PortalDsrRequest),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 422, description = "The password is wrong, or an unknown request type", body = ErrorResponse),
    ),
)]
async fn privacy_request(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PrivacyRequestBody>,
) -> Result<
    (
        StatusCode,
        Json<attome_compliance::dsr_admin::PortalDsrRequest>,
    ),
    AppError,
> {
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, true).await?;
    portal_budget(&state, &portal).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if !account::password_ok(&mut tx, &principal, &body.password).await? {
        write(
            &state,
            &mut tx,
            event(
                MandatoryCategory::Credential,
                AuditOperation::Create,
                Some(principal.user_id),
            )
            .named("portal privacy request refused: wrong password")
            .outcome(AuditOutcome::Failed),
        )
        .await?;
        tx.commit().await.map_err(sqlx_err)?;
        return Err(AppError::Validation("the password is wrong".into()));
    }
    tx.commit().await.map_err(sqlx_err)?;
    let subject = subject_of(&state, principal.user_id).await?;
    let request = attome_compliance::dsr_admin::record_portal_request(
        &state,
        &subject,
        &body.request_type,
        principal.user_id,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(request)))
}

/// My privacy requests
///
/// R1-T2: the privacy requests the signed-in person made, newest first, with their status and
/// deadline.
#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/me/privacy-requests",
    operation_id = "portal_privacy_requests",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    responses(
        (status = 200, description = "The person's requests", body = Vec<attome_compliance::dsr_admin::PortalDsrRequest>),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn privacy_requests(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<attome_compliance::dsr_admin::PortalDsrRequest>>, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, false).await?;
    let subject = subject_of(&state, principal.user_id).await?;
    attome_compliance::dsr_admin::portal_requests(&state, &subject, principal.user_id)
        .await
        .map(Json)
}

/// The signed-in person's answer to a lead offered to their partner account (F9-T4).
async fn answer_partner_lead(
    state: &EngineState,
    keyword: &str,
    headers: &HeaderMap,
    id: Uuid,
    accept: bool,
) -> Result<Json<attome_partner::leads::PartnerLead>, AppError> {
    if !state.modules.load().has(attome_modules::MODULE_PARTNER) {
        return Err(AppError::NotFound);
    }
    let portal = portal_for(state, keyword).await?;
    let principal = authenticate(state, &portal, headers, false).await?;
    let partner = attome_partner::leads::partner_of_portal_user(state, principal.user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    attome_partner::leads::respond(state, partner, principal.user_id, id, accept)
        .await
        .map(Json)
}

/// Accept a lead
///
/// F9-T4: only the partner the lead is offered to, before the limit. Audited.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/partner/leads/{id}/accept",
    operation_id = "portal_partner_lead_accept",
    tag = "partner",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("id" = Uuid, Path, description = "The lead"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::BusinessEvent, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Accepted", body = attome_partner::leads::PartnerLead),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal, or no live offer to the caller's partner", body = ErrorResponse),
    ),
)]
async fn partner_lead_accept(
    State(state): State<EngineState>,
    Path((keyword, id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<attome_partner::leads::PartnerLead>, AppError> {
    answer_partner_lead(&state, &keyword, &headers, id, true).await
}

/// Reject a lead
///
/// F9-T4: only the partner the lead is offered to, before the limit; the lead stops naming the
/// partner. Audited.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/partner/leads/{id}/reject",
    operation_id = "portal_partner_lead_reject",
    tag = "partner",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("id" = Uuid, Path, description = "The lead"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::BusinessEvent, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Rejected", body = attome_partner::leads::PartnerLead),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal, or no live offer to the caller's partner", body = ErrorResponse),
    ),
)]
async fn partner_lead_reject(
    State(state): State<EngineState>,
    Path((keyword, id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<attome_partner::leads::PartnerLead>, AppError> {
    answer_partner_lead(&state, &keyword, &headers, id, false).await
}

/// `GET /{keyword}/api/v1/partner/statement`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PartnerStatementQuery {
    /// The commission period.
    pub period_id: Uuid,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    pub page: Option<i64>,
    /// Rows per page.
    pub page_size: Option<i64>,
}

/// The partner's commission statement
///
/// F10-T12: the statement of the signed-in person's own partner account, for one period.
#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/partner/statement",
    operation_id = "portal_partner_statement",
    tag = "partner",
    params(("keyword" = String, Path, description = "The portal"), PartnerStatementQuery),
    responses(
        (status = 200, description = "The statement", body = attome_types::PaginatedResponse<attome_commission::statement::CommissionStatementRow>),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 404, description = "No such portal, or nothing for the caller's partner in the period", body = ErrorResponse),
    ),
)]
async fn partner_statement(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Query(query): Query<PartnerStatementQuery>,
) -> Result<
    Json<attome_types::PaginatedResponse<attome_commission::statement::CommissionStatementRow>>,
    AppError,
> {
    if !state.modules.load().has(attome_modules::MODULE_PARTNER) {
        return Err(AppError::NotFound);
    }
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, false).await?;
    let partner = attome_partner::leads::partner_of_portal_user(&state, principal.user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let page = attome_types::OnePageQuery {
        page: query.page,
        page_size: query.page_size,
    };
    let statement = attome_commission::partner_pay::partner_statement(
        &state,
        partner,
        query.period_id,
        &page,
    )
    .await?;
    Ok(Json(statement))
}

/// A public partner application, with the CAPTCHA token sign-up takes.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PartnerApplicationBody {
    #[serde(flatten)]
    pub application: attome_partner::recruiting::Application,
    #[serde(default)]
    pub captcha_token: Option<String>,
}

/// Apply to become a partner
///
/// F9-T6: anyone may apply, through the same limits and CAPTCHA as sign-up. The answer says nothing
/// about whether the company is known. Audited.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/partner/applications",
    operation_id = "portal_partner_application",
    tag = "partner",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = PartnerApplicationBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::BusinessEvent, AuditOperation::Create)])))),
    responses(
        (status = 202, description = "Received", body = PortalAck),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 422, description = "A field is invalid, or the CAPTCHA failed", body = ErrorResponse),
        (status = 429, description = "Too many attempts", body = ErrorResponse),
    ),
)]
async fn partner_application(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    connect: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<PartnerApplicationBody>,
) -> Result<(StatusCode, Json<PortalAck>), AppError> {
    if !state.modules.load().has(attome_modules::MODULE_PARTNER) {
        return Err(AppError::NotFound);
    }
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
            format!("attome-portal:rl:partner-apply-ip:{}:{ip}", portal.id),
            IP_SIGNUP_RPM,
        )
        .await?;
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
    attome_partner::recruiting::submit(&state, &body.application).await?;
    Ok((StatusCode::ACCEPTED, Json(PortalAck { ok: true })))
}

/// `POST /api/v1/partner/applications/{id}/decision`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PartnerApplicationDecision {
    pub approve: bool,
    /// Required to reject.
    #[serde(default)]
    pub reason: Option<String>,
    /// The portal the partner's administrator signs in to; required to approve.
    #[serde(default)]
    pub portal_id: Option<Uuid>,
}

/// What a decision made.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PartnerApplicationDecided {
    /// `approved` or `rejected`.
    pub status: String,
    pub partner_account_id: Option<Uuid>,
    /// The administrator's portal membership, invited.
    pub portal_user_id: Option<Uuid>,
}

/// Decide a partner application
///
/// F9-T6: a person with update access approves or rejects. Approval marks the matched account a
/// partner, or creates one, and invites its administrator to the portal, in one transaction. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/partner/applications/{id}/decision",
    operation_id = "partner_application_decision",
    tag = "partner",
    params(("id" = Uuid, Path, description = "The application")),
    request_body = PartnerApplicationDecision,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::BusinessEvent, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Decided", body = PartnerApplicationDecided),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not a person, or no update access", body = ErrorResponse),
        (status = 404, description = "No such application the caller may read", body = ErrorResponse),
        (status = 409, description = "Already decided, or the email has a portal account", body = ErrorResponse),
        (status = 422, description = "No reason to reject, or no portal to approve into", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn partner_application_decision(
    State(state): State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<PartnerApplicationDecision>,
) -> Result<Json<PartnerApplicationDecided>, AppError> {
    use attome_partner::recruiting;
    if !state.modules.load().has(attome_modules::MODULE_PARTNER) {
        return Err(AppError::NotFound);
    }
    if !body.approve {
        let reason = body
            .reason
            .as_deref()
            .ok_or_else(|| AppError::Validation("a rejection needs a reason".into()))?;
        recruiting::reject(&state, &ctx, id, reason).await?;
        return Ok(Json(PartnerApplicationDecided {
            status: "rejected".to_owned(),
            partner_account_id: None,
            portal_user_id: None,
        }));
    }
    let portal = body
        .portal_id
        .ok_or_else(|| AppError::Validation("an approval needs a portal_id".into()))?;
    recruiting::may_decide(&state, &ctx, id).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (row, approved) = recruiting::approve_in_tx(&state, &mut tx, ctx.user_id, id).await?;
    let user = crate::provision::create_user(
        &mut tx,
        ctx.user_id,
        portal,
        crate::provision::NewPortalUser {
            name: row.contact_name.unwrap_or(row.company_name),
            email: row.contact_email,
            username: None,
        },
    )
    .await?;
    sqlx::query(
        "UPDATE webportal_user SET contact_ref = $2, row_version = row_version + 1 WHERE id = $1",
    )
    .bind(user.id)
    .bind(approved.contact_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(PartnerApplicationDecided {
        status: "approved".to_owned(),
        partner_account_id: Some(approved.partner_account_id),
        portal_user_id: Some(user.id),
    }))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/{keyword}/api/v1/partner/applications",
            post(partner_application),
        )
        .route(
            "/api/v1/partner/applications/{id}/decision",
            post(partner_application_decision),
        )
        .route("/{keyword}/api/v1/partner/statement", get(partner_statement))
        .route(
            "/{keyword}/api/v1/partner/leads/{id}/accept",
            post(partner_lead_accept),
        )
        .route(
            "/{keyword}/api/v1/partner/leads/{id}/reject",
            post(partner_lead_reject),
        )
        .route(
            "/{keyword}/api/v1/me/privacy-requests",
            get(privacy_requests).post(privacy_request),
        )
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
#[openapi(
    paths(
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
        privacy_request,
        privacy_requests,
        partner_lead_accept,
        partner_lead_reject,
        partner_statement,
        partner_application,
        partner_application_decision,
    ),
    components(schemas(
        PartnerApplicationBody,
        PartnerApplicationDecision,
        PartnerApplicationDecided
    ))
)]
pub(super) struct AccountApiDoc;
