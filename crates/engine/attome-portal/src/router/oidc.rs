//! Per-portal OIDC routes (D-588 item 3). The flow and its safety rules are
//! [`crate::oidc`]'s; this is the HTTP half.
//!
//! - `GET …/auth/oidc/{provider}/start` redirects to the provider, after
//!   binding the flow's state to this portal and provider (server-side) and
//!   to this browser (a short-lived `SameSite=Lax` cookie, so a login can't be
//!   planted in someone else's browser).
//! - `GET …/auth/oidc/{provider}/callback` is where the provider sends the
//!   browser back. It redirects on to the portal app: home when signed in,
//!   or a page that finishes a pending link or MFA step. Every failure
//!   redirects to the same login error, whatever went wrong.
//! - `POST …/auth/oidc/link` and `POST …/auth/oidc/mfa` finish those steps.

use attome_audit::security::{MandatoryCategory, x_audit};
use attome_audit::{AuditCategory, AuditOperation, AuditOutcome};
use attome_core::EngineState;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::{
    PortalSessionInfo, check_same_origin, cookie, event, mint, portal_base_url, portal_budget,
    portal_for, secure_cookies, session_cookies, set_cookie, write,
};
use crate::auth::{self, LoginOutcome};
use crate::oidc::{self, PendingKind, Resolution};
use crate::policy;
use crate::provision::PortalDetail;

const BROWSER_COOKIE_TTL_SECS: u64 = 600;

fn browser_cookie_name(portal: &PortalDetail, secure: bool) -> String {
    if secure {
        format!("__Secure-wp_{}_oidc", portal.keyword)
    } else {
        format!("wp_{}_oidc", portal.keyword)
    }
}

fn browser_cookie_path(portal: &PortalDetail) -> String {
    format!("/{}/api/v1/auth/oidc/", portal.keyword)
}

/// `Lax`, unlike every other portal cookie: the provider's redirect back is a
/// cross-site top-level navigation, on which a `Strict` cookie isn't sent.
fn browser_cookie(portal: &PortalDetail, secure: bool, value: &str, max_age: u64) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{}={value}; HttpOnly{secure_flag}; SameSite=Lax; Path={}; Max-Age={max_age}",
        browser_cookie_name(portal, secure),
        browser_cookie_path(portal)
    )
}

/// A provider this portal offers, from the deployment's configuration.
fn provider_config<'a>(
    state: &'a EngineState,
    policy: &policy::AuthPolicy,
    provider: &str,
) -> Result<&'a attome_config::OidcProviderConfig, AppError> {
    if !policy.oidc_providers.iter().any(|p| p == provider) {
        return Err(AppError::NotFound);
    }
    state
        .base
        .config
        .portal
        .oidc_providers
        .get(provider)
        .ok_or(AppError::NotFound)
}

/// The key `attome_auth::oidc` caches discovery and JWKS under: per provider,
/// shared by every portal that offers it.
fn provider_cache_key(provider: &str) -> String {
    format!("portal-{provider}")
}

fn callback_uri(state: &EngineState, portal: &PortalDetail, provider: &str) -> String {
    format!(
        "{}/{}/api/v1/auth/oidc/{provider}/callback",
        portal_base_url(state),
        portal.keyword
    )
}

fn redirect(location: &str) -> Result<Response, AppError> {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location).map_err(AppError::internal)?,
    );
    Ok(response)
}

fn failed(portal: &PortalDetail) -> Result<Response, AppError> {
    redirect(&format!("/{}/login?error=oidc", portal.keyword))
}

/// Start signing in with an identity provider
///
/// Redirects (303) to one of the portal's OIDC providers, after binding the flow to this portal,
/// provider and browser so a sign-in cannot be planted in someone else's browser.
#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/auth/oidc/{provider}/start",
    operation_id = "portal_oidc_start",
    tag = "auth",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("provider" = String, Path, description = "An OIDC provider key the portal offers"),
    ),
    responses(
        (status = 200, description = "Not returned: every accepted request gets a 303 redirect. Listed because every documented operation declares a 2xx."),
        (status = 303, description = "Redirect to the identity provider"),
        (status = 404, description = "No such portal, or the portal doesn't offer this provider", body = ErrorResponse),
    ),
)]
async fn start(
    State(state): State<EngineState>,
    Path((keyword, provider)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    portal_budget(&state, &portal).await?;
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let policy = policy::load(&mut conn, portal.id).await?;
    drop(conn);
    let config = provider_config(&state, &policy, &provider)?;
    let authorize_url = attome_auth::oidc::start_login(
        &state.base.redis_coordination,
        &state.base.redis,
        config,
        &provider_cache_key(&provider),
        &callback_uri(&state, &portal, &provider),
        None,
    )
    .await?;
    let state_id = oidc::state_param(&authorize_url)
        .ok_or_else(|| AppError::internal("oidc authorization URL without a state"))?;
    oidc::bind(
        &state.base.redis_coordination,
        &state_id,
        portal.id,
        &provider,
    )
    .await?;
    let mut response = redirect(&authorize_url)?;
    set_cookie(
        &mut response,
        browser_cookie(
            &portal,
            secure_cookies(&state),
            &state_id,
            BROWSER_COOKIE_TTL_SECS,
        ),
    )?;
    Ok(response)
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CallbackQuery {
    /// The authorization code the provider sent back.
    #[serde(default)]
    code: Option<String>,
    /// The state value this sign-in started with.
    #[serde(default)]
    state: Option<String>,
}

impl std::fmt::Debug for CallbackQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackQuery").finish_non_exhaustive()
    }
}

/// Finish signing in with an identity provider
///
/// Where the provider sends the browser back. Redirects (303) to the portal app: home when signed in,
/// a page that finishes a pending link or MFA step, or the login page with one error, whatever went
/// wrong.
#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/auth/oidc/{provider}/callback",
    operation_id = "portal_oidc_callback",
    tag = "auth",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("provider" = String, Path, description = "The OIDC provider key"),
        CallbackQuery,
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Login), (AuditCategory::Security, AuditOperation::FailedLogin)])))),
    responses(
        (status = 200, description = "Not returned: every accepted request gets a 303 redirect. Listed because every documented operation declares a 2xx."),
        (status = 303, description = "Redirect to the portal app: signed in, a pending link or MFA step, or the login page with an error"),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn callback(
    State(state): State<EngineState>,
    Path((keyword, provider)): Path<(String, String)>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    portal_budget(&state, &portal).await?;
    let secure = secure_cookies(&state);
    let (Some(code), Some(state_id)) = (query.code, query.state) else {
        return failed(&portal);
    };
    // Bound to this browser, then to this portal and provider. BAU-4b: the
    // browser check now *yields* the proof `complete_login` requires, instead
    // of being a separate comparison a future caller could forget.
    let browser_state = cookie(&headers, &browser_cookie_name(&portal, secure));
    let Ok(bound) = attome_auth::oidc::bind_to_browser(browser_state.as_deref(), &state_id) else {
        return failed(&portal);
    };
    if !oidc::take_binding(
        &state.base.redis_coordination,
        &state_id,
        portal.id,
        &provider,
    )
    .await
    {
        return failed(&portal);
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let policy = policy::load(&mut conn, portal.id).await?;
    drop(conn);
    let Ok(config) = provider_config(&state, &policy, &provider) else {
        return failed(&portal);
    };
    let identity = match attome_auth::oidc::complete_login(
        &state.base.redis_coordination,
        &state.base.redis,
        config,
        &provider_cache_key(&provider),
        &code,
        bound,
    )
    .await
    {
        Ok(identity) => identity,
        Err(e) => {
            tracing::info!(error = %e, portal = %portal.id, "portal oidc callback refused");
            return failed(&portal);
        }
    };

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let resolution = oidc::resolve(
        &mut tx,
        &state.base.redis_coordination,
        &portal,
        &policy,
        &provider,
        &config.issuer,
        &identity.sub,
        &identity.email,
    )
    .await?;
    let mut response = match resolution {
        Resolution::SignIn { user_id } => {
            let mfa_ring = state.base.secrets.load().mfa_encryption_key.clone();
            match auth::federated_session(
                &mut tx,
                &state.base.pepper_ring(),
                &mfa_ring,
                &portal,
                user_id,
            )
            .await?
            {
                Some(LoginOutcome::Success {
                    user_id,
                    epoch,
                    family,
                    ..
                }) => {
                    write(
                        &state,
                        &mut tx,
                        event(
                            MandatoryCategory::Security,
                            AuditOperation::Login,
                            Some(user_id),
                        )
                        .named("portal login through OIDC")
                        .outcome(AuditOutcome::Succeeded),
                    )
                    .await?;
                    tx.commit().await.map_err(AppError::internal)?;
                    let access = mint(&state, &portal, user_id, epoch, family.family_id)?;
                    let mut response = redirect(&format!("/{}/", portal.keyword))?;
                    session_cookies(&state, &portal, &access, &family.bearer, &mut response)?;
                    response
                }
                _ => {
                    tx.commit().await.map_err(AppError::internal)?;
                    failed(&portal)?
                }
            }
        }
        Resolution::NeedsMfa { pending } => {
            tx.commit().await.map_err(AppError::internal)?;
            redirect(&format!("/{}/oidc/mfa?pending={pending}", portal.keyword))?
        }
        Resolution::NeedsLink { pending } => {
            tx.commit().await.map_err(AppError::internal)?;
            redirect(&format!("/{}/oidc/link?pending={pending}", portal.keyword))?
        }
        Resolution::Refused => {
            write(
                &state,
                &mut tx,
                event(
                    MandatoryCategory::Security,
                    AuditOperation::FailedLogin,
                    None,
                )
                .named("portal OIDC login refused")
                .outcome(AuditOutcome::Failed),
            )
            .await?;
            tx.commit().await.map_err(AppError::internal)?;
            failed(&portal)?
        }
    };
    // The browser binding is single-use too.
    set_cookie(&mut response, browser_cookie(&portal, secure, "", 0))?;
    Ok(response)
}

#[derive(Deserialize, ToSchema)]
pub struct OidcLinkBody {
    pub pending: Uuid,
    pub password: String,
    /// The account's TOTP or recovery code, when it has MFA enabled.
    #[serde(default)]
    pub code: Option<String>,
}

impl std::fmt::Debug for OidcLinkBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcLinkBody").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct OidcMfaBody {
    pub pending: Uuid,
    pub code: String,
}

impl std::fmt::Debug for OidcMfaBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcMfaBody").finish_non_exhaustive()
    }
}

/// Finishes a successful login: the event, the commit, the cookies.
async fn signed_in(
    state: &EngineState,
    portal: &PortalDetail,
    mut tx: attome_db::Tx<'_>,
    outcome: LoginOutcome,
    name: &'static str,
) -> Result<Response, AppError> {
    let LoginOutcome::Success {
        user_id,
        epoch,
        family,
        mfa_enrollment_required,
        recovery_code_used,
    } = outcome
    else {
        return Err(AppError::internal("signed_in called without a success"));
    };
    write(
        state,
        &mut tx,
        event(
            MandatoryCategory::Security,
            AuditOperation::Login,
            Some(user_id),
        )
        .named(name)
        .outcome(AuditOutcome::Succeeded),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    let access = mint(state, portal, user_id, epoch, family.family_id)?;
    let mut response = Json(PortalSessionInfo {
        user_id,
        mfa_enrollment_required,
        recovery_code_used,
    })
    .into_response();
    session_cookies(state, portal, &access, &family.bearer, &mut response)?;
    Ok(response)
}

async fn refused(
    state: &EngineState,
    mut tx: attome_db::Tx<'_>,
    user_id: Option<Uuid>,
    name: &'static str,
) -> Result<Response, AppError> {
    write(
        state,
        &mut tx,
        event(
            MandatoryCategory::Security,
            AuditOperation::FailedLogin,
            user_id,
        )
        .named(name)
        .outcome(AuditOutcome::Failed),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Err(AppError::Unauthorized)
}

/// Link an identity provider to a portal account
///
/// Finishes a pending link with proof of the existing account and signs in; an unknown, used or
/// expired link, or a failed proof, is 401.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/auth/oidc/link",
    operation_id = "portal_oidc_link",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = OidcLinkBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Login), (AuditCategory::Security, AuditOperation::FailedLogin)])))),
    responses(
        (status = 200, description = "Linked and signed in", body = PortalSessionInfo),
        (status = 401, description = "The pending link is unknown, used or expired, or the account proof failed", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn link(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<OidcLinkBody>,
) -> Result<Response, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    check_same_origin(&state, &portal, &headers)?;
    portal_budget(&state, &portal).await?;
    let Some(pending) = oidc::take_pending(
        &state.base.redis_coordination,
        body.pending,
        PendingKind::Link,
        portal.id,
    )
    .await?
    else {
        return Err(AppError::Unauthorized);
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // Proof of the account is its own password, signed in by its email or
    // (D-777) its username.
    let login: Option<Option<String>> = sqlx::query_scalar(
        "SELECT COALESCE(u.email, u.username) FROM webportal_user u \
         WHERE u.id = $1 AND u.webportal_ref = $2",
    )
    .bind(pending.user_id)
    .bind(portal.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(Some(email)) = login else {
        return refused(&state, tx, None, "portal OIDC link refused").await;
    };
    let mfa_ring = state.base.secrets.load().mfa_encryption_key.clone();
    let outcome = auth::login(
        &mut tx,
        &state.base.pepper_ring(),
        &mfa_ring,
        &portal,
        &email,
        &body.password,
        body.code.as_deref(),
    )
    .await?;
    match outcome {
        LoginOutcome::Success { user_id, .. } if user_id == pending.user_id => {
            oidc::link_identity(&mut tx, &pending).await?;
            signed_in(
                &state,
                &portal,
                tx,
                outcome,
                "portal OIDC identity linked; login",
            )
            .await
        }
        _ => {
            refused(
                &state,
                tx,
                Some(pending.user_id),
                "portal OIDC link refused: account proof failed",
            )
            .await
        }
    }
}

/// Finish an identity provider sign-in with MFA
///
/// Sends the MFA code for a provider sign-in that needs one and signs in; an unknown, used or expired
/// step, or a wrong code, is 401.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/auth/oidc/mfa",
    operation_id = "portal_oidc_mfa",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = OidcMfaBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Login), (AuditCategory::Security, AuditOperation::FailedLogin)])))),
    responses(
        (status = 200, description = "Signed in", body = PortalSessionInfo),
        (status = 401, description = "The pending step is unknown, used or expired, or the code is wrong", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn mfa(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<OidcMfaBody>,
) -> Result<Response, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    check_same_origin(&state, &portal, &headers)?;
    portal_budget(&state, &portal).await?;
    let Some(pending) = oidc::take_pending(
        &state.base.redis_coordination,
        body.pending,
        PendingKind::Mfa,
        portal.id,
    )
    .await?
    else {
        return Err(AppError::Unauthorized);
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mfa_ring = state.base.secrets.load().mfa_encryption_key.clone();
    let outcome = auth::second_factor(
        &mut tx,
        &state.base.pepper_ring(),
        &mfa_ring,
        &portal,
        pending.user_id,
        &body.code,
    )
    .await?;
    match outcome {
        LoginOutcome::Success { .. } => {
            signed_in(
                &state,
                &portal,
                tx,
                outcome,
                "portal login through OIDC and MFA",
            )
            .await
        }
        _ => {
            refused(
                &state,
                tx,
                Some(pending.user_id),
                "portal OIDC MFA step refused",
            )
            .await
        }
    }
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/{keyword}/api/v1/auth/oidc/{provider}/start", get(start))
        .route(
            "/{keyword}/api/v1/auth/oidc/{provider}/callback",
            get(callback),
        )
        .route("/{keyword}/api/v1/auth/oidc/link", post(link))
        .route("/{keyword}/api/v1/auth/oidc/mfa", post(mfa))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(start, callback, link, mfa))]
pub(super) struct OidcApiDoc;
