//! Q4-T1: signing in with a directory (LDAP) account. Thin wiring over
//! `attome_auth::ldap` (the directory checks the password),
//! `attome_security::accounts` (the person's Attome account),
//! `attome_security::directory_mapping` (the roles their groups give) and the
//! password sign-in's own second-factor and session steps.
//!
//! The person types their directory username (`sAMAccountName` or
//! `userPrincipalName` by default) and password. A directory password is a
//! password: an SSO-only domain or role refuses it like a local one, and a
//! role that requires a second factor asks for it the same way.

use attome_audit::security::{MandatoryCategory, SecurityAuditor, SecurityEvent, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_auth::ldap::{Directory, LdapError};
use attome_server::AppState;
use attome_server::middleware::rate_limit::enforce_account_budget;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Extension, State},
    response::Response,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

/// The `provider_key` a directory account is linked under in
/// `user_identity`.
const PROVIDER_KEY: &str = "ldap";

/// Attempts per directory username per rolling minute, as for a password.
const LDAP_ATTEMPTS_PER_ACCOUNT_RPM: i32 = 10;

#[derive(Deserialize, ToSchema)]
pub struct LdapLoginRequest {
    /// The directory username: `sAMAccountName` or `userPrincipalName` by
    /// default (`auth.ldap.user_filter`).
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for LdapLoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapLoginRequest").finish_non_exhaustive()
    }
}

/// The per-username bucket. Hashed, so Redis never holds the name.
fn throttle_key(username: &str) -> String {
    let digest = Sha256::digest(username.trim().to_lowercase().as_bytes());
    attome_cache::rate_limit::account_key(&hex::encode(digest), "ldap_login")
}

fn failed(name: &str) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Security,
        AuditOperation::FailedLogin,
        Uuid::nil(),
        "user_account",
        None,
    )
    .named(name.to_owned())
}

/// Sign in with a directory account
///
/// Q4-T1: checks the username and password against `auth.ldap`'s directory,
/// links or creates the Attome account by the directory's email address,
/// gives the roles the person's groups map to (and takes back the ones the
/// directory gave that they no longer map to), then answers like
/// `POST /api/v1/auth/login`: a session, or a second-factor challenge.
#[utoipa::path(
    post,
    path = "/api/v1/auth/ldap/login",
    operation_id = "ldap_login",
    tag = "auth",
    request_body = LdapLoginRequest,
    extensions(("x-audit" = json!(x_audit(&[
        (AuditCategory::Security, AuditOperation::Login),
        (AuditCategory::Security, AuditOperation::FailedLogin),
        (AuditCategory::Access, AuditOperation::Grant),
        (AuditCategory::Access, AuditOperation::Revoke),
    ])))),
    responses(
        (status = 200, description = "Signed in, or a second factor is needed (as for a password)"),
        (status = 401, description = "Wrong username or password, or refused like a password", body = ErrorResponse),
        (status = 404, description = "No directory is configured", body = ErrorResponse),
        (status = 409, description = "No Attome account may be linked to this person", body = ErrorResponse),
        (status = 429, description = "Too many attempts for this username", body = ErrorResponse),
        (status = 503, description = "The directory is unavailable", body = ErrorResponse),
    ),
)]
pub(super) async fn ldap_login(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Extension(license): Extension<super::LicenseHandle>,
    Json(body): Json<LdapLoginRequest>,
) -> Result<Response, AppError> {
    let Some(settings) = state.config.auth.ldap.as_ref() else {
        return Err(AppError::NotFound);
    };
    if let Some(rejected) = enforce_account_budget(
        &state.redis_coordination,
        &throttle_key(&body.username),
        LDAP_ATTEMPTS_PER_ACCOUNT_RPM,
        "ldap_login",
    )
    .await?
    {
        return Ok(rejected);
    }
    let directory = Directory::load(settings).await.map_err(|e| {
        tracing::error!(error = %e, "ldap login: auth.ldap cannot be used");
        AppError::CapabilityUnavailable("directory")
    })?;
    let person = match directory.authenticate(&body.username, &body.password).await {
        Ok(person) => person,
        Err(LdapError::InvalidCredentials) => {
            auditor.write(failed("ldap_login_failed")).await?;
            return Err(AppError::Unauthorized);
        }
        Err(e) => {
            tracing::warn!(error = %e, "ldap login: the directory is unavailable");
            return Err(AppError::CapabilityUnavailable("directory"));
        }
    };
    let Some(email) = person
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    else {
        tracing::warn!(
            attribute = %settings.email_attribute,
            "ldap login: the directory entry has no email address"
        );
        auditor.write(failed("ldap_login_no_email")).await?;
        return Err(AppError::Unauthorized);
    };

    let mode = if settings.create_users {
        attome_security::accounts::LinkMode::Create { default_role: None }
    } else {
        attome_security::accounts::LinkMode::LinkOnly
    };
    let active_license = (*license.load()).clone();
    let user_id = attome_security::accounts::link_oidc_identity(
        &state.db,
        PROVIDER_KEY,
        &person.dn.to_lowercase(),
        email,
        &mode,
        &active_license,
    )
    .await?;

    // A directory password is a password: an SSO-only rule refuses it.
    super::local::password_policy_gate(&state, &auditor, user_id, email).await?;

    let roles = attome_auth::ldap::roles_for(&person.groups, &settings.group_roles);
    let mut tx = attome_db::tx::begin(&state.db).await?;
    let changes = attome_security::directory_mapping::apply_directory_roles_in_tx(
        &mut tx,
        &auditor.service(),
        user_id,
        &roles,
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    if !changes.is_empty() {
        tracing::info!(%user_id, ?changes, "ldap sign-in: group mappings applied");
        state.security.invalidate_sync(user_id).await?;
    }

    let outcome = attome_auth::accounts::second_factor_outcome(
        &state.db,
        &state.redis_coordination,
        user_id,
        true,
        &attome_security::mfa_policy::RoleMfaPolicySource {
            db: &state.db,
            deployment_floor: &state.config.auth.mfa_policy,
        },
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
        None,
    )
    .await?;
    super::local::login_response(&state, &auditor, outcome, email, "ldap").await
}

/// This file's slice of the workspace OpenAPI document (see
/// `session::openapi_fragment`).
#[derive(utoipa::OpenApi)]
#[openapi(paths(ldap_login))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
