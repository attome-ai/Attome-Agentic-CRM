//! Q1-T7: SSO-only roles and break-glass accounts
//! ([`crate::auth_policy`]).
//!
//! - `PUT /api/v1/admin/security/roles/{id}/auth-policy` sets whether a
//!   role signs in only through single sign-on.
//! - `POST /api/v1/admin/security/break-glass-accounts` adds one of
//!   the accounts that keep their password whatever the SSO-only rules say.
//!   An account must have a confirmed authenticator (TOTP or a passkey) to
//!   be one.
//! - `DELETE /api/v1/admin/security/break-glass-accounts/{user_id}` removes
//!   one, refused while it is the last and any SSO-only rule is in force.
//!
//! Every change is a configuration event in its own transaction.

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, post, put},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// A role's sign-in policy. Every field is optional; the ones given change.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleAuthPolicyBody {
    /// Only single sign-on, never a password, for every holder of the role
    /// who is not a break-glass account.
    #[serde(default)]
    pub sso_only: Option<bool>,
    /// Q5-T10: `inherit` (the deployment's `auth.mfa_policy`), `off`,
    /// `optional` or `required`.
    #[serde(default)]
    pub mfa_mode: Option<String>,
    /// Q5-T10: the second factors the role allows: `passkey`, `push`,
    /// `totp`, `recovery`, `email`, `sms`, `whatsapp`. The weak ones (codes
    /// sent by email or message) are never used for an administrator.
    #[serde(default)]
    pub mfa_factors: Option<Vec<String>>,
    /// Q5-T10: days a holder may put off enrolling once a factor is required
    /// (0 to 90).
    #[serde(default)]
    pub mfa_grace_days: Option<i32>,
    /// Q5-T10: days a browser stays remembered after a second factor (0 to
    /// 365; 0 never remembers).
    #[serde(default)]
    pub remember_device_days: Option<i32>,
    /// Q5-T10: only phishing-resistant factors (passkeys) count.
    #[serde(default)]
    pub phishing_resistant_only: Option<bool>,
    /// Q6-T1: holders may sign in with a passkey alone, no password.
    #[serde(default)]
    pub passkey_sign_in: Option<bool>,
}

/// A role's stored sign-in policy.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct RoleAuthPolicy {
    pub role_id: Uuid,
    pub sso_only: bool,
    pub mfa_mode: String,
    pub mfa_factors: Vec<String>,
    pub mfa_grace_days: i32,
    pub remember_device_days: i32,
    pub phishing_resistant_only: bool,
    /// Q6-T1: holders may sign in with a passkey alone.
    pub passkey_sign_in: bool,
    /// The role grants `system.admin`: weak factors never apply to it.
    pub is_admin_role: bool,
    pub row_version: i64,
}

const MFA_MODES: &[&str] = &["inherit", "off", "optional", "required"];

/// Refuses an unknown mode or factor and an out-of-range number of days.
/// Pure.
pub fn check_policy(body: &RoleAuthPolicyBody) -> Result<(), AppError> {
    if let Some(mode) = &body.mfa_mode
        && !MFA_MODES.contains(&mode.as_str())
    {
        return Err(AppError::Validation(
            "mfa_mode is inherit, off, optional or required".into(),
        ));
    }
    if let Some(factors) = &body.mfa_factors {
        if let Some(bad) = factors
            .iter()
            .find(|f| crate::mfa_policy::FactorKind::parse(f).is_none())
        {
            return Err(AppError::Validation(format!(
                "unknown second factor {bad:?}"
            )));
        }
        if factors.is_empty() {
            return Err(AppError::Validation(
                "mfa_factors needs at least one factor".into(),
            ));
        }
    }
    if body.mfa_grace_days.is_some_and(|d| !(0..=90).contains(&d)) {
        return Err(AppError::Validation("mfa_grace_days is 0 to 90".into()));
    }
    if body
        .remember_device_days
        .is_some_and(|d| !(0..=365).contains(&d))
    {
        return Err(AppError::Validation(
            "remember_device_days is 0 to 365".into(),
        ));
    }
    Ok(())
}

const POLICY_SELECT: &str = "SELECT r.id AS role_id, \
        COALESCE(p.sso_only, false) AS sso_only, \
        COALESCE(p.mfa_mode, 'inherit') AS mfa_mode, \
        COALESCE(p.mfa_factors, '{passkey,push,totp,recovery}'::text[]) AS mfa_factors, \
        COALESCE(p.mfa_grace_days, 7) AS mfa_grace_days, \
        COALESCE(p.remember_device_days, 30) AS remember_device_days, \
        COALESCE(p.phishing_resistant_only, false) AS phishing_resistant_only, \
        COALESCE(p.passkey_sign_in, false) AS passkey_sign_in, \
        EXISTS (SELECT 1 FROM role_mm_privilege rp \
                  JOIN privilege pr ON pr.id = rp.privilege_ref AND pr.is_active \
                 WHERE rp.role_ref = r.id AND NOT rp.is_deleted AND pr.key = $2) AS is_admin_role, \
        COALESCE(p.row_version, 0) AS row_version \
   FROM role r LEFT JOIN role_auth_policy p ON p.role_ref = r.id \
  WHERE r.id = $1";

/// Read a role's sign-in policy
///
/// Q5-T10: a role's single sign-on and second-factor policy, with the defaults for a role that has none stored. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/roles/{id}/auth-policy",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The role")),
    responses(
        (status = 200, description = "The role's policy", body = RoleAuthPolicy),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such role", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_role_auth_policy(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Security>>,
    Path(role_id): Path<Uuid>,
) -> Result<Json<RoleAuthPolicy>, AppError> {
    sqlx::query_as(POLICY_SELECT)
        .bind(role_id)
        .bind(attome_server::security::ADMIN_PRIVILEGE_KEY)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .map(Json)
        .ok_or(AppError::NotFound)
}

/// A break-glass account to add.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassBody {
    pub user_id: Uuid,
    /// Why this account keeps its password (kept with the record).
    pub reason: String,
}

/// Set a role's sign-in policy
///
/// Sets whether a role signs in only through single sign-on (Q1-T7), its second-factor policy: mode, allowed factors, grace days, remember-browser days and phishing-resistant only (Q5-T10), and whether its holders may sign in with a passkey alone (Q6-T1). Only the fields given change. Administrators only.
#[utoipa::path(
    put,
    path = "/api/v1/admin/security/roles/{id}/auth-policy",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The role")),
    request_body = RoleAuthPolicyBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The role's policy", body = RoleAuthPolicy),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such role", body = ErrorResponse),
        (status = 422, description = "An unknown mode or factor, no factor, or days out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_role_auth_policy(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Security>>,
    Path(role_id): Path<Uuid>,
    Json(body): Json<RoleAuthPolicyBody>,
) -> Result<Json<RoleAuthPolicy>, AppError> {
    check_policy(&body)?;
    let changes = serde_json::to_string(&serde_json::json!({
        "sso_only": body.sso_only,
        "mfa_mode": body.mfa_mode,
        "mfa_factors": body.mfa_factors,
        "mfa_grace_days": body.mfa_grace_days,
        "remember_device_days": body.remember_device_days,
        "phishing_resistant_only": body.phishing_resistant_only,
        "passkey_sign_in": body.passkey_sign_in,
    }))
    .map_err(AppError::internal)?;
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "role_auth_policy",
            Some(role_id),
        )
        .named("role_auth_policy_set")
        .comment(changes),
    )
    .await?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM role WHERE id = $1)")
        .bind(role_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    sqlx::query(
        "INSERT INTO role_auth_policy (role_ref, sso_only, mfa_mode, mfa_factors, mfa_grace_days, \
                                       remember_device_days, phishing_resistant_only, \
                                       passkey_sign_in) \
         VALUES ($1, COALESCE($2, false), COALESCE($3, 'inherit'), \
                 COALESCE($4, '{passkey,push,totp,recovery}'::text[]), COALESCE($5, 7), \
                 COALESCE($6, 30), COALESCE($7, false), COALESCE($8, false)) \
         ON CONFLICT (role_ref) DO UPDATE SET \
             sso_only = COALESCE($2, role_auth_policy.sso_only), \
             mfa_mode = COALESCE($3, role_auth_policy.mfa_mode), \
             mfa_factors = COALESCE($4, role_auth_policy.mfa_factors), \
             mfa_grace_days = COALESCE($5, role_auth_policy.mfa_grace_days), \
             remember_device_days = COALESCE($6, role_auth_policy.remember_device_days), \
             phishing_resistant_only = COALESCE($7, role_auth_policy.phishing_resistant_only), \
             passkey_sign_in = COALESCE($8, role_auth_policy.passkey_sign_in), \
             row_version = role_auth_policy.row_version + 1, updated_at = now()",
    )
    .bind(role_id)
    .bind(body.sso_only)
    .bind(&body.mfa_mode)
    .bind(&body.mfa_factors)
    .bind(body.mfa_grace_days)
    .bind(body.remember_device_days)
    .bind(body.phishing_resistant_only)
    .bind(body.passkey_sign_in)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let policy: RoleAuthPolicy = sqlx::query_as(POLICY_SELECT)
        .bind(role_id)
        .bind(attome_server::security::ADMIN_PRIVILEGE_KEY)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    tx.commit().await?;
    Ok(Json(policy))
}

/// Add a break-glass account
///
/// Makes a user a break-glass account (Q1-T7). The user must have a
/// confirmed authenticator.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/break-glass-accounts",
    tag = "admin-security",
    request_body = BreakGlassBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The user is a break-glass account"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such user", body = ErrorResponse),
        (status = 409, description = "The user already is one", body = ErrorResponse),
        (status = 422, description = "No reason, or the user has no second factor (`break_glass_needs_second_factor`)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn add_break_glass(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Security>>,
    Json(body): Json<BreakGlassBody>,
) -> Result<StatusCode, AppError> {
    crate::delegation::require_not_above(&state.base.db, &ctx, body.user_id).await?;
    let reason = body.reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 {
        return Err(AppError::Validation(
            "reason says why the account keeps its password (at most 500 characters)".into(),
        ));
    }
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "break_glass_account",
            Some(body.user_id),
        )
        .named("break_glass_account_added")
        .comment(reason.to_owned()),
    )
    .await?;
    let (exists, has_factor): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM user_account WHERE id = $1 AND is_active), \
                EXISTS (SELECT 1 FROM user_mfa \
                         WHERE user_ref = $1 AND NOT is_deleted AND confirmed_at IS NOT NULL) \
             OR EXISTS (SELECT 1 FROM webauthn_credential \
                         WHERE user_ref = $1 AND NOT is_deleted)",
    )
    .bind(body.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    if !has_factor {
        return Err(AppError::Validation(
            "break_glass_needs_second_factor".into(),
        ));
    }
    let inserted = sqlx::query(
        "INSERT INTO break_glass_account (user_ref, reason) VALUES ($1, $2) \
         ON CONFLICT (user_ref) DO NOTHING",
    )
    .bind(body.user_id)
    .bind(reason)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if inserted == 0 {
        return Err(AppError::Conflict(
            "the user already is a break-glass account",
        ));
    }
    tx.commit().await?;
    Ok(StatusCode::CREATED)
}

/// Remove a break-glass account
///
/// Removes a break-glass account (Q1-T7); refused while it is the last one
/// and an SSO-only rule is in force.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/break-glass-accounts/{user_id}",
    tag = "admin-security",
    params(("user_id" = Uuid, Path, description = "The break-glass account's user")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::HardDelete)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not a break-glass account", body = ErrorResponse),
        (status = 409, description = "The last break-glass account while an SSO-only rule is in force", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn remove_break_glass(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Security>>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    crate::delegation::require_not_above(&state.base.db, &ctx, user_id).await?;
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::HardDelete,
            ctx.user_id,
            "break_glass_account",
            Some(user_id),
        )
        .named("break_glass_account_removed"),
    )
    .await?;
    // Serialise removals so two concurrent ones cannot both see "not the
    // last" and leave none.
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT user_ref FROM break_glass_account FOR UPDATE")
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !ids.contains(&user_id) {
        return Err(AppError::NotFound);
    }
    if ids.len() == 1 && crate::auth_policy::any_sso_only(&mut tx).await? {
        return Err(AppError::Conflict(
            "the last break-glass account cannot be removed while an SSO-only rule is in force",
        ));
    }
    sqlx::query("DELETE FROM break_glass_account WHERE user_ref = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/roles/{id}/auth-policy",
            put(put_role_auth_policy).get(get_role_auth_policy),
        )
        .route(
            "/api/v1/admin/security/break-glass-accounts",
            post(add_break_glass),
        )
        .route(
            "/api/v1/admin/security/break-glass-accounts/{user_id}",
            delete(remove_break_glass),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        get_role_auth_policy,
        put_role_auth_policy,
        add_break_glass,
        remove_break_glass
    ),
    components(schemas(RoleAuthPolicyBody, RoleAuthPolicy, BreakGlassBody))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
