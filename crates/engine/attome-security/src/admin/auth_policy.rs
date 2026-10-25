//! Q1-T7: SSO-only roles and break-glass accounts
//! ([`crate::auth_policy`]).
//!
//! - `PUT /api/v1/admin/security/roles/{id}/auth-policy` sets whether a
//!   role signs in only through single sign-on.
//! - `POST /api/v1/admin/security/break-glass-accounts` adds one of
//!   the accounts that keep their password whatever the SSO-only rules say.
//!   An account must have a confirmed authenticator (TOTP; passkeys are not
//!   built yet) to be one.
//! - `DELETE /api/v1/admin/security/break-glass-accounts/{user_id}` removes
//!   one, refused while it is the last and any SSO-only rule is in force.
//!
//! Every change is a configuration event in its own transaction.

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
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

/// A role's sign-in policy.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleSsoPolicyBody {
    /// Only single sign-on, never a password, for every holder of the role
    /// who is not a break-glass account.
    pub sso_only: bool,
}

/// A role's stored sign-in policy.
#[derive(Debug, Serialize, ToSchema)]
pub struct RoleSsoPolicy {
    pub role_id: Uuid,
    pub sso_only: bool,
    pub row_version: i64,
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
/// Sets whether a role signs in only through single sign-on (Q1-T7).
/// Administrators only.
#[utoipa::path(
    put,
    path = "/api/v1/admin/security/roles/{id}/auth-policy",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The role")),
    request_body = RoleSsoPolicyBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The role's policy", body = RoleSsoPolicy),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such role", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_role_auth_policy(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(role_id): Path<Uuid>,
    Json(body): Json<RoleSsoPolicyBody>,
) -> Result<Json<RoleSsoPolicy>, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "role_auth_policy",
            Some(role_id),
        )
        .named("role_sso_only_set")
        .comment(format!("sso_only = {}", body.sso_only)),
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
    let row_version: i64 = sqlx::query_scalar(
        "INSERT INTO role_auth_policy (role_ref, sso_only) VALUES ($1, $2) \
         ON CONFLICT (role_ref) DO UPDATE \
             SET sso_only = EXCLUDED.sso_only, row_version = role_auth_policy.row_version + 1, \
                 updated_at = now() \
         RETURNING row_version",
    )
    .bind(role_id)
    .bind(body.sso_only)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;
    Ok(Json(RoleSsoPolicy {
        role_id,
        sso_only: body.sso_only,
        row_version,
    }))
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
    ctx: Authorized<Admin>,
    Json(body): Json<BreakGlassBody>,
) -> Result<StatusCode, AppError> {
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
                         WHERE user_ref = $1 AND NOT is_deleted AND confirmed_at IS NOT NULL)",
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
    ctx: Authorized<Admin>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
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
            put(put_role_auth_policy),
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
    paths(put_role_auth_policy, add_break_glass, remove_break_glass),
    components(schemas(RoleSsoPolicyBody, RoleSsoPolicy, BreakGlassBody))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
