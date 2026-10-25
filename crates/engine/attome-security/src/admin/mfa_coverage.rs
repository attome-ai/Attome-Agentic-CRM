//! `GET /api/v1/admin/security/mfa/coverage` (roadmap Q5-T9): who has which
//! second factor, by role, and which administrators lack a
//! phishing-resistant one. Read-only; administrators only.
//!
//! The factors this deployment records are a TOTP app (`user_mfa`) and
//! recovery codes (`user_mfa_recovery_code`, the unused ones). There is no
//! passkey store yet, so no account has a phishing-resistant factor and
//! every administrator is flagged until passkeys land (Q5).

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The most rows one answer carries.
const MAX_ROWS: i64 = 500;

/// One active account's second factors.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct MfaCoverageRow {
    pub user_id: Uuid,
    pub email: Option<String>,
    /// The names of the account's roles.
    pub roles: Vec<String>,
    /// `totp`, `recovery` (unused recovery codes left); `passkey` when
    /// passkeys exist.
    pub factors: Vec<String>,
    pub is_admin: bool,
    /// An administrator with no phishing-resistant factor (a passkey).
    pub admin_missing_phishing_resistant: bool,
}

/// One role's coverage.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct MfaCoverageSummary {
    pub role_id: Option<Uuid>,
    /// The role's name; absent for accounts with no role.
    pub role: Option<String>,
    pub users: i64,
    pub with_totp: i64,
    pub without_mfa: i64,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CoverageQuery {
    /// Only members of this role.
    pub role_id: Option<Uuid>,
    /// Only accounts with no second factor at all.
    #[serde(default)]
    pub missing_only: bool,
}

/// The accounts' factors, one query. An administrator holds `system.admin`
/// directly, through a role, or through a team's role.
const COVERAGE_SQL: &str = r#"
WITH admins AS (
    SELECT up.user_ref AS user_id FROM user_account_mm_privilege up
      JOIN privilege p ON p.id = up.privilege_ref
     WHERE p.key = 'system.admin' AND up.is_active AND p.is_active
    UNION
    SELECT ur.user_ref FROM user_account_mm_role ur
      JOIN role_mm_privilege rp ON rp.role_ref = ur.role_ref AND NOT rp.is_deleted
      JOIN privilege p ON p.id = rp.privilege_ref
     WHERE p.key = 'system.admin' AND NOT ur.is_deleted AND p.is_active
    UNION
    SELECT ut.user_ref FROM user_account_mm_team ut
      JOIN role_mm_team rt ON rt.team_ref = ut.team_ref AND NOT rt.is_deleted
      JOIN role_mm_privilege rp ON rp.role_ref = rt.role_ref AND NOT rp.is_deleted
      JOIN privilege p ON p.id = rp.privilege_ref
     WHERE p.key = 'system.admin' AND NOT ut.is_deleted AND p.is_active
),
rows AS (
    SELECT u.id AS user_id,
           u.email::text AS email,
           COALESCE((SELECT array_agg(r.name::text ORDER BY r.name)
                       FROM user_account_mm_role ur JOIN role r ON r.id = ur.role_ref
                      WHERE ur.user_ref = u.id AND NOT ur.is_deleted AND NOT r.is_deleted),
                    ARRAY[]::text[]) AS roles,
           array_remove(ARRAY[
               CASE WHEN EXISTS (SELECT 1 FROM user_mfa m
                                  WHERE m.user_ref = u.id AND NOT m.is_deleted
                                    AND m.confirmed_at IS NOT NULL) THEN 'totp' END,
               CASE WHEN EXISTS (SELECT 1 FROM user_mfa_recovery_code c
                                  WHERE c.user_ref = u.id AND c.used_at IS NULL) THEN 'recovery' END
           ], NULL) AS factors,
           EXISTS (SELECT 1 FROM admins a WHERE a.user_id = u.id) AS is_admin
      FROM user_account u
     WHERE u.is_active
       AND ($1::uuid IS NULL OR EXISTS (SELECT 1 FROM user_account_mm_role ur
                                         WHERE ur.user_ref = u.id AND ur.role_ref = $1
                                           AND NOT ur.is_deleted))
)
SELECT user_id, email, roles, factors, is_admin,
       is_admin AND NOT ('passkey' = ANY(factors)) AS admin_missing_phishing_resistant
  FROM rows
 WHERE NOT $2 OR cardinality(factors) = 0
 ORDER BY is_admin DESC, cardinality(factors), email
 LIMIT $3
"#;

/// MFA coverage by user
///
/// Each user's second-factor state against the policy that applies to them. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/mfa/coverage",
    tag = "security",
    operation_id = "mfa_coverage",
    params(CoverageQuery),
    responses(
        (status = 200, description = "Active accounts with their second factors, administrators first (at most 500)", body = PaginatedResponse<MfaCoverageRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn coverage(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<CoverageQuery>,
) -> Result<Json<PaginatedResponse<MfaCoverageRow>>, AppError> {
    let rows: Vec<MfaCoverageRow> = sqlx::query_as(COVERAGE_SQL)
        .bind(query.role_id)
        .bind(query.missing_only)
        .bind(MAX_ROWS)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let total = rows.len() as i64;
    Ok(Json(PaginatedResponse {
        items: rows,
        total,
        page: 1,
        page_size: MAX_ROWS,
        warnings: Vec::new(),
    }))
}

/// MFA coverage summary
///
/// How many users meet their second-factor policy and how many do not. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/mfa/coverage/summary",
    tag = "security",
    operation_id = "mfa_coverage_summary",
    responses(
        (status = 200, description = "Per role: active members, with a TOTP app, without any second factor", body = Vec<MfaCoverageSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn coverage_summary(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<Vec<MfaCoverageSummary>>, AppError> {
    let rows: Vec<MfaCoverageSummary> = sqlx::query_as(
        "WITH members AS ( \
             SELECT u.id AS user_id, ur.role_ref \
               FROM user_account u \
               LEFT JOIN user_account_mm_role ur ON ur.user_ref = u.id AND NOT ur.is_deleted \
              WHERE u.is_active), \
         factors AS ( \
             SELECT m.user_id, m.role_ref, \
                    EXISTS (SELECT 1 FROM user_mfa f WHERE f.user_ref = m.user_id \
                             AND NOT f.is_deleted AND f.confirmed_at IS NOT NULL) AS totp, \
                    EXISTS (SELECT 1 FROM user_mfa_recovery_code c WHERE c.user_ref = m.user_id \
                             AND c.used_at IS NULL) AS recovery \
               FROM members m) \
         SELECT f.role_ref AS role_id, r.name::text AS role, COUNT(*)::bigint AS users, \
                COUNT(*) FILTER (WHERE f.totp)::bigint AS with_totp, \
                COUNT(*) FILTER (WHERE NOT f.totp AND NOT f.recovery)::bigint AS without_mfa \
           FROM factors f LEFT JOIN role r ON r.id = f.role_ref \
          GROUP BY f.role_ref, r.name \
          ORDER BY r.name NULLS LAST",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(rows))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/security/mfa/coverage", get(coverage))
        .route(
            "/api/v1/admin/security/mfa/coverage/summary",
            get(coverage_summary),
        )
}

/// This file's slice of the workspace OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(coverage, coverage_summary),
    components(schemas(MfaCoverageRow, MfaCoverageSummary))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
