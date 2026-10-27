//! Q10-T8: conflicting-access rules over the admin API, under
//! `/api/v1/admin/security/role-conflicts`: the rules, and everyone who holds
//! both sides of one today. The check itself is `crate::conflicts`, run by
//! every grant path in its own transaction.
//!
//! A rule names roles, privileges and permission sets by id, which differ
//! between deployments, so rules are kept per environment and not recorded
//! in the changeset ledger.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get},
};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::conflicts::{ConflictRule, CurrentConflict, KINDS, current_conflicts, live_rules};

use super::shared::access_tx;

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateConflictRuleBody {
    /// `role`, `privilege` or `set`.
    left_kind: String,
    left_ref: Uuid,
    right_kind: String,
    right_ref: Uuid,
    /// `refuse` or `approval`.
    mode: String,
    /// Why the pair conflicts; shown to whoever is refused or asked.
    reason: String,
}

/// Whether `kind`/`id` names a live role, privilege or set.
async fn exists(db: &attome_db::DbPool, kind: &str, id: Uuid) -> Result<bool, AppError> {
    let sql = match kind {
        "role" => "SELECT EXISTS(SELECT 1 FROM role WHERE id = $1 AND is_deleted = false)",
        "privilege" => "SELECT EXISTS(SELECT 1 FROM privilege WHERE id = $1 AND is_active = true)",
        "set" => "SELECT EXISTS(SELECT 1 FROM permission_set WHERE id = $1 AND is_deleted = false)",
        _ => return Ok(false),
    };
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// Conflict rules
///
/// Every live rule naming two roles, privileges or permission sets one person must not hold together. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/role-conflicts/rules",
    operation_id = "list_role_conflict_rules",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ConflictRule>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_rules(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Roles>>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ConflictRule>>, AppError> {
    let window = query.window();
    let all = live_rules(&state.base.db).await?;
    let total = i64::try_from(all.len()).unwrap_or(i64::MAX);
    let items = all
        .into_iter()
        .skip(usize::try_from(window.offset).unwrap_or(0))
        .take(usize::try_from(window.page_size).unwrap_or(0))
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Add a conflict rule
///
/// From now on, a grant that would give one person both sides is refused (`refuse`) or needs a second administrator (`approval`). Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/role-conflicts/rules",
    operation_id = "create_role_conflict_rule",
    tag = "admin-security",
    request_body = CreateConflictRuleBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created", body = ConflictRule),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "An unknown kind, mode or side, the same thing on both sides, or no reason", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Json(body): Json<CreateConflictRuleBody>,
) -> Result<(StatusCode, Json<ConflictRule>), AppError> {
    for kind in [&body.left_kind, &body.right_kind] {
        if !KINDS.contains(&kind.as_str()) {
            return Err(AppError::Validation(
                "a side's kind is role, privilege or set".into(),
            ));
        }
    }
    if !["refuse", "approval"].contains(&body.mode.as_str()) {
        return Err(AppError::Validation("mode is refuse or approval".into()));
    }
    let reason = body.reason.trim();
    if reason.is_empty() {
        return Err(AppError::Validation("reason is required".into()));
    }
    if (body.left_kind.as_str(), body.left_ref) == (body.right_kind.as_str(), body.right_ref) {
        return Err(AppError::Validation(
            "the two sides of a rule must differ".into(),
        ));
    }
    for (kind, id) in [
        (&body.left_kind, body.left_ref),
        (&body.right_kind, body.right_ref),
    ] {
        if !exists(&state.base.db, kind, id).await? {
            return Err(AppError::Validation(format!("no live {kind} {id}")));
        }
    }
    let id = Uuid::now_v7();
    let mut tx = access_tx(
        &state,
        AuditOperation::Create,
        ctx.user_id,
        "role_conflict_rule",
        Some(id),
    )
    .await?;
    sqlx::query(
        "INSERT INTO role_conflict_rule \
             (id, left_kind, left_ref, right_kind, right_ref, mode, reason, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(&body.left_kind)
    .bind(body.left_ref)
    .bind(&body.right_kind)
    .bind(body.right_ref)
    .bind(&body.mode)
    .bind(reason)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(attome_db::classify)?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(ConflictRule {
            id,
            left_kind: body.left_kind,
            left_ref: body.left_ref,
            right_kind: body.right_kind,
            right_ref: body.right_ref,
            mode: body.mode,
            reason: reason.to_owned(),
        }),
    ))
}

/// Remove a conflict rule
///
/// Grants stop being checked against it. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/role-conflicts/rules/{id}",
    operation_id = "delete_role_conflict_rule",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The rule")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such live rule", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = access_tx(
        &state,
        AuditOperation::SoftDelete,
        ctx.user_id,
        "role_conflict_rule",
        Some(id),
    )
    .await?;
    let n = sqlx::query(
        "UPDATE role_conflict_rule SET is_deleted = true, row_version = row_version + 1 \
         WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Current conflicts
///
/// Everyone who holds both sides of a live rule today (granted before the rule existed, or through paths a rule cannot stop), by rule then user. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/role-conflicts/current",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<CurrentConflict>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_current(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Roles>>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<CurrentConflict>>, AppError> {
    let window = query.window();
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let all = current_conflicts(&mut conn).await?;
    let total = i64::try_from(all.len()).unwrap_or(i64::MAX);
    let items = all
        .into_iter()
        .skip(usize::try_from(window.offset).unwrap_or(0))
        .take(usize::try_from(window.page_size).unwrap_or(0))
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_rules, create_rule, delete_rule, list_current))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/role-conflicts/rules",
            get(list_rules).post(create_rule),
        )
        .route(
            "/api/v1/admin/security/role-conflicts/rules/{id}",
            delete(delete_rule),
        )
        .route(
            "/api/v1/admin/security/role-conflicts/current",
            get(list_current),
        )
}
