//! Direct user↔privilege grants (`user_account_mm_privilege`) plus
//! `whoami` — the oldest, simplest slice of this admin surface (D-011).

use std::sync::Arc;

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, SelfService, area};
use attome_server::security::SecurityContext;
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::ensure_privilege;

use super::shared::GrantRow;
use attome_types::ErrorResponse;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct GrantItem {
    id: Uuid,
    user_id: Uuid,
    user_email: Option<String>,
    privilege_key: String,
    privilege_name: String,
    granted_on: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for GrantItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantItem").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub(super) struct CreateGrantBody {
    user_email: String,
    privilege_key: String,
    #[serde(default)]
    privilege_name: Option<String>,
}

/// Returns the caller's *own* resolved context — authenticated-only by
/// design, so there is no further privilege to require. Serializes the `Arc`
/// directly rather than deep-copying the context to hand it to `Json`.
///
/// D-789 §4.3: the body carries `role_ids` — every live role the caller holds,
/// directly or through a team (additive; a client uses it for display only,
/// business-rule delivery is filtered on the server). The per-request
/// `service_principal` mark (D-791) is never serialized.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/whoami",
    tag = "admin-security",
    responses(
        (status = 200, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn whoami(ctx: Authorized<SelfService>) -> Json<Arc<SecurityContext>> {
    Json(ctx.into_inner())
}

/// List privilege grants
///
/// Privileges granted straight to users, outside their roles. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/grants",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<GrantItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_grants(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Roles>>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<GrantItem>>, AppError> {
    let window = query.window();

    let rows: Vec<GrantRow> = sqlx::query_as(
        r#"
        SELECT up.id, up.user_ref, u.email, p.key, p.name, up.created_at
        FROM user_account_mm_privilege up
        JOIN privilege p  ON p.id = up.privilege_ref
        LEFT JOIN user_account u ON u.id = up.user_ref
        WHERE up.is_active = true
        ORDER BY up.created_at DESC NULLS LAST
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_account_mm_privilege WHERE is_active = true")
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(
            |(id, user_id, user_email, privilege_key, privilege_name, granted_on)| GrantItem {
                id,
                user_id,
                user_email,
                privilege_key,
                privilege_name,
                granted_on,
            },
        )
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Grant a privilege to a user
///
/// Grants one privilege to one user directly. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/grants",
    tag = "admin-security",
    request_body = CreateGrantBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 201, description = "Success", body = GrantItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_grant(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Json(body): Json<CreateGrantBody>,
) -> Result<(StatusCode, Json<GrantItem>), AppError> {
    let email = body.user_email.trim();
    if email.is_empty() {
        return Err(AppError::Validation("user_email is required".into()));
    }
    let key = body.privilege_key.trim();
    if key.is_empty() {
        return Err(AppError::Validation("privilege_key is required".into()));
    }
    // Q12-T3: never a privilege the granter lacks.
    crate::grants::require_privilege_within_ceiling(&ctx, key)?;

    let user_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM user_account WHERE lower(email) = lower($1)")
            .bind(email)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let user_id = user_id
        .ok_or_else(|| AppError::Validation(format!("no user found with email '{email}'")))?;

    let display_name = body.privilege_name.as_deref().unwrap_or(key);
    // Solution 7 (D-785): direct user grants are not recorded (design §1.3);
    // a privilege minted here takes the deployment's automatic layer, the
    // layer an unrecorded admin write stamps.
    let privilege_id = ensure_privilege(
        &state.base.db,
        key,
        display_name,
        "Created via privilege-grants admin page",
        state.base.config.metadata.changesets.auto_layer,
    )
    .await?;

    // Audit plan 3.3: the grant and its `Access` + `Grant` event share one
    // transaction. Same idempotent shape as `db::ensure_user_privilege_grant`
    // (an existing row for the pair, active or not, is left as it is), as one
    // statement so it can run inside that transaction.
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Grant,
        ctx.user_id,
        "user_account_mm_privilege",
        None,
    )
    .await?;
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         SELECT $1, $2, $3, true, NOW() \
         WHERE NOT EXISTS (SELECT 1 FROM user_account_mm_privilege \
                           WHERE user_ref = $2 AND privilege_ref = $3)",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(privilege_id)
    .execute(&mut *tx)
    .await
    .map_err(attome_db::classify)?;
    let row: (Uuid, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT id, created_at FROM user_account_mm_privilege WHERE user_ref = $1 AND privilege_ref = $2",
    )
    .bind(user_id)
    .bind(privilege_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.event_mut().set_record_id(row.0);
    tx.commit().await?;
    state.base.security.invalidate_sync(user_id).await?;

    Ok((
        StatusCode::CREATED,
        Json(GrantItem {
            id: row.0,
            user_id,
            user_email: Some(email.to_owned()),
            privilege_key: key.to_owned(),
            privilege_name: display_name.to_owned(),
            granted_on: row.1,
        }),
    ))
}

/// Revoke a privilege grant
///
/// Takes a directly granted privilege away from its user at once. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/grants/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The privilege grant")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_grant(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path(grant_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let holder: Option<Uuid> =
        sqlx::query_scalar("SELECT user_ref FROM user_account_mm_privilege WHERE id = $1")
            .bind(grant_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if let Some(holder) = holder {
        crate::delegation::require_not_above(&state.base.db, &ctx, holder).await?;
    }
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Revoke,
        ctx.user_id,
        "user_account_mm_privilege",
        Some(grant_id),
    )
    .await?;
    let user_id: Option<Uuid> = sqlx::query_scalar(
        "UPDATE user_account_mm_privilege SET is_active = false \
         WHERE id = $1 AND is_active = true RETURNING user_ref",
    )
    .bind(grant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let user_id = user_id.ok_or(AppError::NotFound)?;
    tx.commit().await?;
    state.base.security.invalidate_sync(user_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/security/whoami", get(whoami))
        .route(
            "/api/v1/admin/security/grants",
            get(list_grants).post(create_grant),
        )
        .route(
            "/api/v1/admin/security/grants/{id}",
            axum::routing::delete(delete_grant),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(whoami, list_grants, create_grant, delete_grant))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
