//! Business units (D-133 (3): user_account_mm_organization).
//! user_account_mm_organization was created by migration 0051 purely as
//! `db::resolve_accessible_org_ids`'s BusinessUnit-tier data source — D-133/
//! D-134 shipped every other admin mutation surface (teams, record shares,
//! entity-default shares, user roles) but left this one membership edge
//! reachable only via raw SQL. Organization records themselves are managed
//! through the generic entity route instead (`/xrm/core/organization/list`,
//! `attome-server/src/sidebar_seed.rs`) — `organization` predates
//! `entity_info` and was never migrated onto it, so `list_organizations`
//! below reads it directly rather than going through `AdminService`'s
//! `entity_info`-backed entity list. Membership mutations mirror
//! `positions::add_position_member`/`positions::remove_position_member`'s
//! exact shape.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::ErrorResponse;
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, ToSchema)]
pub struct OrganizationItem {
    id: Uuid,
    name: Option<String>,
}

impl std::fmt::Debug for OrganizationItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrganizationItem").finish_non_exhaustive()
    }
}

/// List business units
///
/// The business units (organizations). Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/organizations",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<OrganizationItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_organizations(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<OrganizationItem>>, AppError> {
    let window = query.window();

    let rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, name FROM organization WHERE is_active IS NOT FALSE \
         ORDER BY name LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM organization WHERE is_active IS NOT FALSE")
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|(id, name)| OrganizationItem { id, name })
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(Serialize, ToSchema)]
pub(super) struct OrganizationMemberItem {
    id: Uuid,
    organization_id: Uuid,
    user_id: Uuid,
    user_email: Option<String>,
}

async fn organization_exists(
    db: &attome_db::DbPool,
    organization_id: Uuid,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organization WHERE id = $1 AND is_active IS NOT FALSE)",
    )
    .bind(organization_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// A business unit's members
///
/// The users who belong to a business unit. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/organizations/{id}/members",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The business unit"), OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<OrganizationMemberItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_organization_members(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(organization_id): Path<Uuid>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<OrganizationMemberItem>>, AppError> {
    let window = query.window();

    let rows: Vec<(Uuid, Uuid, Option<String>)> = sqlx::query_as(
        "SELECT m.id, m.user_ref, u.email \
         FROM user_account_mm_organization m \
         LEFT JOIN user_account u ON u.id = m.user_ref \
         WHERE m.organization_ref = $1 AND m.is_deleted = false \
         ORDER BY u.email LIMIT $2 OFFSET $3",
    )
    .bind(organization_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_account_mm_organization \
         WHERE organization_ref = $1 AND is_deleted = false",
    )
    .bind(organization_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|(id, user_id, user_email)| OrganizationMemberItem {
            id,
            organization_id,
            user_id,
            user_email,
        })
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(Deserialize, ToSchema)]
pub(super) struct AddOrganizationMemberBody {
    user_email: String,
}

/// Add a user to a business unit
///
/// Makes a user a member of a business unit. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/organizations/{id}/members",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The business unit")),
    request_body = AddOrganizationMemberBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 201, description = "Success", body = OrganizationMemberItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn add_organization_member(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(organization_id): Path<Uuid>,
    Json(body): Json<AddOrganizationMemberBody>,
) -> Result<(StatusCode, Json<OrganizationMemberItem>), AppError> {
    let email = body.user_email.trim();
    if email.is_empty() {
        return Err(AppError::Validation("user_email is required".into()));
    }

    if !organization_exists(&state.base.db, organization_id).await? {
        return Err(AppError::Validation(
            "no active organization found with this organization_id".into(),
        ));
    }

    let user_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM user_account WHERE lower(email) = lower($1)")
            .bind(email)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let user_id = user_id
        .ok_or_else(|| AppError::Validation(format!("no user found with email '{email}'")))?;

    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Grant,
        ctx.user_id,
        "user_account_mm_organization",
        None,
    )
    .await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO user_account_mm_organization (id, user_ref, organization_ref) VALUES ($1, $2, $3) \
         ON CONFLICT (user_ref, organization_ref) DO UPDATE SET is_deleted = false, updated_at = NOW() \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(organization_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.event_mut().set_record_id(id);
    tx.commit().await?;

    // BusinessUnit-tier reach changed for this user — invalidate so the next
    // request sees the new org, same posture `positions::add_position_member`/
    // `teams::add_team_member` already take for their own membership edges.
    state.base.security.invalidate_sync(user_id).await?;

    Ok((
        StatusCode::CREATED,
        Json(OrganizationMemberItem {
            id,
            organization_id,
            user_id,
            user_email: Some(email.to_owned()),
        }),
    ))
}

/// Remove a user from a business unit
///
/// Ends a user's membership of a business unit. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/organizations/{id}/members/{user_id}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "The business unit"),
        ("user_id" = Uuid, Path, description = "The user"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn remove_organization_member(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((organization_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Revoke,
        ctx.user_id,
        "user_account_mm_organization",
        None,
    )
    .await?;
    let removed: Option<Uuid> = sqlx::query_scalar(
        "UPDATE user_account_mm_organization SET is_deleted = true, updated_at = NOW() \
         WHERE organization_ref = $1 AND user_ref = $2 AND is_deleted = false RETURNING user_ref",
    )
    .bind(organization_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    removed.ok_or(AppError::NotFound)?;
    tx.commit().await?;

    state.base.security.invalidate_sync(user_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/organizations",
            get(list_organizations),
        )
        .route(
            "/api/v1/admin/security/organizations/{id}/members",
            get(list_organization_members).post(add_organization_member),
        )
        .route(
            "/api/v1/admin/security/organizations/{id}/members/{user_id}",
            axum::routing::delete(remove_organization_member),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_organizations,
    list_organization_members,
    add_organization_member,
    remove_organization_member
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
