//! Teams (D-133 Phase 4). A team is a pure people-grouping — no privileges of
//! its own. Roles attach to a team (role_mm_team, "everyone on this team
//! gets this role") the same way they attach directly to a user
//! (user_account_mm_role); the two paths are unioned by
//! resolve_access_level/resolve_privileges, not a hierarchy. See D-133 in
//! DECISIONS.md for the full team-vs-role design.
//!
//! Also carries the team membership/role listing endpoints (P-rls-admin-ui
//! addition): `add_team_member`/`remove_team_member` and
//! `add_team_role`/`remove_team_role` existed with no matching list
//! endpoint — an admin UI managing team composition needs to see the current
//! members/roles before deciding what to add or remove.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::shared::invalidate_sync_all;
use attome_types::ErrorResponse;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct TeamItem {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

impl std::fmt::Debug for TeamItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TeamItem").finish_non_exhaustive()
    }
}

/// List teams
///
/// Every team. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/teams",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<TeamItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_teams(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Roles>>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<TeamItem>>, AppError> {
    let window = query.window();

    let rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, name, description FROM team WHERE is_deleted = false \
         ORDER BY name LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM team WHERE is_deleted = false")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|(id, name, description)| TeamItem {
            id,
            name,
            description,
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
pub(super) struct CreateTeamBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
}

/// Create a team
///
/// Creates a team, to share records with and to give roles to as a group. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/teams",
    tag = "admin-security",
    request_body = CreateTeamBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = TeamItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_team(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Json(body): Json<CreateTeamBody>,
) -> Result<(StatusCode, Json<TeamItem>), AppError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }

    let id = Uuid::now_v7();
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Create,
        ctx.user_id,
        "team",
        Some(id),
    )
    .await?;
    sqlx::query("INSERT INTO team (id, name, description) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(name)
        .bind(body.description.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(TeamItem {
            id,
            name: name.to_owned(),
            description: body.description.clone(),
        }),
    ))
}

/// Delete a team
///
/// Deletes a team. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/teams/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The team")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_team(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path(team_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    // Members must be invalidated (their team_ids/access_level via
    // team-mediated roles both change) — resolve before the soft-delete so
    // the membership rows are still readable, same ordering
    // role_grants::delete_role_grant uses (resolve affected users, then
    // invalidate).
    let member_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_ref FROM user_account_mm_team WHERE team_ref = $1 AND is_deleted = false",
    )
    .bind(team_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::SoftDelete,
        ctx.user_id,
        "team",
        Some(team_id),
    )
    .await?;
    let deleted: Option<Uuid> = sqlx::query_scalar(
        "UPDATE team SET is_deleted = true, updated_at = NOW() \
         WHERE id = $1 AND is_deleted = false RETURNING id",
    )
    .bind(team_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    deleted.ok_or(AppError::NotFound)?;
    tx.commit().await?;

    invalidate_sync_all(&state.base.security, member_ids).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
pub(super) struct AddTeamMemberBody {
    user_email: String,
}

#[derive(Serialize, ToSchema)]
pub(super) struct TeamMemberItem {
    id: Uuid,
    team_id: Uuid,
    user_id: Uuid,
    user_email: String,
}

/// Add a team member
///
/// Adds a user to a team, so they hold the team's roles. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/teams/{id}/members",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The team")),
    request_body = AddTeamMemberBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 201, description = "Success", body = TeamMemberItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn add_team_member(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path(team_id): Path<Uuid>,
    Json(body): Json<AddTeamMemberBody>,
) -> Result<(StatusCode, Json<TeamMemberItem>), AppError> {
    let email = body.user_email.trim();
    if email.is_empty() {
        return Err(AppError::Validation("user_email is required".into()));
    }

    let team_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM team WHERE id = $1 AND is_deleted = false)",
    )
    .bind(team_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !team_exists {
        return Err(AppError::Validation(
            "no active team found with this team_id".into(),
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
        "user_account_mm_team",
        None,
    )
    .await?;
    // Q10-T8: joining brings the team's roles and sets; a conflict refuses.
    crate::conflicts::refuse_any_conflict(
        &mut tx,
        user_id,
        crate::conflicts::GrantRef::Team(team_id),
    )
    .await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO user_account_mm_team (id, user_ref, team_ref) VALUES ($1, $2, $3) \
         ON CONFLICT (user_ref, team_ref) DO UPDATE SET is_deleted = false, updated_at = NOW(), \
             source_provider_ref = NULL \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(team_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.event_mut().set_record_id(id);
    tx.commit().await?;

    state.base.security.invalidate_sync(user_id).await?;

    Ok((
        StatusCode::CREATED,
        Json(TeamMemberItem {
            id,
            team_id,
            user_id,
            user_email: email.to_owned(),
        }),
    ))
}

/// Remove a team member
///
/// Takes a user out of a team. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/teams/{id}/members/{user_id}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "The team"),
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
pub(super) async fn remove_team_member(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path((team_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Revoke,
        ctx.user_id,
        "user_account_mm_team",
        None,
    )
    .await?;
    let removed: Option<Uuid> = sqlx::query_scalar(
        "UPDATE user_account_mm_team SET is_deleted = true, updated_at = NOW() \
         WHERE team_ref = $1 AND user_ref = $2 AND is_deleted = false RETURNING user_ref",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    removed.ok_or(AppError::NotFound)?;
    tx.commit().await?;

    state.base.security.invalidate_sync(user_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub(super) struct TeamRoleItem {
    id: Uuid,
    team_id: Uuid,
    role_id: Uuid,
    role_name: String,
}

#[derive(Deserialize, ToSchema)]
pub(super) struct AddTeamRoleBody {
    role_id: Uuid,
}

/// Give a team a role
///
/// Assigns `role_id` to every member of `team_id` — the D-133 "everyone on
/// Finance team gets Finance Role" association. Distinct from
/// `role_grants::create_role_grant` (role → privilege); this is role → team.
/// Takes a `{role_id}` object body (not a bare JSON UUID) — same shape every
/// other mutation body in this file uses, and the only shape a browser HTTP
/// client reliably sends as `application/json` for a POST with no other
/// fields (a bare string body serializes as `text/plain` by default in most
/// HTTP clients, which axum's `Json` extractor rejects).
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/teams/{id}/roles",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The team")),
    request_body = AddTeamRoleBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 201, description = "Success", body = TeamRoleItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn add_team_role(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path(team_id): Path<Uuid>,
    Json(AddTeamRoleBody { role_id }): Json<AddTeamRoleBody>,
) -> Result<(StatusCode, Json<TeamRoleItem>), AppError> {
    // Q12-T3: never a role carrying privileges the granter lacks.
    crate::grants::require_role_within_ceiling(&state.base.db, &ctx, role_id).await?;
    let role_name: Option<String> =
        sqlx::query_scalar("SELECT name FROM role WHERE id = $1 AND is_deleted = false")
            .bind(role_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let role_name = role_name.ok_or_else(|| AppError::Validation("no active role found".into()))?;

    let team_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM team WHERE id = $1 AND is_deleted = false)",
    )
    .bind(team_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !team_exists {
        return Err(AppError::Validation("no active team found".into()));
    }

    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Grant,
        ctx.user_id,
        "role_mm_team",
        None,
    )
    .await?;
    // Q10-T8: every member gets the role; a conflict for any of them refuses.
    let members: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_ref FROM user_account_mm_team WHERE team_ref = $1 AND is_deleted = false",
    )
    .bind(team_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for member in members {
        crate::conflicts::refuse_any_conflict(
            &mut tx,
            member,
            crate::conflicts::GrantRef::Role(role_id),
        )
        .await?;
    }
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO role_mm_team (id, role_ref, team_ref) VALUES ($1, $2, $3) \
         ON CONFLICT (role_ref, team_ref) DO UPDATE SET is_deleted = false, updated_at = NOW() \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(team_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.event_mut().set_record_id(id);
    tx.commit().await?;

    let member_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_ref FROM user_account_mm_team WHERE team_ref = $1 AND is_deleted = false",
    )
    .bind(team_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    invalidate_sync_all(&state.base.security, member_ids).await?;

    Ok((
        StatusCode::CREATED,
        Json(TeamRoleItem {
            id,
            team_id,
            role_id,
            role_name,
        }),
    ))
}

/// Take a role from a team
///
/// Removes a role from a team. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/teams/{id}/roles/{role_id}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "The team"),
        ("role_id" = Uuid, Path, description = "The role"),
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
pub(super) async fn remove_team_role(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Path((team_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Revoke,
        ctx.user_id,
        "role_mm_team",
        None,
    )
    .await?;
    let removed: Option<Uuid> = sqlx::query_scalar(
        "UPDATE role_mm_team SET is_deleted = true, updated_at = NOW() \
         WHERE team_ref = $1 AND role_ref = $2 AND is_deleted = false RETURNING role_ref",
    )
    .bind(team_id)
    .bind(role_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    removed.ok_or(AppError::NotFound)?;
    tx.commit().await?;

    let member_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_ref FROM user_account_mm_team WHERE team_ref = $1 AND is_deleted = false",
    )
    .bind(team_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    invalidate_sync_all(&state.base.security, member_ids).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub(super) struct TeamMemberListItem {
    id: Uuid,
    team_id: Uuid,
    user_id: Uuid,
    user_email: Option<String>,
}

/// A team's members
///
/// The users in a team. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/teams/{id}/members",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The team"), OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<TeamMemberListItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_team_members(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Roles>>,
    Path(team_id): Path<Uuid>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<TeamMemberListItem>>, AppError> {
    let window = query.window();

    let rows: Vec<(Uuid, Uuid, Option<String>)> = sqlx::query_as(
        "SELECT ut.id, ut.user_ref, u.email \
         FROM user_account_mm_team ut \
         LEFT JOIN user_account u ON u.id = ut.user_ref \
         WHERE ut.team_ref = $1 AND ut.is_deleted = false \
         ORDER BY u.email LIMIT $2 OFFSET $3",
    )
    .bind(team_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_account_mm_team WHERE team_ref = $1 AND is_deleted = false",
    )
    .bind(team_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|(id, user_id, user_email)| TeamMemberListItem {
            id,
            team_id,
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

/// A team's roles
///
/// The roles a team gives its members. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/teams/{id}/roles",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The team"), OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<TeamRoleItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_team_roles(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Roles>>,
    Path(team_id): Path<Uuid>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<TeamRoleItem>>, AppError> {
    let window = query.window();

    let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT rt.id, rt.role_ref, r.name \
         FROM role_mm_team rt \
         JOIN role r ON r.id = rt.role_ref \
         WHERE rt.team_ref = $1 AND rt.is_deleted = false \
         ORDER BY r.name LIMIT $2 OFFSET $3",
    )
    .bind(team_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_mm_team WHERE team_ref = $1 AND is_deleted = false",
    )
    .bind(team_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|(id, role_id, role_name)| TeamRoleItem {
            id,
            team_id,
            role_id,
            role_name,
        })
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/teams",
            get(list_teams).post(create_team),
        )
        .route(
            "/api/v1/admin/security/teams/{id}",
            axum::routing::delete(delete_team),
        )
        .route(
            "/api/v1/admin/security/teams/{id}/members",
            get(list_team_members).post(add_team_member),
        )
        .route(
            "/api/v1/admin/security/teams/{id}/members/{user_id}",
            axum::routing::delete(remove_team_member),
        )
        .route(
            "/api/v1/admin/security/teams/{id}/roles",
            get(list_team_roles).post(add_team_role),
        )
        .route(
            "/api/v1/admin/security/teams/{id}/roles/{role_id}",
            axum::routing::delete(remove_team_role),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_teams,
    create_team,
    delete_team,
    add_team_member,
    remove_team_member,
    add_team_role,
    remove_team_role,
    list_team_members,
    list_team_roles
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
