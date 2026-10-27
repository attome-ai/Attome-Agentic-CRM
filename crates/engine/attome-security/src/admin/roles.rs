//! Roles (D-111 — supersedes D-011/D-012's core_job-based grouping).
//!
//! Solution 7 Phase 1 (D-785): create and update are recorded as
//! `upsert_role` (target `{ role: <name> }`); a new role is stamped with the
//! changeset's layer and an update is refused (409 `layer_mismatch`) unless
//! the role's `owner_layer` is that layer.

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_core::changeset::{Op, RecordingCtx};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::ErrorResponse;
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::shared::{ROLE_SNAPSHOT, lock_live_role, security_op, snapshot_row};

#[derive(Serialize, ToSchema)]
pub struct RoleItem {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// F138: whether this role extends its `role_mm_entity_access`
    /// depths down the holder's position subtree (see the
    /// `position-hierarchy` endpoint in `role_entity_access`). Defaults to
    /// `false` at the DB layer (migration 0053) — orthogonal to the
    /// access-level ladder, not a fifth rung on it.
    position_hierarchy_enabled: bool,
    /// M03/D-434: per-role CIDR allow-list (`role.ip_allowlist`,
    /// migration 0225) — `attome_server::middleware::auth::check_role_ip_
    /// allowlist` enforces it on every request from a holder of this role.
    /// `None`/absent means unrestricted, matching the column's `NULL`
    /// default.
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_allowlist: Option<Vec<String>>,
    /// C-19: send back as `If-Match` on the next `PATCH` to guard against a
    /// lost update. Additive — a caller that ignores this keeps behaving
    /// exactly as it did before `update_role` started honoring the header.
    row_version: i64,
    /// Solution 7 (D-785): the layer that owns this role — `platform`,
    /// `product`, `project` or `customer`. Only a changeset of that layer may
    /// change it.
    owner_layer: String,
}

impl std::fmt::Debug for RoleItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoleItem").finish_non_exhaustive()
    }
}

/// A `role` row: (id, name, description, position_hierarchy_enabled,
/// ip_allowlist, row_version, owner_layer) — [`list_roles`]'s shape
/// (clippy::type_complexity: named here instead of inline).
type RoleRow = (
    Uuid,
    String,
    Option<String>,
    bool,
    Option<Vec<String>>,
    i64,
    String,
);

/// [`update_role`]'s current-row fetch — same fields as [`RoleRow`] minus
/// `id` (already known from the path param).
type RoleUpdateRow = (String, Option<String>, bool, Option<Vec<String>>, i64);

/// List roles
///
/// Every role. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/roles",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<RoleItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_roles(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Roles>>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<RoleItem>>, AppError> {
    let window = query.window();

    let rows: Vec<RoleRow> = sqlx::query_as(
        "SELECT id, name, description, position_hierarchy_enabled, ip_allowlist, row_version, \
                owner_layer \
         FROM role WHERE is_deleted = false ORDER BY name LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM role WHERE is_deleted = false")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(
            |(
                id,
                name,
                description,
                position_hierarchy_enabled,
                ip_allowlist,
                row_version,
                owner_layer,
            )| {
                RoleItem {
                    id,
                    name,
                    description,
                    position_hierarchy_enabled,
                    ip_allowlist,
                    row_version,
                    owner_layer,
                }
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

#[derive(Deserialize, ToSchema)]
pub(super) struct CreateRoleBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    /// Defaults to `false` — the DB column default (migration 0053); a role
    /// created without specifying this never extends via position hierarchy.
    #[serde(default)]
    position_hierarchy_enabled: bool,
    /// Every entry is validated (`attome_server::middleware::ip_allowlist::
    /// validate_cidr_list`) before the write — a typo'd CIDR is rejected here
    /// at save time rather than silently never matching at request time.
    #[serde(default)]
    ip_allowlist: Option<Vec<String>>,
}

/// Create a role
///
/// Creates an empty role; privileges and entity access are added to it separately. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/roles",
    tag = "admin-security",
    request_body = CreateRoleBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = RoleItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_role(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    recording: RecordingCtx,
    Json(body): Json<CreateRoleBody>,
) -> Result<(StatusCode, Json<RoleItem>), AppError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    if let Some(entries) = &body.ip_allowlist {
        attome_server::middleware::ip_allowlist::validate_cidr_list(entries)
            .map_err(AppError::Validation)?;
    }

    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;

    // P-environment-promotion §5 step 5: an admin write marks the row
    // `is_customized` so boot seeds leave it alone and promotion bundles carry
    // the marker.
    let id = Uuid::now_v7();
    let mut stx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Access,
            AuditOperation::Create,
            ctx.user_id,
            "role",
            Some(id),
        ),
    )
    .await?;
    sqlx::query(
        // D-589 item 3: a role created here is `listed` (bulk_field_mode 1):
        // bulk surfaces show its holders only the fields it lists. Roles that
        // existed before migration 0491, and bundle-reconciled roles, keep the
        // column default, `legacy`.
        "INSERT INTO role \
            (id, name, description, position_hierarchy_enabled, ip_allowlist, is_customized, \
             bulk_field_mode, owner_layer) \
         VALUES ($1, $2, $3, $4, $5, true, 1, $6)",
    )
    .bind(id)
    .bind(name)
    .bind(body.description.as_deref())
    .bind(body.position_hierarchy_enabled)
    .bind(&body.ip_allowlist)
    .bind(layer.as_str())
    .execute(&mut *stx)
    .await
    .map_err(super::shared::map_unique_violation)?;
    let snapshot = snapshot_row(&mut stx, ROLE_SNAPSHOT, id).await?;
    recording
        .record(
            stx.tx(),
            security_op(
                Op::UpsertRole,
                "role",
                id,
                serde_json::json!({ "role": name }),
                snapshot,
            ),
        )
        .await?;
    stx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(RoleItem {
            id,
            name: name.to_owned(),
            description: body.description.clone(),
            position_hierarchy_enabled: body.position_hierarchy_enabled,
            ip_allowlist: body.ip_allowlist.clone(),
            // Fresh row — the column default (migration 0040).
            row_version: 0,
            owner_layer: layer.as_str().to_owned(),
        }),
    ))
}

/// `name`/`description` only — `position_hierarchy_enabled` has its own
/// dedicated endpoint (`PUT .../roles/{id}/position-hierarchy`,
/// `role_entity_access.rs`) because toggling it must invalidate every
/// current holder's cached `SecurityContext` (it changes `resolve()`'s
/// output, unlike a role's display name/description); folding it into this
/// generic PATCH would make that invalidation easy to forget on a future
/// edit to this handler.
#[derive(Deserialize, ToSchema)]
pub(super) struct UpdateRoleBody {
    name: Option<String>,
    /// Set to an empty string to clear the description.
    description: Option<String>,
    /// Omit to leave the current allow-list untouched; `[]` clears it back
    /// to unrestricted. Validated the same way `create_role` validates it —
    /// see `CreateRoleBody::ip_allowlist`'s doc comment.
    #[serde(default)]
    ip_allowlist: Option<Vec<String>>,
}

/// Update a role
///
/// Updates a role's details. Administrators only; audited.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/security/roles/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The role")),
    request_body = UpdateRoleBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = RoleItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such role", body = ErrorResponse),
        (status = 409, description = "row_version mismatch, no open changeset to record into, or the role is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn update_role(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    recording: RecordingCtx,
    Path(role_id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<UpdateRoleBody>,
) -> Result<Json<RoleItem>, AppError> {
    // C-19: additive optimistic-concurrency guard — absent header means no
    // check (today's behavior unchanged); present-but-malformed is a 422,
    // never a silent fall-through to the unguarded path.
    let expected_row_version = optional_expected_row_version(&headers)?;

    let cur: Option<RoleUpdateRow> = sqlx::query_as(
        "SELECT name, description, position_hierarchy_enabled, ip_allowlist, row_version \
         FROM role WHERE id = $1 AND is_deleted = false",
    )
    .bind(role_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (cur_name, cur_description, position_hierarchy_enabled, cur_ip_allowlist, _cur_row_version) =
        cur.ok_or(AppError::NotFound)?;

    let new_name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or(cur_name);
    if new_name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }

    let new_description = match body.description.as_deref().map(str::trim) {
        Some("") => None,
        Some(s) => Some(s.to_owned()),
        None => cur_description,
    };

    if let Some(entries) = &body.ip_allowlist {
        attome_server::middleware::ip_allowlist::validate_cidr_list(entries)
            .map_err(AppError::Validation)?;
    }
    let new_ip_allowlist = body.ip_allowlist.or(cur_ip_allowlist);
    recording.preflight(&state.base.db).await?;

    // C-19: `WHERE ... AND ($5::bigint IS NULL OR row_version = $5)` makes
    // this a real optimistic-concurrency guard, not a check-then-write —
    // two concurrent PATCHes each reading the same prior `row_version` can
    // still only have one win, since the loser's UPDATE now matches zero
    // rows once the winner has committed its `+ 1`.
    let mut stx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Access,
            AuditOperation::Update,
            ctx.user_id,
            "role",
            Some(role_id),
        ),
    )
    .await?;
    let (_, owner) = lock_live_role(&mut stx, role_id)
        .await?
        .ok_or(AppError::NotFound)?;
    recording.check_owner(owner)?;
    let new_row_version: Option<i64> = sqlx::query_scalar(
        "UPDATE role SET name = $2, description = $3, ip_allowlist = $4, \
         is_customized = true, updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND is_deleted = false AND ($5::bigint IS NULL OR row_version = $5) \
         RETURNING row_version",
    )
    .bind(role_id)
    .bind(&new_name)
    .bind(&new_description)
    .bind(&new_ip_allowlist)
    .bind(expected_row_version)
    .fetch_optional(&mut *stx)
    .await
    .map_err(super::shared::map_unique_violation)?;

    let new_row_version = match new_row_version {
        Some(v) => v,
        None if expected_row_version.is_some() => {
            return Err(AppError::VersionConflict);
        }
        None => return Err(AppError::NotFound),
    };
    let snapshot = snapshot_row(&mut stx, ROLE_SNAPSHOT, role_id).await?;
    recording
        .record(
            stx.tx(),
            security_op(
                Op::UpsertRole,
                "role",
                role_id,
                serde_json::json!({ "role": new_name }),
                snapshot,
            ),
        )
        .await?;
    stx.commit().await?;

    Ok(Json(RoleItem {
        id: role_id,
        name: new_name,
        description: new_description,
        position_hierarchy_enabled,
        ip_allowlist: new_ip_allowlist,
        row_version: new_row_version,
        owner_layer: owner.as_str().to_owned(),
    }))
}

/// Parses `If-Match` into an expected `row_version`, when present (C-19).
/// Additive, not the generic entity PATCH path's mandatory contract (D-079
/// is scoped to `entity_crud`, not this admin surface): a caller that never
/// sends the header keeps behaving exactly as it did before this check
/// existed. A malformed header is still a 422 — garbage must never silently
/// degrade into the unguarded last-write-wins path.
fn optional_expected_row_version(headers: &HeaderMap) -> Result<Option<i64>, AppError> {
    let Some(raw) = headers.get(IF_MATCH) else {
        return Ok(None);
    };
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map(Some).map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

#[derive(Serialize, ToSchema)]
pub struct RoleUserItem {
    /// `user_account_mm_role.id` — the assignment row, not the user.
    id: Uuid,
    user_id: Uuid,
    user_name: String,
    email: Option<String>,
    granted_on: Option<chrono::DateTime<chrono::Utc>>,
}

impl std::fmt::Debug for RoleUserItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoleUserItem").finish_non_exhaustive()
    }
}

/// `user_account_mm_role` row joined to its user, for
/// [`list_role_users`]: (assignment id, user id, user_name, email, granted_on).
type RoleUserRow = (
    Uuid,
    Uuid,
    Option<String>,
    Option<String>,
    Option<chrono::DateTime<chrono::Utc>>,
);

/// A role's users
///
/// Reverse of `user_roles::list_user_roles` — direct assignments only
/// (`user_account_mm_role`), same team-mediated-roles caveat: a user
/// holding this role only via team membership does not appear here, mirrored
/// instead through `teams::list_team_roles`. Backs the Role form's
/// Assignments tab; add/remove still goes through the existing per-user
/// endpoints (`POST/DELETE /api/v1/admin/security/users/{id}/roles`).
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/roles/{id}/users",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The role"), OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<RoleUserItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_role_users(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Roles>>,
    Path(role_id): Path<Uuid>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<RoleUserItem>>, AppError> {
    let window = query.window();

    let rows: Vec<RoleUserRow> = sqlx::query_as(
        "SELECT ur.id, u.id, u.user_name, u.email, ur.created_at \
         FROM user_account_mm_role ur \
         JOIN user_account u ON u.id = ur.user_ref \
         WHERE ur.role_ref = $1 AND ur.is_deleted = false \
         ORDER BY u.user_name LIMIT $2 OFFSET $3",
    )
    .bind(role_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_account_mm_role WHERE role_ref = $1 AND is_deleted = false",
    )
    .bind(role_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|(id, user_id, user_name, email, granted_on)| RoleUserItem {
            id,
            user_id,
            user_name: user_name.unwrap_or_default(),
            email,
            granted_on,
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
            "/api/v1/admin/security/roles",
            get(list_roles).post(create_role),
        )
        .route(
            "/api/v1/admin/security/roles/{id}",
            axum::routing::patch(update_role),
        )
        .route(
            "/api/v1/admin/security/roles/{id}/users",
            get(list_role_users),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_roles, create_role, update_role, list_role_users))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
