//! Q10-T5: permission sets over the admin API, under
//! `/api/v1/admin/security/permission-sets`; their assignments under
//! `/api/v1/admin/security/permission-set-assignments/{set}`, outside the
//! production authoring gate, as a user's roles are.
//!
//! The set, its entity levels and its privileges are configuration: every
//! write is recorded in the changeset ledger (D-785) as
//! `upsert_permission_set`, `retire_permission_set`,
//! `set_permission_set_entity_access`, `clear_permission_set_entity_access`,
//! `grant_permission_set_privilege` and `revoke_permission_set_privilege`
//! (target `{ permission_set[, entity | privilege] }`), so sets promote
//! between environments. Assignments to users and teams are environment
//! data, like a user's roles, and are not recorded. Every write is a
//! security event in its own transaction, and every user the set reaches
//! gets a fresh security context afterwards. A set never grants
//! `system.admin` (422 `set_cannot_grant_admin`).

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_core::changeset::{Op, RecordingCtx};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::{delete, get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::permission_sets::{
    SetLevels, invalidate_set_holders, refuse_admin, retire_in_tx, set_set_privilege,
    upsert_set_entity_access,
};

use super::shared::{
    access_tx, map_unique_violation, parse_owner_layer, security_op, snapshot_row,
};

const SET_SNAPSHOT: &str = "SELECT id, name, name_ar, description, is_customized, is_deleted, \
     row_version, owner_layer FROM permission_set WHERE id = $1";

const ACCESS_SNAPSHOT: &str = "SELECT ea.id, ea.set_ref, ea.entity_ref, ei.logicalname AS entity, \
     ea.read_access_level, ea.write_access_level, ea.delete_access_level, \
     ea.create_access_level, ea.assign_access_level, ea.share_access_level, \
     ea.export_access_level, ea.bulk_access_level, ea.read_bu_children, ea.write_bu_children, \
     ea.delete_bu_children, ea.assign_bu_children, ea.share_bu_children, ea.owner_layer \
     FROM permission_set_entity_access ea JOIN entity_info ei ON ei.id = ea.entity_ref \
     WHERE ea.id = $1";

/// A permission set.
#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionSetItem {
    id: Uuid,
    name: String,
    name_ar: Option<String>,
    description: Option<String>,
    /// Send back as `If-Match` on the next `PATCH`.
    row_version: i64,
    owner_layer: String,
}

/// A set with its privileges and entity levels.
#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionSetDetail {
    #[serde(flatten)]
    set: PermissionSetItem,
    /// Privilege keys.
    privileges: Vec<String>,
    entity_access: Vec<SetEntityAccessItem>,
}

/// One entity's levels in a set: 0 None, 1 Team, 2 Business unit, 3 Global.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SetEntityAccessItem {
    pub entity: String,
    #[serde(default = "global")]
    pub read_access_level: i16,
    #[serde(default = "global")]
    pub write_access_level: i16,
    #[serde(default = "global")]
    pub delete_access_level: i16,
    /// Null: the write level.
    #[serde(default)]
    pub create_access_level: Option<i16>,
    /// Null: the write level.
    #[serde(default)]
    pub assign_access_level: Option<i16>,
    /// Null: the write level.
    #[serde(default)]
    pub share_access_level: Option<i16>,
    #[serde(default)]
    pub export_access_level: i16,
    #[serde(default)]
    pub bulk_access_level: i16,
    #[serde(default = "yes")]
    pub read_bu_children: bool,
    #[serde(default = "yes")]
    pub write_bu_children: bool,
    #[serde(default = "yes")]
    pub delete_bu_children: bool,
    #[serde(default = "yes")]
    pub assign_bu_children: bool,
    #[serde(default = "yes")]
    pub share_bu_children: bool,
}

fn global() -> i16 {
    3
}

fn yes() -> bool {
    true
}

impl SetEntityAccessItem {
    fn levels(&self) -> SetLevels {
        SetLevels {
            read: self.read_access_level,
            write: self.write_access_level,
            delete: self.delete_access_level,
            create: self.create_access_level,
            assign: self.assign_access_level,
            share: self.share_access_level,
            export: self.export_access_level,
            bulk: self.bulk_access_level,
            read_bu_children: self.read_bu_children,
            write_bu_children: self.write_bu_children,
            delete_bu_children: self.delete_bu_children,
            assign_bu_children: self.assign_bu_children,
            share_bu_children: self.share_bu_children,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePermissionSetBody {
    name: String,
    #[serde(default)]
    name_ar: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

/// Fields left out stay as they are; the name is the set's key and does not
/// change.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePermissionSetBody {
    #[serde(default)]
    name_ar: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetPrivilegeBody {
    privilege_key: String,
}

/// Exactly one of `user_id` and `team_id`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAssignmentBody {
    #[serde(default)]
    user_id: Option<Uuid>,
    #[serde(default)]
    team_id: Option<Uuid>,
    /// When the assignment stops giving anything; open-ended when omitted.
    #[serde(default)]
    ends_at: Option<DateTime<Utc>>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AssignmentItem {
    id: Uuid,
    user_id: Option<Uuid>,
    team_id: Option<Uuid>,
    ends_at: Option<DateTime<Utc>>,
    reason: Option<String>,
    granted_by: Option<Uuid>,
    created_at: DateTime<Utc>,
}

/// Most assignments one set lists.
const MAX_ASSIGNMENTS: i64 = 500;

type SetRow = (Uuid, String, Option<String>, Option<String>, i64, String);

async fn set_row(db: impl sqlx::PgExecutor<'_>, id: Uuid) -> Result<SetRow, AppError> {
    sqlx::query_as(
        "SELECT id, name, name_ar, description, row_version, owner_layer FROM permission_set \
         WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

fn item((id, name, name_ar, description, row_version, owner_layer): SetRow) -> PermissionSetItem {
    PermissionSetItem {
        id,
        name,
        name_ar,
        description,
        row_version,
        owner_layer,
    }
}

/// The set's row locked for a change: `FOR UPDATE`, its layer checked.
async fn lock_set(
    tx: &mut sqlx::PgConnection,
    recording: &RecordingCtx,
    id: Uuid,
) -> Result<SetRow, AppError> {
    let row: SetRow = sqlx::query_as(
        "SELECT id, name, name_ar, description, row_version, owner_layer FROM permission_set \
         WHERE id = $1 AND is_deleted = false FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    recording.check_owner(parse_owner_layer(&row.5)?)?;
    Ok(row)
}

async fn invalidate(state: &EngineState, set_id: Uuid) -> Result<(), AppError> {
    invalidate_set_holders(&state.base.db, &state.base.security, set_id).await
}

/// Permission sets
///
/// Every live permission set, by name. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/permission-sets",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<PermissionSetItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_sets(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<PermissionSetItem>>, AppError> {
    let window = query.window();
    let rows: Vec<SetRow> = sqlx::query_as(
        "SELECT id, name, name_ar, description, row_version, owner_layer FROM permission_set \
         WHERE is_deleted = false ORDER BY lower(name) LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM permission_set WHERE is_deleted = false")
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        rows.into_iter().map(item).collect(),
        total,
        window.page,
        window.page_size,
    )))
}

/// Create a permission set
///
/// Creates an empty permission set; add privileges and entity levels next. Administrators only; audited and recorded in the changeset.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/permission-sets",
    tag = "admin-security",
    request_body = CreatePermissionSetBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = PermissionSetItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "A set with this name exists, or no open changeset to record into", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_set(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Json(body): Json<CreatePermissionSetBody>,
) -> Result<(StatusCode, Json<PermissionSetItem>), AppError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;
    let id = Uuid::now_v7();
    let mut tx = access_tx(
        &state,
        AuditOperation::Create,
        ctx.user_id,
        "permission_set",
        Some(id),
    )
    .await?;
    sqlx::query(
        "INSERT INTO permission_set (id, name, name_ar, description, is_customized, owner_layer) \
         VALUES ($1, $2, $3, $4, true, $5)",
    )
    .bind(id)
    .bind(name)
    .bind(body.name_ar.as_deref())
    .bind(body.description.as_deref())
    .bind(layer.as_str())
    .execute(&mut *tx)
    .await
    .map_err(map_unique_violation)?;
    let snapshot = snapshot_row(&mut tx, SET_SNAPSHOT, id).await?;
    recording
        .record(
            tx.tx(),
            security_op(
                Op::UpsertPermissionSet,
                "permission_set",
                id,
                serde_json::json!({ "permission_set": name }),
                snapshot,
            ),
        )
        .await?;
    let row = set_row(&mut *tx, id).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(item(row))))
}

/// A permission set
///
/// One set with its privileges and entity levels. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/permission-sets/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The permission set")),
    responses(
        (status = 200, description = "Success", body = PermissionSetDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such live set", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_set(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<PermissionSetDetail>, AppError> {
    let db = &state.base.db;
    let row = set_row(db, id).await?;
    let privileges: Vec<String> = sqlx::query_scalar(
        "SELECT p.key FROM permission_set_privilege sp JOIN privilege p ON p.id = sp.privilege_ref \
         WHERE sp.set_ref = $1 AND sp.is_deleted = false ORDER BY p.key",
    )
    .bind(id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let access = crate::permission_sets::export_sets(db)
        .await?
        .into_iter()
        .find(|(desc, _)| desc.name == row.1)
        .map(|(desc, _)| desc.entity_access)
        .unwrap_or_default()
        .into_iter()
        .map(|(entity, l)| SetEntityAccessItem {
            entity,
            read_access_level: l.read,
            write_access_level: l.write,
            delete_access_level: l.delete,
            create_access_level: l.create,
            assign_access_level: l.assign,
            share_access_level: l.share,
            export_access_level: l.export,
            bulk_access_level: l.bulk,
            read_bu_children: l.read_bu_children,
            write_bu_children: l.write_bu_children,
            delete_bu_children: l.delete_bu_children,
            assign_bu_children: l.assign_bu_children,
            share_bu_children: l.share_bu_children,
        })
        .collect();
    Ok(Json(PermissionSetDetail {
        set: item(row),
        privileges,
        entity_access: access,
    }))
}

/// Update a permission set
///
/// Changes a set's Arabic name or description. `If-Match: "<row_version>"` guards against a lost update. Administrators only; audited and recorded in the changeset.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/security/permission-sets/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The permission set")),
    request_body = UpdatePermissionSetBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = PermissionSetItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such live set", body = ErrorResponse),
        (status = 409, description = "The set changed since `If-Match`, it is owned by another layer, or no open changeset", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn update_set(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdatePermissionSetBody>,
) -> Result<Json<PermissionSetItem>, AppError> {
    let expected = match headers.get(IF_MATCH) {
        None => None,
        Some(raw) => Some(
            raw.to_str()
                .ok()
                .map(|s| s.trim().trim_matches('"'))
                .and_then(|s| s.parse::<i64>().ok())
                .ok_or_else(|| {
                    AppError::Validation("If-Match must be a row_version integer".into())
                })?,
        ),
    };
    recording.preflight(&state.base.db).await?;
    let mut tx = access_tx(
        &state,
        AuditOperation::Update,
        ctx.user_id,
        "permission_set",
        Some(id),
    )
    .await?;
    let row = lock_set(&mut tx, &recording, id).await?;
    if expected.is_some_and(|v| v != row.4) {
        return Err(AppError::Conflict(
            "version_conflict: the set changed; reload it",
        ));
    }
    sqlx::query(
        "UPDATE permission_set SET name_ar = COALESCE($2, name_ar), \
             description = COALESCE($3, description), is_customized = true, \
             updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(body.name_ar.as_deref())
    .bind(body.description.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let snapshot = snapshot_row(&mut tx, SET_SNAPSHOT, id).await?;
    recording
        .record(
            tx.tx(),
            security_op(
                Op::UpsertPermissionSet,
                "permission_set",
                id,
                serde_json::json!({ "permission_set": row.1 }),
                snapshot,
            ),
        )
        .await?;
    let row = set_row(&mut *tx, id).await?;
    tx.commit().await?;
    Ok(Json(item(row)))
}

/// Remove a permission set
///
/// Retires a set and ends its assignments; everyone it reached loses what it gave. Administrators only; audited and recorded in the changeset.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/permission-sets/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The permission set")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such live set", body = ErrorResponse),
        (status = 409, description = "Owned by another layer, or no open changeset", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_set(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    // The holders before the retire, which also ends their assignments.
    let holders = crate::permission_sets::set_holders(&state.base.db, id).await?;
    let mut tx = access_tx(
        &state,
        AuditOperation::SoftDelete,
        ctx.user_id,
        "permission_set",
        Some(id),
    )
    .await?;
    let row = lock_set(&mut tx, &recording, id).await?;
    retire_in_tx(&mut tx, id).await?;
    let snapshot = snapshot_row(&mut tx, SET_SNAPSHOT, id).await?;
    recording
        .record(
            tx.tx(),
            security_op(
                Op::RetirePermissionSet,
                "permission_set",
                id,
                serde_json::json!({ "permission_set": row.1 }),
                snapshot,
            ),
        )
        .await?;
    tx.commit().await?;
    super::shared::invalidate_sync_all(&state.base.security, holders).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Set an entity's levels in a permission set
///
/// Adds or replaces one entity's levels in a set. Administrators only; audited and recorded in the changeset.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/permission-sets/{id}/entity-access",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The permission set")),
    request_body = SetEntityAccessItem,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = SetEntityAccessItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such live set or entity", body = ErrorResponse),
        (status = 409, description = "Owned by another layer, or no open changeset", body = ErrorResponse),
        (status = 422, description = "A level outside 0..3", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn set_entity_access(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    Json(body): Json<SetEntityAccessItem>,
) -> Result<Json<SetEntityAccessItem>, AppError> {
    body.levels().validate()?;
    let entity_ref = super::shared::resolve_entity_ref(&state.base.db, &body.entity).await?;
    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;
    let mut tx = access_tx(
        &state,
        AuditOperation::Update,
        ctx.user_id,
        "permission_set",
        Some(id),
    )
    .await?;
    let row = lock_set(&mut tx, &recording, id).await?;
    let access_id =
        upsert_set_entity_access(&mut *tx, id, entity_ref, &body.levels(), layer).await?;
    let snapshot = snapshot_row(&mut tx, ACCESS_SNAPSHOT, access_id).await?;
    recording
        .record(
            tx.tx(),
            security_op(
                Op::SetPermissionSetEntityAccess,
                "permission_set_entity_access",
                access_id,
                serde_json::json!({ "permission_set": row.1, "entity": body.entity }),
                snapshot,
            ),
        )
        .await?;
    tx.commit().await?;
    invalidate(&state, id).await?;
    Ok(Json(body))
}

/// Clear an entity's levels from a permission set
///
/// The set stops giving anything on that entity. Administrators only; audited and recorded in the changeset.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/permission-sets/{id}/entity-access/{entity}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "The permission set"),
        ("entity" = String, Path, description = "The entity's logical name"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Cleared"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such set, or the set gives nothing on that entity", body = ErrorResponse),
        (status = 409, description = "Owned by another layer, or no open changeset", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn clear_entity_access(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((id, entity)): Path<(Uuid, String)>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = access_tx(
        &state,
        AuditOperation::Update,
        ctx.user_id,
        "permission_set",
        Some(id),
    )
    .await?;
    let row = lock_set(&mut tx, &recording, id).await?;
    let access_id: Uuid = sqlx::query_scalar(
        "UPDATE permission_set_entity_access ea SET is_deleted = true, updated_at = NOW(), \
             row_version = ea.row_version + 1 \
         FROM entity_info ei \
         WHERE ea.set_ref = $1 AND ea.entity_ref = ei.id AND ei.logicalname = $2 \
           AND ea.is_deleted = false \
         RETURNING ea.id",
    )
    .bind(id)
    .bind(&entity)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let snapshot = snapshot_row(&mut tx, ACCESS_SNAPSHOT, access_id).await?;
    recording
        .record(
            tx.tx(),
            security_op(
                Op::ClearPermissionSetEntityAccess,
                "permission_set_entity_access",
                access_id,
                serde_json::json!({ "permission_set": row.1, "entity": entity }),
                snapshot,
            ),
        )
        .await?;
    tx.commit().await?;
    invalidate(&state, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Add a privilege to a permission set
///
/// Never `system.admin` (422 `set_cannot_grant_admin`). Administrators only; audited and recorded in the changeset.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/permission-sets/{id}/privileges",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The permission set")),
    request_body = SetPrivilegeBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 204, description = "Granted (or already granted)"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such live set", body = ErrorResponse),
        (status = 409, description = "Owned by another layer, or no open changeset", body = ErrorResponse),
        (status = 422, description = "Unknown privilege, or `set_cannot_grant_admin`", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn grant_privilege(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    Json(body): Json<SetPrivilegeBody>,
) -> Result<StatusCode, AppError> {
    change_privilege(
        &state,
        &ctx,
        &recording,
        id,
        body.privilege_key.trim(),
        true,
    )
    .await
}

/// Take a privilege out of a permission set
///
/// Administrators only; audited and recorded in the changeset.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/permission-sets/{id}/privileges/{key}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "The permission set"),
        ("key" = String, Path, description = "The privilege key"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Revoked (or was not granted)"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such live set", body = ErrorResponse),
        (status = 409, description = "Owned by another layer, or no open changeset", body = ErrorResponse),
        (status = 422, description = "Unknown privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn revoke_privilege(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((id, key)): Path<(Uuid, String)>,
) -> Result<StatusCode, AppError> {
    change_privilege(&state, &ctx, &recording, id, key.trim(), false).await
}

async fn change_privilege(
    state: &EngineState,
    ctx: &Authorized<Admin>,
    recording: &RecordingCtx,
    id: Uuid,
    key: &str,
    granted: bool,
) -> Result<StatusCode, AppError> {
    if granted {
        refuse_admin(key)?;
    }
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1 AND is_active = true")
            .bind(key)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or_else(|| AppError::Validation(format!("no privilege {key}")))?;
    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;
    let operation = if granted {
        AuditOperation::Grant
    } else {
        AuditOperation::Revoke
    };
    let mut tx = access_tx(state, operation, ctx.user_id, "permission_set", Some(id)).await?;
    let row = lock_set(&mut tx, recording, id).await?;
    let changed = set_set_privilege(&mut *tx, id, privilege_id, granted, layer).await?;
    if changed > 0 {
        recording
            .record(
                tx.tx(),
                security_op(
                    if granted {
                        Op::GrantPermissionSetPrivilege
                    } else {
                        Op::RevokePermissionSetPrivilege
                    },
                    "permission_set_privilege",
                    id,
                    serde_json::json!({ "permission_set": row.1, "privilege": key }),
                    serde_json::json!({ "set_ref": id, "privilege_ref": privilege_id }),
                ),
            )
            .await?;
    }
    tx.commit().await?;
    if changed > 0 {
        invalidate(state, id).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// A permission set's assignments
///
/// Who the set is assigned to, live and ended. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/permission-set-assignments/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The permission set")),
    responses(
        (status = 200, description = "The assignments, newest first (page 1 holds them all)", body = PaginatedResponse<AssignmentItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such live set", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_assignments(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<AssignmentItem>>, AppError> {
    set_row(&state.base.db, id).await?;
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        Uuid,
        Option<Uuid>,
        Option<Uuid>,
        Option<DateTime<Utc>>,
        Option<String>,
        Option<Uuid>,
        DateTime<Utc>,
    )> = sqlx::query_as(
        "SELECT id, user_ref, team_ref, ends_at, reason, granted_by, created_at \
             FROM permission_set_assignment WHERE set_ref = $1 AND is_deleted = false \
             ORDER BY created_at DESC, id DESC LIMIT $2",
    )
    .bind(id)
    .bind(MAX_ASSIGNMENTS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<AssignmentItem> = rows
        .into_iter()
        .map(
            |(id, user_id, team_id, ends_at, reason, granted_by, created_at)| AssignmentItem {
                id,
                user_id,
                team_id,
                ends_at,
                reason,
                granted_by,
                created_at,
            },
        )
        .collect();
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        1,
        MAX_ASSIGNMENTS,
    )))
}

/// Assign a permission set
///
/// Gives the set to a user or a team, optionally until an end date. Environment data, not recorded in the changeset. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/permission-set-assignments/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The permission set")),
    request_body = CreateAssignmentBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 201, description = "Assigned", body = AssignmentItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such live set", body = ErrorResponse),
        (status = 422, description = "Not exactly one of user_id and team_id, an unknown one, or an end date in the past", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_assignment(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateAssignmentBody>,
) -> Result<(StatusCode, Json<AssignmentItem>), AppError> {
    if body.user_id.is_some() == body.team_id.is_some() {
        return Err(AppError::Validation(
            "specify exactly one of user_id or team_id".into(),
        ));
    }
    if body.ends_at.is_some_and(|t| t <= Utc::now()) {
        return Err(AppError::Validation("ends_at must be in the future".into()));
    }
    let db = &state.base.db;
    set_row(db, id).await?;
    let known: bool = match (body.user_id, body.team_id) {
        (Some(user), _) => {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_account WHERE id = $1)")
                .bind(user)
                .fetch_one(db)
                .await
        }
        (_, Some(team)) => {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM team WHERE id = $1)")
                .bind(team)
                .fetch_one(db)
                .await
        }
        _ => Ok(false),
    }
    .map_err(AppError::internal)?;
    if !known {
        return Err(AppError::Validation("no such user or team".into()));
    }
    let mut tx = access_tx(
        &state,
        AuditOperation::Grant,
        ctx.user_id,
        "permission_set",
        Some(id),
    )
    .await?;
    // Q10-T8: the set must not complete a conflicting pair for anyone it reaches.
    let reached: Vec<Uuid> = match (body.user_id, body.team_id) {
        (Some(user), _) => vec![user],
        (_, Some(team)) => sqlx::query_scalar(
            "SELECT user_ref FROM user_account_mm_team WHERE team_ref = $1 AND is_deleted = false",
        )
        .bind(team)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?,
        _ => Vec::new(),
    };
    for user in reached {
        crate::conflicts::refuse_any_conflict(&mut tx, user, crate::conflicts::GrantRef::Set(id))
            .await?;
    }
    let (assignment_id, created_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO permission_set_assignment \
             (set_ref, user_ref, team_ref, ends_at, reason, granted_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at",
    )
    .bind(id)
    .bind(body.user_id)
    .bind(body.team_id)
    .bind(body.ends_at)
    .bind(body.reason.as_deref())
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(attome_db::classify)?;
    tx.event_mut().set_record_id(assignment_id);
    tx.commit().await?;
    invalidate(&state, id).await?;
    Ok((
        StatusCode::CREATED,
        Json(AssignmentItem {
            id: assignment_id,
            user_id: body.user_id,
            team_id: body.team_id,
            ends_at: body.ends_at,
            reason: body.reason,
            granted_by: Some(ctx.user_id),
            created_at,
        }),
    ))
}

/// Remove a permission set assignment
///
/// The user or team stops getting the set. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/permission-set-assignments/{id}/{assignment_id}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "The permission set"),
        ("assignment_id" = Uuid, Path, description = "The assignment"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such live assignment of this set", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_assignment(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((id, assignment_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    // Who loses the set, read before the row goes.
    let holders = crate::permission_sets::set_holders(&state.base.db, id).await?;
    let mut tx = access_tx(
        &state,
        AuditOperation::Revoke,
        ctx.user_id,
        "permission_set",
        Some(id),
    )
    .await?;
    let n = sqlx::query(
        "UPDATE permission_set_assignment SET is_deleted = true \
         WHERE id = $1 AND set_ref = $2 AND is_deleted = false",
    )
    .bind(assignment_id)
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }
    tx.event_mut().set_record_id(assignment_id);
    tx.commit().await?;
    super::shared::invalidate_sync_all(&state.base.security, holders).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_sets,
    create_set,
    get_set,
    update_set,
    delete_set,
    set_entity_access,
    clear_entity_access,
    grant_privilege,
    revoke_privilege,
    list_assignments,
    create_assignment,
    delete_assignment,
))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/permission-sets",
            get(list_sets).post(create_set),
        )
        .route(
            "/api/v1/admin/security/permission-sets/{id}",
            get(get_set).patch(update_set).delete(delete_set),
        )
        .route(
            "/api/v1/admin/security/permission-sets/{id}/entity-access",
            post(set_entity_access),
        )
        .route(
            "/api/v1/admin/security/permission-sets/{id}/entity-access/{entity}",
            delete(clear_entity_access),
        )
        .route(
            "/api/v1/admin/security/permission-sets/{id}/privileges",
            post(grant_privilege),
        )
        .route(
            "/api/v1/admin/security/permission-sets/{id}/privileges/{key}",
            delete(revoke_privilege),
        )
        .route(
            "/api/v1/admin/security/permission-set-assignments/{id}",
            get(list_assignments).post(create_assignment),
        )
        .route(
            "/api/v1/admin/security/permission-set-assignments/{id}/{assignment_id}",
            delete(delete_assignment),
        )
}
