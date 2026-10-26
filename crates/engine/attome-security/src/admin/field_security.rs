//! Field-security profiles (F013/F135, D-111). A profile is a named bundle
//! of per-(entity, field) read grants, assigned to roles the same way
//! privileges are — see `resolve_field_access` in db.rs. Also carries the
//! field-security profile ↔ role assignment endpoints.
//!
//! Solution 7 Phase 1 (D-785): profile create is recorded as
//! `upsert_field_profile` (target `{ profile }`), a member write as
//! `set_field_profile_field` (`{ profile, entity, field }`), and role links
//! as `assign_field_profile` / `unassign_field_profile` (`{ profile, role }`).
//! New rows are stamped with the changeset's layer; changing, restoring or
//! removing an existing row needs that row's own layer.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_core::changeset::{Op, RecordingCtx};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::{upsert_profile_field, users_holding_role};

use super::shared::{
    invalidate_sync_all, map_unique_violation, mark_profile_customized, mark_role_customized,
    parse_owner_layer, security_op, snapshot_row,
};

/// `field_security_profile`'s snapshot.
const PROFILE_SNAPSHOT: &str = "SELECT id, name, description, is_customized, is_deleted, \
     owner_layer FROM field_security_profile WHERE id = $1";

/// `field_security_profile_field`'s snapshot, profile by name.
const PROFILE_FIELD_SNAPSHOT: &str = "SELECT f.id, f.profile_ref, p.name AS profile, \
     f.entity_logicalname, f.field_logicalname, f.can_read, f.can_update, f.mask_format, \
     f.row_version, f.owner_layer \
     FROM field_security_profile_field f \
     JOIN field_security_profile p ON p.id = f.profile_ref \
     WHERE f.id = $1";

/// `role_mm_field_security_profile`'s snapshot, both ends by name.
const PROFILE_LINK_SNAPSHOT: &str = "SELECT l.id, l.role_ref, r.name AS role, l.profile_ref, \
     p.name AS profile, l.is_deleted, l.row_version, l.owner_layer \
     FROM role_mm_field_security_profile l \
     JOIN role r ON r.id = l.role_ref \
     JOIN field_security_profile p ON p.id = l.profile_ref \
     WHERE l.id = $1";

/// A live profile's name, or `None`.
async fn live_profile_name(
    conn: &mut sqlx::PgConnection,
    profile_id: Uuid,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar(
        "SELECT name FROM field_security_profile WHERE id = $1 AND is_deleted = false",
    )
    .bind(profile_id)
    .fetch_optional(conn)
    .await
    .map_err(AppError::internal)
}
use attome_types::ErrorResponse;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct FieldSecurityProfileItem {
    id: Uuid,
    name: String,
    description: Option<String>,
    /// Solution 7 (D-785): the layer that owns this profile.
    owner_layer: String,
}

impl std::fmt::Debug for FieldSecurityProfileItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldSecurityProfileItem")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub(super) struct CreateFieldSecurityProfileBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
}

/// List field-security profiles
///
/// Every field-security profile. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/field-profiles",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<FieldSecurityProfileItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_field_profiles(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<FieldSecurityProfileItem>>, AppError> {
    let window = query.window();

    let rows: Vec<(Uuid, String, Option<String>, String)> = sqlx::query_as(
        "SELECT id, name, description, owner_layer FROM field_security_profile \
         WHERE is_deleted = false ORDER BY name LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM field_security_profile WHERE is_deleted = false")
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(
            |(id, name, description, owner_layer)| FieldSecurityProfileItem {
                id,
                name,
                description,
                owner_layer,
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

/// Create a field-security profile
///
/// Creates a field-security profile, to assign to roles. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/field-profiles",
    tag = "admin-security",
    request_body = CreateFieldSecurityProfileBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = FieldSecurityProfileItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_field_profile(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Json(body): Json<CreateFieldSecurityProfileBody>,
) -> Result<(StatusCode, Json<FieldSecurityProfileItem>), AppError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;

    // P-environment-promotion §5 step 5: admin-authored rows carry the
    // ownership marker from birth.
    let id = Uuid::now_v7();
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Create,
        ctx.user_id,
        "field_security_profile",
        Some(id),
    )
    .await?;
    sqlx::query(
        "INSERT INTO field_security_profile \
             (id, name, description, is_customized, owner_layer) \
         VALUES ($1, $2, $3, true, $4)",
    )
    .bind(id)
    .bind(name)
    .bind(body.description.as_deref())
    .bind(layer.as_str())
    .execute(&mut *tx)
    .await
    .map_err(map_unique_violation)?;
    let snapshot = snapshot_row(&mut tx, PROFILE_SNAPSHOT, id).await?;
    recording
        .record(
            tx.tx(),
            security_op(
                Op::UpsertFieldProfile,
                "field_security_profile",
                id,
                serde_json::json!({ "profile": name }),
                snapshot,
            ),
        )
        .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(FieldSecurityProfileItem {
            id,
            name: name.to_owned(),
            description: body.description,
            owner_layer: layer.as_str().to_owned(),
        }),
    ))
}

#[derive(Serialize, ToSchema)]
pub struct FieldSecurityProfileFieldItem {
    id: Uuid,
    entity_logicalname: String,
    field_logicalname: String,
    can_read: bool,
    can_update: bool,
    /// Q15-T1: `last4`, `email`, `phone` or `full` when the profile shows the
    /// field only masked; absent when it shows it in full.
    #[serde(skip_serializing_if = "Option::is_none")]
    mask_format: Option<String>,
    /// Solution 7 (D-785): the layer that owns this member row.
    owner_layer: String,
}

impl std::fmt::Debug for FieldSecurityProfileFieldItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldSecurityProfileFieldItem")
            .finish_non_exhaustive()
    }
}

/// A profile's field rights
///
/// The entity fields a field-security profile can read or update. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/field-profiles/{id}/fields",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The field-security profile"), OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<FieldSecurityProfileFieldItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_field_profile_fields(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(profile_id): Path<Uuid>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<FieldSecurityProfileFieldItem>>, AppError> {
    let window = query.window();

    #[allow(clippy::type_complexity)]
    let rows: Vec<(Uuid, String, String, bool, bool, Option<String>, String)> = sqlx::query_as(
        "SELECT id, entity_logicalname, field_logicalname, can_read, can_update, mask_format, \
                owner_layer \
         FROM field_security_profile_field WHERE profile_ref = $1 \
         ORDER BY entity_logicalname, field_logicalname LIMIT $2 OFFSET $3",
    )
    .bind(profile_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM field_security_profile_field WHERE profile_ref = $1",
    )
    .bind(profile_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(
            |(
                id,
                entity_logicalname,
                field_logicalname,
                can_read,
                can_update,
                mask_format,
                owner_layer,
            )| {
                FieldSecurityProfileFieldItem {
                    id,
                    entity_logicalname,
                    field_logicalname,
                    can_read,
                    can_update,
                    mask_format,
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
pub(super) struct SetFieldProfileFieldBody {
    entity_logicalname: String,
    field_logicalname: String,
    can_read: bool,
    /// Omitted: true (P-field-write-security, D-141: an admin caller that only
    /// ever sent `can_read` keeps behaving as before, matching the column
    /// default), or false when `mask_format` is set (a masked field cannot be
    /// changed).
    #[serde(default)]
    can_update: Option<bool>,
    /// Q15-T1: show the field only masked: `last4`, `email`, `phone` or
    /// `full`. Needs `can_read`; omitted or null shows it in full.
    #[serde(default)]
    mask_format: Option<String>,
}

/// Set a profile's field right
///
/// Upserts one `(entity, field)` row's `can_read`/`can_update` for
/// `profile_id` — the bulk-set primitive the field-profile admin UI's
/// per-field checkboxes call one at a time; there's no separate "delete a
/// field row" endpoint since `can_read = false, can_update = false` is the
/// row's steady state, not its absence.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/field-profiles/{id}/fields",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The field-security profile")),
    request_body = SetFieldProfileFieldBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = FieldSecurityProfileFieldItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or the member row is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn set_field_profile_field(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(profile_id): Path<Uuid>,
    Json(body): Json<SetFieldProfileFieldBody>,
) -> Result<Json<FieldSecurityProfileFieldItem>, AppError> {
    let entity = body.entity_logicalname.trim();
    let field = body.field_logicalname.trim();
    if entity.is_empty() || field.is_empty() {
        return Err(AppError::Validation(
            "entity_logicalname and field_logicalname are required".into(),
        ));
    }
    // Q15-T1: a masked field is read masked and never changed.
    let mask_format = match body.mask_format.as_deref() {
        None => None,
        Some(name) => Some(
            attome_core::field_mask::MaskFormat::parse(name)
                .ok_or_else(|| {
                    AppError::Validation(format!(
                        "mask_format must be one of {}",
                        attome_core::field_mask::MaskFormat::ALL.join(", ")
                    ))
                })?
                .as_str(),
        ),
    };
    let can_update = body.can_update.unwrap_or(mask_format.is_none());
    if mask_format.is_some() && (can_update || !body.can_read) {
        return Err(AppError::Validation(
            "a masked field needs can_read and cannot be updated: send can_read true and \
             can_update false"
                .into(),
        ));
    }

    let profile_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM field_security_profile WHERE id = $1 AND is_deleted = false)",
    )
    .bind(profile_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !profile_exists {
        return Err(AppError::NotFound);
    }
    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;

    // C-19: the one atomic upsert, shared with `reconcile_field_security_profile`
    // — same `ON CONFLICT` statement, one copy instead of two.
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Update,
        ctx.user_id,
        "field_security_profile_field",
        None,
    )
    .await?;
    let profile_name = live_profile_name(&mut tx, profile_id)
        .await?
        .ok_or(AppError::NotFound)?;
    // An existing member is changed only by its own layer; one already
    // holding these permissions changes nothing and records nothing.
    let existing: Option<(String, bool, bool, Option<String>)> = sqlx::query_as(
        "SELECT owner_layer, can_read, can_update, mask_format FROM field_security_profile_field \
         WHERE profile_ref = $1 AND entity_logicalname = $2 AND field_logicalname = $3 \
         FOR UPDATE",
    )
    .bind(profile_id)
    .bind(entity)
    .bind(field)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let changes = match &existing {
        None => true,
        Some((owner, row_read, row_update, row_mask)) => {
            let same = (*row_read, *row_update, row_mask.as_deref())
                == (body.can_read, can_update, mask_format);
            if !same {
                recording.check_owner(parse_owner_layer(owner)?)?;
            }
            !same
        }
    };
    let id = upsert_profile_field(
        &mut *tx,
        profile_id,
        entity,
        field,
        body.can_read,
        can_update,
        layer,
    )
    .await?;
    sqlx::query("UPDATE field_security_profile_field SET mask_format = $2 WHERE id = $1")
        .bind(id)
        .bind(mask_format)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    mark_profile_customized(&mut *tx, profile_id).await?;
    let snapshot = snapshot_row(&mut tx, PROFILE_FIELD_SNAPSHOT, id).await?;
    let owner_layer = snapshot["owner_layer"]
        .as_str()
        .unwrap_or(layer.as_str())
        .to_owned();
    if changes {
        recording
            .record(
                tx.tx(),
                security_op(
                    Op::SetFieldProfileField,
                    "field_security_profile_field",
                    id,
                    serde_json::json!({
                        "profile": profile_name,
                        "entity": entity,
                        "field": field,
                    }),
                    snapshot,
                ),
            )
            .await?;
    }
    tx.event_mut().set_record_id(id);
    tx.commit().await?;

    // Every user reachable through any role this profile is assigned to needs
    // its cached field_grants recomputed — same fan-out shape as a role's
    // privilege grant, one query hop further through the assignment table.
    let user_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT ur.user_ref
        FROM user_account_mm_role ur
        JOIN role_mm_field_security_profile rp ON rp.role_ref = ur.role_ref
        WHERE rp.profile_ref = $1 AND ur.is_deleted = false AND rp.is_deleted = false
        "#,
    )
    .bind(profile_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    invalidate_sync_all(&state.base.security, user_ids).await?;

    Ok(Json(FieldSecurityProfileFieldItem {
        id,
        entity_logicalname: entity.to_owned(),
        field_logicalname: field.to_owned(),
        can_read: body.can_read,
        can_update,
        mask_format: mask_format.map(str::to_owned),
        owner_layer,
    }))
}

#[derive(Deserialize, ToSchema)]
pub(super) struct CreateFieldProfileAssignmentBody {
    role_id: Uuid,
}

/// Assign a profile to a role
///
/// Gives a role the field rights of a field-security profile. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/field-profiles/{id}/assignments",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The field-security profile")),
    request_body = CreateFieldProfileAssignmentBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or a removed link being restored is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn assign_field_profile(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(profile_id): Path<Uuid>,
    Json(body): Json<CreateFieldProfileAssignmentBody>,
) -> Result<StatusCode, AppError> {
    let profile_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM field_security_profile WHERE id = $1 AND is_deleted = false)",
    )
    .bind(profile_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !profile_exists {
        return Err(AppError::Validation(
            "no active field-security profile with this id".into(),
        ));
    }
    let role_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM role WHERE id = $1 AND is_deleted = false)",
    )
    .bind(body.role_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !role_exists {
        return Err(AppError::Validation(
            "no active role found with this role_id".into(),
        ));
    }
    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;

    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Grant,
        ctx.user_id,
        "role_mm_field_security_profile",
        None,
    )
    .await?;
    // A live link is re-assigned as a no-op (nothing recorded); a removed one
    // is restored, which needs the link row's own layer.
    let existing: Option<(bool, String)> = sqlx::query_as(
        "SELECT is_deleted, owner_layer FROM role_mm_field_security_profile \
         WHERE role_ref = $1 AND profile_ref = $2 FOR UPDATE",
    )
    .bind(body.role_id)
    .bind(profile_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let changes = match &existing {
        Some((false, _)) => false,
        Some((true, owner)) => {
            recording.check_owner(parse_owner_layer(owner)?)?;
            true
        }
        None => true,
    };
    let link_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO role_mm_field_security_profile (id, role_ref, profile_ref, owner_layer)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (role_ref, profile_ref) DO UPDATE SET is_deleted = false, updated_at = NOW()
        RETURNING id
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(body.role_id)
    .bind(profile_id)
    .bind(layer.as_str())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // The link is a property of the role's desired state (bundle
    // `roles[].field_security_profiles`), so the role carries the marker.
    mark_role_customized(&mut *tx, body.role_id).await?;
    if changes {
        let snapshot = snapshot_row(&mut tx, PROFILE_LINK_SNAPSHOT, link_id).await?;
        let target = serde_json::json!({
            "profile": snapshot["profile"],
            "role": snapshot["role"],
        });
        recording
            .record(
                tx.tx(),
                security_op(
                    Op::AssignFieldProfile,
                    "field_security_profile_link",
                    link_id,
                    target,
                    snapshot,
                ),
            )
            .await?;
    }
    tx.commit().await?;

    invalidate_sync_all(
        &state.base.security,
        users_holding_role(&state.base.db, body.role_id).await?,
    )
    .await?;

    Ok(StatusCode::CREATED)
}

/// Unassign a profile from a role
///
/// Takes a field-security profile's rights away from a role. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/field-profiles/{id}/assignments/{role_id}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "The field-security profile"),
        ("role_id" = Uuid, Path, description = "The role"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or the link is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn unassign_field_profile(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((profile_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Revoke,
        ctx.user_id,
        "role_mm_field_security_profile",
        None,
    )
    .await?;
    let live: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, owner_layer FROM role_mm_field_security_profile \
         WHERE profile_ref = $1 AND role_ref = $2 AND is_deleted = false FOR UPDATE",
    )
    .bind(profile_id)
    .bind(role_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (link_id, owner) = live.ok_or(AppError::NotFound)?;
    recording.check_owner(parse_owner_layer(&owner)?)?;
    let existed: bool = sqlx::query_scalar(
        "UPDATE role_mm_field_security_profile SET is_deleted = true, updated_at = NOW() \
         WHERE profile_ref = $1 AND role_ref = $2 AND is_deleted = false \
         RETURNING true",
    )
    .bind(profile_id)
    .bind(role_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .unwrap_or(false);
    if !existed {
        return Err(AppError::NotFound);
    }
    mark_role_customized(&mut *tx, role_id).await?;
    let snapshot = snapshot_row(&mut tx, PROFILE_LINK_SNAPSHOT, link_id).await?;
    let target = serde_json::json!({
        "profile": snapshot["profile"],
        "role": snapshot["role"],
    });
    recording
        .record(
            tx.tx(),
            security_op(
                Op::UnassignFieldProfile,
                "field_security_profile_link",
                link_id,
                target,
                snapshot,
            ),
        )
        .await?;
    tx.commit().await?;

    invalidate_sync_all(
        &state.base.security,
        users_holding_role(&state.base.db, role_id).await?,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/field-profiles",
            get(list_field_profiles).post(create_field_profile),
        )
        .route(
            "/api/v1/admin/security/field-profiles/{id}/fields",
            get(list_field_profile_fields).post(set_field_profile_field),
        )
        .route(
            "/api/v1/admin/security/field-profiles/{id}/assignments",
            axum::routing::post(assign_field_profile),
        )
        .route(
            "/api/v1/admin/security/field-profiles/{id}/assignments/{role_id}",
            axum::routing::delete(unassign_field_profile),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_field_profiles,
    create_field_profile,
    list_field_profile_fields,
    set_field_profile_field,
    assign_field_profile,
    unassign_field_profile
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
