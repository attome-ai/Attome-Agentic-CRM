//! D-589: a role's bulk-surface field exposure.
//!
//! `GET` reads a role's mode and listed fields. `PUT` replaces both in one
//! transaction with a D-542 security event, then invalidates every current
//! holder's cached `SecurityContext`, the same fan-out every role-mutating
//! handler here performs.
//!
//! Only non-sensitive fields are listed here. A sensitive field is exposed by
//! its field-security profile grant (D-111), on every surface, so listing it
//! would be a second switch for the same thing; the route refuses it.
//!
//! Solution 7 Phase 1 (D-785): `PUT` is recorded as `set_role_bulk_fields`
//! (target `{ role }`, snapshot the role's mode and whole field list). The
//! mode is a property of the role row, so the write needs the role's layer;
//! the replaced `role_bulk_field` rows are stamped with it.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_core::changeset::{Op, RecordingCtx};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::db::users_holding_role;

use super::shared::{invalidate_sync_all, lock_live_role, mark_role_customized, security_op};

/// `legacy` (0): every non-sensitive field, the behaviour before D-589.
/// `listed` (1): only the fields in `fields`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BulkFieldMode {
    Legacy,
    Listed,
}

impl BulkFieldMode {
    fn as_i16(self) -> i16 {
        match self {
            Self::Legacy => 0,
            Self::Listed => 1,
        }
    }

    fn from_i16(v: i16) -> Self {
        if v == 0 { Self::Legacy } else { Self::Listed }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct BulkField {
    pub entity: String,
    pub attribute: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RoleBulkFields {
    pub mode: BulkFieldMode,
    /// Meaningful in `listed` mode; kept as stored in `legacy` mode, so
    /// switching back to `listed` restores the list.
    pub fields: Vec<BulkField>,
}

impl std::fmt::Debug for RoleBulkFields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoleBulkFields").finish_non_exhaustive()
    }
}

/// Every attribute must exist on a live entity and not be sensitive.
fn validate(state: &EngineState, fields: &[BulkField]) -> Result<(), AppError> {
    let registry = state.entities.load();
    for f in fields {
        let Some(meta) = registry.get(&f.entity) else {
            return Err(AppError::Validation(format!(
                "unknown entity {:?}",
                f.entity
            )));
        };
        let Some(attr) = meta.attrs.iter().find(|a| a.logicalname == f.attribute) else {
            return Err(AppError::Validation(format!(
                "entity {:?} has no attribute {:?}",
                f.entity, f.attribute
            )));
        };
        if attr.is_sensitive {
            return Err(AppError::Validation(format!(
                "{}.{} is sensitive: expose it with a field-security profile, which applies \
                 on every surface",
                f.entity, f.attribute
            )));
        }
    }
    Ok(())
}

async fn load(state: &EngineState, role_id: Uuid) -> Result<RoleBulkFields, AppError> {
    let mode: Option<i16> =
        sqlx::query_scalar("SELECT bulk_field_mode FROM role WHERE id = $1 AND is_deleted = false")
            .bind(role_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let mode = mode.ok_or(AppError::NotFound)?;
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT entity_logicalname, attribute_logicalname FROM role_bulk_field \
         WHERE role_ref = $1 ORDER BY entity_logicalname, attribute_logicalname",
    )
    .bind(role_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(RoleBulkFields {
        mode: BulkFieldMode::from_i16(mode),
        fields: rows
            .into_iter()
            .map(|(entity, attribute)| BulkField { entity, attribute })
            .collect(),
    })
}

/// A role's field access
///
/// The field read and update access a role has, for editing many fields at once. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/roles/{id}/bulk-fields",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The role")),
    responses(
        (status = 200, description = "The role's bulk-surface field exposure (D-589)", body = RoleBulkFields),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such role", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_role_bulk_fields(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(role_id): Path<Uuid>,
) -> Result<Json<RoleBulkFields>, AppError> {
    Ok(Json(load(&state, role_id).await?))
}

/// Set a role's field access
///
/// Sets a role's read and update access on many fields in one change. Administrators only; audited.
#[utoipa::path(
    put,
    path = "/api/v1/admin/security/roles/{id}/bulk-fields",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The role")),
    request_body = RoleBulkFields,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Replaced; every holder's cached access is invalidated", body = RoleBulkFields),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such role", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or the role is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Unknown entity or attribute, or a sensitive field", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn put_role_bulk_fields(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(role_id): Path<Uuid>,
    Json(body): Json<RoleBulkFields>,
) -> Result<Json<RoleBulkFields>, AppError> {
    validate(&state, &body.fields)?;
    let mut fields = body.fields.clone();
    fields.sort();
    fields.dedup();
    recording.preflight(&state.base.db).await?;

    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Update,
        ctx.user_id,
        "role",
        Some(role_id),
    )
    .await?;
    let (role_name, owner) = lock_live_role(&mut tx, role_id)
        .await?
        .ok_or(AppError::NotFound)?;
    recording.check_owner(owner)?;
    let updated: Option<Uuid> = sqlx::query_scalar(
        "UPDATE role SET bulk_field_mode = $2, updated_at = NOW() \
         WHERE id = $1 AND is_deleted = false RETURNING id",
    )
    .bind(role_id)
    .bind(body.mode.as_i16())
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    updated.ok_or(AppError::NotFound)?;
    sqlx::query("DELETE FROM role_bulk_field WHERE role_ref = $1")
        .bind(role_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    for f in &fields {
        sqlx::query(
            "INSERT INTO role_bulk_field \
               (role_ref, entity_logicalname, attribute_logicalname, owner_layer) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(role_id)
        .bind(&f.entity)
        .bind(&f.attribute)
        .bind(owner.as_str())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    mark_role_customized(&mut *tx, role_id).await?;
    let snapshot = serde_json::json!({
        "id": role_id,
        "role": role_name,
        "bulk_field_mode": body.mode.as_i16(),
        "fields": fields,
        "owner_layer": owner.as_str(),
    });
    recording
        .record(
            tx.tx(),
            security_op(
                Op::SetRoleBulkFields,
                "role_bulk_fields",
                role_id,
                serde_json::json!({ "role": role_name }),
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

    Ok(Json(RoleBulkFields {
        mode: body.mode,
        fields,
    }))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/security/roles/{id}/bulk-fields",
        get(get_role_bulk_fields).put(put_role_bulk_fields),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_role_bulk_fields, put_role_bulk_fields))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
