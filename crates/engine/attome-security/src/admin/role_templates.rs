//! Q10-T7: the roles modules suggest, and installing one as a copy.
//!
//! `GET /api/v1/admin/security/role-templates` lists the templates of every
//! licensed, installed module (`attome_core::model::RoleTemplate`, collected
//! from `EngineModel::role_templates`). `POST .../{key}/install` creates an
//! ordinary role from one: its privileges and entity levels are written and
//! recorded in the changeset ledger exactly as an administrator adding them
//! one by one would be (`upsert_role`, `grant_role_privilege`,
//! `set_role_entity_access`), and `role_template_install` remembers where it
//! came from. The copy is the administrators' from then on: upgrades never
//! change it and there is no re-sync. A privilege or entity this deployment
//! does not have is skipped and named in the answer.

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_core::changeset::{Op, RecordingCtx};
use attome_core::model::RoleTemplate;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::db::{upsert_role_entity_access, upsert_role_privilege_grant};

use super::shared::{ROLE_SNAPSHOT, map_unique_violation, security_op, snapshot_row};

/// One suggested role.
#[derive(Debug, Serialize, ToSchema)]
pub struct RoleTemplateItem {
    key: String,
    /// The module that suggests it.
    module: String,
    name: String,
    name_ar: String,
    description: String,
    privileges: Vec<String>,
    /// `{entity: [read, write, delete]}` levels, 0 None .. 3 Global.
    entity_access: Vec<(String, [i16; 3])>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct InstallTemplateBody {
    /// The new role's name; the template's name when omitted.
    #[serde(default)]
    name: Option<String>,
}

/// What an install created.
#[derive(Debug, Serialize, ToSchema)]
pub struct InstalledRole {
    role_id: Uuid,
    name: String,
    template: String,
    /// Privileges and entities the template names that this deployment does
    /// not have, left out.
    skipped: Vec<String>,
}

fn licensed(state: &EngineState) -> Vec<(attome_modules::ModuleId, RoleTemplate)> {
    let modules = state.modules.load();
    state
        .role_templates
        .iter()
        .filter(|(module, _)| modules.require(*module).is_ok())
        .copied()
        .collect()
}

/// Suggested roles
///
/// The roles the licensed, installed modules suggest, to install as editable copies. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/role-templates",
    tag = "admin-security",
    responses(
        (status = 200, description = "Success", body = Vec<RoleTemplateItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_templates(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<Vec<RoleTemplateItem>>, AppError> {
    Ok(Json(
        licensed(&state)
            .into_iter()
            .map(|(module, t)| RoleTemplateItem {
                key: t.key.to_owned(),
                module: attome_modules::module_name(module)
                    .unwrap_or("unknown")
                    .to_owned(),
                name: t.name.to_owned(),
                name_ar: t.name_ar.to_owned(),
                description: t.description.to_owned(),
                privileges: t.privileges.iter().map(|p| (*p).to_owned()).collect(),
                entity_access: t
                    .entity_access
                    .iter()
                    .map(|(e, l)| ((*e).to_owned(), *l))
                    .collect(),
            })
            .collect(),
    ))
}

/// Install a suggested role
///
/// Creates a new, independent role from a module's template; edit it freely afterwards, upgrades never change it. Administrators only; audited and recorded in the changeset.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/role-templates/{key}/install",
    tag = "admin-security",
    params(("key" = String, Path, description = "The template key")),
    request_body = InstallTemplateBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The new role", body = InstalledRole),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such template among the licensed modules", body = ErrorResponse),
        (status = 409, description = "A role with this name exists, or no open changeset", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn install_template(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(key): Path<String>,
    body: Option<Json<InstallTemplateBody>>,
) -> Result<(StatusCode, Json<InstalledRole>), AppError> {
    let template = licensed(&state)
        .into_iter()
        .map(|(_, t)| t)
        .find(|t| t.key == key)
        .ok_or(AppError::NotFound)?;
    let name = body
        .and_then(|Json(b)| b.name)
        .map(|n| n.trim().to_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| template.name.to_owned());

    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;
    let role_id = Uuid::now_v7();
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Access,
            AuditOperation::Create,
            ctx.user_id,
            "role",
            Some(role_id),
        ),
    )
    .await?;
    // A role created by an administrator, D-589 `listed` like `create_role`'s.
    sqlx::query(
        "INSERT INTO role (id, name, description, is_customized, bulk_field_mode, owner_layer) \
         VALUES ($1, $2, $3, true, 1, $4)",
    )
    .bind(role_id)
    .bind(&name)
    .bind(template.description)
    .bind(layer.as_str())
    .execute(&mut *tx)
    .await
    .map_err(map_unique_violation)?;
    let snapshot = snapshot_row(&mut tx, ROLE_SNAPSHOT, role_id).await?;
    recording
        .record(
            tx.tx(),
            security_op(
                Op::UpsertRole,
                "role",
                role_id,
                serde_json::json!({ "role": name }),
                snapshot,
            ),
        )
        .await?;

    let mut skipped = Vec::new();
    for privilege in template.privileges {
        let privilege_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1 AND is_active = true")
                .bind(privilege)
                .fetch_optional(&mut *tx)
                .await
                .map_err(AppError::internal)?;
        let Some(privilege_id) = privilege_id else {
            skipped.push(format!("privilege {privilege}"));
            continue;
        };
        let grant_id = upsert_role_privilege_grant(&mut *tx, role_id, privilege_id, layer).await?;
        let snapshot = snapshot_row(&mut tx, super::role_grants::GRANT_SNAPSHOT, grant_id).await?;
        recording
            .record(
                tx.tx(),
                security_op(
                    Op::GrantRolePrivilege,
                    "role_privilege",
                    grant_id,
                    serde_json::json!({ "role": name, "privilege": privilege }),
                    snapshot,
                ),
            )
            .await?;
    }
    for (entity, [read, write, delete]) in template.entity_access {
        let entity_ref: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = $1")
                .bind(entity)
                .fetch_optional(&mut *tx)
                .await
                .map_err(AppError::internal)?;
        let Some(entity_ref) = entity_ref else {
            skipped.push(format!("entity {entity}"));
            continue;
        };
        let access_id = upsert_role_entity_access(
            &mut *tx, role_id, entity_ref, *read, *write, *delete, false, false, false, layer,
        )
        .await?;
        let snapshot = snapshot_row(
            &mut tx,
            super::role_entity_access::ENTITY_ACCESS_SNAPSHOT,
            access_id,
        )
        .await?;
        recording
            .record(
                tx.tx(),
                security_op(
                    Op::SetRoleEntityAccess,
                    "role_entity_access",
                    access_id,
                    serde_json::json!({ "role": name, "entity": entity }),
                    snapshot,
                ),
            )
            .await?;
    }
    sqlx::query(
        "INSERT INTO role_template_install (role_ref, template_key, installed_by) \
         VALUES ($1, $2, $3)",
    )
    .bind(role_id)
    .bind(template.key)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(InstalledRole {
            role_id,
            name,
            template: template.key.to_owned(),
            skipped,
        }),
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_templates, install_template))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/security/role-templates", get(list_templates))
        .route(
            "/api/v1/admin/security/role-templates/{key}/install",
            post(install_template),
        )
}
