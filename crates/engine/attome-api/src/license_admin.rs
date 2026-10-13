//! License Admin API — Module Management.
//!
//! All routes are under /api/v1/admin/license/ and require `system.admin`.
//!
//! D-778: no signed licence is checked. `GET`/`PUT .../modules` (Module
//! Management) is the only switch that changes what a deployment runs; the
//! running licence is always `ModuleSet::all()` narrowed by the
//! module configuration.
//!
//! The signed-licence `POST .../import` and `GET .../usage` routes were
//! deleted outright (D-790), together with their four-eyes action
//! (`license.import`). The generic entity CRUD endpoint
//! (`/api/v1/license`) remains reachable under ordinary per-entity
//! privileges, like any registered entity; nothing reads such a row for
//! enforcement.

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_modules::{MODULE_MAP, ModuleSet};
use attome_server::authz::{Admin, Authorized};
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{Json, Router, extract::State, routing::get};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/license/modules",
        get(get_module_configuration).put(update_module_configuration),
    )
}

#[derive(Serialize, ToSchema)]
struct ModuleConfigurationResponse {
    enabled: bool,
    /// The base platform modules (`attome_modules::MODULE_MAP`).
    modules: Vec<ModuleItem>,
    /// D-778: one section per installed vertical (project), with its areas.
    projects: Vec<ProjectSection>,
}

/// An installed vertical: a top-level sidebar group that a vertical bundle
/// created. Bundles write their sidebar roots with `is_customized = true` and
/// no `module_key` (every `verticals/*/bundle.json` does), which separates
/// them from the platform's own seeded groups. Switching a project or an area
/// off only hides it (`sidebar.is_active = false`, through
/// `PATCH /api/v1/sidebar/admin/{id}`); its data and API stay reachable.
#[derive(Serialize, ToSchema)]
struct ProjectSection {
    id: Uuid,
    name: String,
    is_active: bool,
    row_version: i64,
    areas: Vec<ProjectArea>,
}

/// One sidebar area of a project, e.g. Game Ops → Bans.
#[derive(Serialize, ToSchema)]
struct ProjectArea {
    id: Uuid,
    name: String,
    is_active: bool,
    row_version: i64,
}

/// The installed projects and their areas, inactive ones included so they
/// can be switched back on.
async fn project_sections(db: &attome_db::DbPool) -> Result<Vec<ProjectSection>, AppError> {
    let rows: Vec<(Uuid, Option<Uuid>, String, bool, i64)> = sqlx::query_as(
        "WITH roots AS (
             SELECT id FROM sidebar
              WHERE parent_ref IS NULL AND module_key IS NULL
                AND is_customized = true AND is_deleted = false
         )
         SELECT s.id, s.parent_ref, COALESCE(s.name, ''), COALESCE(s.is_active, true), s.row_version
           FROM sidebar s
          WHERE s.is_deleted = false
            AND (s.id IN (SELECT id FROM roots) OR s.parent_ref IN (SELECT id FROM roots))
          ORDER BY s.display_order, s.name",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut sections: Vec<ProjectSection> = rows
        .iter()
        .filter(|(_, parent, ..)| parent.is_none())
        .map(|(id, _, name, is_active, row_version)| ProjectSection {
            id: *id,
            name: name.clone(),
            is_active: *is_active,
            row_version: *row_version,
            areas: Vec::new(),
        })
        .collect();
    for (id, parent, name, is_active, row_version) in rows {
        let Some(parent) = parent else { continue };
        if let Some(section) = sections.iter_mut().find(|s| s.id == parent) {
            section.areas.push(ProjectArea {
                id,
                name,
                is_active,
                row_version,
            });
        }
    }
    Ok(sections)
}

#[derive(Serialize, ToSchema)]
struct ModuleItem {
    name: &'static str,
    enabled: bool,
    /// Always true since D-778 (no licence is checked); kept so the wire
    /// shape stays additive (D-678).
    licensed: bool,
}

/// One row per known module: selected in the configuration, and granted by
/// the signed licence.
fn module_items(selected: &[String], signed: &ModuleSet) -> Vec<ModuleItem> {
    MODULE_MAP
        .iter()
        .map(|(name, id)| ModuleItem {
            name,
            enabled: selected.iter().any(|selected| selected == name),
            licensed: signed.has(*id),
        })
        .collect()
}

#[derive(Deserialize, ToSchema)]
struct UpdateModuleConfiguration {
    enabled: bool,
    modules: Vec<String>,
}

/// The module bits a list of module names selects. Unknown names select
/// nothing (the `PUT` refuses them before they are stored).
fn configured_module_bits(modules: &[String]) -> attome_modules::ModuleBits {
    let mut bits = [0_u64; 4];
    for name in modules {
        if let Some((_, id)) = MODULE_MAP.iter().find(|(known, _)| *known == name) {
            bits[id.word] |= id.mask;
        }
    }
    bits
}

/// D-778: the only way modules are turned off — `signed` (always
/// `ModuleSet::all()` now) narrowed by the
/// `module_configuration` row. Used by `system::load_license` (boot
/// and the hourly reload) and by the `PUT` below. If the row cannot be read,
/// every module stays on until the next reload, and the failure is logged.
pub(crate) async fn narrow_by_runtime_configuration(
    db: &attome_db::DbPool,
    signed: &ModuleSet,
) -> ModuleSet {
    let row: Result<Option<(bool, Vec<String>)>, sqlx::Error> = sqlx::query_as(
        "SELECT enabled, enabled_modules FROM module_configuration WHERE singleton = TRUE",
    )
    .fetch_optional(db)
    .await;
    match row {
        Ok(row) => signed
            .narrowed_by(row.map(|(enabled, modules)| (enabled, configured_module_bits(&modules)))),
        Err(error) => {
            tracing::warn!(
                %error,
                "failed to load runtime module configuration; the signed license applies un-narrowed"
            );
            signed.clone()
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/license/modules",
    tag = "admin",
    responses(
        (status = 200, description = "Success", body = ModuleConfigurationResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_module_configuration(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<ModuleConfigurationResponse>, AppError> {
    let (enabled, selected): (bool, Vec<String>) = sqlx::query_as(
        "SELECT enabled, enabled_modules FROM module_configuration WHERE singleton = TRUE",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    // D-778: no signed licence; every module is available to switch on.
    let signed = ModuleSet::all();

    Ok(Json(ModuleConfigurationResponse {
        enabled,
        modules: module_items(&selected, &signed),
        projects: project_sections(&state.base.db).await?,
    }))
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/license/modules",
    tag = "admin",
    request_body = UpdateModuleConfiguration,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::License, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = ModuleConfigurationResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_module_configuration(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(request): Json<UpdateModuleConfiguration>,
) -> Result<Json<ModuleConfigurationResponse>, AppError> {
    // D-778: Module Management is the only module switch; any known module may
    // be turned on or off. No signed licence is consulted.
    let signed = ModuleSet::all();
    let mut modules = Vec::new();
    for name in request.modules {
        if !MODULE_MAP.iter().any(|(known, _)| *known == name) {
            return Err(AppError::Validation(format!("unknown module: {name}")));
        }
        if !modules.contains(&name) {
            modules.push(name);
        }
    }

    // Audit plan 3.3: the singleton row update and its `License` + `Update`
    // event commit together, before this node's arc-swap is touched.
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::License,
            AuditOperation::Update,
            ctx.user_id,
            "module_configuration",
            None,
        )
        .named(if request.enabled {
            "license_modules_enabled"
        } else {
            "license_modules_disabled"
        })
        .comment(format!("enabled_modules = [{}]", modules.join(", "))),
    )
    .await?;
    sqlx::query(
        "UPDATE module_configuration SET enabled = $1, enabled_modules = $2, updated_at = NOW() WHERE singleton = TRUE",
    )
    .bind(request.enabled)
    .bind(&modules)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;

    state.modules.store(std::sync::Arc::new(
        signed.narrowed_by(Some((request.enabled, configured_module_bits(&modules)))),
    ));

    Ok(Json(ModuleConfigurationResponse {
        enabled: request.enabled,
        modules: module_items(&modules, &signed),
        projects: project_sections(&state.base.db).await?,
    }))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(get_module_configuration, update_module_configuration))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
