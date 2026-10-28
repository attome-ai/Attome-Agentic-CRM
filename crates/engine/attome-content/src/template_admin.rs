//! Content Management admin API — Page Templates: reusable block content
//! selectable when creating a page (D-369, amends D-367). Mounted in
//! `system.rs::core_routes()` behind `license_gate(..., MODULE_CONTENT, …)`,
//! the same helper `content_admin`/`content_space_admin` use — an
//! unlicensed deployment 404s every route here; each handler additionally
//! requires `Authorized<Admin>`.
//!
//! Selecting a template copies its `blocks` into a new page's
//! `blocks_draft` once, at create time (`content_admin::create_page`) —
//! there is no ongoing link back to the template afterward, so editing a
//! template here never rewrites pages already built from it.

use crate::blocks;
use crate::model::{ContentTemplate, CreateTemplateBody, UpdateTemplateBody};
use attome_core::EngineState;
use attome_db::is_unique_violation;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::get,
};
use serde_json::Value;
use sqlx::types::Json as SqlxJson;
use uuid::Uuid;

const TEMPLATE_COLUMNS: &str = "id, name, description, blocks, row_version, created_at, updated_at";

/// Same `If-Match: "<row_version>"` contract as `content_admin::
/// expected_row_version` — reimplemented per-file, same reasoning as
/// `content_space_admin`'s copy.
fn expected_row_version(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(IF_MATCH)
        .ok_or_else(|| AppError::Validation("If-Match is required for every update".into()))?;
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

/// List content templates
///
/// Every page template that is not deleted, by name. Content administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/content/templates",
    tag = "admin-content",
    responses(
        (status = 200, description = "Success", body = Vec<ContentTemplate>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_templates(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Communication>>,
) -> Result<Json<Vec<ContentTemplate>>, AppError> {
    let sql = format!(
        "SELECT {TEMPLATE_COLUMNS} FROM content_template WHERE is_deleted = FALSE ORDER BY name ASC"
    );
    let rows = sqlx::query_as::<_, ContentTemplate>(&sql)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(rows))
}

/// Create a content template
///
/// A page template: its name, description and the blocks a page made from it starts with. Content
/// administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/content/templates",
    tag = "admin-content",
    request_body = CreateTemplateBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = ContentTemplate),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 409, description = "A template with this name already exists", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_template(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Communication>>,
    Json(body): Json<CreateTemplateBody>,
) -> Result<(StatusCode, Json<ContentTemplate>), AppError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    blocks::validate_blocks(&body.blocks).map_err(|e| AppError::Validation(e.to_string()))?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    // Solution 7 (D-785): content templates are Phase 3 customer-creatable
    // objects and are not recorded in Phase 1 (design §1.2); a new template
    // takes the deployment's automatic layer, what an unrecorded write stamps.
    let owner_layer = state.base.config.metadata.changesets.auto_layer;
    let sql = format!(
        "INSERT INTO content_template (name, description, blocks, created_by, updated_by, \
             owner_layer) \
         VALUES ($1, $2, $3, $4, $4, $5) RETURNING {TEMPLATE_COLUMNS}"
    );
    let row = sqlx::query_as::<_, ContentTemplate>(&sql)
        .bind(name)
        .bind(
            body.description
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty()),
        )
        .bind(SqlxJson(&body.blocks))
        .bind(ctx.user_id)
        .bind(owner_layer.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                AppError::Conflict("a template with this name already exists")
            } else {
                AppError::internal(e)
            }
        })?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            "content_template",
            Some(row.id),
        )
        .named("content_template.create"),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// Get a content template
///
/// One template with its blocks and `row_version`. Content administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/content/templates/{id}",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The template")),
    responses(
        (status = 200, description = "Success", body = ContentTemplate),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Template not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_template(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Communication>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ContentTemplate>, AppError> {
    let sql = format!(
        "SELECT {TEMPLATE_COLUMNS} FROM content_template WHERE id = $1 AND is_deleted = FALSE"
    );
    let row = sqlx::query_as::<_, ContentTemplate>(&sql)
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

/// Change a content template
///
/// Changes the name, description or blocks given;
/// Requires `If-Match: "<row_version>"`. Content administrators only. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/content/templates/{id}",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The template")),
    request_body = UpdateTemplateBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = ContentTemplate),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Template not found", body = ErrorResponse),
        (status = 409, description = "If-Match's row_version is stale, or a template with this name already exists", body = ErrorResponse),
        (status = 422, description = "Request failed validation, or If-Match is missing/malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_template(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Communication>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<UpdateTemplateBody>,
) -> Result<Json<ContentTemplate>, AppError> {
    let row_version = expected_row_version(&headers)?;
    if let Some(name) = &body.name
        && name.trim().is_empty()
    {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    if let Some(template_blocks) = &body.blocks {
        blocks::validate_blocks(template_blocks)
            .map_err(|e| AppError::Validation(e.to_string()))?;
    }
    let description = body.description.as_deref().map(str::trim);

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let sql = format!(
        "WITH old AS ( \
            SELECT {TEMPLATE_COLUMNS} FROM content_template WHERE id = $1 AND is_deleted = FALSE \
         ), updated AS ( \
            UPDATE content_template \
            SET name = COALESCE($2, name), \
                description = CASE WHEN $3 = '' THEN NULL WHEN $3 IS NULL THEN description ELSE $3 END, \
                blocks = COALESCE($4, blocks), \
                row_version = row_version + 1, \
                updated_at = NOW(), \
                updated_by = $5 \
            WHERE id = $1 AND is_deleted = FALSE AND row_version = $6 \
            RETURNING {TEMPLATE_COLUMNS} \
         ) \
         SELECT (SELECT row_to_json(old) FROM old) AS old_row, \
                (SELECT row_to_json(updated) FROM updated) AS new_row"
    );
    let (old_row, new_row) = sqlx::query_as::<_, (Option<Value>, Option<Value>)>(&sql)
        .bind(id)
        .bind(body.name.as_deref().map(str::trim))
        .bind(description)
        .bind(body.blocks.as_ref().map(SqlxJson))
        .bind(ctx.user_id)
        .bind(row_version)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                AppError::Conflict("a template with this name already exists")
            } else {
                AppError::internal(e)
            }
        })?;

    let new_row = match new_row {
        Some(row) => row,
        None if old_row.is_some() => return Err(AppError::VersionConflict),
        None => return Err(AppError::NotFound),
    };
    let template: ContentTemplate = serde_json::from_value(new_row).map_err(AppError::internal)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "content_template",
            Some(template.id),
        )
        .named("content_template.update"),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(template))
}

/// Delete a content template
///
/// Marks the template deleted. Content administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/content/templates/{id}",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The template")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Template not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_template(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Communication>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let result = sqlx::query(
        "UPDATE content_template SET is_deleted = TRUE, row_version = row_version + 1, updated_at = NOW() \
         WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::SoftDelete,
            ctx.user_id,
            "content_template",
            Some(id),
        )
        .named("content_template.delete"),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Routes / OpenAPI ─────────────────────────────────────────────────────────

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/content/templates",
            get(list_templates).post(create_template),
        )
        .route(
            "/api/v1/admin/content/templates/{id}",
            get(get_template)
                .patch(update_template)
                .delete(delete_template),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_templates,
    create_template,
    get_template,
    update_template,
    delete_template,
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
