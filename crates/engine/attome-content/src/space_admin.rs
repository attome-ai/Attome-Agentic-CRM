//! Content Management admin API — Content Spaces, the organizational
//! container pages belong to, and the space<->template allow-list
//! (D-369, amends D-367). Mounted in `system.rs::core_routes()` behind
//! `license_gate(..., MODULE_CONTENT, …)`, the same helper `content_admin`
//! uses — an unlicensed deployment 404s every route here; each handler
//! additionally requires `Authorized<Admin>`.
//!
//! A space is a pure organizational grouping, not a URL namespace — see
//! `content_admin.rs`'s module doc and D-369 for why `url_path` uniqueness
//! stays global across all spaces.

use crate::model::{ContentSpace, CreateSpaceBody, SpaceTemplatesBody, UpdateSpaceBody};
use attome_core::EngineState;
use attome_db::is_unique_violation;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::get,
};
use serde_json::Value;
use uuid::Uuid;

const SPACE_COLUMNS: &str = "id, name, description, require_approval, kind, domain, site_title, \
     theme, menu, blog_path, row_version, created_at, updated_at";

/// Same `If-Match: "<row_version>"` contract as `content_admin::
/// expected_row_version` — reimplemented here rather than shared across the
/// module boundary (`content_admin`'s helper is `pub(super)`/private), same
/// reasoning that file's own doc comment gives for its copy.
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

#[utoipa::path(
    get,
    path = "/api/v1/admin/content/spaces",
    tag = "admin-content",
    responses(
        (status = 200, description = "Success", body = Vec<ContentSpace>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_spaces(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<Vec<ContentSpace>>, AppError> {
    let sql = format!(
        "SELECT {SPACE_COLUMNS} FROM content_space WHERE is_deleted = FALSE ORDER BY name ASC"
    );
    let rows = sqlx::query_as::<_, ContentSpace>(&sql)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(rows))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/content/spaces",
    tag = "admin-content",
    request_body = CreateSpaceBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = ContentSpace),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 409, description = "A space with this name already exists", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_space(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreateSpaceBody>,
) -> Result<(StatusCode, Json<ContentSpace>), AppError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    let kind = body.kind.as_deref().map_or("standard", str::trim);
    if !crate::landing::SPACE_KINDS.contains(&kind) {
        return Err(AppError::Validation("kind is standard or marketing".into()));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    // Solution 7 (D-785): content spaces are Phase 3 customer-creatable
    // objects and are not recorded in Phase 1 (design §1.2); a new space takes
    // the deployment's automatic layer, what an unrecorded write stamps.
    let owner_layer = state.base.config.metadata.changesets.auto_layer;
    let sql = format!(
        "INSERT INTO content_space (name, description, created_by, updated_by, owner_layer, \
                                    require_approval, kind) \
         VALUES ($1, $2, $3, $3, $4, $5, $6) RETURNING {SPACE_COLUMNS}"
    );
    let row = sqlx::query_as::<_, ContentSpace>(&sql)
        .bind(name)
        .bind(
            body.description
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty()),
        )
        .bind(ctx.user_id)
        .bind(owner_layer.as_str())
        .bind(body.require_approval)
        .bind(kind)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                AppError::Conflict("a space with this name already exists")
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
            "content_space",
            Some(row.id),
        )
        .named("content_space.create"),
    )
    .await?;
    // E11-T1: a marketing space starts with the landing page templates.
    if kind == "marketing" {
        crate::landing::add_templates(&mut tx, row.id, ctx.user_id, owner_layer.as_str()).await?;
    }

    tx.commit().await.map_err(AppError::internal)?;
    Ok((StatusCode::CREATED, Json(row)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/content/spaces/{id}",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = ContentSpace),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Space not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_space(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<ContentSpace>, AppError> {
    let sql =
        format!("SELECT {SPACE_COLUMNS} FROM content_space WHERE id = $1 AND is_deleted = FALSE");
    let row = sqlx::query_as::<_, ContentSpace>(&sql)
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/content/spaces/{id}",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    request_body = UpdateSpaceBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = ContentSpace),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Space not found", body = ErrorResponse),
        (status = 409, description = "If-Match's row_version is stale, or a space with this name already exists", body = ErrorResponse),
        (status = 422, description = "Request failed validation, or If-Match is missing/malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_space(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<UpdateSpaceBody>,
) -> Result<Json<ContentSpace>, AppError> {
    let row_version = expected_row_version(&headers)?;
    if let Some(name) = &body.name
        && name.trim().is_empty()
    {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    let description = body.description.as_deref().map(str::trim);
    // E12-T2: the site settings, checked before anything is written.
    let domain = match body.domain.as_deref().map(str::trim) {
        Some("") => Some(String::new()),
        Some(d) => Some(crate::sites::normalise_domain(d).ok_or_else(|| {
            AppError::Validation("domain: a host name such as www.example.com".into())
        })?),
        None => None,
    };
    if let Some(theme) = &body.theme {
        crate::sites::validate_theme(theme)?;
    }
    if let Some(menu) = &body.menu {
        crate::sites::validate_menu(menu)?;
    }
    let blog_path = match body.blog_path.as_deref().map(str::trim) {
        Some(p) if !p.is_empty() && !(p.starts_with('/') && !p.starts_with("//")) => {
            return Err(AppError::Validation(
                "blog_path: a site path such as /blog".into(),
            ));
        }
        other => other.map(str::to_owned),
    };
    let theme = body
        .theme
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(AppError::internal)?;
    let menu = body
        .menu
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(AppError::internal)?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let sql = format!(
        "WITH old AS ( \
            SELECT {SPACE_COLUMNS} FROM content_space WHERE id = $1 AND is_deleted = FALSE \
         ), updated AS ( \
            UPDATE content_space \
            SET name = COALESCE($2, name), \
                description = CASE WHEN $3 = '' THEN NULL WHEN $3 IS NULL THEN description ELSE $3 END, \
                require_approval = COALESCE($6, require_approval), \
                domain = CASE WHEN $7 = '' THEN NULL WHEN $7 IS NULL THEN domain ELSE $7 END, \
                site_title = CASE WHEN $8 = '' THEN NULL WHEN $8 IS NULL THEN site_title ELSE $8 END, \
                theme = COALESCE($9, theme), \
                menu = COALESCE($10, menu), \
                blog_path = CASE WHEN $11 = '' THEN NULL WHEN $11 IS NULL THEN blog_path ELSE $11 END, \
                row_version = row_version + 1, \
                updated_at = NOW(), \
                updated_by = $4 \
            WHERE id = $1 AND is_deleted = FALSE AND row_version = $5 \
            RETURNING {SPACE_COLUMNS} \
         ) \
         SELECT (SELECT row_to_json(old) FROM old) AS old_row, \
                (SELECT row_to_json(updated) FROM updated) AS new_row"
    );
    let (old_row, new_row) = sqlx::query_as::<_, (Option<Value>, Option<Value>)>(&sql)
        .bind(id)
        .bind(body.name.as_deref().map(str::trim))
        .bind(description)
        .bind(ctx.user_id)
        .bind(row_version)
        .bind(body.require_approval)
        .bind(&domain)
        .bind(body.site_title.as_deref().map(str::trim))
        .bind(&theme)
        .bind(&menu)
        .bind(&blog_path)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            let on_domain = e
                .as_database_error()
                .and_then(|d| d.constraint())
                .is_some_and(|c| c == "content_space_domain_uq");
            if on_domain {
                AppError::Conflict("another space is served on this domain")
            } else if is_unique_violation(&e) {
                AppError::Conflict("a space with this name already exists")
            } else {
                AppError::internal(e)
            }
        })?;

    let new_row = match new_row {
        Some(row) => row,
        None if old_row.is_some() => return Err(AppError::VersionConflict),
        None => return Err(AppError::NotFound),
    };
    let space: ContentSpace = serde_json::from_value(new_row).map_err(AppError::internal)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "content_space",
            Some(space.id),
        )
        .named("content_space.update"),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(space))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/content/spaces/{id}",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Space not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_space(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let result = sqlx::query(
        "UPDATE content_space SET is_deleted = TRUE, row_version = row_version + 1, updated_at = NOW() \
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
            "content_space",
            Some(id),
        )
        .named("content_space.delete"),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Space <-> Template allow-list ────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/admin/content/spaces/{id}/templates",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = Vec<Uuid>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_space_templates(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Uuid>>, AppError> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT template_id FROM content_space_template WHERE content_space_id = $1",
    )
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(ids))
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/content/spaces/{id}/templates",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    request_body = SpaceTemplatesBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = Vec<Uuid>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Space not found", body = ErrorResponse),
        (status = 422, description = "template_ids includes a template that does not exist", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Full-set replace of the space's allowed templates.
async fn set_space_templates(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<SpaceTemplatesBody>,
) -> Result<Json<Vec<Uuid>>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM content_space WHERE id = $1 AND is_deleted = FALSE)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }

    if !body.template_ids.is_empty() {
        let live_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_template WHERE id = ANY($1) AND is_deleted = FALSE",
        )
        .bind(&body.template_ids)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if live_count as usize != body.template_ids.len() {
            return Err(AppError::Validation(
                "template_ids includes a template that does not exist".into(),
            ));
        }
    }

    sqlx::query("DELETE FROM content_space_template WHERE content_space_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    for template_id in &body.template_ids {
        sqlx::query(
            "INSERT INTO content_space_template (content_space_id, template_id) VALUES ($1, $2)",
        )
        .bind(id)
        .bind(template_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "content_space",
            Some(id),
        )
        .named("content_space.set_templates"),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(body.template_ids))
}

// ── Routes / OpenAPI ─────────────────────────────────────────────────────────

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/content/spaces",
            get(list_spaces).post(create_space),
        )
        .route(
            "/api/v1/admin/content/spaces/{id}",
            get(get_space).patch(update_space).delete(delete_space),
        )
        .route(
            "/api/v1/admin/content/spaces/{id}/templates",
            get(get_space_templates).put(set_space_templates),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_spaces,
    create_space,
    get_space,
    update_space,
    delete_space,
    get_space_templates,
    set_space_templates,
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
