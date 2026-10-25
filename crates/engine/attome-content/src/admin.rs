//! Content Management admin API — page CRUD, the editorial hierarchy
//! (`.../move`, `.../ancestors`), and draft/publish. Mounted in
//! `system.rs::core_routes()` behind `license_gate(..., MODULE_CONTENT, …)`
//! (the same helper `entity_crud`/`bulk` use for `MODULE_CORE`), so an
//! unlicensed deployment 404s every route here; each handler additionally
//! requires `Authorized<Admin>`.
//!
//! The public, anonymous page-view surface is a separate file
//! (`content_public.rs`) — this module never serves an unauthenticated
//! request.

use crate::hierarchy::{self, AncestorRow};
use crate::model::{
    Block, CreatePageBody, MovePageBody, PageDetail, PageStats, PageSummary, RelatedPagesBody,
    ReviewByBody, SchedulePageBody, UpdatePageBody, validate_url_path,
};
use crate::{blocks, hierarchy::try_lock_hierarchy};
use attome_core::EngineState;
use attome_db::is_unique_violation;
use attome_server::authz::{Admin, Authorized};
use attome_types::{
    AppError, DEFAULT_PAGE_SIZE, ErrorResponse, PageBase, PageWindow, PaginatedResponse,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::{get, patch, post, put},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::types::Json as SqlxJson;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

pub(crate) const PAGE_COLUMNS: &str = "id, parent_page_id, content_space_id, title, url_path, status, \
     template_id, blocks_draft, blocks_published, seo_title, seo_description, published_at, \
     publish_at, unpublish_at, row_version, created_at, updated_at, review_by, audience";

/// Parses the `If-Match` header into an expected `row_version` — the same
/// contract `entity_crud`'s generic PATCH enforces (D-079), reimplemented
/// here rather than reused across module boundaries (`entity_crud::
/// row_version`'s helpers are `pub(super)`, private to that module) since
/// it's a small, self-contained ~10 lines. Accepts `"3"` (quoted, as
/// `@attome/base`'s `ApiService.patch` sends) or a bare `3`. Mandatory on
/// every update — a missing header is a validation error, never an
/// unguarded last-write-wins update.
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

#[derive(Deserialize, IntoParams)]
struct ListQuery {
    /// Every list is scoped to one space — pages in other spaces never
    /// appear, matching the admin UI's per-space "Pages" screen.
    content_space_id: Uuid,
    /// Children of this page. Omit for root-level pages. Ignored when
    /// `search` is set (search runs across the whole tree).
    parent_page_id: Option<Uuid>,
    search: Option<String>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

// ── List / create ──────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/admin/content/pages",
    operation_id = "list_content_pages",
    tag = "admin-content",
    params(ListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<PageSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_pages(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<ListQuery>,
) -> Result<Json<PaginatedResponse<PageSummary>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    let (items, total) = if let Some(search) = q.search.as_deref().filter(|s| !s.trim().is_empty())
    {
        let pattern = format!("%{}%", search.trim());
        let items = sqlx::query_as::<_, PageSummary>(
            "SELECT id, parent_page_id, content_space_id, title, url_path, status, updated_at \
             FROM content_page \
             WHERE is_deleted = FALSE AND content_space_id = $4 AND title ILIKE $3 \
             ORDER BY title ASC LIMIT $1 OFFSET $2",
        )
        .bind(page_size)
        .bind(offset)
        .bind(&pattern)
        .bind(q.content_space_id)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_page \
             WHERE is_deleted = FALSE AND content_space_id = $2 AND title ILIKE $1",
        )
        .bind(&pattern)
        .bind(q.content_space_id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        (items, total)
    } else {
        let items = sqlx::query_as::<_, PageSummary>(
            "SELECT id, parent_page_id, content_space_id, title, url_path, status, updated_at \
             FROM content_page \
             WHERE is_deleted = FALSE AND content_space_id = $4 \
               AND parent_page_id IS NOT DISTINCT FROM $3 \
             ORDER BY title ASC LIMIT $1 OFFSET $2",
        )
        .bind(page_size)
        .bind(offset)
        .bind(q.parent_page_id)
        .bind(q.content_space_id)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_page \
             WHERE is_deleted = FALSE AND content_space_id = $2 \
               AND parent_page_id IS NOT DISTINCT FROM $1",
        )
        .bind(q.parent_page_id)
        .bind(q.content_space_id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        (items, total)
    };

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/content/pages",
    tag = "admin-content",
    request_body = CreatePageBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = PageDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 409, description = "url_path is already in use by another live page", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_page(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreatePageBody>,
) -> Result<(StatusCode, Json<PageDetail>), AppError> {
    let title = body.title.trim();
    if title.is_empty() {
        return Err(AppError::Validation("title must not be empty".into()));
    }
    validate_url_path(&body.url_path).map_err(AppError::Validation)?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let space_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM content_space WHERE id = $1 AND is_deleted = FALSE)",
    )
    .bind(body.content_space_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !space_exists {
        return Err(AppError::Validation(
            "content_space_id does not reference a live space".into(),
        ));
    }

    if let Some(parent_id) = body.parent_page_id {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM content_page \
             WHERE id = $1 AND content_space_id = $2 AND is_deleted = FALSE)",
        )
        .bind(parent_id)
        .bind(body.content_space_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if !exists {
            return Err(AppError::Validation(
                "parent_page_id does not reference a live page in the same space".into(),
            ));
        }
    }

    // A template must be one of the space's allowed set (content_space_
    // template) — its blocks are copied into blocks_draft once, here; there
    // is no ongoing link back to the template afterward (D-369).
    let initial_blocks: SqlxJson<Value> = if let Some(template_id) = body.template_id {
        let blocks: Option<Value> = sqlx::query_scalar(
            "SELECT t.blocks FROM content_template t \
             JOIN content_space_template st ON st.template_id = t.id \
             WHERE t.id = $1 AND st.content_space_id = $2 AND t.is_deleted = FALSE",
        )
        .bind(template_id)
        .bind(body.content_space_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let blocks = blocks.ok_or_else(|| {
            AppError::Validation("template_id is not an allowed template for this space".into())
        })?;
        SqlxJson(blocks)
    } else {
        SqlxJson(Value::Array(vec![]))
    };

    let sql = format!(
        "INSERT INTO content_page \
            (parent_page_id, content_space_id, title, url_path, template_id, blocks_draft, \
             created_by, updated_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
         RETURNING {PAGE_COLUMNS}"
    );
    let row = sqlx::query_as::<_, PageDetail>(&sql)
        .bind(body.parent_page_id)
        .bind(body.content_space_id)
        .bind(title)
        .bind(&body.url_path)
        .bind(body.template_id)
        .bind(initial_blocks)
        .bind(ctx.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                AppError::Conflict("a page with this url_path already exists")
            } else {
                AppError::internal(e)
            }
        })?;
    // E13-T5: a page created at a redirected path takes the path over.
    crate::redirect::release_path(&mut tx, &row.url_path).await?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            "content_page",
            Some(row.id),
        )
        .named("content_page.create"),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok((StatusCode::CREATED, Json(row)))
}

// ── Get / update / delete ──────────────────────────────────────────────────

/// E13-T8: one live page, for the engine functions that need it.
pub(crate) async fn load_page(db: &attome_db::DbPool, id: Uuid) -> Result<PageDetail, AppError> {
    let sql =
        format!("SELECT {PAGE_COLUMNS} FROM content_page WHERE id = $1 AND is_deleted = FALSE");
    sqlx::query_as::<_, PageDetail>(&sql)
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/content/pages/{id}",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = PageDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Page not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_page(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<PageDetail>, AppError> {
    Ok(Json(load_page(&state.base.db, id).await?))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/content/pages/{id}",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    request_body = UpdatePageBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = PageDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Page not found", body = ErrorResponse),
        (status = 409, description = "If-Match's row_version is stale, or url_path is already in use by another live page", body = ErrorResponse),
        (status = 422, description = "Request failed validation, or If-Match is missing/malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Requires an `If-Match: "<row_version>"` header on every call (D-079's
/// contract) — a missing or stale header is a 422, never an unguarded
/// last-write-wins update.
async fn update_page(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<UpdatePageBody>,
) -> Result<Json<PageDetail>, AppError> {
    let row_version = expected_row_version(&headers)?;
    if let Some(title) = &body.title
        && title.trim().is_empty()
    {
        return Err(AppError::Validation("title must not be empty".into()));
    }
    if let Some(url_path) = &body.url_path
        && validate_url_path(url_path).is_err()
    {
        // E13-T5: an Arabic page may have an Arabic path when the flag is on.
        let language: Option<Option<String>> = sqlx::query_scalar(
            "SELECT language FROM content_page WHERE id = $1 AND is_deleted = FALSE",
        )
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let arabic = crate::model::is_arabic_language(language.flatten().as_deref())
            && state
                .feature_flags()
                .is_on("content.seo_arabic_paths", &ctx)
                .await;
        crate::model::validate_url_path_with(url_path, arabic).map_err(AppError::Validation)?;
    }
    if let Some(page_blocks) = &body.blocks {
        blocks::validate_blocks(page_blocks).map_err(|e| AppError::Validation(e.to_string()))?;
    }

    // `seo_title`/`seo_description`: `None` leaves the stored value
    // unchanged; `Some("")` clears it to NULL; `Some(nonempty)` sets it.
    // This is deliberately NOT an `Option<Option<String>>` wire shape —
    // the editor's property panel is a controlled form that always has a
    // concrete string (possibly empty) to send once the field is touched,
    // so the ambiguity a bare `Option<String>` would otherwise have
    // ("omitted" vs "explicitly cleared") never arises in practice.
    let seo_title = body.seo_title.as_deref().map(str::trim);
    let seo_description = body.seo_description.as_deref().map(str::trim);

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let sql = format!(
        "WITH old AS ( \
            SELECT {PAGE_COLUMNS} FROM content_page WHERE id = $1 AND is_deleted = FALSE \
         ), updated AS ( \
            UPDATE content_page \
            SET title = COALESCE($2, title), \
                url_path = COALESCE($3, url_path), \
                blocks_draft = COALESCE($4, blocks_draft), \
                seo_title = CASE WHEN $5 = '' THEN NULL WHEN $5 IS NULL THEN seo_title ELSE $5 END, \
                seo_description = CASE WHEN $6 = '' THEN NULL WHEN $6 IS NULL THEN seo_description ELSE $6 END, \
                row_version = row_version + 1, \
                updated_at = NOW(), \
                updated_by = $7 \
            WHERE id = $1 AND is_deleted = FALSE AND row_version = $8 \
            RETURNING {PAGE_COLUMNS} \
         ) \
         SELECT (SELECT row_to_json(old) FROM old) AS old_row, \
                (SELECT row_to_json(updated) FROM updated) AS new_row"
    );
    let (old_row, new_row) = sqlx::query_as::<_, (Option<Value>, Option<Value>)>(&sql)
        .bind(id)
        .bind(body.title.as_deref().map(str::trim))
        .bind(body.url_path.as_deref())
        .bind(body.blocks.as_ref().map(SqlxJson))
        .bind(seo_title)
        .bind(seo_description)
        .bind(ctx.user_id)
        .bind(row_version)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                AppError::Conflict("a page with this url_path already exists")
            } else {
                AppError::internal(e)
            }
        })?;

    let new_row = match new_row {
        Some(row) => row,
        None if old_row.is_some() => return Err(AppError::VersionConflict),
        None => return Err(AppError::NotFound),
    };
    let page: PageDetail = serde_json::from_value(new_row).map_err(AppError::internal)?;
    // E13-T5: the old path keeps working, in this same transaction.
    if let Some(old_path) = old_row
        .as_ref()
        .and_then(|r| r.get("url_path"))
        .and_then(Value::as_str)
    {
        crate::redirect::record_path_change(&mut tx, page.id, old_path, &page.url_path).await?;
    }

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "content_page",
            Some(page.id),
        )
        .named("content_page.update"),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    // E13-T7: the page audit, after the save and never blocking it.
    crate::seo::audit::audit_after_save(&state, &ctx, &page).await;
    Ok(Json(page))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/content/pages/{id}",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Page not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_page(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let result = sqlx::query(
        "UPDATE content_page SET is_deleted = TRUE, row_version = row_version + 1, updated_at = NOW() \
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
            "content_page",
            Some(id),
        )
        .named("content_page.delete"),
    )
    .await?;
    // G11-T1: a deleted article leaves the knowledge index.
    crate::article::enqueue_sync_in_tx(&mut tx, id).await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Hierarchy ───────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/admin/content/pages/{id}/ancestors",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = Vec<AncestorRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_ancestors(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<AncestorRow>>, AppError> {
    let rows = hierarchy::ancestors(&state.base.db, id)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(rows))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/content/pages/{id}/move",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    request_body = MovePageBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = PageDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Page not found", body = ErrorResponse),
        (status = 409, description = "A hierarchy change is already in progress, or this move would create a cycle", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn move_page(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<MovePageBody>,
) -> Result<Json<PageDetail>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    // Entity-level (here, tree-level), non-blocking advisory lock — see
    // crate::hierarchy's doc comment for why this and the cycle guard
    // below always run together, unconditionally, matching D-095/D-138.
    let locked = try_lock_hierarchy(&mut tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a hierarchy change is already in progress for the page tree",
        ));
    }

    let space_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT content_space_id FROM content_page WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(space_id) = space_id else {
        return Err(AppError::NotFound);
    };

    // A page's tree stays inside its own space — same invariant
    // `create_page` enforces for a brand-new page's parent (D-369).
    if let Some(parent_id) = body.parent_page_id {
        let parent_space_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT content_space_id FROM content_page WHERE id = $1 AND is_deleted = FALSE",
        )
        .bind(parent_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if parent_space_id != Some(space_id) {
            return Err(AppError::Validation(
                "parent_page_id does not reference a live page in the same space".into(),
            ));
        }
    }

    let valid = hierarchy::is_valid_new_parent(&mut tx, id, body.parent_page_id)
        .await
        .map_err(AppError::internal)?;
    if !valid {
        return Err(AppError::Conflict(
            "moving this page under that parent would create a cycle",
        ));
    }

    let sql = format!(
        "UPDATE content_page \
         SET parent_page_id = $2, row_version = row_version + 1, updated_at = NOW(), updated_by = $3 \
         WHERE id = $1 AND is_deleted = FALSE \
         RETURNING {PAGE_COLUMNS}"
    );
    let row = sqlx::query_as::<_, PageDetail>(&sql)
        .bind(id)
        .bind(body.parent_page_id)
        .bind(ctx.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "content_page",
            Some(id),
        )
        .named("content_page.move"),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(row))
}

// ── Publish ─────────────────────────────────────────────────────────────────

/// A publish's outcome: published (with its version), or waiting for
/// approval in a space that requires it (K5-T1).
#[derive(Debug, Serialize, ToSchema)]
pub struct PublishResult {
    pub id: Uuid,
    /// `published`, or `pending_approval`.
    pub status: String,
    pub published_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The version this publish recorded.
    pub version_number: Option<i32>,
    /// The approval request a publish waits for.
    pub approval_request_id: Option<Uuid>,
}

/// Publishes a page's draft as `actor` and records it as the page's next
/// version (K5-T1), with its audit event, in one transaction. The caller has
/// already decided the publish may happen (directly, or approved).
pub async fn do_publish_page(
    state: &EngineState,
    id: Uuid,
    actor: Uuid,
    restored_from: Option<i32>,
) -> Result<PublishResult, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let draft: SqlxJson<Vec<Block>> = sqlx::query_scalar(
        "SELECT blocks_draft FROM content_page WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;

    // Re-validated at publish time, not just at each draft save — the block
    // registry (e.g. the Component allow-list) can change between when a
    // draft was last saved and when it's published.
    blocks::validate_blocks(&draft.0).map_err(|e| AppError::Validation(e.to_string()))?;

    let row: (Uuid, String, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
        "UPDATE content_page \
         SET blocks_published = blocks_draft, status = 'published', published_at = NOW(), \
             row_version = row_version + 1, updated_at = NOW(), updated_by = $2 \
         WHERE id = $1 AND is_deleted = FALSE \
         RETURNING id, status, published_at",
    )
    .bind(id)
    .bind(actor)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let version_number =
        crate::versions::record_version_in_tx(&mut tx, id, actor, restored_from).await?;
    // E12-T1: the version's HTML, rendered once here so serving it does no work.
    crate::render_html::render_version_in_tx(
        &mut tx,
        id,
        version_number,
        &crate::render_html::Site {
            base_url: state.base.config.frontend_url(),
        },
    )
    .await?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Activated,
            actor,
            "content_page",
            Some(row.0),
        )
        .named("content_page.publish")
        .comment(format!("version {version_number}")),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(PublishResult {
        id: row.0,
        status: row.1,
        published_at: Some(row.2),
        version_number: Some(version_number),
        approval_request_id: None,
    })
}

/// Publishes now (200), or, in a space with `require_approval`, submits the
/// publish for approval (202 with the request's id): K5-T1, through Z10's
/// approval engine (`crate::versions::ACTION_CONTENT_PUBLISH`).
pub async fn publish_or_submit(
    state: &EngineState,
    id: Uuid,
    actor: Uuid,
    restored_from: Option<i32>,
) -> Result<(StatusCode, Json<PublishResult>), AppError> {
    if crate::versions::space_requires_approval(&state.base.db, id).await? {
        let payload = serde_json::to_value(crate::versions::PublishPayload {
            page_id: id,
            restored_from,
        })
        .map_err(AppError::internal)?;
        let request = attome_audit::approval::gate_required(
            state,
            crate::versions::ACTION_CONTENT_PUBLISH,
            payload,
            actor,
            true,
        )
        .await?
        .ok_or_else(|| AppError::internal("a required page-publish approval was not opened"))?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(PublishResult {
                id,
                status: "pending_approval".to_owned(),
                published_at: None,
                version_number: None,
                approval_request_id: Some(request.id),
            }),
        ));
    }
    let published = do_publish_page(state, id, actor, restored_from).await?;
    Ok((StatusCode::OK, Json(published)))
}

/// Publishes a page's draft (K5-T1: as a new numbered version).
///
/// The draft's blocks are checked again and become the published content; the
/// publish is kept as the page's next version. In a space that requires
/// approval the publish waits for it instead (202 with the request's id).
#[utoipa::path(
    post,
    path = "/api/v1/admin/content/pages/{id}/publish",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The page's id")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Activated)])))),
    responses(
        (status = 200, description = "Published as a new version", body = PublishResult),
        (status = 202, description = "The publish waits for approval", body = PublishResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Page not found", body = ErrorResponse),
        (status = 422, description = "The current draft fails block validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn publish_page(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<PublishResult>), AppError> {
    publish_or_submit(&state, id, ctx.user_id, None).await
}

// ── Scheduled publishing ────────────────────────────────────────────────────

#[utoipa::path(
    put,
    path = "/api/v1/admin/content/pages/{id}/schedule",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    request_body = SchedulePageBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = PageDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Page not found", body = ErrorResponse),
        (status = 409, description = "If-Match's row_version is stale", body = ErrorResponse),
        (status = 422, description = "unpublish_at is not after publish_at, or If-Match is missing/malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Sets (or clears, via `null`) `publish_at`/`unpublish_at` — the sweep
/// (`attome_content::scheduling::sweep_scheduled_transitions`,
/// `EngineJob::ContentScheduledPublishSweep`) is what actually flips
/// `status` once one of these passes `NOW()`; this endpoint only records the
/// schedule. Requires `If-Match` (D-079's contract), same as `update_page`.
async fn schedule_page(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<SchedulePageBody>,
) -> Result<Json<PageDetail>, AppError> {
    let row_version = expected_row_version(&headers)?;
    if let (Some(publish_at), Some(unpublish_at)) = (body.publish_at, body.unpublish_at)
        && unpublish_at <= publish_at
    {
        return Err(AppError::Validation(
            "unpublish_at must be after publish_at".into(),
        ));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let sql = format!(
        "WITH old AS ( \
            SELECT {PAGE_COLUMNS} FROM content_page WHERE id = $1 AND is_deleted = FALSE \
         ), updated AS ( \
            UPDATE content_page \
            SET publish_at = $2, unpublish_at = $3, row_version = row_version + 1, \
                updated_at = NOW(), updated_by = $4 \
            WHERE id = $1 AND is_deleted = FALSE AND row_version = $5 \
            RETURNING {PAGE_COLUMNS} \
         ) \
         SELECT (SELECT row_to_json(old) FROM old) AS old_row, \
                (SELECT row_to_json(updated) FROM updated) AS new_row"
    );
    let (old_row, new_row) = sqlx::query_as::<_, (Option<Value>, Option<Value>)>(&sql)
        .bind(id)
        .bind(body.publish_at)
        .bind(body.unpublish_at)
        .bind(ctx.user_id)
        .bind(row_version)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    let new_row = match new_row {
        Some(row) => row,
        None if old_row.is_some() => return Err(AppError::VersionConflict),
        None => return Err(AppError::NotFound),
    };
    let page: PageDetail = serde_json::from_value(new_row).map_err(AppError::internal)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "content_page",
            Some(page.id),
        )
        .named("content_page.schedule"),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(page))
}

// ── Related pages ───────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/admin/content/pages/{id}/related",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = Vec<PageSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_related_pages(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<PageSummary>>, AppError> {
    let rows = sqlx::query_as::<_, PageSummary>(
        "SELECT p.id, p.parent_page_id, p.content_space_id, p.title, p.url_path, p.status, p.updated_at \
         FROM content_page p \
         JOIN content_page_related r ON r.related_page_id = p.id \
         WHERE r.page_id = $1 AND p.is_deleted = FALSE \
         ORDER BY p.title ASC",
    )
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(rows))
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/content/pages/{id}/related",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    request_body = RelatedPagesBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = Vec<PageSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Page not found", body = ErrorResponse),
        (status = 422, description = "related_page_ids includes this page itself, or a page that does not exist", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Full-set replace, symmetric: writes both (id, related) and (related, id)
/// for every entry, so a read for either page's related list is a
/// single-direction query (D-369).
async fn set_related_pages(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<RelatedPagesBody>,
) -> Result<Json<Vec<PageSummary>>, AppError> {
    if body.related_page_ids.contains(&id) {
        return Err(AppError::Validation(
            "related_page_ids must not include the page itself".into(),
        ));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM content_page WHERE id = $1 AND is_deleted = FALSE)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }

    if !body.related_page_ids.is_empty() {
        let live_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_page WHERE id = ANY($1) AND is_deleted = FALSE",
        )
        .bind(&body.related_page_ids)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if live_count as usize != body.related_page_ids.len() {
            return Err(AppError::Validation(
                "related_page_ids includes a page that does not exist".into(),
            ));
        }
    }

    sqlx::query("DELETE FROM content_page_related WHERE page_id = $1 OR related_page_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    for related_id in &body.related_page_ids {
        sqlx::query(
            "INSERT INTO content_page_related (page_id, related_page_id) VALUES ($1, $2), ($2, $1)",
        )
        .bind(id)
        .bind(related_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }

    let rows = sqlx::query_as::<_, PageSummary>(
        "SELECT p.id, p.parent_page_id, p.content_space_id, p.title, p.url_path, p.status, p.updated_at \
         FROM content_page p \
         JOIN content_page_related r ON r.related_page_id = p.id \
         WHERE r.page_id = $1 AND p.is_deleted = FALSE \
         ORDER BY p.title ASC",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "content_page",
            Some(id),
        )
        .named("content_page.set_related"),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(rows))
}

// ── Staleness / analytics (M37 Phase 2, D-452) ──────────────────────────────

#[utoipa::path(
    patch,
    path = "/api/v1/admin/content/pages/{id}/review-by",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    request_body = ReviewByBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = PageDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Page not found", body = ErrorResponse),
        (status = 409, description = "If-Match's row_version is stale", body = ErrorResponse),
        (status = 422, description = "If-Match is missing/malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Sets (or clears, via `null`) `review_by` — full replace (no empty-string
/// sentinel to resolve, unlike `seo_title`/`seo_description`), requiring
/// `If-Match` like every other page mutation (D-079). `PATCH`, not `PUT`
/// (unlike `schedule_page`'s otherwise-identical shape): `ApiService` (the
/// Angular client both surfaces share) has no `If-Match`-capable `put`, only
/// `patch` — `schedule_page` predates this endpoint and has no Angular
/// caller yet either, so this one follows the client capability that
/// actually exists rather than repeating the same gap.
/// `EngineJob::ContentReviewReminderSweep` reads this column, never writes
/// it; nothing else touches it.
async fn set_review_by(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<ReviewByBody>,
) -> Result<Json<PageDetail>, AppError> {
    let row_version = expected_row_version(&headers)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let sql = format!(
        "WITH old AS ( \
            SELECT {PAGE_COLUMNS} FROM content_page WHERE id = $1 AND is_deleted = FALSE \
         ), updated AS ( \
            UPDATE content_page \
            SET review_by = $2, row_version = row_version + 1, updated_at = NOW(), updated_by = $3 \
            WHERE id = $1 AND is_deleted = FALSE AND row_version = $4 \
            RETURNING {PAGE_COLUMNS} \
         ) \
         SELECT (SELECT row_to_json(old) FROM old) AS old_row, \
                (SELECT row_to_json(updated) FROM updated) AS new_row"
    );
    let (old_row, new_row) = sqlx::query_as::<_, (Option<Value>, Option<Value>)>(&sql)
        .bind(id)
        .bind(body.review_by)
        .bind(ctx.user_id)
        .bind(row_version)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    let new_row = match new_row {
        Some(row) => row,
        None if old_row.is_some() => return Err(AppError::VersionConflict),
        None => return Err(AppError::NotFound),
    };
    let page: PageDetail = serde_json::from_value(new_row).map_err(AppError::internal)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "content_page",
            Some(page.id),
        )
        .named("content_page.set_review_by"),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(page))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/content/pages/{id}/stats",
    tag = "admin-content",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success — zeroed row if the rollup has never run for this page", body = PageStats),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Page not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Reads `content_page_stats` — maintained only by
/// `EngineJob::ContentPageStatsRollup`, never by this route.
async fn page_stats(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<PageStats>, AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM content_page WHERE id = $1 AND is_deleted = FALSE)",
    )
    .bind(id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }

    let stats = crate::analytics::page_stats(&state.base.db, id).await?;
    Ok(Json(stats))
}

// ── Routes / OpenAPI ─────────────────────────────────────────────────────────

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/content/pages",
            get(list_pages).post(create_page),
        )
        .route(
            "/api/v1/admin/content/pages/{id}",
            get(get_page).patch(update_page).delete(delete_page),
        )
        .route(
            "/api/v1/admin/content/pages/{id}/publish",
            post(publish_page),
        )
        .route(
            "/api/v1/admin/content/pages/{id}/schedule",
            put(schedule_page),
        )
        .route("/api/v1/admin/content/pages/{id}/move", post(move_page))
        .route(
            "/api/v1/admin/content/pages/{id}/ancestors",
            get(get_ancestors),
        )
        .route(
            "/api/v1/admin/content/pages/{id}/related",
            get(get_related_pages).put(set_related_pages),
        )
        .route(
            "/api/v1/admin/content/pages/{id}/review-by",
            patch(set_review_by),
        )
        .route("/api/v1/admin/content/pages/{id}/stats", get(page_stats))
        .merge(crate::versions::routes())
        .merge(crate::audience::routes())
        .merge(crate::translations::routes())
        .merge(crate::article::routes())
        // E13-T8: page search settings, findings, topics and robots.txt.
        .merge(crate::seo::routes::routes())
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_pages,
    create_page,
    get_page,
    update_page,
    delete_page,
    publish_page,
    schedule_page,
    move_page,
    get_ancestors,
    get_related_pages,
    set_related_pages,
    set_review_by,
    page_stats,
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    let mut doc = <ApiDocFragment as utoipa::OpenApi>::openapi();
    doc.merge(crate::versions::openapi_fragment());
    doc.merge(crate::audience::openapi_fragment());
    doc.merge(crate::translations::openapi_fragment());
    doc.merge(crate::article::openapi_fragment());
    doc.merge(crate::seo::routes::openapi_fragment());
    doc
}
