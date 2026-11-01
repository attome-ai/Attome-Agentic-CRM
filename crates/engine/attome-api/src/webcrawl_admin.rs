//! Web Crawling admin API (D-365) — extends D-363's Knowledge Base with a
//! website source. All routes require `Authorized<Admin>`, matching Knowledge
//! Base's own admin-authored posture (no license module bit gates this — see
//! `attome_webcrawl`'s crate doc for why). Crawl-triggering routes additionally
//! require `config.webcrawl.enabled` (default off); read routes always work.
//!
//! Creating the Data Source/Data Item rows an import produces goes through
//! `attome_records::entity_crud::create_record_for` — the same shared primitive the
//! generic `/api/v1/{entity}` route uses — rather than a hand-rolled INSERT,
//! so record-level security (the implicit `record_share` grant),
//! field validation, and audit all stay exactly as the platform guarantees
//! them for every other entity write (guidelines §9).

use attome_core::EngineState;
use attome_server::authz::{AdminArea, Authorized, SelfService};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use attome_webcrawl::admin::{Access, ChangeItem, RunItem, UpdateTargetBody, authorize};
use attome_webcrawl::model::{
    CreateTargetBody, ImportBody, ImportResult, PageListItem, SelectionBody, TARGET_COLUMNS,
    TargetListItem,
};
use attome_webcrawl::safety;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::{delete, get, patch, post},
};
use uuid::Uuid;

fn require_enabled(state: &EngineState) -> Result<(), AppError> {
    if state.base.config.webcrawl.enabled {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

// ── Targets ─────────────────────────────────────────────────────────────────

/// List crawl targets
///
/// List crawl targets. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/webcrawl/targets",
    tag = "admin-webcrawl",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<TargetListItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_targets(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<TargetListItem>>, AppError> {
    authorize(&ctx, Access::Read)?;
    let PageWindow {
        page,
        page_size,
        offset,
    } = q.window();

    let items = sqlx::query_as::<_, TargetListItem>(&format!(
        "SELECT {TARGET_COLUMNS} \
         FROM webcrawl_target \
         WHERE is_deleted = FALSE \
         ORDER BY created_at DESC \
         LIMIT $1 OFFSET $2"
    ))
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webcrawl_target WHERE is_deleted = FALSE")
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// Add a crawl target
///
/// Add a crawl target. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/webcrawl/targets",
    tag = "admin-webcrawl",
    request_body = CreateTargetBody,
    responses(
        (status = 201, description = "Success", body = TargetListItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or webcrawl.enabled is false", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create),
    ])))),
)]
async fn create_target(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<CreateTargetBody>,
) -> Result<(StatusCode, Json<TargetListItem>), AppError> {
    authorize(&ctx, Access::Manage)?;
    // K6-T10: an intranet host or a credential is an administrator's call.
    if !AdminArea::Integrations.held_by(&ctx)
        && (body.allow_host.is_some() || body.credential_ref.is_some())
    {
        return Err(AppError::Forbidden);
    }
    require_enabled(&state)?;

    body.validate_settings().map_err(AppError::Validation)?;
    let url_str = body.url.trim();
    // A bare domain ("techbay.io") has no scheme, which `Url::parse` rejects
    // outright rather than guessing one — default to https, same as a
    // browser's address bar, rather than surfacing that as a validation
    // error for the common case of a user typing a domain with no scheme.
    let url_str = if url_str.contains("://") {
        url_str.to_string()
    } else {
        format!("https://{url_str}")
    };
    let url = reqwest::Url::parse(&url_str)
        .map_err(|_| AppError::Validation("url is not a valid website address".into()))?;
    // Fast feedback on an obviously-unsafe URL. The crawl job re-validates
    // regardless (DNS can change between submission and crawl) — this is
    // convenience, not the enforcement point.
    safety::validate_url(&url)
        .await
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let max_depth = body
        .max_depth
        .unwrap_or(state.base.config.webcrawl.max_depth as i32)
        .clamp(
            attome_webcrawl::model::MIN_DEPTH,
            attome_webcrawl::model::MAX_DEPTH,
        );

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(attome_webcrawl::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("webcrawl/crawl:{}", url.as_str()))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a crawl of this URL is already being started",
        ));
    }

    // Submitting an already-crawled URL again is a recrawl, not a second
    // website — reuse the existing target row (with whatever depth was just
    // requested) instead of accumulating duplicates for the same site.
    let existing_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM webcrawl_target WHERE url = $1 AND is_deleted = FALSE")
            .bind(url.as_str())
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;

    let (status_code, event_name, row): (StatusCode, &str, TargetListItem) =
        if let Some(existing_id) = existing_id {
            let row = sqlx::query_as(&format!(
                "UPDATE webcrawl_target \
             SET status = 'pending', last_error = NULL, max_depth = $2, \
                 include_patterns = COALESCE($3, include_patterns), \
                 exclude_patterns = COALESCE($4, exclude_patterns), \
                 languages = COALESCE($5, languages), \
                 audience = COALESCE($6, audience), \
                 import_mode = COALESCE($7, import_mode), \
                 schedule = COALESCE($8, schedule), \
                 sitemap_url = COALESCE($9, sitemap_url), \
                 watch_only = COALESCE($10, watch_only), \
                 allow_host = COALESCE($11, allow_host), \
                 credential_ref = COALESCE($12, credential_ref), \
                 row_version = row_version + 1, updated_at = NOW() \
             WHERE id = $1 \
             RETURNING {TARGET_COLUMNS}"
            ))
            .bind(existing_id)
            .bind(max_depth as i16)
            .bind(body.include_patterns.as_deref())
            .bind(body.exclude_patterns.as_deref())
            .bind(body.languages.clone())
            .bind(body.audience.as_deref())
            .bind(body.import_mode.as_deref())
            .bind(body.schedule.as_deref())
            .bind(body.sitemap_url.as_deref())
            .bind(body.watch_only)
            .bind(body.allow_host.as_deref())
            .bind(body.credential_ref.as_deref())
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            (StatusCode::OK, "webcrawl_target_recrawled", row)
        } else {
            let row = sqlx::query_as(&format!(
                "INSERT INTO webcrawl_target \
                 (url, created_by, max_depth, include_patterns, exclude_patterns, languages, \
                  audience, import_mode, schedule, sitemap_url, watch_only, allow_host, \
                  credential_ref) \
             VALUES ($1, $2, $3, COALESCE($4, ''), COALESCE($5, ''), \
                     COALESCE($6, '{{}}'::text[]), COALESCE($7, 'internal'), \
                     COALESCE($8, 'review'), COALESCE($9, 'manual'), $10, \
                     COALESCE($11, false), COALESCE($12, ''), $13) \
             RETURNING {TARGET_COLUMNS}"
            ))
            .bind(url.as_str())
            .bind(ctx.user_id)
            .bind(max_depth as i16)
            .bind(body.include_patterns.as_deref())
            .bind(body.exclude_patterns.as_deref())
            .bind(body.languages.clone())
            .bind(body.audience.as_deref())
            .bind(body.import_mode.as_deref())
            .bind(body.schedule.as_deref())
            .bind(body.sitemap_url.as_deref())
            .bind(body.watch_only)
            .bind(body.allow_host.as_deref())
            .bind(body.credential_ref.as_deref())
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            (StatusCode::CREATED, "webcrawl_target_created", row)
        };

    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::CrawlWebsite { target_id: row.id },
    )
    .await
    .map_err(AppError::internal)?;

    // K6-T8: letting a source reach an intranet host, or sign in, is a
    // security choice: audited in the same transaction (the routes are
    // administrator-only).
    let non_empty = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.trim().is_empty());
    if non_empty(&body.allow_host) || non_empty(&body.credential_ref) {
        attome_audit::security::write_security_event(
            &mut tx,
            &attome_audit::audit_service(&state),
            attome_audit::security::SecurityEvent::new(
                attome_audit::security::MandatoryCategory::Configuration,
                attome_audit::AuditOperation::Update,
                ctx.user_id,
                "webcrawl_target",
                Some(row.id),
            )
            .named("webcrawl_target.network_access")
            .comment(format!(
                "allow_host={} credential_ref={}",
                body.allow_host.as_deref().unwrap_or(""),
                body.credential_ref.as_deref().unwrap_or("")
            )),
        )
        .await?;
    }

    tx.commit().await.map_err(AppError::internal)?;

    write_business_event(
        &state,
        &ctx,
        attome_audit::AuditOperation::Create,
        event_name,
        Some(row.id),
        &format!("started a web crawl of {}", url.as_str()),
    )
    .await;

    Ok((status_code, Json(row)))
}

/// Recrawl a target
///
/// Recrawl a target. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/webcrawl/targets/{id}/recrawl",
    tag = "admin-webcrawl",
    params(("id" = Uuid, Path, description = "The target")),
    responses(
        (status = 200, description = "Success", body = TargetListItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or webcrawl.enabled is false", body = ErrorResponse),
        (status = 404, description = "Target not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn recrawl_target(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<TargetListItem>, AppError> {
    authorize(&ctx, Access::Manage)?;
    require_enabled(&state)?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let row: Option<TargetListItem> = sqlx::query_as(&format!(
        "UPDATE webcrawl_target \
         SET status = 'pending', last_error = NULL, row_version = row_version + 1, updated_at = NOW() \
         WHERE id = $1 AND is_deleted = FALSE \
         RETURNING {TARGET_COLUMNS}"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;

    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::CrawlWebsite { target_id: id },
    )
    .await
    .map_err(AppError::internal)?;

    tx.commit().await.map_err(AppError::internal)?;

    write_business_event(
        &state,
        &ctx,
        attome_audit::AuditOperation::Update,
        "webcrawl_target_recrawled",
        Some(id),
        "recrawl requested",
    )
    .await;

    Ok(Json(row))
}

/// Delete a crawl target
///
/// Delete a crawl target. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/webcrawl/targets/{id}",
    tag = "admin-webcrawl",
    params(("id" = Uuid, Path, description = "The target")),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Target not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::SoftDelete),
    ])))),
)]
async fn delete_target(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    authorize(&ctx, Access::Manage)?;
    let result = sqlx::query(
        "UPDATE webcrawl_target SET is_deleted = TRUE, row_version = row_version + 1, updated_at = NOW() \
         WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    write_business_event(
        &state,
        &ctx,
        attome_audit::AuditOperation::SoftDelete,
        "webcrawl_target_deleted",
        Some(id),
        "target soft-deleted",
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Pages ───────────────────────────────────────────────────────────────────

/// A target's pages
///
/// A target's pages. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/webcrawl/targets/{id}/pages",
    operation_id = "list_webcrawl_target_pages",
    tag = "admin-webcrawl",
    params(("id" = Uuid, Path, description = "The target")),
    responses(
        (status = 200, description = "Success", body = Vec<PageListItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_target_pages(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<PageListItem>>, AppError> {
    authorize(&ctx, Access::Read)?;
    let items = sqlx::query_as::<_, PageListItem>(
        "SELECT id, url_path, parent_path, depth, size_bytes, status, is_selected, imported_data_item_ref \
         FROM webcrawl_page \
         WHERE target_ref = $1 AND is_deleted = FALSE \
         ORDER BY url_path ASC",
    )
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(items))
}

/// Select a target's pages
///
/// Select a target's pages. Administrators only. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/webcrawl/targets/{id}/pages/selection",
    tag = "admin-webcrawl",
    params(("id" = Uuid, Path, description = "The target")),
    request_body = SelectionBody,
    responses(
        (status = 200, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn update_selection(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<SelectionBody>,
) -> Result<StatusCode, AppError> {
    authorize(&ctx, Access::Manage)?;
    if body.page_ids.is_empty() {
        return Err(AppError::Validation("page_ids must not be empty".into()));
    }
    let page_count = body.page_ids.len();
    sqlx::query(
        "UPDATE webcrawl_page \
         SET is_selected = $3, row_version = row_version + 1, updated_at = NOW() \
         WHERE target_ref = $1 AND id = ANY($2) AND is_deleted = FALSE",
    )
    .bind(id)
    .bind(&body.page_ids)
    .bind(body.selected)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    write_business_event(
        &state,
        &ctx,
        attome_audit::AuditOperation::Update,
        "webcrawl_page_selection_updated",
        Some(id),
        &format!(
            "{page_count} page(s) marked {}",
            if body.selected {
                "selected"
            } else {
                "unselected"
            }
        ),
    )
    .await;
    Ok(StatusCode::OK)
}

// ── Import ──────────────────────────────────────────────────────────────────

/// Import crawled pages
///
/// Import crawled pages. A page imported before whose text changed on a
/// recrawl replaces its item's text as the next version (K6-T4).
/// Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/webcrawl/targets/{id}/import",
    tag = "admin-webcrawl",
    params(("id" = Uuid, Path, description = "The target")),
    request_body = ImportBody,
    responses(
        (status = 200, description = "New pages imported, and changed imported pages updated as new versions", body = ImportResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Target not found", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create),
    ])))),
)]
async fn import_pages(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<ImportBody>,
) -> Result<Json<ImportResult>, AppError> {
    authorize(&ctx, Access::Manage)?;
    attome_webcrawl::import::import_pages(&state, &ctx, id, &body.page_ids)
        .await
        .map(Json)
}

// ── K6-T10: settings, run history and changes to review ────────────────────

/// `If-Match: "<row_version>"`, required.
fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers.get(IF_MATCH).ok_or_else(|| {
        AppError::Validation("If-Match: \"<row_version>\" is required to change a source".into())
    })?;
    let value = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    value.parse::<i64>().map_err(|_| {
        AppError::Validation(format!(
            "If-Match must be a row_version integer, got: {value}"
        ))
    })
}

/// Change a crawl source's settings
///
/// Changes a source's settings; each one left out keeps its value. Send the
/// source's `row_version` as `If-Match`. A knowledge manager may change
/// everything but the intranet host and the credential, which stay with
/// administrators. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/webcrawl/targets/{id}",
    tag = "admin-webcrawl",
    params(
        ("id" = Uuid, Path, description = "The source"),
        ("If-Match" = String, Header, description = "The source's row_version, quoted"),
    ),
    request_body = UpdateTargetBody,
    responses(
        (status = 200, description = "The source as it now stands", body = TargetListItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not manage sources, or changed an administrator's setting", body = ErrorResponse),
        (status = 404, description = "No such source", body = ErrorResponse),
        (status = 409, description = "version_conflict: the source changed since it was read", body = ErrorResponse),
        (status = 422, description = "A missing or malformed If-Match, or a setting outside its values", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn patch_target(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<UpdateTargetBody>,
) -> Result<Json<TargetListItem>, AppError> {
    let expected = if_match(&headers)?;
    let row =
        attome_webcrawl::admin::update_target(&state.base.db, &ctx, id, expected, &body).await?;
    write_business_event(
        &state,
        &ctx,
        attome_audit::AuditOperation::Update,
        "webcrawl_target_settings_changed",
        Some(id),
        &format!("settings of {} changed", row.url),
    )
    .await;
    Ok(Json(row))
}

/// A crawl source's runs
///
/// Each crawl of the source, newest first: when it ran, how it ended, the
/// pages it found and what it did to the source's knowledge items.
#[utoipa::path(
    get,
    path = "/api/v1/webcrawl/targets/{id}/runs",
    tag = "admin-webcrawl",
    params(("id" = Uuid, Path, description = "The source"), OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<RunItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not read sources", body = ErrorResponse),
        (status = 404, description = "No such source", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_runs(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<RunItem>>, AppError> {
    attome_webcrawl::admin::runs(&state.base.db, &ctx, id, &q)
        .await
        .map(Json)
}

/// A crawl source's changes to review
///
/// The source's knowledge items a recrawl changed after an editor published
/// them: their text is kept and they wait for review (importing the page
/// again takes the site's version).
#[utoipa::path(
    get,
    path = "/api/v1/webcrawl/targets/{id}/changes",
    tag = "admin-webcrawl",
    params(("id" = Uuid, Path, description = "The source"), OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ChangeItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not read sources", body = ErrorResponse),
        (status = 404, description = "No such source", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_changes(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ChangeItem>>, AppError> {
    attome_webcrawl::admin::changes(&state.base.db, &ctx, id, &q)
        .await
        .map(Json)
}

/// A crawl target being created is a business event, not entity CRUD (D-363's
/// entities are the only registered ones this feature touches, and their own
/// `create_record_for` writes already audit themselves — see `import_pages`).
async fn write_business_event(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    operation: attome_audit::AuditOperation,
    event_name: &str,
    record_id: Option<Uuid>,
    comment: &str,
) {
    let (user_ctx, org_ref) =
        attome_records::entity_crud::fetch_audit_ctx(state, ctx.user_id).await;
    let event = attome_audit::AuditEvent {
        organization_ref: org_ref,
        category: attome_audit::AuditCategory::BusinessEvent,
        entity_name: Some("webcrawl_target".to_string()),
        record_id,
        operation,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: attome_audit::AuditSource::Api,
        request_context: attome_audit::AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(event_name.to_string()),
        event_comment: Some(comment.to_string()),
        changed_fields: vec![],
        snapshot_json: None,
    };
    let audit_service =
        attome_audit::AuditService::new(&state.base.db, state.audit_signer.as_deref())
            .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
            .with_chainer_enabled(state.base.config.audit.chainer_enabled)
            .with_erasure_key(state.audit_erasure_key.clone());
    if let Err(e) = audit_service.write(event).await {
        tracing::warn!(error = %e, event_name, "webcrawl: audit write failed");
    }
}

// ── Routes ──────────────────────────────────────────────────────────────────

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/webcrawl/targets",
            get(list_targets).post(create_target),
        )
        .route(
            "/api/v1/webcrawl/targets/{id}",
            delete(delete_target).patch(patch_target),
        )
        .route("/api/v1/webcrawl/targets/{id}/runs", get(list_runs))
        .route("/api/v1/webcrawl/targets/{id}/changes", get(list_changes))
        .route(
            "/api/v1/webcrawl/targets/{id}/recrawl",
            post(recrawl_target),
        )
        .route(
            "/api/v1/webcrawl/targets/{id}/pages",
            get(list_target_pages),
        )
        .route(
            "/api/v1/webcrawl/targets/{id}/pages/selection",
            patch(update_selection),
        )
        .route("/api/v1/webcrawl/targets/{id}/import", post(import_pages))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_targets,
    create_target,
    recrawl_target,
    delete_target,
    list_target_pages,
    update_selection,
    import_pages,
    patch_target,
    list_runs,
    list_changes
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
