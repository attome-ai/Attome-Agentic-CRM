//! M14 Phase 1 (Data Quality) — the admin surface: read-only score/issue
//! listing plus the one issue-resolution action, `/api/v1/admin/data/
//! quality*`. `system.admin` only, mounted with `strict_authz` — same
//! posture as every other `/admin/data/*` surface (`duplicates_admin.rs`,
//! `data_profile_admin.rs`). The scoring sweep itself
//! (`EngineJob::DataQualityScoreSweep`) lives in `quality_score.rs`; this
//! file only reads what that job wrote and lets a steward close an issue
//! its own remediation (a bulk transform, a fixed record) already resolved.
//!
//! Phase 1 scope note (see `quality_score.rs`'s module doc and migration
//! `0386`'s comment): two dimensions only, `completeness` and `uniqueness`.
//! No M27 metric-adapter wiring and no Angular dashboard page yet — both
//! explicitly deferred to a later pass; this is the minimal read surface the
//! M51 alert this job raises already links to (`/admin/data/quality`).

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, audit_service,
};
use attome_core::EngineState;
use attome_records::entity_crud;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

const DIMENSIONS: [&str; 2] = ["completeness", "uniqueness"];

// ── Scores ───────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow, Serialize, ToSchema)]
struct QualityScoreView {
    id: Uuid,
    entity_logicalname: String,
    period: String,
    dimension: String,
    pass_count: i64,
    fail_count: i64,
    sample_size: i64,
    score: f64,
    computed_at: DateTime<Utc>,
}

#[derive(Deserialize, IntoParams)]
struct ListScoresQuery {
    /// Filter to one entity's scores. Omit for every entity.
    entity: Option<String>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

/// `GET /api/v1/admin/data/quality/scores` — `system.admin` only. The
/// *latest* score per (entity, dimension) — one row per dimension the sweep
/// has ever computed for that entity, not every historical period. A
/// dedicated trend endpoint (`GET .../scores/history`, below) serves the
/// full period series for one entity+dimension.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/quality/scores",
    tag = "admin",
    params(ListScoresQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<QualityScoreView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_scores(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<ListScoresQuery>,
) -> Result<Json<PaginatedResponse<QualityScoreView>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    // DISTINCT ON picks the newest row per (entity, dimension); the outer
    // query re-sorts and pages that already-deduplicated set — DISTINCT ON's
    // own ORDER BY must lead with its distinct columns, so it can't also
    // deliver the outward-facing "entity, then dimension" listing order.
    let items: Vec<QualityScoreView> = sqlx::query_as(
        "SELECT id, entity_logicalname, period, dimension, pass_count, fail_count, \
                sample_size, score, computed_at \
         FROM ( \
             SELECT DISTINCT ON (entity_logicalname, dimension) \
                 id, entity_logicalname, period, dimension, pass_count, fail_count, \
                 sample_size, score, computed_at \
             FROM quality_score \
             WHERE ($1::text IS NULL OR entity_logicalname = $1) \
             ORDER BY entity_logicalname, dimension, computed_at DESC \
         ) latest \
         ORDER BY entity_logicalname, dimension \
         OFFSET $2 LIMIT $3",
    )
    .bind(&q.entity)
    .bind(offset)
    .bind(page_size)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ( \
             SELECT DISTINCT entity_logicalname, dimension FROM quality_score \
             WHERE ($1::text IS NULL OR entity_logicalname = $1) \
         ) t",
    )
    .bind(&q.entity)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Deserialize, IntoParams)]
struct ScoreHistoryQuery {
    entity: String,
    /// Must be one of `DIMENSIONS` — validated below rather than by the
    /// column CHECK constraint alone, so a bad value gets a 422 instead of a
    /// masked-internal 500 from a constraint violation.
    dimension: String,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

/// `GET /api/v1/admin/data/quality/scores/history` — `system.admin` only.
/// The full period series for one entity+dimension, newest first — what a
/// trend chart reads.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/quality/scores/history",
    tag = "admin",
    params(ScoreHistoryQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<QualityScoreView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn score_history(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<ScoreHistoryQuery>,
) -> Result<Json<PaginatedResponse<QualityScoreView>>, AppError> {
    if !DIMENSIONS.contains(&q.dimension.as_str()) {
        return Err(AppError::Validation(
            "dimension must be one of: completeness, uniqueness".into(),
        ));
    }
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    let items: Vec<QualityScoreView> = sqlx::query_as(
        "SELECT id, entity_logicalname, period, dimension, pass_count, fail_count, \
                sample_size, score, computed_at \
         FROM quality_score \
         WHERE entity_logicalname = $1 AND dimension = $2 \
         ORDER BY period DESC OFFSET $3 LIMIT $4",
    )
    .bind(&q.entity)
    .bind(&q.dimension)
    .bind(offset)
    .bind(page_size)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM quality_score \
         WHERE entity_logicalname = $1 AND dimension = $2",
    )
    .bind(&q.entity)
    .bind(&q.dimension)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

// ── Issues ───────────────────────────────────────────────────────────────

const ISSUE_COLUMNS: &str = "id, entity_logicalname, period, dimension, record_id, \
     field_logicalname, related_record_id, detail, status, detected_at, resolved_at";

#[derive(sqlx::FromRow, Serialize, ToSchema)]
struct QualityIssueView {
    id: Uuid,
    entity_logicalname: String,
    period: String,
    dimension: String,
    record_id: Uuid,
    field_logicalname: String,
    related_record_id: Option<Uuid>,
    detail: String,
    status: String,
    detected_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize, IntoParams)]
struct ListIssuesQuery {
    entity: Option<String>,
    dimension: Option<String>,
    /// `"open"` (default view for the steward queue) or `"resolved"`. Omit
    /// for every status.
    status: Option<String>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

/// `GET /api/v1/admin/data/quality/issues` — `system.admin` only. Defaults
/// to no status filter left to the caller; a UI should request
/// `status=open` for the steward queue view.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/quality/issues",
    tag = "admin",
    params(ListIssuesQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<QualityIssueView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_issues(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<ListIssuesQuery>,
) -> Result<Json<PaginatedResponse<QualityIssueView>>, AppError> {
    if let Some(s) = &q.status
        && !["open", "resolved"].contains(&s.as_str())
    {
        return Err(AppError::Validation(
            "status must be one of: open, resolved".into(),
        ));
    }
    if let Some(d) = &q.dimension
        && !DIMENSIONS.contains(&d.as_str())
    {
        return Err(AppError::Validation(
            "dimension must be one of: completeness, uniqueness".into(),
        ));
    }
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    let items: Vec<QualityIssueView> = sqlx::query_as(&format!(
        "SELECT {ISSUE_COLUMNS} FROM quality_issue \
          WHERE ($1::text IS NULL OR entity_logicalname = $1) \
            AND ($2::text IS NULL OR dimension = $2) \
            AND ($3::text IS NULL OR status = $3) \
          ORDER BY detected_at DESC OFFSET $4 LIMIT $5"
    ))
    .bind(&q.entity)
    .bind(&q.dimension)
    .bind(&q.status)
    .bind(offset)
    .bind(page_size)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM quality_issue \
          WHERE ($1::text IS NULL OR entity_logicalname = $1) \
            AND ($2::text IS NULL OR dimension = $2) \
            AND ($3::text IS NULL OR status = $3)",
    )
    .bind(&q.entity)
    .bind(&q.dimension)
    .bind(&q.status)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// `POST /api/v1/admin/data/quality/issues/{id}/resolve` — `system.admin`
/// only. Marks one issue resolved once a steward has fixed (or accepted) the
/// underlying record — the sweep never reopens a resolved issue on its own
/// (see migration `0387`'s comment: the upsert's conflict target covers
/// every status, not just `open`), so this is the only way a resolved issue
/// re-enters the `open` state is a fresh sweep tick re-detecting the same
/// (entity, period, dimension, record, field) combination in a *later*
/// period, a new row rather than a mutation of this one.
#[utoipa::path(
    post,
    path = "/api/v1/admin/data/quality/issues/{id}/resolve",
    tag = "admin",
    params(("id" = Uuid, Path)),
    responses(
        (status = 204, description = "Issue marked resolved"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Issue not found", body = ErrorResponse),
        (status = 409, description = "Issue already resolved", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
)]
async fn resolve_issue(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT status, entity_logicalname FROM quality_issue WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let entity_logicalname = match row {
        None => return Err(AppError::NotFound),
        Some((status, _)) if status == "resolved" => {
            return Err(AppError::Conflict("this issue is already resolved"));
        }
        Some((_, entity_logicalname)) => entity_logicalname,
    };

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let result = sqlx::query(
        "UPDATE quality_issue SET status = 'resolved', resolved_at = NOW() \
         WHERE id = $1 AND status = 'open'",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if result.rows_affected() == 0 {
        // Lost a race against a concurrent resolve between the read above
        // and this write — same outcome as having observed it resolved.
        return Err(AppError::Conflict("this issue is already resolved"));
    }
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some(entity_logicalname),
                record_id: Some(id),
                operation: AuditOperation::Update,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("quality_issue_resolved".to_owned()),
                event_comment: None,
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/data/quality/scores", get(list_scores))
        .route(
            "/api/v1/admin/data/quality/scores/history",
            get(score_history),
        )
        .route("/api/v1/admin/data/quality/issues", get(list_issues))
        .route(
            "/api/v1/admin/data/quality/issues/{id}/resolve",
            post(resolve_issue),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document. Separate per file because `#[utoipa::path]` generates a
/// `__path_*` type with the handler's own visibility, and these handlers
/// are module-private — the crate's `openapi()` merges every fragment back
/// into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_scores, score_history, list_issues, resolve_issue))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
