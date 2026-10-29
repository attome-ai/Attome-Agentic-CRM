//! M14 / L2 (Data Quality) — the admin surface, `/api/v1/admin/data/
//! quality*`: scores and their history, the issue queue, quality rules,
//! targets and bulk fixes. Scoring itself lives in `quality_score.rs` and
//! `crate::quality`; this file reads what scoring wrote and authors what it
//! reads.
//!
//! Since L2-T2 the scores carry six dimensions (`crate::quality::dimensions`)
//! and the web app has the quality screen (L2-T8); `docs/data-quality.md`
//! describes the whole feature.
//!
//! L2-T4: issues carry an owner (the domain steward or the record owner,
//! `crate::quality::routing`) and a due date; the owner moves an issue
//! through its statuses (`PATCH .../issues/{id}`, a reason to accept);
//! `metadata.read` holders list the issues of records they may read; and
//! rules and targets (weights, threshold, timeliness, record scoring, issue
//! due days) are authored here, each change a Configuration security event.

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, audit_service,
};
use attome_core::EngineState;
use attome_records::entity_crud;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege, SelfService, area};
use attome_server::capability::{Available, BatchJobs};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, patch, post, put},
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
#[into_params(parameter_in = Query)]
struct ListScoresQuery {
    /// Filter to one entity's scores. Omit for every entity.
    entity: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// Data quality scores
///
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
    _ctx: Authorized<Privilege<area::DataModel>>,
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
#[into_params(parameter_in = Query)]
struct ScoreHistoryQuery {
    /// Only this entity (its logical name).
    entity: String,
    /// Must be one of `DIMENSIONS` — validated below rather than by the
    /// column CHECK constraint alone, so a bad value gets a 422 instead of a
    /// masked-internal 500 from a constraint violation.
    dimension: String,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// Data quality score history
///
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
    _ctx: Authorized<Privilege<area::DataModel>>,
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
     field_logicalname, related_record_id, detail, status, detected_at, resolved_at, \
     owner_id, due_at, accepted_reason";

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
    /// L2-T4: who works the issue.
    owner_id: Option<Uuid>,
    due_at: Option<DateTime<Utc>>,
    accepted_reason: Option<String>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListIssuesQuery {
    /// Only this entity (its logical name).
    entity: Option<String>,
    /// Only this quality dimension.
    dimension: Option<String>,
    /// `open`, `in_progress`, `fixed`, `accepted` or `resolved`. Omit for
    /// every status.
    status: Option<String>,
    /// L2-T4: only the issues this person owns.
    owner_id: Option<Uuid>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// Data quality issues
///
/// `GET /api/v1/admin/data/quality/issues` — `metadata.read` (L2-T4): an
/// administrator sees every issue; anyone else the issues of entities they
/// may read, without the records they may not read, and a total that counts
/// only those (L2-T10). A UI requests `status=open` for the steward queue
/// view.
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
    ctx: Authorized<Privilege<crate::data_profile_admin::MetadataRead>>,
    Query(q): Query<ListIssuesQuery>,
) -> Result<Json<PaginatedResponse<QualityIssueView>>, AppError> {
    if let Some(s) = &q.status
        && !crate::quality::routing::STATUSES.contains(&s.as_str())
    {
        return Err(AppError::Validation(format!(
            "status must be one of: {}",
            crate::quality::routing::STATUSES.join(", ")
        )));
    }
    // L2-T4: the entities the caller may read (every one for an admin).
    let readable: Option<Vec<String>> = (!ctx.is_admin).then(|| {
        state
            .entities
            .load()
            .iter()
            .filter(|m| ctx.require(&m.logicalname, "read").is_ok())
            .map(|m| m.logicalname.clone())
            .collect()
    });
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

    // L2-T10: what the caller may see is part of the SQL, so a page and its
    // total agree and the total never counts an issue on a record they
    // cannot read. An entity they read in full is one name in $5; each
    // entity they read only in part adds its own record predicate.
    let mut full: Vec<String> = Vec::new();
    let mut partial: Vec<(String, attome_security::RlsPredicate)> = Vec::new();
    let mut parts = String::new();
    let mut next = if readable.is_some() { 6 } else { 5 };
    if let Some(entities) = &readable {
        let levels = attome_security::resolve_all_entity_access_levels(
            &state.base.db,
            ctx.user_id,
            attome_security::RecordAction::Read,
        )
        .await?;
        let registry = state.entities.load();
        for name in entities {
            let Some(meta) = registry.get(name) else {
                continue;
            };
            let level = levels
                .get(name)
                .map_or(attome_server::security::AccessLevel::None, |(_, l)| *l);
            match attome_security::rls_predicate(
                &ctx,
                meta.entity_id,
                "",
                level,
                attome_security::RecordAction::Read.share_capability(),
                next + 1,
            ) {
                None => full.push(name.clone()),
                Some(pred) => {
                    parts.push_str(&format!(
                        " OR (entity_logicalname = ${next} AND record_id IN \
                           (SELECT id FROM {} WHERE true {}))",
                        attome_core::quote_ident(name),
                        pred.sql
                    ));
                    next += 1 + attome_security::RLS_BIND_COUNT;
                    partial.push((name.clone(), pred));
                }
            }
        }
    }
    let visible = if readable.is_some() {
        format!("AND (entity_logicalname = ANY($5){parts})")
    } else {
        String::new()
    };
    let filters = format!(
        "WHERE ($1::text IS NULL OR entity_logicalname = $1) \
           AND ($2::text IS NULL OR dimension = $2) \
           AND ($3::text IS NULL OR status = $3) \
           AND ($4::uuid IS NULL OR owner_id = $4) {visible}"
    );
    let list_sql = format!(
        "SELECT {ISSUE_COLUMNS} FROM quality_issue {filters} \
          ORDER BY detected_at DESC OFFSET ${next} LIMIT ${}",
        next + 1
    );
    let mut list = sqlx::query_as::<_, QualityIssueView>(&list_sql)
        .bind(&q.entity)
        .bind(&q.dimension)
        .bind(&q.status)
        .bind(q.owner_id);
    if readable.is_some() {
        list = list.bind(&full);
        for (name, pred) in &partial {
            list = attome_security::bind_rls_predicate_as(list.bind(name), &pred.binds);
        }
    }
    let items: Vec<QualityIssueView> = list
        .bind(offset)
        .bind(page_size)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    // L2-T4: an issue about a record the caller may not read is not shown.
    let items = if ctx.is_admin {
        items
    } else {
        let mut kept = Vec::with_capacity(items.len());
        for item in items {
            let entity_id = state
                .entities
                .load()
                .get(&item.entity_logicalname)
                .map(|m| m.entity_id);
            let Some(entity_id) = entity_id else {
                continue;
            };
            match entity_crud::require_record_access(
                &state,
                &ctx,
                entity_id,
                &item.entity_logicalname,
                item.record_id,
                attome_security::RecordAction::Read,
            )
            .await
            {
                Ok(()) => kept.push(item),
                Err(AppError::Forbidden | AppError::NotFound) => {}
                Err(e) => return Err(e),
            }
        }
        kept
    };

    let count_sql = format!("SELECT COUNT(*) FROM quality_issue {filters}");
    let mut count = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(&q.entity)
        .bind(&q.dimension)
        .bind(&q.status)
        .bind(q.owner_id);
    if readable.is_some() {
        count = count.bind(&full);
        for (name, pred) in &partial {
            count = attome_security::bind_rls_predicate(count.bind(name), &pred.binds);
        }
    }
    let total = count
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// Resolve a quality issue
///
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
    params(("id" = Uuid, Path, description = "The issue")),
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
    ctx: Authorized<Privilege<area::DataModel>>,
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

// ── L2-T4: issue workflow ────────────────────────────────────────────────

/// A status change of one issue.
#[derive(Deserialize, ToSchema)]
struct UpdateIssueBody {
    /// `open`, `in_progress`, `fixed`, `accepted` or `resolved`.
    status: String,
    /// Why the issue is accepted as it is; required for `accepted`.
    accepted_reason: Option<String>,
}

/// The caller may work `owner`'s issue on `entity`: an administrator, or the
/// issue's owner while they may still read the entity.
fn require_issue_editor(
    ctx: &attome_server::security::SecurityContext,
    owner: Option<Uuid>,
    entity: &str,
) -> Result<(), AppError> {
    if ctx.is_admin {
        return Ok(());
    }
    if owner == Some(ctx.user_id) && ctx.require(entity, "read").is_ok() {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// Update a quality issue
///
/// `PATCH /api/v1/admin/data/quality/issues/{id}`: the issue's owner (or an
/// administrator) moves it through its statuses; accepting needs a reason.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/data/quality/issues/{id}",
    operation_id = "quality_issue_update",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The issue")),
    request_body = UpdateIssueBody,
    responses(
        (status = 204, description = "The issue's status changed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Neither the issue's owner nor an administrator", body = ErrorResponse),
        (status = 404, description = "Issue not found", body = ErrorResponse),
        (status = 422, description = "Unknown status, or accepted without a reason", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
)]
async fn update_issue(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateIssueBody>,
) -> Result<StatusCode, AppError> {
    crate::quality::routing::check_change(&body.status, body.accepted_reason.as_deref())
        .map_err(AppError::Validation)?;
    let row: Option<(String, Option<Uuid>)> =
        sqlx::query_as("SELECT entity_logicalname, owner_id FROM quality_issue WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let (entity_logicalname, owner) = row.ok_or(AppError::NotFound)?;
    require_issue_editor(&ctx, owner, &entity_logicalname)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let changed = sqlx::query(
        "UPDATE quality_issue SET status = $2, \
                accepted_reason = CASE WHEN $2 = 'accepted' THEN $3 ELSE NULL END, \
                resolved_at = CASE WHEN $2 IN ('fixed', 'accepted', 'resolved') \
                                   THEN COALESCE(resolved_at, now()) END \
          WHERE id = $1",
    )
    .bind(id)
    .bind(&body.status)
    .bind(body.accepted_reason.as_deref().map(str::trim))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if changed == 0 {
        return Err(AppError::NotFound);
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
                event_name: Some("quality_issue_status".to_owned()),
                event_comment: Some(body.status.clone()),
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── L2-T4: rules and targets ─────────────────────────────────────────────

const RULE_COLUMNS: &str = "id, entity, attribute, dimension, expression, severity, weight::float8 AS weight, enabled, row_version";

#[derive(sqlx::FromRow, Serialize, ToSchema)]
struct QualityRuleView {
    id: Uuid,
    entity: String,
    attribute: Option<String>,
    dimension: String,
    expression: String,
    severity: String,
    weight: f64,
    enabled: bool,
    row_version: i64,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListRulesQuery {
    /// Only this entity (its logical name).
    entity: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// The dimensions a rule measures.
const RULE_DIMENSIONS: &[&str] = &["validity", "consistency"];
const SEVERITIES: &[&str] = &["info", "warning", "error"];

#[derive(Deserialize, ToSchema)]
struct CreateRuleBody {
    entity: String,
    attribute: Option<String>,
    /// `validity` or `consistency`.
    dimension: String,
    /// A condition each record must hold, e.g. `amount >= 0`.
    expression: String,
    severity: Option<String>,
    weight: Option<f64>,
    enabled: Option<bool>,
}

#[derive(Deserialize, ToSchema)]
struct UpdateRuleBody {
    expression: Option<String>,
    severity: Option<String>,
    weight: Option<f64>,
    enabled: Option<bool>,
    /// The version the change was made against.
    row_version: i64,
}

fn check_rule_parts(
    expression: Option<&str>,
    severity: Option<&str>,
    weight: Option<f64>,
) -> Result<(), AppError> {
    if let Some(e) = expression {
        attome_workflow::condition::check_expression(e)
            .map_err(|m| AppError::Validation(format!("expression: {m}")))?;
    }
    if let Some(s) = severity
        && !SEVERITIES.contains(&s)
    {
        return Err(AppError::Validation(
            "severity must be one of: info, warning, error".into(),
        ));
    }
    if let Some(w) = weight
        && !(w.is_finite() && w >= 0.0)
    {
        return Err(AppError::Validation(
            "weight is a number of 0 or more".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn config_event(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    actor: Uuid,
    operation: AuditOperation,
    table: &'static str,
    record: Option<Uuid>,
    name: &'static str,
    comment: String,
) -> Result<(), AppError> {
    write_security_event(
        tx,
        &audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            operation,
            actor,
            table,
            record,
        )
        .named(name)
        .comment(comment),
    )
    .await
    .map(|_| ())
}

/// List quality rules
///
/// `GET /api/v1/admin/data/quality/rules` — `system.admin` only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/quality/rules",
    operation_id = "quality_rules_list",
    tag = "admin",
    params(ListRulesQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<QualityRuleView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_rules(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Query(q): Query<ListRulesQuery>,
) -> Result<Json<PaginatedResponse<QualityRuleView>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);
    let items: Vec<QualityRuleView> = sqlx::query_as(&format!(
        "SELECT {RULE_COLUMNS} FROM quality_rule WHERE ($1::text IS NULL OR entity = $1) \
          ORDER BY entity, id OFFSET $2 LIMIT $3"
    ))
    .bind(&q.entity)
    .bind(offset)
    .bind(page_size)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM quality_rule WHERE ($1::text IS NULL OR entity = $1)",
    )
    .bind(&q.entity)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// Create a quality rule
///
/// `POST /api/v1/admin/data/quality/rules` — `system.admin` only. The
/// expression is checked as the shared condition evaluator reads it.
#[utoipa::path(
    post,
    path = "/api/v1/admin/data/quality/rules",
    operation_id = "quality_rule_create",
    tag = "admin",
    request_body = CreateRuleBody,
    responses(
        (status = 201, description = "The rule", body = QualityRuleView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Unknown entity, attribute or dimension, or a bad expression", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Create)])))),
)]
async fn create_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Json(body): Json<CreateRuleBody>,
) -> Result<(StatusCode, Json<QualityRuleView>), AppError> {
    if !RULE_DIMENSIONS.contains(&body.dimension.as_str()) {
        return Err(AppError::Validation(
            "dimension must be one of: validity, consistency".into(),
        ));
    }
    check_rule_parts(
        Some(&body.expression),
        body.severity.as_deref(),
        body.weight,
    )?;
    let (_, entity_name, attrs, _) = entity_crud::resolve_entity(&state, &body.entity).await?;
    if let Some(a) = &body.attribute
        && !attrs.iter().any(|x| &x.logicalname == a)
    {
        return Err(AppError::Validation(format!(
            "attribute '{a}' does not exist on this entity"
        )));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let rule: QualityRuleView = sqlx::query_as(&format!(
        "INSERT INTO quality_rule (entity, attribute, dimension, expression, severity, weight, enabled) \
         VALUES ($1, $2, $3, $4, COALESCE($5, 'warning'), COALESCE($6, 1)::numeric, COALESCE($7, true)) \
         RETURNING {RULE_COLUMNS}"
    ))
    .bind(&entity_name)
    .bind(&body.attribute)
    .bind(&body.dimension)
    .bind(body.expression.trim())
    .bind(&body.severity)
    .bind(body.weight)
    .bind(body.enabled)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    config_event(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::Create,
        "quality_rule",
        Some(rule.id),
        "quality.rule_created",
        format!("{entity_name} {}: {}", rule.dimension, rule.expression),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(rule)))
}

/// Update a quality rule
///
/// `PATCH /api/v1/admin/data/quality/rules/{id}` — `system.admin` only;
/// `row_version` must match.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/data/quality/rules/{id}",
    operation_id = "quality_rule_update",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The rule")),
    request_body = UpdateRuleBody,
    responses(
        (status = 200, description = "The rule", body = QualityRuleView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
        (status = 409, description = "The rule changed since that version", body = ErrorResponse),
        (status = 422, description = "A bad expression, severity or weight", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn update_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateRuleBody>,
) -> Result<Json<QualityRuleView>, AppError> {
    check_rule_parts(
        body.expression.as_deref(),
        body.severity.as_deref(),
        body.weight,
    )?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let rule: Option<QualityRuleView> = sqlx::query_as(&format!(
        "UPDATE quality_rule SET expression = COALESCE($2, expression), \
                severity = COALESCE($3, severity), weight = COALESCE($4::numeric, weight), \
                enabled = COALESCE($5, enabled), row_version = row_version + 1 \
          WHERE id = $1 AND row_version = $6 RETURNING {RULE_COLUMNS}"
    ))
    .bind(id)
    .bind(body.expression.as_deref().map(str::trim))
    .bind(&body.severity)
    .bind(body.weight)
    .bind(body.enabled)
    .bind(body.row_version)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(rule) = rule else {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM quality_rule WHERE id = $1)")
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::internal)?;
        return Err(if exists {
            AppError::VersionConflict
        } else {
            AppError::NotFound
        });
    };
    config_event(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::Update,
        "quality_rule",
        Some(id),
        "quality.rule_updated",
        format!("{} {}: {}", rule.entity, rule.dimension, rule.expression),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(rule))
}

/// Delete a quality rule
///
/// `DELETE /api/v1/admin/data/quality/rules/{id}` — `system.admin` only.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/data/quality/rules/{id}",
    operation_id = "quality_rule_delete",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The rule")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::HardDelete)])))),
)]
async fn delete_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let gone: Option<(String, String)> =
        sqlx::query_as("DELETE FROM quality_rule WHERE id = $1 RETURNING entity, expression")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let (entity, expression) = gone.ok_or(AppError::NotFound)?;
    config_event(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::HardDelete,
        "quality_rule",
        Some(id),
        "quality.rule_deleted",
        format!("{entity}: {expression}"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(sqlx::FromRow, Serialize, ToSchema)]
struct QualityTargetView {
    entity: String,
    /// Dimension name to weight in the overall score.
    #[schema(value_type = Object)]
    dimension_weights: serde_json::Value,
    threshold: f64,
    timeliness_days: Option<i32>,
    record_scoring: bool,
    issue_sla_days: Option<i32>,
}

const TARGET_COLUMNS: &str = "entity, dimension_weights, threshold::float8 AS threshold, \
     timeliness_days, record_scoring, issue_sla_days";

#[derive(Deserialize, ToSchema)]
struct PutTargetBody {
    /// Dimension name to weight (0 or more); unset dimensions weigh 1.
    #[schema(value_type = Option<Object>)]
    dimension_weights: Option<serde_json::Value>,
    /// The overall score the entity should keep, 0 to 100 (default 70).
    threshold: Option<f64>,
    /// Records changed longer ago than this many days are not timely.
    timeliness_days: Option<i32>,
    /// Keep a score per record.
    record_scoring: Option<bool>,
    /// Days an issue is due in (default 7).
    issue_sla_days: Option<i32>,
}

fn check_target(body: &PutTargetBody) -> Result<(), AppError> {
    if let Some(w) = &body.dimension_weights {
        let map = w
            .as_object()
            .ok_or_else(|| AppError::Validation("dimension_weights is an object".into()))?;
        for (dimension, weight) in map {
            if crate::quality::dimensions::Dimension::parse(dimension).is_none() {
                return Err(AppError::Validation(format!(
                    "dimension_weights: '{dimension}' is not a dimension"
                )));
            }
            if !weight.as_f64().is_some_and(|x| x.is_finite() && x >= 0.0) {
                return Err(AppError::Validation(format!(
                    "dimension_weights.{dimension} is a number of 0 or more"
                )));
            }
        }
    }
    if let Some(t) = body.threshold
        && !(0.0..=100.0).contains(&t)
    {
        return Err(AppError::Validation("threshold is 0 to 100".into()));
    }
    for (name, days) in [
        ("timeliness_days", body.timeliness_days),
        ("issue_sla_days", body.issue_sla_days),
    ] {
        if days.is_some_and(|d| d <= 0) {
            return Err(AppError::Validation(format!("{name} is at least 1")));
        }
    }
    Ok(())
}

/// Quality targets
///
/// `GET /api/v1/admin/data/quality/targets` — `system.admin` only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/quality/targets",
    operation_id = "quality_targets_list",
    tag = "admin",
    params(ListRulesQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<QualityTargetView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_targets(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Query(q): Query<ListRulesQuery>,
) -> Result<Json<PaginatedResponse<QualityTargetView>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);
    let items: Vec<QualityTargetView> = sqlx::query_as(&format!(
        "SELECT {TARGET_COLUMNS} FROM quality_target WHERE ($1::text IS NULL OR entity = $1) \
          ORDER BY entity OFFSET $2 LIMIT $3"
    ))
    .bind(&q.entity)
    .bind(offset)
    .bind(page_size)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM quality_target WHERE ($1::text IS NULL OR entity = $1)",
    )
    .bind(&q.entity)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// Set a quality target
///
/// `PUT /api/v1/admin/data/quality/targets/{entity}` — `system.admin` only.
/// Sets the entity's weights, threshold, timeliness, record scoring and
/// issue due days; an absent field keeps its value (or default).
#[utoipa::path(
    put,
    path = "/api/v1/admin/data/quality/targets/{entity}",
    operation_id = "quality_target_put",
    tag = "admin",
    params(("entity" = String, Path, description = "The entity's logical name")),
    request_body = PutTargetBody,
    responses(
        (status = 200, description = "The target", body = QualityTargetView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Unknown entity or dimension, or a value out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn put_target(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(entity): Path<String>,
    Json(body): Json<PutTargetBody>,
) -> Result<Json<QualityTargetView>, AppError> {
    check_target(&body)?;
    let (_, entity_name, _, _) = entity_crud::resolve_entity(&state, &entity).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let target: QualityTargetView = sqlx::query_as(&format!(
        "INSERT INTO quality_target (entity, dimension_weights, threshold, timeliness_days, \
                                     record_scoring, issue_sla_days) \
         VALUES ($1, COALESCE($2, '{{}}'::jsonb), COALESCE($3::numeric, 70), $4, \
                 COALESCE($5, false), $6) \
         ON CONFLICT (entity) DO UPDATE SET \
             dimension_weights = COALESCE($2, quality_target.dimension_weights), \
             threshold = COALESCE($3::numeric, quality_target.threshold), \
             timeliness_days = COALESCE($4, quality_target.timeliness_days), \
             record_scoring = COALESCE($5, quality_target.record_scoring), \
             issue_sla_days = COALESCE($6, quality_target.issue_sla_days) \
         RETURNING {TARGET_COLUMNS}"
    ))
    .bind(&entity_name)
    .bind(&body.dimension_weights)
    .bind(body.threshold)
    .bind(body.timeliness_days)
    .bind(body.record_scoring)
    .bind(body.issue_sla_days)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    config_event(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::Update,
        "quality_target",
        None,
        "quality.target_set",
        format!("{entity_name}: threshold {:.0}", target.threshold),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(target))
}

/// Remove a quality target
///
/// `DELETE /api/v1/admin/data/quality/targets/{entity}` — `system.admin`
/// only; the entity reverts to the defaults.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/data/quality/targets/{entity}",
    operation_id = "quality_target_delete",
    tag = "admin",
    params(("entity" = String, Path, description = "The entity's logical name")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No target for that entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::HardDelete)])))),
)]
async fn delete_target(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(entity): Path<String>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let gone = sqlx::query("DELETE FROM quality_target WHERE entity = $1")
        .bind(&entity)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    if gone == 0 {
        return Err(AppError::NotFound);
    }
    config_event(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::HardDelete,
        "quality_target",
        None,
        "quality.target_deleted",
        entity,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── L2-T5: bulk fixes with preview and undo ──────────────────────────────

/// A data-quality fix over many records.
#[derive(Deserialize, ToSchema)]
struct QualityFixBody {
    entity: String,
    /// The text attribute to fix.
    attribute: String,
    /// `trim_spaces`, `title_case`, `digits_to_western`, `phone_e164`, or
    /// `{"fix": "phone_e164", "country": "AE"}`.
    #[schema(value_type = Object)]
    fix: serde_json::Value,
    /// The records, at most 500; give `ids` or `filters`.
    #[serde(default)]
    ids: Vec<Uuid>,
    /// The records by a list's filters; at most 500 may match.
    #[serde(default)]
    filters: Vec<attome_core::filter::Filter>,
}

impl QualityFixBody {
    fn as_bulk_edit(&self) -> attome_records::bulk_edit::BulkEditRequest {
        attome_records::bulk_edit::BulkEditRequest {
            ids: self.ids.clone(),
            filters: self.filters.clone(),
            operations: vec![attome_records::bulk_edit::EditOperation {
                attribute: self.attribute.clone(),
                op: "fix".into(),
                value: Some(self.fix.clone()),
            }],
            quiet: false,
        }
    }
}

/// `POST /api/v1/admin/data/quality/fixes/preview`: what a fix would change.
#[utoipa::path(
    post,
    path = "/api/v1/admin/data/quality/fixes/preview",
    operation_id = "quality_fix_preview",
    tag = "admin",
    request_body = QualityFixBody,
    responses(
        (status = 200, description = "Counts and the first 20 records before and after", body = attome_records::bulk_edit::BulkEditPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator", body = ErrorResponse),
        (status = 422, description = "Unknown fix, not a text attribute, or too many records", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "L2-T5: computes what a data-quality fix would change and writes nothing"
    )))),
)]
/// Previews a data-quality fix over many records.
///
/// Counts the picked records the caller can read, those the fix would
/// change and those already clean, and shows the first 20 before and
/// after. Nothing is written.
async fn preview_fix(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Json(body): Json<QualityFixBody>,
) -> Result<Json<attome_records::bulk_edit::BulkEditPreview>, AppError> {
    let plan =
        attome_records::bulk_edit::plan_bulk_edit(&state, &ctx, &body.entity, &body.as_bulk_edit())
            .await?;
    Ok(Json(attome_records::bulk_edit::BulkEditPreview {
        matched: plan.matched,
        to_change: plan.items.len(),
        unchanged: plan.unchanged,
        samples: plan.samples,
    }))
}

/// `POST /api/v1/admin/data/quality/fixes/apply`: runs a fix as one bulk
/// update.
#[utoipa::path(
    post,
    path = "/api/v1/admin/data/quality/fixes/apply",
    operation_id = "quality_fix_apply",
    tag = "admin",
    request_body = QualityFixBody,
    responses(
        (status = 200, description = "No record needed the fix", body = attome_records::bulk_edit::BulkEditSubmitted),
        (status = 202, description = "The fix runs as one bulk update; `undo` puts it back", body = attome_records::bulk_edit::BulkEditSubmitted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator", body = ErrorResponse),
        (status = 422, description = "Unknown fix, not a text attribute, or too many records", body = ErrorResponse),
        (status = 503, description = "No batch worker can run the fix", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::BulkAccepted)])))),
)]
/// Applies a data-quality fix to many records as one bulk update.
///
/// Each record goes through the normal update path (validation, rules,
/// access, audit) with its row version, so one changed since the preview is
/// reported, not overwritten. The answer's `undo` list, sent to
/// `POST /api/v1/{entity}/bulk-edit/undo`, puts the batch back. The fixed
/// records leave the A3 clean-up queues; a record still failing a rule
/// returns at that rule's next scan.
async fn apply_fix(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    _jobs: Available<BatchJobs>,
    Json(body): Json<QualityFixBody>,
) -> Result<
    (
        StatusCode,
        Json<attome_records::bulk_edit::BulkEditSubmitted>,
    ),
    AppError,
> {
    let (status, submitted) = attome_records::bulk_edit::submit_bulk_edit(
        &state,
        &ctx,
        &body.entity,
        &body.as_bulk_edit(),
    )
    .await?;
    if submitted.id.is_some() && !submitted.record_ids.is_empty() {
        sqlx::query("DELETE FROM validation_cleanup WHERE entity = $1 AND record_id = ANY($2)")
            .bind(&body.entity)
            .bind(&submitted.record_ids)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    }
    Ok((status, Json(submitted)))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/data/quality/fixes/preview",
            post(preview_fix),
        )
        .route("/api/v1/admin/data/quality/fixes/apply", post(apply_fix))
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
        .route(
            "/api/v1/admin/data/quality/issues/{id}",
            patch(update_issue),
        )
        .route(
            "/api/v1/admin/data/quality/rules",
            get(list_rules).post(create_rule),
        )
        .route(
            "/api/v1/admin/data/quality/rules/{id}",
            patch(update_rule).delete(delete_rule),
        )
        .route("/api/v1/admin/data/quality/targets", get(list_targets))
        .route(
            "/api/v1/admin/data/quality/targets/{entity}",
            put(put_target).delete(delete_target),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document. Separate per file because `#[utoipa::path]` generates a
/// `__path_*` type with the handler's own visibility, and these handlers
/// are module-private — the crate's `openapi()` merges every fragment back
/// into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_scores,
    score_history,
    list_issues,
    resolve_issue,
    update_issue,
    list_rules,
    create_rule,
    update_rule,
    delete_rule,
    list_targets,
    put_target,
    delete_target,
    preview_fix,
    apply_fix
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
