//! D-432 / M13 (Master Data Management, scoped to dedup + survivorship
//! only) — the admin surface: `match_rule` and
//! `survivorship_rule` CRUD, plus the `duplicate_candidate`
//! steward queue (`/api/v1/admin/data/duplicates*`). `system.admin` only,
//! mounted with `strict_authz` — same posture as every other M12/M13
//! `/admin/data/*` surface (`data_profile_admin.rs`, `data_mapping_admin.rs`).
//!
//! The matching job itself (`EngineJob::DataMatchSweep`) lives in
//! `duplicates_match.rs`; the merge execution this module's `merge_candidate`
//! and `approval_admin::execute_approved`'s `ACTION_MDM_AUTO_MERGE` arm both
//! call is `entity_crud::do_merge_core` — this file never duplicates that
//! logic, only decides *when* to call it.

use attome_core::EngineState;
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
use serde_json::Value;
use std::collections::HashSet;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::duplicates_match::{Comparator, MatchField};
use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, audit_service,
};
use attome_records::entity_crud;

/// The gated action `duplicates_match::submit_auto_merge_request` submits
/// and `approval_admin::execute_approved` dispatches — see
/// `duplicates_match::submit_auto_merge_request`'s doc comment for why this
/// is submitted unconditionally rather than only when `approval.
/// required_actions` opts it in.
pub const ACTION_MDM_AUTO_MERGE: &str = "mdm.auto_merge";

// ── Match rules ─────────────────────────────────────────────────────────────

fn validate_match_fields(
    known_fields: &HashSet<&str>,
    fields: &[MatchField],
) -> Result<(), AppError> {
    attome_core::match_rule::validate_fields(known_fields, fields)
}

const MATCH_RULE_COLUMNS: &str = "id, entity_logicalname, name, is_active, fields, \
     threshold::float8, auto_merge, row_version, created_at, updated_at, created_by, \
     scan_schedule, last_scan_at, on_save";

/// A15-T4: what saving a likely duplicate does.
const ON_SAVE: [&str; 4] = ["off", "warn", "allow_with_reason", "block"];

fn on_save_of(raw: Option<&str>) -> Result<Option<String>, AppError> {
    match raw.map(str::trim) {
        None => Ok(None),
        Some(s) if ON_SAVE.contains(&s) => Ok(Some(s.to_owned())),
        Some(s) => Err(AppError::Validation(format!(
            "on_save: '{s}' is not off, warn, allow_with_reason or block"
        ))),
    }
}

/// A15-T6: the schedules a full scan may run on.
const SCAN_SCHEDULES: [&str; 3] = ["hourly", "daily", "weekly"];

/// A15-T6: `""` clears the schedule; anything else must be one of
/// [`SCAN_SCHEDULES`].
fn scan_schedule_of(raw: Option<&str>) -> Result<Option<Option<String>>, AppError> {
    match raw.map(|s| s.trim().trim_start_matches('@').to_ascii_lowercase()) {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(Some(None)),
        Some(s) if SCAN_SCHEDULES.contains(&s.as_str()) => Ok(Some(Some(s))),
        Some(s) => Err(AppError::Validation(format!(
            "scan_schedule: '{s}' is not hourly, daily or weekly"
        ))),
    }
}

#[derive(sqlx::FromRow)]
struct MatchRuleRow {
    id: Uuid,
    entity_logicalname: String,
    name: String,
    is_active: bool,
    fields: Value,
    threshold: f64,
    auto_merge: bool,
    row_version: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    created_by: Uuid,
    scan_schedule: Option<String>,
    last_scan_at: Option<DateTime<Utc>>,
    on_save: String,
}

#[derive(Serialize, ToSchema)]
struct MatchRuleView {
    id: Uuid,
    entity_logicalname: String,
    name: String,
    is_active: bool,
    fields: Vec<MatchField>,
    threshold: f64,
    auto_merge: bool,
    row_version: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    created_by: Uuid,
    /// A15-T6: `hourly`, `daily` or `weekly`; `null`: scans run only on demand.
    scan_schedule: Option<String>,
    /// A15-T6: when the last full scan finished.
    last_scan_at: Option<DateTime<Utc>>,
    /// A15-T4: what saving a likely duplicate does: `off`, `warn`,
    /// `allow_with_reason` or `block`.
    on_save: String,
}

impl TryFrom<MatchRuleRow> for MatchRuleView {
    type Error = AppError;

    fn try_from(row: MatchRuleRow) -> Result<Self, AppError> {
        let fields: Vec<MatchField> = serde_json::from_value(row.fields)
            .map_err(|e| AppError::internal(format!("corrupt match_rule.fields: {e}")))?;
        Ok(Self {
            id: row.id,
            entity_logicalname: row.entity_logicalname,
            name: row.name,
            is_active: row.is_active,
            fields,
            threshold: row.threshold,
            auto_merge: row.auto_merge,
            row_version: row.row_version,
            created_at: row.created_at,
            updated_at: row.updated_at,
            created_by: row.created_by,
            scan_schedule: row.scan_schedule,
            last_scan_at: row.last_scan_at,
            on_save: row.on_save,
        })
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListMatchRulesQuery {
    /// Only this entity (its logical name).
    entity: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// List duplicate match rules
///
/// `GET /api/v1/admin/data/match-rules` — `system.admin` only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/match-rules",
    tag = "admin",
    params(ListMatchRulesQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<MatchRuleView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_match_rules(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<ListMatchRulesQuery>,
) -> Result<Json<PaginatedResponse<MatchRuleView>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    let rows: Vec<MatchRuleRow> = sqlx::query_as(&format!(
        "SELECT {MATCH_RULE_COLUMNS} FROM match_rule \
          WHERE NOT is_deleted AND ($1::text IS NULL OR entity_logicalname = $1) \
          ORDER BY name ASC OFFSET $2 LIMIT $3"
    ))
    .bind(&q.entity)
    .bind(offset)
    .bind(page_size)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM match_rule \
          WHERE NOT is_deleted AND ($1::text IS NULL OR entity_logicalname = $1)",
    )
    .bind(&q.entity)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Deserialize, ToSchema)]
struct CreateMatchRuleBody {
    entity: String,
    name: String,
    #[serde(default = "default_true")]
    is_active: bool,
    fields: Vec<MatchField>,
    threshold: f64,
    #[serde(default)]
    auto_merge: bool,
    /// A15-T6: `hourly`, `daily` or `weekly` full scans; absent: on demand.
    #[serde(default)]
    scan_schedule: Option<String>,
    /// A15-T4: `off` (the default), `warn`, `allow_with_reason` or `block`.
    #[serde(default)]
    on_save: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Create a match rule
///
/// `POST /api/v1/admin/data/match-rules` — `system.admin` only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/data/match-rules",
    tag = "admin",
    request_body = CreateMatchRuleBody,
    responses(
        (status = 201, description = "Success", body = MatchRuleView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Create)])))),
)]
async fn create_match_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreateMatchRuleBody>,
) -> Result<(StatusCode, Json<MatchRuleView>), AppError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    if body.threshold <= 0.0 || body.threshold > 1.0 {
        return Err(AppError::Validation(
            "threshold must be greater than 0 and at most 1".into(),
        ));
    }
    let (_, entity_name, attrs, _) = entity_crud::resolve_entity(&state, &body.entity).await?;
    let known: HashSet<&str> = attrs.iter().map(|a| a.logicalname.as_str()).collect();
    validate_match_fields(&known, &body.fields)?;
    let fields_json = serde_json::to_value(&body.fields).map_err(AppError::internal)?;
    let scan_schedule = scan_schedule_of(body.scan_schedule.as_deref())?.flatten();
    let on_save = on_save_of(body.on_save.as_deref())?.unwrap_or_else(|| "off".to_owned());

    let rule_id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: MatchRuleRow = sqlx::query_as(&format!(
        "INSERT INTO match_rule \
             (id, entity_logicalname, name, is_active, fields, threshold, auto_merge, row_version, \
              created_by, scan_schedule, on_save) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, $9, $10) \
         RETURNING {MATCH_RULE_COLUMNS}"
    ))
    .bind(rule_id)
    .bind(&entity_name)
    .bind(name)
    .bind(body.is_active)
    .bind(&fields_json)
    .bind(body.threshold)
    .bind(body.auto_merge)
    .bind(ctx.user_id)
    .bind(&scan_schedule)
    .bind(&on_save)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Configuration,
                entity_name: Some(entity_name.clone()),
                record_id: Some(rule_id),
                operation: AuditOperation::Create,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("match_rule_created".to_owned()),
                event_comment: Some(format!("match rule {name:?} on {entity_name}")),
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await?;
    // A15-T6: the existing rows get their keys and are scored by a scan.
    if row.is_active {
        start_scan_best_effort(&state, rule_id).await;
    }
    Ok((StatusCode::CREATED, Json(row.try_into()?)))
}

/// A15-T6: starts a rule's full scan after a save; a failure to queue it is
/// logged and leaves the save in place (the scan route starts it again).
async fn start_scan_best_effort(state: &EngineState, rule_id: Uuid) {
    if let Err(e) = crate::duplicates_match::start_match_scan(&state.base.db, rule_id).await {
        tracing::warn!(error = %e, %rule_id, "match rule saved, but its scan could not be queued");
    }
}

#[derive(Deserialize, ToSchema)]
struct UpdateMatchRuleBody {
    name: Option<String>,
    is_active: Option<bool>,
    fields: Option<Vec<MatchField>>,
    threshold: Option<f64>,
    auto_merge: Option<bool>,
    /// A15-T6: `hourly`, `daily`, `weekly`, or `""` to scan on demand only.
    scan_schedule: Option<String>,
    /// A15-T4: `off`, `warn`, `allow_with_reason` or `block`.
    on_save: Option<String>,
    row_version: i64,
}

/// Replace a match rule
///
/// `PUT /api/v1/admin/data/match-rules/{id}` — `system.admin` only.
/// `entity` is immutable after creation (delete and recreate to retarget a
/// rule) — same posture `approval_policy_admin::update_policy` takes for
/// `action_type`.
#[utoipa::path(
    put,
    path = "/api/v1/admin/data/match-rules/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The match rule")),
    request_body = UpdateMatchRuleBody,
    responses(
        (status = 200, description = "Success", body = MatchRuleView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Match rule not found", body = ErrorResponse),
        (status = 409, description = "row_version is stale", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn update_match_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateMatchRuleBody>,
) -> Result<Json<MatchRuleView>, AppError> {
    if let Some(name) = &body.name
        && name.trim().is_empty()
    {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    if let Some(t) = body.threshold
        && (t <= 0.0 || t > 1.0)
    {
        return Err(AppError::Validation(
            "threshold must be greater than 0 and at most 1".into(),
        ));
    }

    let fields_json = match &body.fields {
        Some(fields) => {
            let entity_logicalname: Option<String> = sqlx::query_scalar(
                "SELECT entity_logicalname FROM match_rule WHERE id = $1 AND NOT is_deleted",
            )
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let entity_logicalname = entity_logicalname.ok_or(AppError::NotFound)?;
            let (_, _, attrs, _) = entity_crud::resolve_entity(&state, &entity_logicalname).await?;
            let known: HashSet<&str> = attrs.iter().map(|a| a.logicalname.as_str()).collect();
            validate_match_fields(&known, fields)?;
            Some(serde_json::to_value(fields).map_err(AppError::internal)?)
        }
        None => None,
    };

    let scan_schedule = scan_schedule_of(body.scan_schedule.as_deref())?;
    let on_save = on_save_of(body.on_save.as_deref())?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<MatchRuleRow> = sqlx::query_as(&format!(
        "UPDATE match_rule \
         SET name = COALESCE($3, name), \
             is_active = COALESCE($4, is_active), \
             fields = COALESCE($5, fields), \
             threshold = COALESCE($6, threshold), \
             auto_merge = COALESCE($7, auto_merge), \
             scan_schedule = CASE WHEN $8 THEN $9 ELSE scan_schedule END, \
             on_save = COALESCE($10, on_save), \
             row_version = row_version + 1, \
             updated_at = NOW() \
         WHERE id = $1 AND row_version = $2 AND NOT is_deleted \
         RETURNING {MATCH_RULE_COLUMNS}"
    ))
    .bind(id)
    .bind(body.row_version)
    .bind(body.name.as_deref().map(str::trim))
    .bind(body.is_active)
    .bind(&fields_json)
    .bind(body.threshold)
    .bind(body.auto_merge)
    .bind(scan_schedule.is_some())
    .bind(scan_schedule.clone().flatten())
    .bind(&on_save)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let row = match row {
        Some(row) => row,
        None => {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM match_rule WHERE id = $1 AND NOT is_deleted)",
            )
            .bind(id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            return Err(if exists {
                AppError::VersionConflict
            } else {
                AppError::NotFound
            });
        }
    };
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Configuration,
                entity_name: Some(row.entity_logicalname.clone()),
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
                event_name: Some("match_rule_updated".to_owned()),
                event_comment: None,
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await?;
    // A15-T6: new fields need keys for the rows already there.
    if body.fields.is_some() && row.is_active {
        start_scan_best_effort(&state, id).await;
    }
    Ok(Json(row.try_into()?))
}

/// A15-T6: whether a scan was queued (`false`: one is queued already).
#[derive(Debug, Serialize, ToSchema)]
struct MatchScanStarted {
    queued: bool,
}

/// Scan with a match rule
///
/// `POST /api/v1/admin/data/match-rules/{id}/scan` — `system.admin` only.
/// A15-T6: scans every live row of the rule's entity in pages of 500 in the
/// background (keys written, each row scored against its peers, candidates
/// recorded); a restart resumes from the last page.
#[utoipa::path(
    post,
    path = "/api/v1/admin/data/match-rules/{id}/scan",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The match rule")),
    responses(
        (status = 202, description = "The scan is queued", body = MatchScanStarted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such rule", body = ErrorResponse),
        (status = 422, description = "The rule is switched off", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn scan_match_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<MatchScanStarted>), AppError> {
    let rule: Option<(String, bool)> = sqlx::query_as(
        "SELECT entity_logicalname, is_active FROM match_rule WHERE id = $1 AND NOT is_deleted",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (entity_logicalname, is_active) = rule.ok_or(AppError::NotFound)?;
    if !is_active {
        return Err(AppError::Validation(
            "the rule is switched off; switch it on to scan".into(),
        ));
    }
    let queued = crate::duplicates_match::start_match_scan(&state.base.db, id).await?;
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Configuration,
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
                event_name: Some("match_scan_started".to_owned()),
                event_comment: None,
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::ACCEPTED, Json(MatchScanStarted { queued })))
}

/// Delete a match rule
///
/// `DELETE /api/v1/admin/data/match-rules/{id}` — `system.admin` only.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/data/match-rules/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The match rule")),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Match rule not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::SoftDelete)])))),
)]
async fn delete_match_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let entity_logicalname: Option<String> = sqlx::query_scalar(
        "SELECT entity_logicalname FROM match_rule WHERE id = $1 AND NOT is_deleted",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(entity_logicalname) = entity_logicalname else {
        return Err(AppError::NotFound);
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let result = sqlx::query(
        "UPDATE match_rule SET is_deleted = TRUE, row_version = row_version + 1, \
             updated_at = NOW() WHERE id = $1 AND NOT is_deleted",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Configuration,
                entity_name: Some(entity_logicalname),
                record_id: Some(id),
                operation: AuditOperation::SoftDelete,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("match_rule_deleted".to_owned()),
                event_comment: None,
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Survivorship rules ──────────────────────────────────────────────────────

const SURVIVORSHIP_STRATEGIES: &[&str] = &[
    "most_recent",
    "most_complete",
    "source_priority",
    "manual",
    "source_system_rank",
];

const SURVIVORSHIP_COLUMNS: &str = "id, entity_logicalname, field_logicalname, strategy, \
     priority_owner_ids, config, row_version, created_at, updated_at, created_by";

#[derive(sqlx::FromRow, Serialize, ToSchema)]
struct SurvivorshipRuleView {
    id: Uuid,
    entity_logicalname: String,
    field_logicalname: String,
    strategy: String,
    priority_owner_ids: Option<Vec<Uuid>>,
    /// L1-T3: a `source_system_rank` rule's trust per system per attribute.
    #[schema(value_type = Option<Object>)]
    config: Option<Value>,
    row_version: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    created_by: Uuid,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListSurvivorshipQuery {
    /// Only this entity (its logical name).
    entity: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// List survivorship rules
///
/// `GET /api/v1/admin/data/survivorship-rules` — `system.admin` only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/survivorship-rules",
    tag = "admin",
    params(ListSurvivorshipQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<SurvivorshipRuleView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_survivorship_rules(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<ListSurvivorshipQuery>,
) -> Result<Json<PaginatedResponse<SurvivorshipRuleView>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    let items: Vec<SurvivorshipRuleView> = sqlx::query_as(&format!(
        "SELECT {SURVIVORSHIP_COLUMNS} FROM survivorship_rule \
          WHERE NOT is_deleted AND ($1::text IS NULL OR entity_logicalname = $1) \
          ORDER BY entity_logicalname ASC, field_logicalname ASC OFFSET $2 LIMIT $3"
    ))
    .bind(&q.entity)
    .bind(offset)
    .bind(page_size)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM survivorship_rule \
          WHERE NOT is_deleted AND ($1::text IS NULL OR entity_logicalname = $1)",
    )
    .bind(&q.entity)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Deserialize, ToSchema)]
struct CreateSurvivorshipRuleBody {
    entity: String,
    field: String,
    strategy: String,
    #[serde(default)]
    priority_owner_ids: Vec<Uuid>,
    /// L1-T3: for `source_system_rank`, `{"ranks": {"<attribute>" | "*":
    /// ["<system>", ...]}, "tie_break": "recency" | "completeness",
    /// "validated_only": bool}`; absent for the other strategies.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    config: Option<Value>,
}

/// Create a survivorship rule
///
/// `POST /api/v1/admin/data/survivorship-rules` — `system.admin` only.
/// `409` when an active rule for this `(entity, field)` already exists
/// (migration `0219`'s partial unique index) — update the existing one
/// instead.
#[utoipa::path(
    post,
    path = "/api/v1/admin/data/survivorship-rules",
    tag = "admin",
    request_body = CreateSurvivorshipRuleBody,
    responses(
        (status = 201, description = "Success", body = SurvivorshipRuleView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "An active rule for this (entity, field) already exists", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Create)])))),
)]
async fn create_survivorship_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreateSurvivorshipRuleBody>,
) -> Result<(StatusCode, Json<SurvivorshipRuleView>), AppError> {
    if !SURVIVORSHIP_STRATEGIES.contains(&body.strategy.as_str()) {
        return Err(AppError::Validation(format!(
            "strategy must be one of: {}",
            SURVIVORSHIP_STRATEGIES.join(", ")
        )));
    }
    entity_crud::check_rule_config(&body.strategy, body.config.as_ref())
        .map_err(AppError::Validation)?;
    let (_, entity_name, attrs, _) = entity_crud::resolve_entity(&state, &body.entity).await?;
    if !attrs.iter().any(|a| a.logicalname == body.field) {
        return Err(AppError::Validation(format!(
            "field '{}' does not exist on this entity",
            body.field
        )));
    }

    let rule_id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: SurvivorshipRuleView = sqlx::query_as(&format!(
        "INSERT INTO survivorship_rule \
             (id, entity_logicalname, field_logicalname, strategy, priority_owner_ids, config, \
              row_version, created_by) \
         VALUES ($1, $2, $3, $4, $5, $7, 0, $6) \
         RETURNING {SURVIVORSHIP_COLUMNS}"
    ))
    .bind(rule_id)
    .bind(&entity_name)
    .bind(&body.field)
    .bind(&body.strategy)
    .bind(&body.priority_owner_ids)
    .bind(ctx.user_id)
    .bind(&body.config)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if attome_db::is_unique_violation(&e) {
            AppError::Conflict(
                "an active survivorship rule for this (entity, field) already exists",
            )
        } else {
            AppError::internal(e)
        }
    })?;
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Configuration,
                entity_name: Some(entity_name.clone()),
                record_id: Some(rule_id),
                operation: AuditOperation::Create,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("survivorship_rule_created".to_owned()),
                event_comment: Some(format!("{entity_name}.{}", body.field)),
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// Delete a survivorship rule
///
/// `DELETE /api/v1/admin/data/survivorship-rules/{id}` — `system.admin`
/// only. The (entity, field) reverts to the implicit `most_complete`
/// default.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/data/survivorship-rules/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The survivorship rule")),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Survivorship rule not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::SoftDelete)])))),
)]
async fn delete_survivorship_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let entity_logicalname: Option<String> = sqlx::query_scalar(
        "SELECT entity_logicalname FROM survivorship_rule WHERE id = $1 AND NOT is_deleted",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(entity_logicalname) = entity_logicalname else {
        return Err(AppError::NotFound);
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let result = sqlx::query(
        "UPDATE survivorship_rule SET is_deleted = TRUE, row_version = row_version + 1, \
             updated_at = NOW() WHERE id = $1 AND NOT is_deleted",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Configuration,
                entity_name: Some(entity_logicalname),
                record_id: Some(id),
                operation: AuditOperation::SoftDelete,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("survivorship_rule_deleted".to_owned()),
                event_comment: None,
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Duplicate candidates (steward queue) ────────────────────────────────────

const CANDIDATE_COLUMNS: &str = "id, entity_logicalname, record_a, record_b, match_rule_id, \
     score::float8, status, auto_merge_eligible, approval_request_id, detected_at, \
     resolved_at, resolved_by, resolution_note, row_version";

#[derive(sqlx::FromRow, Serialize, ToSchema)]
struct DuplicateCandidateView {
    id: Uuid,
    entity_logicalname: String,
    record_a: Uuid,
    record_b: Uuid,
    match_rule_id: Uuid,
    score: f64,
    status: String,
    auto_merge_eligible: bool,
    approval_request_id: Option<Uuid>,
    detected_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
    resolved_by: Option<Uuid>,
    resolution_note: Option<String>,
    row_version: i64,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListCandidatesQuery {
    /// Only this entity (its logical name).
    entity: Option<String>,
    /// `"open"` (default view for the steward queue), `"merged"`, or
    /// `"dismissed"`. Omit for every status.
    status: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// List duplicate pairs
///
/// `GET /api/v1/admin/data/duplicates` — `system.admin` only. The steward
/// queue's list view — filter `status=open` for candidates awaiting a
/// decision (the default a UI should request).
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/duplicates",
    tag = "admin",
    params(ListCandidatesQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<DuplicateCandidateView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_candidates(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<ListCandidatesQuery>,
) -> Result<Json<PaginatedResponse<DuplicateCandidateView>>, AppError> {
    if let Some(s) = &q.status
        && !["open", "merged", "dismissed"].contains(&s.as_str())
    {
        return Err(AppError::Validation(
            "status must be one of: open, merged, dismissed".into(),
        ));
    }
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    let items: Vec<DuplicateCandidateView> = sqlx::query_as(&format!(
        "SELECT {CANDIDATE_COLUMNS} FROM duplicate_candidate \
          WHERE ($1::text IS NULL OR entity_logicalname = $1) \
            AND ($2::text IS NULL OR status = $2) \
          ORDER BY detected_at DESC OFFSET $3 LIMIT $4"
    ))
    .bind(&q.entity)
    .bind(&q.status)
    .bind(offset)
    .bind(page_size)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM duplicate_candidate \
          WHERE ($1::text IS NULL OR entity_logicalname = $1) \
            AND ($2::text IS NULL OR status = $2)",
    )
    .bind(&q.entity)
    .bind(&q.status)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// One duplicate pair
///
/// `GET /api/v1/admin/data/duplicates/{id}` — `system.admin` only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/duplicates/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The duplicate")),
    responses(
        (status = 200, description = "Success", body = DuplicateCandidateView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Candidate not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_candidate(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<DuplicateCandidateView>, AppError> {
    let row: Option<DuplicateCandidateView> = sqlx::query_as(&format!(
        "SELECT {CANDIDATE_COLUMNS} FROM duplicate_candidate WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(row.ok_or(AppError::NotFound)?))
}

async fn load_open_candidate(
    state: &EngineState,
    id: Uuid,
) -> Result<(String, Uuid, Uuid), AppError> {
    let row: Option<(String, Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT entity_logicalname, record_a, record_b, status \
           FROM duplicate_candidate WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (entity, a, b, status) = row.ok_or(AppError::NotFound)?;
    if status != "open" {
        return Err(AppError::Conflict(
            "this candidate has already been resolved (merged or dismissed)",
        ));
    }
    Ok((entity, a, b))
}

#[derive(Deserialize, ToSchema)]
struct MergeCandidateBody {
    /// Which of the candidate's two records survives — must equal this
    /// candidate's `record_a` or `record_b`. The other becomes the
    /// duplicate and is soft-deleted, same as the ordinary
    /// `/{entity}/{id}/merge` endpoint this delegates to.
    canonical_id: Uuid,
}

/// Merge a duplicate pair
///
/// `POST /api/v1/admin/data/duplicates/{id}/merge` — `system.admin` only.
/// A steward's manual resolution of a candidate: runs the exact same merge
/// (`entity_crud::do_merge_core`) the ordinary `/{entity}/{id}/merge`
/// endpoint runs, attributed to the deciding admin, with a fully-privileged
/// context (`entity_crud::admin_security_context`) — see that function's
/// doc comment for why that's sound here specifically (the steward's own
/// `Authorized<Admin>` review IS the human decision this action needed; no
/// additional `attome_approval` gate — that's reserved for the *unattended*
/// `mdm.auto_merge` path, see `duplicates_match::submit_auto_merge_request`).
#[utoipa::path(
    post,
    path = "/api/v1/admin/data/duplicates/{id}/merge",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The duplicate")),
    request_body = MergeCandidateBody,
    responses(
        (status = 200, description = "Success", body = entity_crud::MergeResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Candidate not found", body = ErrorResponse),
        (status = 409, description = "Candidate already resolved", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update), (AuditCategory::Entity, AuditOperation::SoftDelete)])))),
)]
async fn merge_candidate(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<MergeCandidateBody>,
) -> Result<Json<entity_crud::MergeResponse>, AppError> {
    let (entity, a, b) = load_open_candidate(&state, id).await?;
    let duplicate_id = if body.canonical_id == a {
        b
    } else if body.canonical_id == b {
        a
    } else {
        return Err(AppError::Validation(
            "canonical_id must match one of this candidate's two records".into(),
        ));
    };

    let admin_ctx = entity_crud::admin_security_context(ctx.user_id);
    let outcome = entity_crud::do_merge_core(
        &state,
        &admin_ctx,
        &entity,
        body.canonical_id,
        duplicate_id,
        ctx.user_id,
        Some(id),
    )
    .await?;
    Ok(Json(entity_crud::MergeResponse::from_outcome(outcome)))
}

#[derive(Deserialize, ToSchema)]
struct DismissCandidateBody {
    row_version: i64,
    #[serde(default)]
    note: Option<String>,
}

/// Dismiss a duplicate pair
///
/// `POST /api/v1/admin/data/duplicates/{id}/dismiss` — `system.admin` only.
/// Marks the candidate "not actually a duplicate" — the matching job never
/// re-flags the same pair again (migration `0218`'s unique index covers
/// every status, not only `open`).
#[utoipa::path(
    post,
    path = "/api/v1/admin/data/duplicates/{id}/dismiss",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The duplicate")),
    request_body = DismissCandidateBody,
    responses(
        (status = 200, description = "Success", body = DuplicateCandidateView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Candidate not found", body = ErrorResponse),
        (status = 409, description = "row_version is stale, or candidate already resolved", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
)]
async fn dismiss_candidate(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<DismissCandidateBody>,
) -> Result<Json<DuplicateCandidateView>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<DuplicateCandidateView> = sqlx::query_as(&format!(
        "UPDATE duplicate_candidate \
         SET status = 'dismissed', resolved_at = NOW(), resolved_by = $3, resolution_note = $4, \
             row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 AND status = 'open' \
         RETURNING {CANDIDATE_COLUMNS}"
    ))
    .bind(id)
    .bind(body.row_version)
    .bind(ctx.user_id)
    .bind(&body.note)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    match row {
        Some(row) => {
            let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
            audit_service(&state)
                .write_in_tx(
                    &mut tx,
                    AuditEvent {
                        organization_ref: org_ref,
                        category: AuditCategory::Entity,
                        entity_name: Some(row.entity_logicalname.clone()),
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
                        event_name: Some("duplicate_candidate_dismissed".to_owned()),
                        event_comment: Some(format!(
                            "duplicate candidate {} vs {} dismissed",
                            row.record_a, row.record_b
                        )),
                        changed_fields: vec![],
                        snapshot_json: None,
                    },
                )
                .await?;
            attome_db::tx::commit(tx).await?;
            Ok(Json(row))
        }
        None => {
            let current: Option<(i64, String)> =
                sqlx::query_as("SELECT row_version, status FROM duplicate_candidate WHERE id = $1")
                    .bind(id)
                    .fetch_optional(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
            match current {
                None => Err(AppError::NotFound),
                Some((_, status)) if status != "open" => Err(AppError::Conflict(
                    "this candidate has already been resolved (merged or dismissed)",
                )),
                Some(_) => Err(AppError::VersionConflict),
            }
        }
    }
}

/// Surfaced by the record form's "possible duplicate" banner — a bounded
/// view of open candidates touching one specific record, not a full admin
/// listing. Any authenticated caller may call this (no `Admin` gate), but
/// only once `require_record_access` confirms they can actually read
/// `record_id` under their own record-level (RLS) scope — this echoes back
/// candidate metadata (peer record id, score) for a record the caller may
/// not otherwise have any admin visibility into, so read access to that
/// specific record is the correct boundary, not mere authentication. It
/// does NOT reveal the *other* record's data, only its id.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct RecordCandidatesQuery {
    /// Only this entity (its logical name).
    entity: String,
    /// Only this record.
    record_id: Uuid,
}

/// Likely duplicates of a record
///
/// Likely duplicates of a record. Any signed-in user.
#[utoipa::path(
    get,
    path = "/api/v1/data/duplicates/for-record",
    tag = "entity",
    params(RecordCandidatesQuery),
    responses(
        (status = 200, description = "Success", body = Vec<DuplicateCandidateView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "Record not found or not visible to the caller", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn candidates_for_record(
    State(state): State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
    Query(q): Query<RecordCandidatesQuery>,
) -> Result<Json<Vec<DuplicateCandidateView>>, AppError> {
    let (entity_id, entity_name, _, _) = entity_crud::resolve_entity(&state, &q.entity).await?;
    entity_crud::require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        q.record_id,
        attome_security::RecordAction::Read,
    )
    .await?;
    let items: Vec<DuplicateCandidateView> = sqlx::query_as(&format!(
        "SELECT {CANDIDATE_COLUMNS} FROM duplicate_candidate \
          WHERE entity_logicalname = $1 AND status = 'open' AND (record_a = $2 OR record_b = $2) \
          ORDER BY score DESC LIMIT 10"
    ))
    .bind(&entity_name)
    .bind(q.record_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(items))
}

// ── A15-T7: check, explain, rule preview, stats ─────────────────────────────

#[derive(Deserialize, ToSchema)]
struct DuplicateCheckBody {
    entity: String,
    /// The record's values, as a create or update would send them.
    #[schema(value_type = Object)]
    values: Value,
    /// The record being edited, never its own duplicate.
    #[serde(default)]
    record_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
struct DuplicateCheckResult {
    /// What saving would do: `warn`, `allow_with_reason` or `block`; `null`
    /// when nothing matches.
    action: Option<String>,
    matches: Vec<attome_records::duplicate_check::DuplicateMatch>,
    /// Matches the caller may not read.
    hidden: i64,
}

/// Check values for duplicates
///
/// `POST /api/v1/data/duplicates/check` — A15-T7: what saving these values
/// would meet under the entity's duplicate rules (the check a create or
/// update runs), without saving anything. The caller needs read access to
/// the entity.
#[utoipa::path(
    post,
    path = "/api/v1/data/duplicates/check",
    tag = "entity",
    request_body = DuplicateCheckBody,
    responses(
        (status = 200, description = "The matches and what saving would do", body = DuplicateCheckResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "looks the values up under the duplicate rules and writes nothing"
    )))),
)]
async fn check_duplicates(
    State(state): State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
    Json(body): Json<DuplicateCheckBody>,
) -> Result<Json<DuplicateCheckResult>, AppError> {
    let (entity_id, entity_name, _, _) = entity_crud::resolve_entity(&state, &body.entity).await?;
    attome_security::SecurityContextExt::require(&*ctx, &entity_name, "read")?;
    let values = body
        .values
        .as_object()
        .ok_or_else(|| AppError::Validation("values must be an object".into()))?;
    let outcome = attome_records::duplicate_check::check(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        body.record_id,
        values,
    )
    .await?;
    let action = outcome.action.and_then(|a| match a {
        attome_core::match_rule::OnSave::Off => None,
        attome_core::match_rule::OnSave::Warn => Some("warn".to_owned()),
        attome_core::match_rule::OnSave::AllowWithReason => Some("allow_with_reason".to_owned()),
        attome_core::match_rule::OnSave::Block => Some("block".to_owned()),
    });
    Ok(Json(DuplicateCheckResult {
        action,
        matches: outcome.visible,
        hidden: outcome.hidden,
    }))
}

#[derive(Debug, Serialize, ToSchema)]
struct FieldExplanation {
    field: String,
    comparator: Comparator,
    weight: f64,
    /// 1 matched, 0 differed, `null` no evidence (a side without a value).
    score: Option<f64>,
    /// Each record's key for a key comparator (phone, email, id, name,
    /// phonetic); `null` otherwise or when the record has none.
    key_a: Option<String>,
    key_b: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
struct CandidateExplanation {
    candidate_id: Uuid,
    rule_id: Uuid,
    score: f64,
    threshold: f64,
    fields: Vec<FieldExplanation>,
}

/// Explain a duplicate pair
///
/// `GET /api/v1/admin/data/duplicates/{id}/explain` — A15-T7: why a pair was
/// flagged: per field of its rule, the comparator, the weight, the score the
/// sweep stored and, for key comparators, both records' keys.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/duplicates/{id}/explain",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The duplicate")),
    responses(
        (status = 200, description = "The per-field explanation", body = CandidateExplanation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such candidate", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn explain_candidate(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<CandidateExplanation>, AppError> {
    let db = &state.base.db;
    #[allow(clippy::type_complexity)]
    let row: Option<(Uuid, Uuid, Uuid, f64, Option<Value>, Value, f64)> = sqlx::query_as(
        "SELECT c.record_a, c.record_b, c.match_rule_id, c.score::float8, c.field_scores, \
                r.fields, r.threshold::float8 \
           FROM duplicate_candidate c JOIN match_rule r ON r.id = c.match_rule_id \
          WHERE c.id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (record_a, record_b, rule_id, score, field_scores, fields, threshold) =
        row.ok_or(AppError::NotFound)?;
    let fields: Vec<MatchField> = serde_json::from_value(fields)
        .map_err(|e| AppError::internal(format!("corrupt match_rule.fields: {e}")))?;
    let keys: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT record_id, field, key FROM match_key \
          WHERE match_rule_id = $1 AND record_id = ANY($2)",
    )
    .bind(rule_id)
    .bind(vec![record_a, record_b])
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let key_of = |record: Uuid, field: &str| {
        keys.iter()
            .find(|(r, f, _)| *r == record && f == field)
            .map(|(_, _, k)| k.clone())
    };
    let explained = fields
        .iter()
        .map(|f| FieldExplanation {
            field: f.field.clone(),
            comparator: f.comparator,
            weight: f.weight,
            score: field_scores
                .as_ref()
                .and_then(|s| s.get(&f.field))
                .and_then(Value::as_f64),
            key_a: f
                .comparator
                .is_key()
                .then(|| key_of(record_a, &f.field))
                .flatten(),
            key_b: f
                .comparator
                .is_key()
                .then(|| key_of(record_b, &f.field))
                .flatten(),
        })
        .collect();
    Ok(Json(CandidateExplanation {
        candidate_id: id,
        rule_id,
        score,
        threshold,
        fields: explained,
    }))
}

#[derive(Deserialize, ToSchema)]
struct RulePreviewBody {
    entity: String,
    fields: Vec<MatchField>,
    threshold: f64,
}

/// Preview a match rule
///
/// `POST /api/v1/admin/data/match-rules/preview` — A15-T7: how many pairs a
/// draft rule would flag over a sample of the entity's live records (5,000
/// rows), with up to 20 examples. Pairs are found on the fields' keys
/// (exact, normalized and key comparators; trigram fields count as no
/// evidence here) and scored as the sweep scores them. Writes nothing.
#[utoipa::path(
    post,
    path = "/api/v1/admin/data/match-rules/preview",
    tag = "admin",
    request_body = RulePreviewBody,
    responses(
        (status = 200, description = "Pairs the draft rule would flag", body = attome_records::duplicate_check::RulePreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "scores a draft rule over a sample and writes nothing"
    )))),
)]
async fn preview_match_rule(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Json(body): Json<RulePreviewBody>,
) -> Result<Json<attome_records::duplicate_check::RulePreview>, AppError> {
    if body.threshold <= 0.0 || body.threshold > 1.0 {
        return Err(AppError::Validation(
            "threshold must be greater than 0 and at most 1".into(),
        ));
    }
    let (_, entity_name, attrs, _) = entity_crud::resolve_entity(&state, &body.entity).await?;
    let known: HashSet<&str> = attrs.iter().map(|a| a.logicalname.as_str()).collect();
    validate_match_fields(&known, &body.fields)?;
    Ok(Json(
        attome_records::duplicate_check::preview_rule(
            &state,
            &entity_name,
            &body.fields,
            body.threshold,
            attome_records::duplicate_check::RULE_PREVIEW_SAMPLE,
        )
        .await?,
    ))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct DuplicateStatsQuery {
    /// One entity; absent: every entity.
    entity: Option<String>,
}

#[derive(Debug, sqlx::FromRow, Serialize, ToSchema)]
struct DuplicateStats {
    entity: String,
    open: i64,
    merged: i64,
    dismissed: i64,
}

/// Duplicate statistics
///
/// `GET /api/v1/admin/data/duplicates/stats` — A15-T7: duplicate pairs per
/// entity by status (open, merged, dismissed), for the data-quality view.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/duplicates/stats",
    tag = "admin",
    params(DuplicateStatsQuery),
    responses(
        (status = 200, description = "Counts per entity", body = PaginatedResponse<DuplicateStats>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn duplicate_stats(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<DuplicateStatsQuery>,
) -> Result<Json<PaginatedResponse<DuplicateStats>>, AppError> {
    let items: Vec<DuplicateStats> = sqlx::query_as(
        "SELECT entity_logicalname AS entity, \
                count(*) FILTER (WHERE status = 'open') AS open, \
                count(*) FILTER (WHERE status = 'merged') AS merged, \
                count(*) FILTER (WHERE status = 'dismissed') AS dismissed \
           FROM duplicate_candidate \
          WHERE ($1::text IS NULL OR entity_logicalname = $1) \
          GROUP BY entity_logicalname ORDER BY entity_logicalname",
    )
    .bind(&q.entity)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/data/match-rules",
            get(list_match_rules).post(create_match_rule),
        )
        .route(
            "/api/v1/admin/data/match-rules/{id}",
            axum::routing::put(update_match_rule).delete(delete_match_rule),
        )
        .route(
            "/api/v1/admin/data/match-rules/{id}/scan",
            post(scan_match_rule),
        )
        .route(
            "/api/v1/admin/data/match-rules/preview",
            post(preview_match_rule),
        )
        .route("/api/v1/data/duplicates/check", post(check_duplicates))
        .route(
            "/api/v1/admin/data/duplicates/{id}/explain",
            get(explain_candidate),
        )
        .route("/api/v1/admin/data/duplicates/stats", get(duplicate_stats))
        .route(
            "/api/v1/admin/data/survivorship-rules",
            get(list_survivorship_rules).post(create_survivorship_rule),
        )
        .route(
            "/api/v1/admin/data/survivorship-rules/{id}",
            axum::routing::delete(delete_survivorship_rule),
        )
        .route("/api/v1/admin/data/duplicates", get(list_candidates))
        .route("/api/v1/admin/data/duplicates/{id}", get(get_candidate))
        .route(
            "/api/v1/admin/data/duplicates/{id}/merge",
            post(merge_candidate),
        )
        .route(
            "/api/v1/admin/data/duplicates/{id}/dismiss",
            post(dismiss_candidate),
        )
        .route(
            "/api/v1/data/duplicates/for-record",
            get(candidates_for_record),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_match_rules,
    create_match_rule,
    update_match_rule,
    delete_match_rule,
    scan_match_rule,
    preview_match_rule,
    check_duplicates,
    explain_candidate,
    duplicate_stats,
    list_survivorship_rules,
    create_survivorship_rule,
    delete_survivorship_rule,
    list_candidates,
    get_candidate,
    merge_candidate,
    dismiss_candidate,
    candidates_for_record,
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
