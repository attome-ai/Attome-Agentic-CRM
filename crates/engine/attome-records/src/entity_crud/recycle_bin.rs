//! The recycle bin (roadmap A18-T7): an entity's deleted records the caller
//! may see, newest deletion first, with the reason and the operation each
//! deletion belonged to (the `deletion` ledger, A18-T2). A deleted record
//! comes back through `POST /api/v1/{entity}/{id}/restore`, a selection
//! through `POST /api/v1/bin/restore`, and a whole operation (the undo after
//! a delete) through `POST /api/v1/bin/operations/{operation_id}/restore`.
//!
//! Visibility is the entity's own record rules, through the same
//! `rls_predicate` every read uses: a deleted record the caller could not
//! read while it was live stays out of their bin.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_auth::SessionClaims;
use attome_core::{EngineState, quote_ident};
use attome_security::record_action::{Delete, Read};
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Admin, Authorized, RecordScoped, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::resolve::resolve_entity;

/// One deleted record.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct DeletedRecord {
    pub id: Uuid,
    /// The record's primary name, when its entity declares one.
    pub label: Option<String>,
    /// When it was last changed, which for a deleted record is its deletion.
    pub deleted_at: Option<DateTime<Utc>>,
    pub deleted_by: Option<Uuid>,
    /// Why, when a reason was given.
    pub reason: Option<String>,
    /// The operation it was removed in; restore it whole through
    /// `POST /api/v1/bin/operations/{operation_id}/restore`.
    pub operation_id: Option<String>,
    /// `request`, `agent`, `flow`, `bulk`, `import`, `merge`, `portal` or
    /// `migration`.
    pub operation_kind: Option<String>,
}

/// A page of `entity`'s deleted records the caller may see.
pub async fn deleted_records(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    query: &OnePageQuery,
) -> Result<PaginatedResponse<DeletedRecord>, AppError> {
    let window = query.window();
    let (entity_id, entity, _, is_append_only) = resolve_entity(state, entity_input).await?;
    ctx.require(&entity, "read")?;
    if is_append_only {
        // An append-only entity never deletes, so its bin is always empty.
        return Ok(PaginatedResponse::new(
            Vec::new(),
            0,
            window.page,
            window.page_size,
        ));
    }
    let name_attr = state
        .entities
        .load()
        .get(&entity)
        .and_then(|m| m.primary_name_attribute.clone());
    let access_level = attome_security::resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        &entity,
        RecordAction::Read,
    )
    .await?;
    let table = quote_ident(&entity);
    let name_expr = name_attr.as_deref().map_or_else(
        || "NULL::text".to_owned(),
        |c| format!("{}::text", quote_ident(c)),
    );

    let count_pred = attome_security::rls_predicate(
        ctx,
        entity_id,
        "",
        access_level,
        RecordAction::Read.share_capability(),
        1,
    );
    let count_sql = format!(
        "SELECT COUNT(*) FROM {table} WHERE is_active = false {}",
        count_pred.as_ref().map_or("", |p| p.sql.as_str())
    );
    let count_sql = attome_db::tag_dynamic("entity.recycle_bin", &count_sql);
    let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
    if let Some(p) = &count_pred {
        count_query = count_query
            .bind(p.binds.entity_ref)
            .bind(p.binds.caller_id)
            .bind(&p.binds.team_ids)
            .bind(p.binds.capability)
            .bind(&p.binds.accessible_org_ids)
            .bind(&p.binds.subordinate_user_ids);
    }
    let total = count_query
        .fetch_one(&state.base.db)
        .await
        .map_err(attome_db::classify)?;

    let pred = attome_security::rls_predicate(
        ctx,
        entity_id,
        "",
        access_level,
        RecordAction::Read.share_capability(),
        3,
    );
    // The ledger's open row for each record, joined laterally so its
    // columns stay qualified next to the record-rule predicate.
    let entity_param = if pred.is_some() { 9 } else { 3 };
    let sql = format!(
        "SELECT {table}.id, {name_expr} AS label, {table}.modified_at AS deleted_at, \
                {table}.modified_by AS deleted_by, \
                d.reason, d.operation_id, d.operation_kind \
         FROM {table} \
         LEFT JOIN LATERAL (SELECT l.reason, l.operation_id, l.operation_kind FROM deletion l \
                            WHERE l.entity = ${entity_param} AND l.record_id = {table}.id \
                              AND l.restored_at IS NULL AND l.purged_at IS NULL) d ON true \
         WHERE {table}.is_active = false {} \
         ORDER BY {table}.modified_at DESC NULLS LAST, {table}.id DESC LIMIT $1 OFFSET $2",
        pred.as_ref().map_or("", |p| p.sql.as_str())
    );
    let sql = attome_db::tag_dynamic("entity.recycle_bin", &sql);
    let mut rows_query = sqlx::query_as::<_, DeletedRecord>(&sql)
        .bind(window.page_size)
        .bind(window.offset);
    if let Some(p) = &pred {
        rows_query = rows_query
            .bind(p.binds.entity_ref)
            .bind(p.binds.caller_id)
            .bind(&p.binds.team_ids)
            .bind(p.binds.capability)
            .bind(&p.binds.accessible_org_ids)
            .bind(&p.binds.subordinate_user_ids);
    }
    rows_query = rows_query.bind(&entity);
    let items = rows_query
        .fetch_all(&state.base.db)
        .await
        .map_err(attome_db::classify)?;
    Ok(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    ))
}

/// Deleted records
///
/// A18-T7: the entity's deleted records the caller may see, newest
/// deletion first. Restore one with `POST /api/v1/{entity}/{id}/restore`.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/deleted",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name"), OnePageQuery),
    responses(
        (status = 200, description = "A page of deleted records", body = PaginatedResponse<DeletedRecord>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the entity's read privilege", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_deleted(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path(entity): Path<String>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<DeletedRecord>>, AppError> {
    Ok(Json(deleted_records(&state, &ctx, &entity, &query).await?))
}

/// `POST /api/v1/{entity}/delete-impact`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DeleteImpactRequest {
    /// The records about to be deleted, at most 500.
    pub ids: Vec<Uuid>,
}

/// Live records of one entity that point at the records being deleted
/// through one lookup field.
#[derive(Debug, Serialize, ToSchema)]
pub struct DependentCount {
    pub entity: String,
    pub field: String,
    pub count: i64,
}

/// What deleting the records would do (A18-T4), counted without changing
/// anything.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeleteImpact {
    /// Removed with them (and restored with them).
    pub cascades: Vec<DependentCount>,
    /// Records that stop the delete while they point here.
    pub blocked_by: Vec<DependentCount>,
    /// Left pointing at a deleted record.
    pub orphaned: Vec<DependentCount>,
    /// Dependents in entities the caller cannot read exist; they are not
    /// counted here.
    pub hidden_dependents: bool,
    /// The entity's bin setting asks for a reason.
    pub reason_required: bool,
}

/// The live records pointing at `ids` through each lookup to the entity,
/// counted per relationship, in entities the caller can read; the flag is
/// true when an unreadable entity has some.
pub(super) async fn dependent_counts(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    ids: &[Uuid],
) -> Result<(Vec<(DependentCount, attome_core::OnTargetDelete)>, bool), AppError> {
    let registry = state.entities.load();
    let mut found = Vec::new();
    let mut hidden = false;
    for (dependent, field, policy) in registry.dependents_of(entity_id) {
        let live = match registry.get(&dependent) {
            Some(meta) if meta.is_append_only => "",
            Some(_) => " AND is_active = true",
            None => continue,
        };
        let count: i64 = sqlx::query_scalar(&attome_db::tag_dynamic(
            "entity.recycle_bin",
            &format!(
                "SELECT COUNT(*) FROM {} WHERE {} = ANY($1){live}",
                quote_ident(&dependent),
                quote_ident(&field)
            ),
        ))
        .bind(ids)
        .fetch_one(&state.base.db)
        .await
        .map_err(attome_db::classify)?;
        if count == 0 {
            continue;
        }
        if ctx.require(&dependent, "read").is_err() {
            hidden = true;
            continue;
        }
        found.push((
            DependentCount {
                entity: dependent,
                field,
                count,
            },
            policy,
        ));
    }
    Ok((found, hidden))
}

/// Counts what deleting `ids` of `entity_input` would touch.
pub async fn delete_impact(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    ids: &[Uuid],
) -> Result<DeleteImpact, AppError> {
    if ids.is_empty() || ids.len() > MAX_BIN_RESTORE {
        return Err(AppError::Validation(format!(
            "give 1 to {MAX_BIN_RESTORE} ids"
        )));
    }
    let (entity_id, entity, _, _) = resolve_entity(state, entity_input).await?;
    ctx.require(&entity, "delete")?;
    let mut impact = DeleteImpact {
        cascades: Vec::new(),
        blocked_by: Vec::new(),
        orphaned: Vec::new(),
        hidden_dependents: false,
        reason_required: false,
    };
    let (dependents, hidden) = dependent_counts(state, ctx, entity_id, ids).await?;
    impact.hidden_dependents = hidden;
    for (row, policy) in dependents {
        match policy {
            attome_core::OnTargetDelete::CascadeDeactivate => impact.cascades.push(row),
            attome_core::OnTargetDelete::Restrict => impact.blocked_by.push(row),
            attome_core::OnTargetDelete::Orphan => impact.orphaned.push(row),
        }
    }
    impact.reason_required = sqlx::query_scalar::<_, bool>(attome_db::tagged_sql!(
        "entity.recycle_bin",
        "SELECT require_reason FROM bin_setting WHERE entity = $1"
    ))
    .bind(&entity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(attome_db::classify)?
    .unwrap_or(false);
    Ok(impact)
}

/// Preview a delete
///
/// A18-T4: what deleting these records would cascade to, be blocked by or
/// leave pointing at them, and whether a reason is required; nothing is
/// changed.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/delete-impact",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name")),
    request_body = DeleteImpactRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "counts dependent records and writes nothing"
    )))),
    responses(
        (status = 200, description = "What the delete would touch", body = DeleteImpact),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not delete this entity's records", body = ErrorResponse),
        (status = 422, description = "No ids, or more than 500", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn preview_delete(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Delete>>,
    Path(entity): Path<String>,
    Json(body): Json<DeleteImpactRequest>,
) -> Result<Json<DeleteImpact>, AppError> {
    Ok(Json(delete_impact(&state, &ctx, &entity, &body.ids).await?))
}

/// `?action=` of the impact preview.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ImpactQuery {
    /// `delete` (the default), `merge` or `reassign`.
    #[serde(default)]
    pub action: Option<String>,
}

/// Preview an action's impact
///
/// A7-T2: what deleting, merging away or reassigning this record would
/// touch: per entity and path, how many records and the first 20, whether a
/// restrict rule would refuse it, at every depth of a delete's cascade.
/// Nothing is changed. A delete's whole cascade is undone as one unit by
/// restoring the record (`POST .../{id}/restore` brings back everything the
/// cascade took, level by level).
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/impact",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ImpactQuery,
    ),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "walks what the action would touch and writes nothing"
    )))),
    responses(
        (status = 200, description = "What the action would touch", body = crate::cascade::Impact),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not take this action on the record", body = ErrorResponse),
        (status = 404, description = "No such record", body = ErrorResponse),
        (status = 422, description = "Not delete, merge or reassign", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn preview_impact(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity, id)): Path<(String, Uuid)>,
    Query(query): Query<ImpactQuery>,
) -> Result<Json<crate::cascade::Impact>, AppError> {
    let (_, entity, _, _) = resolve_entity(&state, &entity).await?;
    let action = query.action.as_deref().unwrap_or("delete").to_owned();
    let privilege = match action.as_str() {
        "delete" | "merge" => "delete",
        "reassign" => "update",
        _ => {
            return Err(AppError::Validation(
                "action is delete, merge or reassign".into(),
            ));
        }
    };
    ctx.require(&entity, privilege)?;
    let live: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE id = $1 AND is_active = TRUE)",
        quote_ident(&entity)
    ))
    .bind(id)
    .fetch_one(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    if !live {
        return Err(AppError::NotFound);
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let can_read = |e: &str| ctx.require(e, "read").is_ok();
    Ok(Json(
        crate::cascade::impact(&mut conn, &entity, id, &action, &can_read).await?,
    ))
}

/// One entity's recycle-bin rules (`bin_setting`); an entity with no row
/// has the defaults.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct BinSetting {
    pub entity: String,
    /// A person must give a reason to delete.
    pub require_reason: bool,
    /// Days a deleted record stays in the bin before it is purged; `null`
    /// follows the deployment's `retention.entity_purge_grace_days`.
    pub retention_days: Option<i32>,
    /// Deletions by one person within ten minutes that raise an alert.
    pub alert_threshold: i32,
    /// A permanent delete waits for a second person's approval.
    pub hard_delete_needs_approval: bool,
    pub updated_at: DateTime<Utc>,
    pub row_version: i64,
}

/// `PUT /api/v1/admin/bin-settings/{entity}`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct BinSettingBody {
    #[serde(default)]
    pub require_reason: bool,
    /// 1 to 3,650, or `null`.
    pub retention_days: Option<i32>,
    /// 1 to 100,000; default 100.
    pub alert_threshold: Option<i32>,
    #[serde(default)]
    pub hard_delete_needs_approval: bool,
}

const BIN_SETTING_COLUMNS: &str = "entity, require_reason, retention_days, alert_threshold, \
     hard_delete_needs_approval, updated_at, row_version";

/// Recycle bin rules
///
/// A18-T7: every entity that has its own bin rules.
#[utoipa::path(
    get,
    path = "/api/v1/admin/bin-settings",
    tag = "admin",
    responses(
        (status = 200, description = "Entities with their own bin rules", body = PaginatedResponse<BinSetting>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_bin_settings(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<PaginatedResponse<BinSetting>>, AppError> {
    let items: Vec<BinSetting> = sqlx::query_as(&attome_db::tag_dynamic(
        "entity.recycle_bin",
        &format!("SELECT {BIN_SETTING_COLUMNS} FROM bin_setting ORDER BY entity"),
    ))
    .fetch_all(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    let total = i64::try_from(items.len()).map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

/// Set an entity's bin rules
///
/// A18-T7: sets an entity's bin rules.
#[utoipa::path(
    put,
    path = "/api/v1/admin/bin-settings/{entity}",
    tag = "admin",
    params(("entity" = String, Path, description = "The entity's logical name")),
    request_body = BinSettingBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The entity's bin rules", body = BinSetting),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 422, description = "A value out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn put_bin_setting(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(entity_input): Path<String>,
    Json(body): Json<BinSettingBody>,
) -> Result<Json<BinSetting>, AppError> {
    let (_, entity, _, _) = resolve_entity(&state, &entity_input).await?;
    if body
        .retention_days
        .is_some_and(|d| !(1..=3650).contains(&d))
    {
        return Err(AppError::Validation(
            "retention_days is 1 to 3650, or null".into(),
        ));
    }
    let threshold = body.alert_threshold.unwrap_or(100);
    if !(1..=100_000).contains(&threshold) {
        return Err(AppError::Validation(
            "alert_threshold is 1 to 100000".into(),
        ));
    }
    let event = SecurityEvent::new(
        MandatoryCategory::Configuration,
        AuditOperation::Update,
        ctx.user_id,
        "bin_setting",
        None,
    )
    .named("bin_setting.updated")
    .comment(format!("recycle bin rules for {entity}"));
    let mut stx = SecurityTx::begin(&state, event).await?;
    let setting: BinSetting = sqlx::query_as(&attome_db::tag_dynamic(
        "entity.recycle_bin",
        &format!(
            "INSERT INTO bin_setting (entity, require_reason, retention_days, alert_threshold, \
                                  hard_delete_needs_approval) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (entity) DO UPDATE SET require_reason = EXCLUDED.require_reason, \
             retention_days = EXCLUDED.retention_days, alert_threshold = EXCLUDED.alert_threshold, \
             hard_delete_needs_approval = EXCLUDED.hard_delete_needs_approval, \
             updated_at = NOW(), row_version = bin_setting.row_version + 1 \
         RETURNING {BIN_SETTING_COLUMNS}"
        ),
    ))
    .bind(&entity)
    .bind(body.require_reason)
    .bind(body.retention_days)
    .bind(threshold)
    .bind(body.hard_delete_needs_approval)
    .fetch_one(&mut *stx)
    .await
    .map_err(attome_db::classify)?;
    stx.commit().await?;
    Ok(Json(setting))
}

/// A person who deleted at least an entity's `alert_threshold` records of it
/// in the last ten minutes (A18-T4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LargeDelete {
    pub user_id: Uuid,
    pub entity: String,
    pub count: i64,
}

/// A18-T4: the bursts of deletion to report now. Each person is reported
/// once an hour at most: the ones returned are marked as reported before the
/// caller sends anything, so a crash costs an alert, never a repeat storm.
pub async fn take_large_deletes(db: &attome_db::DbPool) -> Result<Vec<LargeDelete>, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let rows: Vec<(Uuid, String, i64)> = sqlx::query_as(attome_db::tagged_sql!(
        "entity.recycle_bin",
        "SELECT d.deleted_by, d.entity, COUNT(*) \
         FROM deletion d LEFT JOIN bin_setting s ON s.entity = d.entity \
         WHERE d.deleted_at > now() - interval '10 minutes' AND d.deleted_by IS NOT NULL \
           AND NOT EXISTS (SELECT 1 FROM bin_delete_alert a \
                           WHERE a.user_ref = d.deleted_by \
                             AND a.alerted_at > now() - interval '1 hour') \
         GROUP BY d.deleted_by, d.entity, s.alert_threshold \
         HAVING COUNT(*) >= COALESCE(s.alert_threshold, 100) \
         ORDER BY d.deleted_by, d.entity"
    ))
    .fetch_all(&mut *tx)
    .await
    .map_err(attome_db::classify)?;
    let mut users: Vec<Uuid> = rows.iter().map(|(user, _, _)| *user).collect();
    users.dedup();
    if !users.is_empty() {
        sqlx::query(attome_db::tagged_sql!(
            "entity.recycle_bin",
            "INSERT INTO bin_delete_alert (user_ref, alerted_at) \
             SELECT unnest($1::uuid[]), now() \
             ON CONFLICT (user_ref) DO UPDATE SET alerted_at = EXCLUDED.alerted_at"
        ))
        .bind(&users)
        .execute(&mut *tx)
        .await
        .map_err(attome_db::classify)?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(user_id, entity, count)| LargeDelete {
            user_id,
            entity,
            count,
        })
        .collect())
}

/// Records one bin restore may bring back.
pub const MAX_BIN_RESTORE: usize = 500;

/// One record to restore.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BinItem {
    pub entity: String,
    pub id: Uuid,
}

/// `POST /api/v1/bin/restore`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct BinRestoreRequest {
    /// At most 500.
    pub items: Vec<BinItem>,
}

/// One record a restore could not bring back.
#[derive(Debug, Serialize, ToSchema)]
pub struct BinRestoreFailure {
    pub entity: String,
    pub id: Uuid,
    /// `not_found`, `forbidden`, `conflict` (live already, or a value now
    /// taken by another record), `invalid` (a lookup it points at is gone)
    /// or `failed`.
    pub code: &'static str,
    /// For `invalid`: a deleted record this one points at, which the caller
    /// may restore first ("Restore parent too", A18-T9).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<BinItem>,
}

/// What a bin restore did.
#[derive(Debug, Serialize, ToSchema)]
pub struct BinRestoreResult {
    pub restored: usize,
    pub failed: Vec<BinRestoreFailure>,
}

/// Restores each item through the same path as a single restore (update
/// access to the entity and the record), reporting the ones that failed.
pub async fn restore_items(
    state: &EngineState,
    ctx: &SecurityContext,
    acting_user_id: Uuid,
    items: &[BinItem],
) -> Result<BinRestoreResult, AppError> {
    if items.is_empty() || items.len() > MAX_BIN_RESTORE {
        return Err(AppError::Validation(format!(
            "restore 1 to {MAX_BIN_RESTORE} records"
        )));
    }
    let mut result = BinRestoreResult {
        restored: 0,
        failed: Vec::new(),
    };
    for item in items {
        let outcome = match ctx.require(&item.entity, "update") {
            Ok(()) => {
                super::restore_record_for(state, ctx, acting_user_id, &item.entity, item.id, None)
                    .await
                    .map(|_| ())
            }
            Err(error) => Err(error),
        };
        let code = match outcome {
            Ok(()) => {
                result.restored += 1;
                continue;
            }
            Err(AppError::NotFound) => "not_found",
            Err(AppError::Forbidden) => "forbidden",
            Err(AppError::Conflict(_) | AppError::VersionConflict) => "conflict",
            Err(AppError::Validation(_) | AppError::FieldValidation(_)) => "invalid",
            Err(error) => {
                tracing::warn!(%error, entity = %item.entity, record_id = %item.id,
                    "bin restore could not bring a record back");
                "failed"
            }
        };
        let parent = if code == "invalid" {
            deleted_parent(state, ctx, &item.entity, item.id)
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!(%error, entity = %item.entity, record_id = %item.id,
                        "bin restore could not look for a deleted parent");
                    None
                })
        } else {
            None
        };
        result.failed.push(BinRestoreFailure {
            entity: item.entity.clone(),
            id: item.id,
            code,
            parent,
        });
    }
    Ok(result)
}

/// The first deleted record `id` points at through a lookup, in an entity
/// the caller may restore: what keeps it from coming back.
async fn deleted_parent(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    id: Uuid,
) -> Result<Option<BinItem>, AppError> {
    let (_, entity_name, attrs, _) = resolve_entity(state, entity).await?;
    let lookups: Vec<(String, String)> = {
        let registry = state.entities.load();
        attrs
            .iter()
            .filter(|a| a.field_type_int == 11)
            .filter_map(|a| {
                let target = registry.get_by_id(a.lookup_entity_ref?)?;
                (!target.is_append_only)
                    .then(|| (a.logicalname.clone(), target.logicalname.clone()))
            })
            .collect()
    };
    for (field, target) in lookups {
        if ctx.require(&target, "update").is_err() {
            continue;
        }
        let parent_id: Option<Uuid> = sqlx::query_scalar(&attome_db::tag_dynamic(
            "entity.recycle_bin",
            &format!(
                "SELECT {} FROM {} WHERE id = $1",
                quote_ident(&field),
                quote_ident(&entity_name)
            ),
        ))
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(attome_db::classify)?
        .flatten();
        let Some(parent_id) = parent_id else {
            continue;
        };
        let deleted: Option<bool> = sqlx::query_scalar(&attome_db::tag_dynamic(
            "entity.recycle_bin",
            &format!(
                "SELECT NOT is_active FROM {} WHERE id = $1",
                quote_ident(&target)
            ),
        ))
        .bind(parent_id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(attome_db::classify)?;
        if deleted == Some(true) {
            return Ok(Some(BinItem {
                entity: target,
                id: parent_id,
            }));
        }
    }
    Ok(None)
}

/// Restore deleted records
///
/// A18-T7: restores up to 500 deleted records, each checked as a single
/// restore would be; the ones that could not come back are listed.
#[utoipa::path(
    post,
    path = "/api/v1/bin/restore",
    tag = "entity",
    request_body = BinRestoreRequest,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Restore)])))),
    responses(
        (status = 200, description = "How many came back, and which could not", body = BinRestoreResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "No items, or more than 500", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn restore_selection(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Extension(claims): Extension<SessionClaims>,
    Json(body): Json<BinRestoreRequest>,
) -> Result<Json<BinRestoreResult>, AppError> {
    Ok(Json(
        restore_items(&state, &ctx, claims.sub, &body.items).await?,
    ))
}

/// Undo a delete operation
///
/// A18-T7: undoes one delete operation: every record its ledger rows still
/// hold in the bin (at most 500), restored as [`restore_selection`] would.
#[utoipa::path(
    post,
    path = "/api/v1/bin/operations/{operation_id}/restore",
    tag = "entity",
    params(("operation_id" = String, Path, description = "The delete operation")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Restore)])))),
    responses(
        (status = 200, description = "How many came back, and which could not", body = BinRestoreResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "Nothing from that operation is in the bin", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn restore_operation(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Extension(claims): Extension<SessionClaims>,
    Path(operation_id): Path<String>,
) -> Result<Json<BinRestoreResult>, AppError> {
    let rows: Vec<(String, Uuid)> = sqlx::query_as(attome_db::tagged_sql!(
        "entity.recycle_bin",
        "SELECT entity, record_id FROM deletion \
         WHERE operation_id = $1 AND restored_at IS NULL AND purged_at IS NULL \
         ORDER BY deleted_at LIMIT $2"
    ))
    .bind(operation_id.trim())
    .bind(MAX_BIN_RESTORE as i64)
    .fetch_all(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    if rows.is_empty() {
        return Err(AppError::NotFound);
    }
    let items: Vec<BinItem> = rows
        .into_iter()
        .map(|(entity, id)| BinItem { entity, id })
        .collect();
    Ok(Json(restore_items(&state, &ctx, claims.sub, &items).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_deleted,
    restore_selection,
    restore_operation,
    preview_delete,
    preview_impact,
    list_bin_settings,
    put_bin_setting
))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
