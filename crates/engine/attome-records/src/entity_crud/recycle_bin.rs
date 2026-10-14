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

use attome_auth::SessionClaims;
use attome_core::{EngineState, quote_ident};
use attome_security::record_action::Read;
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, RecordScoped, SelfService};
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

/// A18-T7: the entity's deleted records the caller may see, newest
/// deletion first. Restore one with `POST /api/v1/{entity}/{id}/restore`.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/deleted",
    tag = "entity",
    params(("entity" = String, Path), OnePageQuery),
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

/// Records one bin restore may bring back.
pub const MAX_BIN_RESTORE: usize = 500;

/// One record to restore.
#[derive(Debug, Clone, Deserialize, ToSchema)]
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
        result.failed.push(BinRestoreFailure {
            entity: item.entity.clone(),
            id: item.id,
            code,
        });
    }
    Ok(result)
}

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

/// A18-T7: undoes one delete operation: every record its ledger rows still
/// hold in the bin (at most 500), restored as [`restore_selection`] would.
#[utoipa::path(
    post,
    path = "/api/v1/bin/operations/{operation_id}/restore",
    tag = "entity",
    params(("operation_id" = String, Path)),
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
    let rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT entity, record_id FROM deletion \
         WHERE operation_id = $1 AND restored_at IS NULL AND purged_at IS NULL \
         ORDER BY deleted_at LIMIT $2",
    )
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
#[openapi(paths(list_deleted, restore_selection, restore_operation))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
