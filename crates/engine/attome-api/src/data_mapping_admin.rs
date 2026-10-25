//! M12 (data management) — the ONE shared field-mapping model
//! (`data_mapping`), admin CRUD. Meant to be reused unchanged by
//! staged import (this plan, `bulk.rs`'s `mapping_ref`), M17 record
//! migration, and M59 connector sync — see D-408.
//!
//! `fields[].transform` is a nullable free-text M45 (attome-rules) expression
//! column. M45 does not exist in this worktree — every reader of this
//! column (including this admin surface) MUST treat an unset OR a
//! set-but-unevaluated `transform` as identity/passthrough. Evaluating it is
//! explicitly deferred (D-408); this surface only stores and returns it
//! verbatim, with a sanity length cap.
//!
//! `system.admin` only, mounted with `strict_authz` in `system.rs` — same
//! posture as every other metadata-admin surface in this crate
//! (`view_admin`, `query_admin`).

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, audit_service,
};
use attome_core::EngineState;
use attome_records::data_mapping::DataMappingField;
use attome_records::entity_crud;
use attome_records::entity_mutation;
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
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Sanity bound only — this column is stored and returned verbatim, never
/// parsed or evaluated here (see this file's module doc / D-408).
const MAX_TRANSFORM_LEN: usize = 4000;

fn valid_source_kind(s: &str) -> bool {
    matches!(s, "csv" | "json" | "connector")
}

fn valid_lookup_resolution(s: &str) -> bool {
    matches!(s, "by_id" | "by_natural_key" | "by_label")
}

fn validate_fields(
    target_entity_attrs: &[attome_core::AttrInfo],
    fields: &[DataMappingField],
) -> Result<(), AppError> {
    if fields.is_empty() {
        return Err(AppError::Validation("fields must not be empty".into()));
    }
    for field in fields {
        if field.source.trim().is_empty() {
            return Err(AppError::Validation(
                "field.source must not be empty".into(),
            ));
        }
        if !target_entity_attrs
            .iter()
            .any(|a| a.logicalname == field.target)
        {
            return Err(AppError::Validation(format!(
                "field.target '{}' is not a registered attribute of the target entity",
                field.target
            )));
        }
        if let Some(transform) = &field.transform
            && transform.len() > MAX_TRANSFORM_LEN
        {
            return Err(AppError::Validation(format!(
                "field.transform exceeds {MAX_TRANSFORM_LEN} characters"
            )));
        }
        if !valid_lookup_resolution(&field.lookup_resolution) {
            return Err(AppError::Validation(format!(
                "field.lookup_resolution must be by_id, by_natural_key, or by_label, got: {}",
                field.lookup_resolution
            )));
        }
        if field.lookup_resolution == "by_natural_key"
            && field
                .lookup_match_field
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(AppError::Validation(
                "field.lookup_match_field is required when lookup_resolution is by_natural_key"
                    .into(),
            ));
        }
    }
    Ok(())
}

#[derive(Deserialize, ToSchema)]
struct CreateMappingBody {
    name: String,
    target_entity: String,
    source_kind: String,
    fields: Vec<DataMappingField>,
}

#[derive(Deserialize, ToSchema)]
struct UpdateMappingBody {
    name: Option<String>,
    source_kind: Option<String>,
    fields: Option<Vec<DataMappingField>>,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
struct DataMappingRow {
    id: Uuid,
    name: String,
    target_entity: String,
    source_kind: String,
    fields: Value,
    created_by: Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListMappingsQuery {
    /// Only mappings or projects into this entity (its logical name).
    target_entity: Option<String>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// Create a data mapping
///
/// Create a data mapping. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/data/mappings",
    tag = "admin",
    request_body = CreateMappingBody,
    responses(
        (status = 201, description = "Success", body = DataMappingRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "A live mapping already has this name", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Create)])))),
)]
async fn create_mapping(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreateMappingBody>,
) -> Result<(StatusCode, Json<DataMappingRow>), AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    if !valid_source_kind(&body.source_kind) {
        return Err(AppError::Validation(
            "source_kind must be csv, json, or connector".into(),
        ));
    }
    let (_, target_entity, attrs, _) =
        entity_crud::resolve_entity(&state, &body.target_entity).await?;
    validate_fields(&attrs, &body.fields)?;

    let fields_json = serde_json::to_value(&body.fields).map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: DataMappingRow = sqlx::query_as(
        "INSERT INTO data_mapping (name, target_entity, source_kind, fields, created_by) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING id, name, target_entity, source_kind, fields, created_by, created_at, updated_at",
    )
    .bind(body.name.trim())
    .bind(&target_entity)
    .bind(&body.source_kind)
    .bind(&fields_json)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    // `uq_core_data_mapping_name` (migration 0165): a second live mapping
    // with the same name is the caller's input clashing with existing
    // state — a 409 the CSV import wizard can explain (D-606), not a 500.
    .map_err(entity_mutation::classify_db_error)?;
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Configuration,
                entity_name: Some(target_entity),
                record_id: Some(row.id),
                operation: AuditOperation::Create,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("data_mapping_created".to_owned()),
                event_comment: Some(row.name.clone()),
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await?;

    Ok((StatusCode::CREATED, Json(row)))
}

/// List data mappings
///
/// List data mappings. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/mappings",
    tag = "admin",
    params(ListMappingsQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<DataMappingRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_mappings(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<ListMappingsQuery>,
) -> Result<Json<PaginatedResponse<DataMappingRow>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(
        query.page,
        query.page_size,
        PageBase::One,
        DEFAULT_PAGE_SIZE,
    );

    let items: Vec<DataMappingRow> = sqlx::query_as(
        "SELECT id, name, target_entity, source_kind, fields, created_by, created_at, updated_at \
           FROM data_mapping \
          WHERE is_deleted = false AND ($1::text IS NULL OR target_entity = $1) \
          ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&query.target_entity)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM data_mapping \
          WHERE is_deleted = false AND ($1::text IS NULL OR target_entity = $1)",
    )
    .bind(&query.target_entity)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// One data mapping
///
/// One data mapping. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/mappings/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The mapping")),
    responses(
        (status = 200, description = "Success", body = DataMappingRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_mapping(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<DataMappingRow>, AppError> {
    let row: Option<DataMappingRow> = sqlx::query_as(
        "SELECT id, name, target_entity, source_kind, fields, created_by, created_at, updated_at \
           FROM data_mapping WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(row.ok_or(AppError::NotFound)?))
}

/// Replace a data mapping
///
/// Replace a data mapping. Administrators only. Audited.
#[utoipa::path(
    put,
    path = "/api/v1/admin/data/mappings/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The mapping")),
    request_body = UpdateMappingBody,
    responses(
        (status = 200, description = "Success", body = DataMappingRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "A live mapping already has this name", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn update_mapping(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateMappingBody>,
) -> Result<Json<DataMappingRow>, AppError> {
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT target_entity FROM data_mapping WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (target_entity,) = existing.ok_or(AppError::NotFound)?;

    if let Some(source_kind) = &body.source_kind
        && !valid_source_kind(source_kind)
    {
        return Err(AppError::Validation(
            "source_kind must be csv, json, or connector".into(),
        ));
    }
    let fields_json = if let Some(fields) = &body.fields {
        let (_, _, attrs, _) = entity_crud::resolve_entity(&state, &target_entity).await?;
        validate_fields(&attrs, fields)?;
        Some(serde_json::to_value(fields).map_err(AppError::internal)?)
    } else {
        None
    };
    if let Some(name) = &body.name
        && name.trim().is_empty()
    {
        return Err(AppError::Validation("name must not be empty".into()));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: DataMappingRow = sqlx::query_as(
        "UPDATE data_mapping \
            SET name = COALESCE($2, name), \
                source_kind = COALESCE($3, source_kind), \
                fields = COALESCE($4, fields), \
                updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND is_deleted = false \
          RETURNING id, name, target_entity, source_kind, fields, created_by, created_at, updated_at",
    )
    .bind(id)
    .bind(body.name.as_deref().map(str::trim))
    .bind(&body.source_kind)
    .bind(&fields_json)
    .fetch_optional(&mut *tx)
    .await
    // A rename onto another live mapping's name — see `create_mapping`.
    .map_err(entity_mutation::classify_db_error)?
    .ok_or(AppError::NotFound)?;
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Configuration,
                entity_name: Some(row.target_entity.clone()),
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
                event_name: Some("data_mapping_updated".to_owned()),
                event_comment: None,
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await?;

    Ok(Json(row))
}

/// Delete a data mapping
///
/// Delete a data mapping. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/data/mappings/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The mapping")),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::SoftDelete)])))),
)]
async fn delete_mapping(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    // Soft delete only — a mapping already referenced by a past staged
    // import (`automation_staged_import.mapping_ref`) is historical
    // provenance and must stay resolvable.
    let target_entity: Option<String> = sqlx::query_scalar(
        "SELECT target_entity FROM data_mapping WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(target_entity) = target_entity else {
        return Err(AppError::NotFound);
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let result = sqlx::query(
        "UPDATE data_mapping SET is_deleted = true, updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND is_deleted = false",
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
                entity_name: Some(target_entity),
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
                event_name: Some("data_mapping_deleted".to_owned()),
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
        .route(
            "/api/v1/admin/data/mappings",
            post(create_mapping).get(list_mappings),
        )
        .route(
            "/api/v1/admin/data/mappings/{id}",
            get(get_mapping).put(update_mapping).delete(delete_mapping),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    create_mapping,
    list_mappings,
    get_mapping,
    update_mapping,
    delete_mapping
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
