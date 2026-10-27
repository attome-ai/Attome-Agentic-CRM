//! M17 (data migration, D-433) — `migration_project`/`migration_run`
//! admin CRUD, built on top of M12's shared mapping model
//! (`data_mapping`, `data_mapping_admin.rs`) and the existing
//! staged-import mechanism (`bulk.rs`).
//!
//! A "run" is always exactly one `automation_staged_import` row: this
//! module never re-implements validate/approve/apply — a caller still
//! submits through `POST /{entity}/staged-import` (with `mapping_ref`, and
//! `mode: "dry_run"` for a preview that can never be approved) and
//! `POST /{entity}/staged-import/{id}/approve`. `POST .../runs` only links
//! an already-created staged import to a migration project; run status and
//! counts are read live by joining the linked staged-import row rather than
//! duplicated here (a second, independently-updated copy of the same state
//! is exactly the drift this platform's engine layer avoids elsewhere).
//!
//! Rollback (this module's own job) reverts the create/update items
//! `bulk.rs::apply_staged_one` recorded into `migration_run_item` (only
//! when the staged import it applied was linked to a run) — see
//! `process_rollback`'s doc comment and D-433 for the concurrency contract.
//!
//! `system.admin` only, mounted with `strict_authz` in `system.rs` — same
//! posture as `data_mapping_admin`/`data_profile_admin`.

use std::collections::HashSet;

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSource,
};
use attome_core::{AttrInfo, EngineState, OnTargetDelete};
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, Privilege, area};
use attome_server::capability::{Available, BatchJobs};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, OnePageQuery, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use attome_records::entity_crud;
use attome_records::entity_mutation::{self, MutationMode};

fn valid_source_kind(s: &str) -> bool {
    matches!(s, "csv" | "json" | "connector")
}

fn valid_project_status(s: &str) -> bool {
    matches!(s, "draft" | "active" | "completed" | "archived")
}

// ── Project wire types ──────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct CreateProjectBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    source_kind: String,
    #[serde(default)]
    source_ref: Option<String>,
    target_entity: String,
    #[serde(default)]
    mapping_ref: Option<Uuid>,
    /// Defaults to the caller when omitted.
    #[serde(default)]
    owner: Option<Uuid>,
}

#[derive(Deserialize, ToSchema)]
struct UpdateProjectBody {
    name: Option<String>,
    description: Option<String>,
    status: Option<String>,
    mapping_ref: Option<Uuid>,
    owner: Option<Uuid>,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
struct MigrationProjectRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    source_kind: String,
    source_ref: Option<String>,
    target_entity: String,
    mapping_ref: Option<Uuid>,
    status: String,
    owner: Uuid,
    created_by: Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListProjectsQuery {
    /// Only mappings or projects into this entity (its logical name).
    target_entity: Option<String>,
    /// Only this status.
    status: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

const PROJECT_COLUMNS: &str = "id, name, description, source_kind, source_ref, target_entity, \
     mapping_ref, status, owner, created_by, created_at, updated_at";

async fn fetch_project(
    db: &attome_db::DbPool,
    id: Uuid,
) -> Result<Option<MigrationProjectRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {PROJECT_COLUMNS} FROM migration_project WHERE id = $1 AND is_deleted = false"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Validates an (optional) `mapping_ref` against `target_entity` — the same
/// check `data_mapping_admin::create_mapping` enforces the other direction.
async fn validate_mapping_ref(
    db: &attome_db::DbPool,
    mapping_ref: Option<Uuid>,
    target_entity: &str,
) -> Result<(), AppError> {
    let Some(mapping_id) = mapping_ref else {
        return Ok(());
    };
    let (mapping_target, _fields) = attome_records::data_mapping::load_mapping(db, mapping_id)
        .await?
        .ok_or_else(|| AppError::Validation("unknown mapping_ref".into()))?;
    if mapping_target != target_entity {
        return Err(AppError::Validation(format!(
            "mapping_ref targets entity '{mapping_target}', not this project's '{target_entity}'"
        )));
    }
    Ok(())
}

/// Create a migration project
///
/// Create a migration project. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/migration-projects",
    tag = "admin",
    request_body = CreateProjectBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = MigrationProjectRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_project(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Json(body): Json<CreateProjectBody>,
) -> Result<(StatusCode, Json<MigrationProjectRow>), AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    if !valid_source_kind(&body.source_kind) {
        return Err(AppError::Validation(
            "source_kind must be csv, json, or connector".into(),
        ));
    }
    let (_, target_entity, _attrs, _) =
        entity_crud::resolve_entity(&state, &body.target_entity).await?;
    validate_mapping_ref(&state.base.db, body.mapping_ref, &target_entity).await?;

    let id = Uuid::now_v7();
    let owner = body.owner.unwrap_or(ctx.user_id);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: MigrationProjectRow = sqlx::query_as(&format!(
        "INSERT INTO migration_project \
            (id, name, description, source_kind, source_ref, target_entity, mapping_ref, owner, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING {PROJECT_COLUMNS}"
    ))
    .bind(id)
    .bind(body.name.trim())
    .bind(&body.description)
    .bind(&body.source_kind)
    .bind(&body.source_ref)
    .bind(&target_entity)
    .bind(body.mapping_ref)
    .bind(owner)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(entity_mutation::classify_db_error)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            "migration_project",
            Some(id),
        )
        .named("migration_project.create"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok((StatusCode::CREATED, Json(row)))
}

/// List migration projects
///
/// List migration projects. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/migration-projects",
    tag = "admin",
    params(ListProjectsQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<MigrationProjectRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_projects(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Query(query): Query<ListProjectsQuery>,
) -> Result<Json<PaginatedResponse<MigrationProjectRow>>, AppError> {
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

    let items: Vec<MigrationProjectRow> = sqlx::query_as(&format!(
        "SELECT {PROJECT_COLUMNS} FROM migration_project \
          WHERE is_deleted = false \
            AND ($1::text IS NULL OR target_entity = $1) \
            AND ($2::text IS NULL OR status = $2) \
          ORDER BY created_at DESC LIMIT $3 OFFSET $4"
    ))
    .bind(&query.target_entity)
    .bind(&query.status)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM migration_project \
          WHERE is_deleted = false \
            AND ($1::text IS NULL OR target_entity = $1) \
            AND ($2::text IS NULL OR status = $2)",
    )
    .bind(&query.target_entity)
    .bind(&query.status)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// One migration project
///
/// One migration project. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/migration-projects/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The migration project")),
    responses(
        (status = 200, description = "Success", body = MigrationProjectRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_project(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path(id): Path<Uuid>,
) -> Result<Json<MigrationProjectRow>, AppError> {
    let row = fetch_project(&state.base.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

/// Replace a migration project
///
/// Replace a migration project. Administrators only. Audited.
#[utoipa::path(
    put,
    path = "/api/v1/admin/migration-projects/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The migration project")),
    request_body = UpdateProjectBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = MigrationProjectRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_project(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateProjectBody>,
) -> Result<Json<MigrationProjectRow>, AppError> {
    let existing = fetch_project(&state.base.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if let Some(name) = &body.name
        && name.trim().is_empty()
    {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    if let Some(status) = &body.status
        && !valid_project_status(status)
    {
        return Err(AppError::Validation(format!(
            "status must be draft, active, completed, or archived, got: {status}"
        )));
    }
    if let Some(mapping_ref) = body.mapping_ref {
        validate_mapping_ref(&state.base.db, Some(mapping_ref), &existing.target_entity).await?;
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: MigrationProjectRow = sqlx::query_as(&format!(
        "UPDATE migration_project \
            SET name = COALESCE($2, name), \
                description = COALESCE($3, description), \
                status = COALESCE($4, status), \
                mapping_ref = COALESCE($5, mapping_ref), \
                owner = COALESCE($6, owner), \
                updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND is_deleted = false \
          RETURNING {PROJECT_COLUMNS}"
    ))
    .bind(id)
    .bind(body.name.as_deref().map(str::trim))
    .bind(&body.description)
    .bind(&body.status)
    .bind(body.mapping_ref)
    .bind(body.owner)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "migration_project",
            Some(id),
        )
        .named("migration_project.update"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok(Json(row))
}

/// Delete a migration project
///
/// Delete a migration project. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/migration-projects/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The migration project")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_project(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let result = sqlx::query(
        "UPDATE migration_project SET is_deleted = true, updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND is_deleted = false",
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
            "migration_project",
            Some(id),
        )
        .named("migration_project.delete"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Run wire types ──────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct CreateRunBody {
    /// An `automation_staged_import` id already created via
    /// `POST /api/v1/{entity}/staged-import` (with this project's
    /// `mapping_ref`, and `mode: "dry_run"` for a preview run).
    staged_import_id: Uuid,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
struct MigrationRunListItem {
    id: Uuid,
    project_id: Uuid,
    staged_import_id: Uuid,
    entity_logicalname: String,
    operation: String,
    mode: String,
    import_status: String,
    total: i32,
    rejected: i32,
    rollback_status: String,
    created_by: Uuid,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct MigrationRunDetailRow {
    id: Uuid,
    project_id: Uuid,
    staged_import_id: Uuid,
    entity_logicalname: String,
    operation: String,
    mode: String,
    import_status: String,
    total: i32,
    rejected: i32,
    validation_report: Value,
    rollback_status: String,
    rollback_error: Option<String>,
    rolled_back_by: Option<Uuid>,
    rolled_back_at: Option<DateTime<Utc>>,
    created_by: Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
struct RollbackItemSummary {
    item_index: i32,
    record_id: Uuid,
    operation: String,
    rollback_status: String,
    rollback_error: Option<String>,
}

/// One run's full detail: the linked staged import's live status/counts
/// (D-433's "read live, never duplicated" rule) plus its
/// `migration_run_item` rollback ledger — this doubles as the "bundle
/// diff"-style surface the master plan calls for on the record side: the
/// same `validation_report` a caller already saw from `staged_import`'s own
/// response, still inspectable after the fact.
#[derive(Serialize, ToSchema)]
struct MigrationRunDetail {
    id: Uuid,
    project_id: Uuid,
    staged_import_id: Uuid,
    entity_logicalname: String,
    operation: String,
    mode: String,
    import_status: String,
    total: i32,
    rejected: i32,
    #[schema(value_type = Object)]
    validation_report: Value,
    rollback_status: String,
    rollback_error: Option<String>,
    rolled_back_by: Option<Uuid>,
    rolled_back_at: Option<DateTime<Utc>>,
    rollback_items: Vec<RollbackItemSummary>,
    created_by: Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<MigrationRunDetailRow> for MigrationRunListItem {
    fn from(r: MigrationRunDetailRow) -> Self {
        MigrationRunListItem {
            id: r.id,
            project_id: r.project_id,
            staged_import_id: r.staged_import_id,
            entity_logicalname: r.entity_logicalname,
            operation: r.operation,
            mode: r.mode,
            import_status: r.import_status,
            total: r.total,
            rejected: r.rejected,
            rollback_status: r.rollback_status,
            created_by: r.created_by,
            created_at: r.created_at,
        }
    }
}

const RUN_DETAIL_QUERY: &str = "SELECT r.id, r.project_id, r.staged_import_id, \
         si.entity_logicalname, si.operation, si.mode, si.status AS import_status, \
         jsonb_array_length(si.raw_records) AS total, si.rejected, si.validation_report, \
         r.rollback_status, r.rollback_error, r.rolled_back_by, r.rolled_back_at, \
         r.created_by, r.created_at, r.updated_at \
     FROM migration_run r \
     JOIN automation_staged_import si ON si.id = r.staged_import_id \
     WHERE r.project_id = $1 AND r.is_deleted = false";

async fn fetch_run_detail(
    db: &attome_db::DbPool,
    project_id: Uuid,
    run_id: Uuid,
) -> Result<Option<MigrationRunDetail>, AppError> {
    let head: Option<MigrationRunDetailRow> =
        sqlx::query_as(&format!("{RUN_DETAIL_QUERY} AND r.id = $2"))
            .bind(project_id)
            .bind(run_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let Some(head) = head else {
        return Ok(None);
    };
    let items: Vec<RollbackItemSummary> = sqlx::query_as(
        "SELECT item_index, record_id, operation, rollback_status, rollback_error \
         FROM migration_run_item WHERE migration_run_id = $1 ORDER BY item_index",
    )
    .bind(run_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(Some(MigrationRunDetail {
        id: head.id,
        project_id: head.project_id,
        staged_import_id: head.staged_import_id,
        entity_logicalname: head.entity_logicalname,
        operation: head.operation,
        mode: head.mode,
        import_status: head.import_status,
        total: head.total,
        rejected: head.rejected,
        validation_report: head.validation_report,
        rollback_status: head.rollback_status,
        rollback_error: head.rollback_error,
        rolled_back_by: head.rolled_back_by,
        rolled_back_at: head.rolled_back_at,
        rollback_items: items,
        created_by: head.created_by,
        created_at: head.created_at,
        updated_at: head.updated_at,
    }))
}

/// Start a migration run
///
/// Start a migration run. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/migration-projects/{project_id}/runs",
    tag = "admin",
    params(("project_id" = Uuid, Path, description = "The migration project")),
    request_body = CreateRunBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = MigrationRunDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Project or staged import not found", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_run(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(project_id): Path<Uuid>,
    Json(body): Json<CreateRunBody>,
) -> Result<(StatusCode, Json<MigrationRunDetail>), AppError> {
    let project = fetch_project(&state.base.db, project_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let staged_import_entity: Option<String> = sqlx::query_scalar(
        "SELECT entity_logicalname FROM automation_staged_import \
         WHERE id = $1 AND is_deleted = false",
    )
    .bind(body.staged_import_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let staged_import_entity = staged_import_entity
        .ok_or_else(|| AppError::Validation("unknown staged_import_id".into()))?;
    if staged_import_entity != project.target_entity {
        return Err(AppError::Validation(format!(
            "staged import targets entity '{staged_import_entity}', not this project's \
             '{}'",
            project.target_entity
        )));
    }

    let run_id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO migration_run (id, project_id, staged_import_id, created_by) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(run_id)
    .bind(project_id)
    .bind(body.staged_import_id)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(entity_mutation::classify_db_error)?;
    sqlx::query(
        "UPDATE automation_staged_import SET migration_run_id = $2 \
         WHERE id = $1 AND migration_run_id IS NULL",
    )
    .bind(body.staged_import_id)
    .bind(run_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::business::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::business::BusinessEvent::new(
            "migration_run",
            run_id,
            attome_audit::AuditOperation::Create,
            "migration_run.create",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;

    let detail = fetch_run_detail(&state.base.db, project_id, run_id)
        .await?
        .ok_or_else(|| AppError::internal("migration run vanished immediately after insert"))?;
    Ok((StatusCode::CREATED, Json(detail)))
}

/// A migration project's runs
///
/// A migration project's runs. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/migration-projects/{project_id}/runs",
    tag = "admin",
    params(("project_id" = Uuid, Path, description = "The migration project"), OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<MigrationRunListItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_runs(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path(project_id): Path<Uuid>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<MigrationRunListItem>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = query.window();

    let items: Vec<MigrationRunDetailRow> = sqlx::query_as(&format!(
        "{RUN_DETAIL_QUERY} ORDER BY r.created_at DESC LIMIT $2 OFFSET $3"
    ))
    .bind(project_id)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM migration_run WHERE project_id = $1 AND is_deleted = false",
    )
    .bind(project_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = items.into_iter().map(MigrationRunListItem::from).collect();
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// One migration run
///
/// One migration run. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/migration-projects/{project_id}/runs/{run_id}",
    tag = "admin",
    params(("project_id" = Uuid, Path, description = "The migration project"), ("run_id" = Uuid, Path, description = "The run")),
    responses(
        (status = 200, description = "Success", body = MigrationRunDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_run(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path((project_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<MigrationRunDetail>, AppError> {
    let detail = fetch_run_detail(&state.base.db, project_id, run_id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(detail))
}

/// A migration run's errors
///
/// `GET .../runs/{run_id}/errors` — a downloadable CSV of every non-passing
/// row in the linked staged import's `validation_report` (both the
/// pre-approval `passed`/`failed`/`rejected` vocabulary and the
/// post-approval `succeeded`/`failed`/`rejected` one — see this module's
/// doc comment on why the two differ). Regenerated on demand from data
/// already retained in the database rather than a separately stored file:
/// staged imports are capped at `bulk::MAX_BULK_RECORDS` (500) records, so
/// there is nothing here that benefits from a durable export artifact.
#[utoipa::path(
    get,
    path = "/api/v1/admin/migration-projects/{project_id}/runs/{run_id}/errors",
    tag = "admin",
    params(("project_id" = Uuid, Path, description = "The migration project"), ("run_id" = Uuid, Path, description = "The run")),
    responses(
        (status = 200, description = "CSV of non-passing rows", body = String),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn download_run_errors(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path((project_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, AppError> {
    let row: Option<(Value,)> = sqlx::query_as(
        "SELECT si.validation_report FROM migration_run r \
         JOIN automation_staged_import si ON si.id = r.staged_import_id \
         WHERE r.id = $1 AND r.project_id = $2 AND r.is_deleted = false",
    )
    .bind(run_id)
    .bind(project_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (report,) = row.ok_or(AppError::NotFound)?;

    let mut csv = String::from("index,status,error\n");
    if let Some(items) = report.as_array() {
        for item in items {
            let status = item.get("status").and_then(Value::as_str).unwrap_or("");
            if matches!(status, "passed" | "succeeded") {
                continue;
            }
            let index = item
                .get("index")
                .map(ToString::to_string)
                .unwrap_or_default();
            let error = item
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("")
                .replace('"', "\"\"");
            csv.push_str(&format!("{index},{status},\"{error}\"\n"));
        }
    }

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"migration-run-errors.csv\"",
            ),
        ],
        csv,
    )
        .into_response())
}

/// Roll back a migration run
///
/// Roll back a migration run. Administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/migration-projects/{project_id}/runs/{run_id}/rollback",
    tag = "admin",
    params(("project_id" = Uuid, Path, description = "The migration project"), ("run_id" = Uuid, Path, description = "The run")),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("EngineJob::RollbackMigrationRun (rollback_one_item -> entity_mutation::update_one/delete_one)"), "the route only flips rollback_status to requested and enqueues the job; each reverted record's audit event is written by the generic entity_mutation path the job calls per item (D-062)")))),
    responses(
        (status = 202, description = "Rollback enqueued", body = MigrationRunDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "Rollback already requested or completed", body = ErrorResponse),
        (status = 422, description = "Run is not yet approved", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn rollback_run(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    // Same "durable job, not a request-thread loop" contract as
    // `approve_staged_import` — see `bulk.rs`.
    _jobs: Available<BatchJobs>,
    Path((project_id, run_id)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, Json<MigrationRunDetail>), AppError> {
    let staged_import_status: Option<String> = sqlx::query_scalar(
        "SELECT si.status FROM migration_run r \
         JOIN automation_staged_import si ON si.id = r.staged_import_id \
         WHERE r.id = $1 AND r.project_id = $2 AND r.is_deleted = false",
    )
    .bind(run_id)
    .bind(project_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let staged_import_status = staged_import_status.ok_or(AppError::NotFound)?;
    if staged_import_status != "approved" {
        return Err(AppError::Validation(format!(
            "run's staged import must be approved before it can be rolled back (status: {staged_import_status})"
        )));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let claimed = sqlx::query(
        "UPDATE migration_run \
         SET rollback_status = 'requested', rolled_back_by = $2, updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND rollback_status IN ('none', 'failed')",
    )
    .bind(run_id)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if claimed.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "rollback already requested or completed for this run",
        ));
    }
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::RollbackMigrationRun {
            run_id,
            user_id: ctx.user_id,
        },
    )
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;

    let detail = fetch_run_detail(&state.base.db, project_id, run_id)
        .await?
        .ok_or_else(|| {
            AppError::internal("migration run vanished immediately after rollback request")
        })?;
    Ok((StatusCode::ACCEPTED, Json(detail)))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/migration-projects",
            post(create_project).get(list_projects),
        )
        .route(
            "/api/v1/admin/migration-projects/{id}",
            get(get_project).put(update_project).delete(delete_project),
        )
        .route(
            "/api/v1/admin/migration-projects/{project_id}/runs",
            post(create_run).get(list_runs),
        )
        .route(
            "/api/v1/admin/migration-projects/{project_id}/runs/{run_id}",
            get(get_run),
        )
        .route(
            "/api/v1/admin/migration-projects/{project_id}/runs/{run_id}/errors",
            get(download_run_errors),
        )
        .route(
            "/api/v1/admin/migration-projects/{project_id}/runs/{run_id}/rollback",
            post(rollback_run),
        )
        // A24-T3: the project's model mapping.
        .merge(crate::migration_model::routes())
        // A24-T4: the project's waves.
        .merge(crate::migration_run::routes())
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    create_project,
    list_projects,
    get_project,
    update_project,
    delete_project,
    create_run,
    list_runs,
    get_run,
    download_run_errors,
    rollback_run
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    let mut doc = <ApiDocFragment as utoipa::OpenApi>::openapi();
    doc.merge(crate::migration_model::openapi_fragment());
    doc.merge(crate::migration_run::openapi_fragment());
    doc
}

// ── Rollback job ─────────────────────────────────────────────────────────────

async fn mark_run_rollback_failed(
    state: &EngineState,
    run_id: Uuid,
    message: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE migration_run \
         SET rollback_status = 'failed', rollback_error = $2, updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(run_id)
    .bind(message)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn mark_item_refused(
    state: &EngineState,
    item_id: Uuid,
    reason: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE migration_run_item \
         SET rollback_status = 'refused', rollback_error = $2, updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND rollback_status <> 'rolled_back'",
    )
    .bind(item_id)
    .bind(reason)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Reverts one `migration_run_item`: for a tracked `create`, soft-deletes
/// the record it created; for a tracked `update`, restores `prior_data`'s
/// fields. Both go through `entity_mutation::delete_one`/`update_one` with
/// `expected_row_version = applied_row_version` — the SAME optimistic-
/// concurrency check every other write on this platform uses, so "a later
/// edit exists on this record" is detected by that primitive returning
/// `AppError::VersionConflict` (or `NotFound`, if the record is gone or
/// already inactive), not by a second, bespoke comparison. Mirrors
/// `bulk.rs::apply_staged_one`'s claim-then-mutate-then-finalize shape:
/// FOR UPDATE-claims the ledger row first so a redelivered job attempt can
/// never double-process an item, then does the mutation, audit event, and
/// ledger finalize in the SAME transaction.
#[allow(clippy::too_many_arguments)]
async fn rollback_one_item(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    attrs: &[AttrInfo],
    known_attrs: &HashSet<&str>,
    dependents: &[(String, String, OnTargetDelete)],
    item_id: Uuid,
    record_id: Uuid,
    operation: &str,
    applied_row_version: i64,
    prior_data: Option<&Value>,
    user_id: Uuid,
) -> Result<(), AppError> {
    // Reverting a create is a delete; reverting an update is an update — the
    // same independent-depth reasoning `bulk.rs::apply_one` documents for
    // its own `action` selection.
    let action = if operation == "create" {
        RecordAction::Delete
    } else {
        RecordAction::Update
    };
    entity_crud::require_record_access(state, ctx, entity_id, entity_name, record_id, action)
        .await?;

    // M01 Core C-12: resolved here, on the pool, before the transaction below
    // opens — see `entity_crud::resolve_cascade_dependent_access`'s doc
    // comment. Only the "create" (revert-as-delete) branch below consults
    // this.
    let cascade_access = if operation == "create" {
        Some(entity_crud::resolve_cascade_dependent_access(state, ctx, dependents).await?)
    } else {
        None
    };

    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(state, user_id).await;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let claimed: Option<String> = sqlx::query_scalar(
        "SELECT rollback_status FROM migration_run_item WHERE id = $1 FOR UPDATE",
    )
    .bind(item_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(status) = claimed else {
        return Err(AppError::Internal(
            "migration run item ledger row is missing".into(),
        ));
    };
    if status != "pending" {
        // Already handled by this or an earlier attempt — nothing to do.
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(());
    }
    sqlx::query(
        "UPDATE migration_run_item \
         SET rollback_status = 'running', claimed_at = NOW(), updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(item_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let mutation = if operation == "create" {
        entity_crud::guard_cascade_dependent_access(
            &mut tx,
            state,
            ctx,
            dependents,
            record_id,
            cascade_access.as_deref().unwrap_or(&[]),
        )
        .await?;
        entity_mutation::delete_one(
            &mut tx,
            entity_name,
            dependents,
            record_id,
            user_id,
            Some(applied_row_version),
            &entity_mutation::DeleteOrigin::with_id(
                entity_mutation::DeleteKind::Migration,
                item_id.to_string(),
            ),
        )
        .await?
    } else {
        let prior_obj = prior_data.and_then(Value::as_object).ok_or_else(|| {
            AppError::internal("migration run item missing prior_data for update rollback")
        })?;
        let mut obj = serde_json::Map::new();
        for (k, v) in prior_obj {
            if known_attrs.contains(k.as_str()) {
                obj.insert(k.clone(), v.clone());
            }
        }
        entity_mutation::update_one(
            &mut tx,
            state,
            ctx,
            entity_name,
            entity_id,
            record_id,
            attrs,
            &obj,
            user_id,
            applied_row_version,
            MutationMode::ApprovedStagedImport,
        )
        .await?
    };

    let audit_operation = if operation == "create" {
        AuditOperation::SoftDelete
    } else {
        AuditOperation::Update
    };
    let changed_fields = if operation == "create" {
        Vec::new()
    } else {
        let obj_for_diff = mutation
            .new_row
            .as_ref()
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        entity_crud::field_changes_from_obj(
            &mut tx,
            state,
            attrs,
            &obj_for_diff,
            mutation.old_row.as_ref(),
        )
        .await
    };
    let event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.to_owned()),
        record_id: Some(mutation.record_id),
        operation: audit_operation,
        version_before: Some(applied_row_version),
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: None,
        event_comment: Some("migration rollback".into()),
        changed_fields,
        snapshot_json: None,
    };
    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());
    audit_service.write_in_tx(&mut tx, event).await?;

    sqlx::query(
        "UPDATE migration_run_item \
         SET rollback_status = 'rolled_back', rollback_error = NULL, updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(item_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// Worker entry for `EngineJob::RollbackMigrationRun` — reverts every
/// still-`pending` `migration_run_item` row for `run_id`. Crash/
/// redelivery-safe: each item claims and finalizes in its own transaction
/// (`rollback_one_item`), so a retried job attempt only re-processes items
/// that never actually committed. D-433: an item whose record has a later
/// edit is *refused*, not skipped or forced — it stays visible on the run's
/// `migration_run_item` ledger with `rollback_status = 'refused'` and
/// the conflict reason, and the run's own `rollback_status` lands on
/// `'refused'` (not `'completed'`) whenever at least one item was.
pub async fn process_rollback(
    state: &EngineState,
    run_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT si.entity_logicalname FROM migration_run r \
         JOIN automation_staged_import si ON si.id = r.staged_import_id \
         WHERE r.id = $1 AND r.is_deleted = false",
    )
    .bind(run_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((entity_logicalname,)) = row else {
        // Soft-delete only — a vanished run means nothing to roll back.
        return Ok(());
    };

    let (entity_id, entity_name, attrs, _is_append_only) =
        match entity_crud::resolve_entity(state, &entity_logicalname).await {
            Ok(value) => value,
            Err(error) => {
                mark_run_rollback_failed(
                    state,
                    run_id,
                    &format!("entity resolution failed: {error}"),
                )
                .await?;
                return Ok(());
            }
        };

    // Same fail-closed re-authorization every worker in this crate applies:
    // a grant revoked between the rollback request and this job running must
    // not apply.
    let security = attome_security::resolve_uncached(&state.base.db, user_id).await?;
    if security.require(&entity_name, "update").is_err()
        && security.require(&entity_name, "delete").is_err()
    {
        mark_run_rollback_failed(
            state,
            run_id,
            "rollback authorization was revoked before processing",
        )
        .await?;
        return Ok(());
    }

    sqlx::query(
        "UPDATE migration_run SET rollback_status = 'running', updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND rollback_status IN ('requested', 'running', 'failed')",
    )
    .bind(run_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let known_attrs: HashSet<&str> = attrs.iter().map(|a| a.logicalname.as_str()).collect();
    let dependents = state.entities.load().dependents_of(entity_id);

    let pending: Vec<(Uuid, Uuid, String, i64, Option<Value>)> = sqlx::query_as(
        "SELECT id, record_id, operation, applied_row_version, prior_data \
         FROM migration_run_item \
         WHERE migration_run_id = $1 AND rollback_status = 'pending' \
         ORDER BY item_index",
    )
    .bind(run_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    for (item_id, record_id, operation, applied_row_version, prior_data) in pending {
        if let Err(error) = rollback_one_item(
            state,
            &security,
            entity_id,
            &entity_name,
            &attrs,
            &known_attrs,
            &dependents,
            item_id,
            record_id,
            &operation,
            applied_row_version,
            prior_data.as_ref(),
            user_id,
        )
        .await
        {
            if matches!(&error, AppError::Internal(_)) {
                // Leave this item `pending` and let Apalis retry the whole
                // job — a transient database failure must not be recorded
                // as a permanent refusal.
                return Err(error);
            }
            mark_item_refused(state, item_id, &error.to_string()).await?;
        }
    }

    let (refused, unfinished): (i64, i64) = sqlx::query_as(
        "SELECT \
             COUNT(*) FILTER (WHERE rollback_status = 'refused'), \
             COUNT(*) FILTER (WHERE rollback_status IN ('pending', 'running')) \
         FROM migration_run_item WHERE migration_run_id = $1",
    )
    .bind(run_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let final_status = if unfinished > 0 {
        // Should not normally happen — every pending item above was just
        // processed synchronously — but guards a partial crash-resume that
        // still leaves something unfinished after a retry budget is spent.
        "failed"
    } else if refused > 0 {
        "refused"
    } else {
        "completed"
    };
    sqlx::query(
        "UPDATE migration_run \
         SET rollback_status = $2, rolled_back_at = NOW(), updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(run_id)
    .bind(final_status)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}
