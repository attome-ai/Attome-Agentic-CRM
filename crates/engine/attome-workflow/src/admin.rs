//! Workflow definition/version admin CRUD — /api/v1/workflow/definitions.
//!
//! Mounted through `WorkflowModel::routes()` (`engine.rs`), so every
//! route here is already license-gated by `ModelRegistry` before this
//! module ever sees a request (D-010) — handlers below only need to check
//! `require_admin()`, the same posture `s2s_admin.rs`/`NotificationModel`
//! use for their own admin surfaces.
//!
//! Solution 7 Phase 1 (D-785, design §1.1): every write here is recorded as
//! one changeset operation as the last statement before commit, target
//! `{ workflow: <logicalname> }` (the definition's immutable, unique logical
//! key): `upsert_workflow` (definition create/update), `retire_workflow`
//! (delete), `set_workflow_draft` (version create / graph edit) and
//! `publish_workflow` (publish). Versions carry no `owner_layer` of their
//! own: they inherit the definition's, so every version route checks the
//! definition's layer. A new definition is stamped with the recording
//! changeset's layer; any other write is refused with 409 `layer_mismatch`
//! unless the definition's `owner_layer` is that layer.
use attome_core::EngineState;
use attome_core::changeset::{Layer, Op, RecordedOp, RecordingCtx};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, DEFAULT_PAGE_SIZE, PageBase, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::model::{
    CreateDefinitionBody, CreateVersionBody, DefinitionDetail, DefinitionListItem,
    UpdateDefinitionBody, UpdateVersionGraphBody, VersionDetail, VersionSummary,
};
use crate::node_types::NodeType;
use attome_types::ErrorResponse;
use utoipa::IntoParams;

// ── Validation helpers ──────────────────────────────────────────────────────

fn valid_logicalname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

// ── Changeset recording (D-785) ─────────────────────────────────────────────

/// A stored `owner_layer`, parsed. The column's CHECK admits only the four
/// layers, so an unknown value is a defect, not client input.
fn parse_owner_layer(value: &str) -> Result<Layer, AppError> {
    Layer::parse(value).ok_or_else(|| AppError::internal(format!("unknown owner_layer {value:?}")))
}

/// A definition row as the changeset snapshot, enumerated columns.
#[derive(sqlx::FromRow, serde::Serialize)]
struct DefinitionSnapshot {
    id: Uuid,
    logicalname: String,
    name: String,
    is_active: bool,
    is_deleted: bool,
    row_version: i64,
    owner_layer: String,
}

/// A version row as the changeset snapshot, enumerated columns.
#[derive(sqlx::FromRow, serde::Serialize)]
struct VersionSnapshot {
    id: Uuid,
    definition_id: Uuid,
    version_number: i32,
    graph: serde_json::Value,
    status: String,
    published_at: Option<chrono::DateTime<Utc>>,
    row_version: i64,
}

fn definition_op(op: Op, row: &DefinitionSnapshot) -> Result<RecordedOp, AppError> {
    Ok(RecordedOp {
        op,
        object_kind: "workflow",
        object_ref: Some(row.id),
        target: serde_json::json!({ "workflow": row.logicalname }),
        snapshot: serde_json::to_value(row).map_err(AppError::internal)?,
        changed: Vec::new(),
    })
}

/// `set_workflow_draft` / `publish_workflow`: the target is the owning
/// definition; the snapshot is the version row just written.
fn version_op(op: Op, logicalname: &str, row: &VersionSnapshot) -> Result<RecordedOp, AppError> {
    Ok(RecordedOp {
        op,
        object_kind: "workflow_version",
        object_ref: Some(row.id),
        target: serde_json::json!({ "workflow": logicalname }),
        snapshot: serde_json::to_value(row).map_err(AppError::internal)?,
        changed: Vec::new(),
    })
}

/// The definition row inside the write's transaction (live or just
/// soft-deleted).
async fn fetch_definition_in_tx(
    tx: &mut attome_db::Tx<'_>,
    id: Uuid,
) -> Result<DefinitionSnapshot, AppError> {
    sqlx::query_as(
        "SELECT id, logicalname, name, is_active, is_deleted, row_version, owner_layer \
         FROM workflow_definition WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// The version row inside the write's transaction.
async fn fetch_version_in_tx(
    tx: &mut attome_db::Tx<'_>,
    version_id: Uuid,
) -> Result<VersionSnapshot, AppError> {
    sqlx::query_as(
        "SELECT id, definition_id, version_number, graph, status, published_at, row_version \
         FROM workflow_definition_version WHERE id = $1",
    )
    .bind(version_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// A definition's `(logicalname, owner_layer)`, live rows only when
/// `live_only`; `None` when there is no such row.
async fn definition_owner(
    tx: &mut attome_db::Tx<'_>,
    id: Uuid,
    live_only: bool,
) -> Result<Option<(String, String)>, AppError> {
    sqlx::query_as(
        "SELECT logicalname, owner_layer FROM workflow_definition \
         WHERE id = $1 AND (NOT $2 OR is_deleted = FALSE)",
    )
    .bind(id)
    .bind(live_only)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)
}

// ── Query types ──────────────────────────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct DefinitionListQuery {
    /// Only active (true) or inactive (false) ones.
    is_active: Option<bool>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

// ── Handlers: Definitions ────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/workflow/definitions",
    tag = "workflow",
    params(DefinitionListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<DefinitionListItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_definitions(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<DefinitionListQuery>,
) -> Result<Json<PaginatedResponse<DefinitionListItem>>, AppError> {
    let window = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM workflow_definition
        WHERE is_deleted = FALSE AND ($1::bool IS NULL OR is_active = $1)
        "#,
    )
    .bind(q.is_active)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let rows = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            bool,
            Option<i32>,
            chrono::DateTime<Utc>,
            String,
        ),
    >(
        r#"
        SELECT d.id, d.logicalname, d.name, d.is_active,
               (SELECT v.version_number FROM workflow_definition_version v
                WHERE v.definition_id = d.id AND v.status = 'published'
                ORDER BY v.version_number DESC LIMIT 1),
               d.created_at, d.owner_layer
        FROM workflow_definition d
        WHERE d.is_deleted = FALSE AND ($1::bool IS NULL OR d.is_active = $1)
        ORDER BY d.created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(q.is_active)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(
            |(id, logicalname, name, is_active, published_version, created_at, owner_layer)| {
                DefinitionListItem {
                    id,
                    logicalname,
                    name,
                    is_active,
                    published_version,
                    created_at,
                    owner_layer,
                }
            },
        )
        .collect();

    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/workflow/definitions",
    tag = "workflow",
    request_body = CreateDefinitionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = DefinitionDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "A workflow with this logicalname already exists, or no open changeset to record into", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_definition(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Json(body): Json<CreateDefinitionBody>,
) -> Result<(StatusCode, Json<DefinitionDetail>), AppError> {
    let logicalname = body.logicalname.trim().to_lowercase();
    if !valid_logicalname(&logicalname) {
        return Err(AppError::Validation(
            "logicalname must be lowercase letters, digits, hyphens, or underscores (max 100 chars)"
                .into(),
        ));
    }
    let name = body.name.trim().to_owned();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let locked: bool =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-workflow/create-definition:{logicalname}"))
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;

    if !locked {
        return Err(AppError::Conflict(
            "another request is creating a workflow with this logicalname",
        ));
    }

    let now = Utc::now();
    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO workflow_definition
            (logicalname, name, created_by, created_at, updated_at, owner_layer)
        VALUES ($1, $2, $3, $4, $4, $5)
        RETURNING id
        "#,
    )
    .bind(&logicalname)
    .bind(&name)
    .bind(ctx.user_id)
    .bind(now)
    .bind(layer.as_str())
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
            AppError::Conflict("a workflow with this logicalname already exists")
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
            "workflow_definition",
            Some(id),
        )
        .named("workflow_definition.create"),
    )
    .await?;
    let snapshot = fetch_definition_in_tx(&mut tx, id).await?;
    recording
        .record(&mut tx, definition_op(Op::UpsertWorkflow, &snapshot)?)
        .await?;

    tx.commit().await.map_err(AppError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(DefinitionDetail {
            id,
            logicalname,
            name,
            is_active: true,
            row_version: 0,
            created_at: now,
            updated_at: now,
            owner_layer: snapshot.owner_layer,
            versions: vec![],
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/workflow/definitions/{id}",
    tag = "workflow",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = DefinitionDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_definition(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(definition_id): Path<Uuid>,
) -> Result<Json<DefinitionDetail>, AppError> {
    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            bool,
            i64,
            chrono::DateTime<Utc>,
            chrono::DateTime<Utc>,
            String,
        ),
    >(
        r#"
        SELECT id, logicalname, name, is_active, row_version, created_at, updated_at, owner_layer
        FROM workflow_definition
        WHERE id = $1 AND is_deleted = FALSE
        "#,
    )
    .bind(definition_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;

    let versions = fetch_versions(&state.base.db, definition_id).await?;

    Ok(Json(DefinitionDetail {
        id: row.0,
        logicalname: row.1,
        name: row.2,
        is_active: row.3,
        row_version: row.4,
        created_at: row.5,
        updated_at: row.6,
        owner_layer: row.7,
        versions,
    }))
}

#[utoipa::path(
    patch,
    path = "/api/v1/workflow/definitions/{id}",
    tag = "workflow",
    params(("id" = Uuid, Path)),
    request_body = UpdateDefinitionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = DefinitionDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "row_version mismatch, no open changeset to record into, or the workflow is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_definition(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(definition_id): Path<Uuid>,
    Json(body): Json<UpdateDefinitionBody>,
) -> Result<Json<DefinitionDetail>, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let cur = sqlx::query_as::<_, (String, bool, i64, String)>(
        r#"
        SELECT name, is_active, row_version, owner_layer
        FROM workflow_definition
        WHERE id = $1 AND is_deleted = FALSE
        "#,
    )
    .bind(definition_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    recording.check_owner(parse_owner_layer(&cur.3)?)?;

    let new_name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or(cur.0);
    let new_active = body.is_active.unwrap_or(cur.1);

    let rows = sqlx::query(
        r#"
        UPDATE workflow_definition
        SET name       = $2,
            is_active  = $3,
            updated_at = NOW(),
            row_version = row_version + 1
        WHERE id = $1 AND row_version = $4 AND is_deleted = FALSE
        "#,
    )
    .bind(definition_id)
    .bind(&new_name)
    .bind(new_active)
    .bind(body.row_version)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::VersionConflict);
    }

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "workflow_definition",
            Some(definition_id),
        )
        .named("workflow_definition.update"),
    )
    .await?;
    let snapshot = fetch_definition_in_tx(&mut tx, definition_id).await?;
    recording
        .record(&mut tx, definition_op(Op::UpsertWorkflow, &snapshot)?)
        .await?;

    tx.commit().await.map_err(AppError::internal)?;

    get_definition(State(state), ctx, Path(definition_id)).await
}

#[utoipa::path(
    delete,
    path = "/api/v1/workflow/definitions/{id}",
    tag = "workflow",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 200, description = "Success", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or the workflow is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_definition(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(definition_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (_, owner_layer) = definition_owner(&mut tx, definition_id, true)
        .await?
        .ok_or(AppError::NotFound)?;
    recording.check_owner(parse_owner_layer(&owner_layer)?)?;
    let n = sqlx::query(
        "UPDATE workflow_definition SET is_deleted = TRUE, is_active = FALSE, updated_at = NOW()
         WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(definition_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if n == 0 {
        return Err(AppError::NotFound);
    }

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::SoftDelete,
            ctx.user_id,
            "workflow_definition",
            Some(definition_id),
        )
        .named("workflow_definition.delete"),
    )
    .await?;
    let snapshot = fetch_definition_in_tx(&mut tx, definition_id).await?;
    recording
        .record(&mut tx, definition_op(Op::RetireWorkflow, &snapshot)?)
        .await?;

    tx.commit().await.map_err(AppError::internal)?;

    Ok(Json(
        serde_json::json!({ "id": definition_id, "deleted": true }),
    ))
}

// ── Handlers: Versions ───────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/api/v1/workflow/definitions/{id}/versions",
    tag = "workflow",
    params(("id" = Uuid, Path)),
    request_body = CreateVersionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = VersionDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "Another version is being created, no open changeset to record into, or the workflow is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_version(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(definition_id): Path<Uuid>,
    Json(body): Json<CreateVersionBody>,
) -> Result<(StatusCode, Json<VersionDetail>), AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let locked: bool =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-workflow/create-version:{definition_id}"))
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;

    if !locked {
        return Err(AppError::Conflict(
            "another request is creating a version for this workflow",
        ));
    }

    let (logicalname, owner_layer) = definition_owner(&mut tx, definition_id, true)
        .await?
        .ok_or(AppError::NotFound)?;
    recording.check_owner(parse_owner_layer(&owner_layer)?)?;

    let next_version: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version_number), 0) + 1 FROM workflow_definition_version WHERE definition_id = $1",
    )
    .bind(definition_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let graph = body
        .graph
        .unwrap_or_else(|| serde_json::json!({"nodes": [], "edges": []}));
    let now = Utc::now();

    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO workflow_definition_version
            (definition_id, version_number, graph, status, created_at)
        VALUES ($1, $2, $3, 'draft', $4)
        RETURNING id
        "#,
    )
    .bind(definition_id)
    .bind(next_version)
    .bind(&graph)
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            "workflow_definition_version",
            Some(id),
        )
        .named("workflow_version.create"),
    )
    .await?;
    let snapshot = fetch_version_in_tx(&mut tx, id).await?;
    recording
        .record(
            &mut tx,
            version_op(Op::SetWorkflowDraft, &logicalname, &snapshot)?,
        )
        .await?;

    tx.commit().await.map_err(AppError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(VersionDetail {
            id,
            definition_id,
            version_number: next_version,
            graph,
            status: "draft".into(),
            published_at: None,
            row_version: 0,
            created_at: now,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/workflow/definitions/{id}/versions/{version_id}",
    tag = "workflow",
    params(
        ("id" = Uuid, Path),
        ("version_id" = Uuid, Path),
    ),
    responses(
        (status = 200, description = "Success", body = VersionDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_version(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path((definition_id, version_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<VersionDetail>, AppError> {
    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            i32,
            serde_json::Value,
            String,
            Option<chrono::DateTime<Utc>>,
            i64,
            chrono::DateTime<Utc>,
        ),
    >(
        r#"
        SELECT id, version_number, graph, status, published_at, row_version, created_at
        FROM workflow_definition_version
        WHERE id = $1 AND definition_id = $2
        "#,
    )
    .bind(version_id)
    .bind(definition_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;

    Ok(Json(VersionDetail {
        id: row.0,
        definition_id,
        version_number: row.1,
        graph: row.2,
        status: row.3,
        published_at: row.4,
        row_version: row.5,
        created_at: row.6,
    }))
}

/// Draft-only graph edit — the `row_version` CAS this plan's design review
/// settled on for concurrent editor sessions (P-workflow-engine.md §4.3).
#[utoipa::path(
    patch,
    path = "/api/v1/workflow/definitions/{id}/versions/{version_id}",
    tag = "workflow",
    params(
        ("id" = Uuid, Path),
        ("version_id" = Uuid, Path),
    ),
    request_body = UpdateVersionGraphBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = VersionDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "row_version mismatch or not a draft, no open changeset to record into, or the workflow is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_version_graph(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((definition_id, version_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateVersionGraphBody>,
) -> Result<Json<VersionDetail>, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // Any definition row, as the UPDATE below matches by `definition_id`
    // alone: no row means the UPDATE would match nothing, which this route
    // has always answered with a version conflict.
    let (logicalname, owner_layer) = definition_owner(&mut tx, definition_id, false)
        .await?
        .ok_or(AppError::VersionConflict)?;
    recording.check_owner(parse_owner_layer(&owner_layer)?)?;
    let rows = sqlx::query(
        r#"
        UPDATE workflow_definition_version
        SET graph = $3, row_version = row_version + 1
        WHERE id = $1 AND definition_id = $2 AND row_version = $4 AND status = 'draft'
        "#,
    )
    .bind(version_id)
    .bind(definition_id)
    .bind(&body.graph)
    .bind(body.row_version)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if rows == 0 {
        // Distinguish "not draft anymore" from "stale row_version" only
        // matters for a better error message; either way the client must
        // re-fetch, so a single VersionConflict is correct here too.
        return Err(AppError::VersionConflict);
    }

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "workflow_definition_version",
            Some(version_id),
        )
        .named("workflow_version.update"),
    )
    .await?;
    let snapshot = fetch_version_in_tx(&mut tx, version_id).await?;
    recording
        .record(
            &mut tx,
            version_op(Op::SetWorkflowDraft, &logicalname, &snapshot)?,
        )
        .await?;

    tx.commit().await.map_err(AppError::internal)?;

    get_version(State(state), ctx, Path((definition_id, version_id))).await
}

/// Adapts `graph::Graph` (the wire/storage shape, `node_type: String` +
/// `config: Value`) into `escalation::GraphNode` (the typed shape that
/// validator needs). Kept local to this call site rather than moved into
/// `graph.rs`/`escalation.rs` themselves — the two files deliberately keep
/// separate vocabularies (see `escalation.rs`'s own doc comment on
/// `GraphNode`/`GraphView`), so the conversion belongs at the one place that
/// actually needs both.
///
/// **`.expect()` rather than silently dropping an unparseable node.** By the
/// time this runs, `crate::graph::validate` has already rejected any node
/// whose `node_type` does not resolve — silently filtering one out here
/// instead of trusting that would let a future refactor quietly weaken the
/// escalation walk (a dropped node loses its edges too, which can hide a
/// reachable path rather than merely mis-classify one node).
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
fn escalation_nodes(graph: &crate::graph::Graph) -> Vec<crate::escalation::GraphNode> {
    graph
        .nodes
        .iter()
        .map(|n| {
            let node_type = NodeType::parse(&n.node_type).expect(
                "every node type must already parse here — graph::validate, called \
                 immediately before this, rejects any graph containing an unknown type",
            );
            // Only `AgentStep` carries a per-instance override today — every
            // other node type's risk comes from `NodeType::capability()`
            // alone. Missing or unrecognised reads as the most conservative
            // tier. D-503 §3: the SAME resolver runtime session start uses,
            // so the ceiling reviewed here is the ceiling the session runs with.
            let action_risk = (node_type == NodeType::AgentStep)
                .then(|| crate::node_types::agent_step_risk_ceiling(&n.config));
            crate::escalation::GraphNode {
                id: n.id.clone(),
                node_type,
                action_risk,
            }
        })
        .collect()
}

/// draft -> published. Graph validation (cycle/port-type check) and
/// `node_schema_hash` computation (P-workflow-engine.md §4.3/§5 step 4) run
/// here, before the status flip — a bad graph fails fast with an actionable
/// error, never a silent partial-publish. `workflow_trigger_index`'s
/// `entry` rows are rebuilt in the same transaction (§5 step 6).
#[utoipa::path(
    post,
    path = "/api/v1/workflow/definitions/{id}/versions/{version_id}/publish",
    tag = "workflow",
    params(
        ("id" = Uuid, Path),
        ("version_id" = Uuid, Path),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Activated)])))),
    responses(
        (status = 200, description = "Success", body = VersionDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "Not a draft, another publish in progress, no open changeset to record into, or the workflow is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn publish_version(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((definition_id, version_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<VersionDetail>, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let locked: bool =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-workflow/publish-version:{definition_id}"))
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another request is publishing a version for this workflow",
        ));
    }

    let graph_json: serde_json::Value = sqlx::query_scalar(
        "SELECT graph FROM workflow_definition_version WHERE id = $1 AND definition_id = $2 AND status = 'draft'",
    )
    .bind(version_id)
    .bind(definition_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::Conflict("version not found or not in draft status"))?;
    // The version exists, so its definition row does (FK); the layer rule
    // runs before any validation or write.
    let (_, owner_layer) = definition_owner(&mut tx, definition_id, false)
        .await?
        .ok_or(AppError::NotFound)?;
    recording.check_owner(parse_owner_layer(&owner_layer)?)?;
    let graph = crate::graph::Graph::parse(&graph_json)
        .map_err(|e| AppError::Validation(format!("graph did not parse: {e}")))?;
    let schema_hash = crate::graph::validate(&graph)
        .map_err(|e| AppError::Validation(format!("graph validation failed: {e}")))?;
    crate::graph::validate_module_steps(&state, &graph)?;
    // A30-T2: every `env.<name>` a condition reads must be readable here.
    attome_core::env_vars::check_publish(
        &state.base.db,
        graph.nodes.iter().filter_map(|n| {
            crate::condition::expression_of(&n.config).and_then(serde_json::Value::as_str)
        }),
    )
    .await?;

    // TODO-047 / M32 Phase 1 (D-450): publish-time escalation validation.
    // `escalation::validate` existed as a pure, fully-tested module before
    // this line — this is the first call site that actually wires it in.
    // Closing that gap here (rather than special-casing it to run only when
    // an `AgentStep` is present) is deliberate: `escalation.rs`'s own header
    // names the hole precisely — "an agent that may only invoke Read actions
    // can still start a workflow, and that workflow can do anything its
    // author could" — and that hole exists for EVERY node type already
    // classified `Consequential` (`SendNotification`/`Webhook`), not only for
    // the new one. This can newly reject a PUBLISH of a graph that was
    // publishable before this change; it cannot affect an already-published
    // version or a running instance (validation only ever runs at this
    // draft->published transition, never retroactively).
    let escalation_nodes = escalation_nodes(&graph);
    let escalation_edges: Vec<(String, String)> = graph
        .edges
        .iter()
        .map(|e| (e.from_node.clone(), e.to_node.clone()))
        .collect();
    crate::escalation::validate(&crate::escalation::GraphView {
        nodes: &escalation_nodes,
        edges: &escalation_edges,
    })
    .map_err(
        |crate::escalation::EscalationError::UnapprovedConsequentialPath { path }| {
            AppError::Validation(format!(
                "graph escalates without passing an Approval node first: {}",
                path.join(" -> ")
            ))
        },
    )?;

    // §8 risk ("sub-workflow recursion... infinite nesting"): cheap,
    // publish-time rejection of the most common authoring mistake — a
    // definition's own sub_workflow node pointing at itself. A cycle
    // spanning two or more *different* definitions can't be fully ruled out
    // here (a target definition can be edited/republished after this check
    // passes) — `limits.workflow.max_nesting` (`scheduler::nesting_depth`) is the runtime backstop
    // for every cycle length this check can't see.
    let (own_logicalname, own_name): (String, String) =
        sqlx::query_as("SELECT logicalname, name FROM workflow_definition WHERE id = $1")
            .bind(definition_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    crate::graph::reject_self_referencing_sub_workflow(&graph, &own_logicalname)
        .map_err(|e| AppError::Validation(e.0))?;

    // M06 plan §4.2 (G3): an entry trigger's attome-rules `expression` must
    // compile against its entity before the version can go live. No I/O —
    // registry snapshot plus the in-process compile cache.
    crate::entity_trigger::validate_entry_expressions(&state, version_id, &graph).await?;

    // Only one published version at a time per definition — deprecate the
    // previous one (F094: existing running instances stay pinned to it by
    // definition_version_id, this never touches their reference).
    sqlx::query(
        "UPDATE workflow_definition_version SET status = 'deprecated'
         WHERE definition_id = $1 AND status = 'published'",
    )
    .bind(definition_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let now = Utc::now();
    let rows = sqlx::query(
        r#"
        UPDATE workflow_definition_version
        SET status = 'published', published_at = $3, published_by = $4,
            node_schema_hash = $5, row_version = row_version + 1
        WHERE id = $1 AND definition_id = $2 AND status = 'draft'
        "#,
    )
    .bind(version_id)
    .bind(definition_id)
    .bind(now)
    .bind(ctx.user_id)
    .bind(&schema_hash)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::Conflict(
            "version not found or not in draft status",
        ));
    }

    crate::trigger_index::rebuild_entry_rows(&mut tx, version_id, &graph)
        .await
        .map_err(AppError::internal)?;

    // M18 Data Catalog Phase 1 (D-466): keyed by the STABLE definition id
    // (not `version_id`), same reasoning `query_admin::write_catalog_lineage`
    // documents — a later republish replaces this same object's reference
    // set rather than leaving the prior version's rows orphaned. L5-T2: the
    // edges are attribute level where the graph names fields, with what the
    // flow does to each, under a new graph version.
    {
        use attome_core::lineage::EdgeSource;
        let edges = crate::lineage_source::FlowSource
            .edges(&serde_json::to_value(&graph).map_err(AppError::internal)?);
        attome_core::lineage::write_edges(&mut tx, "workflow", definition_id, &own_name, edges)
            .await?;
    }

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Activated,
            ctx.user_id,
            "workflow_definition_version",
            Some(version_id),
        )
        .named("workflow_version.publish"),
    )
    .await?;
    let snapshot = fetch_version_in_tx(&mut tx, version_id).await?;
    recording
        .record(
            &mut tx,
            version_op(Op::PublishWorkflow, &own_logicalname, &snapshot)?,
        )
        .await?;

    tx.commit().await.map_err(AppError::internal)?;

    get_version(State(state), ctx, Path((definition_id, version_id))).await
}

// ── DB helpers ───────────────────────────────────────────────────────────────

async fn fetch_versions(
    db: &sqlx::PgPool,
    definition_id: Uuid,
) -> Result<Vec<VersionSummary>, AppError> {
    let rows = sqlx::query_as::<_, (Uuid, i32, String, Option<chrono::DateTime<Utc>>, i64)>(
        r#"
        SELECT id, version_number, status, published_at, row_version
        FROM workflow_definition_version
        WHERE definition_id = $1
        ORDER BY version_number DESC
        "#,
    )
    .bind(definition_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(
            |(id, version_number, status, published_at, row_version)| VersionSummary {
                id,
                version_number,
                status,
                published_at,
                row_version,
            },
        )
        .collect())
}

// ── Routes ───────────────────────────────────────────────────────────────────

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/workflow/definitions",
            get(list_definitions).post(create_definition),
        )
        .route(
            "/api/v1/workflow/definitions/{id}",
            get(get_definition)
                .patch(update_definition)
                .delete(delete_definition),
        )
        .route(
            "/api/v1/workflow/definitions/{id}/versions",
            post(create_version),
        )
        .route(
            "/api/v1/workflow/definitions/{id}/versions/{version_id}",
            get(get_version).patch(update_version_graph),
        )
        .route(
            "/api/v1/workflow/definitions/{id}/versions/{version_id}/publish",
            post(publish_version),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_definitions,
    create_definition,
    get_definition,
    update_definition,
    delete_definition,
    create_version,
    get_version,
    update_version_graph,
    publish_version
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{Graph, GraphEdge, GraphNode as WireNode};

    fn node(id: &str, ty: &str, config: serde_json::Value) -> WireNode {
        WireNode {
            id: id.into(),
            node_type: ty.into(),
            config,
            ports: serde_json::json!({}),
        }
    }

    fn edge(from: &str, to: &str) -> GraphEdge {
        GraphEdge {
            from_node: from.into(),
            from_port: "out".into(),
            to_node: to.into(),
            to_port: "in".into(),
        }
    }

    fn escalation_check(graph: &Graph) -> Result<(), crate::escalation::EscalationError> {
        let nodes = escalation_nodes(graph);
        let edges: Vec<(String, String)> = graph
            .edges
            .iter()
            .map(|e| (e.from_node.clone(), e.to_node.clone()))
            .collect();
        crate::escalation::validate(&crate::escalation::GraphView {
            nodes: &nodes,
            edges: &edges,
        })
    }

    /// **TODO-047, closed for real.** An `agent_step` node reachable without
    /// passing an `Approval` fails escalation validation — the exact hole
    /// this decision's module doc names: an agent-driven workflow node must
    /// not be able to reach Consequential-equivalent authority unguarded.
    #[test]
    fn an_unguarded_agent_step_at_the_default_ceiling_is_rejected() {
        let graph = Graph {
            nodes: vec![
                node("t", "trigger", serde_json::json!({})),
                node("a", "agent_step", serde_json::json!({})),
            ],
            edges: vec![edge("t", "a")],
        };
        assert!(
            escalation_check(&graph).is_err(),
            "an agent_step with no declared risk_ceiling must default to the \
             conservative tier and require an Approval upstream"
        );
    }

    /// The node's own `config.risk_ceiling` overrides the container default —
    /// the same "the action's own risk wins over the node type's" rule
    /// `escalation.rs`'s own test already pins, applied to `agent_step`.
    #[test]
    fn an_agent_step_declared_read_ceiling_does_not_need_an_approval() {
        let graph = Graph {
            nodes: vec![
                node("t", "trigger", serde_json::json!({})),
                node(
                    "a",
                    "agent_step",
                    serde_json::json!({ "risk_ceiling": "read" }),
                ),
            ],
            edges: vec![edge("t", "a")],
        };
        assert!(escalation_check(&graph).is_ok());
    }

    /// An `Approval` node upstream of a Consequential-ceiling `agent_step`
    /// makes the graph publishable, same as for any other Consequential node.
    #[test]
    fn an_approval_upstream_of_a_consequential_agent_step_is_accepted() {
        let graph = Graph {
            nodes: vec![
                node("t", "trigger", serde_json::json!({})),
                node("appr", "approval", serde_json::json!({})),
                node(
                    "a",
                    "agent_step",
                    serde_json::json!({ "risk_ceiling": "consequential" }),
                ),
            ],
            edges: vec![edge("t", "appr"), edge("appr", "a")],
        };
        assert!(escalation_check(&graph).is_ok());
    }

    /// **The wiring closes the gap for every pre-existing Consequential node
    /// type too, not only `agent_step`.** `send_notification` was already
    /// classified `Consequential` in `node_types.rs` before this change; it
    /// was simply never checked at publish time. This is the behavior change
    /// this module's doc comment on the call site names explicitly.
    #[test]
    fn an_unguarded_send_notification_is_now_rejected_too() {
        let graph = Graph {
            nodes: vec![
                node("t", "trigger", serde_json::json!({})),
                node("n", "send_notification", serde_json::json!({})),
            ],
            edges: vec![edge("t", "n")],
        };
        assert!(escalation_check(&graph).is_err());
    }

    /// An ordinary graph with no Consequential-tier node anywhere still
    /// publishes — the wiring must not reject graphs it has no reason to.
    #[test]
    fn an_ordinary_graph_with_no_consequential_node_still_passes() {
        let graph = Graph {
            nodes: vec![
                node("t", "trigger", serde_json::json!({})),
                node("c", "condition", serde_json::json!({})),
                node("u", "update_record", serde_json::json!({})),
            ],
            edges: vec![edge("t", "c"), edge("c", "u")],
        };
        assert!(escalation_check(&graph).is_ok());
    }

    #[test]
    fn workflow_ops_are_keyed_by_logicalname() {
        let definition = DefinitionSnapshot {
            id: Uuid::now_v7(),
            logicalname: "lead-intake".into(),
            name: "Lead intake".into(),
            is_active: true,
            is_deleted: false,
            row_version: 1,
            owner_layer: "project".into(),
        };
        for op in [Op::UpsertWorkflow, Op::RetireWorkflow] {
            let recorded = definition_op(op, &definition).expect("op");
            recorded.check().expect("well-formed op");
            assert_eq!(
                recorded.target,
                serde_json::json!({ "workflow": "lead-intake" })
            );
            assert_eq!(recorded.snapshot["owner_layer"], "project");
        }
        let version = VersionSnapshot {
            id: Uuid::now_v7(),
            definition_id: definition.id,
            version_number: 2,
            graph: serde_json::json!({ "nodes": [], "edges": [] }),
            status: "draft".into(),
            published_at: None,
            row_version: 0,
        };
        for op in [Op::SetWorkflowDraft, Op::PublishWorkflow] {
            let recorded = version_op(op, "lead-intake", &version).expect("op");
            recorded.check().expect("well-formed op");
            assert_eq!(
                recorded.target,
                serde_json::json!({ "workflow": "lead-intake" })
            );
            assert_eq!(recorded.snapshot["version_number"], 2);
        }
        assert!(matches!(parse_owner_layer("x"), Err(AppError::Internal(_))));
    }

    /// An `agent_step` with a malformed `risk_ceiling` string reads as the
    /// conservative default, not as unrestricted — the same "an unknown
    /// value must not widen authority" direction the rest of this module
    /// takes.
    #[test]
    fn a_malformed_risk_ceiling_string_defaults_conservative() {
        let graph = Graph {
            nodes: vec![
                node("t", "trigger", serde_json::json!({})),
                node(
                    "a",
                    "agent_step",
                    serde_json::json!({ "risk_ceiling": "godmode" }),
                ),
            ],
            edges: vec![edge("t", "a")],
        };
        assert!(escalation_check(&graph).is_err());
    }
}
