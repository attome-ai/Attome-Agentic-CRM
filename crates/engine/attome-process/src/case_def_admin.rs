//! `process_case_def` admin CRUD — `/api/v1/process/case-defs*`.
//!
//! Mounted through `ProcessModel::routes()` (`lib.rs`), so every route here
//! is already license-gated by `ModelRegistry` before this module ever sees
//! a request (D-010) — handlers only need `Authorized<Admin>`, the same
//! posture `attome-state`'s admin CRUD (`admin.rs`) uses for its own
//! migration-owned config table.
//!
//! Solution 7 Phase 1 (D-785, design §1.1): every write here is recorded as
//! one changeset operation (`upsert_case_def` / `retire_case_def`, target
//! `{ case_def: <name> }`) as the last statement before commit. A new row is
//! stamped with the recording changeset's layer; an update or delete is
//! refused with 409 `layer_mismatch` unless the row's `owner_layer` is that
//! layer.

use attome_core::EngineState;
use attome_core::changeset::{Layer, Op, RecordedOp, RecordingCtx};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use uuid::Uuid;

use crate::model::{CaseDefDetail, CaseDefListItem, CreateCaseDefBody, UpdateCaseDefBody};

/// The row as read back, enumerated columns. `Serialize` is the changeset
/// operation's post-write snapshot.
#[derive(sqlx::FromRow, serde::Serialize)]
struct CaseDefRow {
    id: Uuid,
    name: String,
    source: String,
    activity_mapping: serde_json::Value,
    resource_mapping: serde_json::Value,
    visibility_privilege: Option<String>,
    is_active: bool,
    row_version: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    last_extracted_at: Option<chrono::DateTime<chrono::Utc>>,
    owner_layer: String,
}

impl From<CaseDefRow> for CaseDefListItem {
    fn from(r: CaseDefRow) -> Self {
        CaseDefListItem {
            id: r.id,
            name: r.name,
            source: r.source,
            is_active: r.is_active,
            row_version: r.row_version,
            last_extracted_at: r.last_extracted_at,
            owner_layer: r.owner_layer,
        }
    }
}

impl From<CaseDefRow> for CaseDefDetail {
    fn from(r: CaseDefRow) -> Self {
        CaseDefDetail {
            id: r.id,
            name: r.name,
            source: r.source,
            activity_mapping: r.activity_mapping,
            resource_mapping: r.resource_mapping,
            visibility_privilege: r.visibility_privilege,
            is_active: r.is_active,
            row_version: r.row_version,
            created_at: r.created_at,
            updated_at: r.updated_at,
            last_extracted_at: r.last_extracted_at,
            owner_layer: r.owner_layer,
        }
    }
}

const CASE_DEF_COLUMNS: &str = "id, name, source, activity_mapping, resource_mapping, \
     visibility_privilege, is_active, row_version, created_at, updated_at, last_extracted_at, \
     owner_layer";

/// A stored `owner_layer`, parsed. The column's CHECK admits only the four
/// layers, so an unknown value is a defect, not client input.
fn parse_owner_layer(value: &str) -> Result<Layer, AppError> {
    Layer::parse(value).ok_or_else(|| AppError::internal(format!("unknown owner_layer {value:?}")))
}

/// The changeset operation for a case definition just written: the target
/// is its logical key (the unique `name`), the snapshot the post-write row.
fn case_def_op(op: Op, row: &CaseDefRow) -> Result<RecordedOp, AppError> {
    Ok(RecordedOp {
        op,
        object_kind: "case_def",
        object_ref: Some(row.id),
        target: serde_json::json!({ "case_def": row.name }),
        snapshot: serde_json::to_value(row).map_err(AppError::internal)?,
        changed: Vec::new(),
    })
}

/// The row inside the write's transaction (live or just soft-deleted), for
/// the snapshot and the response.
async fn fetch_row_in_tx(tx: &mut attome_db::Tx<'_>, id: Uuid) -> Result<CaseDefRow, AppError> {
    sqlx::query_as(&format!(
        "SELECT {CASE_DEF_COLUMNS} FROM process_case_def WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Checks the live row's owner layer against the recording (409
/// `layer_mismatch`); `NotFound` when there is no live row.
async fn check_live_owner(
    tx: &mut attome_db::Tx<'_>,
    recording: &RecordingCtx,
    id: Uuid,
) -> Result<(), AppError> {
    let layer: Option<String> = sqlx::query_scalar(
        "SELECT owner_layer FROM process_case_def WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let layer = layer.ok_or(AppError::NotFound)?;
    recording.check_owner(parse_owner_layer(&layer)?)
}

/// `source` must match `crate::extraction::Source::parse`'s accepted shapes —
/// validated here too (not just at the SQL `CHECK` constraint) so a bad value
/// comes back as an actionable 422 instead of a masked 500 from the
/// constraint violation.
fn validate_body(
    name: &str,
    source: &str,
) -> Result<(String, crate::extraction::Source), AppError> {
    let name = name.trim().to_owned();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    let parsed = crate::extraction::Source::parse(source)?;
    Ok((name, parsed))
}

#[utoipa::path(
    get,
    path = "/api/v1/process/case-defs",
    tag = "process",
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<CaseDefListItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_case_defs(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<PaginatedResponse<CaseDefListItem>>, AppError> {
    let rows: Vec<CaseDefRow> = sqlx::query_as(&format!(
        "SELECT {CASE_DEF_COLUMNS} FROM process_case_def \
         WHERE is_deleted = false ORDER BY name"
    ))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = rows.len() as i64;
    let items: Vec<CaseDefListItem> = rows.into_iter().map(Into::into).collect();
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

async fn fetch_detail(state: &EngineState, id: Uuid) -> Result<CaseDefDetail, AppError> {
    let row: CaseDefRow = sqlx::query_as(&format!(
        "SELECT {CASE_DEF_COLUMNS} FROM process_case_def WHERE id = $1 AND is_deleted = false"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    Ok(row.into())
}

#[utoipa::path(
    get,
    path = "/api/v1/process/case-defs/{id}",
    tag = "process",
    params(("id" = Uuid, Path, description = "Case definition id")),
    responses(
        (status = 200, description = "Success", body = CaseDefDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_case_def(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<CaseDefDetail>, AppError> {
    Ok(Json(fetch_detail(&state, id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/process/case-defs",
    tag = "process",
    request_body = CreateCaseDefBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = CaseDefDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "A case def with this name already exists, or no open changeset to record into", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_case_def(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Json(body): Json<CreateCaseDefBody>,
) -> Result<(StatusCode, Json<CaseDefDetail>), AppError> {
    let (name, _source) = validate_body(&body.name, &body.source)?;
    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-process/case-def:{name}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a case-def write with this name is already in progress",
        ));
    }

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO process_case_def \
             (name, source, activity_mapping, resource_mapping, visibility_privilege, is_active, \
              owner_layer) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(&name)
    .bind(&body.source)
    .bind(&body.activity_mapping)
    .bind(&body.resource_mapping)
    .bind(&body.visibility_privilege)
    .bind(body.is_active)
    .bind(layer.as_str())
    .fetch_one(&mut *tx)
    .await
    .map_err(map_unique_violation)?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            "process_case_def",
            Some(id),
        )
        .named("process_case_def.create"),
    )
    .await?;
    let row = fetch_row_in_tx(&mut tx, id).await?;
    recording
        .record(&mut tx, case_def_op(Op::UpsertCaseDef, &row)?)
        .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok((StatusCode::CREATED, Json(row.into())))
}

#[utoipa::path(
    patch,
    path = "/api/v1/process/case-defs/{id}",
    tag = "process",
    params(("id" = Uuid, Path, description = "Case definition id")),
    request_body = UpdateCaseDefBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = CaseDefDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "row_version mismatch, no open changeset to record into, or the definition is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_case_def(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateCaseDefBody>,
) -> Result<Json<CaseDefDetail>, AppError> {
    let name = body.name.trim().to_owned();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    recording.preflight(&state.base.db).await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-process/case-def:{id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a case-def write for this id is already in progress",
        ));
    }
    check_live_owner(&mut tx, &recording, id).await?;

    let n = sqlx::query(
        "UPDATE process_case_def \
         SET name = $2, activity_mapping = $3, resource_mapping = $4, \
             visibility_privilege = $5, is_active = $6, updated_at = NOW(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND is_deleted = false AND row_version = $7",
    )
    .bind(id)
    .bind(&name)
    .bind(&body.activity_mapping)
    .bind(&body.resource_mapping)
    .bind(&body.visibility_privilege)
    .bind(body.is_active)
    .bind(body.row_version)
    .execute(&mut *tx)
    .await
    .map_err(map_unique_violation)?
    .rows_affected();
    if n == 0 {
        let exists: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM process_case_def WHERE id = $1 AND is_deleted = false",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        return Err(if exists.is_some() {
            AppError::VersionConflict
        } else {
            AppError::NotFound
        });
    }
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "process_case_def",
            Some(id),
        )
        .named("process_case_def.update"),
    )
    .await?;
    let row = fetch_row_in_tx(&mut tx, id).await?;
    recording
        .record(&mut tx, case_def_op(Op::UpsertCaseDef, &row)?)
        .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok(Json(row.into()))
}

#[utoipa::path(
    delete,
    path = "/api/v1/process/case-defs/{id}",
    tag = "process",
    params(("id" = Uuid, Path, description = "Case definition id")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or the definition is owned by another layer", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_case_def(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    check_live_owner(&mut tx, &recording, id).await?;
    let n = sqlx::query(
        "UPDATE process_case_def \
         SET is_deleted = true, is_active = false, updated_at = NOW(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
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
            "process_case_def",
            Some(id),
        )
        .named("process_case_def.delete"),
    )
    .await?;
    let row = fetch_row_in_tx(&mut tx, id).await?;
    recording
        .record(&mut tx, case_def_op(Op::RetireCaseDef, &row)?)
        .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

fn map_unique_violation(error: sqlx::Error) -> AppError {
    if attome_db::is_unique_violation(&error) {
        AppError::Conflict("a case def with this name already exists")
    } else {
        AppError::internal(error)
    }
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/process/case-defs",
            get(list_case_defs).post(create_case_def),
        )
        .route(
            "/api/v1/process/case-defs/{id}",
            get(get_case_def)
                .patch(update_case_def)
                .delete(delete_case_def),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_case_defs,
    get_case_def,
    create_case_def,
    update_case_def,
    delete_case_def,
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str) -> CaseDefRow {
        let now = chrono::Utc::now();
        CaseDefRow {
            id: Uuid::now_v7(),
            name: name.into(),
            source: "entity:account".into(),
            activity_mapping: serde_json::json!({}),
            resource_mapping: serde_json::json!({}),
            visibility_privilege: None,
            is_active: true,
            row_version: 3,
            created_at: now,
            updated_at: now,
            last_extracted_at: None,
            owner_layer: "project".into(),
        }
    }

    #[test]
    fn case_def_ops_are_keyed_by_name_and_pass_the_recorder_check() {
        for op in [Op::UpsertCaseDef, Op::RetireCaseDef] {
            let recorded = case_def_op(op, &row("order_to_cash")).expect("op");
            recorded.check().expect("well-formed op");
            assert_eq!(
                recorded.target,
                serde_json::json!({ "case_def": "order_to_cash" })
            );
            assert_eq!(recorded.snapshot["owner_layer"], "project");
            assert_eq!(recorded.snapshot["row_version"], 3);
        }
    }

    #[test]
    fn an_unknown_stored_layer_is_an_internal_error() {
        assert_eq!(parse_owner_layer("platform").ok(), Some(Layer::Platform));
        assert!(matches!(
            parse_owner_layer("tenant"),
            Err(AppError::Internal(_))
        ));
    }
}
