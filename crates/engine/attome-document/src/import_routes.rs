//! A23-T8: the import routes.
//!
//! - `POST /api/v1/{entity}/imports` takes a `multipart/form-data` body: a
//!   `file` part (CSV or XLSX) and an optional `options` part (JSON:
//!   `mapping`, `match_mode`, `match_columns`, `all_or_nothing`,
//!   `triggers_on`, `encoding`, `sheet`, `dry_run`, `schedule`). The file is
//!   stored and the job staged in the background (202). The same file for
//!   the same entity finds the job already made for it (200). The upload is
//!   held to the deployment's request body limit (`http.max_body_bytes`); a
//!   bigger file comes in as a recurring import's storage source.
//! - `GET /api/v1/{entity}/imports` and `GET .../imports/{id}`: the jobs, an
//!   administrator's all of them, anyone else's their own.
//! - `POST .../imports/{id}/dry-run`, `/apply`, `/undo`, `/cancel` queue the
//!   phase (202). An apply over the entity policy's `approval_over_rows`,
//!   or one that maps a sensitive attribute while `sensitive_needs_approval`
//!   is on, opens an approval request ([`ACTION_IMPORT_APPLY`]) and waits in
//!   `awaiting_approval`; the approved request queues the apply.
//! - `GET .../imports/{id}/preview?limit=50`: the first staged rows as
//!   mapped, with every sensitive attribute's value masked.
//! - `GET`/`PUT /api/v1/admin/imports/policy/{entity}`: the entity's import
//!   policy (administrators; `PUT` takes `If-Match`).
//!
//! Who may import: the caller must be allowed to create the entity's
//! records, and when the policy lists `allowed_roles` (role ids) hold one of
//! them; an administrator always may.

use attome_audit::AuditOperation;
use attome_audit::business::{BusinessEvent, write_business_event_in_tx};
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::{AttrInfo, EngineState, Sensitivity};
use attome_security::SecurityContextExt;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::import_jobs::{self, Phase, PhaseJob};

/// One staged import row as the preview reads it.
type PreviewRow = (i32, String, Option<String>, Option<Value>, Option<Value>);

/// The approval action an import apply waits on.
pub const ACTION_IMPORT_APPLY: &str = "records.import_apply";

/// The most rows a preview shows.
pub const MAX_PREVIEW: i64 = 200;

/// The options part of an upload.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportOptions {
    /// `attome_records::import_validate::ImportMapping`: `columns`,
    /// `lookups`, `create_missing`.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub mapping: Option<Value>,
    /// `create`, `update` or `upsert` (the default).
    #[serde(default)]
    pub match_mode: Option<String>,
    #[serde(default)]
    pub match_columns: Vec<String>,
    #[serde(default)]
    pub all_or_nothing: bool,
    /// Run workflow triggers and notifications for the imported rows.
    #[serde(default)]
    pub triggers_on: bool,
    #[serde(default)]
    pub encoding: Option<String>,
    #[serde(default)]
    pub sheet: Option<String>,
    /// Stop after validation.
    #[serde(default)]
    pub dry_run: bool,
    /// Make the job a recurring import's template (A23-T7).
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub schedule: Option<Value>,
    /// A23-T9: this file fixes the rows of that job's error file; each row's
    /// `attome_row` names the row it fixes.
    #[serde(default)]
    pub source_job_id: Option<Uuid>,
}

/// The multipart body of an upload, for the API document.
#[derive(Debug, ToSchema)]
pub struct ImportUpload {
    /// The CSV or XLSX file.
    #[schema(value_type = String, format = Binary)]
    pub file: Vec<u8>,
    /// ImportOptions, as JSON text.
    pub options: Option<String>,
}

/// An upload's answer.
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportCreated {
    pub job_id: Uuid,
    /// The same file was imported before: this is that job.
    pub existing: bool,
}

/// A queued phase.
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportAccepted {
    pub job_id: Uuid,
    pub status: String,
    /// When the apply waits for approval: the request.
    pub approval_request_id: Option<Uuid>,
}

/// One import job.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct ImportJobView {
    pub id: Uuid,
    pub entity_logicalname: String,
    pub file_name: String,
    pub status: String,
    #[schema(value_type = Object)]
    pub counts: Value,
    #[schema(value_type = Object)]
    pub mapping: Value,
    pub match_mode: String,
    pub match_columns: Vec<String>,
    pub all_or_nothing: bool,
    pub triggers_on: bool,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

/// One staged row as the preview shows it.
#[derive(Debug, Serialize, ToSchema)]
pub struct PreviewRow {
    pub row_no: i32,
    pub status: String,
    pub action: Option<String>,
    /// The mapped values; a sensitive attribute's value is `"•••"`.
    #[schema(value_type = Object)]
    pub mapped: Value,
    #[schema(value_type = Option<Object>)]
    pub error: Option<Value>,
}

/// The preview of a job.
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportPreview {
    pub job_id: Uuid,
    pub rows: Vec<PreviewRow>,
    /// The attributes whose values were masked.
    pub masked: Vec<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ImportPreviewQuery {
    /// Rows to show, 1 to 200 (50 by default).
    #[serde(default)]
    pub limit: Option<i64>,
}

/// An entity's import policy.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ImportPolicy {
    /// The largest file, in rows.
    #[serde(default)]
    pub max_rows: Option<i32>,
    /// More staged rows than this need approval before applying.
    #[serde(default)]
    pub approval_over_rows: Option<i32>,
    /// Role ids that may import; empty lets anyone who may create records.
    #[serde(default)]
    pub allowed_roles: Vec<String>,
    /// `[{"start": "HH:MM", "end": "HH:MM"}]` in the deployment's time.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub quiet_hours: Option<Value>,
    /// Mapping a sensitive attribute needs approval.
    #[serde(default = "yes")]
    pub sensitive_needs_approval: bool,
}

fn yes() -> bool {
    true
}

/// A policy as stored, with its row version (send it back as `If-Match`).
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportPolicyView {
    pub entity_logicalname: String,
    #[serde(flatten)]
    pub policy: ImportPolicy,
    pub row_version: i64,
}

const JOB_COLUMNS: &str = "id, entity_logicalname, file_name, status, counts, mapping, match_mode, \
     match_columns, all_or_nothing, triggers_on, created_by, created_at, finished_at, row_version";

/// The entity's name as the registry spells it, after the caller's create
/// right and the policy's role list.
async fn admitted(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
) -> Result<(String, Vec<AttrInfo>), AppError> {
    let (_, name, attrs, _) = attome_records::entity_crud::resolve_entity(state, entity).await?;
    ctx.require(&name, "create")?;
    if !ctx.is_admin {
        let roles: Option<Vec<String>> = sqlx::query_scalar(
            "SELECT allowed_roles FROM import_policy WHERE entity_logicalname = $1",
        )
        .bind(&name)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if let Some(roles) = roles.filter(|r| !r.is_empty()) {
            let held = ctx.role_ids.clone().unwrap_or_default();
            if !roles
                .iter()
                .any(|r| Uuid::parse_str(r).is_ok_and(|id| held.contains(&id)))
            {
                return Err(AppError::Forbidden);
            }
        }
    }
    Ok((name, attrs))
}

/// The job `id` of `entity` the caller may see (its own, or any for an
/// administrator).
async fn visible_job(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    id: Uuid,
) -> Result<ImportJobView, AppError> {
    let job: ImportJobView = sqlx::query_as(&format!(
        "SELECT {JOB_COLUMNS} FROM import_job WHERE id = $1 AND entity_logicalname = $2"
    ))
    .bind(id)
    .bind(entity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    if !ctx.is_admin && job.created_by != ctx.user_id {
        return Err(AppError::NotFound);
    }
    Ok(job)
}

/// Writes an import's business event in the change's own transaction.
async fn import_event(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    actor: Uuid,
    job_id: Uuid,
    operation: AuditOperation,
    name: &str,
    comment: String,
) -> Result<(), AppError> {
    let event = BusinessEvent::new("import_job", job_id, operation, name, actor).comment(comment);
    write_business_event_in_tx(tx, &attome_audit::audit_service(state), event)
        .await
        .map(|_| ())
}

fn file_name_ok(name: &str) -> Result<String, AppError> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();
    let lower = base.to_ascii_lowercase();
    if base.is_empty() || !(lower.ends_with(".csv") || lower.ends_with(".xlsx")) {
        return Err(AppError::Validation(
            "the file must be a .csv or .xlsx file".into(),
        ));
    }
    Ok(base.chars().take(200).collect())
}

/// Upload a file to import
///
/// A23-T8: a `multipart/form-data` body with a `file` part and an optional
/// `options` part (JSON). Stores the file and stages it in the background;
/// the same file for the same entity answers the job already made for it.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/imports",
    tag = "import",
    operation_id = "create_import",
    params(("entity" = String, Path, description = "The entity the rows become")),
    request_body(content = ImportUpload, content_type = "multipart/form-data", description = "A `file` part and an optional `options` part (ImportOptions as JSON)"),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "The same file was imported before: its job", body = ImportCreated),
        (status = 202, description = "Stored; staging starts in the background", body = ImportCreated),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not import this entity's records", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 413, description = "Larger than the request body limit", body = ErrorResponse),
        (status = 422, description = "No file, not CSV or XLSX, or options that do not parse", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn create_import(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(entity): Path<String>,
    mut form: Multipart,
) -> Result<Response, AppError> {
    let (entity, attrs) = admitted(&state, &ctx, &entity).await?;
    let mut file: Option<(String, Vec<u8>)> = None;
    let mut options = ImportOptions::default();
    while let Some(field) = form
        .next_field()
        .await
        .map_err(|e| AppError::Validation(format!("multipart: {e}")))?
    {
        let part = field.name().map(str::to_owned);
        match part.as_deref() {
            Some("file") => {
                let name = file_name_ok(field.file_name().unwrap_or_default())?;
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| AppError::Validation(format!("file: {e}")))?;
                file = Some((name, bytes.to_vec()));
            }
            Some("options") => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| AppError::Validation(format!("options: {e}")))?;
                options = serde_json::from_str(&text)
                    .map_err(|e| AppError::Validation(format!("options: {e}")))?;
            }
            _ => {}
        }
    }
    let (file_name, bytes) =
        file.ok_or_else(|| AppError::Validation("send the file as a `file` part".into()))?;
    let match_mode = options
        .match_mode
        .clone()
        .unwrap_or_else(|| "upsert".into());
    if !["create", "update", "upsert"].contains(&match_mode.as_str()) {
        return Err(AppError::Validation(
            "match_mode is create, update or upsert".into(),
        ));
    }
    let mapping = options
        .mapping
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));
    let parsed: attome_records::import_validate::ImportMapping =
        serde_json::from_value(mapping.clone())
            .map_err(|e| AppError::Validation(format!("mapping: {e}")))?;
    parsed.check(&attrs)?;
    if let Some(schedule) = &options.schedule {
        let schedule: import_jobs::RecurringSchedule = serde_json::from_value(schedule.clone())
            .map_err(|e| AppError::Validation(format!("schedule: {e}")))?;
        import_jobs::due_slot(
            &schedule,
            state.base.config.app.time_zone.as_deref(),
            Utc::now(),
            Utc::now(),
        )?;
        if !ctx.is_admin {
            return Err(AppError::Validation(
                "only an administrator sets up a recurring import".into(),
            ));
        }
    }

    let sha = hex::encode(Sha256::digest(&bytes));
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM import_job \
          WHERE entity_logicalname = $1 AND file_sha256 = $2 \
            AND status NOT IN ('failed', 'cancelled', 'undone')",
    )
    .bind(&entity)
    .bind(&sha)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if let Some(job_id) = existing {
        return Ok((
            StatusCode::OK,
            Json(ImportCreated {
                job_id,
                existing: true,
            }),
        )
            .into_response());
    }

    let job_id = Uuid::now_v7();
    let key = format!("imports/{job_id}/{file_name}");
    attome_storage::mirror::write_object(&state.base.storage, &key, bytes)
        .await
        .map_err(AppError::internal)?;
    let mut counts = match &options.schedule {
        Some(schedule) => serde_json::json!({ "schedule": schedule }),
        None => serde_json::json!({}),
    };
    if let Some(source) = options.source_job_id {
        visible_job(&state, &ctx, &entity, source).await?;
        counts["source_job_id"] = serde_json::json!(source);
    }
    let actor = ctx.user_id;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO import_job (id, entity_logicalname, storage_key, file_name, \
                                         file_sha256, encoding, sheet, mapping, match_mode, \
                                         match_columns, all_or_nothing, triggers_on, status, \
                                         counts, created_by) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'uploaded', $13, $14) \
                 ON CONFLICT (entity_logicalname, file_sha256) \
                     WHERE status NOT IN ('failed', 'cancelled', 'undone') DO NOTHING \
                 RETURNING id",
    )
    .bind(job_id)
    .bind(&entity)
    .bind(&key)
    .bind(&file_name)
    .bind(&sha)
    .bind(&options.encoding)
    .bind(&options.sheet)
    .bind(&mapping)
    .bind(&match_mode)
    .bind(&options.match_columns)
    .bind(options.all_or_nothing)
    .bind(options.triggers_on)
    .bind(&counts)
    .bind(actor)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if row.is_none() {
        // The same file raced in: the other upload's job stands.
        return Err(AppError::Conflict("this file is already being imported"));
    }
    import_event(
        &mut tx,
        &state,
        actor,
        job_id,
        AuditOperation::Create,
        "import.created",
        format!("{file_name} for {entity}"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    import_jobs::enqueue(
        &state.base.db,
        Phase::Stage,
        &PhaseJob {
            job_id,
            dry_run: options.dry_run,
        },
    )
    .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(ImportCreated {
            job_id,
            existing: false,
        }),
    )
        .into_response())
}

/// List an entity's imports
///
/// A23-T8: newest first; an administrator's are every one, anyone else's
/// their own.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/imports",
    tag = "import",
    operation_id = "list_imports",
    params(("entity" = String, Path, description = "The entity"), OnePageQuery),
    responses(
        (status = 200, description = "A page of import jobs", body = PaginatedResponse<ImportJobView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not import this entity's records", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn list_imports(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(entity): Path<String>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ImportJobView>>, AppError> {
    let (entity, _) = admitted(&state, &ctx, &entity).await?;
    let window = page.window();
    let mine = if ctx.is_admin {
        None
    } else {
        Some(ctx.user_id)
    };
    let items: Vec<ImportJobView> = sqlx::query_as(&format!(
        "SELECT {JOB_COLUMNS} FROM import_job \
          WHERE entity_logicalname = $1 AND ($2::uuid IS NULL OR created_by = $2) \
          ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4"
    ))
    .bind(&entity)
    .bind(mine)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM import_job \
          WHERE entity_logicalname = $1 AND ($2::uuid IS NULL OR created_by = $2)",
    )
    .bind(&entity)
    .bind(mine)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Get an import
///
/// A23-T8: its status, counts, mapping, who started it and when.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/imports/{id}",
    tag = "import",
    operation_id = "get_import",
    params(
        ("entity" = String, Path, description = "The entity"),
        ("id" = Uuid, Path, description = "The import job"),
    ),
    responses(
        (status = 200, description = "The import job", body = ImportJobView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not import this entity's records", body = ErrorResponse),
        (status = 404, description = "No such import the caller may see", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_import(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, id)): Path<(String, Uuid)>,
) -> Result<Json<ImportJobView>, AppError> {
    let (entity, _) = admitted(&state, &ctx, &entity).await?;
    Ok(Json(visible_job(&state, &ctx, &entity, id).await?))
}

/// What `PATCH .../imports/{id}` changes; an absent field keeps its value.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportOptionsChange {
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub mapping: Option<Value>,
    #[serde(default)]
    pub match_mode: Option<String>,
    #[serde(default)]
    pub match_columns: Option<Vec<String>>,
    #[serde(default)]
    pub all_or_nothing: Option<bool>,
    #[serde(default)]
    pub triggers_on: Option<bool>,
}

/// Change an import's mapping and options
///
/// A23-T13: the wizard sets the mapping after the file is staged (an agent
/// can only propose one from staged rows). Allowed until the import starts
/// applying; a validated import goes back to staged, so its counts are
/// computed again by the next dry run.
#[utoipa::path(
    patch,
    path = "/api/v1/{entity}/imports/{id}",
    tag = "import",
    operation_id = "update_import",
    params(
        ("entity" = String, Path, description = "The entity"),
        ("id" = Uuid, Path, description = "The import job"),
    ),
    request_body = ImportOptionsChange,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The import with its new options", body = ImportJobView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not import this entity's records", body = ErrorResponse),
        (status = 404, description = "No such import the caller may see", body = ErrorResponse),
        (status = 409, description = "The import started applying", body = ErrorResponse),
        (status = 422, description = "A mapping or option that does not fit the entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn update_import(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, id)): Path<(String, Uuid)>,
    Json(change): Json<ImportOptionsChange>,
) -> Result<Json<ImportJobView>, AppError> {
    let (entity, attrs) = admitted(&state, &ctx, &entity).await?;
    let job = visible_job(&state, &ctx, &entity, id).await?;
    if !matches!(job.status.as_str(), "uploaded" | "staged" | "validated") {
        return Err(AppError::Conflict(
            "an import's options change only until it starts applying",
        ));
    }
    let mapping = change
        .mapping
        .clone()
        .unwrap_or_else(|| job.mapping.clone());
    let parsed: attome_records::import_validate::ImportMapping =
        serde_json::from_value(mapping.clone())
            .map_err(|e| AppError::Validation(format!("mapping: {e}")))?;
    parsed.check(&attrs)?;
    let match_mode = change
        .match_mode
        .clone()
        .unwrap_or_else(|| job.match_mode.clone());
    if !["create", "update", "upsert"].contains(&match_mode.as_str()) {
        return Err(AppError::Validation(
            "match_mode is create, update or upsert".into(),
        ));
    }
    let match_columns = change
        .match_columns
        .clone()
        .unwrap_or_else(|| job.match_columns.clone());
    if let Some(unknown) = match_columns
        .iter()
        .find(|c| !attrs.iter().any(|a| &a.logicalname == *c))
    {
        return Err(AppError::Validation(format!(
            "match_columns: {unknown} is not a field of this entity"
        )));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let updated: Option<ImportJobView> = sqlx::query_as(&format!(
        "UPDATE import_job SET mapping = $2, match_mode = $3, match_columns = $4, \
                all_or_nothing = $5, triggers_on = $6, \
                status = CASE WHEN status = 'validated' THEN 'staged' ELSE status END, \
                row_version = row_version + 1 \
          WHERE id = $1 AND status IN ('uploaded', 'staged', 'validated') \
         RETURNING {JOB_COLUMNS}"
    ))
    .bind(id)
    .bind(&mapping)
    .bind(&match_mode)
    .bind(&match_columns)
    .bind(change.all_or_nothing.unwrap_or(job.all_or_nothing))
    .bind(change.triggers_on.unwrap_or(job.triggers_on))
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let updated = updated.ok_or(AppError::Conflict(
        "an import's options change only until it starts applying",
    ))?;
    import_event(
        &mut tx,
        &state,
        ctx.user_id,
        id,
        AuditOperation::Update,
        "import.options",
        format!("mapping and options of {}", updated.file_name),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(updated))
}

/// Whether an apply of `job` needs approval first: more staged rows than
/// the policy allows, or a sensitive attribute mapped while the policy asks
/// for approval of those.
async fn apply_needs_approval(
    state: &EngineState,
    job: &ImportJobView,
    attrs: &[AttrInfo],
) -> Result<bool, AppError> {
    let policy: Option<(Option<i32>, bool)> = sqlx::query_as(
        "SELECT approval_over_rows, sensitive_needs_approval FROM import_policy \
          WHERE entity_logicalname = $1",
    )
    .bind(&job.entity_logicalname)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (over, sensitive_needs) = policy.unwrap_or((None, true));
    if let Some(over) = over {
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM import_stage WHERE job_id = $1")
            .bind(job.id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        if rows > i64::from(over) {
            return Ok(true);
        }
    }
    if sensitive_needs {
        let targets = mapped_targets(&job.mapping, attrs);
        if attrs
            .iter()
            .any(|a| is_sensitive(a) && targets.contains(&a.logicalname))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether an attribute's values are masked and need approval to import.
fn is_sensitive(attr: &AttrInfo) -> bool {
    attr.is_sensitive
        || matches!(
            attr.sensitivity,
            Sensitivity::Personal
                | Sensitivity::Financial
                | Sensitivity::Health
                | Sensitivity::Secret
        )
}

/// The fields a mapping writes: every column's target, or with no column
/// rules every attribute (the identity mapping). Pure.
fn mapped_targets(mapping: &Value, attrs: &[AttrInfo]) -> Vec<String> {
    let columns = mapping.get("columns").and_then(Value::as_array);
    match columns {
        Some(columns) if !columns.is_empty() => columns
            .iter()
            .filter(|c| !c.get("skip").and_then(Value::as_bool).unwrap_or(false))
            .flat_map(|c| {
                let mut out: Vec<String> = Vec::new();
                if let Some(target) = c.get("target").and_then(Value::as_str) {
                    out.push(target.to_owned());
                } else if let Some(source) = c.get("source").and_then(Value::as_str) {
                    out.push(source.to_owned());
                }
                if let Some(split) = c.pointer("/split/targets").and_then(Value::as_array) {
                    out.extend(split.iter().filter_map(|t| t.as_str().map(str::to_owned)));
                }
                out
            })
            .collect(),
        _ => attrs.iter().map(|a| a.logicalname.clone()).collect(),
    }
}

/// The phase a request asks for.
#[derive(Debug, Clone, Copy)]
enum ImportAction {
    DryRun,
    Apply,
    Undo,
    Cancel,
}

async fn act(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    id: Uuid,
    action: ImportAction,
) -> Result<ImportAccepted, AppError> {
    let (entity, attrs) = admitted(state, ctx, entity).await?;
    let job = visible_job(state, ctx, &entity, id).await?;
    let wrong = |what: &'static str| AppError::Conflict(what);
    let (phase, dry_run, next_status) = match action {
        ImportAction::DryRun => {
            if !matches!(job.status.as_str(), "uploaded" | "staged" | "validated") {
                return Err(wrong("only an import not yet applying can be dry run"));
            }
            if job.status == "uploaded" {
                (Phase::Stage, true, "uploaded")
            } else {
                // Validating again is a dry run from the staged rows.
                (Phase::Validate, true, "staged")
            }
        }
        ImportAction::Apply => {
            if job.status != "validated" {
                return Err(wrong("validate the import (a dry run) before applying it"));
            }
            (Phase::Apply, false, "validated")
        }
        ImportAction::Undo => {
            if !matches!(job.status.as_str(), "applied" | "failed") {
                return Err(wrong("only an applied or failed import can be undone"));
            }
            (Phase::Undo, false, job.status.as_str())
        }
        ImportAction::Cancel => {
            if !matches!(
                job.status.as_str(),
                "uploaded" | "staged" | "validated" | "awaiting_approval"
            ) {
                return Err(wrong("an import that started applying cannot be cancelled"));
            }
            (Phase::Stage, false, "cancelled")
        }
    };
    let (event_name, operation) = match action {
        ImportAction::DryRun => ("import.dry_run", AuditOperation::Update),
        ImportAction::Apply => ("import.apply", AuditOperation::Update),
        ImportAction::Undo => ("import.undo", AuditOperation::Update),
        ImportAction::Cancel => ("import.cancel", AuditOperation::Update),
    };

    if matches!(action, ImportAction::Apply) && apply_needs_approval(state, &job, &attrs).await? {
        let request = attome_audit::approval::gate_regarding_required(
            state,
            ACTION_IMPORT_APPLY,
            serde_json::json!({ "job_id": job.id }),
            ctx.user_id,
            Some(("import_job", job.id)),
        )
        .await?;
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        sqlx::query(
            "UPDATE import_job SET status = 'awaiting_approval', \
                    approval_request_id = $2, row_version = row_version + 1 \
              WHERE id = $1 AND status = 'validated'",
        )
        .bind(job.id)
        .bind(request.id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        import_event(
            &mut tx,
            state,
            ctx.user_id,
            job.id,
            operation,
            "import.apply_requested",
            format!("approval request {}", request.id),
        )
        .await?;
        attome_db::tx::commit(tx).await?;
        return Ok(ImportAccepted {
            job_id: job.id,
            status: "awaiting_approval".into(),
            approval_request_id: Some(request.id),
        });
    }

    let status = next_status.to_owned();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if matches!(action, ImportAction::Cancel) {
        sqlx::query(
            "UPDATE import_job SET status = 'cancelled', finished_at = now(), \
                    row_version = row_version + 1 WHERE id = $1",
        )
        .bind(job.id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    } else if matches!(action, ImportAction::DryRun) && job.status == "validated" {
        sqlx::query(
            "UPDATE import_job SET status = 'staged', row_version = row_version + 1 \
              WHERE id = $1 AND status = 'validated'",
        )
        .bind(job.id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    import_event(
        &mut tx,
        state,
        ctx.user_id,
        job.id,
        operation,
        event_name,
        format!("{} by request", event_name.trim_start_matches("import.")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    if !matches!(action, ImportAction::Cancel) {
        import_jobs::enqueue(
            &state.base.db,
            phase,
            &PhaseJob {
                job_id: job.id,
                dry_run,
            },
        )
        .await?;
    }
    Ok(ImportAccepted {
        job_id: job.id,
        status,
        approval_request_id: None,
    })
}

/// Dry-run an import
///
/// A23-T8: validates the import and writes nothing.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/imports/{id}/dry-run",
    tag = "import",
    operation_id = "dry_run_import",
    params(
        ("entity" = String, Path, description = "The entity"),
        ("id" = Uuid, Path, description = "The import job"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 202, description = "Queued, or waiting for approval", body = ImportAccepted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not import this entity's records", body = ErrorResponse),
        (status = 404, description = "No such import the caller may see", body = ErrorResponse),
        (status = 409, description = "The import is not in a state that allows this", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn dry_run_import(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, id)): Path<(String, Uuid)>,
) -> Result<(StatusCode, Json<ImportAccepted>), AppError> {
    let accepted = act(&state, &ctx, &entity, id, ImportAction::DryRun).await?;
    Ok((StatusCode::ACCEPTED, Json(accepted)))
}

/// Apply an import
///
/// A23-T8: applies a validated import, or asks for approval when its policy wants it.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/imports/{id}/apply",
    tag = "import",
    operation_id = "apply_import",
    params(
        ("entity" = String, Path, description = "The entity"),
        ("id" = Uuid, Path, description = "The import job"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 202, description = "Queued, or waiting for approval", body = ImportAccepted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not import this entity's records", body = ErrorResponse),
        (status = 404, description = "No such import the caller may see", body = ErrorResponse),
        (status = 409, description = "The import is not in a state that allows this", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn apply_import(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, id)): Path<(String, Uuid)>,
) -> Result<(StatusCode, Json<ImportAccepted>), AppError> {
    let accepted = act(&state, &ctx, &entity, id, ImportAction::Apply).await?;
    Ok((StatusCode::ACCEPTED, Json(accepted)))
}

/// Undo an import
///
/// A23-T8: reverts an applied import; records edited since stay and are reported.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/imports/{id}/undo",
    tag = "import",
    operation_id = "undo_import",
    params(
        ("entity" = String, Path, description = "The entity"),
        ("id" = Uuid, Path, description = "The import job"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 202, description = "Queued, or waiting for approval", body = ImportAccepted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not import this entity's records", body = ErrorResponse),
        (status = 404, description = "No such import the caller may see", body = ErrorResponse),
        (status = 409, description = "The import is not in a state that allows this", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn undo_import(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, id)): Path<(String, Uuid)>,
) -> Result<(StatusCode, Json<ImportAccepted>), AppError> {
    let accepted = act(&state, &ctx, &entity, id, ImportAction::Undo).await?;
    Ok((StatusCode::ACCEPTED, Json(accepted)))
}

/// Cancel an import
///
/// A23-T8: cancels an import that has not started applying.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/imports/{id}/cancel",
    tag = "import",
    operation_id = "cancel_import",
    params(
        ("entity" = String, Path, description = "The entity"),
        ("id" = Uuid, Path, description = "The import job"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 202, description = "Queued, or waiting for approval", body = ImportAccepted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not import this entity's records", body = ErrorResponse),
        (status = 404, description = "No such import the caller may see", body = ErrorResponse),
        (status = 409, description = "The import is not in a state that allows this", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn cancel_import(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, id)): Path<(String, Uuid)>,
) -> Result<(StatusCode, Json<ImportAccepted>), AppError> {
    let accepted = act(&state, &ctx, &entity, id, ImportAction::Cancel).await?;
    Ok((StatusCode::ACCEPTED, Json(accepted)))
}

/// The reader's language from `Accept-Language`: `ar` or `en` (a region
/// counts), else the deployment's.
fn reader_locale(headers: &HeaderMap, state: &EngineState) -> String {
    headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| {
            raw.split(',').find_map(|tag| {
                let tag = tag.split(';').next().unwrap_or("").trim();
                match tag
                    .split('-')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "ar" => Some("ar".to_owned()),
                    "en" => Some("en".to_owned()),
                    _ => None,
                }
            })
        })
        .unwrap_or_else(|| state.deployment_locale())
}

/// Download an import's row errors
///
/// A23-T9: a CSV (UTF-8 with a byte order mark) of the invalid rows: their
/// number, their original columns, the problems in the reader's language
/// and an empty `fix` column. Upload it fixed with `source_job_id`.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/imports/{id}/errors",
    tag = "import",
    operation_id = "import_error_file",
    params(
        ("entity" = String, Path, description = "The entity"),
        ("id" = Uuid, Path, description = "The import job"),
    ),
    responses(
        (status = 200, description = "The error file", content_type = "text/csv", body = String),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not import this entity's records", body = ErrorResponse),
        (status = 404, description = "No such import the caller may see", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn import_error_file(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (entity, _) = admitted(&state, &ctx, &entity).await?;
    let job = visible_job(&state, &ctx, &entity, id).await?;
    let locale = reader_locale(&headers, &state);
    let stream = crate::import_error_file::stream(state.clone(), id, locale).await?;
    let stem = job
        .file_name
        .rsplit_once('.')
        .map_or(job.file_name.as_str(), |(stem, _)| stem)
        .replace(['"', '\\', '\r', '\n'], "_");
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/csv; charset=utf-8".to_owned(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{stem}-errors.csv\""),
            ),
        ],
        axum::body::Body::from_stream(stream),
    )
        .into_response())
}

/// Preview an import
///
/// A23-T8: the first staged rows as mapped, every sensitive attribute's
/// value masked.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/imports/{id}/preview",
    tag = "import",
    operation_id = "preview_import",
    params(
        ("entity" = String, Path, description = "The entity"),
        ("id" = Uuid, Path, description = "The import job"),
        ImportPreviewQuery,
    ),
    responses(
        (status = 200, description = "The first staged rows", body = ImportPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not import this entity's records", body = ErrorResponse),
        (status = 404, description = "No such import the caller may see", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn preview_import(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, id)): Path<(String, Uuid)>,
    Query(query): Query<ImportPreviewQuery>,
) -> Result<Json<ImportPreview>, AppError> {
    let (entity, attrs) = admitted(&state, &ctx, &entity).await?;
    visible_job(&state, &ctx, &entity, id).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, MAX_PREVIEW);
    let rows: Vec<PreviewRow> = sqlx::query_as(
        "SELECT row_no, status, action, COALESCE(mapped, raw), error FROM import_stage \
          WHERE job_id = $1 ORDER BY row_no LIMIT $2",
    )
    .bind(id)
    .bind(limit)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let masked: Vec<String> = attrs
        .iter()
        .filter(|a| is_sensitive(a))
        .map(|a| a.logicalname.clone())
        .collect();
    let rows = rows
        .into_iter()
        .map(|(row_no, status, action, mapped, error)| {
            let mut mapped = mapped.unwrap_or(Value::Null);
            if let Some(object) = mapped.as_object_mut() {
                for name in &masked {
                    if let Some(value) = object.get_mut(name)
                        && !value.is_null()
                    {
                        *value = Value::String("•••".into());
                    }
                }
            }
            PreviewRow {
                row_no,
                status,
                action,
                mapped,
                error,
            }
        })
        .collect();
    Ok(Json(ImportPreview {
        job_id: id,
        rows,
        masked,
    }))
}

#[derive(sqlx::FromRow)]
struct PolicyRow {
    max_rows: Option<i32>,
    approval_over_rows: Option<i32>,
    allowed_roles: Vec<String>,
    quiet_hours: Option<Value>,
    sensitive_needs_approval: bool,
    row_version: i64,
}

impl PolicyRow {
    fn view(self, entity: String) -> ImportPolicyView {
        ImportPolicyView {
            entity_logicalname: entity,
            policy: ImportPolicy {
                max_rows: self.max_rows,
                approval_over_rows: self.approval_over_rows,
                allowed_roles: self.allowed_roles,
                quiet_hours: self.quiet_hours,
                sensitive_needs_approval: self.sensitive_needs_approval,
            },
            row_version: self.row_version,
        }
    }
}

const POLICY_COLUMNS: &str = "max_rows, approval_over_rows, allowed_roles, quiet_hours, sensitive_needs_approval, row_version";

/// Get an entity's import policy
///
/// A23-T8: the defaults (no caps, approval for sensitive attributes) when
/// none is stored. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/imports/policy/{entity}",
    tag = "admin",
    operation_id = "get_import_policy",
    params(("entity" = String, Path, description = "The entity")),
    responses(
        (status = 200, description = "The policy", body = ImportPolicyView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_import_policy(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(entity): Path<String>,
) -> Result<Json<ImportPolicyView>, AppError> {
    let (_, entity, _, _) = attome_records::entity_crud::resolve_entity(&state, &entity).await?;
    let row: Option<PolicyRow> = sqlx::query_as(&format!(
        "SELECT {POLICY_COLUMNS} FROM import_policy WHERE entity_logicalname = $1"
    ))
    .bind(&entity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let row = row.unwrap_or(PolicyRow {
        max_rows: None,
        approval_over_rows: None,
        allowed_roles: Vec::new(),
        quiet_hours: None,
        sensitive_needs_approval: true,
        row_version: 0,
    });
    Ok(Json(row.view(entity)))
}

/// Set an entity's import policy
///
/// A23-T8: replaces the policy. Send the row version you read as
/// `If-Match` (`0` when none was stored); a stale one is a 409.
/// Administrators only; audited.
#[utoipa::path(
    put,
    path = "/api/v1/admin/imports/policy/{entity}",
    tag = "admin",
    operation_id = "put_import_policy",
    params(("entity" = String, Path, description = "The entity")),
    request_body = ImportPolicy,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The policy as stored", body = ImportPolicyView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 409, description = "The policy changed since it was read", body = ErrorResponse),
        (status = 422, description = "A missing or malformed If-Match, or a value out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn put_import_policy(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(entity): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ImportPolicy>,
) -> Result<Json<ImportPolicyView>, AppError> {
    let (_, entity, _, _) = attome_records::entity_crud::resolve_entity(&state, &entity).await?;
    let expected: i64 = headers
        .get(IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().trim_matches('"'))
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| {
            AppError::Validation("send If-Match with the policy's row_version".into())
        })?;
    if body.max_rows.is_some_and(|n| n <= 0) || body.approval_over_rows.is_some_and(|n| n <= 0) {
        return Err(AppError::Validation(
            "max_rows and approval_over_rows are positive".into(),
        ));
    }
    if body
        .allowed_roles
        .iter()
        .any(|r| Uuid::parse_str(r).is_err())
    {
        return Err(AppError::Validation("allowed_roles are role ids".into()));
    }
    if let Some(hours) = &body.quiet_hours
        && attome_core::quiet_window::windows_of(hours).len()
            != hours.as_array().map_or(usize::MAX, Vec::len)
    {
        return Err(AppError::Validation(
            "quiet_hours is a list of {start, end} times, HH:MM".into(),
        ));
    }
    let event = SecurityEvent::new(
        MandatoryCategory::Configuration,
        AuditOperation::Update,
        ctx.user_id,
        "import_policy",
        None,
    )
    .named("import.policy_set")
    .comment(entity.clone());
    let mut stx = SecurityTx::begin(&state, event).await?;
    // Row version 0 is "none stored yet": a create that loses a race to
    // another create finds the row and answers 409 like a stale update.
    let sql = if expected == 0 {
        format!(
            "INSERT INTO import_policy (entity_logicalname, max_rows, approval_over_rows, \
                                        allowed_roles, quiet_hours, sensitive_needs_approval) \
             SELECT $1, $2, $3, $4, $5, $6 WHERE $7::bigint = 0 \
             ON CONFLICT (entity_logicalname) DO NOTHING \
             RETURNING {POLICY_COLUMNS}"
        )
    } else {
        format!(
            "UPDATE import_policy SET max_rows = $2, approval_over_rows = $3, allowed_roles = $4, \
                    quiet_hours = $5, sensitive_needs_approval = $6, row_version = row_version + 1 \
              WHERE entity_logicalname = $1 AND row_version = $7 \
             RETURNING {POLICY_COLUMNS}"
        )
    };
    let row: Option<PolicyRow> = sqlx::query_as(&sql)
        .bind(&entity)
        .bind(body.max_rows)
        .bind(body.approval_over_rows)
        .bind(&body.allowed_roles)
        .bind(&body.quiet_hours)
        .bind(body.sensitive_needs_approval)
        .bind(expected)
        .fetch_optional(&mut *stx)
        .await
        .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::VersionConflict)?;
    stx.commit().await?;
    Ok(Json(row.view(entity)))
}

// ── For agent tools (A23-T11) ─────────────────────────────────────────────────

/// The entity of import `job_id`, or a 404.
async fn job_entity(state: &EngineState, job_id: Uuid) -> Result<String, AppError> {
    sqlx::query_scalar("SELECT entity_logicalname FROM import_job WHERE id = $1")
        .bind(job_id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)
}

/// Import `job_id` as `ctx` may see it, with the entity's attributes; the
/// same checks as `GET /api/v1/{entity}/imports/{id}`.
pub async fn job_for(
    state: &EngineState,
    ctx: &SecurityContext,
    job_id: Uuid,
) -> Result<(ImportJobView, Vec<AttrInfo>), AppError> {
    let entity = job_entity(state, job_id).await?;
    let (entity, attrs) = admitted(state, ctx, &entity).await?;
    Ok((visible_job(state, ctx, &entity, job_id).await?, attrs))
}

/// Applies import `job_id` for `ctx`, as `POST .../imports/{id}/apply` does:
/// queued, or waiting for approval when its policy wants it.
pub async fn start_import(
    state: &EngineState,
    ctx: &SecurityContext,
    job_id: Uuid,
) -> Result<ImportAccepted, AppError> {
    let entity = job_entity(state, job_id).await?;
    act(state, ctx, &entity, job_id, ImportAction::Apply).await
}

/// The first `limit` invalid rows of import `job_id`: their numbers and
/// error lists, no cell values.
pub async fn error_rows(
    state: &EngineState,
    ctx: &SecurityContext,
    job_id: Uuid,
    limit: i64,
) -> Result<Vec<(i32, Value)>, AppError> {
    job_for(state, ctx, job_id).await?;
    sqlx::query_as(
        "SELECT row_no, COALESCE(error->'errors', '[]'::jsonb) FROM import_stage \
          WHERE job_id = $1 AND status = 'invalid' ORDER BY row_no LIMIT $2",
    )
    .bind(job_id)
    .bind(limit.clamp(1, 1_000))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Up to `per_column` non-empty sample cells of each column of import
/// `job_id`, from its first staged rows; the columns in the file's order.
pub async fn column_samples(
    state: &EngineState,
    job_id: Uuid,
    per_column: usize,
) -> Result<Vec<(String, Vec<String>)>, AppError> {
    let columns: Option<Value> =
        sqlx::query_scalar("SELECT counts->'columns' FROM import_job WHERE id = $1")
            .bind(job_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .flatten();
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT raw FROM import_stage WHERE job_id = $1 ORDER BY row_no LIMIT 200",
    )
    .bind(job_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let names: Vec<String> = columns
        .and_then(|c| serde_json::from_value(c).ok())
        .or_else(|| {
            rows.first()
                .and_then(Value::as_object)
                .map(|o| o.keys().cloned().collect())
        })
        .unwrap_or_default();
    Ok(names
        .into_iter()
        .map(|name| {
            let samples: Vec<String> = rows
                .iter()
                .filter_map(|r| r.get(&name).and_then(Value::as_str))
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .take(per_column)
                .map(|v| v.chars().take(80).collect())
                .collect();
            (name, samples)
        })
        .collect())
}

/// The mappings of the entity's last `n` imports that named columns.
pub async fn recent_mappings(
    state: &EngineState,
    entity: &str,
    n: i64,
) -> Result<Vec<Value>, AppError> {
    sqlx::query_scalar(
        "SELECT mapping FROM import_job \
          WHERE entity_logicalname = $1 AND jsonb_array_length(COALESCE(mapping->'columns', '[]'::jsonb)) > 0 \
          ORDER BY created_at DESC LIMIT $2",
    )
    .bind(entity)
    .bind(n)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Whether an attribute's values are sensitive (masked in previews, never
/// sent to a model).
pub fn attribute_is_sensitive(attr: &AttrInfo) -> bool {
    is_sensitive(attr)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/{entity}/imports",
            get(list_imports).post(create_import),
        )
        .route(
            "/api/v1/{entity}/imports/{id}",
            get(get_import).patch(update_import),
        )
        .route(
            "/api/v1/{entity}/imports/{id}/dry-run",
            post(dry_run_import),
        )
        .route("/api/v1/{entity}/imports/{id}/apply", post(apply_import))
        .route("/api/v1/{entity}/imports/{id}/undo", post(undo_import))
        .route("/api/v1/{entity}/imports/{id}/cancel", post(cancel_import))
        .route("/api/v1/{entity}/imports/{id}/preview", get(preview_import))
        .route(
            "/api/v1/{entity}/imports/{id}/errors",
            get(import_error_file),
        )
        .route(
            "/api/v1/admin/imports/policy/{entity}",
            get(get_import_policy).put(put_import_policy),
        )
}

/// What an approved [`ACTION_IMPORT_APPLY`] request does: the job leaves
/// `awaiting_approval` and its apply is queued.
pub async fn execute_approved_apply(
    state: &EngineState,
    payload: &Value,
) -> Result<Value, AppError> {
    #[derive(Deserialize)]
    struct Payload {
        job_id: Uuid,
    }
    let Payload { job_id } = serde_json::from_value(payload.clone()).map_err(AppError::internal)?;
    let moved = sqlx::query(
        "UPDATE import_job SET status = 'validated', row_version = row_version + 1 \
          WHERE id = $1 AND status = 'awaiting_approval'",
    )
    .bind(job_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if moved.rows_affected() == 1 {
        import_jobs::enqueue(
            &state.base.db,
            Phase::Apply,
            &PhaseJob {
                job_id,
                dry_run: false,
            },
        )
        .await?;
    }
    Ok(serde_json::json!({ "job_id": job_id, "queued": moved.rows_affected() == 1 }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        create_import,
        list_imports,
        get_import,
        update_import,
        dry_run_import,
        apply_import,
        undo_import,
        cancel_import,
        preview_import,
        import_error_file,
        get_import_policy,
        put_import_policy
    ),
    components(schemas(
        ImportUpload,
        ImportOptions,
        ImportOptionsChange,
        ImportCreated,
        ImportAccepted,
        ImportJobView,
        PreviewRow,
        ImportPreview,
        ImportPolicy,
        ImportPolicyView
    ))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_mapping_names_the_fields_it_writes() {
        let mapping = json!({"columns": [
            {"source": "Name", "target": "title"},
            {"source": "Notes", "skip": true},
            {"source": "phone"},
            {"source": "Full", "split": {"separator": " ", "targets": ["first", "last"]}},
        ]});
        let targets = mapped_targets(&mapping, &[]);
        assert_eq!(targets, ["title", "phone", "Full", "first", "last"]);
    }

    #[test]
    fn only_csv_and_xlsx_files_are_taken() {
        assert_eq!(file_name_ok("C:\\x\\accounts.CSV").unwrap(), "accounts.CSV");
        assert!(file_name_ok("data.json").is_err());
        assert!(file_name_ok("").is_err());
    }
}
