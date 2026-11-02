//! Y10-T5: `/api/v1/admin/extensions`, publishing, versioning, rolling back
//! and switching off extensions (WebAssembly modules run by
//! `attome-extension`).
//!
//! - `POST /api/v1/admin/extensions` uploads a version: `{name, module_base64,
//!   manifest}`. The module must compile in the extension runtime and the
//!   manifest's grants must be well formed; the module goes to the file
//!   store (`extensions/<name>/<version>.wasm`) and the row starts `draft`.
//!   The administrator uploading it approves its grants (Z10's two-person
//!   approval of grants comes with extension upload to the admin screens).
//! - `POST .../{name}/versions/{version}/publish` publishes that version,
//!   superseding the one published before; publishing an older version is a
//!   rollback.
//! - `POST .../{name}/off` switches every version of the extension off at
//!   once. [`published`] reads the status from the database on every call,
//!   so the switch takes effect on every node immediately.
//! - `GET` lists the versions.
//!
//! All need the automation administration area; the writes are audited.

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, audit_service};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_storage::object_store::{ObjectStoreExt, path::Path as ObjectPath};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

/// The largest module accepted, in bytes.
pub const MAX_MODULE_BYTES: usize = 10 * 1024 * 1024;

/// One version of an extension.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct ExtensionVersion {
    pub id: Uuid,
    pub name: String,
    pub version: i32,
    pub module_sha256: String,
    #[schema(value_type = Object)]
    pub manifest: Value,
    /// `draft`, `published`, `superseded` or `off`.
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub published_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// An uploaded version.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadExtension {
    pub name: String,
    /// The compiled WebAssembly module, base64.
    pub module_base64: String,
    /// The grants: `{entities, secrets, hosts}`.
    #[schema(value_type = Object)]
    pub manifest: Value,
}

const COLUMNS: &str =
    "id, name, version, module_sha256, manifest, status, created_at, published_at";

fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The published version of `name`, if it is published and not off.
pub async fn published(
    db: &attome_db::DbPool,
    name: &str,
) -> Result<Option<ExtensionVersion>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM extension WHERE name = $1 AND status = 'published'"
    ))
    .bind(name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

async fn audit(
    state: &EngineState,
    actor: Uuid,
    op: AuditOperation,
    what: String,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    write_security_event(
        &mut tx,
        &audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            op,
            actor,
            "extension",
            None,
        )
        .named("extension.change")
        .comment(what),
    )
    .await?;
    attome_db::tx::commit(tx).await
}

/// List extension versions
#[utoipa::path(
    get,
    path = "/api/v1/admin/extensions",
    operation_id = "list_extensions",
    tag = "admin",
    responses(
        (status = 200, description = "Every version, by name and newest first", body = PaginatedResponse<ExtensionVersion>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Automation>>,
) -> Result<Json<PaginatedResponse<ExtensionVersion>>, AppError> {
    let items: Vec<ExtensionVersion> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM extension ORDER BY name, version DESC LIMIT 1000"
    ))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

/// Upload an extension version
///
/// Y10-T5: the module must compile in the extension runtime and the
/// manifest's grants must be well formed. Stored as the next version, in
/// draft. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/extensions",
    operation_id = "upload_extension",
    tag = "admin",
    request_body = UploadExtension,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The stored version", body = ExtensionVersion),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "A bad name, a module that does not compile, or bad grants", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn upload(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    Json(body): Json<UploadExtension>,
) -> Result<(StatusCode, Json<ExtensionVersion>), AppError> {
    if !name_ok(&body.name) {
        return Err(AppError::Validation(
            "name is a lower-case identifier of at most 63 characters".into(),
        ));
    }
    let module = base64::engine::general_purpose::STANDARD
        .decode(body.module_base64.trim())
        .map_err(|_| AppError::Validation("module_base64 is not base64".into()))?;
    if module.is_empty() || module.len() > MAX_MODULE_BYTES {
        return Err(AppError::Validation(format!(
            "the module is 1 byte to {MAX_MODULE_BYTES} bytes"
        )));
    }
    let grants: attome_extension::Grants = serde_json::from_value(body.manifest.clone())
        .map_err(|e| AppError::Validation(format!("the manifest: {e}")))?;
    // M17-T1: a schedule's cron expression and time zone must parse.
    if let Some(schedule) = &grants.schedule {
        attome_jobs::schedule::Schedule::cron(&schedule.cron, &schedule.timezone)
            .map_err(|e| AppError::Validation(format!("the manifest's schedule: {e}")))?;
    }
    let problems = attome_extension::grants::check(&grants);
    if !problems.is_empty() {
        return Err(AppError::Validation(format!(
            "the manifest: {}",
            problems.join("; ")
        )));
    }
    // Compiling is CPU work: off the async workers.
    let to_compile = module.clone();
    tokio::task::spawn_blocking(move || {
        attome_extension::Runtime::shared()
            .and_then(|rt| rt.compile(&to_compile))
            .map(|_| ())
    })
    .await
    .map_err(AppError::internal)?
    .map_err(|e| AppError::Validation(e.to_string()))?;

    let sha = hex::encode(Sha256::digest(&module));
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // Two uploads racing for one number: the second meets the unique
    // (name, version) and is answered 409 to retry.
    let version: i32 =
        sqlx::query_scalar("SELECT COALESCE(max(version), 0) + 1 FROM extension WHERE name = $1")
            .bind(&body.name)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let key = format!("extensions/{}/{version}.wasm", body.name);
    let path = ObjectPath::parse(&key).map_err(AppError::internal)?;
    state
        .base
        .storage
        .store()
        .put(&path, module.into())
        .await
        .map_err(AppError::internal)?;
    let row: ExtensionVersion = sqlx::query_as(&format!(
        "INSERT INTO extension (name, version, module_key, module_sha256, manifest, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING {COLUMNS}"
    ))
    .bind(&body.name)
    .bind(version)
    .bind(&key)
    .bind(&sha)
    .bind(&body.manifest)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if attome_db::is_unique_violation(&e) {
            AppError::Conflict("another version was uploaded at the same time; upload again")
        } else {
            AppError::internal(e)
        }
    })?;
    attome_db::tx::commit(tx).await?;
    audit(
        &state,
        ctx.user_id,
        AuditOperation::Create,
        format!("extension {} version {version} uploaded", body.name),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// Publish an extension version
///
/// Y10-T5: that version becomes the one that runs; the one published
/// before is superseded. Publishing an older version rolls back. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/extensions/{name}/versions/{version}/publish",
    operation_id = "publish_extension",
    tag = "admin",
    params(
        ("name" = String, Path, description = "The extension"),
        ("version" = i32, Path, description = "The version to publish"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The published version", body = ExtensionVersion),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such version", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn publish(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    Path((name, version)): Path<(String, i32)>,
) -> Result<Json<ExtensionVersion>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // The partial unique index keeps one published version; a racing publish
    // of the same name meets it and is answered 409.
    sqlx::query(
        "UPDATE extension SET status = 'superseded' WHERE name = $1 AND status = 'published'",
    )
    .bind(&name)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let row: Option<ExtensionVersion> = sqlx::query_as(&format!(
        "UPDATE extension SET status = 'published', published_at = now() \
          WHERE name = $1 AND version = $2 RETURNING {COLUMNS}"
    ))
    .bind(&name)
    .bind(version)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        if attome_db::is_unique_violation(&e) {
            AppError::Conflict("another version was published at the same time")
        } else {
            AppError::internal(e)
        }
    })?;
    let Some(row) = row else {
        return Err(AppError::NotFound);
    };
    attome_db::tx::commit(tx).await?;
    audit(
        &state,
        ctx.user_id,
        AuditOperation::Update,
        format!("extension {name} version {version} published"),
    )
    .await?;
    Ok(Json(row))
}

/// Switch an extension off
///
/// Y10-T5: every version of the extension stops running at once, on every
/// node (the runtime reads the status on every call). Publish a version to
/// switch it on again. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/extensions/{name}/off",
    operation_id = "switch_off_extension",
    tag = "admin",
    params(("name" = String, Path, description = "The extension")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Off"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such extension", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn switch_off(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    Path(name): Path<String>,
) -> Result<StatusCode, AppError> {
    let changed = sqlx::query(
        "UPDATE extension SET status = 'off' WHERE name = $1 AND status IN ('published', 'draft', 'superseded')",
    )
    .bind(&name)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM extension WHERE name = $1)")
            .bind(&name)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    tracing::warn!(extension = %name, versions = changed, "extension switched off");
    audit(
        &state,
        ctx.user_id,
        AuditOperation::Update,
        format!("extension {name} switched off"),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Y10-T6: one run of an extension, as logged.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct ExtensionRun {
    pub id: Uuid,
    pub version: i32,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub duration_ms: i32,
    pub fuel_used: i64,
    pub ok: bool,
    pub error: Option<String>,
    /// `[{level, message}]`, secrets masked.
    #[schema(value_type = Object)]
    pub logs: Value,
    pub is_test: bool,
}

/// Y10-T6: logs one run of `name`'s `version`: its cost, result and log
/// lines, each line with every value of `secrets` masked before it is
/// written.
#[allow(clippy::too_many_arguments)]
pub async fn record_run(
    db: &attome_db::DbPool,
    name: &str,
    version: i32,
    cost: attome_extension::CallCost,
    error: Option<&str>,
    logs: &[(attome_extension::Level, String)],
    secrets: &[&str],
    is_test: bool,
) -> Result<Uuid, AppError> {
    let lines: Vec<Value> = logs
        .iter()
        .map(|(level, line)| {
            json!({
                "level": format!("{level:?}").to_lowercase(),
                "message": attome_extension::mask_secrets(line, secrets),
            })
        })
        .collect();
    let error = error.map(|e| attome_extension::mask_secrets(e, secrets));
    sqlx::query_scalar(
        "INSERT INTO extension_run (extension_name, version, duration_ms, fuel_used, ok, error, logs, is_test) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(name)
    .bind(version)
    .bind(i32::try_from(cost.elapsed.as_millis()).unwrap_or(i32::MAX))
    .bind(i64::try_from(cost.fuel_used).unwrap_or(i64::MAX))
    .bind(error.is_none())
    .bind(&error)
    .bind(Value::Array(lines))
    .bind(is_test)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// An extension's runs
///
/// Y10-T6: the latest 200 runs, newest first, with time, fuel, result and
/// masked log lines.
#[utoipa::path(
    get,
    path = "/api/v1/admin/extensions/{name}/runs",
    operation_id = "list_extension_runs",
    tag = "admin",
    params(("name" = String, Path, description = "The extension")),
    responses(
        (status = 200, description = "The runs", body = PaginatedResponse<ExtensionRun>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn runs(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Automation>>,
    Path(name): Path<String>,
) -> Result<Json<PaginatedResponse<ExtensionRun>>, AppError> {
    let items: Vec<ExtensionRun> = sqlx::query_as(
        "SELECT id, version, started_at, duration_ms, fuel_used, ok, error, logs, is_test \
           FROM extension_run WHERE extension_name = $1 ORDER BY started_at DESC LIMIT 200",
    )
    .bind(&name)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

/// The most sample records one test run takes.
pub const MAX_TEST_SAMPLES: usize = 50;

/// Y10-T6: sample writes to run a version's hook on.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TestExtension {
    /// One to [`MAX_TEST_SAMPLES`] writes, each as the hook would be given
    /// it: `{stage, entity, values, previous?, is_create?, record_id?,
    /// actor?}`.
    #[schema(value_type = Vec<Object>)]
    pub samples: Vec<attome_extension::HookInput>,
}

/// What the hook answered for one sample.
#[derive(Debug, Serialize, ToSchema)]
pub struct TestOutcome {
    /// `"continue"`, `{"change": {...}}` or `{"reject": "..."}`; absent on
    /// an error.
    #[schema(value_type = Option<Object>)]
    pub answer: Option<Value>,
    pub error: Option<String>,
    pub fuel_used: i64,
    pub duration_ms: i64,
}

/// Test an extension version on sample records
///
/// Y10-T6: runs the version's `on_record` hook on each sample exactly as a
/// write would (only granted attributes, its changes held to its grants)
/// and saves nothing but the runs, logged as test runs. Any version may be
/// tested, drafts included.
#[utoipa::path(
    post,
    path = "/api/v1/admin/extensions/{name}/versions/{version}/test",
    operation_id = "test_extension",
    tag = "admin",
    params(
        ("name" = String, Path, description = "The extension"),
        ("version" = i32, Path, description = "The version"),
    ),
    request_body = TestExtension,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "runs a hook on sample records and saves only the run log"
    )))),
    responses(
        (status = 200, description = "One outcome per sample", body = PaginatedResponse<TestOutcome>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such version", body = ErrorResponse),
        (status = 422, description = "No samples, too many, or a stored manifest that does not parse", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn test_version(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Automation>>,
    Path((name, version)): Path<(String, i32)>,
    Json(body): Json<TestExtension>,
) -> Result<Json<PaginatedResponse<TestOutcome>>, AppError> {
    if body.samples.is_empty() || body.samples.len() > MAX_TEST_SAMPLES {
        return Err(AppError::Validation(format!(
            "samples holds 1 to {MAX_TEST_SAMPLES} writes"
        )));
    }
    let row: Option<(String, String, Value)> = sqlx::query_as(
        "SELECT module_key, module_sha256, manifest FROM extension WHERE name = $1 AND version = $2",
    )
    .bind(&name)
    .bind(version)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((key, sha, manifest)) = row else {
        return Err(AppError::NotFound);
    };
    let grants: attome_extension::Grants = serde_json::from_value(manifest)
        .map_err(|e| AppError::Validation(format!("the stored manifest: {e}")))?;
    let module = crate::extension_hooks::load(&state, &key, &sha).await?;
    let limits = attome_extension::Limits::from(&state.base.config.extensions);
    let mut items = Vec::with_capacity(body.samples.len());
    for sample in body.samples {
        let module = module.clone();
        let grants = grants.clone();
        let (answer, cost) =
            tokio::task::spawn_blocking(move || match attome_extension::Runtime::shared() {
                Ok(rt) => attome_extension::call_hook(rt, &module, &sample, &grants, &limits),
                Err(e) => (Err(e.to_string()), attome_extension::CallCost::default()),
            })
            .await
            .map_err(AppError::internal)?;
        let error = answer.as_ref().err().cloned();
        record_run(
            &state.base.db,
            &name,
            version,
            cost,
            error.as_deref(),
            &[],
            &[],
            true,
        )
        .await?;
        items.push(TestOutcome {
            answer: answer
                .ok()
                .map(|a| serde_json::to_value(a).unwrap_or(Value::Null)),
            error,
            fuel_used: i64::try_from(cost.fuel_used).unwrap_or(i64::MAX),
            duration_ms: i64::try_from(cost.elapsed.as_millis()).unwrap_or(i64::MAX),
        });
    }
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

/// A job extension's input.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct QueueExtensionJob {
    /// Given to the module's `on_job` export as `input`.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub input: Value,
}

/// Run a job extension
///
/// M17-T1: queues one run of the published extension's `on_job` export with
/// `input`, as the caller: the records it answers are written as the
/// caller through the generic write path.
#[utoipa::path(
    post,
    path = "/api/v1/admin/extensions/{name}/jobs",
    operation_id = "queue_extension_job",
    tag = "admin",
    params(("name" = String, Path, description = "The extension")),
    request_body = QueueExtensionJob,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("extension_kinds::run_kind -> entity_crud"),
        "queues the run; every record it writes goes through the audited generic write path \
         as the caller"
    )))),
    responses(
        (status = 202, description = "Queued"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No published version of that name", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn queue_job(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    Path(name): Path<String>,
    Json(body): Json<QueueExtensionJob>,
) -> Result<StatusCode, AppError> {
    if published(&state.base.db, &name).await?.is_none() {
        return Err(AppError::NotFound);
    }
    crate::extension_kinds::queue_job(
        &state,
        &crate::extension_kinds::ExtensionJobPayload {
            name,
            run_as: ctx.user_id,
            input: body.input,
        },
    )
    .await?;
    Ok(StatusCode::ACCEPTED)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/extensions", get(list).post(upload))
        .route(
            "/api/v1/admin/extensions/{name}/versions/{version}/publish",
            post(publish),
        )
        .route("/api/v1/admin/extensions/{name}/off", post(switch_off))
        .route("/api/v1/admin/extensions/{name}/runs", get(runs))
        .route("/api/v1/admin/extensions/{name}/jobs", post(queue_job))
        .route(
            "/api/v1/admin/extensions/{name}/versions/{version}/test",
            post(test_version),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list, upload, publish, switch_off, runs, test_version, queue_job))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_names_are_identifiers() {
        assert!(name_ok("erp_sync"));
        assert!(!name_ok("ERP"));
        assert!(!name_ok("_x"));
        assert!(!name_ok(""));
        assert!(!name_ok(&"x".repeat(64)));
    }
}
