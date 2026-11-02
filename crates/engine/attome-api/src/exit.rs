//! Y5-T5 (V2-D1628 (4)): the clean exit. A deployment that is leaving takes
//! everything with it in open formats, then deletes everything, with a signed
//! certificate saying so.
//!
//! **Export.** `POST /api/v1/admin/exit/export` queues the [`EXPORT_JOB`];
//! it writes one zip to `exit/<id>/attome-exit-<id>.zip` in the deployment's
//! object store:
//!
//! - `data/<entity>.csv`: every row of every entity table, every physical
//!   column but retired ones (`COPY ... (FORMAT csv, HEADER)`);
//! - `metadata/bundle.json`: the metadata bundle (A22's `attome-bundle/v1`);
//! - `audit/audit_header.csv` and `audit/audit_detail.csv`: the audit log;
//! - `files/<key>`: every stored file but earlier exit archives;
//! - `README.txt`: what each part is.
//!
//! `GET /api/v1/admin/exit/export/{id}` answers progress and, once done, the
//! archive's SHA-256, size and a download link valid for a day.
//!
//! **Deletion.** `POST /api/v1/admin/exit/delete` names a finished export and
//! repeats its SHA-256 (proof the archive was fetched and checked). It asks
//! for an approval that two administrators other than the requester must
//! give (`system.admin` holders, two of them, N of M). The [`DELETE_JOB`]
//! then carries out each approved deletion once (the approval's execution
//! claim): it reads the audit chain's last hash and the approvers, deletes
//! every stored object, empties every table of the deployment's schema but
//! this one and the migration ledger, and writes the **deletion
//! certificate**: the export's id, hash and size, what was deleted, the
//! audit chain's final hash, who asked and who approved, signed with the
//! audit signing key (its public key inside, since the key registry is
//! emptied too). The certificate is kept on the export's row and written
//! beside the archive's place in the store, `exit/<id>/deletion-certificate.json`,
//! since nobody can sign in afterwards to read the row.
//!
//! Both routes need `system.admin` and are audited.

use std::path::{Path as FsPath, PathBuf};
use std::time::Duration;

use attome_audit::approval::gate_with_plan_regarding;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, audit_service};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use futures_util::StreamExt;
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use utoipa::ToSchema;
use uuid::Uuid;

/// The registered job that builds one export.
pub const EXPORT_JOB: &str = "exit_export";
/// The registered job that carries out approved deletions.
pub const DELETE_JOB: &str = "exit_delete";
/// The approval action a deletion waits on.
pub const ACTION_DELETE: &str = "deployment.exit_delete";
/// Where exports live in the store.
pub const PREFIX: &str = "exit";
/// Approvals a deletion needs, from administrators other than the requester.
pub const APPROVALS: i32 = 2;
/// How long a download link works.
const LINK_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Tables a deletion keeps: this one (the certificate) and the migration
/// ledgers.
pub const KEEP_TABLES: [&str; 3] = ["exit_export", "_sqlx_migrations", "schema_migrations"];
/// The certificate's format.
pub const CERTIFICATE_FORMAT: &str = "attome-exit-certificate/v1";

/// The export job's payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportPayload {
    pub export_id: Uuid,
}

/// An export as the routes show it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ExitExportView {
    pub id: Uuid,
    /// `queued`, `running`, `done`, `failed`, `deleting` or `deleted`.
    pub status: String,
    pub entities_total: i32,
    pub entities_done: i32,
    pub files_done: i32,
    pub sha256: Option<String>,
    pub bytes: Option<i64>,
    /// A link to the archive, valid for a day, once it is done.
    pub download_url: Option<String>,
    pub error: Option<String>,
    #[schema(value_type = Option<Object>)]
    pub certificate: Option<Value>,
}

/// `POST /api/v1/admin/exit/delete`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DeleteBody {
    pub export_id: Uuid,
    /// The SHA-256 of the downloaded archive, as the export reported it.
    pub export_sha256: String,
}

/// The approval a deletion waits on.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeleteRequested {
    pub approval_id: Uuid,
    pub approvals_needed: i32,
}

// ── Pure rules ──────────────────────────────────────────────────────────────

/// The tables a deletion empties: every table but [`KEEP_TABLES`]. Pure.
pub fn tables_to_empty(all: &[String]) -> Vec<String> {
    let mut out: Vec<String> = all
        .iter()
        .filter(|t| !KEEP_TABLES.contains(&t.as_str()))
        .cloned()
        .collect();
    out.sort();
    out
}

/// The archive's object key. Pure.
pub fn archive_key(id: Uuid) -> String {
    format!("{PREFIX}/{id}/attome-exit-{id}.zip")
}

/// Whether a deletion may be asked for this export. Pure.
pub fn check_delete(status: &str, sha256: Option<&str>, confirmed: &str) -> Result<(), AppError> {
    if status != "done" {
        return Err(AppError::Validation(format!(
            "the export is {status}; a deletion needs a finished export"
        )));
    }
    match sha256 {
        Some(hash) if hash.eq_ignore_ascii_case(confirmed.trim()) => Ok(()),
        _ => Err(AppError::Validation(
            "export_sha256 does not match the export: fetch and check the archive first".into(),
        )),
    }
}

/// The certificate body, without its signature. Pure.
#[allow(clippy::too_many_arguments)]
pub fn certificate_body(
    export_id: Uuid,
    export_sha256: &str,
    export_bytes: i64,
    deleted_at: chrono::DateTime<chrono::Utc>,
    tables_emptied: usize,
    objects_deleted: usize,
    audit_chain_final_hash: Option<&str>,
    requested_by: Uuid,
    approved_by: &[Uuid],
) -> Value {
    json!({
        "format": CERTIFICATE_FORMAT,
        "export_id": export_id,
        "export_sha256": export_sha256,
        "export_bytes": export_bytes,
        "deleted_at": deleted_at.to_rfc3339(),
        "deleted": {
            "tables_emptied": tables_emptied,
            "stored_objects": objects_deleted,
            "kept": KEEP_TABLES,
        },
        "audit_chain_final_hash": audit_chain_final_hash,
        "requested_by": requested_by,
        "approved_by": approved_by,
    })
}

/// The hash a certificate's signature covers: SHA-256 of its canonical
/// (sorted-key) JSON. Pure.
pub fn certificate_hash(body: &Value) -> String {
    let canonical = crate::changeset::jcs::canonicalize(body).unwrap_or_default();
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

// ── Export ──────────────────────────────────────────────────────────────────

async fn view(state: &EngineState, id: Uuid) -> Result<ExitExportView, AppError> {
    type Row = (
        String,
        i32,
        i32,
        i32,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<Value>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT status, entities_total, entities_done, files_done, object_key, sha256, bytes, \
                error, certificate FROM exit_export WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (status, total, done, files, key, sha256, bytes, error, certificate) =
        row.ok_or(AppError::NotFound)?;
    let download_url = match (status.as_str(), key) {
        ("done", Some(key)) => Some(
            attome_storage::presign_download(&state.base.storage, &key, LINK_TTL)
                .await
                .map_err(AppError::internal)?,
        ),
        _ => None,
    };
    Ok(ExitExportView {
        id,
        status,
        entities_total: total,
        entities_done: done,
        files_done: files,
        sha256,
        bytes,
        download_url,
        error,
        certificate,
    })
}

/// Start a clean-exit export
///
/// Queues an export of every record, the metadata, the audit log and every
/// file into one archive (Y5-T5). Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/exit/export",
    tag = "admin",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Export)])))),
    responses(
        (status = 202, description = "The export, queued", body = ExitExportView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "An export is already queued or running", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn start_export(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
) -> Result<(StatusCode, Json<ExitExportView>), AppError> {
    let id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let busy: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM exit_export WHERE status IN ('queued', 'running', 'deleting'))",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if busy {
        return Err(AppError::Conflict("an exit export is already under way"));
    }
    sqlx::query("INSERT INTO exit_export (id, requested_by) VALUES ($1, $2)")
        .bind(id)
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let job = attome_core::jobs::JOB_TYPES
        .job(EXPORT_JOB, &ExportPayload { export_id: id })
        .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Export,
            ctx.user_id,
            "exit_export",
            Some(id),
        )
        .named("deployment.exit_export_started"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::ACCEPTED, Json(view(&state, id).await?)))
}

/// Read a clean-exit export
///
/// Progress, and once done the archive's SHA-256, size and a download link
/// valid for a day; after a deletion, its certificate. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/exit/export/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The export")),
    responses(
        (status = 200, description = "The export", body = ExitExportView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such export", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_export(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<ExitExportView>, AppError> {
    Ok(Json(view(&state, id).await?))
}

async fn set_progress(state: &EngineState, id: Uuid, entities: i32, files: i32) {
    if let Err(error) = sqlx::query(
        "UPDATE exit_export SET entities_done = $2, files_done = $3, row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(entities)
    .bind(files)
    .execute(&state.base.db)
    .await
    {
        tracing::warn!(export = %id, %error, "exit export: progress not recorded");
    }
}

/// `COPY` of `table`'s physical columns (retired ones left out) to `file`.
async fn copy_table(state: &EngineState, table: &str, file: &FsPath) -> Result<(), AppError> {
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = $1 \
            AND column_name NOT LIKE '\\_\\_retired\\_%' ORDER BY ordinal_position",
    )
    .bind(table)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if columns.is_empty() {
        return Ok(());
    }
    let list = columns
        .iter()
        .map(|c| attome_core::quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "COPY (SELECT {list} FROM {}) TO STDOUT WITH (FORMAT csv, HEADER)",
        attome_core::quote_ident(table)
    );
    let mut out = tokio::fs::File::create(file)
        .await
        .map_err(AppError::internal)?;
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let mut stream = conn.copy_out_raw(&sql).await.map_err(AppError::internal)?;
    while let Some(chunk) = stream.next().await {
        out.write_all(&chunk.map_err(AppError::internal)?)
            .await
            .map_err(AppError::internal)?;
    }
    out.flush().await.map_err(AppError::internal)?;
    Ok(())
}

/// Writes every part of the export under `dir`; how many entities and files.
async fn gather(state: &EngineState, id: Uuid, dir: &FsPath) -> Result<(), AppError> {
    let tables: Vec<String> = {
        let registry = state.entities.load();
        let mut names: Vec<String> = registry
            .iter()
            .map(|meta| meta.logicalname.clone())
            .filter(|name| attome_db::ident::is_logical_name(name))
            .collect();
        names.sort();
        names.dedup();
        names
    };
    let existing: Vec<String> = sqlx::query_scalar(
        "SELECT tablename::text FROM pg_tables WHERE schemaname = current_schema()",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let tables: Vec<String> = tables
        .into_iter()
        .filter(|t| existing.contains(t))
        .collect();
    sqlx::query("UPDATE exit_export SET entities_total = $2 WHERE id = $1")
        .bind(id)
        .bind(i32::try_from(tables.len()).unwrap_or(i32::MAX))
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    for sub in ["data", "metadata", "audit", "files"] {
        tokio::fs::create_dir_all(dir.join(sub))
            .await
            .map_err(AppError::internal)?;
    }
    let mut done = 0;
    for table in &tables {
        copy_table(state, table, &dir.join("data").join(format!("{table}.csv"))).await?;
        done += 1;
        if done % 20 == 0 {
            set_progress(state, id, done, 0).await;
        }
    }
    set_progress(state, id, done, 0).await;

    let bundle = crate::bundle::export::export_bundle(&state.base.db_migrator).await?;
    let bundle = serde_json::to_vec_pretty(&bundle).map_err(AppError::internal)?;
    tokio::fs::write(dir.join("metadata").join("bundle.json"), bundle)
        .await
        .map_err(AppError::internal)?;
    for table in ["audit_header", "audit_detail"] {
        if existing.iter().any(|t| t == table) {
            copy_table(
                state,
                table,
                &dir.join("audit").join(format!("{table}.csv")),
            )
            .await?;
        }
    }

    let store = state.base.storage.store();
    let mut listing = store.list(None);
    let mut files = 0;
    while let Some(meta) = listing.next().await {
        let meta = meta.map_err(AppError::internal)?;
        let key = meta.location.to_string();
        if key.starts_with(&format!("{PREFIX}/"))
            || key.split('/').any(|p| p == ".." || p.is_empty())
        {
            continue;
        }
        let target = dir.join("files").join(&key);
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(AppError::internal)?;
        }
        let bytes = store
            .get(&meta.location)
            .await
            .map_err(AppError::internal)?
            .bytes()
            .await
            .map_err(AppError::internal)?;
        tokio::fs::write(&target, &bytes)
            .await
            .map_err(AppError::internal)?;
        files += 1;
        if files % 100 == 0 {
            set_progress(state, id, done, files).await;
        }
    }
    set_progress(state, id, done, files).await;
    tokio::fs::write(
        dir.join("README.txt"),
        "Attome clean-exit export.\n\
         data/<entity>.csv     every row of every entity, one CSV per entity, with a header row\n\
         metadata/bundle.json  the deployment's metadata (attome-bundle/v1)\n\
         audit/*.csv           the audit log\n\
         files/                every stored file, under its storage key\n",
    )
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Zips `dir` into `zip_path` (stored, zip64), off the runtime.
fn zip_dir(dir: &FsPath, zip_path: &FsPath) -> Result<(), String> {
    use std::io::Write;
    let file = std::fs::File::create(zip_path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipWriter::new(std::io::BufWriter::new(file));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true);
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&current)
            .map_err(|e| e.to_string())?
            .flatten()
            .map(|e| e.path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let name = path
                .strip_prefix(dir)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            zip.start_file(name, options).map_err(|e| e.to_string())?;
            let mut source = std::fs::File::open(&path).map_err(|e| e.to_string())?;
            std::io::copy(&mut source, &mut zip).map_err(|e| e.to_string())?;
        }
    }
    let mut inner = zip.finish().map_err(|e| e.to_string())?;
    inner.flush().map_err(|e| e.to_string())
}

/// Uploads `file` to `key`; its SHA-256 and size.
async fn upload(state: &EngineState, file: &FsPath, key: &str) -> Result<(String, i64), AppError> {
    use tokio::io::AsyncReadExt;
    let path = ObjectPath::parse(key).map_err(AppError::internal)?;
    let mut writer = object_store::buffered::BufWriter::new(state.base.storage.store_arc(), path);
    let mut source = tokio::fs::File::open(file)
        .await
        .map_err(AppError::internal)?;
    let mut hasher = Sha256::new();
    let mut total: i64 = 0;
    let mut buf = vec![0u8; 8 * 1024 * 1024];
    loop {
        let n = source.read(&mut buf).await.map_err(AppError::internal)?;
        if n == 0 {
            break;
        }
        let chunk = buf.get(..n).unwrap_or_default();
        hasher.update(chunk);
        writer.write_all(chunk).await.map_err(AppError::internal)?;
        total += i64::try_from(n).unwrap_or(0);
    }
    writer.shutdown().await.map_err(AppError::internal)?;
    Ok((hex::encode(hasher.finalize()), total))
}

/// The export job: builds and uploads the archive; the export's status.
pub async fn run_export(state: &EngineState, id: Uuid) -> Result<&'static str, AppError> {
    let claimed = sqlx::query(
        "UPDATE exit_export SET status = 'running', started_at = now(), \
                row_version = row_version + 1 WHERE id = $1 AND status = 'queued'",
    )
    .bind(id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if claimed.rows_affected() == 0 {
        return Ok("skipped");
    }
    let work = std::env::temp_dir().join(format!("attome-exit-{id}"));
    let zip_path = std::env::temp_dir().join(format!("attome-exit-{id}.zip"));
    let outcome = async {
        let _ = tokio::fs::remove_dir_all(&work).await;
        gather(state, id, &work).await?;
        let (dir, target) = (work.clone(), zip_path.clone());
        tokio::task::spawn_blocking(move || zip_dir(&dir, &target))
            .await
            .map_err(AppError::internal)?
            .map_err(AppError::internal)?;
        let key = archive_key(id);
        let (sha256, bytes) = upload(state, &zip_path, &key).await?;
        Ok::<_, AppError>((key, sha256, bytes))
    }
    .await;
    let _ = tokio::fs::remove_dir_all(&work).await;
    let _ = tokio::fs::remove_file(&zip_path).await;
    match outcome {
        Ok((key, sha256, bytes)) => {
            sqlx::query(
                "UPDATE exit_export SET status = 'done', finished_at = now(), object_key = $2, \
                        sha256 = $3, bytes = $4, row_version = row_version + 1 WHERE id = $1",
            )
            .bind(id)
            .bind(key)
            .bind(sha256)
            .bind(bytes)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok("done")
        }
        Err(error) => {
            tracing::error!(export = %id, %error, "exit export failed");
            sqlx::query(
                "UPDATE exit_export SET status = 'failed', finished_at = now(), error = $2, \
                        row_version = row_version + 1 WHERE id = $1",
            )
            .bind(id)
            .bind("the export failed; see the server log")
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok("failed")
        }
    }
}

// ── Deletion ────────────────────────────────────────────────────────────────

/// Every active user who holds `system.admin`, directly, through a role or
/// through a team's role.
pub(crate) async fn administrators(state: &EngineState) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT DISTINCT u.id FROM user_account u \
          WHERE COALESCE(u.is_active, true) AND u.id IN ( \
            SELECT up.user_ref FROM user_account_mm_privilege up \
              JOIN privilege p ON p.id = up.privilege_ref \
             WHERE p.key = 'system.admin' AND up.is_active = true AND p.is_active = true \
            UNION \
            SELECT ur.user_ref FROM user_account_mm_role ur \
              JOIN role_mm_privilege rp ON rp.role_ref = ur.role_ref AND rp.is_deleted = false \
              JOIN privilege p ON p.id = rp.privilege_ref \
             WHERE p.key = 'system.admin' AND ur.is_deleted = false AND p.is_active = true \
            UNION \
            SELECT ut.user_ref FROM user_account_mm_team ut \
              JOIN role_mm_team rt ON rt.team_ref = ut.team_ref AND rt.is_deleted = false \
              JOIN role_mm_privilege rp ON rp.role_ref = rt.role_ref AND rp.is_deleted = false \
              JOIN privilege p ON p.id = rp.privilege_ref \
             WHERE p.key = 'system.admin' AND ut.is_deleted = false AND p.is_active = true)",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Ask to delete the deployment
///
/// After a finished export whose SHA-256 the caller repeats, asks two other
/// administrators to approve deleting every record, file and piece of
/// metadata (Y5-T5). Nothing is deleted until they do. Administrators only.
/// Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/exit/delete",
    tag = "admin",
    request_body = DeleteBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, AuditOperation::Submitted)])))),
    responses(
        (status = 202, description = "The approval the deletion waits on", body = DeleteRequested),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such export", body = ErrorResponse),
        (status = 409, description = "A deletion of this export is already asked for", body = ErrorResponse),
        (status = 422, description = "The export is not finished, the hash does not match, or there are not two other administrators", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn request_delete(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<DeleteBody>,
) -> Result<(StatusCode, Json<DeleteRequested>), AppError> {
    let row: Option<(String, Option<String>, Option<Uuid>)> =
        sqlx::query_as("SELECT status, sha256, approval_request_id FROM exit_export WHERE id = $1")
            .bind(body.export_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let (status, sha256, pending) = row.ok_or(AppError::NotFound)?;
    if pending.is_some() {
        return Err(AppError::Conflict(
            "a deletion of this export is already asked for",
        ));
    }
    check_delete(&status, sha256.as_deref(), &body.export_sha256)?;
    let approvers: Vec<String> = administrators(&state)
        .await?
        .into_iter()
        .filter(|id| *id != ctx.user_id)
        .map(|id| format!("user:{id}"))
        .collect();
    if approvers.len() < usize::try_from(APPROVALS).unwrap_or(2) {
        return Err(AppError::Validation(
            "a deletion needs two other administrators to approve it".into(),
        ));
    }
    let plan = attome_approval::ApprovalPlan {
        steps: vec![attome_approval::ApprovalStep {
            mode: attome_approval::StepMode::NofM,
            threshold: Some(APPROVALS),
            approvers,
            sla_minutes: None,
            on_timeout: attome_approval::OnTimeout::Escalate,
            extras: Default::default(),
        }],
    };
    let request = gate_with_plan_regarding(
        &state,
        ACTION_DELETE,
        json!({ "export_id": body.export_id, "export_sha256": sha256 }),
        ctx.user_id,
        plan,
        None,
    )
    .await?;
    let updated = sqlx::query(
        "UPDATE exit_export SET approval_request_id = $2, row_version = row_version + 1 \
          WHERE id = $1 AND approval_request_id IS NULL",
    )
    .bind(body.export_id)
    .bind(request.id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "a deletion of this export is already asked for",
        ));
    }
    tracing::warn!(export = %body.export_id, approval = %request.id, "deployment deletion requested");
    Ok((
        StatusCode::ACCEPTED,
        Json(DeleteRequested {
            approval_id: request.id,
            approvals_needed: APPROVALS,
        }),
    ))
}

/// Carries out every approved deletion; how many ran.
pub async fn run_approved_deletions(state: &EngineState) -> Result<usize, AppError> {
    let waiting: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM approval_request \
          WHERE action_type = $1 AND status = 'approved' AND executed_at IS NULL \
          ORDER BY requested_at LIMIT 1",
    )
    .bind(ACTION_DELETE)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut ran = 0;
    for id in waiting {
        if delete_one(state, id).await? {
            ran += 1;
        }
    }
    Ok(ran)
}

async fn delete_one(state: &EngineState, approval: Uuid) -> Result<bool, AppError> {
    let db = &state.base.db;
    let request = attome_approval::get(db, approval)
        .await
        .map_err(AppError::internal)?;
    if request.status != attome_approval::ApprovalStatus::Approved || request.executed_at.is_some()
    {
        return Ok(false);
    }
    let claimed = match attome_approval::claim_execution(
        db,
        request.id,
        request.row_version,
        attome_approval::POLICY_ACTOR_ID,
    )
    .await
    {
        Ok(claimed) => claimed,
        Err(AppError::Conflict(_)) => return Ok(false),
        Err(e) => return Err(e),
    };
    let export_id = claimed.payload["export_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::internal("an exit deletion names no export"))?;
    let row: Option<(String, Option<String>, Option<i64>, Uuid)> =
        sqlx::query_as("SELECT status, sha256, bytes, requested_by FROM exit_export WHERE id = $1")
            .bind(export_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let Some((status, Some(sha256), bytes, _)) = row else {
        return Err(AppError::internal(
            "an approved exit deletion's export is missing",
        ));
    };
    if status != "done" {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE exit_export SET status = 'deleting', row_version = row_version + 1 WHERE id = $1",
    )
    .bind(export_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?;

    // What the certificate needs, read before it is gone.
    let approved_by: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT COALESCE(decided_by, approver_id) FROM approval_grant \
          WHERE request_id = $1 AND decision = 'approved'",
    )
    .bind(approval)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let audit_final: Option<String> = sqlx::query_scalar(
        "SELECT event_hash FROM audit_header WHERE event_hash <> '' \
          ORDER BY event_index DESC NULLS LAST, changed_on DESC NULLS LAST LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    // The files, the archive included.
    let store = state.base.storage.store();
    let keys: Vec<ObjectPath> = store
        .list(None)
        .filter_map(|meta| async move { meta.ok().map(|m| m.location) })
        .collect()
        .await;
    let mut objects = 0;
    for key in &keys {
        match store.delete(key).await {
            Ok(()) => objects += 1,
            Err(error) => {
                tracing::error!(%key, %error, "exit deletion: a stored object was not deleted")
            }
        }
    }

    // Every table but the kept ones, in one statement.
    let all: Vec<String> = sqlx::query_scalar(
        "SELECT tablename::text FROM pg_tables WHERE schemaname = current_schema()",
    )
    .fetch_all(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;
    let tables = tables_to_empty(&all);
    if !tables.is_empty() {
        let list = tables
            .iter()
            .map(|t| attome_core::quote_ident(t))
            .collect::<Vec<_>>()
            .join(", ");
        let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;
        sqlx::query("SET LOCAL lock_timeout = '30s'")
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        sqlx::query(&format!("TRUNCATE TABLE {list} CASCADE"))
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
    }

    let deleted_at = chrono::Utc::now();
    let mut certificate = certificate_body(
        export_id,
        &sha256,
        bytes.unwrap_or(0),
        deleted_at,
        tables.len(),
        objects,
        audit_final.as_deref(),
        claimed.requested_by,
        &approved_by,
    );
    let hash = certificate_hash(&certificate);
    certificate["sha256"] = json!(hash);
    match state.audit_signer.as_deref() {
        Some(signer) => {
            certificate["signature"] = json!(signer.sign(CERTIFICATE_FORMAT, &hash));
            certificate["key_id"] = json!(signer.key_id);
            certificate["verifying_key"] = json!(signer.verifying_key_b64());
        }
        None => certificate["signature"] = Value::Null,
    }
    sqlx::query(
        "UPDATE exit_export SET status = 'deleted', deleted_at = $2, certificate = $3, \
                row_version = row_version + 1 WHERE id = $1",
    )
    .bind(export_id)
    .bind(deleted_at)
    .bind(&certificate)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    let key = ObjectPath::parse(format!("{PREFIX}/{export_id}/deletion-certificate.json"))
        .map_err(AppError::internal)?;
    let bytes = serde_json::to_vec_pretty(&certificate).map_err(AppError::internal)?;
    if let Err(error) = store.put(&key, bytes.into()).await {
        tracing::error!(%error, "exit deletion: the certificate is on the export row only");
    }
    tracing::warn!(export = %export_id, certificate = %hash, "deployment deleted after its clean exit");
    Ok(true)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/exit/export", post(start_export))
        .route("/api/v1/admin/exit/export/{id}", get(get_export))
        .route("/api/v1/admin/exit/delete", post(request_delete))
}

/// This file's slice of the OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(start_export, get_export, request_delete))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_keeps_the_certificate_table() {
        let all = vec![
            "account".to_owned(),
            "exit_export".to_owned(),
            "_sqlx_migrations".to_owned(),
            "audit_header".to_owned(),
        ];
        assert_eq!(tables_to_empty(&all), vec!["account", "audit_header"]);
    }

    #[test]
    fn deletion_needs_a_finished_checked_export() {
        assert!(check_delete("running", Some("ab"), "ab").is_err());
        assert!(check_delete("done", Some("abcd"), "ABCD ").is_ok());
        assert!(check_delete("done", Some("abcd"), "abce").is_err());
        assert!(check_delete("done", None, "abcd").is_err());
    }

    #[test]
    fn certificate_hash_is_stable() {
        let id = Uuid::from_u128(7);
        let at = chrono::DateTime::parse_from_rfc3339("2026-11-02T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let body = certificate_body(id, "aa", 10, at, 3, 4, Some("ff"), id, &[id]);
        assert_eq!(certificate_hash(&body), certificate_hash(&body.clone()));
        assert_eq!(body["deleted"]["tables_emptied"], 3);
        assert_eq!(archive_key(id), format!("exit/{id}/attome-exit-{id}.zip"));
    }
}
