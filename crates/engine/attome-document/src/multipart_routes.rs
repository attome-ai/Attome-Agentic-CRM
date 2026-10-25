//! Resumable multipart uploads for large files (roadmap Z6-T2).
//!
//! A multipart upload is an ordinary upload session (`files::start_upload`)
//! whose quarantine object arrives in parts:
//!
//! - `POST /api/v1/{entity}/{id}/files/{field}/multipart` opens the session
//!   with the same checks as a single upload and says how many parts of
//!   what size to send.
//! - `PUT /api/v1/files/uploads/{session_id}/parts/{n}` gives a presigned
//!   PUT for part `n`; the bytes go straight to the object store.
//! - `GET /api/v1/files/uploads/{session_id}` lists the parts that arrived,
//!   so an interrupted client resumes with only the missing ones.
//! - `POST .../complete` assembles the parts into the quarantine object; the
//!   session's ordinary finalize and scan then take over.
//! - `DELETE .../{session_id}` abandons it and removes the parts.
//!
//! Only the person who opened the upload may send to it. An open multipart
//! upload lives 24 hours ([`MULTIPART_TTL_HOURS`]); the session prune leaves
//! it alone until then and removes its parts after.

use std::time::Duration;

use attome_core::EngineState;
use attome_security::RecordAction;
use attome_security::record_action::Update;
use attome_server::authz::{Authorized, RecordScoped, SelfService};
use attome_server::capability::{Available, ObjectStorage};
use attome_storage::multipart;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::files::{FileOwner, UploadSessionRequest};

/// How long an open multipart upload may take, in hours.
pub const MULTIPART_TTL_HOURS: i64 = 24;

/// How long a part's presigned PUT stays valid.
const PART_URL_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Serialize, ToSchema)]
pub struct MultipartStarted {
    pub session_id: Uuid,
    /// Every part but the last is this many bytes.
    pub part_size: u64,
    pub part_count: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PartUpload {
    pub part: u32,
    /// PUT the part's bytes here.
    pub upload_url: String,
    pub expires_in_secs: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MultipartStatus {
    pub session_id: Uuid,
    /// `open`, `assembled` or `aborted`.
    pub status: String,
    pub part_size: u64,
    pub part_count: u32,
    /// The parts that arrived, by number.
    pub received: Vec<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MultipartAssembled {
    pub session_id: Uuid,
    pub size: u64,
    /// Lowercase hex SHA-256 of the assembled file.
    pub checksum_sha256: String,
}

/// An open multipart upload the caller owns: its quarantine key, declared
/// size, declared checksum, part count and status.
struct Owned {
    key: String,
    size: u64,
    declared_checksum: Option<String>,
    part_size: u64,
    part_count: u32,
    status: String,
}

async fn owned(state: &EngineState, user_id: Uuid, session_id: Uuid) -> Result<Owned, AppError> {
    let row: Option<(String, i64, Option<String>, i64, i32, String, Option<Uuid>)> =
        sqlx::query_as(
            "SELECT s.quarantine_key, s.declared_max_size_bytes, s.declared_checksum_sha256, \
                    m.part_size, m.part_count, m.status, s.owner_user_ref \
               FROM upload_multipart m JOIN upload_session s ON s.id = m.session_id \
              WHERE m.session_id = $1",
        )
        .bind(session_id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let (key, size, declared_checksum, part_size, part_count, status, owner) =
        row.ok_or(AppError::NotFound)?;
    // Someone else's upload is not there for this caller.
    if owner != Some(user_id) {
        return Err(AppError::NotFound);
    }
    Ok(Owned {
        key,
        size: u64::try_from(size).map_err(AppError::internal)?,
        declared_checksum,
        part_size: u64::try_from(part_size).map_err(AppError::internal)?,
        part_count: u32::try_from(part_count).map_err(AppError::internal)?,
        status,
    })
}

fn storage(e: attome_storage::StorageError) -> AppError {
    AppError::internal(e)
}

/// Start a multipart upload
///
/// Opens an upload session for a large file sent in parts, with the same
/// checks as a single upload (record access, check-out, type, size and
/// quota), and says how many parts of what size to send. Needs update
/// access to the record.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/files/{field}/multipart",
    tag = "entity",
    operation_id = "start_multipart_upload",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ("field" = String, Path, description = "The file field"),
    ),
    request_body = UploadSessionRequest,
    responses(
        (status = 200, description = "The session and its parts", body = MultipartStarted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller cannot update the record", body = ErrorResponse),
        (status = 409, description = "The file is checked out by someone else, or a session is being created", body = ErrorResponse),
        (status = 422, description = "A type, size or checksum the field does not take, or more than 10,000 parts", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(
        ("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("files_scan.rs / entity_crud update"), "only records upload intent, as the single upload session does; the scan result and the field promotion are audited on their own paths"))),
        ("x-body-limit" = json!(65_536)),
        ("x-auth" = json!("session")),
        ("x-idempotent" = json!(false)),
    ),
)]
async fn start_multipart(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    _storage: Available<ObjectStorage>,
    Path((entity_input, record_id, field_input)): Path<(String, Uuid, String)>,
    Json(body): Json<UploadSessionRequest>,
) -> Result<Json<MultipartStarted>, AppError> {
    let size = u64::try_from(body.declared_size_bytes)
        .map_err(|_| AppError::Validation("declared_size_bytes must be positive".into()))?;
    let part_count = multipart::part_count(size).ok_or_else(|| {
        AppError::Validation(format!(
            "a multipart upload has at most {} parts of {} bytes",
            multipart::MAX_PARTS,
            multipart::PART_SIZE
        ))
    })?;
    let (entity_id, entity_name, field_name) =
        crate::files::resolve_file_field(&state, &entity_input, &field_input).await?;
    attome_records::entity_crud::require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Update,
    )
    .await?;
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    if attome_records::entity_mutation::file_checked_out_by_other(
        &mut conn,
        &entity_name,
        record_id,
        std::slice::from_ref(&field_name),
        Some(ctx.user_id),
    )
    .await?
    .is_some()
    {
        return Err(AppError::Conflict(
            "the file is checked out by someone else; it can change after check-in",
        ));
    }
    drop(conn);
    let started = crate::files::start_upload(
        &state,
        FileOwner::Staff(ctx.user_id),
        &entity_name,
        record_id,
        &field_name,
        body,
    )
    .await?;
    sqlx::query(
        "INSERT INTO upload_multipart (session_id, part_size, part_count) VALUES ($1, $2, $3)",
    )
    .bind(started.session_id)
    .bind(i64::try_from(multipart::PART_SIZE).map_err(AppError::internal)?)
    .bind(i32::try_from(part_count).map_err(AppError::internal)?)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(MultipartStarted {
        session_id: started.session_id,
        part_size: multipart::PART_SIZE,
        part_count,
    }))
}

/// Get a part's upload link
///
/// A presigned PUT for part `n` (1-based) of an open multipart upload the
/// caller started; sending a part again replaces it. Only the person who
/// started the upload.
#[utoipa::path(
    put,
    path = "/api/v1/files/uploads/{session_id}/parts/{n}",
    tag = "entity",
    operation_id = "multipart_part_url",
    params(
        ("session_id" = Uuid, Path, description = "The upload session"),
        ("n" = u32, Path, description = "The part number, from 1"),
    ),
    responses(
        (status = 200, description = "Where to PUT the part", body = PartUpload),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No open multipart upload of the caller's", body = ErrorResponse),
        (status = 409, description = "The upload is no longer open", body = ErrorResponse),
        (status = 422, description = "No such part number", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("files_scan.rs / entity_crud update"), "issues an upload link and writes nothing")))),
)]
async fn part_url(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    _storage: Available<ObjectStorage>,
    Path((session_id, n)): Path<(Uuid, u32)>,
) -> Result<Json<PartUpload>, AppError> {
    let upload = owned(&state, ctx.user_id, session_id).await?;
    if upload.status != "open" {
        return Err(AppError::Conflict(
            "this multipart upload is no longer open",
        ));
    }
    if n == 0 || n > upload.part_count {
        return Err(AppError::Validation(format!(
            "parts are numbered 1 to {}",
            upload.part_count
        )));
    }
    let upload_url = attome_storage::presign_upload(
        &state.base.storage,
        &multipart::part_key(&upload.key, n),
        PART_URL_TTL,
    )
    .await
    .map_err(storage)?;
    Ok(Json(PartUpload {
        part: n,
        upload_url,
        expires_in_secs: PART_URL_TTL.as_secs(),
    }))
}

/// A multipart upload's progress
///
/// The parts of a multipart upload that have arrived, so a client resumes
/// with only the missing ones. Only the person who started the upload.
#[utoipa::path(
    get,
    path = "/api/v1/files/uploads/{session_id}",
    tag = "entity",
    operation_id = "multipart_status",
    params(("session_id" = Uuid, Path, description = "The upload session")),
    responses(
        (status = 200, description = "The upload and the parts received", body = MultipartStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No multipart upload of the caller's", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn status(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<MultipartStatus>, AppError> {
    let upload = owned(&state, ctx.user_id, session_id).await?;
    let received = if upload.status == "open" {
        multipart::parts_present(&state.base.storage, &upload.key)
            .await
            .map_err(storage)?
            .into_keys()
            .filter(|n| (1..=upload.part_count).contains(n))
            .collect()
    } else {
        Vec::new()
    };
    Ok(Json(MultipartStatus {
        session_id,
        status: upload.status,
        part_size: upload.part_size,
        part_count: upload.part_count,
        received,
    }))
}

/// Complete a multipart upload
///
/// Checks every part arrived with the right length, assembles them into the
/// upload's file and removes the parts; finalize the upload session next, as
/// for a single upload. A declared checksum must match. Only the person who
/// started the upload.
#[utoipa::path(
    post,
    path = "/api/v1/files/uploads/{session_id}/complete",
    tag = "entity",
    operation_id = "complete_multipart_upload",
    params(("session_id" = Uuid, Path, description = "The upload session")),
    responses(
        (status = 200, description = "The assembled file's size and checksum", body = MultipartAssembled),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No multipart upload of the caller's", body = ErrorResponse),
        (status = 409, description = "The upload is no longer open", body = ErrorResponse),
        (status = 422, description = "Parts missing or of the wrong length, or a checksum that does not match", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("files_scan.rs / entity_crud update"), "assembles the quarantine object; the scan result and the field promotion are audited on their own paths")))),
)]
async fn complete(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    _storage: Available<ObjectStorage>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<MultipartAssembled>, AppError> {
    let upload = owned(&state, ctx.user_id, session_id).await?;
    if upload.status != "open" {
        return Err(AppError::Conflict(
            "this multipart upload is no longer open",
        ));
    }
    let present = multipart::parts_present(&state.base.storage, &upload.key)
        .await
        .map_err(storage)?;
    if let Some(problem) = multipart::missing_or_wrong(&present, upload.size) {
        return Err(AppError::Validation(problem));
    }
    let assembled = multipart::assemble(&state.base.storage, &upload.key, upload.part_count)
        .await
        .map_err(storage)?;
    if let Some(declared) = &upload.declared_checksum
        && !declared.eq_ignore_ascii_case(&assembled.sha256)
    {
        attome_storage::mirror::delete_object(&state.base.storage, &upload.key)
            .await
            .map_err(storage)?;
        return Err(AppError::Validation(
            "the assembled file does not match checksum_sha256".into(),
        ));
    }
    let updated = sqlx::query(
        "UPDATE upload_multipart SET status = 'assembled', checksum_sha256 = $2, \
                assembled_at = now() \
          WHERE session_id = $1 AND status = 'open'",
    )
    .bind(session_id)
    .bind(&assembled.sha256)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "this multipart upload is no longer open",
        ));
    }
    if let Err(error) = multipart::discard(&state.base.storage, &upload.key).await {
        // The file is whole and recorded; leftover parts only cost storage
        // until the prune removes them.
        tracing::warn!(%session_id, %error, "multipart upload: parts left after assembly");
    }
    Ok(Json(MultipartAssembled {
        session_id,
        size: assembled.size,
        checksum_sha256: assembled.sha256,
    }))
}

/// Abandon a multipart upload
///
/// Stops a multipart upload and removes the parts that arrived. Only the
/// person who started the upload.
#[utoipa::path(
    delete,
    path = "/api/v1/files/uploads/{session_id}",
    tag = "entity",
    operation_id = "abort_multipart_upload",
    params(("session_id" = Uuid, Path, description = "The upload session")),
    responses(
        (status = 204, description = "Abandoned"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No multipart upload of the caller's", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("files_scan.rs"), "abandons an upload that never became a file; nothing it removes was ever attached")))),
)]
async fn abort(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let upload = owned(&state, ctx.user_id, session_id).await?;
    abort_upload(&state, session_id, &upload.key).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Marks the multipart upload `session_id` aborted, expires its pending
/// session and removes its parts.
async fn abort_upload(state: &EngineState, session_id: Uuid, key: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE upload_multipart SET status = 'aborted' WHERE session_id = $1 AND status = 'open'",
    )
    .bind(session_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE upload_session SET status = 'expired', updated_at = NOW(), \
                row_version = row_version + 1 \
          WHERE id = $1 AND status = 'pending'",
    )
    .bind(session_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    multipart::discard(&state.base.storage, key)
        .await
        .map_err(storage)
}

/// Part of the session prune: aborts open multipart uploads older than
/// [`MULTIPART_TTL_HOURS`] and removes their parts.
pub async fn prune_stale_multipart(state: &EngineState) -> Result<(), AppError> {
    let stale: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT m.session_id, s.quarantine_key FROM upload_multipart m \
           JOIN upload_session s ON s.id = m.session_id \
          WHERE m.status = 'open' AND m.created_at < now() - make_interval(hours => $1) \
          ORDER BY m.created_at LIMIT 200",
    )
    .bind(i32::try_from(MULTIPART_TTL_HOURS).unwrap_or(24))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for (session_id, key) in stale {
        if let Err(error) = abort_upload(state, session_id, &key).await {
            tracing::warn!(%session_id, %error, "multipart prune: could not abort; next sweep retries");
        }
    }
    Ok(())
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/{entity}/{id}/files/{field}/multipart",
            post(start_multipart),
        )
        .route(
            "/api/v1/files/uploads/{session_id}",
            get(status).delete(abort),
        )
        .route(
            "/api/v1/files/uploads/{session_id}/parts/{n}",
            put(part_url),
        )
        .route(
            "/api/v1/files/uploads/{session_id}/complete",
            post(complete),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(start_multipart, part_url, status, complete, abort),
    components(schemas(MultipartStarted, PartUpload, MultipartStatus, MultipartAssembled))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
