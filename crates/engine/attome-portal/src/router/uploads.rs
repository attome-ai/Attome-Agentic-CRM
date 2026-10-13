//! Portal file uploads (D-774, web-portal plan Phase 5): the platform's one
//! file pipeline with a portal user as the session's owner.
//!
//! 1. `POST …/files/{field}/upload-session` opens a session and returns a
//!    presigned PUT to a quarantine key (`files::start_upload`).
//! 2. The browser PUTs the bytes to the object store, then
//!    `POST …/upload-session/{session_id}/finalize` verifies the size and
//!    enqueues the virus scan (`files::finalize_upload`).
//! 3. `GET …/upload-session/{session_id}` polls until the scan promotes the
//!    file (`clean`, with its `final_key`) or rejects it.
//! 4. An ordinary record `PATCH` names `final_key` on the field; the engine
//!    accepts only a clean session this portal user owns
//!    (`entity_mutation::lock_file_field_sessions`).
//!
//! Every route goes through the record routes' session, budget, consent and
//! plan path (I-18) and then `access_plan::plan_upload_target`: the field must
//! be a file the plan can write and the record live and in scope, else the
//! uniform 404. A child of [`super`].

use attome_core::EngineState;
use attome_document::files::{
    self, FileOwner, FinalizeResponse, SessionStatusResponse, UploadSessionRequest,
    UploadSessionResponse,
};
use attome_records::access_plan::{self, AccessPlan};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use uuid::Uuid;

use super::{budget, plan_for};

/// Uploads counted across every user of one portal (D-774 item 4), by
/// the same rule as the per-user cap (`files::PORTAL_QUOTA_SESSIONS`). A fixed
/// default; a per-portal policy column only when a customer needs one.
pub const PORTAL_UPLOAD_QUOTA_BYTES: i64 = 50 << 30;

/// Upload sessions one portal account may open per minute. A presigned PUT
/// can't bound the object's size (the quotas see the declared size), so how
/// many PUT URLs an account gets is the brake on quarantine storage; far
/// below the record write budget. Fails closed with the other budgets.
const ACCOUNT_UPLOAD_SESSIONS_RPM: i32 = 6;
/// Upload sessions a whole portal may open per minute.
const PORTAL_UPLOAD_SESSIONS_RPM: i32 = 60;

/// The per-portal cap. **Best effort**: it reads the total outside
/// `files::start_upload`'s transaction and holds no lock across the session
/// insert, so N uploads racing past the check can overshoot by up to N
/// sessions (bounded by the budgets above). The per-user cap
/// (`files::PORTAL_USER_UPLOAD_QUOTA_BYTES`) is enforced under a lock inside
/// `files::start_upload`.
async fn check_portal_quota(
    state: &EngineState,
    webportal_id: Uuid,
    new_bytes: i64,
) -> Result<(), AppError> {
    // Both fragments are constants, never input.
    let used: i64 = sqlx::query_scalar(&format!(
        "SELECT {counted} FROM upload_session s
         JOIN webportal_user u ON u.id = s.owner_portal_user_ref
         WHERE u.webportal_ref = $1 AND {sessions}",
        counted = files::PORTAL_QUOTA_COUNTED,
        sessions = files::PORTAL_QUOTA_SESSIONS,
    ))
    .bind(webportal_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if used.max(0).saturating_add(new_bytes.max(0)) > PORTAL_UPLOAD_QUOTA_BYTES {
        return Err(AppError::Validation(
            "this upload would exceed the portal's storage quota".into(),
        ));
    }
    Ok(())
}

fn owner(plan: &AccessPlan) -> FileOwner {
    FileOwner::Portal(plan.portal_user_id)
}

#[utoipa::path(
    post,
    operation_id = "portal_start_upload",
    path = "/{keyword}/api/v1/records/{entity}/{id}/files/{field}/upload-session",
    tag = "entity",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("entity" = String, Path, description = "Entity logical name"),
        ("id" = Uuid, Path, description = "Record id"),
        ("field" = String, Path, description = "A file field the caller's role can write"),
    ),
    request_body = UploadSessionRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("files_scan.rs / portal record update"), "only records upload intent; the scan result (FileScanned) and the record write naming the file (Entity/Update) are audited on their own paths")))),
    responses(
        (status = 200, description = "A session and a presigned PUT to its quarantine key", body = UploadSessionResponse),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such record, not in scope, or a field the caller can't write (indistinguishable)", body = ErrorResponse),
        (status = 409, description = "An upload for this field is already being created", body = ErrorResponse),
        (status = 422, description = "Content type or size not allowed, or a storage quota would be exceeded", body = ErrorResponse),
        (status = 429, description = "Too many upload sessions for this account or portal", body = ErrorResponse),
    ),
)]
async fn start_upload(
    State(state): State<EngineState>,
    Path((keyword, entity, id, field)): Path<(String, String, Uuid, String)>,
    headers: HeaderMap,
    Json(body): Json<UploadSessionRequest>,
) -> Result<Json<UploadSessionResponse>, AppError> {
    let access = plan_for(&state, &keyword, &entity, &headers, true).await?;
    let plan = &access.plan;
    access_plan::plan_upload_target(&state, plan, id, &field).await?;
    budget(
        &state,
        format!("attome-portal:rl:upload:{}", plan.webportal_id),
        PORTAL_UPLOAD_SESSIONS_RPM,
    )
    .await?;
    budget(
        &state,
        format!(
            "attome-portal:rl:upload:{}:{}",
            plan.webportal_id, plan.portal_user_id
        ),
        ACCOUNT_UPLOAD_SESSIONS_RPM,
    )
    .await?;
    check_portal_quota(&state, plan.webportal_id, body.declared_size_bytes).await?;
    Ok(Json(
        files::start_upload(&state, owner(plan), &plan.entity, id, &field, body).await?,
    ))
}

#[utoipa::path(
    post,
    operation_id = "portal_finalize_upload",
    path = "/{keyword}/api/v1/records/{entity}/{id}/files/{field}/upload-session/{session_id}/finalize",
    tag = "entity",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("entity" = String, Path, description = "Entity logical name"),
        ("id" = Uuid, Path, description = "Record id"),
        ("field" = String, Path, description = "A file field the caller's role can write"),
        ("session_id" = Uuid, Path, description = "The upload session"),
    ),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("files_scan.rs / portal record update"), "moves the session to uploaded and enqueues the scan; the scan result (FileScanned) and the record write naming the file (Entity/Update) are audited on their own paths")))),
    responses(
        (status = 200, description = "`uploaded` (the scan is queued) or `rejected`", body = FinalizeResponse),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such record, writable file field, or session of yours (indistinguishable)", body = ErrorResponse),
        (status = 409, description = "The session was already finalized", body = ErrorResponse),
    ),
)]
async fn finalize_upload(
    State(state): State<EngineState>,
    Path((keyword, entity, id, field, session_id)): Path<(String, String, Uuid, String, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<FinalizeResponse>, AppError> {
    let access = plan_for(&state, &keyword, &entity, &headers, true).await?;
    let plan = &access.plan;
    access_plan::plan_upload_target(&state, plan, id, &field).await?;
    Ok(Json(
        files::finalize_upload(&state, owner(plan), &plan.entity, id, &field, session_id).await?,
    ))
}

#[utoipa::path(
    get,
    operation_id = "portal_upload_status",
    path = "/{keyword}/api/v1/records/{entity}/{id}/files/{field}/upload-session/{session_id}",
    tag = "entity",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("entity" = String, Path, description = "Entity logical name"),
        ("id" = Uuid, Path, description = "Record id"),
        ("field" = String, Path, description = "A file field the caller's role can write"),
        ("session_id" = Uuid, Path, description = "The upload session"),
    ),
    responses(
        (status = 200, description = "The session's progress; once `clean`, `final_key` is the value to write on the record's field", body = SessionStatusResponse),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such record, writable file field, or session of yours (indistinguishable)", body = ErrorResponse),
    ),
)]
async fn upload_status(
    State(state): State<EngineState>,
    Path((keyword, entity, id, field, session_id)): Path<(String, String, Uuid, String, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<SessionStatusResponse>, AppError> {
    let access = plan_for(&state, &keyword, &entity, &headers, false).await?;
    let plan = &access.plan;
    access_plan::plan_upload_target(&state, plan, id, &field).await?;
    Ok(Json(
        files::upload_status(
            &state,
            owner(plan),
            false,
            &plan.entity,
            id,
            &field,
            session_id,
        )
        .await?,
    ))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/{keyword}/api/v1/records/{entity}/{id}/files/{field}/upload-session",
            post(start_upload),
        )
        .route(
            "/{keyword}/api/v1/records/{entity}/{id}/files/{field}/upload-session/{session_id}/finalize",
            post(finalize_upload),
        )
        .route(
            "/{keyword}/api/v1/records/{entity}/{id}/files/{field}/upload-session/{session_id}",
            get(upload_status),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(start_upload, finalize_upload, upload_status))]
pub(super) struct UploadsApiDoc;
