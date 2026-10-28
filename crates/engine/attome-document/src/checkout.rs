//! K1-T2: check-out and check-in of a record's file.
//!
//! `POST /api/v1/{entity}/{id}/files/{field}/checkout` takes the lock for the
//! caller (again by the same person is a no-op); while it is held, nobody
//! else may store a new version of that file — the upload session refuses
//! to start and the record write refuses the new key, administrators
//! included (`attome_records::entity_mutation::file_checked_out_by_other`).
//! The holder checks in by storing the new version and then
//! `DELETE …/checkout`, which releases it; an administrator may break
//! someone else's lock with `?force=true`. Taking, releasing and breaking a
//! lock are audited.

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, audit_service,
    fetch_audit_ctx,
};
use attome_core::EngineState;
use attome_records::entity_crud::require_record_access;
use attome_security::RecordAction;
use attome_security::record_action::{Read, Update};
use attome_server::authz::{Authorized, RecordScoped};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::post,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Who holds a file's check-out.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct FileCheckout {
    pub checked_out_by: Uuid,
    pub checked_out_at: DateTime<Utc>,
    pub note: Option<String>,
}

/// `GET …/checkout`: the lock, when one is held.
#[derive(Debug, Serialize, ToSchema)]
pub struct FileCheckoutStatus {
    pub checkout: Option<FileCheckout>,
    /// Whether the caller holds it.
    pub held_by_me: bool,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct CheckoutRequest {
    /// Why it is checked out, shown to others (at most 500 characters).
    pub note: Option<String>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CheckinQuery {
    /// An administrator breaks someone else's lock.
    #[serde(default)]
    pub force: bool,
}

async fn resolve(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    entity_input: &str,
    record_id: Uuid,
    field_input: &str,
    action: RecordAction,
) -> Result<(String, String), AppError> {
    let (entity_id, entity, field) =
        crate::files::resolve_file_field(state, entity_input, field_input).await?;
    require_record_access(state, ctx, entity_id, &entity, record_id, action).await?;
    Ok((entity, field))
}

async fn current(
    state: &EngineState,
    entity: &str,
    record_id: Uuid,
    field: &str,
) -> Result<Option<FileCheckout>, AppError> {
    sqlx::query_as(
        "SELECT checked_out_by, checked_out_at, note FROM file_checkout \
          WHERE entity = $1 AND record_id = $2 AND field = $3",
    )
    .bind(entity)
    .bind(record_id)
    .bind(field)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

#[allow(clippy::too_many_arguments)]
async fn audit(
    state: &EngineState,
    tx: &mut attome_db::Tx<'_>,
    actor: Uuid,
    entity: &str,
    record_id: Uuid,
    field: &str,
    comment: String,
) -> Result<(), AppError> {
    let (user_context, organization_ref) = fetch_audit_ctx(state, actor).await;
    audit_service(state)
        .write_in_tx(
            tx,
            AuditEvent {
                organization_ref,
                category: AuditCategory::Attachment,
                entity_name: Some(entity.to_owned()),
                record_id: Some(record_id),
                operation: AuditOperation::Update,
                version_before: None,
                version_after: None,
                user_context,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some(field.to_owned()),
                event_comment: Some(comment),
                changed_fields: Vec::new(),
                snapshot_json: None,
            },
        )
        .await?;
    Ok(())
}

/// Read a file's check-out
///
/// Who holds the lock on the file, since when and with what note, and whether it is the caller.
/// Anyone who may read the record.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/files/{field}/checkout",
    tag = "entity",
    operation_id = "get_file_checkout",
    params(("entity" = String, Path, description = "The entity's logical name"), ("id" = Uuid, Path, description = "The record"), ("field" = String, Path, description = "The file field")),
    responses(
        (status = 200, description = "Who holds the file's check-out, if anyone", body = FileCheckoutStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not read the record", body = ErrorResponse),
        (status = 404, description = "No such record or field", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_checkout(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id, field_input)): Path<(String, Uuid, String)>,
) -> Result<Json<FileCheckoutStatus>, AppError> {
    let (entity, field) = resolve(
        &state,
        &ctx,
        &entity_input,
        record_id,
        &field_input,
        RecordAction::Read,
    )
    .await?;
    let checkout = current(&state, &entity, record_id, &field).await?;
    let held_by_me = checkout
        .as_ref()
        .is_some_and(|c| c.checked_out_by == ctx.user_id);
    Ok(Json(FileCheckoutStatus {
        checkout,
        held_by_me,
    }))
}

/// Check out a record's file
///
/// Takes the lock on the file for the caller (taking it again is a no-op); while it is held nobody
/// else, administrators included, may store a new version. Needs update rights on the record. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/files/{field}/checkout",
    tag = "entity",
    operation_id = "check_out_file",
    params(("entity" = String, Path, description = "The entity's logical name"), ("id" = Uuid, Path, description = "The record"), ("field" = String, Path, description = "The file field")),
    request_body = CheckoutRequest,
    responses(
        (status = 200, description = "Checked out to the caller", body = FileCheckout),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not change the record", body = ErrorResponse),
        (status = 404, description = "No such record or field", body = ErrorResponse),
        (status = 409, description = "Someone else has it checked out", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Attachment, attome_audit::AuditOperation::Update)])))),
)]
async fn check_out(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Path((entity_input, record_id, field_input)): Path<(String, Uuid, String)>,
    Json(body): Json<CheckoutRequest>,
) -> Result<Json<FileCheckout>, AppError> {
    let (entity, field) = resolve(
        &state,
        &ctx,
        &entity_input,
        record_id,
        &field_input,
        RecordAction::Update,
    )
    .await?;
    let note = body
        .note
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty());
    if note.is_some_and(|n| n.chars().count() > 500) {
        return Err(AppError::Validation(
            "note must be at most 500 characters".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // Taken only when free; the primary key settles two people racing.
    let taken: Option<FileCheckout> = sqlx::query_as(
        "INSERT INTO file_checkout (entity, record_id, field, checked_out_by, note) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (entity, record_id, field) DO NOTHING \
         RETURNING checked_out_by, checked_out_at, note",
    )
    .bind(&entity)
    .bind(record_id)
    .bind(&field)
    .bind(ctx.user_id)
    .bind(note)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(taken) = taken else {
        drop(tx);
        return match current(&state, &entity, record_id, &field).await? {
            Some(held) if held.checked_out_by == ctx.user_id => Ok(Json(held)),
            _ => Err(AppError::Conflict(
                "the file is already checked out by someone else",
            )),
        };
    };
    audit(
        &state,
        &mut tx,
        ctx.user_id,
        &entity,
        record_id,
        &field,
        "file checked out".to_owned(),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(taken))
}

/// Check in a record's file
///
/// Releases the caller's lock after storing the new version; an administrator may break someone
/// else's lock with `force=true`. Needs update rights on the record. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/{entity}/{id}/files/{field}/checkout",
    tag = "entity",
    operation_id = "check_in_file",
    params(("entity" = String, Path, description = "The entity's logical name"), ("id" = Uuid, Path, description = "The record"), ("field" = String, Path, description = "The file field"), CheckinQuery),
    responses(
        (status = 204, description = "Released"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Someone else holds it and the caller is not an administrator breaking it", body = ErrorResponse),
        (status = 404, description = "Not checked out", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Attachment, attome_audit::AuditOperation::Update)])))),
)]
async fn check_in(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Path((entity_input, record_id, field_input)): Path<(String, Uuid, String)>,
    Query(query): Query<CheckinQuery>,
) -> Result<StatusCode, AppError> {
    let (entity, field) = resolve(
        &state,
        &ctx,
        &entity_input,
        record_id,
        &field_input,
        RecordAction::Update,
    )
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let holder: Option<Uuid> = sqlx::query_scalar(
        "SELECT checked_out_by FROM file_checkout \
          WHERE entity = $1 AND record_id = $2 AND field = $3 FOR UPDATE",
    )
    .bind(&entity)
    .bind(record_id)
    .bind(&field)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let holder = holder.ok_or(AppError::NotFound)?;
    let breaking = holder != ctx.user_id;
    if breaking && !(query.force && ctx.is_admin) {
        return Err(AppError::Forbidden);
    }
    sqlx::query("DELETE FROM file_checkout WHERE entity = $1 AND record_id = $2 AND field = $3")
        .bind(&entity)
        .bind(record_id)
        .bind(&field)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let comment = if breaking {
        format!("check-out lock of user {holder} broken by an administrator")
    } else {
        "file checked in".to_owned()
    };
    audit(
        &state,
        &mut tx,
        ctx.user_id,
        &entity,
        record_id,
        &field,
        comment,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/{entity}/{id}/files/{field}/checkout",
        post(check_out).get(get_checkout).delete(check_in),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_checkout, check_out, check_in),
    components(schemas(FileCheckout, FileCheckoutStatus, CheckoutRequest))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
