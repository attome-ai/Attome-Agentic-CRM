//! M52 Phase 1 (D-465) — outbound compose/reply for `communication`.
//!
//! Two channels only, per the Phase 1 scope decision: `email` (rides M51's
//! `SendEmail` job path, `attome_email`/`attome_jobs`) and `internal` (in-platform
//! messaging between users — `recipient_user_ids`, an in-app notification via
//! `attome_notification::dispatch`, never customer-visible). Explicitly **not**
//! in scope: the inbound mailbox connector (M59, a separate connector kind),
//! attachments (M55), and response-time metrics (M27) — see
//! `document/module-master-plans/M52-communication.md`.
//!
//! Both routes write the `communication` row and its `communication_event`
//! "queued" child row(s) in the SAME transaction as the `SendEmail` job
//! enqueue (email channel only) — see `communication_event_seed.rs`'s doc
//! comment for why that atomicity matters. The one thing the generic
//! `entity_mutation::create_one` primitive genuinely cannot express is
//! `thread_id`'s self-reference on a fresh compose (the row's own id isn't
//! known until after the insert): handled with a single scoped
//! parameterized `UPDATE ... WHERE id = $1`, same transaction, immediately
//! after the insert — see `write_communication`'s doc comment.
//!
//! Authorization mirrors `entity_crud/related.rs` and `files.rs`: the route
//! carries a real `{entity}` path segment so `Authorized<RecordScoped<Update>>`
//! self-enforces the entity-level privilege, and the handler additionally
//! calls `require_record_access` for the specific record — composing (or
//! replying to) a communication about a record is authorized as an `update`
//! on that record, the same posture `files.rs` takes for attaching a file.

use attome_core::EngineState;
use attome_notification::communication::{
    CommunicationResponse, notify_internal_recipients, validate_recipients, write_communication,
};
use attome_security::RecordAction;
use attome_security::record_action::Update;
use attome_server::authz::{Authorized, RecordScoped};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use attome_records::entity_crud::{require_record_access, resolve_entity};

#[derive(Deserialize, ToSchema)]
pub struct ComposeRequest {
    /// `email` or `internal` — Phase 1 accepts no other value (see this
    /// module's doc comment).
    pub channel: String,
    /// Recipient email addresses. Required, non-empty, for `channel=email`;
    /// ignored otherwise.
    #[serde(default)]
    pub to: Vec<String>,
    /// Recipient `user_account` ids. Required, non-empty, for
    /// `channel=internal`; ignored otherwise.
    #[serde(default)]
    pub recipient_user_ids: Vec<Uuid>,
    pub subject: String,
    pub body: String,
}

impl std::fmt::Debug for ComposeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComposeRequest").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct ReplyRequest {
    pub body: String,
}

impl std::fmt::Debug for ReplyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplyRequest").finish_non_exhaustive()
    }
}

#[derive(sqlx::FromRow)]
struct ParentRow {
    id: Uuid,
    channel: String,
    thread_id: Option<Uuid>,
    to_addresses: Option<String>,
    recipient_user_ids: Option<String>,
    subject: Option<String>,
    message_id: Option<String>,
    references_header: Option<String>,
    entity_name: String,
    record_id: String,
}

struct ParentCommunication {
    id: Uuid,
    channel: String,
    thread_id: Uuid,
    to_addresses: Vec<String>,
    recipient_user_ids: Vec<Uuid>,
    subject: String,
    message_id: Option<String>,
    references_header: Option<String>,
}

/// Loads the message being replied to and confirms it really belongs to the
/// `{entity}/{id}` the reply route's own path names — a defense-in-depth
/// check, not the authorization decision itself (that is
/// `require_record_access` on `entity_name`/`record_id`, called by both
/// handlers before this runs).
async fn fetch_parent(
    state: &EngineState,
    comm_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
) -> Result<ParentCommunication, AppError> {
    let row: Option<ParentRow> = sqlx::query_as(
        r#"SELECT id, channel, thread_id, to_addresses, recipient_user_ids, subject,
                  message_id, references_header, entity_name, record_id
             FROM "communication"
            WHERE id = $1 AND is_active IS NOT FALSE"#,
    )
    .bind(comm_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;

    let parent_record_id = Uuid::parse_str(&row.record_id)
        .map_err(|_| AppError::internal("communication.record_id was not a UUID"))?;
    if row.entity_name != entity_name || parent_record_id != record_id {
        return Err(AppError::Validation(
            "communication does not belong to this record".into(),
        ));
    }

    Ok(ParentCommunication {
        id: row.id,
        channel: row.channel,
        thread_id: row.thread_id.unwrap_or(row.id),
        to_addresses: row
            .to_addresses
            .map(|s| {
                s.split(',')
                    .map(|a| a.trim().to_string())
                    .filter(|a| !a.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        recipient_user_ids: row
            .recipient_user_ids
            .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
            .map(|ids| ids.iter().filter_map(|s| Uuid::parse_str(s).ok()).collect())
            .unwrap_or_default(),
        subject: row.subject.unwrap_or_default(),
        message_id: row.message_id,
        references_header: row.references_header,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/communications",
    tag = "entity",
    params(("entity" = String, Path), ("id" = Uuid, Path)),
    request_body = ComposeRequest,
    responses(
        (status = 201, description = "Success", body = CommunicationResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Record not found", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
)]
async fn compose(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    Json(body): Json<ComposeRequest>,
) -> Result<(StatusCode, Json<CommunicationResponse>), AppError> {
    let (entity_id, entity_name, _, _) = resolve_entity(&state, &entity_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Update,
    )
    .await?;

    let (to, recipient_user_ids) =
        validate_recipients(&body.channel, &body.to, &body.recipient_user_ids)?;
    let subject = body.subject.trim();
    if subject.is_empty() {
        return Err(AppError::Validation("subject is required".into()));
    }
    let text = body.body.trim();
    if text.is_empty() {
        return Err(AppError::Validation("body is required".into()));
    }

    let outcome = write_communication(
        &state,
        &ctx,
        ctx.user_id,
        &entity_name,
        record_id,
        &body.channel,
        "outbound",
        &to,
        &recipient_user_ids,
        subject,
        text,
        None,
        None,
        None,
        None,
    )
    .await?;

    if body.channel == "internal" {
        notify_internal_recipients(
            &state,
            &recipient_user_ids,
            &entity_name,
            record_id,
            subject,
        )
        .await;
    }

    Ok((StatusCode::CREATED, Json(outcome)))
}

#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/communications/{comm_id}/reply",
    tag = "entity",
    params(
        ("entity" = String, Path),
        ("id" = Uuid, Path),
        ("comm_id" = Uuid, Path),
    ),
    request_body = ReplyRequest,
    responses(
        (status = 201, description = "Success", body = CommunicationResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Record or communication not found", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
)]
async fn reply(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Path((entity_input, record_id, comm_id)): Path<(String, Uuid, Uuid)>,
    Json(body): Json<ReplyRequest>,
) -> Result<(StatusCode, Json<CommunicationResponse>), AppError> {
    let (entity_id, entity_name, _, _) = resolve_entity(&state, &entity_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Update,
    )
    .await?;

    let parent = fetch_parent(&state, comm_id, &entity_name, record_id).await?;

    let text = body.body.trim();
    if text.is_empty() {
        return Err(AppError::Validation("body is required".into()));
    }
    let subject = if parent
        .subject
        .trim_start()
        .to_lowercase()
        .starts_with("re:")
    {
        parent.subject.clone()
    } else {
        format!("Re: {}", parent.subject)
    };

    let outcome = write_communication(
        &state,
        &ctx,
        ctx.user_id,
        &entity_name,
        record_id,
        &parent.channel,
        "outbound",
        &parent.to_addresses,
        &parent.recipient_user_ids,
        &subject,
        text,
        Some(parent.id),
        Some(parent.thread_id),
        parent.message_id.as_deref(),
        parent.references_header.as_deref(),
    )
    .await?;

    if parent.channel == "internal" {
        notify_internal_recipients(
            &state,
            &parent.recipient_user_ids,
            &entity_name,
            record_id,
            &subject,
        )
        .await;
    }

    Ok((StatusCode::CREATED, Json(outcome)))
}

/// System-authored append to `communication_event`'s delivery-status
/// timeline — called from `crates/server/src/jobs.rs`'s `SendEmail` arm once
/// a send's real outcome (`sent`/`failed`) is known. A background job has no
/// acting user and no `SecurityContext`/`EngineState`-shaped request context, so
/// this writes the append-only row directly rather than through
/// `entity_mutation::create_one` — `created_by`/`organization_ref`/`owner_ref`
/// stay `NULL`, which `attome-metadata`'s provisioned table shape allows (none of
/// the three carry a `NOT NULL` constraint, see `attome-metadata/src/provision/
/// table.rs`). The row still carries everything a human caller needs: it is
/// read only via the `communication_id` lookup from a `communication` row
/// the caller already had access to (the Communications panel embeds this as
/// a related grid), so it needs no record-level access grant of its own. The
/// one accepted gap: this bypasses the generic engine's outbox write
/// (`write_entity_change_event`), so nothing here fires a workflow trigger or
/// search-reindex hook on a delivery-status change — no such consumer exists
/// yet for this new entity; revisit if one is added.
pub async fn record_delivery_event(
    db: &attome_db::DbPool,
    communication_id: Uuid,
    event_type: &str,
    detail: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query(
        r#"INSERT INTO "communication_event" (communication_id, event_type, detail, occurred_at)
           VALUES ($1, $2, $3, NOW())"#,
    )
    .bind(communication_id)
    .bind(event_type)
    .bind(detail)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/{entity}/{id}/communications", post(compose))
        .route(
            "/api/v1/{entity}/{id}/communications/{comm_id}/reply",
            post(reply),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document. Separate per file because `#[utoipa::path]` generates a
/// `__path_*` type with the handler's own visibility, and these handlers are
/// module-private — the crate's `openapi_document` merges every fragment
/// back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(compose, reply))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
