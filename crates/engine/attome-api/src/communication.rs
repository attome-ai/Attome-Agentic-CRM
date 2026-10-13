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

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_core::jobs::EngineJob;
use attome_email::EmailMessage;
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
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use attome_records::entity_crud::{
    field_changes_from_obj, grant_creator_share, require_record_access, resolve_entity,
};
use attome_records::entity_mutation::{MutationMode, create_one};
use attome_records::mutation_ring::{
    GrantInvalidation, MutationActor, MutationAudit, MutationRing, MutationSideEffects,
};

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

#[derive(Serialize, ToSchema)]
pub struct CommunicationResponse {
    pub id: Uuid,
    pub thread_id: Uuid,
    pub channel: String,
    pub status: String,
}

impl std::fmt::Debug for CommunicationResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommunicationResponse")
            .finish_non_exhaustive()
    }
}

/// Validates `channel` against Phase 1's two supported values and returns
/// the normalized recipient list for whichever one it is — the other list is
/// always empty, never partially populated from stray request fields.
fn validate_recipients(
    channel: &str,
    to: &[String],
    recipient_user_ids: &[Uuid],
) -> Result<(Vec<String>, Vec<Uuid>), AppError> {
    match channel {
        "email" => {
            let to: Vec<String> = to
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if to.is_empty() {
                return Err(AppError::Validation(
                    "to is required and must be non-empty for channel=email".into(),
                ));
            }
            for addr in &to {
                // Deliberately not a full RFC 5322 validator — the same
                // shallow check `attome_email`'s own callers already trust
                // lettre's `Message::builder().to(...)` to reject properly at
                // send time; this only catches an obviously-wrong value
                // before it reaches a durable job.
                if !addr.contains('@') {
                    return Err(AppError::Validation(format!(
                        "invalid email address: {addr}"
                    )));
                }
            }
            Ok((to, Vec::new()))
        }
        "internal" => {
            if recipient_user_ids.is_empty() {
                return Err(AppError::Validation(
                    "recipient_user_ids is required and must be non-empty for channel=internal"
                        .into(),
                ));
            }
            Ok((Vec::new(), recipient_user_ids.to_vec()))
        }
        other => Err(AppError::Validation(format!(
            "unsupported channel: {other} (M52 Phase 1 supports email and internal only)"
        ))),
    }
}

fn mail_domain(state: &EngineState) -> String {
    state
        .base
        .config
        .email
        .smtp_from_address
        .split('@')
        .next_back()
        .filter(|s| !s.is_empty())
        .unwrap_or("localhost")
        .to_string()
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

/// Fans out an in-app notification to every `channel=internal` recipient.
/// Best-effort, called AFTER the composing transaction commits:
/// `attome_notification::dispatch::create_dispatch` owns its own transaction
/// (it is not an `_in_tx` primitive), so it cannot join the communication
/// write the way the `SendEmail` job enqueue does. A failure here is logged,
/// never surfaced to the composer — the message itself is already durably
/// recorded; losing only its in-app ping is the same "best-effort side
/// notification" posture the platform already takes elsewhere (e.g.
/// `rw_pin::pin_write_with_current_lsn`).
async fn notify_internal_recipients(
    state: &EngineState,
    recipient_user_ids: &[Uuid],
    entity_name: &str,
    record_id: Uuid,
    subject: &str,
) {
    for &user_id in recipient_user_ids {
        let req = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(user_id),
            is_global: false,
            organization_ref: None,
            channels: None, // REVIEW-2026-09-02 finding #3: inherit the platform default (in_app+email), not an in-app-only override
            subject: Some(subject.to_string()),
            body_html: None,
            body_text: Some(format!("New message on {entity_name}")),
            route: Some(format!("/{entity_name}/{record_id}")),
            variables: std::collections::HashMap::new(),
            priority: "normal".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        if let Err(e) = attome_notification::dispatch::create_dispatch(
            &state.base.db,
            &state.base.config.notification,
            req,
        )
        .await
        {
            tracing::warn!(
                user_id = %user_id,
                error = %e,
                "M52: failed to dispatch in-app notification for an internal-channel communication"
            );
        }
    }
}

/// The shared create core for both `compose` and `reply` — and, as of M53
/// Phase 1 (Omnichannel, D-474), for `crates/server`'s web-chat orchestration
/// too. `pub`, not private or `pub(crate)`: that caller lives in
/// `crates/server`, a different crate from this one (`attome-ai`/
/// `attome-integration` both already have a real dependency on `attome-api`, so
/// `attome-api` cannot depend back on either without a cycle — the web-chat
/// orchestration that needs both of them, plus this writer, has to live one
/// layer up; see `crates/server/src/omnichannel.rs`'s module doc). Exposing
/// this one function avoids a second communication-writing implementation
/// (guidelines §9) rather than duplicating its transaction/audit/thread-
/// backfill logic at that higher layer.
///
/// `direction` is caller-supplied, not hardcoded, so a caller writing on
/// behalf of an external party (a web-chat visitor's own inbound text) can
/// record it accurately. **This still always runs through the full
/// privilege/audit/entity_mutation pipeline** — `author_id` is always
/// `acting_user_id` (the resolved principal, e.g. the web-chat channel's
/// `service_principal_ref`), even for an inbound message the principal did
/// not literally type, matching D-425's own precedent for
/// `attome-integration`'s inbound webhook: "every write... running as the
/// target system's own service principal... rules, privilege, audit, cache
/// invalidation all therefore apply exactly as they would for any other
/// write." A caller with no real acting party at all (no resolved
/// principal — none exists for web chat, since the channel always has one)
/// would need `record_delivery_event`'s no-`SecurityContext` shape instead;
/// this function is for every caller that DOES have one, regardless of
/// whose words the row records.
///
/// `in_reply_to`/`parent_thread_id`/`parent_message_id`/`parent_references`
/// are all `None` for a fresh compose and all `Some` for a reply.
#[allow(clippy::too_many_arguments)]
pub async fn write_communication(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    acting_user_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
    channel: &str,
    direction: &str,
    to_addresses: &[String],
    recipient_user_ids: &[Uuid],
    subject: &str,
    body: &str,
    in_reply_to: Option<Uuid>,
    parent_thread_id: Option<Uuid>,
    parent_message_id: Option<&str>,
    parent_references: Option<&str>,
) -> Result<CommunicationResponse, AppError> {
    let (comm_entity_id, comm_entity_name, comm_attrs, _) =
        resolve_entity(state, "communication").await?;
    let (event_entity_id, event_entity_name, event_attrs, _) =
        resolve_entity(state, "communication_event").await?;

    let now = Utc::now();
    let message_id =
        (channel == "email").then(|| format!("<{}@{}>", Uuid::now_v7(), mail_domain(state)));
    let references = if channel == "email" {
        match (parent_references, parent_message_id) {
            (Some(refs), Some(mid)) if !refs.trim().is_empty() => Some(format!("{refs} {mid}")),
            (_, Some(mid)) => Some(mid.to_string()),
            _ => None,
        }
    } else {
        None
    };
    let status = if channel == "email" {
        "queued"
    } else {
        "logged"
    };

    let mut obj = Map::new();
    obj.insert("entity_name".into(), Value::String(entity_name.to_string()));
    obj.insert("record_id".into(), Value::String(record_id.to_string()));
    obj.insert("channel".into(), Value::String(channel.to_string()));
    obj.insert("direction".into(), Value::String(direction.to_string()));
    obj.insert("subject".into(), Value::String(subject.to_string()));
    obj.insert("body".into(), Value::String(body.to_string()));
    obj.insert("status".into(), Value::String(status.to_string()));
    obj.insert("sent_at".into(), Value::String(now.to_rfc3339()));
    obj.insert(
        "author_id".into(),
        Value::String(acting_user_id.to_string()),
    );
    if !to_addresses.is_empty() {
        obj.insert(
            "to_addresses".into(),
            Value::String(to_addresses.join(", ")),
        );
    }
    if !recipient_user_ids.is_empty() {
        let ids: Vec<String> = recipient_user_ids.iter().map(Uuid::to_string).collect();
        obj.insert(
            "recipient_user_ids".into(),
            Value::String(serde_json::to_string(&ids).unwrap_or_default()),
        );
    }
    if let Some(parent_id) = in_reply_to {
        obj.insert("in_reply_to".into(), Value::String(parent_id.to_string()));
    }
    if let Some(tid) = parent_thread_id {
        // Reply: the whole thread shares its root's id, unchanged.
        obj.insert("thread_id".into(), Value::String(tid.to_string()));
    }
    if let Some(mid) = &message_id {
        obj.insert("message_id".into(), Value::String(mid.clone()));
    }
    if let Some(refs) = &references {
        obj.insert("references_header".into(), Value::String(refs.clone()));
    }

    let actor = MutationActor::fetch(state, acting_user_id).await;
    // Kept as a plain binding — the delivery-status `write_event` calls
    // further down (unrelated to the ring) already thread `org_ref` as a
    // scalar parameter; rebinding it here is less churn than rewriting each
    // of them to `actor.org_ref`.
    let org_ref = actor.org_ref;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let mutation = create_one(
        &mut tx,
        state,
        ctx,
        &comm_entity_name,
        &comm_attrs,
        &obj,
        acting_user_id,
        actor.org_ref,
        MutationMode::Strict,
    )
    .await?;
    let communication_id = mutation.record_id;
    let thread_id = parent_thread_id.unwrap_or(communication_id);

    if parent_thread_id.is_none() {
        // Fresh compose: back-fill the self-referencing thread root now that
        // the row's own id exists. A single scoped, parameterized column
        // update, same transaction as the insert above and everything
        // below — the one thing `entity_mutation::create_one` cannot express
        // (it cannot bind a value the database has not generated yet). See
        // this module's doc comment.
        sqlx::query(r#"UPDATE "communication" SET thread_id = $1 WHERE id = $1"#)
            .bind(communication_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    }

    // C-10: the creator-share grant and the audit write are now the ring's
    // job (`MutationRing::commit_mutation`, called once at the very end of
    // this function, after the delivery-status/job-enqueue work below —
    // reordered from directly-after-insert so the ring's own `commit` is the
    // one commit this whole write makes, same "one transaction, one commit"
    // shape every other mutation call site now has). `changed_fields` still
    // has to be computed here, against `obj`/`None` exactly as before, since
    // the ring has no way to know what a caller's own request body looked
    // like.
    let mut audit = MutationAudit::new();
    audit.changed_fields = field_changes_from_obj(&mut tx, state, &comm_attrs, &obj, None).await;

    // Delivery-status timeline: the `queued` row(s), in the SAME transaction
    // as the parent insert above and the `SendEmail` enqueue below — see
    // `communication_event_seed.rs`'s doc comment for why this can never
    // race "row exists" against "job enqueued". Email fans out one row (and
    // one job) per recipient, `detail` naming the address; `internal` gets a
    // single `delivered` row (the write itself IS the delivery — no async
    // transport in Phase 1).
    async fn write_event(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        state: &EngineState,
        ctx: &attome_server::security::SecurityContext,
        event_entity_id: Uuid,
        event_entity_name: &str,
        event_attrs: &[attome_core::AttrInfo],
        acting_user_id: Uuid,
        org_ref: Uuid,
        communication_id: Uuid,
        event_type: &str,
        detail: Option<&str>,
        now: chrono::DateTime<Utc>,
    ) -> Result<(), AppError> {
        let mut event_obj = Map::new();
        event_obj.insert(
            "communication_id".into(),
            Value::String(communication_id.to_string()),
        );
        event_obj.insert("event_type".into(), Value::String(event_type.to_string()));
        if let Some(d) = detail {
            event_obj.insert("detail".into(), Value::String(d.to_string()));
        }
        event_obj.insert("occurred_at".into(), Value::String(now.to_rfc3339()));
        let event_mutation = create_one(
            tx,
            state,
            ctx,
            event_entity_name,
            event_attrs,
            &event_obj,
            acting_user_id,
            org_ref,
            MutationMode::Strict,
        )
        .await?;
        grant_creator_share(
            tx,
            event_entity_id,
            event_mutation.record_id,
            acting_user_id,
        )
        .await
    }

    if channel == "email" {
        for to in to_addresses {
            // REVIEW-2026-09-02 finding #4: this loop used to enqueue
            // `SendEmail` for every address unconditionally, never
            // consulting `email_suppression` — a bounced
            // or withdrawn address could be emailed through compose even
            // though a direct M51 dispatch already refuses it
            // (`attome_notification::dispatch::create_dispatch`). Same
            // suppression check, same transaction, so the decision is
            // atomic with the event-row write and the enqueue below.
            if attome_notification::dispatch::is_email_suppressed(&mut *tx, to.as_str()).await? {
                write_event(
                    &mut tx,
                    state,
                    ctx,
                    event_entity_id,
                    &event_entity_name,
                    &event_attrs,
                    acting_user_id,
                    org_ref,
                    communication_id,
                    "suppressed",
                    Some(to.as_str()),
                    now,
                )
                .await?;
                continue;
            }

            write_event(
                &mut tx,
                state,
                ctx,
                event_entity_id,
                &event_entity_name,
                &event_attrs,
                acting_user_id,
                org_ref,
                communication_id,
                "queued",
                Some(to.as_str()),
                now,
            )
            .await?;

            let job = EngineJob::SendEmail(Box::new(EmailMessage {
                to: to.clone(),
                subject: subject.to_string(),
                text_body: body.to_string(),
                html_body: None,
                delivery_id: None,
                from_override: None,
                message_id: message_id.clone(),
                in_reply_to: parent_message_id.map(|s| s.to_string()),
                references: references.clone(),
                communication_id: Some(communication_id),
            }));
            attome_jobs::enqueue_in_tx(&mut tx, job)
                .await
                .map_err(AppError::internal)?;
        }
    } else {
        write_event(
            &mut tx,
            state,
            ctx,
            event_entity_id,
            &event_entity_name,
            &event_attrs,
            acting_user_id,
            org_ref,
            communication_id,
            "delivered",
            None,
            now,
        )
        .await?;
    }

    // Captured before `mutation` moves into the ring call below — `&row`
    // would otherwise borrow `mutation` for the same call that also moves
    // it (E0505).
    let row = mutation.new_row.clone();
    MutationRing::new(state)
        .commit_mutation(
            tx,
            ctx,
            comm_entity_id,
            &comm_entity_name,
            &comm_attrs,
            &actor,
            AuditOperation::Create,
            MutationSideEffects {
                grant_creator_share: true,
                mirror_file_fields: false,
            },
            GrantInvalidation::ByRow(row.as_ref()),
            audit,
            "compose communication",
            mutation,
        )
        .await?;

    Ok(CommunicationResponse {
        id: communication_id,
        thread_id,
        channel: channel.to_string(),
        status: status.to_string(),
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
