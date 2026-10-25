//! Outbound messages on a record (`communication`), moved here from
//! attome-api so engines (the AI follow-up agent, roadmap AI4-T4) write them
//! through the same path as the compose and reply routes, which stay in
//! attome-api as thin handlers.
//!
//! Two channels: `email` (the `SendEmail` job, enqueued in the same
//! transaction as the `communication` row and its `communication_event`
//! `queued` rows) and `internal` (in-platform messages between users, with an
//! in-app notification after the commit). See [`write_communication`].

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_core::jobs::EngineJob;
use attome_email::EmailMessage;
use attome_records::entity_crud::{field_changes_from_obj, grant_creator_share, resolve_entity};
use attome_records::entity_mutation::{MutationMode, create_one};
use attome_records::mutation_ring::{
    GrantInvalidation, MutationActor, MutationAudit, MutationRing, MutationSideEffects,
};
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

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

/// J1-T1: how a composed email goes out. The default is what every
/// engine caller wants: now, without a signature or files.
#[derive(Debug, Default, Clone)]
pub struct SendOptions {
    /// Send no earlier than this (email only): the `SendEmail` job is
    /// enqueued with this `run_at`, in the same transaction as the row.
    pub send_at: Option<DateTime<Utc>>,
    /// Append the author's signature ([`crate::signature`]) to an outbound
    /// email. Set by the compose and reply routes, where a person writes.
    pub signature: bool,
    /// J1-T2: files sent with an email (the record's own files, read by the
    /// caller before the transaction), carried in each recipient's job.
    pub attachments: Vec<attome_email::EmailAttachment>,
}

/// How far ahead an email may be scheduled.
pub const MAX_SEND_AHEAD_DAYS: i64 = 90;

/// Refuses a `send_at` on a channel other than email, in the past, or more
/// than [`MAX_SEND_AHEAD_DAYS`] ahead.
pub fn validate_send_at(
    channel: &str,
    send_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let Some(at) = send_at else { return Ok(()) };
    if channel != "email" {
        return Err(AppError::Validation(
            "send_at is only for channel=email".into(),
        ));
    }
    if at <= now {
        return Err(AppError::Validation("send_at must be in the future".into()));
    }
    if at > now + Duration::days(MAX_SEND_AHEAD_DAYS) {
        return Err(AppError::Validation(format!(
            "send_at is at most {MAX_SEND_AHEAD_DAYS} days ahead"
        )));
    }
    Ok(())
}

/// Validates `channel` against Phase 1's two supported values and returns
/// the normalized recipient list for whichever one it is — the other list is
/// always empty, never partially populated from stray request fields.
pub fn validate_recipients(
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

/// Fans out an in-app notification to every `channel=internal` recipient.
/// Best-effort, called AFTER the composing transaction commits:
/// `crate::dispatch::create_dispatch` owns its own transaction
/// (it is not an `_in_tx` primitive), so it cannot join the communication
/// write the way the `SendEmail` job enqueue does. A failure here is logged,
/// never surfaced to the composer — the message itself is already durably
/// recorded; losing only its in-app ping is the same "best-effort side
/// notification" posture the platform already takes elsewhere (e.g.
/// `rw_pin::pin_write_with_current_lsn`).
pub async fn notify_internal_recipients(
    state: &EngineState,
    recipient_user_ids: &[Uuid],
    entity_name: &str,
    record_id: Uuid,
    subject: &str,
) {
    for &user_id in recipient_user_ids {
        let req = crate::dispatch::DispatchRequest {
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
        if let Err(e) =
            crate::dispatch::create_dispatch(&state.base.db, &state.base.config.notification, req)
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
///
/// Sends now and without a signature; [`write_communication_with`] takes
/// [`SendOptions`].
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
    write_communication_with(
        state,
        ctx,
        acting_user_id,
        entity_name,
        record_id,
        channel,
        direction,
        to_addresses,
        recipient_user_ids,
        subject,
        body,
        in_reply_to,
        parent_thread_id,
        parent_message_id,
        parent_references,
        SendOptions::default(),
    )
    .await
}

/// [`write_communication`] with [`SendOptions`] (J1-T1): a later send time
/// and the author's signature.
#[allow(clippy::too_many_arguments)]
pub async fn write_communication_with(
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
    options: SendOptions,
) -> Result<CommunicationResponse, AppError> {
    let (comm_entity_id, comm_entity_name, comm_attrs, _) =
        resolve_entity(state, "communication").await?;
    let (event_entity_id, event_entity_name, event_attrs, _) =
        resolve_entity(state, "communication_event").await?;

    let now = Utc::now();
    validate_send_at(channel, options.send_at, now)?;
    // J1-T1: the signature is part of what is stored and sent, so the
    // timeline shows the message as the recipient got it.
    let signature = if options.signature && channel == "email" && direction == "outbound" {
        crate::signature::for_user(&state.base.db, acting_user_id).await?
    } else {
        None
    };
    let signed;
    let body = match signature {
        Some(sig) => {
            signed = crate::signature::append(body, &sig, crate::tracking::looks_like_html(body));
            signed.as_str()
        }
        None => body,
    };
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
    obj.insert(
        "sent_at".into(),
        Value::String(options.send_at.unwrap_or(now).to_rfc3339()),
    );
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
            // (`crate::dispatch::create_dispatch`). Same
            // suppression check, same transaction, so the decision is
            // atomic with the event-row write and the enqueue below.
            if crate::dispatch::is_email_suppressed(&mut *tx, to.as_str()).await? {
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

            // D16-T1: tracked links and the open pixel, when tracking is on
            // and the person the record is about has not opted out. D16-T2:
            // an HTML body is cleaned and sent as the HTML part (its links
            // rewritten when tracked), with its text as the plain part.
            let is_html = crate::tracking::looks_like_html(body);
            let clean_html = is_html.then(|| {
                attome_html::sanitize(
                    body,
                    attome_html::SanitizeProfile::InboundEmail {
                        allow_remote_images: true,
                    },
                )
            });
            let text_body = match &clean_html {
                Some(html) => attome_html::html_to_text(html),
                None => body.to_string(),
            };
            let tracked = crate::tracking::enabled(state)
                && !crate::tracking::opted_out(&mut tx, entity_name, record_id).await?;
            let secret = tracked
                .then(|| crate::tracking::signing_secret(state))
                .flatten();
            let html_body = match (&clean_html, secret) {
                (Some(html), Some(secret)) => Some(crate::tracking::tracked_rewrite(
                    html,
                    &state.base.config.frontend_url(),
                    communication_id,
                    now.timestamp(),
                    |claim| crate::tracking::sign(&secret, claim),
                )),
                (Some(html), None) => Some(html.clone()),
                (None, Some(secret)) => Some(crate::tracking::tracked_html(
                    body,
                    &state.base.config.frontend_url(),
                    communication_id,
                    now.timestamp(),
                    |claim| crate::tracking::sign(&secret, claim),
                )),
                (None, None) => None,
            };
            let job = EngineJob::SendEmail(Box::new(EmailMessage {
                to: to.clone(),
                subject: subject.to_string(),
                text_body,
                html_body,
                delivery_id: None,
                from_override: None,
                message_id: message_id.clone(),
                in_reply_to: parent_message_id.map(|s| s.to_string()),
                references: references.clone(),
                communication_id: Some(communication_id),
                attachments: options.attachments.clone(),
                stream: Default::default(),
            }));
            match options.send_at {
                Some(at) => attome_jobs::enqueue_at_in_tx(&mut tx, job, at).await,
                None => attome_jobs::enqueue_in_tx(&mut tx, job).await,
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_at_must_be_a_future_email_within_the_window() {
        let now = Utc::now();
        assert!(validate_send_at("email", None, now).is_ok());
        assert!(validate_send_at("email", Some(now + Duration::hours(2)), now).is_ok());
        for (channel, at) in [
            ("internal", now + Duration::hours(2)),
            ("email", now - Duration::minutes(1)),
            ("email", now + Duration::days(MAX_SEND_AHEAD_DAYS + 1)),
        ] {
            assert!(
                matches!(
                    validate_send_at(channel, Some(at), now),
                    Err(AppError::Validation(_))
                ),
                "{channel} at {at} must be refused"
            );
        }
    }
}
