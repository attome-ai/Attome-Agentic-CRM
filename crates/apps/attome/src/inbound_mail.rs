//! J2-T2: shared mailboxes routed into the desk (the rules are
//! `attome_integration::inbound_mail`).
//!
//! The `inbound_mail` job (every two minutes) reads each active
//! `kind = "mailbox"` integration system from where it stopped
//! (`inbound_mail_state`) with its J2-T1 reader. Each message with a
//! `Message-ID` is routed once per mailbox (`inbound_mail_message`): it joins
//! the case it threads to (G1-T2: case number, reply headers, the sender's
//! recent open case), or the mailbox's rule opens a case, opens a lead or
//! logs it on the sender's contact. Everything is written through the
//! generic create as the system's service principal, so record rules,
//! audit and Auto Value apply. Automatic, bulk and our own mail is skipped,
//! and each sender is limited per hour, so the desk never loops with an
//! autoresponder.

use attome_core::EngineState;
use attome_integration::connector::adapters::mail::{self, MailMessage};
use attome_integration::inbound_mail::{
    MAX_PER_SENDER_HOUR, MailboxRouting, Route, SenderMatch, SkipReason, decide, sender,
    sender_rate_key, skip_reason,
};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_service::email_threading::{
    InboundEmail, find_case, open_case_from_email, thread_entry,
};
use attome_types::AppError;
use serde_json::json;
use uuid::Uuid;

/// Most mailbox systems read in one run.
const MAX_SYSTEMS: i64 = 50;
/// Longest body kept on a communication.
const MAX_BODY_CHARS: usize = 100_000;

/// What one run did, for the log.
#[derive(Debug, Default, Clone, Copy)]
pub struct Summary {
    pub routed: u32,
    pub skipped: u32,
    pub failed: u32,
}

/// One pass over every active mailbox system.
pub async fn run(state: &EngineState) -> Result<Summary, AppError> {
    let systems: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM integration_system \
          WHERE kind = 'mailbox' AND status = 'active' AND is_active IS NOT FALSE \
          ORDER BY id LIMIT $1",
    )
    .bind(MAX_SYSTEMS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut summary = Summary::default();
    for system_id in systems {
        if let Err(error) = run_system(state, system_id, &mut summary).await {
            summary.failed += 1;
            tracing::warn!(%system_id, %error, "inbound mail: mailbox not read");
        }
    }
    Ok(summary)
}

async fn run_system(
    state: &EngineState,
    system_id: Uuid,
    summary: &mut Summary,
) -> Result<(), AppError> {
    let db = &state.base.db;
    let system = attome_integration::system::load(db, system_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let ring = state.base.secrets.load().integration_credential_key.clone();
    let credential =
        attome_integration::credential::resolve(db, &ring, system.credential_ref.as_deref())
            .await?;
    let cursor: Option<String> =
        sqlx::query_scalar("SELECT cursor FROM inbound_mail_state WHERE system_id = $1")
            .bind(system_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .flatten();
    let (messages, next) = mail::read(&system, credential.as_ref(), cursor.as_deref()).await?;

    let routing = MailboxRouting::from_config(&mail::config(&system));
    let principal: Uuid = system
        .service_principal_ref
        .parse()
        .map_err(|_| AppError::Validation(format!("{}: no service principal", system.name)))?;
    let ctx = state.base.security.resolve(principal).await?;

    for message in &messages {
        match route_message(state, &ctx, principal, system_id, &routing, message).await {
            Ok(Outcome::Routed) => summary.routed += 1,
            Ok(Outcome::Skipped) => summary.skipped += 1,
            Err(error) => {
                summary.failed += 1;
                tracing::warn!(%system_id, %error, "inbound mail: message not routed");
                // The cursor moves on, so the failure is kept where an
                // operator can see it.
                if let Some(id) = message.message_id.as_deref() {
                    record(
                        state,
                        system_id,
                        id,
                        "failed",
                        None,
                        Some(&error.to_string()),
                    )
                    .await?;
                }
            }
        }
    }

    sqlx::query(
        "INSERT INTO inbound_mail_state (system_id, cursor, updated_at) VALUES ($1, $2, now()) \
         ON CONFLICT (system_id) DO UPDATE SET cursor = EXCLUDED.cursor, updated_at = now()",
    )
    .bind(system_id)
    .bind(next.or(cursor))
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

enum Outcome {
    Routed,
    Skipped,
}

async fn route_message(
    state: &EngineState,
    ctx: &SecurityContext,
    principal: Uuid,
    system_id: Uuid,
    routing: &MailboxRouting,
    message: &MailMessage,
) -> Result<Outcome, AppError> {
    if let Some(reason) = skip_reason(message, routing) {
        if let Some(id) = message.message_id.as_deref() {
            record(state, system_id, id, reason.as_str(), None, None).await?;
        }
        return Ok(Outcome::Skipped);
    }
    let Some(message_id) = message.message_id.as_deref() else {
        return Ok(Outcome::Skipped);
    };
    let stored_id = format!("<{message_id}>");

    // Once per mailbox; and never mail Attome itself wrote (our own sends
    // and captured mail are communications with this Message-ID already).
    let seen: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM inbound_mail_message WHERE system_id = $1 AND message_id = $2) \
             OR EXISTS (SELECT 1 FROM communication WHERE message_id = $3)",
    )
    .bind(system_id)
    .bind(message_id)
    .bind(&stored_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if seen {
        return Ok(Outcome::Skipped);
    }

    let from = sender(message);
    if let Some(from) = &from {
        match state
            .base
            .redis
            .incr_with_ttl(
                sender_rate_key(system_id, from),
                std::time::Duration::from_secs(3600),
            )
            .await
        {
            Ok(count) if count > MAX_PER_SENDER_HOUR => {
                record(
                    state,
                    system_id,
                    message_id,
                    SkipReason::RateLimited.as_str(),
                    None,
                    None,
                )
                .await?;
                return Ok(Outcome::Skipped);
            }
            Ok(_) => {}
            // The limit is a loop guard, not a security control: without
            // Redis the message is still routed.
            Err(error) => tracing::warn!(%error, "inbound mail: sender limit unavailable"),
        }
    }

    let email = InboundEmail {
        subject: message.subject.clone(),
        from: from.clone(),
        in_reply_to: message.in_reply_to.clone(),
        references: message.references.clone(),
    };
    let thread = find_case(state, &email).await?.map(|(case, _)| case);
    let matched = match &from {
        Some(from) => sender_match(state, ctx, from).await?,
        None => SenderMatch::default(),
    };

    let (entity, record_id) = match decide(routing, thread, matched) {
        Route::JoinCase(case) => ("service_ticket", case),
        Route::CreateCase { requester } => {
            let case = open_case_from_email(
                state,
                ctx,
                principal,
                message.subject.as_deref(),
                body_text(message).as_deref(),
                requester.unwrap_or(principal),
            )
            .await?;
            ("service_ticket", case)
        }
        Route::LogOnContact(contact) => ("contact", contact),
        Route::CreateLead => {
            let lead = create_lead(state, ctx, principal, message, from.as_deref()).await?;
            ("lead", lead)
        }
        Route::Ignore => {
            record(state, system_id, message_id, "ignored", None, None).await?;
            return Ok(Outcome::Skipped);
        }
    };

    let mut entry = thread_entry(
        record_id,
        "email",
        "inbound",
        message.subject.as_deref(),
        &body_text(message).unwrap_or_default(),
        Some(message_id),
    );
    entry["entity_name"] = json!(entity);
    if let Some(date) = &message.date {
        entry["sent_at"] = json!(date);
    }
    let to: Vec<&str> = message
        .to
        .iter()
        .chain(&message.cc)
        .map(|a| a.address.as_str())
        .collect();
    if !to.is_empty() {
        entry["to_addresses"] = json!(clip(&to.join(", "), 4000));
    }
    if !message.references.is_empty() {
        let refs: Vec<String> = message
            .references
            .iter()
            .map(|r| format!("<{r}>"))
            .collect();
        entry["references_header"] = json!(clip(&refs.join(" "), 4000));
    }
    attome_records::entity_crud::create_record_with_id_for(
        state,
        ctx,
        principal,
        "communication",
        entry,
        Uuid::now_v7(),
    )
    .await?;
    record(
        state,
        system_id,
        message_id,
        "routed",
        Some((entity, record_id)),
        None,
    )
    .await?;
    Ok(Outcome::Routed)
}

/// The sender as a user and as a contact the principal may read.
async fn sender_match(
    state: &EngineState,
    ctx: &SecurityContext,
    from: &str,
) -> Result<SenderMatch, AppError> {
    let db = &state.base.db;
    let user: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM user_account WHERE lower(email) = $1 AND is_active IS NOT FALSE \
          ORDER BY id LIMIT 1",
    )
    .bind(from)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let contact_ok = state
        .entities
        .load()
        .get("contact")
        .is_some_and(|meta| meta.attrs.iter().any(|a| a.logicalname == "email"))
        && ctx.require("contact", "read").is_ok();
    let contact: Option<Uuid> = if contact_ok {
        sqlx::query_scalar(
            "SELECT id FROM contact WHERE lower(email) = $1 AND is_active IS NOT FALSE \
              ORDER BY id LIMIT 1",
        )
        .bind(from)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
    } else {
        None
    };
    Ok(SenderMatch { user, contact })
}

/// A lead from the sender, as the principal.
async fn create_lead(
    state: &EngineState,
    ctx: &SecurityContext,
    principal: Uuid,
    message: &MailMessage,
    from: Option<&str>,
) -> Result<Uuid, AppError> {
    let name = message
        .from
        .as_ref()
        .and_then(|f| f.name.clone())
        .filter(|n| !n.trim().is_empty())
        .or_else(|| from.map(str::to_owned))
        .unwrap_or_else(|| "(unknown sender)".to_owned());
    let mut body = json!({
        "name": clip(name.trim(), 200),
        "source": "email",
    });
    if let Some(from) = from {
        body["email"] = json!(from);
    }
    let (id, _) = attome_records::entity_crud::create_record_with_id_for(
        state,
        ctx,
        principal,
        "lead",
        body,
        Uuid::now_v7(),
    )
    .await?;
    Ok(id)
}

/// Where a message went, once per mailbox.
async fn record(
    state: &EngineState,
    system_id: Uuid,
    message_id: &str,
    outcome: &str,
    target: Option<(&str, Uuid)>,
    error: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO inbound_mail_message (system_id, message_id, outcome, entity_name, record_id, error) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (system_id, message_id) DO NOTHING",
    )
    .bind(system_id)
    .bind(message_id)
    .bind(outcome)
    .bind(target.map(|(e, _)| e))
    .bind(target.map(|(_, id)| id))
    .bind(error.map(|e| clip(e, 1000)))
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

fn body_text(message: &MailMessage) -> Option<String> {
    message
        .text
        .as_deref()
        .or(message.html.as_deref())
        .map(|t| clip(t, MAX_BODY_CHARS))
}

fn clip(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}
