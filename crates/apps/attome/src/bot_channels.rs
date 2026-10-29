//! N18-T1: WhatsApp and SMS conversations answered by the channel's bot.
//!
//! A WhatsApp or SMS system whose config names a `bot`
//! (`attome_ai::bot::BotConfig`) has each inbound message from a known
//! person answered by that agent: the inbound handler queues a `bot_reply`
//! job ([`enqueue`]) instead of routing the conversation to its queue, and
//! the job ([`run`]) takes the person's turn in their own session (one per
//! system and record, `bot_thread`), then sends the answer on the channel
//! and writes it on the person's timeline. A model turn is too slow for the
//! provider's webhook deadline, which is why it runs as a job.
//!
//! **Hand-off.** When the person asks for a person, or the turn hands off
//! (`attome_ai::bot::reply`), the thread is marked handed off, the
//! conversation is routed to the system's `queue_id` (J10, as without a
//! bot) and the person is told; from then on the bot is silent on that
//! thread and every message is routed. When the assistant cannot answer
//! (switched off, no model, a fault) the message is routed too, without
//! marking the thread: people on a messaging channel are not left waiting.
//!
//! **Idempotent.** A thread remembers the last message it answered; a
//! retried job for it does nothing.

use attome_ai::bot::{BotConfig, BotReply, Channel};
use attome_core::EngineState;
use attome_integration::connector::adapters::social;
use attome_integration::system::IntegrationSystem;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The reply job's name.
pub const BOT_REPLY_JOB: &str = "bot_reply";

/// What a person is told when a person takes over.
pub const HANDOFF_ACK: &str = "Thanks, I've passed this to our team and someone will reply here shortly. \
     شكرًا، حوّلنا محادثتك إلى فريقنا وسيرد عليك أحدهم هنا قريبًا.";

/// One inbound message for the bot: the job's payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BotMessage {
    pub system_id: Uuid,
    /// `whatsapp` or `sms`.
    pub channel: String,
    /// The person's record.
    pub party_entity: String,
    pub party_id: Uuid,
    /// The person's number, E.164.
    pub from: String,
    pub text: String,
    /// The provider's message id.
    pub message_id: String,
    pub received_at: DateTime<Utc>,
}

/// A thread's bot session, last answered message and hand-off time.
type ThreadRow = (Uuid, Option<String>, Option<DateTime<Utc>>);

async fn thread(
    state: &EngineState,
    system: Uuid,
    party: (&str, Uuid),
) -> Result<Option<ThreadRow>, AppError> {
    sqlx::query_as(
        "SELECT agent_session_id, last_message_id, handed_off_at FROM bot_thread \
          WHERE integration_system_id = $1 AND party_entity = $2 AND party_id = $3",
    )
    .bind(system)
    .bind(party.0)
    .bind(party.1)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Queues the bot's reply to `message` when its system has a bot and the
/// thread is not with a person; whether it did. When it did not, the caller
/// routes the conversation as it would without a bot.
pub(crate) async fn enqueue(
    state: &EngineState,
    system: &IntegrationSystem,
    message: BotMessage,
) -> Result<bool, AppError> {
    if !state.modules.load().has(attome_modules::MODULE_AI)
        || BotConfig::from_system_config(&social::config(system)).is_none()
        || message.text.trim().is_empty()
    {
        return Ok(false);
    }
    let party = (message.party_entity.as_str(), message.party_id);
    if thread(state, system.id, party)
        .await?
        .is_some_and(|(_, _, handed_off)| handed_off.is_some())
    {
        return Ok(false);
    }
    let job = attome_jobs::RegisteredJob {
        name: BOT_REPLY_JOB.to_owned(),
        version: 1,
        payload: serde_json::to_value(&message).map_err(AppError::internal)?,
        next: None,
    };
    attome_jobs::enqueue_on_pool(
        &state.base.db,
        attome_core::jobs::EngineJob::Registered(job),
    )
    .await
    .map_err(AppError::internal)?;
    Ok(true)
}

/// Answers one message. See the module doc.
pub async fn run(state: &EngineState, message: &BotMessage) -> Result<(), AppError> {
    let db = &state.base.db;
    let Some(system) = attome_integration::system::load(db, message.system_id).await? else {
        return Ok(());
    };
    let Some(bot) = BotConfig::from_system_config(&social::config(&system)) else {
        return Ok(());
    };
    let channel = match Channel::parse(&message.channel) {
        Some(c @ (Channel::WhatsApp | Channel::Sms)) => c,
        _ => return Ok(()),
    };
    let party = (message.party_entity.as_str(), message.party_id);
    let principal = attome_integration::system::service_principal_id(&system)?;
    let ctx = state.base.security.resolve(principal).await?;

    let existing = thread(state, system.id, party).await?;
    if let Some((_, last, handed_off)) = &existing
        && (handed_off.is_some() || last.as_deref() == Some(message.message_id.as_str()))
    {
        return Ok(());
    }
    let live = match &existing {
        Some((session, _, _)) => attome_ai::session::load_live(db, *session).await?,
        None => None,
    };
    let session_id = match live {
        Some(session) => session.id,
        None => {
            let session = match attome_ai::bot::start_session(state, &ctx, channel, &bot, system.id)
                .await
            {
                Ok(session) => session,
                Err(error) => {
                    // No bot after all: the conversation goes to people.
                    tracing::warn!(system = %system.id, %error, "bot: no session; routing to people");
                    crate::whatsapp_inbound::route(state, &ctx, principal, &system, party).await?;
                    return Ok(());
                }
            };
            sqlx::query(
                "INSERT INTO bot_thread \
                     (integration_system_id, party_entity, party_id, channel, agent_session_id) \
                 VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (integration_system_id, party_entity, party_id) \
                 DO UPDATE SET agent_session_id = EXCLUDED.agent_session_id, updated_at = now()",
            )
            .bind(system.id)
            .bind(party.0)
            .bind(party.1)
            .bind(channel.as_str())
            .bind(session.id)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
            session.id
        }
    };

    match attome_ai::bot::reply(state, ctx.clone(), channel, session_id, &message.text).await {
        BotReply::Say(text, _) => {
            send(state, &ctx, principal, &system, channel, message, &text).await?;
        }
        BotReply::Offline => {
            crate::whatsapp_inbound::route(state, &ctx, principal, &system, party).await?;
        }
        BotReply::Handoff(reason) => {
            let claimed: Option<Uuid> = sqlx::query_scalar(
                "UPDATE bot_thread SET handed_off_at = now(), updated_at = now() \
                  WHERE integration_system_id = $1 AND party_entity = $2 AND party_id = $3 \
                    AND handed_off_at IS NULL \
                 RETURNING agent_session_id",
            )
            .bind(system.id)
            .bind(party.0)
            .bind(party.1)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
            if claimed.is_some() {
                tracing::info!(system = %system.id, ?reason, "bot: handed to a person");
                crate::whatsapp_inbound::route(state, &ctx, principal, &system, party).await?;
                send(
                    state,
                    &ctx,
                    principal,
                    &system,
                    channel,
                    message,
                    HANDOFF_ACK,
                )
                .await?;
            }
        }
    }
    sqlx::query(
        "UPDATE bot_thread SET last_message_id = $4, updated_at = now() \
          WHERE integration_system_id = $1 AND party_entity = $2 AND party_id = $3",
    )
    .bind(system.id)
    .bind(party.0)
    .bind(party.1)
    .bind(&message.message_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Sends `text` to the person on the channel and writes it on their
/// timeline, threaded with their messages there.
async fn send(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    principal: Uuid,
    system: &IntegrationSystem,
    channel: Channel,
    message: &BotMessage,
    text: &str,
) -> Result<(), AppError> {
    let text = attome_ai::bot::fit(channel, text);
    let subject = match channel {
        Channel::WhatsApp => {
            attome_integration::whatsapp_send::send_text(
                state,
                system,
                &message.from,
                &text,
                Some(message.received_at),
            )
            .await?;
            "WhatsApp"
        }
        _ => {
            let sent = attome_integration::sms::send(state, &message.from, &text, None).await?;
            if sent == attome_integration::sms::Sent::Skipped {
                tracing::warn!(system = %system.id, "bot: no SMS provider; the reply was not sent");
                return Ok(());
            }
            "SMS"
        }
    };
    let thread: Option<Uuid> = sqlx::query_scalar(
        "SELECT thread_id FROM communication \
          WHERE entity_name = $1 AND record_id = $2 AND channel = $3 \
            AND is_active IS NOT FALSE \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&message.party_entity)
    .bind(message.party_id.to_string())
    .bind(channel.as_str())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    attome_notification::communication::write_communication(
        state,
        ctx,
        principal,
        &message.party_entity,
        message.party_id,
        channel.as_str(),
        "outbound",
        std::slice::from_ref(&message.from),
        &[],
        subject,
        &text,
        None,
        thread,
        None,
        None,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bot_message_round_trips_as_a_job_payload() {
        let message = BotMessage {
            system_id: Uuid::from_u128(1),
            channel: "whatsapp".into(),
            party_entity: "contact".into(),
            party_id: Uuid::from_u128(2),
            from: "+966500000000".into(),
            text: "متى يصل طلبي؟".into(),
            message_id: "wamid.1".into(),
            received_at: DateTime::from_timestamp(1_800_000_000, 0).expect("a time"),
        };
        let payload = serde_json::to_value(&message).expect("payload");
        assert_eq!(
            serde_json::from_value::<BotMessage>(payload).expect("back"),
            message
        );
    }

    #[test]
    fn the_handoff_notice_is_in_english_and_arabic() {
        assert!(HANDOFF_ACK.contains("our team"));
        assert!(HANDOFF_ACK.contains("فريقنا"));
    }
}
