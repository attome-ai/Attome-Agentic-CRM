//! C10-B — thumbs feedback on a turn's answer (`01-architecture.md`, "C10-B:
//! analytics and feedback").
//!
//! A vote is user state, not a conversation event: it lives in
//! `ai_message_feedback` (migration `0486`), never in the event log, and
//! analytics read it as a separate source.
//!
//! - **Only a turn's answer is rateable**: an assistant message carrying a
//!   terminal state. Anything else is refused.
//! - **One current vote per user and message**, enforced by the table's
//!   `UNIQUE (message_id, user_id)`. Changing a vote is the same row updated,
//!   through one `INSERT … ON CONFLICT DO UPDATE`, never a check-then-write.
//! - **Audited in its own transaction**: the vote and its `Ai` security event
//!   commit together (D-542).
//!
//! Callers authorize the conversation first (I-20); this module takes an id
//! the caller already owns.

use std::collections::HashMap;

use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Up or down, and nothing else.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Vote {
    Up,
    Down,
}

impl Vote {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "up" => Some(Self::Up),
            "down" => Some(Self::Down),
            _ => None,
        }
    }
}

/// A user's current vote on one message.
#[derive(Debug, Clone)]
pub struct Feedback {
    pub message_id: Uuid,
    pub vote: Vote,
    pub updated_at: DateTime<Utc>,
}

/// Records `voter`'s vote on `message_id` in `conversation_id`, replacing any
/// earlier one.
///
/// `NotFound` when the message is not in that conversation; `Validation` when
/// it is not a turn's answer. The audit event and the vote commit together.
pub async fn set_vote(
    state: &attome_core::EngineState,
    conversation_id: Uuid,
    message_id: Uuid,
    voter: Uuid,
    vote: Vote,
) -> Result<Feedback, AppError> {
    let event = attome_audit::security::SecurityEvent::new(
        attome_audit::security::MandatoryCategory::Ai,
        attome_audit::AuditOperation::Update,
        voter,
        "ai_message",
        Some(message_id),
    )
    .named("ai_conversation.feedback");
    let mut stx = attome_audit::security::SecurityTx::begin(state, event).await?;

    let target: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT role, terminal_state FROM ai_message \
          WHERE id = $1 AND conversation_id = $2",
    )
    .bind(message_id)
    .bind(conversation_id)
    .fetch_optional(&mut *stx)
    .await
    .map_err(AppError::internal)?;
    let Some((role, terminal_state)) = target else {
        return Err(AppError::NotFound);
    };
    if role != "assistant" || terminal_state.is_none() {
        return Err(AppError::Validation(
            "only a turn's answer (the assistant's final message) can be rated".into(),
        ));
    }

    let (vote_text, updated_at): (String, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO ai_message_feedback (message_id, conversation_id, user_id, vote) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (message_id, user_id) DO UPDATE \
            SET vote = EXCLUDED.vote, updated_at = NOW(), \
                row_version = ai_message_feedback.row_version + 1 \
         RETURNING vote, updated_at",
    )
    .bind(message_id)
    .bind(conversation_id)
    .bind(voter)
    .bind(vote.as_str())
    .fetch_one(&mut *stx)
    .await
    .map_err(AppError::internal)?;
    stx.commit().await?;

    let vote = Vote::parse(&vote_text)
        .ok_or_else(|| AppError::internal(format!("unknown stored vote {vote_text:?}")))?;
    Ok(Feedback {
        message_id,
        vote,
        updated_at,
    })
}

/// `voter`'s current votes on the given messages of one conversation.
pub async fn votes_for(
    db: &sqlx::PgPool,
    conversation_id: Uuid,
    voter: Uuid,
    message_ids: &[Uuid],
) -> Result<HashMap<Uuid, Vote>, AppError> {
    if message_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT message_id, vote FROM ai_message_feedback \
          WHERE conversation_id = $1 AND user_id = $2 AND message_id = ANY($3)",
    )
    .bind(conversation_id)
    .bind(voter)
    .bind(message_ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, v)| Vote::parse(&v).map(|v| (id, v)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn votes_round_trip_and_match_the_migration_check() {
        for v in [Vote::Up, Vote::Down] {
            assert_eq!(Vote::parse(v.as_str()), Some(v));
        }
        assert_eq!(Vote::parse("sideways"), None);
        let migration = include_str!("../../../apps/attome/migrations/0008_modules.sql");
        assert!(migration.contains("CHECK (vote IN ('up', 'down'))"));
    }
}
