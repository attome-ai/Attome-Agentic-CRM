//! Stop — a user ends a turn they no longer want (C11 B4, P-4, row A-84).
//!
//! **The row is the authority.** A Stop is one `ai_turn_cancel` row keyed
//! by the turn (migration 0493), so a repeated Stop is the same row and the
//! request is honoured whichever node it reached. The turn loop reads it:
//!
//! - at every step boundary, before the next model call;
//! - before each tool call is proposed, and again just before it is
//!   dispatched — a proposal found stopped there is closed as invalidated and
//!   never reaches dispatch. What remains is the one hop from that last check
//!   into `dispatch`: a Stop landing inside it lets that single call run, and
//!   the turn ends `Cancelled` right after it;
//! - while a model call is streaming, through [`wait`], which the model client
//!   races against the stream and which aborts the request when it resolves.
//!
//! **What Stop does not do.** It never interrupts a dispatch whose D-502
//! claim is already taken: that mutation runs to completion and is recorded,
//! and the turn ends at the next boundary. It never touches a proposal waiting
//! for confirmation or approval: the user rejects that through its own route.
//! The turn ends as [`TerminalState::Cancelled`], which, like every other
//! non-success state, forbids autonomous continuation.
//!
//! **Why polling, not pub/sub.** [`wait`] reads the row every [`POLL`]. That
//! bounds how quickly a stream stops at well under a second, needs no
//! per-turn subscription, and keeps working when Redis does not — for a
//! control a user reaches for when something is going wrong, that matters
//! more than the last few hundred milliseconds.
//!
//! [`TerminalState::Cancelled`]: crate::conversation::TerminalState::Cancelled

use std::time::Duration;

use attome_types::AppError;
use sqlx::PgPool;
use uuid::Uuid;

/// How often a streaming model call checks for a Stop.
pub const POLL: Duration = Duration::from_millis(400);

/// What a Stop request found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    /// Recorded now. The turn stops at its next boundary.
    Requested,
    /// An earlier Stop is already recorded. Nothing was written.
    AlreadyRequested,
    /// The turn had already reached a terminal state. Nothing was written.
    AlreadyEnded,
}

impl CancelOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::AlreadyRequested => "already_requested",
            Self::AlreadyEnded => "already_ended",
        }
    }
}

/// Records a Stop for `turn_id` in `conversation_id`, which the caller has
/// already authorized (I-20).
///
/// `NotFound` when the conversation has no such turn. The row and its `Ai`
/// security event commit together (D-542); a Stop that writes nothing — the
/// turn already ended, or was already stopped — writes no audit event either.
pub async fn request(
    state: &attome_core::EngineState,
    conversation_id: Uuid,
    turn_id: Uuid,
    requester: Uuid,
) -> Result<CancelOutcome, AppError> {
    let event = attome_audit::security::SecurityEvent::new(
        attome_audit::security::MandatoryCategory::Ai,
        attome_audit::AuditOperation::Update,
        requester,
        "ai_conversation",
        Some(conversation_id),
    )
    .named("ai_conversation.turn_cancel")
    .comment(format!("turn {turn_id}"));
    let mut stx = attome_audit::security::SecurityTx::begin(state, event).await?;

    let (exists, ended): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM ai_message \
                         WHERE conversation_id = $1 AND turn_id = $2), \
                EXISTS (SELECT 1 FROM ai_message \
                         WHERE conversation_id = $1 AND turn_id = $2 \
                           AND terminal_state IS NOT NULL)",
    )
    .bind(conversation_id)
    .bind(turn_id)
    .fetch_one(&mut *stx)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    if ended {
        return Ok(CancelOutcome::AlreadyEnded);
    }
    let inserted = sqlx::query(
        "INSERT INTO ai_turn_cancel (turn_id, conversation_id, requested_by) \
         VALUES ($1, $2, $3) ON CONFLICT (turn_id) DO NOTHING",
    )
    .bind(turn_id)
    .bind(conversation_id)
    .bind(requester)
    .execute(&mut *stx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if inserted == 0 {
        return Ok(CancelOutcome::AlreadyRequested);
    }
    stx.commit().await?;
    Ok(CancelOutcome::Requested)
}

/// Whether a Stop is recorded for `turn_id`.
pub async fn is_requested(db: &PgPool, turn_id: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM ai_turn_cancel WHERE turn_id = $1)")
        .bind(turn_id)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// Resolves once a Stop is recorded for `turn_id` — the cancel future a
/// streaming model call races against.
///
/// A failed read is logged and retried, never treated as a Stop: Stop is the
/// user's convenience, not a security control, and a database hiccup must not
/// end a turn nobody asked to end. The step-boundary check in the loop reads
/// the row again anyway.
pub async fn wait(db: PgPool, turn_id: Uuid) {
    // Warned once per turn, so a database outage is visible without one line
    // every 400 ms for every streaming turn.
    let mut warned = false;
    loop {
        tokio::time::sleep(POLL).await;
        match is_requested(&db, turn_id).await {
            Ok(true) => return,
            Ok(false) => {}
            Err(error) if !warned => {
                warned = true;
                tracing::warn!(%error, %turn_id, "stop check failed; Stop cannot interrupt this stream until it succeeds");
            }
            Err(error) => tracing::debug!(%error, %turn_id, "stop check failed; retrying"),
        }
    }
}
