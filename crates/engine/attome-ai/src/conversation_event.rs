//! C10-A — the per-conversation durable event log the conversation stream
//! replays and follows (I-14, row A-12). The contract is
//! `document/chatbot/01-architecture.md`, "C10-A: the semantic event contract";
//! migration `0484` owns the table.
//!
//! ## A projection, never a second copy
//!
//! `ai_message` and `ai_tool_call` stay authoritative. An event row
//! carries references and small labels only — never message content, tool
//! arguments or an outcome — so there is one history, and the stream reads
//! content from the ledger when it sends a frame.
//!
//! ## Written with the state change, or not at all
//!
//! [`record_in`] is the only writer, and it takes the caller's transaction:
//! every event commits with the state change it records, and a rolled-back
//! change leaves no event and consumes no ordinal. The ordinal is gapless and
//! allocated the way message ordinals are (`UPDATE ... RETURNING` on the
//! conversation row), from its own counter, so message ordinals keep their
//! meaning. The row lock serializes one conversation's writers, so its events
//! commit in ordinal order — which is what lets a reader poll
//! `ordinal > cursor` without skipping or repeating one.
//!
//! ## Approvals resolve in the approval's own transaction
//!
//! [`ApprovalConversationHook`] is the `attome_db::BeforeCommit` hook the
//! approval transitions run just before they commit. For an
//! `attome-ai/invoke:*` request linked to a conversation tool call it moves the
//! tool call and writes `approval.resolved` and the matching
//! `tool.call.completed`/`failed` in that same transaction. The approval layer
//! stays conversation-agnostic; [`reconcile_approvals`] is recovery only, for
//! a transition that ran without the hook, and applies the same function.

use attome_approval::{ApprovalRequest, ApprovalStatus};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::tool_call::{Status, ToolCallRow};

/// The nine semantic events of the frozen contract. Nothing else is an event:
/// token deltas are transport-only, and leases, gate decisions, invocation
/// claims and tool-result messages are internal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    TurnStarted,
    ToolCallProposed,
    ToolCallStarted,
    ToolCallCompleted,
    ToolCallFailed,
    ApprovalRequired,
    ApprovalResolved,
    MessageCompleted,
    TurnCompleted,
}

impl EventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TurnStarted => "turn.started",
            Self::ToolCallProposed => "tool.call.proposed",
            Self::ToolCallStarted => "tool.call.started",
            Self::ToolCallCompleted => "tool.call.completed",
            Self::ToolCallFailed => "tool.call.failed",
            Self::ApprovalRequired => "approval.required",
            Self::ApprovalResolved => "approval.resolved",
            Self::MessageCompleted => "message.completed",
            Self::TurnCompleted => "turn.completed",
        }
    }
}

/// Appends one event inside the caller's transaction and returns its ordinal.
///
/// The only writer. The caller's transaction is the state change the event
/// records; committing it commits both, and rolling it back returns the
/// ordinal with the event.
pub async fn record_in(
    conn: &mut PgConnection,
    conversation_id: Uuid,
    turn_id: Option<Uuid>,
    event: EventType,
    payload: Value,
) -> Result<i64, AppError> {
    let ordinal: i64 = sqlx::query_scalar(
        "UPDATE ai_conversation SET last_event_ordinal = last_event_ordinal + 1 \
          WHERE id = $1 RETURNING last_event_ordinal",
    )
    .bind(conversation_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    sqlx::query(
        "INSERT INTO ai_conversation_event \
             (conversation_id, ordinal, turn_id, event_type, payload) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(conversation_id)
    .bind(ordinal)
    .bind(turn_id)
    .bind(event.as_str())
    .bind(payload)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(ordinal)
}

/// The event a tool call's **new** status records, read from the row the
/// state change's own `UPDATE ... RETURNING` produced. `reopened` marks a
/// claimed call returned to `proposed`.
pub async fn tool_call_in(
    conn: &mut PgConnection,
    row: &ToolCallRow,
    reopened: bool,
) -> Result<(), AppError> {
    let status = Status::parse(&row.status).ok_or_else(|| {
        AppError::internal(format!(
            "ai_tool_call carries an unknown status {:?}",
            row.status
        ))
    })?;
    let (event, payload) = match status {
        Status::Proposed => (
            EventType::ToolCallProposed,
            json!({
                "tool_call_id": row.tool_call_id,
                "action_id": row.action_id,
                "arguments_hash": row.arguments_hash,
                "reopened": reopened,
            }),
        ),
        Status::Executing => (
            EventType::ToolCallStarted,
            json!({ "tool_call_id": row.tool_call_id, "action_id": row.action_id }),
        ),
        Status::Executed => (
            EventType::ToolCallCompleted,
            json!({ "tool_call_id": row.tool_call_id, "action_id": row.action_id }),
        ),
        Status::Rejected | Status::Invalidated | Status::Expired => (
            EventType::ToolCallFailed,
            json!({
                "tool_call_id": row.tool_call_id,
                "action_id": row.action_id,
                "status": status.as_str(),
            }),
        ),
        Status::ApprovalPending => (
            EventType::ApprovalRequired,
            json!({
                "tool_call_id": row.tool_call_id,
                "action_id": row.action_id,
                "approval_request_id": row.approval_request_id,
            }),
        ),
    };
    record_in(conn, row.conversation_id, Some(row.turn_id), event, payload)
        .await
        .map(|_| ())
}

/// One stored event, as the stream replays it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EventRow {
    pub ordinal: i64,
    pub turn_id: Option<Uuid>,
    pub event_type: String,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
}

/// Events with `ordinal > after`, in order, at most `limit`.
pub async fn list_after(
    db: &PgPool,
    conversation_id: Uuid,
    after: i64,
    limit: i64,
) -> Result<Vec<EventRow>, AppError> {
    sqlx::query_as::<_, EventRow>(
        "SELECT ordinal, turn_id, event_type, payload, created_at \
           FROM ai_conversation_event \
          WHERE conversation_id = $1 AND ordinal > $2 \
          ORDER BY ordinal LIMIT $3",
    )
    .bind(conversation_id)
    .bind(after)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

const TOOL_CALL_COLUMNS: &str = "id, conversation_id, turn_id, tool_call_id, action_id, \
     arguments, arguments_hash, status, claimed_at, approval_request_id, row_version";

/// The `BeforeCommit` hook the approval transitions run (decide, execute,
/// invalidate, expire). It does nothing for a request that is not an
/// `attome-ai/invoke:*` one or has no conversation tool call.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApprovalConversationHook;

impl attome_db::BeforeCommit<ApprovalRequest> for ApprovalConversationHook {
    fn before_commit<'a>(
        &'a self,
        tx: &'a mut attome_db::Tx<'_>,
        committed: &'a ApprovalRequest,
    ) -> attome_db::HookFuture<'a> {
        Box::pin(async move { apply_approval_transition(tx, committed).await })
    }
}

/// Applies an approval request's (new) status to its linked tool call and
/// writes the contract's events, in the caller's transaction.
///
/// **Exactly once.** Every tool-call change is conditional on
/// `status = 'approval_pending'` with the row locked, and
/// `approval.resolved{approved}` is written only if none exists for that tool
/// call; a repeat — a second hook, or the recovery reconcile — changes and
/// writes nothing.
///
/// `Pending` needs nothing. `Cancelled` — the requester withdrew the request —
/// is `approval.resolved{cancelled}` and `tool.call.failed{rejected}` (the
/// contract amendment of 2026-09-22: a human declined it, and the turn's state
/// must not stay ambiguous).
pub async fn apply_approval_transition(
    conn: &mut PgConnection,
    request: &ApprovalRequest,
) -> Result<(), AppError> {
    if !request
        .action_type
        .starts_with(crate::approval::ACTION_TYPE_PREFIX)
    {
        return Ok(());
    }
    match request.status {
        // `Executing` (D-518): the admin execution path has claimed an
        // approved request and is running its action. The decision is made,
        // so it resolves like `Approved`; the tool call itself stays pending
        // until the claim closes as `Executed` or `Invalidated`.
        ApprovalStatus::Approved | ApprovalStatus::Executing => {
            ensure_approved_resolved(conn, request.id).await
        }
        ApprovalStatus::Rejected => {
            close_pending(conn, request.id, Status::Rejected, Some("rejected")).await
        }
        ApprovalStatus::Expired => {
            close_pending(conn, request.id, Status::Expired, Some("expired")).await
        }
        ApprovalStatus::Executed => {
            ensure_approved_resolved(conn, request.id).await?;
            close_pending(conn, request.id, Status::Executed, None).await
        }
        ApprovalStatus::Invalidated => {
            ensure_approved_resolved(conn, request.id).await?;
            close_pending(conn, request.id, Status::Invalidated, None).await
        }
        ApprovalStatus::Cancelled => {
            close_pending(conn, request.id, Status::Rejected, Some("cancelled")).await
        }
        ApprovalStatus::Pending => Ok(()),
    }
}

/// Writes `approval.resolved{approved}` for each still-pending tool call of
/// `request_id` that has none yet. The tool call itself stays
/// `approval_pending`: an approved action has not run.
async fn ensure_approved_resolved(
    conn: &mut PgConnection,
    request_id: Uuid,
) -> Result<(), AppError> {
    let pending: Vec<ToolCallRow> = sqlx::query_as(&format!(
        "SELECT {TOOL_CALL_COLUMNS} FROM ai_tool_call \
          WHERE approval_request_id = $1 AND status = 'approval_pending' FOR UPDATE"
    ))
    .bind(request_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    for row in pending {
        let already: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM ai_conversation_event \
                WHERE conversation_id = $1 AND event_type = 'approval.resolved' \
                  AND payload->>'tool_call_id' = $2)",
        )
        .bind(row.conversation_id)
        .bind(&row.tool_call_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        if !already {
            record_in(
                conn,
                row.conversation_id,
                Some(row.turn_id),
                EventType::ApprovalResolved,
                json!({
                    "tool_call_id": row.tool_call_id,
                    "approval_request_id": request_id,
                    "decision": "approved",
                }),
            )
            .await?;
        }
    }
    Ok(())
}

/// Moves each still-pending tool call of `request_id` to the terminal
/// `status`, writing `approval.resolved{decision}` (when the approval itself
/// decided it) and the tool call's terminal event.
async fn close_pending(
    conn: &mut PgConnection,
    request_id: Uuid,
    status: Status,
    decision: Option<&str>,
) -> Result<(), AppError> {
    let closed: Vec<ToolCallRow> = sqlx::query_as(&format!(
        "UPDATE ai_tool_call \
            SET status = $2, claimed_at = NULL, resolved_at = NOW(), \
                row_version = row_version + 1 \
          WHERE approval_request_id = $1 AND status = 'approval_pending' \
         RETURNING {TOOL_CALL_COLUMNS}"
    ))
    .bind(request_id)
    .bind(status.as_str())
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    for row in closed {
        if let Some(decision) = decision {
            record_in(
                conn,
                row.conversation_id,
                Some(row.turn_id),
                EventType::ApprovalResolved,
                json!({
                    "tool_call_id": row.tool_call_id,
                    "approval_request_id": request_id,
                    "decision": decision,
                }),
            )
            .await?;
        }
        tool_call_in(conn, &row, false).await?;
    }
    Ok(())
}

/// **Recovery only.** Finds `approval_pending` tool calls whose approval
/// request already moved past them without the hook (a decision bounced as
/// expired, a plan-step timeout, a caller that forgot the hook) and applies
/// [`apply_approval_transition`] to each, in its own transaction. By that
/// function's exactly-once rules it writes each missing event once and never a
/// duplicate. Returns how many requests it applied.
pub async fn reconcile_approvals(db: &PgPool) -> Result<u64, AppError> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT t.approval_request_id \
           FROM ai_tool_call t \
           JOIN approval_request r ON r.id = t.approval_request_id \
          WHERE t.status = 'approval_pending' \
            AND (r.status IN ('rejected', 'expired', 'cancelled', 'executed', 'invalidated') \
                 OR (r.status = 'approved' AND NOT EXISTS ( \
                        SELECT 1 FROM ai_conversation_event e \
                         WHERE e.conversation_id = t.conversation_id \
                           AND e.event_type = 'approval.resolved' \
                           AND e.payload->>'tool_call_id' = t.tool_call_id))) \
          LIMIT 500",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut applied = 0;
    for id in ids {
        let request = attome_approval::get(db, id).await?;
        let mut tx = attome_db::tx::begin(db).await?;
        apply_approval_transition(&mut tx, &request).await?;
        tx.commit().await.map_err(AppError::internal)?;
        applied += 1;
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stored names are the migration's CHECK list, one for one.
    #[test]
    fn event_names_match_the_contract() {
        let all = [
            EventType::TurnStarted,
            EventType::ToolCallProposed,
            EventType::ToolCallStarted,
            EventType::ToolCallCompleted,
            EventType::ToolCallFailed,
            EventType::ApprovalRequired,
            EventType::ApprovalResolved,
            EventType::MessageCompleted,
            EventType::TurnCompleted,
        ];
        let migration = include_str!("../../../apps/attome/migrations/0008_modules.sql");
        for event in all {
            assert!(
                migration.contains(&format!("'{}'", event.as_str())),
                "{} missing from the migration CHECK",
                event.as_str()
            );
        }
        assert_eq!(all.len(), 9);
    }
}
