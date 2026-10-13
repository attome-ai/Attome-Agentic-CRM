//! The conversational ledger (C2, D-552, invariant I-12).
//!
//! **Every event required to reconstruct a turn, and every event emitted to a
//! client, is persisted before it is acted on or emitted.** Nothing a model
//! saw, proposed or did exists only in RAM — which is what makes a turn
//! survivable across a restart, resumable after an approval, and replayable to
//! a reconnecting stream.
//!
//! ## Reads are authorized, never merely addressed (I-20, D-562)
//!
//! Every read in this module takes an [`Access`], and there is no variant that
//! means "trust me". That is not ceremony: `omnichannel.rs` starts every
//! anonymous web-chat session with `owner_user_id` set to the one shared
//! `integration_system` service principal, so **every anonymous visitor's
//! conversation has the same owner** and owner-scoping alone would let one
//! visitor read another's transcript. Making the caller name the scope forces
//! that choice into the open at every call site rather than leaving it to a
//! reviewer to notice.
//!
//! ## The ledger is not model context (I-15, D-559)
//!
//! [`history`] returns everything — statuses, terminal states, provenance —
//! because an operator and an auditor need it. [`context_messages`] returns the
//! strict subset a prompt may contain. A context rebuild calls the second,
//! never the first; the difference is `stopped_because` and `gate_decision`
//! strings reaching a model that will read them as instructions.

use attome_types::AppError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Which principal is asking, and therefore what they may see.
///
/// No `Unscoped` variant exists. An administrative read belongs behind the
/// session-supervisor privilege and its own query, not behind a bypass here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// An authenticated human. Scopes by `owner_user_id`.
    Owner(Uuid),
    /// An anonymous channel, resolved from its bearer token. Scopes by
    /// `agent_session_id` — **never** by owner, because every anonymous
    /// session shares one.
    Session(Uuid),
}

/// The surface a conversation runs on. A closed set, mirroring the migration's
/// `CHECK`: a typo becoming a new surface silently is exactly the drift the
/// constraint exists to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    Internal,
    WebChat,
    Mcp,
    Workflow,
}

impl Surface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::WebChat => "webchat",
            Self::Mcp => "mcp",
            Self::Workflow => "workflow",
        }
    }

    /// The inverse of [`Surface::as_str`]; `None` for anything else.
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Internal, Self::WebChat, Self::Mcp, Self::Workflow]
            .into_iter()
            .find(|v| v.as_str() == s)
    }
}

/// How a turn ended (D-565). Thirteen states — `Cancelled` joined the twelve
/// in C11 (P-4) — and every turn reaches exactly one: "it stopped" is never an
/// acceptable answer to "what happened to my turn".
///
/// Only [`TerminalState::Completed`] is a success. Every other variant
/// **prevents autonomous continuation** — the turn may be resumed by a human
/// act (a new message, a confirmation, an approval), never by the loop
/// deciding to carry on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalState {
    Completed,
    MaxSteps,
    BudgetExceeded,
    SessionRevoked,
    KillSwitch,
    PrivilegeRevoked,
    AwaitingConfirmation,
    AwaitingApproval,
    InvalidToolCall,
    ModelFailure,
    ToolFailure,
    ProtocolError,
    /// The user pressed Stop (C11 B4, row A-84). Not a failure, and not a
    /// success: the turn ended because a person asked it to.
    Cancelled,
}

impl TerminalState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::MaxSteps => "max_steps",
            Self::BudgetExceeded => "budget_exceeded",
            Self::SessionRevoked => "session_revoked",
            Self::KillSwitch => "kill_switch",
            Self::PrivilegeRevoked => "privilege_revoked",
            Self::AwaitingConfirmation => "awaiting_confirmation",
            Self::AwaitingApproval => "awaiting_approval",
            Self::InvalidToolCall => "invalid_tool_call",
            Self::ModelFailure => "model_failure",
            Self::ToolFailure => "tool_failure",
            Self::ProtocolError => "protocol_error",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether the turn may be picked up again by a human act.
    pub fn is_resumable(self) -> bool {
        matches!(self, Self::AwaitingConfirmation | Self::AwaitingApproval)
    }

    /// Whether the loop produced an answer. Everything else stops.
    pub fn is_success(self) -> bool {
        self == Self::Completed
    }
}

/// A message's author.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
    /// A tool's result. Re-enters a prompt as untrusted on every rebuild
    /// (I-15) — being persisted does not launder it.
    Tool,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }

    fn from_str(raw: &str) -> Result<Self, AppError> {
        match raw {
            "user" => Ok(Self::User),
            "assistant" => Ok(Self::Assistant),
            "tool" => Ok(Self::Tool),
            // The CHECK constraint makes this unreachable from our own
            // writes; it is an error rather than a default so a future role
            // cannot be silently read as `User`.
            other => Err(AppError::internal(format!(
                "unknown message role {other:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Conversation {
    pub id: Uuid,
    pub agent_session_id: Uuid,
    pub owner_user_id: Uuid,
    pub agent_definition_ref: Option<Uuid>,
    pub surface: String,
    pub title: Option<String>,
    pub last_ordinal: i64,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

const CONVERSATION_COLUMNS: &str = "id, agent_session_id, owner_user_id, agent_definition_ref, \
     surface, title, last_ordinal, started_at, ended_at, row_version";

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MessageRow {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub ordinal: i64,
    pub role: String,
    pub content: String,
    pub turn_id: Uuid,
    pub terminal_state: Option<String>,
    pub model_id: Option<String>,
    pub prompt_version: Option<String>,
    /// Which persona text produced this answer (C11 B2, migration 0490).
    pub persona_sha256: Option<String>,
    pub created_at: DateTime<Utc>,
}

const MESSAGE_COLUMNS: &str = "id, conversation_id, ordinal, role, content, turn_id, \
     terminal_state, model_id, prompt_version, persona_sha256, created_at";

/// What a caller supplies to start a conversation.
pub struct NewConversation {
    pub agent_session_id: Uuid,
    pub owner_user_id: Uuid,
    pub agent_definition_ref: Option<Uuid>,
    pub surface: Surface,
    pub title: Option<String>,
}

impl std::fmt::Debug for NewConversation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewConversation").finish_non_exhaustive()
    }
}

/// What a caller supplies to append one message.
///
/// `ordinal` is absent on purpose: it is allocated by [`append`] and may not be
/// chosen by a caller, because it is the resume cursor.
pub struct NewMessage {
    pub conversation_id: Uuid,
    pub role: Role,
    pub content: String,
    pub turn_id: Uuid,
    /// Set only on a turn's final assistant message.
    pub terminal_state: Option<TerminalState>,
    pub model_id: Option<String>,
    pub prompt_version: Option<String>,
    pub input_tokens: Option<i32>,
    pub output_tokens: Option<i32>,
}

impl std::fmt::Debug for NewMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewMessage").finish_non_exhaustive()
    }
}

pub async fn create(db: &PgPool, new: NewConversation) -> Result<Conversation, AppError> {
    sqlx::query_as::<_, Conversation>(&format!(
        "INSERT INTO ai_conversation \
             (agent_session_id, owner_user_id, agent_definition_ref, surface, title) \
         VALUES ($1, $2, $3, $4, $5) RETURNING {CONVERSATION_COLUMNS}"
    ))
    .bind(new.agent_session_id)
    .bind(new.owner_user_id)
    .bind(new.agent_definition_ref)
    .bind(new.surface.as_str())
    .bind(new.title)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Loads a conversation **for a principal**, or `None` when it does not exist
/// *or* they may not see it.
///
/// The two are deliberately indistinguishable: a caller learning that a
/// conversation id exists but is not theirs has learned something, and the
/// route maps `None` to `404` rather than `403` for that reason (I-20).
pub async fn load_for(
    db: &PgPool,
    id: Uuid,
    access: Access,
) -> Result<Option<Conversation>, AppError> {
    let (clause, scope) = match access {
        Access::Owner(user_id) => ("owner_user_id = $2", user_id),
        Access::Session(session_id) => ("agent_session_id = $2", session_id),
    };
    sqlx::query_as::<_, Conversation>(&format!(
        "SELECT {CONVERSATION_COLUMNS} FROM ai_conversation WHERE id = $1 AND {clause}"
    ))
    .bind(id)
    .bind(scope)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Appends one message, allocating its ordinal.
///
/// ## The ordinal is allocated, never sequenced
///
/// `UPDATE … SET last_ordinal = last_ordinal + 1 … RETURNING` inside the same
/// transaction as the insert. That row-locks the conversation, which is the
/// serialization the gapless guarantee needs, and a rollback returns the
/// counter with the row so no gap ever becomes visible.
///
/// A PostgreSQL sequence would be wrong here: a rolled-back transaction burns
/// its value permanently, and a gap in a resume cursor is indistinguishable
/// from a lost event (I-14).
///
/// The lock is affordable because it is scoped to one conversation: appends to
/// a single conversation are already serialized by the turn loop, and
/// different conversations never contend.
pub async fn append(db: &PgPool, new: NewMessage) -> Result<MessageRow, AppError> {
    append_linked(db, new, MessageMeta::default()).await
}

/// What a message carries beyond its text: its place in the turn's structure
/// (migration 0488) and which persona produced it (0490).
///
/// Transcript only. The executable payload of a call is its
/// `ai_tool_call` row (D-553); nothing is ever confirmed from here.
#[derive(Debug, Clone, Default)]
pub struct MessageMeta {
    /// On an assistant message: the calls exactly as the model emitted them.
    pub tool_calls: Option<Vec<attome_inference::ToolCall>>,
    /// On a tool message: the call it answers.
    pub tool_call_id: Option<String>,
    /// On an assistant message: the SHA-256 of the session's persona snapshot
    /// the model was given (C11 B2), so an answer is traceable to the exact
    /// instructions that shaped it.
    pub persona_sha256: Option<String>,
}

/// [`append`], recording the message's turn structure and provenance.
pub async fn append_linked(
    db: &PgPool,
    new: NewMessage,
    links: MessageMeta,
) -> Result<MessageRow, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let row = append_in(&mut tx, new, links).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(row)
}

/// [`append`], writing the mandatory `Ai` + `Create` audit event **in the same
/// transaction** as the message (D-542): the human's message that starts a
/// turn (`POST …/messages`). Attributed to `actor` — the human who sent it —
/// not to the agent session; what the agent then does is audited where it
/// happens (`execute::run_executor`).
pub async fn append_audited(
    state: &attome_core::EngineState,
    new: NewMessage,
    actor: Uuid,
) -> Result<MessageRow, AppError> {
    let event = attome_audit::security::SecurityEvent::new(
        attome_audit::security::MandatoryCategory::Ai,
        attome_audit::AuditOperation::Create,
        actor,
        "ai_conversation",
        Some(new.conversation_id),
    )
    .named("ai_conversation.message");
    let mut stx = attome_audit::security::SecurityTx::begin(state, event).await?;
    let row = append_in(&mut stx, new, MessageMeta::default()).await?;
    // C10-A: the human message that starts a turn is the turn's first write,
    // and `turn.started` commits with it.
    crate::conversation_event::record_in(
        &mut stx,
        row.conversation_id,
        Some(row.turn_id),
        crate::conversation_event::EventType::TurnStarted,
        serde_json::json!({ "message_ordinal": row.ordinal }),
    )
    .await?;
    stx.commit().await?;
    Ok(row)
}

/// The two statements every append runs, inside the caller's transaction.
async fn append_in(
    tx: &mut sqlx::PgConnection,
    new: NewMessage,
    links: MessageMeta,
) -> Result<MessageRow, AppError> {
    let ordinal: Option<i64> = sqlx::query_scalar(
        "UPDATE ai_conversation SET last_ordinal = last_ordinal + 1, \
                last_message_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND ended_at IS NULL \
         RETURNING last_ordinal",
    )
    .bind(new.conversation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    // Absent or ended. Appending to an ended conversation is a caller bug, not
    // something to paper over by reviving it.
    let Some(ordinal) = ordinal else {
        return Err(AppError::Validation(
            "conversation does not exist or has ended".into(),
        ));
    };

    let row = sqlx::query_as::<_, MessageRow>(&format!(
        "INSERT INTO ai_message \
             (conversation_id, ordinal, role, content, turn_id, terminal_state, \
              model_id, prompt_version, input_tokens, output_tokens, tool_calls, tool_call_id, \
              persona_sha256) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         RETURNING {MESSAGE_COLUMNS}"
    ))
    .bind(new.conversation_id)
    .bind(ordinal)
    .bind(new.role.as_str())
    .bind(&new.content)
    .bind(new.turn_id)
    .bind(new.terminal_state.map(TerminalState::as_str))
    .bind(new.model_id.as_deref())
    .bind(new.prompt_version.as_deref())
    .bind(new.input_tokens)
    .bind(new.output_tokens)
    .bind(
        links
            .tool_calls
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(AppError::internal)?,
    )
    .bind(links.tool_call_id.as_deref())
    .bind(links.persona_sha256.as_deref())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    // C10-A: a turn's final assistant message is `message.completed` then
    // `turn.completed`, in this same transaction. The event stores the
    // ordinal, never the content: the ledger stays the only copy.
    if let (Role::Assistant, Some(terminal)) = (new.role, new.terminal_state) {
        use crate::conversation_event::{EventType, record_in};
        record_in(
            tx,
            row.conversation_id,
            Some(row.turn_id),
            EventType::MessageCompleted,
            serde_json::json!({ "message_ordinal": row.ordinal }),
        )
        .await?;
        record_in(
            tx,
            row.conversation_id,
            Some(row.turn_id),
            EventType::TurnCompleted,
            serde_json::json!({ "terminal_state": terminal.as_str() }),
        )
        .await?;
    }
    Ok(row)
}

/// The transcript from a cursor, oldest first — the operator and auditor view,
/// and the stream's replay source.
///
/// `after` is exclusive, so a client resuming at its last seen ordinal gets
/// exactly what it missed.
pub async fn history(
    db: &PgPool,
    conversation_id: Uuid,
    after: i64,
    limit: i64,
) -> Result<Vec<MessageRow>, AppError> {
    sqlx::query_as::<_, MessageRow>(&format!(
        "SELECT {MESSAGE_COLUMNS} FROM ai_message \
          WHERE conversation_id = $1 AND ordinal > $2 \
          ORDER BY ordinal ASC LIMIT $3"
    ))
    .bind(conversation_id)
    .bind(after)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// One message as a **model** may see it (I-15, D-559).
///
/// Note what is absent: `terminal_state`, `model_id`, `ordinal`, timestamps,
/// every status and every gate decision. Those are execution and audit state.
/// What is present is turn structure: the calls an assistant message made and
/// the call a tool message answers, which a model needs to read its own
/// history (C11 B1, P-1).
#[derive(Debug, Clone, PartialEq)]
pub struct ContextMessage {
    pub role: Role,
    pub content: String,
    /// On an assistant message that asked for tools.
    pub tool_calls: Vec<attome_inference::ToolCall>,
    /// On a tool message: the call it answers. `None` only for a result
    /// written before migration 0488, which has no link to give.
    pub tool_call_id: Option<String>,
}

impl ContextMessage {
    /// A message with no turn structure.
    pub fn text(role: Role, content: &str) -> Self {
        Self {
            role,
            content: content.to_owned(),
            tool_calls: Vec::new(),
            tool_call_id: None,
        }
    }
}

/// The **only** projection permitted to shape model input from the ledger.
///
/// A context rebuild calls this and never [`history`]. The difference is
/// whether `stopped_because`, `gate_decision` and internal status strings
/// reach a model — wasteful, and a mild injection surface for anything an
/// attacker can influence into those fields.
///
/// The window is [`crate::context_window::build`]: the newest history, whole
/// exchanges, bounded by count and tokens, with the current turn always in.
/// It reads the newest rows — never the first ones, which is what kept a long
/// conversation answering its own opening (row A-72).
///
/// Tool results come back with [`Role::Tool`] and **must be re-wrapped as
/// untrusted by the caller**: being persisted does not launder them. Taint is
/// a property of where content came from, not of which side of a database
/// write it sits on.
pub async fn context_messages(
    db: &PgPool,
    conversation_id: Uuid,
    limits: &crate::context_window::Limits,
) -> Result<Vec<ContextMessage>, AppError> {
    use crate::context_window::{CallFate, FETCH_ROWS, LedgerRow};

    type Row = (String, String, Option<serde_json::Value>, Option<String>);
    let mut rows: Vec<Row> = sqlx::query_as(
        "SELECT role, content, tool_calls, tool_call_id FROM ai_message \
          WHERE conversation_id = $1 ORDER BY ordinal DESC LIMIT $2",
    )
    .bind(conversation_id)
    .bind(FETCH_ROWS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    rows.reverse();

    let rows: Vec<LedgerRow> = rows
        .into_iter()
        .map(|(role, content, tool_calls, tool_call_id)| {
            Ok(LedgerRow {
                role: Role::from_str(&role)?,
                content,
                tool_calls: tool_calls
                    .map(serde_json::from_value::<Vec<attome_inference::ToolCall>>)
                    .transpose()
                    .map_err(AppError::internal)?,
                tool_call_id,
            })
        })
        .collect::<Result<_, AppError>>()?;

    // What became of each call this read contains: a confirmed call's result
    // lives on its tool-call row, not in a message.
    let call_ids: Vec<String> = rows
        .iter()
        .filter_map(|r| r.tool_calls.as_ref())
        .flatten()
        .map(|c| c.id.clone())
        .collect();
    let mut fates = std::collections::HashMap::new();
    if !call_ids.is_empty() {
        let found: Vec<(String, String, Option<serde_json::Value>)> = sqlx::query_as(
            "SELECT DISTINCT ON (tool_call_id) tool_call_id, status, outcome \
               FROM ai_tool_call \
              WHERE conversation_id = $1 AND tool_call_id = ANY($2) \
              ORDER BY tool_call_id, created_at DESC",
        )
        .bind(conversation_id)
        .bind(&call_ids)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        for (id, status, outcome) in found {
            fates.insert(id, CallFate { status, outcome });
        }
    }
    Ok(crate::context_window::build(rows, &fates, limits))
}

/// Whether tool-obtained text has ever entered this conversation — a tool
/// message, or a confirmed call whose result is on its row.
///
/// **I-10 across turns, independent of the window.** An answer that repeated
/// what a tool returned carries it on after the tool message itself has aged
/// out of the window, so taint is decided over the whole conversation, never
/// over what one window happens to show.
pub async fn has_tool_output(db: &PgPool, conversation_id: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM ai_message \
                         WHERE conversation_id = $1 AND role = 'tool') \
             OR EXISTS (SELECT 1 FROM ai_tool_call \
                         WHERE conversation_id = $1 AND status = 'executed')",
    )
    .bind(conversation_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Ends a conversation. Idempotent: the first `ended_at` stands.
///
/// This is the operator lever for knowledge revocation (D-561) — a permission
/// change stops *new* retrieval, while ending the conversation stops it
/// continuing to use what it already retrieved.
pub async fn end(db: &PgPool, id: Uuid, access: Access) -> Result<bool, AppError> {
    let (clause, scope) = match access {
        Access::Owner(user_id) => ("owner_user_id = $2", user_id),
        Access::Session(session_id) => ("agent_session_id = $2", session_id),
    };
    let affected = sqlx::query(&format!(
        "UPDATE ai_conversation SET ended_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND {clause} AND ended_at IS NULL"
    ))
    .bind(id)
    .bind(scope)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(affected > 0)
}

/// The owner's own conversations, newest first — `GET /ai/conversations`.
/// Scoped by `owner_user_id` in SQL; there is no unscoped variant (I-20).
pub async fn list_for_owner(
    db: &PgPool,
    owner_user_id: Uuid,
    page: i64,
    page_size: i64,
) -> Result<(Vec<Conversation>, i64), AppError> {
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ai_conversation WHERE owner_user_id = $1")
            .bind(owner_user_id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    let rows = sqlx::query_as::<_, Conversation>(&format!(
        "SELECT {CONVERSATION_COLUMNS} FROM ai_conversation \
          WHERE owner_user_id = $1 \
          ORDER BY started_at DESC, id DESC LIMIT $2 OFFSET $3"
    ))
    .bind(owner_user_id)
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok((rows, total))
}

/// What ending a conversation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndOutcome {
    /// Ended now, and its session revoked.
    Ended,
    /// It had already ended. Nothing changed, no event written.
    AlreadyEnded,
    /// No such conversation for this owner (I-20).
    NotFound,
}

/// `DELETE /ai/conversations/{id}`: ends the conversation **and revokes its
/// session**, with the mandatory `Ai` + `Closed` event, all in one
/// transaction (D-542). Ending the conversation alone would leave its session
/// live and dispatchable; revoking alone would leave a conversation that
/// claims to be open.
///
/// Lock order: the session row, then the conversation row — the same "session
/// first" order the confirm path uses, so the two never lock in opposite
/// orders.
pub async fn end_and_revoke(
    state: &attome_core::EngineState,
    id: Uuid,
    owner_user_id: Uuid,
) -> Result<EndOutcome, AppError> {
    let db = &state.base.db;
    let found: Option<(Uuid, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT agent_session_id, ended_at FROM ai_conversation \
          WHERE id = $1 AND owner_user_id = $2",
    )
    .bind(id)
    .bind(owner_user_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((session_id, ended_at)) = found else {
        return Ok(EndOutcome::NotFound);
    };
    if ended_at.is_some() {
        return Ok(EndOutcome::AlreadyEnded);
    }

    let event = attome_audit::security::SecurityEvent::new(
        attome_audit::security::MandatoryCategory::Ai,
        attome_audit::AuditOperation::Closed,
        owner_user_id,
        "ai_conversation",
        Some(id),
    )
    .named("ai_conversation.end")
    .comment(format!("agent session {session_id} revoked with it"));
    let mut stx = attome_audit::security::SecurityTx::begin(state, event).await?;
    sqlx::query(
        "UPDATE agent_session \
            SET revoked_at = NOW(), revoked_by = $2, revoked_reason = 'conversation ended' \
          WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(session_id)
    .bind(owner_user_id)
    .execute(&mut *stx)
    .await
    .map_err(AppError::internal)?;
    let ended = sqlx::query(
        "UPDATE ai_conversation SET ended_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND owner_user_id = $2 AND ended_at IS NULL",
    )
    .bind(id)
    .bind(owner_user_id)
    .execute(&mut *stx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if ended == 0 {
        // Ended concurrently between the read and this write: drop the
        // transaction (no event, the revoke above rolls back with it).
        return Ok(EndOutcome::AlreadyEnded);
    }
    stx.commit().await?;
    Ok(EndOutcome::Ended)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The twelve states of D-565, and the property that matters
    /// operationally: only one of them is a success, and only two may be
    /// picked up again.
    #[test]
    fn terminal_states_classify_correctly() {
        use TerminalState::*;
        let all = [
            Completed,
            MaxSteps,
            BudgetExceeded,
            SessionRevoked,
            KillSwitch,
            PrivilegeRevoked,
            AwaitingConfirmation,
            AwaitingApproval,
            InvalidToolCall,
            ModelFailure,
            ToolFailure,
            ProtocolError,
        ];
        assert_eq!(all.len(), 12, "D-565 names twelve terminal states");

        let successes: Vec<_> = all.iter().filter(|s| s.is_success()).collect();
        assert_eq!(
            successes.len(),
            1,
            "exactly one terminal state is a success; every other must stop the turn"
        );

        let resumable: Vec<_> = all.iter().filter(|s| s.is_resumable()).collect();
        assert_eq!(
            resumable.len(),
            2,
            "only a pending confirmation or approval may be resumed, and only by a human act"
        );
        assert!(!MaxSteps.is_resumable(), "the loop may never resume itself");
        assert!(!BudgetExceeded.is_resumable());
    }

    /// Every state's string must match migration 0479's CHECK constraint. A
    /// mismatch is a runtime insert failure on a path that only fires when
    /// something has already gone wrong, which is the worst time to find it.
    #[test]
    fn terminal_state_strings_are_snake_case_and_distinct() {
        use TerminalState::*;
        let all = [
            Completed,
            MaxSteps,
            BudgetExceeded,
            SessionRevoked,
            KillSwitch,
            PrivilegeRevoked,
            AwaitingConfirmation,
            AwaitingApproval,
            InvalidToolCall,
            ModelFailure,
            ToolFailure,
            ProtocolError,
        ];
        let mut seen: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        seen.sort_unstable();
        let len = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), len, "terminal state strings must be distinct");
        for s in all {
            let text = s.as_str();
            assert!(
                text.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{text} must match the migration's CHECK vocabulary"
            );
        }
    }

    /// An unknown role is an error, never a silent `User`. A future role read
    /// as a user message would put tool output into the prompt as if the human
    /// had typed it.
    #[test]
    fn an_unknown_role_is_refused_rather_than_defaulted() {
        assert!(Role::from_str("assistant").is_ok());
        assert!(Role::from_str("system").is_err());
        assert!(Role::from_str("").is_err());
    }

    /// `Access` has no "trust me" variant, and the two it has scope by
    /// different columns. This is the I-20 boundary in one assertion.
    #[test]
    fn access_distinguishes_owner_from_anonymous_session() {
        let a = Access::Owner(Uuid::nil());
        let b = Access::Session(Uuid::nil());
        assert_ne!(
            a, b,
            "an owner and a session scope must never compare equal: every \
             anonymous session shares one owner"
        );
    }
}
