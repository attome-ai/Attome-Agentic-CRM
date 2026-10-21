//! AI7-T2: hand-offs between agents and people on a ticket
//! (`service_handoff`, migration `0043`).
//!
//! - [`create_handoff`] records who hands the ticket to whom (an agent, a
//!   person or a queue) with a summary and the reasoning. To a queue, the
//!   ticket moves to that queue unassigned, for the queue to hand out; to a
//!   person, it is assigned to them at once ([`crate::queue::set_assignee`],
//!   the assignment `assign_ticket` uses). A ticket has at most one
//!   hand-off waiting: a second is a conflict (the partial unique index
//!   holds it even across nodes), and the work is serialised per ticket by
//!   `pg_try_advisory_xact_lock(ADVISORY_LOCK_NAMESPACE,
//!   hashtext('attome-service/handoff:{ticket}'))` — a held lock is a
//!   conflict, never a wait.
//! - [`accept_handoff`]: only the person it was handed to, or an active
//!   member of the queue it was handed to, accepts; the ticket is then
//!   theirs.
//! - [`return_to_agent`]: only the ticket's assignee returns a hand-off an
//!   agent made, with a note; the job `ai_handback` (queued in the same
//!   transaction) resumes the agent — this crate never calls the AI engine.
//!
//! Every step writes a business event on the ticket, so its timeline shows
//! the hand-off with its summary and reasoning. All three take the caller's
//! transaction and do no external I/O inside it.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The hand-back job's name (handled by the application, which runs the
/// agent).
pub const HANDBACK_JOB: &str = "ai_handback";
/// The longest summary or reasoning kept.
pub const MAX_TEXT_CHARS: usize = 4_000;

/// Who hands a ticket off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FromKind {
    Agent,
    User,
}

/// Who a ticket is handed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToKind {
    Agent,
    User,
    Queue,
}

impl FromKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::User => "user",
        }
    }
}

impl ToKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::User => "user",
            Self::Queue => "queue",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "agent" => Some(Self::Agent),
            "user" => Some(Self::User),
            "queue" => Some(Self::Queue),
            _ => None,
        }
    }
}

/// A hand-off to record.
#[derive(Debug, Clone)]
pub struct NewHandoff {
    pub ticket_id: Uuid,
    pub from_kind: FromKind,
    /// The agent definition, or the person.
    pub from_ref: Uuid,
    pub to_kind: ToKind,
    /// The agent, the person or the queue.
    pub to_ref: Uuid,
    pub summary: String,
    pub reasoning: String,
    /// The agent session that handed it off, when an agent did.
    pub agent_session_ref: Option<Uuid>,
}

/// One hand-off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Handoff {
    pub id: Uuid,
    pub ticket_id: Uuid,
    pub from_kind: String,
    pub from_ref: Uuid,
    pub to_kind: String,
    pub to_ref: Uuid,
    pub summary: String,
    pub reasoning: String,
    pub agent_session_ref: Option<Uuid>,
    /// `pending`, `accepted`, `returned` or `cancelled`.
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub returned_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

/// The hand-back job's payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandBack {
    pub handoff_id: Uuid,
    /// The person's note for the agent.
    pub note: String,
    /// Who returned it.
    pub returned_by: Uuid,
}

/// Whether `user` may accept a hand-off to (`to_kind`, `to_ref`): the person
/// it names, or an active member of the queue it names. A hand-off to an
/// agent is not a person's to accept. Pure.
pub fn may_accept(to_kind: ToKind, to_ref: Uuid, user: Uuid, queue_member: bool) -> bool {
    match to_kind {
        ToKind::User => to_ref == user,
        ToKind::Queue => queue_member,
        ToKind::Agent => false,
    }
}

/// Whether `user` may return a ticket to the agent: only its current
/// assignee. Pure.
pub fn may_return(assignee: Option<Uuid>, user: Uuid) -> bool {
    assignee == Some(user)
}

/// A summary or reasoning, trimmed and capped; empty is refused. Pure.
pub fn required_text(value: &str, what: &str) -> Result<String, AppError> {
    let text: String = value.trim().chars().take(MAX_TEXT_CHARS).collect();
    if text.is_empty() {
        return Err(AppError::Validation(format!("{what} is required")));
    }
    Ok(text)
}

/// The lock key that serialises hand-offs of one ticket. Pure.
pub fn lock_key(ticket: Uuid) -> String {
    format!("attome-service/handoff:{ticket}")
}

async fn lock_ticket(tx: &mut attome_db::Tx<'_>, ticket: Uuid) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(lock_key(ticket))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another hand-off of this ticket is in progress",
        ));
    }
    Ok(())
}

async fn event(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    ticket: Uuid,
    what: String,
    user: Uuid,
) -> Result<(), AppError> {
    attome_audit::write_business_event_in_tx(
        tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "service_ticket",
            ticket,
            attome_audit::AuditOperation::Update,
            &what,
            user,
        ),
    )
    .await
    .map(|_| ())
}

type HandoffRow = (
    Uuid,
    Uuid,
    String,
    Uuid,
    String,
    Uuid,
    String,
    String,
    Option<Uuid>,
    String,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    i64,
);

const HANDOFF_COLUMNS: &str = "id, ticket_id, from_kind, from_ref, to_kind, to_ref, summary, \
     reasoning, agent_session_ref, status, created_at, accepted_at, returned_at, row_version";

fn from_row(row: HandoffRow) -> Handoff {
    let (
        id,
        ticket_id,
        from_kind,
        from_ref,
        to_kind,
        to_ref,
        summary,
        reasoning,
        agent_session_ref,
        status,
        created_at,
        accepted_at,
        returned_at,
        row_version,
    ) = row;
    Handoff {
        id,
        ticket_id,
        from_kind,
        from_ref,
        to_kind,
        to_ref,
        summary,
        reasoning,
        agent_session_ref,
        status,
        created_at,
        accepted_at,
        returned_at,
        row_version,
    }
}

/// One hand-off, locked for the caller's change.
async fn load_for_update(tx: &mut attome_db::Tx<'_>, id: Uuid) -> Result<Handoff, AppError> {
    let row: Option<HandoffRow> = sqlx::query_as(&format!(
        "SELECT {HANDOFF_COLUMNS} FROM service_handoff WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    row.map(from_row).ok_or(AppError::NotFound)
}

/// One hand-off.
pub async fn get_handoff(db: &attome_db::DbPool, id: Uuid) -> Result<Handoff, AppError> {
    let row: Option<HandoffRow> = sqlx::query_as(&format!(
        "SELECT {HANDOFF_COLUMNS} FROM service_handoff WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    row.map(from_row).ok_or(AppError::NotFound)
}

/// Records a hand-off; its id. See the module doc.
pub async fn create_handoff(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    input: NewHandoff,
    actor: Uuid,
) -> Result<Uuid, AppError> {
    let summary = required_text(&input.summary, "summary")?;
    let reasoning = required_text(&input.reasoning, "reasoning")?;
    lock_ticket(tx, input.ticket_id).await?;
    let ticket: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM service_ticket \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(input.ticket_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    ticket.ok_or(AppError::NotFound)?;
    let waiting: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM service_handoff WHERE ticket_id = $1 AND status = 'pending')",
    )
    .bind(input.ticket_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if waiting {
        return Err(AppError::Conflict(
            "this ticket already has a hand-off waiting",
        ));
    }
    if input.to_kind == ToKind::Queue {
        let queue: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM service_work_queue WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(input.to_ref)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        queue.ok_or_else(|| AppError::Validation("no such active queue".into()))?;
    }
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO service_handoff \
           (ticket_id, from_kind, from_ref, to_kind, to_ref, summary, reasoning, agent_session_ref) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(input.ticket_id)
    .bind(input.from_kind.as_str())
    .bind(input.from_ref)
    .bind(input.to_kind.as_str())
    .bind(input.to_ref)
    .bind(&summary)
    .bind(&reasoning)
    .bind(input.agent_session_ref)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            AppError::Conflict("this ticket already has a hand-off waiting")
        }
        other => AppError::internal(other),
    })?;
    match input.to_kind {
        ToKind::Queue => {
            sqlx::query(
                "UPDATE service_ticket SET work_queue_ref = $2, assignee_id = NULL WHERE id = $1",
            )
            .bind(input.ticket_id)
            .bind(input.to_ref)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
        }
        ToKind::User => {
            crate::queue::set_assignee(tx, input.ticket_id, input.to_ref, false).await?;
        }
        ToKind::Agent => {}
    }
    event(
        tx,
        state,
        input.ticket_id,
        format!(
            "Handed off by {} to {}: {summary}\nReasoning: {reasoning}",
            input.from_kind.as_str(),
            input.to_kind.as_str()
        ),
        actor,
    )
    .await?;
    Ok(id)
}

/// Accepts a waiting hand-off at `expected` row version; the ticket becomes
/// the caller's.
pub async fn accept_handoff(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    id: Uuid,
    user: Uuid,
    expected: i64,
) -> Result<Handoff, AppError> {
    let handoff = load_for_update(tx, id).await?;
    let to_kind = ToKind::parse(&handoff.to_kind)
        .ok_or_else(|| AppError::internal("unknown hand-off target kind"))?;
    let member = if to_kind == ToKind::Queue {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM service_work_queue_member \
              WHERE queue_ref = $1 AND user_ref = $2 AND (is_active IS NULL OR is_active = true))",
        )
        .bind(handoff.to_ref)
        .bind(user)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?
    } else {
        false
    };
    if !may_accept(to_kind, handoff.to_ref, user, member) {
        return Err(AppError::Forbidden);
    }
    if handoff.status != "pending" {
        return Err(AppError::Conflict("this hand-off is no longer waiting"));
    }
    if handoff.row_version != expected {
        return Err(AppError::VersionConflict);
    }
    lock_ticket(tx, handoff.ticket_id).await?;
    sqlx::query(
        "UPDATE service_handoff SET status = 'accepted', accepted_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    crate::queue::set_assignee(tx, handoff.ticket_id, user, false).await?;
    event(
        tx,
        state,
        handoff.ticket_id,
        format!("Hand-off accepted: {}", handoff.summary),
        user,
    )
    .await?;
    let mut accepted = handoff;
    accepted.status = "accepted".into();
    accepted.accepted_at = Some(Utc::now());
    accepted.row_version += 1;
    Ok(accepted)
}

/// Returns an agent's hand-off to the agent with the caller's note, at
/// `expected` row version, and queues the hand-back.
pub async fn return_to_agent(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    id: Uuid,
    user: Uuid,
    note: &str,
    expected: i64,
) -> Result<Handoff, AppError> {
    let note = required_text(note, "note")?;
    let handoff = load_for_update(tx, id).await?;
    let assignee: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT assignee_id FROM service_ticket WHERE id = $1")
            .bind(handoff.ticket_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    if !may_return(assignee.flatten(), user) {
        return Err(AppError::Forbidden);
    }
    if handoff.from_kind != FromKind::Agent.as_str() {
        return Err(AppError::Validation(
            "only a hand-off an agent made goes back to an agent".into(),
        ));
    }
    if !matches!(handoff.status.as_str(), "pending" | "accepted") {
        return Err(AppError::Conflict("this hand-off is already closed"));
    }
    if handoff.row_version != expected {
        return Err(AppError::VersionConflict);
    }
    lock_ticket(tx, handoff.ticket_id).await?;
    sqlx::query(
        "UPDATE service_handoff SET status = 'returned', returned_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let job = attome_jobs::RegisteredJob {
        name: HANDBACK_JOB.to_owned(),
        version: 1,
        payload: serde_json::to_value(HandBack {
            handoff_id: id,
            note: note.clone(),
            returned_by: user,
        })
        .map_err(AppError::internal)?,
        next: None,
    };
    attome_jobs::enqueue_in_tx(tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    event(
        tx,
        state,
        handoff.ticket_id,
        format!("Returned to the agent: {note}"),
        user,
    )
    .await?;
    let mut returned = handoff;
    returned.status = "returned".into();
    returned.returned_at = Some(Utc::now());
    returned.row_version += 1;
    Ok(returned)
}

// ── For people (AI7-T5's routes) ──────────────────────────────────────────

/// The hand-offs waiting for `user`: to them, or to a queue they are an
/// active member of; newest first.
pub async fn pending_for(
    db: &attome_db::DbPool,
    user: Uuid,
    page: &attome_types::OnePageQuery,
) -> Result<attome_types::PaginatedResponse<Handoff>, AppError> {
    let window = page.window();
    let mine = "h.status = 'pending' AND ((h.to_kind = 'user' AND h.to_ref = $1) \
         OR (h.to_kind = 'queue' AND EXISTS (SELECT 1 FROM service_work_queue_member m \
             WHERE m.queue_ref = h.to_ref AND m.user_ref = $1 \
               AND (m.is_active IS NULL OR m.is_active = true))))";
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM service_handoff h WHERE {mine}"
    ))
    .bind(user)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let columns = HANDOFF_COLUMNS
        .split(", ")
        .map(|c| format!("h.{}", c.trim()))
        .collect::<Vec<_>>()
        .join(", ");
    let rows: Vec<HandoffRow> = sqlx::query_as(&format!(
        "SELECT {columns} FROM service_handoff h WHERE {mine} \
          ORDER BY h.created_at DESC, h.id LIMIT $2 OFFSET $3"
    ))
    .bind(user)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(attome_types::PaginatedResponse::new(
        rows.into_iter().map(from_row).collect(),
        total,
        window.page,
        window.page_size,
    ))
}

/// A person accepts a hand-off, in its own transaction.
pub async fn accept(
    state: &EngineState,
    user: Uuid,
    id: Uuid,
    expected: i64,
) -> Result<Handoff, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let accepted = accept_handoff(&mut tx, state, id, user, expected).await?;
    attome_db::tx::commit(tx).await?;
    Ok(accepted)
}

/// A person returns a hand-off to the agent, in its own transaction.
pub async fn give_back(
    state: &EngineState,
    user: Uuid,
    id: Uuid,
    note: &str,
    expected: i64,
) -> Result<Handoff, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let returned = return_to_agent(&mut tx, state, id, user, note, expected).await?;
    attome_db::tx::commit(tx).await?;
    Ok(returned)
}

/// A person hands a ticket they can see to a person, a queue or an agent
/// member of a queue they can see; the hand-off's id.
pub async fn hand_off_by_person(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    ticket: Uuid,
    to_kind: ToKind,
    to_ref: Uuid,
    summary: &str,
    reasoning: &str,
) -> Result<Uuid, AppError> {
    attome_records::entity_crud::read_record_bulk(state, ctx, "service_ticket", ticket).await?;
    let target = match to_kind {
        ToKind::User => "user_account",
        ToKind::Queue => "service_work_queue",
        ToKind::Agent => "ai_agent",
    };
    match attome_records::entity_crud::read_record_bulk(state, ctx, target, to_ref).await {
        Ok(_) => {}
        Err(AppError::NotFound | AppError::Forbidden) => {
            return Err(AppError::Validation(format!(
                "no {} you can see has that id",
                to_kind.as_str()
            )));
        }
        Err(error) => return Err(error),
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let id = create_handoff(
        &mut tx,
        state,
        NewHandoff {
            ticket_id: ticket,
            from_kind: FromKind::User,
            from_ref: ctx.user_id,
            to_kind,
            to_ref,
            summary: summary.to_owned(),
            reasoning: reasoning.to_owned(),
            agent_session_ref: None,
        },
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_target_can_accept() {
        let me = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        assert!(may_accept(ToKind::User, me, me, false));
        assert!(!may_accept(ToKind::User, other, me, false));
        assert!(may_accept(ToKind::Queue, other, me, true), "a queue member");
        assert!(!may_accept(ToKind::Queue, other, me, false));
        assert!(
            !may_accept(ToKind::Agent, me, me, true),
            "an agent's hand-off is not a person's"
        );
    }

    #[test]
    fn only_assignee_can_return() {
        let me = Uuid::from_u128(1);
        assert!(may_return(Some(me), me));
        assert!(!may_return(Some(Uuid::from_u128(2)), me));
        assert!(!may_return(None, me));
    }

    #[test]
    fn summary_and_reasoning_are_required() {
        assert!(required_text("  ", "reasoning").is_err());
        assert_eq!(required_text(" why ", "reasoning").expect("kept"), "why");
        assert_eq!(
            required_text(&"x".repeat(5_000), "summary")
                .expect("capped")
                .len(),
            MAX_TEXT_CHARS
        );
        assert_eq!(
            lock_key(Uuid::nil()),
            format!("attome-service/handoff:{}", Uuid::nil())
        );
    }
}
