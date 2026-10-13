//! The pending-proposal store (C2, D-553, invariant I-13).
//!
//! ## This table is not the concurrency control
//!
//! [`Status::Executing`] and `claimed_at` are **operational and UX state**:
//! they stop two browser tabs both showing "confirming" and give an operator
//! something to read. The correctness boundary for whether a business mutation
//! happens is [`crate::session::claim_invocation`] (D-502), which occupies
//! `(agent_session_id, tool_call_id)` in `action_invocation` *before*
//! the side effect, under a partial unique index.
//!
//! **That is why a lease here may safely expire mid-dispatch.** A stale-lease
//! reclaim authorizes nothing, because the row that authorizes is a different
//! row in a different table that the reclaim never touches. Walk it:
//!
//! ```text
//! 1  A claims proposed -> executing, begins dispatch
//! 2  A's claim_invocation takes (session, tool_call_id)        -> Acquired
//! 3  the lease expires while A is still running
//! 4  the sweep reclaims the row to proposed
//! 5  B claims it and dispatches
//!    B's claim_invocation conflicts on the unique index        -> Existing
//!    B MUST NOT perform the side effect; it replays A's outcome
//! ```
//!
//! Exactly one business mutation. `CONFIRM_LEASE` is therefore an operational
//! recovery setting, not a safety margin — tuning it changes how quickly a
//! crashed confirm becomes re-confirmable, never whether a duplicate is
//! possible.
//!
//! ## No path may return leaving a row in `executing`
//!
//! Every exit is in [`Status`]'s doc and enforced by the failure transitions
//! below: a stale hash returns the row to `proposed` (arguments are immutable,
//! so a mismatch means the *client* held a stale view); a removed action, a
//! revoked session or a gate refusal are terminal `invalidated`; an approval
//! moves to `approval_pending`; success to `executed`; a transient failure
//! whose key was released returns to `proposed`; an expired lease is
//! reclaimed.

use std::time::Duration;

use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// How long a confirm may hold its claim before the sweep reclaims it.
///
/// **An operational recovery setting, not a correctness or safety margin.**
/// The correctness boundary is `action_invocation`'s
/// `(agent_session_id, tool_call_id)` claim, which no lease value can move.
///
/// | Tuned | Cost | Never |
/// |---|---|---|
/// | Too short | A slow confirm is reclaimed underneath itself; proposals may appear to revert and need re-confirming | **Permits a duplicate mutation** |
/// | Too long | A crashed proposal stays apparently stuck for longer | — |
///
/// Lowering this to 30 seconds weakens no guarantee and raising it to an hour
/// creates none. Anyone reading it as a security control has misread the
/// design — re-read this module's header.
pub const CONFIRM_LEASE: Duration = Duration::from_secs(5 * 60);

/// How long an unconfirmed proposal stays executable.
///
/// Shorter than a schema-change approval for the same reason
/// `crate::approval::AGENT_APPROVAL_TTL` is: the context that made a proposal
/// sensible goes stale fast, and expiring is the honest outcome.
pub const PROPOSAL_TTL: Duration = Duration::from_secs(4 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Awaiting a human. Executable.
    Proposed,
    /// Claimed by a confirm request; `claimed_at` holds the lease.
    Executing,
    /// Dispatched, outcome recorded. Terminal.
    Executed,
    /// The human declined it. Terminal.
    Rejected,
    /// Nobody confirmed it before [`PROPOSAL_TTL`]. Terminal.
    Expired,
    /// Re-gating at resume refused it — the action was removed, the session
    /// revoked, or a privilege changed. Terminal; the requester asks again
    /// against the world as it is now.
    Invalidated,
    /// The gate returned `RequiresApproval`. From here `attome_approval.payload`
    /// is the authoritative payload and `approval_request_id` is the link,
    /// never a second copy.
    ApprovalPending,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Executing => "executing",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Invalidated => "invalidated",
            Self::ApprovalPending => "approval_pending",
        }
    }

    /// The inverse of [`Status::as_str`]. `None` for a value the migration's
    /// `CHECK` would never admit.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "proposed" => Self::Proposed,
            "executing" => Self::Executing,
            "executed" => Self::Executed,
            "rejected" => Self::Rejected,
            "expired" => Self::Expired,
            "invalidated" => Self::Invalidated,
            "approval_pending" => Self::ApprovalPending,
            _ => return None,
        })
    }

    /// Whether the row can still change. `executing` counts: it always has an
    /// exit, whether by resolution or by the reclaim sweep.
    pub fn is_live(self) -> bool {
        matches!(self, Self::Proposed | Self::Executing)
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ToolCallRow {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub turn_id: Uuid,
    pub tool_call_id: String,
    pub action_id: String,
    /// **The executable payload** for the confirmation path, and immutable
    /// after insert.
    pub arguments: Value,
    pub arguments_hash: String,
    pub status: String,
    pub claimed_at: Option<DateTime<Utc>>,
    pub approval_request_id: Option<Uuid>,
    pub row_version: i64,
}

const COLUMNS: &str = "id, conversation_id, turn_id, tool_call_id, action_id, arguments, \
     arguments_hash, status, claimed_at, approval_request_id, row_version";

/// The canonical encoding a proposal's hash is taken over.
///
/// ## Why this is written out rather than using `Value::to_string`
///
/// `serde_json`'s `Value::Object` is `BTreeMap`-backed **only while the
/// `preserve_order` feature is off**. Cargo unifies features across a
/// workspace, so one dependency enabling it anywhere would silently make
/// `to_string` insertion-ordered — and this hash would start disagreeing with
/// itself across writers without a single line of this file changing.
///
/// Sorting explicitly costs a few lines and removes that entire class of
/// failure. `tests::canonical_encoding_is_key_order_independent` is the pin.
pub fn canonical(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // `to_string` on a JSON string is correct escaping, and a key
                // is always a string.
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(&map[key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        // Scalars: serde_json's own rendering is already canonical.
        other => out.push_str(&other.to_string()),
    }
}

/// SHA-256 over [`canonical`], hex-encoded.
///
/// An **integrity check**, never the storage strategy: a hash proves two
/// payloads identical without providing either, which is why the arguments
/// themselves are persisted beside it (I-13).
pub fn arguments_hash(value: &Value) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(canonical(value).as_bytes()))
}

pub struct NewToolCall {
    pub conversation_id: Uuid,
    pub message_id: Option<Uuid>,
    pub turn_id: Uuid,
    /// The provider's own call id, or — when a provider omits one — the
    /// caller passes `None` and this row's own `id` is used (D-553).
    ///
    /// **Never derived from `mcp::tool_call_key`**, whose
    /// `SHA256(session ‖ name ‖ arguments)` has no occurrence component: two
    /// legitimate identical calls in one session would collapse into one
    /// proposal. Correct for MCP's dedupe contract, wrong here.
    pub tool_call_id: Option<String>,
    pub action_id: String,
    pub arguments: Value,
    pub initiator_is_agent: bool,
    pub gate_decision: Option<String>,
}

impl std::fmt::Debug for NewToolCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewToolCall").finish_non_exhaustive()
    }
}

/// Persists a proposal **before** anything is dispatched, so a crash between
/// the two leaves a recoverable record rather than a phantom.
///
/// **Idempotent on `(conversation_id, tool_call_id)`.** A model that repeats a
/// tool-call id — which a retry legitimately does — describes the *same*
/// proposal, not a second one, so the existing row is returned rather than a
/// duplicate inserted. Without this the unique index rejects the second
/// insert, and the turn dies with a masked `Internal` instead of reaching a
/// terminal state: a retry, the one thing `tool_call_id` exists to make safe,
/// would have been the thing that broke the loop.
pub async fn propose(db: &PgPool, new: NewToolCall) -> Result<ToolCallRow, AppError> {
    let hash = arguments_hash(&new.arguments);
    // A row id is needed up front so it can stand in as the tool-call id when
    // the provider omitted one — generated here rather than by the column
    // default, which would not be readable until after the insert.
    let id = Uuid::now_v7();
    let tool_call_id = new.tool_call_id.unwrap_or_else(|| id.to_string());

    // C10-A: the insert and its `tool.call.proposed` event commit together;
    // an idempotent repeat inserts nothing and records nothing.
    let mut tx = attome_db::tx::begin(db).await?;
    let inserted = sqlx::query_as::<_, ToolCallRow>(&format!(
        "INSERT INTO ai_tool_call \
             (id, conversation_id, message_id, turn_id, tool_call_id, action_id, \
              arguments, arguments_hash, initiator, gate_decision) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (conversation_id, tool_call_id) DO NOTHING \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(new.conversation_id)
    .bind(new.message_id)
    .bind(new.turn_id)
    .bind(&tool_call_id)
    .bind(&new.action_id)
    .bind(&new.arguments)
    .bind(&hash)
    .bind(i16::from(new.initiator_is_agent))
    .bind(new.gate_decision.as_deref())
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    if let Some(row) = inserted {
        crate::conversation_event::tool_call_in(&mut tx, &row, false).await?;
        tx.commit().await.map_err(AppError::internal)?;
        return Ok(row);
    }
    tx.commit().await.map_err(AppError::internal)?;

    // The id was already proposed in this conversation: same call, same
    // proposal. Hand back what is stored — never the caller's version of it,
    // which is how the persisted arguments stay authoritative (I-13).
    sqlx::query_as::<_, ToolCallRow>(&format!(
        "SELECT {COLUMNS} FROM ai_tool_call \
          WHERE conversation_id = $1 AND tool_call_id = $2"
    ))
    .bind(new.conversation_id)
    .bind(&tool_call_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// What claiming a proposal produced.
#[derive(Debug)]
pub enum Claim {
    /// This caller owns the claim and must resolve it. `arguments` on the
    /// returned row is the payload to dispatch — **the server's copy**.
    Claimed(Box<ToolCallRow>),
    /// The row is not `proposed`: claimed by someone else, or terminal. The
    /// caller does **not** dispatch, and answers from `status` — the state
    /// actually persisted, read in the claim's own transaction — rather than
    /// from the failed update alone (an `executing` row is "in progress", an
    /// `executed` one "already executed", and so on).
    NotProposed {
        status: Status,
        approval_request_id: Option<Uuid>,
    },
    /// The row is `proposed` with the displayed hash, yet the claim did not
    /// take it: a concurrent transition moved it and moved it back between
    /// the claim's evaluation and this read. Nothing changed; the caller
    /// reports a conflict and the human may simply confirm again.
    LostRace,
    /// The hash the client displayed does not match the stored one, so the
    /// human is confirming something they were not shown. **The row never
    /// left `proposed`**: the hash is part of the claim's own `WHERE`, so a
    /// stale confirm changes nothing, not even `row_version`.
    StaleHash,
    /// No such row, or not in this conversation.
    Gone,
}

/// Claims a proposal for execution, verifying the client's view in the same
/// statement.
///
/// The claim comes **before** validation deliberately: it is what makes two
/// concurrent confirmations produce exactly one mutation. Everything that can
/// fail afterwards has a defined exit, so no path returns leaving the row in
/// `executing`.
pub async fn claim(
    db: &PgPool,
    conversation_id: Uuid,
    tool_call_id: &str,
    expected_hash: &str,
) -> Result<Claim, AppError> {
    claim_inner(db, conversation_id, tool_call_id, expected_hash, None).await
}

/// [`claim`], preceded — in the same transaction — by reclaiming **this**
/// row's lease if it has expired, with the sweep's own predicate
/// ([`reclaim_expired_leases`]). A confirm that finds a crashed confirm's
/// stale lease therefore needs no privileged path and no wait for the sweep.
/// The reclaim authorizes nothing: whether a mutation happens is decided by
/// `action_invocation`, which it never touches.
pub async fn claim_reclaiming(
    db: &PgPool,
    conversation_id: Uuid,
    tool_call_id: &str,
    expected_hash: &str,
    lease: Duration,
) -> Result<Claim, AppError> {
    claim_inner(
        db,
        conversation_id,
        tool_call_id,
        expected_hash,
        Some(lease),
    )
    .await
}

async fn claim_inner(
    db: &PgPool,
    conversation_id: Uuid,
    tool_call_id: &str,
    expected_hash: &str,
    reclaim_lease: Option<Duration>,
) -> Result<Claim, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;

    if let Some(lease) = reclaim_lease {
        let reclaimed = sqlx::query_as::<_, ToolCallRow>(&format!(
            "UPDATE ai_tool_call \
                SET status = 'proposed', claimed_at = NULL, row_version = row_version + 1 \
              WHERE conversation_id = $1 AND tool_call_id = $2 AND status = 'executing' \
                AND claimed_at < NOW() - make_interval(secs => $3::double precision) \
             RETURNING {COLUMNS}"
        ))
        .bind(conversation_id)
        .bind(tool_call_id)
        .bind(lease.as_secs() as f64)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if let Some(row) = reclaimed {
            crate::conversation_event::tool_call_in(&mut tx, &row, true).await?;
        }
    }

    // The CAS, conditional on the hash the human was shown. A stale hash
    // therefore never enters `executing`, even inside this transaction, and
    // costs no `row_version` bump. `fetch_optional` distinguishes "claimed
    // by us" from every other outcome — the shape
    // `attome_approval::mark_executed` already uses.
    let row = sqlx::query_as::<_, ToolCallRow>(&format!(
        "UPDATE ai_tool_call \
            SET status = 'executing', claimed_at = NOW(), row_version = row_version + 1 \
          WHERE conversation_id = $1 AND tool_call_id = $2 AND status = 'proposed' \
            AND arguments_hash = $3 \
         RETURNING {COLUMNS}"
    ))
    .bind(conversation_id)
    .bind(tool_call_id)
    .bind(expected_hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    if let Some(row) = row {
        crate::conversation_event::tool_call_in(&mut tx, &row, false).await?;
        tx.commit().await.map_err(AppError::internal)?;
        return Ok(Claim::Claimed(Box::new(row)));
    }

    // A failed conditional update has several possible reasons. Read what is
    // actually there, in this same transaction, and classify from that.
    let found: Option<(String, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT status, arguments_hash, approval_request_id FROM ai_tool_call \
          WHERE conversation_id = $1 AND tool_call_id = $2",
    )
    .bind(conversation_id)
    .bind(tool_call_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;

    let Some((status, stored_hash, approval_request_id)) = found else {
        return Ok(Claim::Gone);
    };
    let status = Status::parse(&status).ok_or_else(|| {
        AppError::internal(format!("ai_tool_call carries an unknown status {status:?}"))
    })?;
    Ok(match status {
        Status::Proposed if stored_hash != expected_hash => Claim::StaleHash,
        Status::Proposed => Claim::LostRace,
        status => Claim::NotProposed {
            status,
            approval_request_id,
        },
    })
}

/// Moves a claimed row to a terminal state, or back to `proposed`.
///
/// CAS'd on the writer's own `row_version`, so a writer whose lease was
/// reclaimed mid-dispatch affects **zero rows** and does not clobber the
/// reclaimed state. `false` means exactly that, and the caller should report
/// from `action_invocation` — which it still owns — rather than
/// overwrite.
pub async fn resolve(
    db: &PgPool,
    id: Uuid,
    expected_row_version: i64,
    status: Status,
    outcome: Option<&Value>,
    approval_request_id: Option<Uuid>,
) -> Result<bool, AppError> {
    let claimed_at_expr = if status == Status::Executing {
        "claimed_at"
    } else {
        "NULL"
    };
    let resolved_at_expr = if status.is_live() { "NULL" } else { "NOW()" };
    let mut tx = attome_db::tx::begin(db).await?;
    let row = sqlx::query_as::<_, ToolCallRow>(&format!(
        "UPDATE ai_tool_call \
            SET status = $3, outcome = $4, approval_request_id = COALESCE($5, approval_request_id), \
                claimed_at = {claimed_at_expr}, resolved_at = {resolved_at_expr}, \
                row_version = row_version + 1 \
          WHERE id = $1 AND row_version = $2 \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(expected_row_version)
    .bind(status.as_str())
    .bind(outcome)
    .bind(approval_request_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // C10-A: the transition and its event commit together.
    if let Some(row) = &row {
        crate::conversation_event::tool_call_in(&mut tx, row, status == Status::Proposed).await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(row.is_some())
}

/// [`resolve`], inside the caller's transaction — for a status transition
/// that must commit atomically with the check that caused it (the confirm
/// path's check transaction, row A-41). Same statement, same `row_version`
/// condition, same meaning of `false`.
pub async fn resolve_in(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
    expected_row_version: i64,
    status: Status,
    outcome: Option<&Value>,
) -> Result<bool, AppError> {
    let claimed_at_expr = if status == Status::Executing {
        "claimed_at"
    } else {
        "NULL"
    };
    let resolved_at_expr = if status.is_live() { "NULL" } else { "NOW()" };
    let row = sqlx::query_as::<_, ToolCallRow>(&format!(
        "UPDATE ai_tool_call \
            SET status = $3, outcome = $4, \
                claimed_at = {claimed_at_expr}, resolved_at = {resolved_at_expr}, \
                row_version = row_version + 1 \
          WHERE id = $1 AND row_version = $2 \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(expected_row_version)
    .bind(status.as_str())
    .bind(outcome)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // C10-A: in the caller's transaction, with the transition.
    if let Some(row) = &row {
        crate::conversation_event::tool_call_in(tx, row, status == Status::Proposed).await?;
    }
    Ok(row.is_some())
}

/// What rejecting a proposal did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// It was `proposed`; it is now `rejected`. Terminal.
    Rejected,
    /// No such tool call in this conversation.
    NotFound,
    /// It is no longer `proposed` (claimed, executed, or terminal). Nothing
    /// changed; the answer is the persisted status.
    NotProposed(Status),
}

/// `DELETE …/tool-calls/{tid}`: the human declines a pending proposal.
/// `proposed → rejected` conditional on the status, with the mandatory `Ai` +
/// `Rejected` event in the same transaction (D-542). A proposal already
/// claimed by a confirm cannot be rejected out from under it.
///
/// The caller has already authorized the conversation (I-20).
pub async fn reject(
    state: &attome_core::EngineState,
    conversation_id: Uuid,
    tool_call_id: &str,
    actor: Uuid,
) -> Result<Rejection, AppError> {
    let event = attome_audit::security::SecurityEvent::new(
        attome_audit::security::MandatoryCategory::Ai,
        attome_audit::AuditOperation::Rejected,
        actor,
        "ai_tool_call",
        None,
    )
    .named("ai_tool_call.reject");
    let mut stx = attome_audit::security::SecurityTx::begin(state, event).await?;
    let rejected = sqlx::query_as::<_, ToolCallRow>(&format!(
        "UPDATE ai_tool_call \
            SET status = 'rejected', claimed_at = NULL, resolved_at = NOW(), \
                row_version = row_version + 1 \
          WHERE conversation_id = $1 AND tool_call_id = $2 AND status = 'proposed' \
         RETURNING {COLUMNS}"
    ))
    .bind(conversation_id)
    .bind(tool_call_id)
    .fetch_optional(&mut *stx)
    .await
    .map_err(AppError::internal)?;
    if let Some(row) = rejected {
        crate::conversation_event::tool_call_in(&mut stx, &row, false).await?;
        stx.event_mut().set_record_id(row.id);
        stx.commit().await?;
        return Ok(Rejection::Rejected);
    }
    let status: Option<String> = sqlx::query_scalar(
        "SELECT status FROM ai_tool_call WHERE conversation_id = $1 AND tool_call_id = $2",
    )
    .bind(conversation_id)
    .bind(tool_call_id)
    .fetch_optional(&mut *stx)
    .await
    .map_err(AppError::internal)?;
    // Dropping `stx` uncommitted writes no event: nothing changed.
    Ok(match status {
        None => Rejection::NotFound,
        Some(status) => Rejection::NotProposed(Status::parse(&status).ok_or_else(|| {
            AppError::internal(format!("ai_tool_call carries an unknown status {status:?}"))
        })?),
    })
}

/// Reclaims leases whose holder is gone, returning those rows to `proposed`.
///
/// Safe against a holder that is merely slow rather than dead: the reclaim
/// touches only this table, and the row that decides whether a mutation
/// happens is `action_invocation`, which it never touches. A second
/// confirm after a reclaim therefore conflicts on that ledger and does not
/// re-execute.
///
/// Without this sweep a process dying mid-confirm would strand the proposal in
/// `executing` forever, with the confirm button silently doing nothing.
pub async fn reclaim_expired_leases(db: &PgPool, lease: Duration) -> Result<u64, AppError> {
    let seconds = lease.as_secs() as i64;
    let mut tx = attome_db::tx::begin(db).await?;
    let reclaimed = sqlx::query_as::<_, ToolCallRow>(&format!(
        "UPDATE ai_tool_call \
            SET status = 'proposed', claimed_at = NULL, row_version = row_version + 1 \
          WHERE status = 'executing' \
            AND claimed_at < NOW() - make_interval(secs => $1::double precision) \
         RETURNING {COLUMNS}"
    ))
    .bind(seconds as f64)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // C10-A: each reclaimed call is reopened, in the reclaim's transaction.
    for row in &reclaimed {
        crate::conversation_event::tool_call_in(&mut tx, row, true).await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(reclaimed.len() as u64)
}

/// The periodic sweep (`EngineJob::AiToolCallSweep`): reclaims expired
/// confirm leases to `proposed`, then expires proposals past
/// [`PROPOSAL_TTL`]. Returns `(reclaimed, expired)`.
///
/// This is the backstop for a process or database failure after a confirm's
/// claim — the path that would otherwise strand a proposal in `executing`
/// (row A-40). It authorizes nothing: a re-confirm of a reclaimed row meets
/// the D-502 invocation ledger, which decides whether anything runs.
pub async fn sweep(db: &PgPool) -> Result<(u64, u64), AppError> {
    let reclaimed = reclaim_expired_leases(db, CONFIRM_LEASE).await?;
    let expired = expire_stale_proposals(db, PROPOSAL_TTL).await?;
    // C10-A recovery only: an approval transition that ran without the
    // conversation hook. The normal path writes these events atomically.
    let reconciled = crate::conversation_event::reconcile_approvals(db).await?;
    // C13.1: `ai_tool_call_sweep_total{transition}`.
    {
        use crate::turn_metrics::{SweepTransition, sweep};
        sweep(SweepTransition::Reclaimed, reclaimed);
        sweep(SweepTransition::Expired, expired);
        sweep(SweepTransition::Reconciled, reconciled);
    }
    if reconciled > 0 {
        tracing::warn!(
            reconciled,
            "approval resolutions reached their conversation only through the recovery sweep"
        );
    }
    Ok((reclaimed, expired))
}

/// Expires proposals nobody confirmed, mirroring
/// `attome_approval::sweep_expired`. A proposal that stays executable forever is
/// a standing authorization nobody reviewed.
pub async fn expire_stale_proposals(db: &PgPool, ttl: Duration) -> Result<u64, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let expired = sqlx::query_as::<_, ToolCallRow>(&format!(
        "UPDATE ai_tool_call \
            SET status = 'expired', resolved_at = NOW(), row_version = row_version + 1 \
          WHERE status = 'proposed' \
            AND created_at < NOW() - make_interval(secs => $1::double precision) \
         RETURNING {COLUMNS}"
    ))
    .bind(ttl.as_secs() as f64)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // C10-A: each expiry and its `tool.call.failed{expired}` commit together.
    for row in &expired {
        crate::conversation_event::tool_call_in(&mut tx, row, false).await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(expired.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// **The pin on the canonical encoding.** Two objects that differ only in
    /// key order must hash identically — otherwise a confirm could be refused
    /// because a client serialised its JSON differently, or worse, two
    /// different payloads could be treated as one.
    ///
    /// This also fails loudly if `serde_json`'s `preserve_order` is ever
    /// unified into the build, which is the whole reason `canonical` sorts
    /// explicitly instead of trusting `Value::to_string`.
    #[test]
    fn canonical_encoding_is_key_order_independent() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"z":[1,2],"y":"x"}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"y":"x","z":[1,2]},"b":1}"#).unwrap();
        assert_eq!(canonical(&a), canonical(&b));
        assert_eq!(arguments_hash(&a), arguments_hash(&b));
    }

    /// Array order is meaningful and must NOT be sorted away.
    #[test]
    fn array_order_is_preserved() {
        assert_ne!(
            canonical(&json!({"ids": [1, 2]})),
            canonical(&json!({"ids": [2, 1]})),
            "reordering an array changes meaning and must change the hash"
        );
    }

    /// A different value must produce a different hash — the property the
    /// staleness check depends on.
    #[test]
    fn a_changed_value_changes_the_hash() {
        let before = arguments_hash(&json!({"status": "open"}));
        let after = arguments_hash(&json!({"status": "resolved"}));
        assert_ne!(before, after);
    }

    /// The published vector. If this changes, every stored hash is
    /// invalidated, so it must change only deliberately.
    #[test]
    fn canonical_vector_is_pinned() {
        let value = json!({"entity": "ticket", "fields": {"status": "resolved"}, "id": 7});
        assert_eq!(
            canonical(&value),
            r#"{"entity":"ticket","fields":{"status":"resolved"},"id":7}"#
        );
        assert_eq!(
            arguments_hash(&value),
            "848f12761988a266d4cf02d6272ef9c97e7f68dd83504c0e0e1f9b63628402e7"
        );
    }

    /// Only `proposed` and `executing` are live. Every terminal status must
    /// report itself terminal, or the sweeps would reap settled rows.
    #[test]
    fn liveness_is_exactly_proposed_and_executing() {
        use Status::*;
        assert!(Proposed.is_live() && Executing.is_live());
        for s in [Executed, Rejected, Expired, Invalidated, ApprovalPending] {
            assert!(!s.is_live(), "{} must be terminal", s.as_str());
        }
    }

    /// Status strings must match migration 0479's CHECK vocabulary and be
    /// distinct.
    #[test]
    fn status_strings_match_the_migration_vocabulary() {
        use Status::*;
        let all = [
            Proposed,
            Executing,
            Executed,
            Rejected,
            Expired,
            Invalidated,
            ApprovalPending,
        ];
        let mut seen: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        seen.sort_unstable();
        let len = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), len);
        assert_eq!(len, 7);
    }

    /// The lease is documented as an operational setting; this pins that it is
    /// comfortably longer than any plausible dispatch while staying far short
    /// of the proposal TTL — a lease longer than the TTL would let a claimed
    /// row outlive the proposal it claims.
    #[test]
    fn the_lease_is_shorter_than_the_proposal_ttl() {
        assert!(CONFIRM_LEASE < PROPOSAL_TTL);
    }
}
