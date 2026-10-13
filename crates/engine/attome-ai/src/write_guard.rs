//! Shared blast-radius controls for an `Effect::Write` action's agent-
//! auto-execute path (M98, D-448; REVIEW-2026-09-02 finding #9).
//!
//! `record.update_field` (the platform's first `Effect::Write` action)
//! originally carried its own private daily-write cap, per-minute rate cap,
//! and auto-approval submission — real, tested, but reachable only by an
//! author who remembered to copy it into a new action by hand. Every
//! `Effect::Write` action registered since (`bot.handoff`, `memory.remember`)
//! shipped with none of it. This module is that machinery, extracted so a
//! new `Reversible`-tier agent-auto-execute write action gets it by calling
//! three functions, not by re-deriving them.
//!
//! **What this does NOT cover.** A `Consequential`-tier write
//! (`memory.forget`, `agent.pause`/`resume`/`kill`) never reaches an
//! executor for an agent caller at all — `gate::evaluate`'s
//! `(Consequential, Agent)` arm always returns `RequiresApproval`, so there
//! is no per-invocation blast radius to cap here; a human decides every one.
//! Those actions still get the invocation-ledger row (see [`crate::execute::
//! dispatch`], which now writes it for every completed `Effect::Write`
//! action, agent or human) — just not the cap/rate-limit/auto-approval
//! machinery in this module, which only makes sense on the auto-execute
//! path.
//!
//! **Closed** (M98 follow-up to the gap this file used to flag and not
//! fix): once a `Consequential` agent action is approved (`attome_approval`
//! status `Approved`), [`crate::execute::dispatch_approved_agent_action`]
//! now runs it, through [`crate::execute::run_executor`] — the same tail
//! `dispatch` itself uses, so `record_write_invocation` still fires for it
//! the same way. Reached from `attome-api::approval_admin::
//! execute_approved`'s dynamic `action.starts_with(approval::
//! ACTION_TYPE_PREFIX)` arm. See `attome_ai::execute`'s module doc and
//! `agent_action_approval_execution.rs` for the end-to-end proof.

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

/// The daily-cap query: completed writes this session has made through
/// `action_id` since UTC midnight. A direct count against
/// `action_invocation` (source of truth, guidelines §5) rather than
/// a second cache of the same fact — the table is already indexed
/// `(agent_session_id, created_at DESC)` for exactly this shape of query and
/// a daily cap has no latency budget tight enough to need a cache in front
/// of it.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
pub async fn writes_today(
    state: &EngineState,
    session_id: Uuid,
    action_id: &str,
) -> Result<i64, AppError> {
    let midnight_utc = chrono::Utc::now()
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("00:00:00 is always a valid time")
        .and_utc();
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM action_invocation \
          WHERE agent_session_id = $1 AND action_id = $2 AND outcome = 'completed' \
            AND created_at >= $3",
    )
    .bind(session_id)
    .bind(action_id)
    .bind(midnight_utc)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Both blast-radius caps `record.update_field`'s plan §5 established, now
/// generic over the caller's own `action_id`, cap values, and rate-limit
/// key namespace. Refuses with `TooManyRequests` — distinct from
/// `Forbidden`, which the caller cannot fix by waiting (guidelines §6:
/// correct error semantics are part of the contract).
pub async fn enforce_write_caps(
    state: &EngineState,
    session_id: Uuid,
    action_id: &str,
    daily_cap: i64,
    per_minute_cap: i32,
) -> Result<(), AppError> {
    let today = writes_today(state, session_id, action_id).await?;
    if today >= daily_cap {
        tracing::warn!(
            session_id = %session_id,
            action_id,
            today,
            cap = daily_cap,
            "daily write cap reached for this agent session"
        );
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    }

    let key = format!("attome-ai:rl:{action_id}:session:{session_id}");
    let outcome =
        attome_cache::rate_limit::check(&state.base.redis_coordination, &key, per_minute_cap)
            .await?;
    if !outcome.allowed {
        tracing::warn!(
            session_id = %session_id,
            action_id,
            limit = per_minute_cap,
            "per-minute rate cap reached for this agent session"
        );
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    }
    Ok(())
}

/// Submits and immediately policy-decides an auto-approval record — module
/// doc's "auto-approval is still an approval" (plan §5). Returns the decided
/// request's id and row_version to pass to [`close_auto_approval`] once the
/// write itself has actually happened — a pending/approved-but-not-yet-
/// executed request is the correct state for the brief window between
/// deciding and writing, not a state to avoid.
///
/// `action_type` is the caller's own `attome_approval` action_type (e.g.
/// `"attome-ai/policy-approved:record.update_field"`), namespaced per
/// action so an approver UI reading `attome_approval` history can tell them
/// apart without parsing the payload.
pub async fn submit_and_auto_approve(
    state: &EngineState,
    action_type: &str,
    requested_by: Uuid,
    payload: Value,
    ttl_minutes: i64,
) -> Result<(Uuid, i64), AppError> {
    let submitted = attome_approval::submit(
        &state.base.db,
        action_type,
        payload,
        requested_by,
        1,
        chrono::Duration::minutes(ttl_minutes),
    )
    .await?;

    // `POLICY_ACTOR_ID` (nil UUID) is never equal to a real user id, so
    // `decide`'s separation-of-duties check (`approver_id == requested_by`)
    // never fires here — this is a different actor deciding, not
    // self-approval, however narrow the gap looks on the page.
    let decided = attome_approval::decide(
        &state.base.db,
        submitted.id,
        attome_approval::POLICY_ACTOR_ID,
        attome_approval::Decision::Approve,
        submitted.row_version,
    )
    .await?;
    Ok((decided.id, decided.row_version))
}

/// Closes an auto-approval out after the write it stood for has actually
/// happened. Best-effort: the write already committed, so a bookkeeping
/// failure here degrades the approval's own trail (left "approved", never
/// "executed") rather than reporting failure for a request that in fact
/// succeeded — same posture `record.update_field`'s own step took before
/// this was extracted.
pub async fn close_auto_approval(state: &EngineState, approval_id: Uuid, row_version: i64) {
    if let Err(e) = attome_approval::mark_executed(&state.base.db, approval_id, row_version).await {
        tracing::error!(
            approval_id = %approval_id,
            error = %e,
            "write action completed but failed to mark its auto-approval executed — \
             the approval stays 'approved'"
        );
    }
}
