//! SLA clock (M73/D-422): pause/resume tracking per ticket, auto-pause on
//! `waiting_on_customer`, a `resolved_at` stamp for the mean-time-to-resolve
//! metric, and the breach-escalation chain (assignee -> queue lead ->
//! manager) that acts on `sla.breached`/`sla.warning`. See
//! `document/decisions/runtime/D-422.md` for the pause/resume semantics this
//! file implements.
//!
//! **Why a change-feed-driven auto-pause sweep, not a synchronous hook "in
//! the ticket update path."** There is no such path to hook into.
//! `service_ticket` is ordinary generic entity CRUD (`convert.rs`'s module doc:
//! "Everything else on service_work_request/service_ticket is generic entity CRUD",
//! D-398) — this crate has no ticket-specific update handler, and guidelines
//! §9 forbids adding a per-entity CRUD handler for behavior the generic
//! engine can already express. `attome-state` (M07) is Phase 1 only: no
//! built-in state model is registered for `service_ticket` (nothing seeds one,
//! and no entry-action mechanism is wired into the generic entity engine
//! yet), so there is no state-model entry action to attach to either.
//! [`sweep_auto_pause`] instead consumes `service_ticket` rows off the existing
//! entity change-feed outbox (`attome_core::change_feed`, D-358's
//! non-destructive cursor model — the same "own consumer, own cursor" shape
//! `attome-workflow`'s trigger dispatch and the search indexer already use),
//! the same "plain, directly callable, directly testable function, not yet a
//! `EngineJob`" posture `sla.rs`'s own `sweep_breaches` already established
//! for exactly this reason.
//!
//! **Escalation chain.** M51's own (not-yet-built, Phase 2) escalation-
//! recipient design is an ordered fallback: explicit ref -> position parent
//! -> template owner (`document/module-master-plans/M51-notification.md`
//! §5's "Escalation recipient"). This module's chain reuses that exact
//! resolution *mechanism* — walking `position.parent_position_ref`
//! via `user_account_mm_position` — for the ticket-specific tiers the
//! checklist names: the assignee themselves (tier 0), the position-parent
//! holder(s) of the assignee's position ("queue lead", tier 1), and the
//! position-grandparent holder(s) ("manager", tier 2). A tier with no
//! resolvable holder is skipped, never fabricated — same "log which rule
//! chose" honesty M51's design states for itself.

use attome_config::NotificationSection;
use attome_core::change_feed::ChangeOperation;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized, Privilege};
use attome_types::ErrorResponse;
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use utoipa::ToSchema;

use crate::auth::TicketUpdate;
use crate::sla::{
    CalculationRecord, CalculationType, CalendarEvidence, SlaCalculationStatus, SlaPolicy,
    Unresolved, UnresolvedReason,
};

// ── Clock state/reason vocabulary (checklist's exact terms) ───────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClockState {
    Running,
    Paused,
}

impl ClockState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Paused => "paused",
        }
    }

    fn parse(s: &str) -> Self {
        // An unrecognised value defaults to Running rather than erroring —
        // the same "unknown value degrades safely" posture `ChangeOperation
        // ::parse` documents; a clock stuck reporting "paused" forever on a
        // decode miss would silently stop the ticket from ever breaching.
        if s == "paused" {
            Self::Paused
        } else {
            Self::Running
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PauseReason {
    WaitingCustomer,
    OnHold,
    OutOfScope,
}

impl PauseReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::WaitingCustomer => "waiting_customer",
            Self::OnHold => "on_hold",
            Self::OutOfScope => "out_of_scope",
        }
    }
}

// ── Clock row + read/create ────────────────────────────────────────────────

struct ClockRow {
    id: Uuid,
    state: ClockState,
    elapsed_business_seconds: i64,
    state_changed_at: DateTime<Utc>,
    /// D-517: past running segments whose business time could not be banked
    /// because the policy's business-time model was unresolvable when the
    /// clock paused. Banked by the next transition or recalculation that can
    /// resolve it — never approximated in the meantime.
    unsettled_segments: Vec<Segment>,
}

/// One running interval of a clock, `[from, to)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Segment {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
}

fn parse_segments(clock_id: Uuid, raw: Option<&str>) -> Result<Vec<Segment>, AppError> {
    match raw.map(str::trim) {
        None | Some("") => Ok(Vec::new()),
        Some(json) => serde_json::from_str(json).map_err(|e| {
            AppError::internal(format!(
                "service_sla_clock {clock_id}: unsettled_segments is not valid JSON: {e}"
            ))
        }),
    }
}

fn render_segments(segments: &[Segment]) -> Result<Option<String>, AppError> {
    if segments.is_empty() {
        return Ok(None);
    }
    serde_json::to_string(segments)
        .map(Some)
        .map_err(AppError::internal)
}

/// Loads the ticket's clock row, creating one (running, zero banked elapsed,
/// backed by the ticket's own `created_at`) the first time anything touches
/// it — most tickets never pause, so nothing pre-creates a row per ticket at
/// provisioning time. `FOR UPDATE` within the caller's transaction so
/// pause/resume can safely read-then-write against concurrent callers (the
/// caller must already hold [`lock_ticket`]'s advisory lock too — belt and
/// suspenders, since `FOR UPDATE` alone only serializes once a row exists).
async fn get_or_create_clock(
    tx: &mut Transaction<'_, Postgres>,
    ticket_id: Uuid,
) -> Result<ClockRow, AppError> {
    /// `(id, state, elapsed_business_seconds, state_changed_at, unsettled_segments)`.
    type StoredClock = (Uuid, String, f64, DateTime<Utc>, Option<String>);
    let existing: Option<StoredClock> = sqlx::query_as(
        "SELECT id, state, elapsed_business_seconds::double precision, state_changed_at, \
                unsettled_segments \
         FROM service_sla_clock WHERE ticket_ref = $1 FOR UPDATE",
    )
    .bind(ticket_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    if let Some((id, state, elapsed, changed_at, segments)) = existing {
        return Ok(ClockRow {
            id,
            state: ClockState::parse(&state),
            elapsed_business_seconds: elapsed as i64,
            state_changed_at: changed_at,
            unsettled_segments: parse_segments(id, segments.as_deref())?,
        });
    }

    let created_on: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT created_at FROM service_ticket WHERE id = $1")
            .bind(ticket_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    let created_on = created_on.ok_or(AppError::NotFound)?;

    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_sla_clock \
             (id, ticket_ref, state, paused_reason, elapsed_business_seconds, state_changed_at) \
         VALUES ($1, $2, 'running', NULL, 0, $3)",
    )
    .bind(id)
    .bind(ticket_id)
    .bind(created_on)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    Ok(ClockRow {
        id,
        state: ClockState::Running,
        elapsed_business_seconds: 0,
        state_changed_at: created_on,
        unsettled_segments: Vec::new(),
    })
}

/// Advisory-locks this ticket's SLA clock before read-modify-write — same
/// "lock, then act" order `convert.rs::lock_and_load_work_request` uses, so
/// a racing pause and resume for the same ticket serialize instead of both
/// reading the same pre-transition state.
async fn lock_ticket(tx: &mut Transaction<'_, Postgres>, ticket_id: Uuid) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-service/sla-clock:{ticket_id}"))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another pause/resume request for this ticket's SLA clock is already in progress",
        ));
    }
    Ok(())
}

/// The ticket's *assigned* policy, if it still exists — pause/resume and
/// recalculation use the policy the ticket already carries, never a fresh
/// priority selection (a policy's priority mapping may have changed since).
async fn assigned_policy(
    tx: &mut Transaction<'_, Postgres>,
    db: &DbPool,
    ticket_id: Uuid,
) -> Result<Option<SlaPolicy>, AppError> {
    let policy_id: Option<Uuid> =
        sqlx::query_scalar("SELECT sla_policy_id FROM service_ticket WHERE id = $1")
            .bind(ticket_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?
            .flatten();
    match policy_id {
        // A read via the pool while `tx` is still open on its own connection —
        // a plain SELECT with no lock, not the external I/O guidelines §10
        // forbids inside a transaction.
        Some(policy_id) => crate::sla::policy_by_id(db, policy_id).await,
        None => Ok(None),
    }
}

/// The result of banking a clock's pending running segments.
struct Banked {
    /// `elapsed_business_seconds` after banking.
    elapsed: i64,
    /// What stays unsettled: empty on success, every pending segment when
    /// the business-time model could not resolve (all-or-nothing).
    unsettled: Vec<Segment>,
    /// Business seconds banked by this step, `None` when nothing could be.
    banked_seconds: Option<i64>,
    unresolved: Option<Unresolved>,
    evidence: CalendarEvidence,
}

/// Banks the clock's unsettled segments plus `extra` (the segment a pause is
/// closing). A ticket with no SLA policy counts wall-clock time, as D-422
/// always did — there is no business-hour model to be unresolved. With a
/// policy, either every pending segment is banked or none is (D-517): a
/// partial bank would understate elapsed time, which is the same as
/// extending the deadline.
async fn settle_segments(
    db: &DbPool,
    policy: Option<&SlaPolicy>,
    clock: &ClockRow,
    extra: Option<Segment>,
) -> Result<Banked, AppError> {
    let mut pending = clock.unsettled_segments.clone();
    pending.extend(extra);

    let Some(policy) = policy else {
        let seconds: i64 = pending
            .iter()
            .map(|s| (s.to - s.from).num_seconds().max(0))
            .sum();
        return Ok(Banked {
            elapsed: clock.elapsed_business_seconds + seconds,
            unsettled: Vec::new(),
            banked_seconds: Some(seconds),
            unresolved: None,
            evidence: CalendarEvidence::default(),
        });
    };

    let mut total = 0i64;
    let mut evidence = CalendarEvidence::default();
    for segment in &pending {
        let calculation = crate::sla::compute_elapsed(db, policy, segment.from, segment.to).await?;
        evidence = calculation.evidence;
        match calculation.outcome {
            Ok(seconds) => total += seconds,
            Err(unresolved) => {
                return Ok(Banked {
                    elapsed: clock.elapsed_business_seconds,
                    unsettled: pending,
                    banked_seconds: None,
                    unresolved: Some(unresolved),
                    evidence,
                });
            }
        }
    }
    Ok(Banked {
        elapsed: clock.elapsed_business_seconds + total,
        unsettled: Vec::new(),
        banked_seconds: Some(total),
        unresolved: None,
        evidence,
    })
}

/// Calculates and stores the ticket's deadline — the policy's remaining
/// budget run forward from `anchor` — with its evidence row. Unresolved
/// banking, or an unresolved due-date calculation, stores no deadline.
/// Returns the stored deadline.
async fn store_deadline(
    tx: &mut Transaction<'_, Postgres>,
    db: &DbPool,
    ticket_id: Uuid,
    policy: &SlaPolicy,
    banked: &Banked,
    anchor: DateTime<Utc>,
    calculation_type: CalculationType,
) -> Result<Option<DateTime<Utc>>, AppError> {
    let (outcome, evidence, target_minutes) = match &banked.unresolved {
        Some(unresolved) => (Err(unresolved.clone()), banked.evidence.clone(), None),
        None => {
            let remaining = policy.remaining_minutes(banked.elapsed);
            let calculation = crate::sla::compute_due(db, policy, anchor, remaining).await?;
            (calculation.outcome, calculation.evidence, Some(remaining))
        }
    };
    crate::sla::set_ticket_deadline(tx, ticket_id, outcome.as_ref().copied()).await?;
    crate::sla::record_calculation(
        tx,
        CalculationRecord {
            ticket_id,
            policy_id: Some(policy.id()),
            calculation_type,
            unresolved: outcome.as_ref().err(),
            evidence: &evidence,
            start_at: anchor,
            end_at: None,
            target_minutes,
            business_seconds: banked.banked_seconds,
            result_due_at: outcome.as_ref().ok().copied(),
        },
    )
    .await?;
    Ok(outcome.ok())
}

async fn write_clock(
    tx: &mut Transaction<'_, Postgres>,
    clock_id: Uuid,
    state: ClockState,
    paused_reason: Option<PauseReason>,
    banked: &Banked,
    state_changed_at: DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE service_sla_clock \
         SET state = $2, paused_reason = $3, elapsed_business_seconds = $4, \
             state_changed_at = $5, unsettled_segments = $6 \
         WHERE id = $1",
    )
    .bind(clock_id)
    .bind(state.as_str())
    .bind(paused_reason.map(PauseReason::as_str))
    .bind(banked.elapsed)
    .bind(state_changed_at)
    .bind(render_segments(&banked.unsettled)?)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Closes the running segment of a running clock and pauses it. With a
/// policy, the segment is banked or — when the business-time model cannot
/// resolve — kept unsettled while the ticket's SLA becomes unresolved.
/// Returns the clock's elapsed business seconds after the pause.
async fn pause_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    db: &DbPool,
    ticket_id: Uuid,
    clock: &ClockRow,
    reason: PauseReason,
    now: DateTime<Utc>,
) -> Result<i64, AppError> {
    let policy = assigned_policy(tx, db, ticket_id).await?;
    let segment = Segment {
        from: clock.state_changed_at,
        to: now,
    };
    let banked = settle_segments(db, policy.as_ref(), clock, Some(segment)).await?;
    write_clock(tx, clock.id, ClockState::Paused, Some(reason), &banked, now).await?;
    // G9-T1: a paused clock waits for nothing.
    refresh_next_due(tx, ticket_id).await?;
    if let Some(policy) = &policy {
        if let Some(unresolved) = &banked.unresolved {
            crate::sla::set_ticket_deadline(tx, ticket_id, Err(unresolved)).await?;
        }
        crate::sla::record_calculation(
            tx,
            CalculationRecord {
                ticket_id,
                policy_id: Some(policy.id()),
                calculation_type: CalculationType::Pause,
                unresolved: banked.unresolved.as_ref(),
                evidence: &banked.evidence,
                start_at: segment.from,
                end_at: Some(now),
                target_minutes: None,
                business_seconds: banked.banked_seconds,
                result_due_at: None,
            },
        )
        .await?;
    }
    Ok(banked.elapsed)
}

/// Resumes a paused clock at `now` and recalculates the deadline from the
/// remaining budget (D-422), banking any unsettled segments first. Returns
/// the clock's elapsed business seconds after resuming.
async fn resume_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    db: &DbPool,
    ticket_id: Uuid,
    clock: &ClockRow,
    now: DateTime<Utc>,
) -> Result<i64, AppError> {
    let policy = assigned_policy(tx, db, ticket_id).await?;
    let banked = settle_segments(db, policy.as_ref(), clock, None).await?;
    write_clock(tx, clock.id, ClockState::Running, None, &banked, now).await?;
    // G9-T1: running again; `store_deadline` below refreshes it once more
    // with the new deadline.
    refresh_next_due(tx, ticket_id).await?;
    if let Some(policy) = &policy {
        store_deadline(
            tx,
            db,
            ticket_id,
            policy,
            &banked,
            now,
            CalculationType::Resume,
        )
        .await?;
    }
    Ok(banked.elapsed)
}

// ── Pause / resume — the engine functions, HTTP-shape-free (so this crate's
// own integration tests can call them directly, same reason
// `convert::convert_work_request_to_ticket` is shaped this way) ────────────

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClockView {
    /// `"running"` | `"paused"`.
    pub state: String,
    pub paused_reason: Option<String>,
    pub elapsed_business_seconds: i64,
    pub state_changed_at: DateTime<Utc>,
}

impl ClockView {
    fn from_row(row: &ClockRow, paused_reason: Option<PauseReason>) -> Self {
        Self {
            state: row.state.as_str().to_string(),
            paused_reason: paused_reason.map(|r| r.as_str().to_string()),
            elapsed_business_seconds: row.elapsed_business_seconds,
            state_changed_at: row.state_changed_at,
        }
    }
}

/// Best-effort audit write, same posture as `break_glass.rs::write_audit`'s:
/// the state transition has already committed and is correct either way; a
/// failed audit row is logged, never turned into a client-visible failure
/// that would suggest the pause/resume didn't happen when it did. Thin
/// wrapper over the shared `attome_audit::write_business_event` (M26 R-15
/// dedup).
async fn write_audit(
    state: &EngineState,
    actor: Uuid,
    ticket_id: Uuid,
    event_name: &str,
    comment: String,
) {
    attome_audit::write_business_event(
        state,
        "service_ticket",
        ticket_id,
        AuditOperation::Update,
        event_name,
        actor,
        None,
        None,
        comment,
    )
    .await;
}

/// Pauses a ticket's SLA clock — privileged (`service_ticket.update`), audited.
/// Idempotent on an already-paused clock: the reason is updated but
/// `state_changed_at`/`elapsed_business_seconds` are left untouched (a
/// second pause call must not silently discard the already-banked running
/// segment by re-stamping the transition instant).
pub async fn pause_ticket(
    state: &EngineState,
    ticket_id: Uuid,
    reason: PauseReason,
    actor: Uuid,
) -> Result<ClockView, AppError> {
    let db = &state.base.db;
    let mut tx = attome_db::tx::begin(db).await?;
    lock_ticket(&mut tx, ticket_id).await?;
    let clock = get_or_create_clock(&mut tx, ticket_id).await?;

    if clock.state == ClockState::Paused {
        sqlx::query("UPDATE service_sla_clock SET paused_reason = $2 WHERE id = $1")
            .bind(clock.id)
            .bind(reason.as_str())
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        tx.commit().await.map_err(AppError::internal)?;
        return Ok(ClockView::from_row(&clock, Some(reason)));
    }

    let now = Utc::now();
    let new_elapsed = pause_in_tx(&mut tx, db, ticket_id, &clock, reason, now).await?;
    tx.commit().await.map_err(AppError::internal)?;

    write_audit(
        state,
        actor,
        ticket_id,
        "sla_clock.paused",
        format!(
            "SLA clock paused ({}); {new_elapsed}s business time banked",
            reason.as_str()
        ),
    )
    .await;

    Ok(ClockView {
        state: ClockState::Paused.as_str().to_string(),
        paused_reason: Some(reason.as_str().to_string()),
        elapsed_business_seconds: new_elapsed,
        state_changed_at: now,
    })
}

/// Resumes a ticket's SLA clock — privileged (`service_ticket.update`), audited.
/// Recomputes `service_ticket.resolution_due_at` from the policy's *remaining*
/// budget (target minus whatever business time is now banked), so the
/// deadline effectively shifts out by however long the ticket was paused,
/// rather than staying anchored to a due date computed before the pause.
/// Idempotent on an already-running clock (no-op).
pub async fn resume_ticket(
    state: &EngineState,
    ticket_id: Uuid,
    actor: Uuid,
) -> Result<ClockView, AppError> {
    let db = &state.base.db;
    let mut tx = attome_db::tx::begin(db).await?;
    lock_ticket(&mut tx, ticket_id).await?;
    let clock = get_or_create_clock(&mut tx, ticket_id).await?;

    if clock.state == ClockState::Running {
        tx.commit().await.map_err(AppError::internal)?;
        return Ok(ClockView::from_row(&clock, None));
    }

    let now = Utc::now();
    // Paused time contributes nothing (the whole point of pausing); only
    // segments left unsettled by an unresolvable calendar can be banked here.
    let elapsed = resume_in_tx(&mut tx, db, ticket_id, &clock, now).await?;
    tx.commit().await.map_err(AppError::internal)?;

    write_audit(
        state,
        actor,
        ticket_id,
        "sla_clock.resumed",
        format!("SLA clock resumed; {elapsed}s business time banked so far"),
    )
    .await;

    Ok(ClockView {
        state: ClockState::Running.as_str().to_string(),
        paused_reason: None,
        elapsed_business_seconds: elapsed,
        state_changed_at: now,
    })
}

// ── Recalculation of unresolved SLAs (D-517) ─────────────────────────────

/// The outcome of recalculating one ticket's SLA.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SlaRecalculation {
    pub ticket_id: Uuid,
    /// `false` when the ticket's SLA was not unresolved (nothing to do), or
    /// its policy no longer exists.
    pub recalculated: bool,
    /// The ticket's SLA status afterwards; `null` when no SLA was applied.
    pub sla_calculation_status: Option<SlaCalculationStatus>,
    pub resolution_due_at: Option<DateTime<Utc>>,
    pub sla_unresolved_reason: Option<UnresolvedReason>,
}

/// A bounded page of unresolved-SLA recalculation.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct UnresolvedRecalculationSummary {
    pub examined: u64,
    pub calculated: u64,
    pub still_unresolved: u64,
    /// Skipped because a concurrent pause/resume held the ticket's clock
    /// lock; they stay unresolved and a later page run picks them up.
    pub skipped: u64,
    /// Pass back as `after` for the next page; `null` when this was the last.
    pub next_after: Option<Uuid>,
}

const RECALCULATION_PAGE_MAX: i64 = 500;

fn parse_status(raw: Option<&str>) -> Option<SlaCalculationStatus> {
    match raw {
        Some("calculated") => Some(SlaCalculationStatus::Calculated),
        Some("unresolved") => Some(SlaCalculationStatus::Unresolved),
        _ => None,
    }
}

fn parse_reason(raw: Option<&str>) -> Option<UnresolvedReason> {
    [
        UnresolvedReason::CalendarUnresolved,
        UnresolvedReason::CalendarNoWorkingTime,
        UnresolvedReason::BusinessHoursInvalid,
        UnresolvedReason::CalculationFailed,
    ]
    .into_iter()
    .find(|reason| Some(reason.as_str()) == raw)
}

async fn read_ticket_sla(
    tx: &mut Transaction<'_, Postgres>,
    ticket_id: Uuid,
) -> Result<SlaRecalculation, AppError> {
    /// `(sla_calculation_status, resolution_due_at, sla_unresolved_reason)`.
    type StoredSla = (Option<String>, Option<DateTime<Utc>>, Option<String>);
    let row: Option<StoredSla> = sqlx::query_as(
        "SELECT sla_calculation_status, resolution_due_at, sla_unresolved_reason \
         FROM service_ticket WHERE id = $1",
    )
    .bind(ticket_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let (status, due_at, reason) = row.ok_or(AppError::NotFound)?;
    Ok(SlaRecalculation {
        ticket_id,
        recalculated: false,
        sla_calculation_status: parse_status(status.as_deref()),
        resolution_due_at: due_at,
        sla_unresolved_reason: parse_reason(reason.as_deref()),
    })
}

/// Where a running clock's deadline is anchored: the later of its last
/// transition and the last apply/resume calculation — an SLA applied after
/// the ticket was created runs from when it was applied, as `apply_policy`
/// itself calculates it.
async fn running_anchor(
    tx: &mut Transaction<'_, Postgres>,
    ticket_id: Uuid,
    clock: &ClockRow,
) -> Result<DateTime<Utc>, AppError> {
    let last_start: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT start_at FROM service_sla_calculation \
         WHERE ticket_ref = $1 AND calculation_type IN ('apply', 'resume') \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(ticket_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(last_start.map_or(clock.state_changed_at, |start| {
        start.max(clock.state_changed_at)
    }))
}

/// Recalculates a ticket whose SLA is unresolved: banks any unsettled clock
/// segments and stores a deadline when the policy's business-time model now
/// resolves, or records another unresolved attempt when it still does not.
/// A ticket whose SLA is not unresolved is left untouched, so this is safe
/// to repeat. A paused clock gets the deadline it would have if resumed now;
/// resuming recalculates it again, as D-422 already does.
pub async fn recalculate_ticket(
    db: &DbPool,
    ticket_id: Uuid,
) -> Result<SlaRecalculation, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    lock_ticket(&mut tx, ticket_id).await?;
    let current = read_ticket_sla(&mut tx, ticket_id).await?;
    if current.sla_calculation_status != Some(SlaCalculationStatus::Unresolved) {
        tx.commit().await.map_err(AppError::internal)?;
        return Ok(current);
    }
    let Some(policy) = assigned_policy(&mut tx, db, ticket_id).await? else {
        tx.commit().await.map_err(AppError::internal)?;
        tracing::warn!(
            ticket_id = %ticket_id,
            "sla: cannot recalculate an unresolved SLA whose policy no longer exists"
        );
        return Ok(current);
    };

    let clock = get_or_create_clock(&mut tx, ticket_id).await?;
    let banked = settle_segments(db, Some(&policy), &clock, None).await?;
    sqlx::query(
        "UPDATE service_sla_clock \
         SET elapsed_business_seconds = $2, unsettled_segments = $3 WHERE id = $1",
    )
    .bind(clock.id)
    .bind(banked.elapsed)
    .bind(render_segments(&banked.unsettled)?)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let anchor = match clock.state {
        ClockState::Running => running_anchor(&mut tx, ticket_id, &clock).await?,
        ClockState::Paused => Utc::now(),
    };
    store_deadline(
        &mut tx,
        db,
        ticket_id,
        &policy,
        &banked,
        anchor,
        CalculationType::Recalculate,
    )
    .await?;
    let after = read_ticket_sla(&mut tx, ticket_id).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(SlaRecalculation {
        recalculated: true,
        ..after
    })
}

/// Recalculates up to `limit` (at most 500) unresolved SLAs with ticket ids
/// after `after`, in id order — a bounded, resumable page: call again with
/// `next_after` until it is `null`. Each ticket commits on its own, so an
/// interrupted run loses nothing already recalculated.
pub async fn recalculate_unresolved(
    state: &EngineState,
    actor: Uuid,
    after: Option<Uuid>,
    limit: i64,
) -> Result<UnresolvedRecalculationSummary, AppError> {
    let db = &state.base.db;
    let limit = limit.clamp(1, RECALCULATION_PAGE_MAX);
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM service_ticket \
         WHERE sla_calculation_status = 'unresolved' AND ($1::uuid IS NULL OR id > $1) \
         ORDER BY id LIMIT $2",
    )
    .bind(after)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut summary = UnresolvedRecalculationSummary::default();
    for ticket_id in &ids {
        summary.examined += 1;
        match recalculate_ticket(db, *ticket_id).await {
            Ok(result)
                if result.sla_calculation_status == Some(SlaCalculationStatus::Calculated) =>
            {
                summary.calculated += 1;
                // Plan 3.7/C13-adjacent (I5): this admin bulk page previously
                // wrote no audit event at all, unlike the single-ticket route
                // it shares `recalculate_ticket` with. One event per
                // successfully-recalculated ticket, same shape as the
                // single-ticket route's, so a reader cannot tell which path
                // produced it.
                write_audit(
                    state,
                    actor,
                    *ticket_id,
                    "sla.recalculated",
                    "SLA recalculated via the unresolved-SLA bulk page".to_string(),
                )
                .await;
            }
            Ok(_) => summary.still_unresolved += 1,
            Err(AppError::Conflict(_)) => summary.skipped += 1,
            Err(AppError::NotFound) => {} // deleted between the page read and now
            Err(e) => return Err(e),
        }
    }
    summary.next_after = ids.last().copied().filter(|_| ids.len() as i64 == limit);
    Ok(summary)
}

// ── HTTP ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct PauseClockRequest {
    pub reason: PauseReason,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct RecalculateUnresolvedRequest {
    /// The previous page's `next_after`; omit for the first page.
    #[serde(default)]
    pub after: Option<Uuid>,
    /// Page size, 1-500 (default 500).
    #[serde(default)]
    pub limit: Option<i64>,
}

#[utoipa::path(
    post,
    path = "/api/v1/ticket/{id}/sla/recalculate",
    tag = "service",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "The ticket's SLA state after recalculation (unchanged unless it was unresolved)", body = SlaRecalculation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such ticket", body = ErrorResponse),
        (status = 409, description = "A pause/resume request for this ticket is in progress", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn recalculate_ticket_route(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketUpdate>>,
    Path(ticket_id): Path<Uuid>,
) -> Result<Json<SlaRecalculation>, AppError> {
    let result = recalculate_ticket(&state.base.db, ticket_id).await?;
    if result.recalculated {
        let status = result.sla_calculation_status.map_or("none", |s| match s {
            SlaCalculationStatus::Calculated => "calculated",
            SlaCalculationStatus::Unresolved => "unresolved",
        });
        write_audit(
            &state,
            ctx.user_id,
            ticket_id,
            "sla.recalculated",
            format!("SLA recalculated; status {status}"),
        )
        .await;
    }
    Ok(Json(result))
}

#[utoipa::path(
    post,
    path = "/api/v1/ticket/sla/recalculate-unresolved",
    tag = "service",
    request_body = RecalculateUnresolvedRequest,
    responses(
        (status = 200, description = "One page of unresolved SLAs recalculated", body = UnresolvedRecalculationSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn recalculate_unresolved_route(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<RecalculateUnresolvedRequest>,
) -> Result<Json<UnresolvedRecalculationSummary>, AppError> {
    let summary = recalculate_unresolved(
        &state,
        ctx.user_id,
        body.after,
        body.limit.unwrap_or(RECALCULATION_PAGE_MAX),
    )
    .await?;
    Ok(Json(summary))
}

#[utoipa::path(
    post,
    path = "/api/v1/ticket/{id}/sla-clock/pause",
    tag = "service",
    params(("id" = Uuid, Path)),
    request_body = PauseClockRequest,
    responses(
        (status = 200, description = "Clock paused", body = ClockView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such ticket", body = ErrorResponse),
        (status = 409, description = "Another pause/resume request for this ticket is already in progress", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn pause_clock_route(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketUpdate>>,
    Path(ticket_id): Path<Uuid>,
    Json(body): Json<PauseClockRequest>,
) -> Result<Json<ClockView>, AppError> {
    let actor = ctx.user_id;
    let view = pause_ticket(&state, ticket_id, body.reason, actor).await?;
    Ok(Json(view))
}

#[utoipa::path(
    post,
    path = "/api/v1/ticket/{id}/sla-clock/resume",
    tag = "service",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Clock resumed", body = ClockView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such ticket", body = ErrorResponse),
        (status = 409, description = "Another pause/resume request for this ticket is already in progress", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn resume_clock_route(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketUpdate>>,
    Path(ticket_id): Path<Uuid>,
) -> Result<Json<ClockView>, AppError> {
    let actor = ctx.user_id;
    let view = resume_ticket(&state, ticket_id, actor).await?;
    Ok(Json(view))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/ticket/{id}/sla-clock/pause",
            post(pause_clock_route),
        )
        .route(
            "/api/v1/ticket/{id}/sla-clock/resume",
            post(resume_clock_route),
        )
        .route(
            "/api/v1/ticket/{id}/sla/recalculate",
            post(recalculate_ticket_route),
        )
        .route(
            "/api/v1/ticket/sla/recalculate-unresolved",
            post(recalculate_unresolved_route),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own `lib.rs::openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    pause_clock_route,
    resume_clock_route,
    recalculate_ticket_route,
    recalculate_unresolved_route
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

// ── Auto-pause (change-feed consumer, D-358 cursor model) ─────────────────

/// This consumer's name in `change_consumer_cursor` — stable, never
/// reused for anything else.
const AUTO_PAUSE_CONSUMER: &str = "attome-service/ticket-auto-pause";
const AUTO_PAUSE_BATCH_SIZE: i64 = 200;

/// Reconciles ticket clocks against `service_ticket.status`: auto-pauses (reason
/// `waiting_customer`) a running clock on any ticket update event whose
/// current status is `waiting_on_customer`, and auto-resumes a clock this
/// function itself paused (never one an operator paused by hand for
/// `on_hold`/`out_of_scope`) once status has moved off `waiting_on_customer`.
///
/// Also stamps/clears `service_ticket.resolved_at` off the same event stream
/// (`reconcile_resolved_at`) — `analytics_seed`'s mean-time-to-resolve query
/// needs it, and nothing else on this entity sets it. Folded into this same
/// sweep/cursor rather than a second consumer: both reconciliations key off
/// exactly the same "an `service_ticket` update happened, re-derive state from
/// its current `status`" read, so a second cursor over the identical event
/// set would just double the read traffic for no isolation benefit.
///
/// A plain, directly callable, directly testable function today — same "not
/// yet a `EngineJob`" posture `sla.rs::sweep_breaches` already established
/// (see this module's doc comment for why no synchronous hook exists to use
/// instead). Returns the number of tickets reconciled (auto-pause/resume
/// and/or `resolved_at` change).
pub async fn sweep_auto_pause(db: &DbPool) -> Result<u64, AppError> {
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let events =
        attome_core::change_feed::read_batch(&mut conn, AUTO_PAUSE_CONSUMER, AUTO_PAUSE_BATCH_SIZE)
            .await?;
    if events.is_empty() {
        return Ok(0);
    }

    // De-duplicate to the latest event per ticket in this batch — a ticket
    // touched several times only needs reconciling once per sweep pass. G9-T1:
    // keep that event's time, so a pause or resume starts when the status
    // changed, not when this sweep happened to run.
    let mut latest: std::collections::BTreeMap<Uuid, DateTime<Utc>> =
        std::collections::BTreeMap::new();
    for event in events
        .iter()
        .filter(|e| e.entity_logicalname == "service_ticket")
    {
        let at = latest.entry(event.record_id).or_insert(event.created_at);
        if event.created_at > *at {
            *at = event.created_at;
        }
    }

    let mut reconciled = 0u64;
    for (ticket_id, changed_at) in latest {
        let paused_or_resumed = reconcile_auto_pause(db, ticket_id, changed_at).await?;
        let resolved_changed = reconcile_resolved_at(db, ticket_id).await?;
        // G9-T3: the supplier clock follows the ticket's hand-off.
        crate::supplier_sla::reconcile(db, ticket_id, Utc::now()).await?;
        // G8-T1: the escalation rules it now matches, or no longer does.
        crate::escalation::schedule_for_ticket(db, ticket_id).await?;
        // G10-T2: a newly resolved case uses its cases entitlement, once.
        if resolved_changed {
            crate::entitlement::on_ticket_resolved(db, ticket_id).await?;
        }
        if paused_or_resumed || resolved_changed {
            reconciled += 1;
        }
    }

    // Advance the cursor past every event in this batch (including ones for
    // other entities, and duplicates for the same ticket) regardless of
    // whether that ticket's own reconciliation changed anything — the
    // reconciliation above is idempotent, so replaying it after a crash is
    // safe, but never re-reading it is the whole point of the cursor.
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    if let Some(last) = events.last() {
        attome_core::change_feed::advance(&mut conn, AUTO_PAUSE_CONSUMER, last).await?;
    }

    Ok(reconciled)
}

/// Stamps `service_ticket.resolved_at = NOW()` the first time `status` reads
/// `resolved`/`closed` (idempotent: only writes when it is currently NULL),
/// and clears it back to NULL if the ticket is reopened (`status` moves off
/// both) — a re-resolved ticket gets a fresh timestamp on its next crossing
/// rather than keeping a stale one from a prior resolution. Mean-time-to-
/// *respond* is deliberately not stamped alongside it: it needs a "first
/// response" concept from ticket comments/notes that does not exist yet,
/// same gap `sla.rs`'s own module doc already names for first-response SLA
/// targets.
async fn reconcile_resolved_at(db: &DbPool, ticket_id: Uuid) -> Result<bool, AppError> {
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM service_ticket WHERE id = $1")
            .bind(ticket_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let Some(status) = status else {
        return Ok(false); // ticket deleted/purged since the event was recorded
    };

    let is_resolved = status == "resolved" || status == "closed";
    let updated = if is_resolved {
        sqlx::query(
            "UPDATE service_ticket SET resolved_at = NOW() WHERE id = $1 AND resolved_at IS NULL",
        )
        .bind(ticket_id)
        .execute(db)
        .await
    } else {
        sqlx::query(
            "UPDATE service_ticket SET resolved_at = NULL WHERE id = $1 AND resolved_at IS NOT NULL",
        )
        .bind(ticket_id)
        .execute(db)
        .await
    }
    .map_err(AppError::internal)?;

    Ok(updated.rows_affected() > 0)
}

async fn reconcile_auto_pause(
    db: &DbPool,
    ticket_id: Uuid,
    changed_at: DateTime<Utc>,
) -> Result<bool, AppError> {
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM service_ticket WHERE id = $1")
            .bind(ticket_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let Some(status) = status else {
        return Ok(false); // ticket deleted/purged since the event was recorded
    };

    let clock: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT state, paused_reason FROM service_sla_clock WHERE ticket_ref = $1")
            .bind(ticket_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;

    let waiting_on_customer = status == "waiting_on_customer";
    match clock {
        None if waiting_on_customer => {
            // System actor: no human is behind an auto-pause, so there is no
            // audit `AuditUserContext` to attribute it to via the same
            // pause_ticket/resume_ticket path that `fetch_audit_ctx` resolves
            // per-actor — a system-authored `note`, same convention
            // `sla.rs::sweep_breaches` already uses for its own breach mark,
            // is the visible record here instead.
            get_or_create_and_pause_system(db, ticket_id, PauseReason::WaitingCustomer, changed_at)
                .await?;
            Ok(true)
        }
        Some((state, _))
            if waiting_on_customer && ClockState::parse(&state) == ClockState::Running =>
        {
            get_or_create_and_pause_system(db, ticket_id, PauseReason::WaitingCustomer, changed_at)
                .await?;
            Ok(true)
        }
        Some((state, Some(reason)))
            if !waiting_on_customer
                && ClockState::parse(&state) == ClockState::Paused
                && reason == PauseReason::WaitingCustomer.as_str() =>
        {
            resume_system(db, ticket_id, changed_at).await?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

async fn get_or_create_and_pause_system(
    db: &DbPool,
    ticket_id: Uuid,
    reason: PauseReason,
    changed_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    lock_ticket(&mut tx, ticket_id).await?;
    let clock = get_or_create_clock(&mut tx, ticket_id).await?;
    if clock.state == ClockState::Paused {
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(());
    }
    let at = transition_time(changed_at, clock.state_changed_at, Utc::now());
    pause_in_tx(&mut tx, db, ticket_id, &clock, reason, at).await?;
    sqlx::query(
        "INSERT INTO note (id, entity_name, record_id, note_text, is_customer_visible) \
         VALUES ($1, 'service_ticket', $2, 'SLA clock auto-paused: ticket is waiting on customer.', false)",
    )
    .bind(Uuid::now_v7())
    .bind(ticket_id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)
}

async fn resume_system(
    db: &DbPool,
    ticket_id: Uuid,
    changed_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    lock_ticket(&mut tx, ticket_id).await?;
    let clock = get_or_create_clock(&mut tx, ticket_id).await?;
    if clock.state == ClockState::Running {
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(());
    }
    let at = transition_time(changed_at, clock.state_changed_at, Utc::now());
    resume_in_tx(&mut tx, db, ticket_id, &clock, at).await?;
    sqlx::query(
        "INSERT INTO note (id, entity_name, record_id, note_text, is_customer_visible) \
         VALUES ($1, 'service_ticket', $2, 'SLA clock auto-resumed: ticket is no longer waiting on customer.', false)",
    )
    .bind(Uuid::now_v7())
    .bind(ticket_id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)
}

// ── G9-T1: the clock's next moment, swept on time ─────────────────────────

/// The clock waits to warn.
pub const DUE_WARNING: &str = "warning";
/// The clock waits to breach.
pub const DUE_BREACH: &str = "breach";
/// The ticket attribute a service clock runs against.
pub const TARGET_ATTRIBUTE: &str = "resolution_due_at";
/// Most clocks one due sweep acts on, and most it backfills.
const DUE_BATCH: i64 = 500;

/// When an automatic pause or resume takes effect: when the status changed,
/// but never before the clock's last change nor after now. Pure.
pub fn transition_time(
    changed_at: DateTime<Utc>,
    clock_changed_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> DateTime<Utc> {
    changed_at.max(clock_changed_at).min(now)
}

/// The next moment a clock waits for: the warning (`warn_at_percent` of the
/// way from the ticket's creation to its deadline, the same measure
/// `sla::sweep_warnings` uses) until it has warned, then the breach at the
/// deadline; nothing while paused, breached, closed or without a deadline.
/// Pure.
pub fn next_due(
    created_at: DateTime<Utc>,
    due_at: Option<DateTime<Utc>>,
    warn_at_percent: Option<f64>,
    warned: bool,
    breached: bool,
    running: bool,
    open: bool,
) -> Option<(DateTime<Utc>, &'static str)> {
    if !running || !open || breached {
        return None;
    }
    let due = due_at?;
    if !warned
        && due > created_at
        && let Some(percent) = warn_at_percent.filter(|p| *p > 0.0 && *p < 100.0)
    {
        let span = (due - created_at).num_milliseconds() as f64;
        let offset = chrono::Duration::milliseconds((span * percent / 100.0).round() as i64);
        return Some((created_at + offset, DUE_WARNING));
    }
    Some((due, DUE_BREACH))
}

/// Recomputes a ticket clock's next moment from the ticket and its policy.
/// Called wherever the deadline, the clock's state, or the warned/breached
/// marks change, in that change's transaction.
pub(crate) async fn refresh_next_due(
    conn: &mut sqlx::PgConnection,
    ticket_id: Uuid,
) -> Result<(), AppError> {
    type Row = (
        DateTime<Utc>,
        Option<DateTime<Utc>>,
        Option<f64>,
        bool,
        bool,
        String,
        String,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT t.created_at, t.resolution_due_at, p.warn_at_percent::double precision, \
                coalesce(t.sla_warned, false), coalesce(t.sla_breached, false), \
                coalesce(t.status, ''), c.state \
           FROM service_sla_clock c \
           JOIN service_ticket t ON t.id = c.ticket_ref \
           LEFT JOIN service_sla_policy p ON p.id = t.sla_policy_id \
          WHERE c.ticket_ref = $1",
    )
    .bind(ticket_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some((created_at, due_at, warn_at, warned, breached, status, state)) = row else {
        return Ok(());
    };
    let next = next_due(
        created_at,
        due_at,
        warn_at,
        warned,
        breached,
        ClockState::parse(&state) == ClockState::Running,
        status != "resolved" && status != "closed",
    );
    sqlx::query(
        "UPDATE service_sla_clock \
            SET target_attribute = $2, next_due_at = $3, next_due_kind = $4 \
          WHERE ticket_ref = $1",
    )
    .bind(ticket_id)
    .bind(TARGET_ATTRIBUTE)
    .bind(next.map(|(at, _)| at))
    .bind(next.map(|(_, kind)| kind))
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Gives a ticket that has a deadline a running clock, so the due sweep
/// tracks it from the start (a clock was created only on the first pause
/// before G9-T1). Takes the ticket's clock lock without waiting; when a
/// pause or resume holds it, that call creates the clock itself.
pub(crate) async fn ensure_tracked_clock(
    conn: &mut sqlx::PgConnection,
    ticket_id: Uuid,
) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-service/sla-clock:{ticket_id}"))
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO service_sla_clock \
             (id, ticket_ref, state, paused_reason, elapsed_business_seconds, state_changed_at) \
         SELECT $1, t.id, 'running', NULL, 0, t.created_at FROM service_ticket t \
          WHERE t.id = $2 AND t.resolution_due_at IS NOT NULL \
            AND NOT EXISTS (SELECT 1 FROM service_sla_clock c WHERE c.ticket_ref = t.id)",
    )
    .bind(Uuid::now_v7())
    .bind(ticket_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Whether this deployment's clocks carry `next_due_at` (the service
/// module's bundle is applied).
async fn clocks_track_due(db: &DbPool) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
                         WHERE table_schema = current_schema() \
                           AND table_name = 'service_sla_clock' AND column_name = 'next_due_at')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// G9-T1, from the timer sweep (M10) every 15 seconds: fires the warnings
/// and breaches whose moment has come, from the clocks' `next_due_at`, and
/// fills `next_due_at` on clocks that predate it, a batch per pass. Returns
/// how many clocks it acted on.
pub async fn sweep_due_clocks(
    db: &DbPool,
    notification_cfg: &NotificationSection,
    now: DateTime<Utc>,
) -> Result<u64, AppError> {
    if !clocks_track_due(db).await? {
        return Ok(0);
    }
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let untracked: Vec<Uuid> = sqlx::query_scalar(
        "SELECT ticket_ref FROM service_sla_clock WHERE target_attribute IS NULL LIMIT $1",
    )
    .bind(DUE_BATCH)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    for ticket_id in untracked {
        refresh_next_due(&mut conn, ticket_id).await?;
    }

    let due: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT ticket_ref, next_due_kind FROM service_sla_clock \
          WHERE state = 'running' AND next_due_at <= $1 \
          ORDER BY next_due_at LIMIT $2",
    )
    .bind(now)
    .bind(DUE_BATCH)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    drop(conn);

    let mut acted = 0u64;
    for (ticket_id, kind) in due {
        let fired = if kind.as_deref() == Some(DUE_WARNING) {
            crate::sla::warn_one(db, notification_cfg, ticket_id).await?
        } else {
            crate::sla::breach_one(db, notification_cfg, ticket_id).await?
        };
        if fired {
            acted += 1;
        }
        // Whether or not it fired (it may have been resolved meanwhile), the
        // clock moves on to its next moment, so it is not picked up again.
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        refresh_next_due(&mut conn, ticket_id).await?;
    }
    Ok(acted)
}

#[cfg(test)]
mod sla_clock_due {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn at(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 19, hour, 0, 0)
            .single()
            .unwrap_or_default()
    }

    #[test]
    fn sla_clock_due_warns_first_then_breaches() {
        let created = at(8);
        let due = Some(at(18));
        assert_eq!(
            next_due(created, due, Some(80.0), false, false, true, true),
            Some((at(16), DUE_WARNING))
        );
        assert_eq!(
            next_due(created, due, Some(80.0), true, false, true, true),
            Some((at(18), DUE_BREACH))
        );
        assert_eq!(
            next_due(created, due, None, false, false, true, true),
            Some((at(18), DUE_BREACH))
        );
    }

    #[test]
    fn sla_clock_due_waits_for_nothing_when_paused_breached_or_closed() {
        let created = at(8);
        let due = Some(at(18));
        assert_eq!(
            next_due(created, due, Some(80.0), false, false, false, true),
            None
        );
        assert_eq!(
            next_due(created, due, Some(80.0), true, true, true, true),
            None
        );
        assert_eq!(
            next_due(created, due, Some(80.0), false, false, true, false),
            None
        );
        assert_eq!(
            next_due(created, None, Some(80.0), false, false, true, true),
            None
        );
    }

    #[test]
    fn sla_clock_due_pause_starts_at_the_status_change() {
        let clock_changed = at(9);
        let now = at(12);
        // The sweep ran at noon; the ticket went to waiting at 10.
        assert_eq!(transition_time(at(10), clock_changed, now), at(10));
        // Never before the clock's own last change, never in the future.
        assert_eq!(transition_time(at(8), clock_changed, now), clock_changed);
        assert_eq!(
            transition_time(now + Duration::minutes(5), clock_changed, now),
            now
        );
    }
}

// ── Escalation chain (assignee -> queue lead -> manager) ──────────────────

/// Position holders exactly `levels_up` positions above `user_id`'s own
/// position(s) in `position`'s hierarchy — `levels_up = 1` is
/// "queue lead" (the immediate position parent's holder(s)), `levels_up = 2`
/// is "manager" (the position grandparent's holder(s)). Same bounded
/// recursive-CTE shape `attome-security::db::would_create_position_cycle`
/// already uses for this table; a user with no position, or whose position
/// chain is shorter than `levels_up`, resolves to an empty list — never an
/// error, and never a fabricated fallback.
async fn position_holders_up(
    db: &DbPool,
    user_id: Uuid,
    levels_up: i32,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"
        WITH RECURSIVE ancestors AS (
            SELECT p.id, p.parent_position_ref, 0 AS depth
            FROM user_account_mm_position mp
            JOIN position p ON p.id = mp.position_ref AND p.is_deleted = false
            WHERE mp.user_ref = $1 AND mp.is_deleted = false

            UNION ALL

            SELECT p2.id, p2.parent_position_ref, a.depth + 1
            FROM position p2
            JOIN ancestors a ON p2.id = a.parent_position_ref
            WHERE p2.is_deleted = false AND a.depth < $2
        )
        SELECT DISTINCT mp2.user_ref
        FROM ancestors a
        JOIN user_account_mm_position mp2 ON mp2.position_ref = a.id AND mp2.is_deleted = false
        JOIN user_account u ON u.id = mp2.user_ref AND u.is_active = true
        WHERE a.depth = $2
        "#,
    )
    .bind(user_id)
    .bind(levels_up)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// The three escalation tiers for a ticket, in order: `[assignee], [queue
/// lead(s)], [manager(s)]`. A ticket with no assignee (or an inactive one)
/// resolves every tier to empty — see this module's doc comment for why that
/// is left unfilled rather than guessing a queue-team fallback.
async fn resolve_escalation_chain(
    db: &DbPool,
    ticket_id: Uuid,
) -> Result<Vec<Vec<Uuid>>, AppError> {
    let assignee_id: Option<Uuid> =
        sqlx::query_scalar("SELECT assignee_id FROM service_ticket WHERE id = $1")
            .bind(ticket_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .flatten();

    let Some(assignee_id) = assignee_id else {
        return Ok(vec![vec![], vec![], vec![]]);
    };

    let assignee_active: bool =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(assignee_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .unwrap_or(false);

    let tier0 = if assignee_active {
        vec![assignee_id]
    } else {
        vec![]
    };
    let tier1 = position_holders_up(db, assignee_id, 1).await?;
    let tier2 = position_holders_up(db, assignee_id, 2).await?;
    Ok(vec![tier0, tier1, tier2])
}

/// The lowest-index non-empty tier at or after `from_tier_index` — the next
/// escalation target, whichever tier it turns out to live in. Returns the
/// tier's 1-based "level" (i.e. `escalation_level` to store) alongside its
/// recipients, or `None` if every remaining tier is empty (nothing left to
/// escalate to).
fn next_escalation_target(chain: &[Vec<Uuid>], from_tier_index: usize) -> Option<(i32, Vec<Uuid>)> {
    for (idx, tier) in chain.iter().enumerate().skip(from_tier_index) {
        if !tier.is_empty() {
            return Some((idx as i32 + 1, tier.clone()));
        }
    }
    None
}

async fn ticket_summary(db: &DbPool, ticket_id: Uuid) -> Result<(String, String), AppError> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT ticket_number, title FROM service_ticket WHERE id = $1")
            .bind(ticket_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(row.unwrap_or_else(|| ("?".to_string(), "(ticket)".to_string())))
}

pub(crate) async fn notify_recipients(
    db: &DbPool,
    notification_cfg: &NotificationSection,
    recipients: &[Uuid],
    subject: &str,
    body_text: &str,
    route: String,
) {
    for &user_id in recipients {
        let req = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(user_id),
            is_global: false,
            organization_ref: None,
            channels: None, // REVIEW-2026-09-02 finding #3: inherit the platform default (in_app+email), not an in-app-only override
            subject: Some(subject.to_string()),
            body_html: None,
            body_text: Some(body_text.to_string()),
            route: Some(route.clone()),
            variables: std::collections::HashMap::new(),
            priority: "high".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        if let Err(e) =
            attome_notification::dispatch::create_dispatch(db, notification_cfg, req).await
        {
            tracing::error!(error = %e, user_id = %user_id, "sla: escalation notification dispatch failed");
        }
    }
}

/// Called by `sla::sweep_breaches` right after a ticket is durably marked
/// breached: emits the `sla.breached` domain event and escalates to tier 0
/// (level 1) of [`resolve_escalation_chain`] — best-effort, so a notification
/// failure never rolls back or contradicts the already-committed breach.
/// Idempotent (guarded by `escalation_level IS NULL OR = 0`): a retried call
/// for an already-escalated ticket is a no-op.
pub async fn escalate_on_breach(
    db: &DbPool,
    notification_cfg: &NotificationSection,
    ticket_id: Uuid,
) -> Result<(), AppError> {
    let chain = resolve_escalation_chain(db, ticket_id).await?;
    let Some((level, recipients)) = next_escalation_target(&chain, 0) else {
        tracing::warn!(
            ticket_id = %ticket_id,
            "sla: breach escalation has no resolvable recipient (no assignee, queue lead, or manager)"
        );
        return Ok(());
    };

    let mut tx = attome_db::tx::begin(db).await?;
    let updated = sqlx::query(
        "UPDATE service_ticket SET escalation_level = $2, escalated_at = NOW() \
         WHERE id = $1 AND (escalation_level IS NULL OR escalation_level = 0)",
    )
    .bind(ticket_id)
    .bind(level)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(()); // already escalated by a concurrent/earlier pass
    }
    attome_core::change_feed::emit_named(
        &mut tx,
        "service_ticket",
        ticket_id,
        ChangeOperation::Update,
        "sla.breached",
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    let (ticket_number, title) = ticket_summary(db, ticket_id).await?;
    notify_recipients(
        db,
        notification_cfg,
        &recipients,
        &format!("[SLA Breach] Ticket {ticket_number} — {title}"),
        &format!(
            "Ticket {ticket_number} ({title}) has missed its SLA resolution target. \
             Escalation level {level}."
        ),
        format!("/tickets/{ticket_id}"),
    )
    .await;
    Ok(())
}

/// Notifies just the ticket's current assignee about a pre-breach warning
/// (`sla.warning`) — informational, not escalatory, so `escalation_level` is
/// never touched here. Called by `sla::sweep_warnings` after the warning is
/// durably recorded.
pub async fn notify_warning(
    db: &DbPool,
    notification_cfg: &NotificationSection,
    ticket_id: Uuid,
) -> Result<(), AppError> {
    let assignee_id: Option<Uuid> =
        sqlx::query_scalar("SELECT assignee_id FROM service_ticket WHERE id = $1")
            .bind(ticket_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .flatten();
    let Some(assignee_id) = assignee_id else {
        return Ok(());
    };
    let (ticket_number, title) = ticket_summary(db, ticket_id).await?;
    notify_recipients(
        db,
        notification_cfg,
        &[assignee_id],
        &format!("[SLA Warning] Ticket {ticket_number} — {title}"),
        &format!("Ticket {ticket_number} ({title}) is approaching its SLA resolution target."),
        format!("/tickets/{ticket_id}"),
    )
    .await;
    Ok(())
}

/// Re-escalation step interval — a fixed, deliberate simplification (not
/// policy-configurable) rather than a second `service_sla_policy` field the
/// checklist never asked for. Same "plain constant, revisit if it needs to
/// vary" posture `sla.rs::SWEEP_BATCH_SIZE` already takes.
const RE_ESCALATION_STEP_MINUTES: i64 = 240;
/// Same batch-bound reasoning as `sla.rs::SWEEP_BATCH_SIZE` — its own
/// constant, not shared, since the two sweeps select different candidate
/// sets.
const ESCALATION_SWEEP_BATCH_SIZE: i64 = 500;

/// Advances still-breached, still-open tickets to the next escalation tier
/// once `RE_ESCALATION_STEP_MINUTES` have passed since the last escalation —
/// `escalate_on_breach` only ever reaches tier 0 (level 1); this is what
/// walks a ticket that stays breached on to "queue lead" (level 2) and
/// "manager" (level 3). A paused clock excludes a ticket here too, same
/// reasoning as `sla.rs::sweep_breaches`/`sweep_warnings`. A ticket whose
/// remaining tiers are all empty is left at its current level (retried next
/// sweep, harmless) rather than errored.
pub async fn sweep_escalations(
    db: &DbPool,
    notification_cfg: &NotificationSection,
) -> Result<u64, AppError> {
    let candidates: Vec<(Uuid, i32)> = sqlx::query_as(
        "SELECT t.id, COALESCE(t.escalation_level, 0) FROM service_ticket t \
         WHERE t.sla_breached = true \
           AND t.status NOT IN ('resolved', 'closed') \
           AND t.escalation_level IS NOT NULL AND t.escalation_level BETWEEN 1 AND 2 \
           AND t.escalated_at IS NOT NULL \
           AND t.escalated_at < NOW() - ($1 * INTERVAL '1 minute') \
           AND NOT EXISTS ( \
               SELECT 1 FROM service_sla_clock c \
               WHERE c.ticket_ref = t.id AND c.state = 'paused' \
           ) \
         LIMIT $2",
    )
    .bind(RE_ESCALATION_STEP_MINUTES as f64)
    .bind(ESCALATION_SWEEP_BATCH_SIZE)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut escalated = 0u64;
    for (ticket_id, current_level) in candidates {
        let chain = resolve_escalation_chain(db, ticket_id).await?;
        let Some((new_level, recipients)) = next_escalation_target(&chain, current_level as usize)
        else {
            continue;
        };

        let mut tx = attome_db::tx::begin(db).await?;
        let updated = sqlx::query(
            "UPDATE service_ticket SET escalation_level = $2, escalated_at = NOW() \
             WHERE id = $1 AND escalation_level = $3",
        )
        .bind(ticket_id)
        .bind(new_level)
        .bind(current_level)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if updated.rows_affected() == 0 {
            tx.rollback().await.map_err(AppError::internal)?;
            continue; // a concurrent pass already advanced this ticket
        }
        tx.commit().await.map_err(AppError::internal)?;

        let (ticket_number, title) = ticket_summary(db, ticket_id).await?;
        notify_recipients(
            db,
            notification_cfg,
            &recipients,
            &format!("[SLA Breach — Level {new_level}] Ticket {ticket_number} — {title}"),
            &format!(
                "Ticket {ticket_number} ({title}) is still breached and has been escalated \
                 to level {new_level}."
            ),
            format!("/tickets/{ticket_id}"),
        )
        .await;
        escalated += 1;
    }

    Ok(escalated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_escalation_target_skips_empty_tiers() {
        let chain = vec![vec![], vec![Uuid::nil()], vec![]];
        assert_eq!(
            next_escalation_target(&chain, 0),
            Some((2, vec![Uuid::nil()]))
        );
    }

    #[test]
    fn next_escalation_target_none_when_every_remaining_tier_is_empty() {
        let chain = vec![vec![Uuid::nil()], vec![], vec![]];
        assert_eq!(next_escalation_target(&chain, 1), None);
    }

    #[test]
    fn next_escalation_target_prefers_the_lowest_index() {
        let chain = vec![vec![Uuid::nil()], vec![Uuid::nil()], vec![]];
        let (level, _) = next_escalation_target(&chain, 0).unwrap();
        assert_eq!(level, 1);
    }
}
