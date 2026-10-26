//! D-421 / M10 (Approval & Governance) — the per-step timeout sweep for a
//! plan-bearing `approval_request`, driven by this crate's own
//! `poller` (F172's escalation timer, M51) instead of a second background-
//! task system (guidelines §10/§13). The module plan explicitly calls for
//! reusing "M51's existing escalation-sweep job" rather than adding a new
//! `EngineJob` variant — `poller::spawn`'s loop is exactly that: a bare
//! `tokio::spawn` scanner, not a durable-queue job, so extending its tick is
//! the actual reuse, not a new mechanism next to it.
//!
//! Ownership split (D-421, mirrored from `attome_approval`'s own doc
//! comments): `attome_approval::list_due_step_timeouts`/`apply_step_timeout`
//! own the DB transition (base layer, no audit/notification knowledge);
//! `attome_audit::approval::apply_and_audit_step_timeout` wraps that with the
//! audit event (`decided_by = policy`) and resolves who to notify on an
//! `Escalated` outcome; this module is the one place that actually sends
//! that notification, since it is the crate with a send API
//! (`dispatch::create_dispatch`).

use attome_approval::{ApprovalRequest, ApprovalStep, TimeoutOutcome};
use attome_audit::approval::StepDueError;
use attome_core::EngineState;
use chrono::{DateTime, Utc};

use crate::dispatch::{self, DispatchRequest};

/// BAP-11b — the dedup key of an auto-approved request's execution job: one
/// live job per request, however often the sweep reaches it.
pub fn execute_approved_dedup_key(request_id: uuid::Uuid) -> String {
    format!("approval-execute:{request_id}")
}

/// BAP-11b — enqueues the execution of an auto-approved request inside the
/// timeout's own transaction, so a crash between the approval and the enqueue
/// cannot strand an approved action nobody will run. Unconditional for an
/// `AutoApproved` outcome: whether this binary dispatches the action type is
/// the job handler's question (`attome_api::execute_approved_request`), not
/// this crate's.
#[derive(Debug)]
pub struct EnqueueAutoApprovedExecution;

impl attome_db::BeforeCommit<(ApprovalRequest, TimeoutOutcome)> for EnqueueAutoApprovedExecution {
    fn before_commit<'a>(
        &'a self,
        tx: &'a mut attome_db::Tx<'_>,
        committed: &'a (ApprovalRequest, TimeoutOutcome),
    ) -> attome_db::HookFuture<'a> {
        Box::pin(async move {
            let (request, outcome) = committed;
            if *outcome == TimeoutOutcome::AutoApproved {
                attome_jobs::enqueue_in_tx_dedup(
                    tx,
                    attome_core::jobs::EngineJob::ExecuteApprovedRequest {
                        request_id: request.id,
                    },
                    &execute_approved_dedup_key(request.id),
                )
                .await
                .map_err(attome_types::AppError::internal)?;
            }
            Ok(())
        })
    }
}

/// Called from `poller::spawn`'s tick, alongside `dispatch::run_due_escalations`.
/// Bounded per tick (`limit`) so one slow/large batch can't starve the
/// notification-dispatch scan running in the same loop.
///
/// Z10-T8: the tick also sends each step's reminder, and both reminders and
/// timeouts count a `business_hours` step's minutes in the deployment's
/// default calendar, loaded once per tick when there is work. The calendar
/// is the organisation default, not an approver's own: a step's SLA
/// belongs to the step, which may have many approvers.
pub async fn run_due_approval_timeouts(state: &EngineState, limit: i64) {
    let now = chrono::Utc::now();
    let reminders = match attome_approval::list_due_reminders(&state.base.db, now, limit).await {
        Ok(requests) => requests,
        Err(e) => {
            tracing::error!(error = %e, "approval reminder sweep: list_due_reminders failed");
            Vec::new()
        }
    };
    let due = match attome_approval::list_due_step_timeouts(&state.base.db, limit).await {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!(error = %e, "approval step-timeout sweep: list_due_step_timeouts failed");
            Vec::new()
        }
    };
    if reminders.is_empty() && due.is_empty() {
        return;
    }
    let loaded = default_calendar(state).await;
    let calendar = loaded.as_ref().map(|c| &c.calendar);

    for request in reminders {
        remind(state, request, now, calendar).await;
    }

    let due_at = |request: &ApprovalRequest,
                  step: &ApprovalStep,
                  started: DateTime<Utc>,
                  minutes: i64|
     -> Option<DateTime<Utc>> {
        due_or_skip(request, step, started, minutes, calendar)
    };
    for request_id in due {
        match attome_audit::approval::apply_and_audit_step_timeout_due(
            state,
            request_id,
            &EnqueueAutoApprovedExecution,
            &due_at,
        )
        .await
        {
            Ok(Some((request, attome_approval::TimeoutOutcome::Escalated, notify_ids))) => {
                for user_id in notify_ids {
                    notify(
                        state,
                        &request,
                        user_id,
                        format!(
                            "Approval reminder: {} is waiting on you",
                            request.action_type
                        ),
                        format!(
                            "Approval request {} (step {}) has passed its SLA and needs a \
                             decision.",
                            request.id, request.step
                        ),
                    )
                    .await;
                }
            }
            Ok(Some((request, attome_approval::TimeoutOutcome::Expired, _notify_ids))) => {
                // BAP-6b: the request was already past its backstop, so the
                // timeout expired it instead of deciding it (BAP-6a). The
                // expiry's audit event was written in the timeout's own
                // transaction; there is nobody to notify.
                tracing::info!(
                    request_id = %request.id,
                    action_type = %request.action_type,
                    "approval step-timeout sweep: request expired past its backstop",
                );
            }
            Ok(Some((_request, _outcome, _notify_ids))) => {
                // AutoApproved/AutoRejected: the audit event (and, for an
                // approval, its execution job) committed with the decision.
            }
            Ok(None) => {
                // Raced (a human decided it first, another node already
                // handled it, etc.) or not due yet in business time —
                // nothing to do this tick.
            }
            Err(e) => {
                tracing::error!(
                    %request_id,
                    error = %e,
                    "approval step-timeout sweep: apply_and_audit_step_timeout failed",
                );
            }
        }
    }
}

/// Z10-T8: the deployment's default calendar, or `None` (no default, or it
/// does not resolve); a business-hours step then waits (D-517).
async fn default_calendar(state: &EngineState) -> Option<attome_core::calendar::LoadedCalendar> {
    let db = &state.base.db;
    let id = match attome_core::calendar::default_calendar_id(db).await {
        Ok(Some(id)) => id,
        Ok(None) => return None,
        Err(e) => {
            tracing::error!(error = %e, "approval sweep: default calendar lookup failed");
            return None;
        }
    };
    match attome_core::calendar::load_calendar(db, id).await {
        Ok(Ok(loaded)) => Some(loaded),
        Ok(Err(unresolved)) => {
            tracing::warn!(calendar_id = %id, %unresolved, "approval sweep: default calendar does not resolve");
            None
        }
        Err(e) => {
            tracing::error!(calendar_id = %id, error = %e, "approval sweep: default calendar failed to load");
            None
        }
    }
}

/// Z10-T8: the step's due time, or `None` to skip the request this tick.
/// A business-hours step with no calendar is skipped with a warning and a
/// count, never timed on the wall clock (D-517).
fn due_or_skip(
    request: &ApprovalRequest,
    step: &ApprovalStep,
    started: DateTime<Utc>,
    minutes: i64,
    calendar: Option<&attome_calendar::BusinessCalendar>,
) -> Option<DateTime<Utc>> {
    match attome_audit::approval::step_due_at(step, started, minutes, calendar) {
        Ok(at) => Some(at),
        Err(StepDueError::CalendarUnresolved) => {
            tracing::warn!(
                request_id = %request.id,
                "approval sweep: business-hours step skipped, no business calendar is resolved",
            );
            metrics::counter!("approval_calendar_unresolved_total").increment(1);
            None
        }
        Err(error) => {
            tracing::warn!(request_id = %request.id, %error, "approval sweep: step due time unknown, skipped");
            None
        }
    }
}

/// Z10-T8: one step's reminder: once its `reminder_minutes` have passed (in
/// business time when the step says so), mark it reminded (resolving its
/// `escalate_to`, who may then decide), then — after that commit, never
/// under the request lock — notify the step's approvers and the escalation
/// target. `reminded_at` gates it, so it is sent once per step.
async fn remind(
    state: &EngineState,
    request: ApprovalRequest,
    now: DateTime<Utc>,
    calendar: Option<&attome_calendar::BusinessCalendar>,
) {
    let Some(plan) = request.plan.as_ref() else {
        return;
    };
    let Some(step) = usize::try_from(request.step)
        .ok()
        .and_then(|i| plan.steps.get(i))
    else {
        return;
    };
    let (Some(minutes), Some(started)) = (step.extras.reminder_minutes, request.step_started_at)
    else {
        return;
    };
    match due_or_skip(&request, step, started, minutes, calendar) {
        Some(at) if now >= at => {}
        _ => return,
    }
    let escalated_to = match step.extras.escalate_to.as_deref() {
        Some(token) => {
            match attome_audit::approval::resolve_escalation_target(state, &request, token).await {
                Ok(user) => user,
                Err(e) => {
                    tracing::warn!(request_id = %request.id, error = %e, "approval reminder: escalation target unresolved");
                    None
                }
            }
        }
        None => None,
    };
    let marked = match attome_audit::approval::mark_reminded_and_audit(
        state,
        &request,
        escalated_to,
    )
    .await
    {
        Ok(Some(marked)) => marked,
        Ok(None) => return,
        Err(e) => {
            tracing::error!(request_id = %request.id, error = %e, "approval reminder: not recorded");
            return;
        }
    };
    let recipients = match attome_audit::approval::resolve_step_approvers(state, step, &marked)
        .await
    {
        Ok((_population, _principals, allowed, _delegate_of)) => allowed,
        Err(e) => {
            tracing::error!(request_id = %marked.id, error = %e, "approval reminder: approvers unresolved");
            return;
        }
    };
    for user_id in recipients {
        let (subject, body) = if Some(user_id) == marked.escalated_to {
            (
                format!("Approval escalated to you: {}", marked.action_type),
                format!(
                    "Approval request {} (step {}) has been escalated to you; you may decide it.",
                    marked.id, marked.step
                ),
            )
        } else {
            (
                format!(
                    "Approval reminder: {} is waiting on you",
                    marked.action_type
                ),
                format!(
                    "Approval request {} (step {}) is waiting for your decision.",
                    marked.id, marked.step
                ),
            )
        };
        notify(state, &marked, user_id, subject, body).await;
    }
}

/// Queues one high-priority notification about `request` for `user_id`; a
/// failure is logged and the sweep goes on.
async fn notify(
    state: &EngineState,
    request: &ApprovalRequest,
    user_id: uuid::Uuid,
    subject: String,
    body: String,
) {
    let req = DispatchRequest {
        template_key: None,
        locale: "en".to_string(),
        recipient_user_ref: Some(user_id),
        is_global: false,
        organization_ref: None,
        channels: None,
        subject: Some(subject),
        body_html: None,
        body_text: Some(body),
        route: Some(format!("/approvals/{}", request.id)),
        variables: Default::default(),
        priority: "high".to_string(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    if let Err(e) =
        dispatch::create_dispatch(&state.base.db, &state.base.config.notification, req).await
    {
        tracing::error!(
            request_id = %request.id,
            %user_id,
            error = %e,
            "approval sweep: notification failed to enqueue",
        );
    }
}
