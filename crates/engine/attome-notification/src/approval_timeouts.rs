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

use attome_approval::{ApprovalRequest, TimeoutOutcome};
use attome_core::EngineState;

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
pub async fn run_due_approval_timeouts(state: &EngineState, limit: i64) {
    let due = match attome_approval::list_due_step_timeouts(&state.base.db, limit).await {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!(error = %e, "approval step-timeout sweep: list_due_step_timeouts failed");
            return;
        }
    };

    for request_id in due {
        match attome_audit::approval::apply_and_audit_step_timeout_with(
            state,
            request_id,
            &EnqueueAutoApprovedExecution,
        )
        .await
        {
            Ok(Some((request, attome_approval::TimeoutOutcome::Escalated, notify_ids))) => {
                for user_id in notify_ids {
                    let req = DispatchRequest {
                        template_key: None,
                        locale: "en".to_string(),
                        recipient_user_ref: Some(user_id),
                        is_global: false,
                        organization_ref: None,
                        channels: None,
                        subject: Some(format!(
                            "Approval reminder: {} is waiting on you",
                            request.action_type
                        )),
                        body_html: None,
                        body_text: Some(format!(
                            "Approval request {} (step {}) has passed its SLA and needs a \
                             decision.",
                            request.id, request.step
                        )),
                        route: Some(format!("/approvals/{}", request.id)),
                        variables: Default::default(),
                        priority: "high".to_string(),
                        escalate_after_minutes: None,
                        escalate_channels: None,
                    };
                    if let Err(e) = dispatch::create_dispatch(
                        &state.base.db,
                        &state.base.config.notification,
                        req,
                    )
                    .await
                    {
                        tracing::error!(
                            request_id = %request.id,
                            %user_id,
                            error = %e,
                            "approval step-timeout sweep: escalation notification failed to enqueue",
                        );
                    }
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
                // handled it, etc.) — not due after all, nothing to do.
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
