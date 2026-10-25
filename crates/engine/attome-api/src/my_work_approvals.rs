//! Dashboard 10/10 Phase 6 — the Approvals [`MyWorkProvider`]. Lives in
//! `attome-api`, not `attome-audit`, because it needs both
//! `attome_audit::approval::resolve_step_approvers` (eligibility, including
//! delegation) and `attome_records::entity_crud`'s
//! `resolve_entity`/`require_record_access` (the "source record readable"
//! half of the visibility rule) — `attome-audit` does not depend on
//! `attome-records` (layer direction, guidelines §1), so only the
//! composition layer can join both. Same posture `approval_admin.rs`'s own
//! module doc already states for the dispatch side of approvals.
//!
//! Only plan-bearing requests are eligible for a non-admin's My Work list —
//! a flat request has no eligible-approver concept other than
//! `system.admin` (D-551), so it never appears here; an admin still finds it
//! through `GET /api/v1/admin/approvals`, unaffected by this provider.

use attome_core::{
    EngineState, MyWorkAction, MyWorkFuture, MyWorkItem, MyWorkPage, MyWorkProvider,
};
use attome_records::entity_crud::{require_record_access, resolve_entity};
use attome_security::RecordAction;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use uuid::Uuid;

/// Same bounded-scan posture `attome-workflow::sla_sweep` already uses for a
/// comparable cross-cutting concern: this is a read model over "what's
/// pending right now", not a paginated report — a deployment with more than
/// this many simultaneously pending, plan-bearing approvals needs its own
/// dedicated capacity conversation, not a silently-unbounded scan here.
const SCAN_LIMIT: i64 = 500;

#[derive(Debug)]
pub struct ApprovalsMyWorkProvider;

impl MyWorkProvider for ApprovalsMyWorkProvider {
    fn name(&self) -> &'static str {
        "approvals"
    }

    fn count<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
    ) -> MyWorkFuture<'a, usize> {
        Box::pin(async move { Ok(eligible_pending_requests(state, ctx).await?.len()) })
    }

    fn list<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
        cursor: Option<&'a str>,
        limit: usize,
    ) -> MyWorkFuture<'a, MyWorkPage> {
        Box::pin(async move {
            let requests = eligible_pending_requests(state, ctx).await?;
            let offset: usize = cursor.and_then(|c| c.parse().ok()).unwrap_or(0);
            let items = requests
                .iter()
                .skip(offset)
                .take(limit)
                .map(to_my_work_item)
                .collect::<Vec<_>>();
            let next_cursor =
                (offset + items.len() < requests.len()).then(|| (offset + items.len()).to_string());
            Ok(MyWorkPage::new(items, next_cursor))
        })
    }

    fn actions<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
        record_id: Uuid,
    ) -> MyWorkFuture<'a, Vec<MyWorkAction>> {
        Box::pin(async move {
            let Ok(request) = attome_approval::get(&state.base.db, record_id).await else {
                return Ok(vec![]);
            };
            if request.status != attome_approval::ApprovalStatus::Pending {
                return Ok(vec![]);
            }
            if !is_eligible(state, ctx, &request).await? {
                return Ok(vec![]);
            }
            Ok(decide_actions(request.id))
        })
    }
}

/// `pub(crate)`: `my_work_workflow.rs` reuses this to build the same
/// approve/reject action pair for a workflow instance blocked on the same
/// underlying `approval_request` — one source of truth for what
/// deciding an approval request looks like as a `MyWorkAction`.
pub(crate) fn decide_actions(request_id: Uuid) -> Vec<MyWorkAction> {
    let route = format!("/api/v1/approvals/{request_id}/decide");
    vec![
        MyWorkAction {
            key: "approve".to_string(),
            method: "POST".to_string(),
            route: route.clone(),
        },
        MyWorkAction {
            key: "reject".to_string(),
            method: "POST".to_string(),
            route,
        },
    ]
}

/// The trait's visibility rule (module doc), applied to one already-fetched
/// request: eligible-decider membership (via `resolve_step_approvers`,
/// delegation included) and, when the request names one, a readable
/// "regarding" record. A request with no `plan` (flat/admin-only) or no
/// `regarding_entity` populated (every caller today — D-551's own follow-up
/// note) skips the corresponding half of the check rather than failing it.
///
/// `pub(crate)`: `my_work_workflow.rs` reuses this verbatim for a workflow
/// instance blocked on the very same request row — the eligibility question
/// ("can this caller decide this request") does not change depending on
/// which provider is asking it.
pub(crate) async fn is_eligible(
    state: &EngineState,
    ctx: &SecurityContext,
    request: &attome_approval::ApprovalRequest,
) -> Result<bool, AppError> {
    if request.requested_by == ctx.user_id {
        return Ok(false);
    }
    let Some(plan) = &request.plan else {
        return Ok(false);
    };
    let Ok(step_index) = usize::try_from(request.step) else {
        return Ok(false);
    };
    let Some(step) = plan.steps.get(step_index) else {
        return Ok(false);
    };
    let (_, _, allowed, _) =
        attome_audit::approval::resolve_step_approvers(state, step, request).await?;
    if !allowed.contains(&ctx.user_id) {
        return Ok(false);
    }
    if let (Some(entity), Some(record_id)) = (&request.regarding_entity, request.regarding_id) {
        let Ok((entity_id, ..)) = resolve_entity(state, entity).await else {
            return Ok(false);
        };
        if require_record_access(state, ctx, entity_id, entity, record_id, RecordAction::Read)
            .await
            .is_err()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Every pending, plan-bearing request the caller is currently eligible to
/// decide — `list`/`count` share this so they can never disagree (the
/// trait's own `count` doc comment).
async fn eligible_pending_requests(
    state: &EngineState,
    ctx: &SecurityContext,
) -> Result<Vec<attome_approval::ApprovalRequest>, AppError> {
    let (requests, _total) =
        attome_approval::list_pending(&state.base.db, None, 1, SCAN_LIMIT).await?;
    let mut eligible = Vec::new();
    for request in requests {
        if is_eligible(state, ctx, &request).await? {
            eligible.push(request);
        }
    }
    Ok(eligible)
}

/// The current step's SLA deadline, when the plan names one — `pub(crate)`
/// for the same reuse reason as `is_eligible`/`decide_actions`.
pub(crate) fn approval_due_date(
    request: &attome_approval::ApprovalRequest,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let plan = request.plan.as_ref()?;
    let step_index = usize::try_from(request.step).ok()?;
    let step = plan.steps.get(step_index)?;
    let sla_minutes = step.sla_minutes?;
    let started_at = request.step_started_at?;
    Some(started_at + chrono::Duration::minutes(sla_minutes))
}

fn to_my_work_item(request: &attome_approval::ApprovalRequest) -> MyWorkItem {
    let due_date = approval_due_date(request);
    MyWorkItem {
        provider: "approvals".to_string(),
        source_entity: "approval_request".to_string(),
        record_id: request.id,
        title: format!("Approve: {}", request.action_type),
        due_date,
        priority: None,
        state: request.status.to_string(),
        actions: decide_actions(request.id),
        row_version: Some(request.row_version),
    }
}
