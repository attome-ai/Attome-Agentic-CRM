//! Dashboard 10/10 Phase 6 — the Workflow `MyWorkProvider`. Covers only the
//! plan's "waiting approval nodes (through Approvals)" row — a workflow
//! instance blocked on an `Approval` node reuses the exact same eligibility
//! and action-route logic `my_work_approvals.rs` already has, just framed
//! as "this workflow needs you" instead of "this request needs you".
//!
//! Deliberately does **not** cover the plan's `wait_for_event` case. Two
//! independent reasons, both confirmed against the engine, not assumed:
//! - There is no user-facing resume action for it at all today —
//!   `scheduler::resume_node`'s own doc comment calls a signal endpoint for
//!   `WaitForEvent` a *future* addition; only an incoming entity-change
//!   event or the SLA sweep's schedule scan can resume one.
//! - `workflow_instance` is not registered as a `require_record_access`-
//!   checkable entity anywhere today (`instance_admin.rs`'s routes are
//!   `Authorized<Admin>` only, not per-record). Inventing a visibility rule
//!   for it here (e.g. "started_by == caller") would be this provider
//!   deciding workflow's own access model, not reusing an established one —
//!   exactly what the trait's module doc warns against.
//! A future pass can add it once either gap is closed; until then an
//! event-wait is informational-only with no safe way to gate who sees it,
//! so it's left out rather than guessed at.
//!
//! Lives in `attome-api`: needs the same `attome_audit::approval` +
//! `attome_records::entity_crud` combination `my_work_approvals.rs` does
//! (via its reused `is_eligible`), which `attome-workflow` cannot depend on
//! (layer direction, guidelines §1).

use attome_core::{
    EngineState, MyWorkAction, MyWorkFuture, MyWorkItem, MyWorkPage, MyWorkProvider,
};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::my_work_approvals::{approval_due_date, decide_actions, is_eligible};

/// Same bounded-scan posture as `my_work_approvals::SCAN_LIMIT`.
const SCAN_LIMIT: i64 = 500;
const ENTITY: &str = "workflow_instance";

#[derive(Debug)]
pub struct WorkflowMyWorkProvider;

#[derive(Debug, sqlx::FromRow)]
struct WaitingApprovalRow {
    node_run_id: Uuid,
    definition_name: String,
    approval_request_id: Option<Uuid>,
}

impl MyWorkProvider for WorkflowMyWorkProvider {
    fn name(&self) -> &'static str {
        "workflow"
    }

    fn count<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
    ) -> MyWorkFuture<'a, usize> {
        Box::pin(async move { Ok(eligible_waiting_instances(state, ctx).await?.len()) })
    }

    fn list<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
        cursor: Option<&'a str>,
        limit: usize,
    ) -> MyWorkFuture<'a, MyWorkPage> {
        Box::pin(async move {
            let waits = eligible_waiting_instances(state, ctx).await?;
            let offset: usize = cursor.and_then(|c| c.parse().ok()).unwrap_or(0);
            let items = waits
                .iter()
                .skip(offset)
                .take(limit)
                .map(|(row, request)| to_my_work_item(row, request))
                .collect::<Vec<_>>();
            let next_cursor =
                (offset + items.len() < waits.len()).then(|| (offset + items.len()).to_string());
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
            let Some(row) = fetch_waiting_row(state, record_id).await? else {
                return Ok(vec![]);
            };
            let Some(request_id) = row.approval_request_id else {
                return Ok(vec![]);
            };
            let Ok(request) = attome_approval::get(&state.base.db, request_id).await else {
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

/// Every `workflow_trigger_index` "waiting on approval" row, keyed by
/// `node_run_id`, joined to the approval request it names and filtered to
/// requests the caller is currently eligible to decide — the exact same
/// eligibility `my_work_approvals.rs` computes for its own list, applied
/// here to the workflow-instance framing of the same underlying request.
async fn eligible_waiting_instances(
    state: &EngineState,
    ctx: &SecurityContext,
) -> Result<Vec<(WaitingApprovalRow, attome_approval::ApprovalRequest)>, AppError> {
    let rows = waiting_approval_rows(state).await?;
    let mut eligible = Vec::new();
    for row in rows {
        let Some(request_id) = row.approval_request_id else {
            continue;
        };
        let Ok(request) = attome_approval::get(&state.base.db, request_id).await else {
            continue;
        };
        if request.status != attome_approval::ApprovalStatus::Pending {
            continue;
        }
        if is_eligible(state, ctx, &request).await? {
            eligible.push((row, request));
        }
    }
    Ok(eligible)
}

async fn waiting_approval_rows(state: &EngineState) -> Result<Vec<WaitingApprovalRow>, AppError> {
    sqlx::query_as(
        "SELECT ti.node_run_id AS node_run_id, \
                wd.name AS definition_name, \
                NULLIF(ti.condition ->> 'approval_request_id', '')::uuid AS approval_request_id \
         FROM workflow_trigger_index ti \
         JOIN workflow_instance wi ON wi.id = ti.instance_id \
         JOIN workflow_definition_version wdv ON wdv.id = wi.definition_version_id \
         JOIN workflow_definition wd ON wd.id = wdv.definition_id \
         WHERE ti.role = 'wait' \
           AND ti.match_type = 'signal' \
           AND ti.condition ->> 'kind' = 'approval' \
           AND wi.status = 'waiting' \
           AND ti.node_run_id IS NOT NULL \
         ORDER BY ti.created_at ASC \
         LIMIT $1",
    )
    .bind(SCAN_LIMIT)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Re-fetched fresh for `actions()` — never trusts a `list()` snapshot,
/// same posture as `my_work_approvals`/`my_work_service`.
async fn fetch_waiting_row(
    state: &EngineState,
    node_run_id: Uuid,
) -> Result<Option<WaitingApprovalRow>, AppError> {
    sqlx::query_as(
        "SELECT ti.node_run_id AS node_run_id, \
                wd.name AS definition_name, \
                NULLIF(ti.condition ->> 'approval_request_id', '')::uuid AS approval_request_id \
         FROM workflow_trigger_index ti \
         JOIN workflow_instance wi ON wi.id = ti.instance_id \
         JOIN workflow_definition_version wdv ON wdv.id = wi.definition_version_id \
         JOIN workflow_definition wd ON wd.id = wdv.definition_id \
         WHERE ti.role = 'wait' \
           AND ti.match_type = 'signal' \
           AND ti.condition ->> 'kind' = 'approval' \
           AND wi.status = 'waiting' \
           AND ti.node_run_id = $1",
    )
    .bind(node_run_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

fn to_my_work_item(
    row: &WaitingApprovalRow,
    request: &attome_approval::ApprovalRequest,
) -> MyWorkItem {
    let due_date: Option<DateTime<Utc>> = approval_due_date(request);
    MyWorkItem {
        provider: "workflow".to_string(),
        source_entity: ENTITY.to_string(),
        record_id: row.node_run_id,
        title: format!("{}: waiting on approval", row.definition_name),
        due_date,
        priority: None,
        state: "waiting".to_string(),
        actions: decide_actions(request.id),
        row_version: Some(request.row_version),
    }
}
