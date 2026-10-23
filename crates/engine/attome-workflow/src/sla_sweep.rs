//! Periodic sweep (P-workflow-engine.md §4.3/§5 step 7): resumes
//! `schedule`-type waits past their `resume_at`, and — since
//! `attome_approval` has no push/callback mechanism of its own (it's a purely
//! polling primitive, confirmed against its own module doc comment) —
//! also polls `signal`-type `approval` waits for a terminal decision. Both
//! share one indexed scan and one dedup-keyed periodic job
//! (`EngineJob::WorkflowSlaSweep`) rather than two separate schedulers,
//! since both are "check `workflow_trigger_index` for a wait row whose
//! resolution condition has become true."

use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

const SWEEP_BATCH_SIZE: i64 = 500;

#[derive(sqlx::FromRow)]
struct ScheduleWait {
    node_run_id: Uuid,
    instance_id: Uuid,
    node_id: String,
    condition: Option<serde_json::Value>,
}

#[derive(sqlx::FromRow)]
struct SignalWait {
    node_run_id: Uuid,
    instance_id: Uuid,
    node_id: String,
    condition: serde_json::Value,
}

/// Returns the number of wait rows resumed.
pub async fn sweep(state: &EngineState) -> Result<u64, AppError> {
    let mut resumed = 0u64;

    let due: Vec<ScheduleWait> = sqlx::query_as::<_, ScheduleWait>(
        "SELECT node_run_id, instance_id, node_id, condition FROM workflow_trigger_index \
         WHERE role = 'wait' AND match_type = 'schedule' AND resume_at < NOW() \
           AND node_run_id IS NOT NULL \
         LIMIT $1",
    )
    .bind(SWEEP_BATCH_SIZE)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    for wait in due {
        let is_retry = wait
            .condition
            .as_ref()
            .and_then(|c| c.get("kind"))
            .and_then(serde_json::Value::as_str)
            == Some("retry");
        if is_retry {
            // F095 backoff — re-execute the node, not a cached replay.
            crate::scheduler::resume_retry(state, wait.instance_id, wait.node_run_id).await?;
        } else {
            crate::scheduler::resume_node(
                state,
                wait.instance_id,
                &wait.node_id,
                wait.node_run_id,
                serde_json::Value::Null,
            )
            .await?;
        }
        resumed += 1;
    }

    // M10-T3: an event wait whose `timeout_seconds` passed resumes with
    // `timed_out` and takes its `timeout` port.
    let timed_out: Vec<ScheduleWait> = sqlx::query_as::<_, ScheduleWait>(
        "SELECT node_run_id, instance_id, node_id, condition FROM workflow_trigger_index \
         WHERE role = 'wait' AND match_type = 'entity_event' AND resume_at < NOW() \
           AND node_run_id IS NOT NULL \
         LIMIT $1",
    )
    .bind(SWEEP_BATCH_SIZE)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for wait in timed_out {
        crate::scheduler::resume_node(
            state,
            wait.instance_id,
            &wait.node_id,
            wait.node_run_id,
            serde_json::json!({ "timed_out": true }),
        )
        .await?;
        resumed += 1;
    }

    let pending_approvals: Vec<SignalWait> = sqlx::query_as::<_, SignalWait>(
        "SELECT node_run_id, instance_id, node_id, condition FROM workflow_trigger_index \
         WHERE role = 'wait' AND match_type = 'signal' \
           AND condition ->> 'kind' = 'approval' AND node_run_id IS NOT NULL \
         LIMIT $1",
    )
    .bind(SWEEP_BATCH_SIZE)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    for wait in pending_approvals {
        let Some(request_id) = wait
            .condition
            .get("approval_request_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        else {
            continue;
        };
        let request = match attome_approval::get(&state.base.db, request_id).await {
            Ok(r) => r,
            Err(AppError::NotFound) => continue,
            Err(e) => return Err(e),
        };
        let decision = match request.status {
            attome_approval::ApprovalStatus::Approved => Some("approved"),
            attome_approval::ApprovalStatus::Rejected => Some("rejected"),
            attome_approval::ApprovalStatus::Expired => Some("expired"),
            attome_approval::ApprovalStatus::Cancelled => Some("cancelled"),
            // Z10-T4: a recalled request is withdrawn like a cancelled one.
            attome_approval::ApprovalStatus::Recalled => Some("cancelled"),
            // Approved, then refused at execution time because the
            // requester's authorization changed. Terminal: the approved path
            // must not run. `approval_taken_port` routes it to `rejected`.
            attome_approval::ApprovalStatus::Invalidated => Some("invalidated"),
            // `Executing` (D-518) is only ever set by `attome-api`'s admin
            // execution path, for an action type it has a handler for; a
            // workflow approval's request is never claimed. Grouped with the
            // other states that carry no decision for this node.
            attome_approval::ApprovalStatus::Pending
            | attome_approval::ApprovalStatus::Executing
            | attome_approval::ApprovalStatus::Executed => None,
        };
        let Some(decision) = decision else { continue };

        crate::scheduler::resume_node(
            state,
            wait.instance_id,
            &wait.node_id,
            wait.node_run_id,
            serde_json::json!({ "decision": decision, "approval_request_id": request_id }),
        )
        .await?;
        resumed += 1;
    }

    Ok(resumed)
}
