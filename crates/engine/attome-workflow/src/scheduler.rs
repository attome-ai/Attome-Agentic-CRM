//! Execution engine core (P-workflow-engine.md §4.4/§5 step 5) — the
//! run-to-checkpoint scheduler. One `EngineJob::WorkflowExecute` job
//! drives an instance in-memory through as many nodes as are ready, back to
//! back, with no database write between them; the engine only persists at
//! an actual checkpoint (a wait-capable node reached, or a terminal state).
//!
//! **Scope simplifications, documented rather than silently assumed:**
//! - Node input resolution is "whichever upstream node's whole output feeds
//!   this port" (a fan-in port takes every non-skipped source, merged into
//!   an array if more than one), not a full expression/templating language.
//!   A join is therefore any node with more than one inbound edge on the
//!   same port name — the v1 node set has no dedicated `Join` type.
//! - Retry (F095) is bounded, immediate, in-pass — no real backoff delay,
//!   since this runs inside one apalis job attempt and guidelines §10
//!   forbids sleeping a runtime thread. `attempt_count`/`last_error` are
//!   still real and correctly observable.
//! - A node exhausting retries fails the whole instance at the next
//!   checkpoint rather than letting independent sibling branches keep
//!   running — a safe, simple containment, not the full "fail only the
//!   affected branch" behavior a future iteration could add.

use std::collections::{HashMap, HashSet};

use attome_audit::{
    Attribution, AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource,
    AuditUserContext, Initiator,
};
use attome_core::EngineState;
use attome_records::mutation_ring::{
    GrantInvalidation, MutationActor, MutationAudit, MutationRing, MutationSideEffects,
};
use attome_security::SecurityContextExt;
use attome_server::middleware::idempotency_durable;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::graph::{Graph, GraphNode};
use crate::model::{InstanceRow, NodeRunRow, NodeRunState};
use crate::node_types::{NodeType, ON_ERROR_PORT};
use crate::trigger_index;

const MAX_PASS_ITERATIONS: usize = 2000;

/// M3-T1: the largest serialized input/output pair a node-run row holds
/// inline; a larger one is written to object storage and the row keeps its
/// key (`payload_ref`).
pub const INLINE_PAYLOAD_MAX: usize = 64 * 1024;

/// Invariant behind the `node_runs.get_mut(&node_id)` lookups in the execute
/// pass: every one of them is preceded, in the same loop iteration, by a
/// `node_runs.entry(node_id.clone()).or_insert_with(..)` that guarantees the
/// key is present. They were bare `.unwrap()`s — sound, but indistinguishable
/// on review from an unchecked one, and a panic here kills an apalis worker
/// task rather than returning an error. Kept as `expect` (not converted to a
/// `continue`) on purpose: each call site goes on to write `node_data` and/or
/// push a `PendingWait`, so skipping the body would leave the node
/// permanently un-advanced and spin the pass until `MAX_PASS_ITERATIONS`
/// fails the whole instance — a worse, quieter failure than an attributable
/// panic.
const NODE_RUN_ENTRY_INVARIANT: &str =
    "node_runs entry was inserted by the or_insert_with earlier in this iteration";

fn system_security_context(user_id: Uuid) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin: true,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        service_principal: false,
    }
}

/// M1-T3: who a flow's nodes act as. The graph's `settings.run_as` is
/// `starter` (the default: the user who started the run) or
/// `flow_identity` (`settings.run_as_user_id`, a service account holding the
/// roles the flow needs). A run with no human starter (an entity or
/// schedule trigger) acts as the user who published the version. The
/// context is the identity's own, resolved fresh, so a flow can do nothing
/// its run-as identity may not. Only a run with no starter and no publisher
/// (versions published before publishers were recorded) keeps the old
/// administrator context.
async fn run_as_context(
    state: &EngineState,
    instance: &InstanceRow,
    graph_json: &Value,
) -> Result<SecurityContext, AppError> {
    let settings = graph_json.get("settings");
    let mode = settings
        .and_then(|s| s.get("run_as"))
        .and_then(Value::as_str)
        .unwrap_or("starter");
    let user_id = match mode {
        "flow_identity" => settings
            .and_then(|s| s.get("run_as_user_id"))
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| {
                AppError::Validation(
                    "a flow that runs as its own identity needs settings.run_as_user_id".into(),
                )
            })?,
        "starter" => {
            let human = instance
                .started_by
                .filter(|id| *id != crate::entity_trigger::workflow_system_user_id());
            match human {
                Some(id) => id,
                None => {
                    let publisher: Option<Uuid> = sqlx::query_scalar(
                        "SELECT published_by FROM workflow_definition_version WHERE id = $1",
                    )
                    .bind(instance.definition_version_id)
                    .fetch_optional(&state.base.db)
                    .await
                    .map_err(AppError::internal)?
                    .flatten();
                    match publisher {
                        Some(id) => id,
                        None => {
                            return Ok(system_security_context(
                                instance.started_by.unwrap_or(Uuid::nil()),
                            ));
                        }
                    }
                }
            }
        }
        other => {
            return Err(AppError::Validation(format!(
                "settings.run_as {other:?} is not `starter` or `flow_identity`"
            )));
        }
    };
    let active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if active != Some(true) {
        tracing::warn!(
            instance_id = %instance.id,
            %user_id,
            "workflow run-as identity is missing or inactive; the flow cannot act"
        );
        return Err(AppError::Forbidden);
    }
    attome_security::resolve_uncached(&state.base.db, user_id).await
}

/// A wait-capable node reached during a pass — collected until the
/// checkpoint write, which is the only place a `trigger_index` wait row can
/// be inserted (it needs the node_run's freshly-assigned id).
struct PendingWait {
    node_id: String,
    match_type: &'static str,
    entity_logicalname: Option<String>,
    condition: Option<Value>,
    resume_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
enum NodeOutcome {
    Succeeded {
        output: Value,
    },
    /// Only `Condition`/`Approval` (the branching types) produce this.
    Branch {
        taken_port: &'static str,
        output: Value,
    },
    Waiting {
        match_type: &'static str,
        entity_logicalname: Option<String>,
        condition: Option<Value>,
        resume_at: Option<DateTime<Utc>>,
        /// The value this node will emit once it resumes — recorded now so
        /// a resume path (sla_sweep, signal) only has to flip status.
        eventual_output: Value,
    },
    /// E8-T2: a module step ended the instance (`StepOutcome::Exit`).
    Exit {
        reason: String,
    },
}

/// Drives `instance_id` in-memory until a checkpoint, then persists it in
/// one transaction. Safe to call for an already-terminal instance (no-op)
/// and for one still parked on a `waiting` node (re-checkpoints it as
/// `waiting`) — apalis at-least-once delivery means this can be invoked
/// more than once for the same logical checkpoint.
///
/// The `waiting` half of that promise was not kept until F-016 was
/// confirmed against a hermetic database (2026-08-10): re-entry on a parked
/// instance fell through to the "fixpoint with unresolved nodes" branch and
/// marked it `failed`, so one duplicate job delivery permanently killed a
/// workflow that was correctly waiting on an approval or an event. See
/// `tests/execution.rs::self_approval_is_forbidden_and_the_instance_stays_waiting`.
///
/// Two deliveries overlapping *in time* are a different promise, kept by
/// [`ExecutionClaim`] (3.14): the second delivery skips, so no node is ever
/// executed by two passes at once. See the claim's doc comment for what a
/// skipped delivery relies on to not strand work.
pub async fn execute_instance(state: &EngineState, instance_id: Uuid) -> Result<(), AppError> {
    let Some(claim) = ExecutionClaim::try_acquire(state, instance_id).await? else {
        tracing::info!(
            %instance_id,
            "workflow execute: another pass holds this instance's execution claim, skipping this delivery"
        );
        return Ok(());
    };
    // L7-T2: every change event this pass writes names the run, so a
    // subscriber can tell the flow's own update from a person's.
    let provenance = attome_core::provenance_scope::Provenance {
        channel: attome_core::provenance_scope::FLOW_CHANNEL,
        run_id: Some(instance_id),
    };
    let result =
        attome_core::provenance_scope::scope(provenance, execute_claimed(state, instance_id)).await;
    claim.release().await;
    if matches!(result, Ok(PassOutcome::CheckpointDiscarded)) {
        // Only after the claim is released: a delivery enqueued while we still
        // held it would be skipped by our own claim, which is the exact
        // stranding this re-enqueue exists to prevent.
        requeue_if_live(state, instance_id).await?;
    }
    result.map(|_| ())
}

/// What a claimed pass did, for [`execute_instance`] to act on once the claim
/// is released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassOutcome {
    /// Instance missing or already terminal — nothing to do.
    NoOp,
    /// The checkpoint committed (and any parent resume ran).
    Committed,
    /// The checkpoint lost its `row_version` CAS to a concurrent transition
    /// and was rolled back; the caller decides whether a fresh pass is owed.
    CheckpointDiscarded,
}

/// The pass proper, run under an [`ExecutionClaim`]. Split from
/// [`execute_instance`] so the claim is released on every exit path — `?`
/// included — and before any follow-up enqueue.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
async fn execute_claimed(state: &EngineState, instance_id: Uuid) -> Result<PassOutcome, AppError> {
    let Some(mut instance) = load_instance(&state.base.db, instance_id).await? else {
        tracing::warn!(%instance_id, "workflow execute: instance not found, dropping job");
        return Ok(PassOutcome::NoOp);
    };
    // `queued` (M1-T5) waits for `promote_queued` to make it `running`;
    // `paused` (M3-T3) waits for a resume.
    if matches!(
        instance.status.as_str(),
        "queued" | "paused" | "completed" | "failed" | "cancelled"
    ) {
        return Ok(PassOutcome::NoOp);
    }

    let graph_json: Value =
        sqlx::query_scalar("SELECT graph FROM workflow_definition_version WHERE id = $1")
            .bind(instance.definition_version_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let graph = Graph::parse(&graph_json).map_err(AppError::internal)?;

    let mut node_runs = load_node_runs(&state.base.db, instance_id).await?;
    let mut node_data: serde_json::Map<String, Value> =
        instance.node_data.as_object().cloned().unwrap_or_default();
    let mut fired: HashSet<String> = instance
        .fired_side_effects
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    // Approval resolves asynchronously (a sweep flips it to `succeeded`
    // outside any pass — see `resume_node`/`sla_sweep`), so — unlike
    // `Condition`, which branches synchronously inside the pass loop below —
    // its untaken-port skip propagation has to run here, once per load,
    // idempotently (`mark_untaken_branch` no-ops on already-settled nodes,
    // so re-running this for a node resolved in an earlier call is safe).
    for node in &graph.nodes {
        if NodeType::parse(&node.node_type) != Some(NodeType::Approval) {
            continue;
        }
        let Some(nr) = node_runs.get(&node.id) else {
            continue;
        };
        if nr.status != "succeeded" {
            continue;
        }
        let Some(decision) = node_data
            .get(&node.id)
            .and_then(|v| v.get("decision"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        if let Some(taken_port) = approval_taken_port(decision) {
            mark_untaken_branch(&graph, &node.id, taken_port, &mut node_runs);
        }
    }
    // M10-T3: a resumed `wait_for_event` took `event` or `timeout`, the same
    // asynchronous branch as an approval's.
    for node in &graph.nodes {
        if NodeType::parse(&node.node_type) != Some(NodeType::WaitForEvent)
            || node_runs.get(&node.id).map(|nr| nr.status.as_str()) != Some("succeeded")
        {
            continue;
        }
        let taken_port = wait_for_event_taken_port(node_data.get(&node.id));
        mark_untaken_branch(&graph, &node.id, taken_port, &mut node_runs);
    }
    // A16-T5: an `update_record` node that waited on an `ask_person`
    // conflict approval has not written yet. Once the request settles it runs
    // again: approved, it applies its changes over the record as it is then;
    // otherwise it fails (`update_by_rule` reads the decision).
    for node in &graph.nodes {
        if NodeType::parse(&node.node_type) != Some(NodeType::UpdateRecord) {
            continue;
        }
        let resumed = node_runs.get(&node.id).map(|nr| nr.status.as_str()) == Some("succeeded")
            && crate::conflict::conflict_decision(node_data.get(&node.id)).is_some();
        if !resumed {
            continue;
        }
        if let Some(entry) = node_runs.get_mut(&node.id) {
            entry.status = "pending".into();
            entry.completed_at = None;
            entry.output = None;
            entry.dirty = true;
        }
        node_data.remove(&node.id);
    }

    // `Arc`, not owned: `execute_route` (M33 Phase 1) needs an owned
    // `Arc<SecurityContext>` to build an `attome_ai::ActionContext` for a
    // real `dispatch` call, and `SecurityContext` deliberately does not
    // derive `Clone` (see its own doc comment). Every existing call site
    // that takes `&SecurityContext` keeps working unchanged — `&Arc<T>`
    // coerces to `&T` at the call site.
    //
    // M1-T3: the nodes act as the flow's run-as identity, resolved fresh from
    // Postgres for every pass, never an administrator context.
    let sys_ctx = std::sync::Arc::new(run_as_context(state, &instance, &graph_json).await?);

    let mut pending_waits: Vec<PendingWait> = Vec::new();
    let mut instance_failed = false;
    // E8-T2: a module step's exit or the kind guard ends the instance.
    let mut instance_cancelled = false;
    let guard = kind_guard(state, instance.definition_version_id).await?;
    let correlation = if guard.is_some() {
        correlation_of(state, instance_id).await?
    } else {
        None
    };
    let mut iterations = 0usize;
    // M1-T4: the run's limits. Steps count every node execution so far,
    // retries included; a run past its time limit fails before its next step.
    let max_steps = run_limit(state, "workflow.max_steps_per_run");
    let mut steps_used: i64 = node_runs
        .values()
        .map(|nr| i64::from(nr.attempt_count))
        .sum();
    let mut limit_exceeded = run_time_exceeded(state, instance_id).await?;

    'pass: loop {
        if limit_exceeded.is_some() {
            instance_failed = true;
            break 'pass;
        }
        iterations += 1;
        if iterations > MAX_PASS_ITERATIONS {
            tracing::error!(%instance_id, "workflow execute: pass exceeded iteration bound, treating as failed");
            instance_failed = true;
            break 'pass;
        }

        let ready = ready_nodes(&graph, &node_runs, &node_data);
        if ready.is_empty() {
            if !propagate_skips(&graph, &node_data, &mut node_runs) {
                break 'pass;
            }
            continue 'pass;
        }

        for node_id in ready {
            let node = graph
                .node(&node_id)
                .expect("ready_nodes only returns real node ids");
            // B20: `graph::validate` rejects an unknown type at publish time,
            // but the stored graph outlives this build's registry (a type
            // removed in a later release, a row edited outside the publish
            // path). `None` is a definition error for THIS instance, routed
            // through the same `Err` arm as any other node failure below —
            // never a panic that takes the apalis worker task with it.
            let node_type = NodeType::parse(&node.node_type);
            let cacheable = node_type.is_some_and(NodeType::is_cacheable);

            if let Some(guard) = &guard
                && let Some(reason) = guard
                    .before_node(state, instance_id, correlation, &node_id)
                    .await?
            {
                node_data.insert("exit_reason".into(), Value::String(reason));
                instance_cancelled = true;
                break 'pass;
            }

            steps_used += 1;
            if steps_used > max_steps {
                limit_exceeded = Some(format!(
                    "the run made more than {max_steps} node executions \
                     (limits.workflow.max_steps_per_run)"
                ));
                instance_failed = true;
                break 'pass;
            }

            let input = resolve_input(&graph, node, &node_data);
            let entry = node_runs
                .entry(node_id.clone())
                .or_insert_with(|| new_node_run_state(&node_id));
            entry.dirty = true;
            entry.input = Some(input.clone());
            entry.started_at.get_or_insert(Utc::now());
            entry.attempt_count += 1;
            let attempt_count = entry.attempt_count;
            let round = entry.round;

            let outcome = match node_type {
                Some(node_type) => {
                    execute_node(
                        state, &sys_ctx, &instance, node, node_type, &input, &mut fired, round,
                    )
                    .await
                }
                None => {
                    tracing::error!(
                        %instance_id,
                        node_id = %node.id,
                        node_type = %node.node_type,
                        "workflow execute: unknown node type, failing the instance"
                    );
                    // `Validation`, not `internal`: its Display carries the
                    // message, so `last_error` below stores a reason an
                    // operator can act on rather than the masked
                    // "internal error".
                    Err(AppError::Validation(format!(
                        "node {:?} has unknown type {:?}: not in this build's node-type registry",
                        node.id, node.node_type
                    )))
                }
            };
            match outcome {
                Ok(NodeOutcome::Succeeded { output }) => {
                    let entry = node_runs.get_mut(&node_id).expect(NODE_RUN_ENTRY_INVARIANT);
                    entry.status = "succeeded".into();
                    entry.completed_at = Some(Utc::now());
                    if cacheable {
                        entry.output_hash = Some(output_hash(node, &input));
                    }
                    entry.output = Some(output.clone());
                    node_data.insert(node_id.clone(), output);
                }
                Ok(NodeOutcome::Branch { taken_port, output }) => {
                    let output_hash = cacheable.then(|| output_hash(node, &input));
                    {
                        let entry = node_runs.get_mut(&node_id).expect(NODE_RUN_ENTRY_INVARIANT);
                        entry.status = "succeeded".into();
                        entry.completed_at = Some(Utc::now());
                        entry.output_hash = output_hash;
                        entry.output = Some(output.clone());
                    }
                    node_data.insert(node_id.clone(), output);
                    mark_untaken_branch(&graph, &node_id, taken_port, &mut node_runs);
                }
                Ok(NodeOutcome::Waiting {
                    match_type,
                    entity_logicalname,
                    condition,
                    resume_at,
                    eventual_output,
                }) => {
                    {
                        let entry = node_runs.get_mut(&node_id).expect(NODE_RUN_ENTRY_INVARIANT);
                        entry.status = "waiting".into();
                    }
                    node_data.insert(node_id.clone(), eventual_output);
                    pending_waits.push(PendingWait {
                        node_id: node_id.clone(),
                        match_type,
                        entity_logicalname,
                        condition,
                        resume_at,
                    });
                }
                Ok(NodeOutcome::Exit { reason }) => {
                    let entry = node_runs.get_mut(&node_id).expect(NODE_RUN_ENTRY_INVARIANT);
                    entry.status = "succeeded".into();
                    entry.completed_at = Some(Utc::now());
                    entry.output = Some(serde_json::json!({ "exit": reason }));
                    node_data.insert("exit_reason".into(), Value::String(reason));
                    instance_cancelled = true;
                    break 'pass;
                }
                Err(e) => {
                    let max_attempts = node
                        .config
                        .get("max_attempts")
                        .and_then(Value::as_i64)
                        .unwrap_or(1)
                        .max(1) as i32;
                    let entry = node_runs.get_mut(&node_id).expect(NODE_RUN_ENTRY_INVARIANT);
                    entry.last_error = Some(e.to_string());
                    if attempt_count < max_attempts {
                        // F095 backoff: a real checkpoint, not an in-pass
                        // spin — this frees the apalis job slot instead of
                        // busy-looping a failing node inside one attempt,
                        // and reuses the same schedule-wait/SLA-sweep
                        // mechanism a Wait node uses (guidelines §13: don't
                        // start a second scheduling mechanism). The sweep
                        // resumes it back to `pending` (see
                        // `sla_sweep::sweep`'s `kind: "retry"` branch), not
                        // `succeeded` — the node re-executes for real on the
                        // next pass, this isn't a cached replay.
                        let base_delay = node
                            .config
                            .get("retry_delay_seconds")
                            .and_then(Value::as_i64)
                            .unwrap_or(5)
                            .max(0);
                        let backoff_secs =
                            base_delay.saturating_mul(1i64 << (attempt_count - 1).min(10));
                        entry.status = "waiting".into();
                        pending_waits.push(PendingWait {
                            node_id: node_id.clone(),
                            match_type: "schedule",
                            entity_logicalname: None,
                            condition: Some(serde_json::json!({ "kind": "retry" })),
                            resume_at: Some(Utc::now() + chrono::Duration::seconds(backoff_secs)),
                        });
                    } else if graph
                        .outbound_edges(&node_id)
                        .any(|edge| edge.from_port == ON_ERROR_PORT)
                    {
                        // M1-T4: the node failed for good but wires
                        // `on_error`: the run goes on down that port.
                        let error = error_output(&node_id, &e.to_string());
                        entry.status = "succeeded".into();
                        entry.completed_at = Some(Utc::now());
                        entry.output = Some(error.clone());
                        node_data.insert(node_id.clone(), error);
                        record_error_taken(&mut node_data, &node_id);
                        mark_untaken_branch(&graph, &node_id, ON_ERROR_PORT, &mut node_runs);
                    } else {
                        entry.status = "failed".into();
                        entry.completed_at = Some(Utc::now());
                        instance_failed = true;
                    }
                }
            }
        }

        if instance_failed || !pending_waits.is_empty() {
            break 'pass;
        }
    }

    if let Some(message) = &limit_exceeded {
        tracing::warn!(%instance_id, %message, "workflow execute: run limit exceeded, failing the run");
        node_data.insert("limit_exceeded".into(), Value::String(message.clone()));
    }

    let all_terminal = graph.nodes.iter().all(|n| {
        node_runs
            .get(&n.id)
            .map(|nr| matches!(nr.status.as_str(), "succeeded" | "skipped" | "failed"))
            .unwrap_or(false)
    });

    // A node parked on a wait by an EARLIER pass — this pass produced no
    // `pending_waits` of its own, but the instance is still legitimately
    // waiting on that one. Only a resume path (`sla_sweep`, a trigger
    // dispatch, an approval decision) ever clears a `waiting` node_run;
    // `execute_instance` never does, so re-entering here with the node
    // still parked is the normal, expected outcome of the at-least-once
    // redelivery this function's own doc comment promises to tolerate.
    let waiting_on_an_earlier_pass = node_runs.values().any(|nr| nr.status == "waiting");

    let new_status = if instance_cancelled {
        "cancelled"
    } else if instance_failed {
        "failed"
    } else if !pending_waits.is_empty() || waiting_on_an_earlier_pass {
        "waiting"
    } else if all_terminal {
        "completed"
    } else {
        // Nothing ready, nothing waiting, not all terminal: a validated
        // graph should make this unreachable (every node is reachable and
        // every required port has a satisfying edge), but fail safe rather
        // than silently leaving the instance stuck at `running` forever.
        tracing::error!(%instance_id, "workflow execute: pass reached fixpoint with unresolved nodes");
        "failed"
    };

    let checkpoint = commit_checkpoint(
        state,
        &mut instance,
        new_status,
        node_data,
        fired,
        node_runs,
        pending_waits,
    )
    .await?;
    if checkpoint == Checkpoint::Discarded {
        // Nothing below may act on a `new_status` that never committed —
        // resuming the parent of a child whose "completed" was just rolled
        // back would hand it a result that does not exist.
        return Ok(PassOutcome::CheckpointDiscarded);
    }

    if matches!(new_status, "completed" | "failed" | "cancelled")
        && let (Some(parent_instance_id), Some(parent_node_id)) = (
            instance
                .context
                .get("parent_instance_id")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok()),
            instance
                .context
                .get("parent_node_id")
                .and_then(Value::as_str),
        )
    {
        resume_parent_after_sub_workflow(
            state,
            parent_instance_id,
            parent_node_id,
            instance.id,
            new_status,
        )
        .await?;
    }
    Ok(PassOutcome::Committed)
}

/// Per-instance execution claim (3.14). apalis at-least-once delivery — and,
/// just as routinely, a sweep resuming two waits of one instance in the same
/// tick — can start a second pass over an instance while the first is still
/// executing nodes. The checkpoint's `row_version` CAS only ever protected the
/// *write*: both passes still ran every ready node, so a webhook or a
/// notification fired twice before one of the two checkpoints was discarded.
///
/// Why this shape and not the other two:
///
/// - `pg_try_advisory_xact_lock` inside the checkpoint transaction cannot
///   cover node execution, which precedes it. Wrapping execution in that
///   transaction would hold it across a webhook's HTTP call,
///   `attome_approval::submit`, and the entity-write nodes' own transactions
///   (guidelines §2/§4: no external I/O inside a transaction).
/// - A `claimed_at` row CAS with a stale-claim timeout (the bulk /
///   schema-change / bundle-ledger pattern) needs a column
///   `0089_workflow_execution.sql` does not have, and a lease deadline that a
///   long pass — up to `MAX_PASS_ITERATIONS` nodes at 15s per webhook — can
///   legitimately outlive, at which point the lease would re-admit exactly the
///   overlap it is meant to exclude.
/// - A non-blocking session lock on a dedicated direct connection is what
///   `server::jobs::run_rewrap` and `attome_metadata::provision::sync_attribute_index`
///   already do for the same "must outlive any one transaction" shape. It is
///   held exactly as long as the pass runs and released by PostgreSQL the
///   moment the session closes — on a clean release, a `?` return, a panic, or
///   the job future being dropped — so a lock can never leak into the
///   application pool. The direct connection (`database.direct_url`) also
///   keeps it off a transaction-pooling pgbouncer, where a session lock is
///   not safe. Cost: one extra session per delivery, bounded by
///   `jobs.worker_concurrency`.
///
/// Key `"attome-workflow/execute:{instance_id}"` under this crate's namespace
/// (registry: `crates/server/tests/advisory_lock_namespaces.rs`).
///
/// **What a skipped delivery relies on.** The skipped job is consumed, so the
/// work it carried must be picked up by the pass that is already running or by
/// a pass that follows it. A resume that committed *before* the running pass
/// loaded its state is simply part of that state. One that committed *after*
/// bumps `workflow_instance.row_version`, so the running pass's checkpoint
/// CAS fails, it returns [`PassOutcome::CheckpointDiscarded`], and
/// [`execute_instance`] re-enqueues once the claim is gone. That invariant is
/// why every resume path — `resume_node`, `resume_retry`,
/// `resume_parent_after_sub_workflow`, `instance_admin`'s cancel — must bump
/// the instance row, never only the node_run.
struct ExecutionClaim {
    conn: attome_db::UnpooledSession,
    key: String,
}

impl ExecutionClaim {
    /// `Ok(None)` when another pass holds the claim: the caller skips, it
    /// does not error (apalis would otherwise retry a delivery whose work
    /// the holder is already doing).
    async fn try_acquire(state: &EngineState, instance_id: Uuid) -> Result<Option<Self>, AppError> {
        let key = format!("attome-workflow/execute:{instance_id}");
        let mut conn = attome_db::UnpooledSession::new(
            attome_db::create_runtime_session(&state.base.config)
                .await
                .map_err(AppError::internal)?,
        );
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(&key)
            .fetch_one(&mut *conn)
            .await
            .map_err(AppError::internal)?;
        if !locked {
            let _ = conn.close().await;
            return Ok(None);
        }
        Ok(Some(Self { conn, key }))
    }

    /// Explicit unlock, then close. The close alone would release the lock;
    /// the unlock is there so a session that somehow no longer holds it is
    /// logged rather than silently assumed.
    async fn release(self) {
        let Self { mut conn, key } = self;
        match sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(&key)
            .fetch_one(&mut *conn)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(key = %key, "workflow execute: execution claim was not held at release")
            }
            Err(e) => tracing::warn!(
                key = %key,
                error = %e,
                "workflow execute: explicit claim release failed; closing the session releases it"
            ),
        }
        let _ = conn.close().await;
    }
}

/// After a discarded checkpoint: a fresh pass, unless the transition we lost
/// to was terminal (a cancel), in which case the next pass would only no-op.
/// A redundant delivery is harmless — the claim and the terminal check absorb
/// it — but a missing one strands the instance, so err towards enqueueing.
async fn requeue_if_live(state: &EngineState, instance_id: Uuid) -> Result<(), AppError> {
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = $1")
            .bind(instance_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if !matches!(status.as_deref(), Some("running" | "waiting")) {
        return Ok(());
    }
    tracing::info!(%instance_id, "workflow execute: checkpoint was discarded, enqueueing a fresh pass");
    attome_jobs::enqueue_on_pool(
        &state.base.db,
        attome_core::jobs::EngineJob::WorkflowExecute { instance_id },
    )
    .await
    .map_err(AppError::internal)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Checkpoint {
    Committed,
    /// Lost the `row_version` CAS to a concurrent transition; rolled back.
    Discarded,
}

#[allow(clippy::too_many_arguments)]
async fn commit_checkpoint(
    state: &EngineState,
    instance: &mut InstanceRow,
    new_status: &str,
    node_data: serde_json::Map<String, Value>,
    fired: HashSet<String>,
    node_runs: HashMap<String, NodeRunState>,
    pending_waits: Vec<PendingWait>,
) -> Result<Checkpoint, AppError> {
    // M3-T1: each dirty run's input/output pair, stored inline or — over
    // `INLINE_PAYLOAD_MAX` — written to object storage first, before the
    // transaction opens (no external I/O inside it). A checkpoint that then
    // loses its CAS leaves an unreferenced object, removed by retention.
    let mut payloads: HashMap<String, StoredPayload> = HashMap::new();
    for (node_id, nr) in &node_runs {
        if nr.dirty && (nr.input.is_some() || nr.output.is_some()) {
            let id = nr.id.unwrap_or_else(Uuid::now_v7);
            payloads.insert(node_id.clone(), store_payload(state, id, nr).await);
        }
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    // C-10: the canonical audit-service builder — this used to be its own
    // 4-line copy of the `AuditService` constructor's `.new(..)
    // .with_ingest_capture(..).with_chainer_enabled(..).with_erasure_key(..)`
    // chain that was duplicated at every mutation call site in the workspace. This
    // function's own shape (a loop writing one audit event per dirty
    // workflow node run, plus a conditional rollback on a lost row_version
    // CAS) does not fit `attome_records::mutation_ring::MutationRing` —
    // there is no single `MutationResult` here, no row created by the
    // generic entity engine, no share grant, no file mirror — so this keeps
    // its own commit/rollback logic and only swaps the builder itself for
    // the one canonical copy.
    let audit_service = attome_audit::audit_service(state);

    let mut node_run_ids: HashMap<String, Uuid> = HashMap::new();
    for (node_id, nr) in &node_runs {
        if !nr.dirty {
            continue;
        }
        let payload = payloads.remove(node_id).unwrap_or_default();
        let id = payload.id.or(nr.id).unwrap_or_else(Uuid::now_v7);
        node_run_ids.insert(node_id.clone(), id);
        sqlx::query(
            "INSERT INTO workflow_node_run \
                (id, instance_id, node_id, status, output_hash, attempt_count, last_error, started_at, completed_at, \
                 round, input, output, payload_ref) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             ON CONFLICT (instance_id, node_id, round) DO UPDATE SET \
                status = EXCLUDED.status, output_hash = EXCLUDED.output_hash, \
                attempt_count = EXCLUDED.attempt_count, last_error = EXCLUDED.last_error, \
                started_at = COALESCE(workflow_node_run.started_at, EXCLUDED.started_at), \
                completed_at = EXCLUDED.completed_at, \
                input = CASE WHEN $14 THEN EXCLUDED.input ELSE workflow_node_run.input END, \
                output = CASE WHEN $14 THEN EXCLUDED.output ELSE workflow_node_run.output END, \
                payload_ref = CASE WHEN $14 THEN EXCLUDED.payload_ref ELSE workflow_node_run.payload_ref END, \
                row_version = workflow_node_run.row_version + 1",
        )
        .bind(id)
        .bind(instance.id)
        .bind(node_id)
        .bind(&nr.status)
        .bind(&nr.output_hash)
        .bind(nr.attempt_count)
        .bind(&nr.last_error)
        .bind(nr.started_at)
        .bind(nr.completed_at)
        .bind(nr.round)
        .bind(&payload.input)
        .bind(&payload.output)
        .bind(&payload.payload_ref)
        .bind(payload.id.is_some())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

        let event = AuditEvent {
            organization_ref: attome_core::ROOT_ORGANIZATION_ID,
            category: AuditCategory::BusinessEvent,
            entity_name: Some("workflow_node_run".to_string()),
            record_id: Some(id),
            operation: AuditOperation::Update,
            version_before: None,
            version_after: None,
            user_context: AuditUserContext {
                user_id: instance.started_by.unwrap_or(Uuid::nil()),
                user_name: "workflow-engine".to_string(),
                user_display_name: "Workflow Engine".to_string(),
                user_email: String::new(),
                user_job_ref: None,
                user_job_name: None,
            },
            changed_on: Utc::now(),
            source: AuditSource::Workflow,
            request_context: AuditRequestContext::default(),
            correlation_id: Some(instance.id),
            batch_id: None,
            event_name: Some(format!("workflow.node_run.{}", nr.status)),
            event_comment: Some(format!("node {node_id} -> {}", nr.status)),
            changed_fields: Vec::new(),
            snapshot_json: None,
        };
        // Plan 4.3 (C19): `write_in_tx`'s own default attribution is
        // `Attribution::user(event.user_context.user_id)` — correct when a
        // human started this instance, but wrong (falsely `Initiator::User`)
        // when it didn't (a scheduled trigger, or `execute_sub_workflow`'s
        // automated sub-workflow start): the same `Uuid::nil()` actor id then
        // reads as "a real user with no id" instead of "the system," the
        // trd-engine `attribution()` helper's exact distinction. `acting_user_id`
        // stays whatever `user_context.user_id` already is (never invented).
        let attribution = Attribution {
            acting_user_id: instance.started_by.unwrap_or(Uuid::nil()),
            initiator: if instance.started_by.is_some() {
                Initiator::User
            } else {
                Initiator::System
            },
            agent_session_id: None,
            agent_action_id: None,
        };
        audit_service
            .write_in_tx_attributed(&mut tx, event, attribution)
            .await
            .map_err(AppError::internal)?;
    }

    for wait in &pending_waits {
        let node_run_id = node_run_ids
            .get(&wait.node_id)
            .copied()
            .ok_or_else(|| AppError::internal("waiting node_run missing an id at checkpoint"))?;
        trigger_index::insert_wait_row(
            &mut tx,
            instance.definition_version_id,
            &wait.node_id,
            instance.id,
            node_run_id,
            wait.match_type,
            wait.entity_logicalname.as_deref(),
            wait.condition.as_ref(),
            wait.resume_at,
        )
        .await
        .map_err(AppError::internal)?;
    }

    let node_data_value = Value::Object(node_data);
    let fired_value = Value::Array(fired.into_iter().map(Value::String).collect());
    let completed_at = matches!(new_status, "completed" | "failed" | "cancelled").then(Utc::now);

    let rows = sqlx::query(
        "UPDATE workflow_instance \
         SET status = $2, node_data = $3, fired_side_effects = $4, completed_at = $5, \
             row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $6",
    )
    .bind(instance.id)
    .bind(new_status)
    .bind(&node_data_value)
    .bind(&fired_value)
    .bind(completed_at)
    .bind(instance.row_version)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if rows == 0 {
        // Lost a race against a concurrent transition (e.g. cancel). Any
        // side effects already fired this pass are the accepted
        // at-least-once cost (§4.4) — do not apply a checkpoint over a
        // state this pass no longer reflects.
        tracing::warn!(instance_id = %instance.id, "workflow checkpoint: row_version conflict, discarding this pass's checkpoint");
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(Checkpoint::Discarded);
    }

    tx.commit().await.map_err(AppError::internal)?;
    Ok(Checkpoint::Committed)
}

async fn load_instance(
    db: &sqlx::PgPool,
    instance_id: Uuid,
) -> Result<Option<InstanceRow>, AppError> {
    sqlx::query_as::<_, InstanceRow>(
        "SELECT id, definition_version_id, status, started_by, context, node_data, \
                fired_side_effects, row_version \
         FROM workflow_instance WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// M3-T1: one node run's input/output as the checkpoint writes it. `id` is
/// set when this pass produced a pair to write (absent: keep the stored one).
#[derive(Debug, Default)]
struct StoredPayload {
    id: Option<Uuid>,
    input: Option<Value>,
    output: Option<Value>,
    payload_ref: Option<String>,
}

/// Inline when the pair is small, else an object-storage write keyed by the
/// node run's id. A failed write keeps the pair out of the row (logged): the
/// run itself is what matters, its recorded payload is for inspection.
async fn store_payload(state: &EngineState, id: Uuid, nr: &NodeRunState) -> StoredPayload {
    let pair = serde_json::json!({ "input": nr.input, "output": nr.output });
    let bytes = serde_json::to_vec(&pair).unwrap_or_default();
    if bytes.len() <= INLINE_PAYLOAD_MAX {
        return StoredPayload {
            id: Some(id),
            input: nr.input.clone(),
            output: nr.output.clone(),
            payload_ref: None,
        };
    }
    let key = format!("workflow/node-run/{id}.json");
    match attome_storage::mirror::write_object(&state.base.storage, &key, bytes).await {
        Ok(()) => StoredPayload {
            id: Some(id),
            input: None,
            output: None,
            payload_ref: Some(key),
        },
        Err(e) => {
            tracing::warn!(node_run_id = %id, error = %e, "workflow node payload not stored");
            StoredPayload {
                id: Some(id),
                ..StoredPayload::default()
            }
        }
    }
}

async fn load_node_runs(
    db: &sqlx::PgPool,
    instance_id: Uuid,
) -> Result<HashMap<String, NodeRunState>, AppError> {
    let rows: Vec<NodeRunRow> = sqlx::query_as(
        "SELECT id, node_id, status, output_hash, attempt_count, last_error, started_at, completed_at, \
                row_version, round \
         FROM workflow_node_run WHERE instance_id = $1 ORDER BY round",
    )
    .bind(instance_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.node_id.clone(),
                NodeRunState {
                    id: Some(r.id),
                    node_id: r.node_id,
                    status: r.status,
                    output_hash: r.output_hash,
                    attempt_count: r.attempt_count,
                    last_error: r.last_error,
                    started_at: r.started_at,
                    completed_at: r.completed_at,
                    row_version: r.row_version,
                    // The latest round wins the map entry (rows load in
                    // round order).
                    round: r.round,
                    input: None,
                    output: None,
                    dirty: false,
                },
            )
        })
        .collect())
}

pub(crate) fn new_node_run_state(node_id: &str) -> NodeRunState {
    NodeRunState {
        id: None,
        node_id: node_id.to_string(),
        status: "pending".into(),
        output_hash: None,
        attempt_count: 0,
        last_error: None,
        started_at: None,
        completed_at: None,
        row_version: 0,
        round: 0,
        input: None,
        output: None,
        dirty: false,
    }
}

/// A `Join` node's `config.mode` (`"all"` / `"any"` / `"n_of_m"`) resolved
/// against how many inbound branches it actually has, into how many of them
/// must settle before it fires. Factored out of both `ready_nodes` (the
/// readiness gate) and `execute_node` (which needs the same number to decide
/// whether it was called too early) so the two can't independently drift —
/// the same "one source of truth, asserted equal" reasoning `node_types.rs`
/// documents for its own capability/side-effect pairing.
///
/// `total` is the number of live inbound edges on the `Join`'s "in" port.
/// `"all"` (and any unrecognized mode — fail safe, not fail open) needs every
/// one of them; `"any"` needs exactly one; `"n_of_m"` needs `config.n`,
/// clamped into `1..=total` so a misconfigured threshold can never leave the
/// node either impossible to satisfy or already-satisfied-by-nothing.
fn join_mode_and_threshold(config: &Value, total: usize) -> (&'static str, usize) {
    let mode = match config.get("mode").and_then(Value::as_str) {
        Some("any") => "any",
        Some("n_of_m") => "n_of_m",
        _ => "all",
    };
    let threshold = match mode {
        "any" => 1,
        "n_of_m" => config
            .get("n")
            .and_then(Value::as_i64)
            .unwrap_or(total as i64)
            .clamp(1, total.max(1) as i64) as usize,
        _ => total,
    };
    (mode, threshold)
}

/// A node is ready when it hasn't already reached a settled status and
/// every one of its required (and any wired optional) input ports is
/// satisfied — every inbound edge on that port has a source node whose
/// status is `succeeded` or `skipped` (a fan-in port with more than one
/// inbound edge on an ordinary node is the implicit "all" join case, per
/// this module's doc comment; `Join` itself uses `join_mode_and_threshold`
/// instead of requiring literally every inbound edge to have settled).
pub(crate) fn ready_nodes(
    graph: &Graph,
    node_runs: &HashMap<String, NodeRunState>,
    node_data: &serde_json::Map<String, Value>,
) -> Vec<String> {
    let mut out = Vec::new();
    for node in &graph.nodes {
        let status = node_runs.get(&node.id).map(|nr| nr.status.as_str());
        if !matches!(status, None | Some("pending")) {
            continue;
        }
        let Some(node_type) = NodeType::parse(&node.node_type) else {
            // B20: a type this build's registry does not know. There is no
            // port table to consult, so it is ready as soon as every upstream
            // node has settled — the execute pass then fails the instance
            // with a stored reason. Skipping it here (the old behavior)
            // parked it forever and left the fixpoint branch to fail the
            // instance with nothing on any node_run to say why.
            if graph
                .inbound_edges(&node.id)
                .all(|e| edge_settled(node_runs, node_data, e))
            {
                out.push(node.id.clone());
            }
            continue;
        };
        if node_type.is_entry() {
            // Entry nodes are materialized at instance-start, never here.
            continue;
        }
        if node_type == NodeType::Join {
            let inbound: Vec<_> = graph.inbound_edges(&node.id).collect();
            let total = inbound.len();
            let settled = inbound
                .iter()
                .filter(|e| edge_settled(node_runs, node_data, e))
                .count();
            let (_, threshold) = join_mode_and_threshold(&node.config, total);
            if total > 0 && settled >= threshold {
                out.push(node.id.clone());
            }
            continue;
        }
        let inbound: Vec<_> = graph.inbound_edges(&node.id).collect();
        let ports_by_name: HashMap<&str, Vec<_>> = {
            let mut m: HashMap<&str, Vec<_>> = HashMap::new();
            for e in &inbound {
                m.entry(e.to_port.as_str()).or_default().push(*e);
            }
            m
        };
        let ready = node_type.input_ports().iter().all(|(port, _, required)| {
            let edges = ports_by_name.get(port).cloned().unwrap_or_default();
            if edges.is_empty() {
                return !required;
            }
            edges.iter().all(|e| edge_settled(node_runs, node_data, e))
        });
        if ready {
            out.push(node.id.clone());
        }
    }
    out
}

/// M1-T4: an `on_error` edge carries something only when its source failed
/// and took that port; otherwise it is settled like any edge.
fn edge_settled(
    node_runs: &HashMap<String, NodeRunState>,
    node_data: &serde_json::Map<String, Value>,
    edge: &crate::graph::GraphEdge,
) -> bool {
    if edge.from_port == ON_ERROR_PORT && !error_taken(node_data, &edge.from_node) {
        return false;
    }
    upstream_settled(node_runs, node_data, &edge.from_node)
}

/// M1-T4: the `node_data` key listing the nodes that took `on_error`.
const ERRORS_TAKEN_KEY: &str = "on_error_taken";

fn error_taken(node_data: &serde_json::Map<String, Value>, node_id: &str) -> bool {
    node_data
        .get(ERRORS_TAKEN_KEY)
        .and_then(Value::as_array)
        .is_some_and(|ids| ids.iter().any(|v| v.as_str() == Some(node_id)))
}

fn record_error_taken(node_data: &mut serde_json::Map<String, Value>, node_id: &str) {
    let ids = node_data
        .entry(ERRORS_TAKEN_KEY)
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::Array(ids) = ids
        && !ids.iter().any(|v| v.as_str() == Some(node_id))
    {
        ids.push(Value::String(node_id.to_owned()));
    }
}

/// M1-T4: what an `on_error` port carries.
pub(crate) fn error_output(node_id: &str, message: &str) -> Value {
    serde_json::json!({
        "error_kind": attome_core::dead_letter::classify_error(message),
        "message": message,
        "node_id": node_id,
    })
}

/// M1-T4: a run limit (`limits.workflow.*`): the value an operator stored,
/// else the registry's default.
fn run_limit(state: &EngineState, key: &str) -> i64 {
    state
        .runtime_limit(key)
        .or_else(|| attome_config::limits::spec(key).map(|spec| spec.default_solo))
        .unwrap_or(i64::MAX)
}

/// M1-T4: why the run is past `limits.workflow.max_run_minutes`, if it is.
async fn run_time_exceeded(
    state: &EngineState,
    instance_id: Uuid,
) -> Result<Option<String>, AppError> {
    let max_minutes = run_limit(state, "workflow.max_run_minutes");
    let started: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT started_at FROM workflow_instance WHERE id = $1")
            .bind(instance_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let over = started.is_some_and(|started| {
        chrono::Duration::try_minutes(max_minutes).is_some_and(|limit| Utc::now() - started > limit)
    });
    Ok(over.then(|| {
        format!("the run is older than {max_minutes} minutes (limits.workflow.max_run_minutes)")
    }))
}

/// An edge's source counts as settled when it `succeeded` (with its output
/// present in `node_data`) or was `skipped` (no output expected).
fn upstream_settled(
    node_runs: &HashMap<String, NodeRunState>,
    node_data: &serde_json::Map<String, Value>,
    from_node: &str,
) -> bool {
    let Some(nr) = node_runs.get(from_node) else {
        return false;
    };
    match nr.status.as_str() {
        "skipped" => true,
        "succeeded" => node_data.contains_key(from_node),
        _ => false,
    }
}

/// After a branching node succeeds, any node reachable *only* through the
/// untaken output port can never run — mark it (and its own downstream
/// closure, transitively) `skipped` rather than leaving it `pending`
/// forever (§4.4, F090).
pub(crate) fn mark_untaken_branch(
    graph: &Graph,
    branch_node_id: &str,
    taken_port: &str,
    node_runs: &mut HashMap<String, NodeRunState>,
) {
    let mut frontier: Vec<String> = graph
        .outbound_edges(branch_node_id)
        .filter(|e| e.from_port != taken_port)
        .map(|e| e.to_node.clone())
        .collect();
    let mut visited = HashSet::new();
    while let Some(node_id) = frontier.pop() {
        if !visited.insert(node_id.clone()) {
            continue;
        }
        // Never override a node that already ran or is running through
        // some other still-live path.
        let already_settled = node_runs
            .get(&node_id)
            .map(|nr| {
                matches!(
                    nr.status.as_str(),
                    "succeeded" | "failed" | "waiting" | "skipped"
                )
            })
            .unwrap_or(false);
        if already_settled {
            continue;
        }
        // Only skip if EVERY inbound edge is now dead (source skipped, or
        // the same untaken-branch closure) — a node fed by another live
        // path must not be skipped.
        let all_dead = graph.inbound_edges(&node_id).all(|e| {
            e.from_node == branch_node_id && e.from_port != taken_port
                || node_runs
                    .get(&e.from_node)
                    .map(|nr| nr.status == "skipped")
                    .unwrap_or(false)
        });
        if !all_dead {
            continue;
        }
        let entry = node_runs
            .entry(node_id.clone())
            .or_insert_with(|| new_node_run_state(&node_id));
        entry.dirty = true;
        entry.status = "skipped".into();
        entry.completed_at = Some(Utc::now());
        for e in graph.outbound_edges(&node_id) {
            frontier.push(e.to_node.clone());
        }
    }
}

/// Fixpoint helper: after a pass finds nothing ready, some `pending` nodes
/// may now be provably unreachable (every inbound edge already dead) even
/// without a fresh branch decision this tick — e.g. a node fed solely by an
/// already-skipped upstream from an earlier iteration. Returns true if any
/// progress was made (caller should loop again).
pub(crate) fn propagate_skips(
    graph: &Graph,
    node_data: &serde_json::Map<String, Value>,
    node_runs: &mut HashMap<String, NodeRunState>,
) -> bool {
    let mut progressed = false;
    for node in &graph.nodes {
        let status = node_runs.get(&node.id).map(|nr| nr.status.as_str());
        if !matches!(status, None | Some("pending")) {
            continue;
        }
        let inbound: Vec<_> = graph.inbound_edges(&node.id).collect();
        if inbound.is_empty() {
            continue;
        }
        // M1-T4: an `on_error` edge of a node that succeeded without taking
        // it is as dead as an edge of a skipped node.
        let all_dead = inbound.iter().all(|e| {
            node_runs
                .get(&e.from_node)
                .map(|nr| {
                    nr.status == "skipped"
                        || (e.from_port == ON_ERROR_PORT
                            && nr.status == "succeeded"
                            && !error_taken(node_data, &e.from_node))
                })
                .unwrap_or(false)
        });
        if all_dead {
            let entry = node_runs
                .entry(node.id.clone())
                .or_insert_with(|| new_node_run_state(&node.id));
            entry.dirty = true;
            entry.status = "skipped".into();
            entry.completed_at = Some(Utc::now());
            progressed = true;
        }
    }
    progressed
}

/// Resolves a node's declared input ports from upstream `node_data`. A
/// fan-in port (more than one live inbound edge) merges into a JSON array;
/// a single source is passed through as-is. See module doc comment for why
/// this is intentionally simple rather than a full expression language.
pub(crate) fn resolve_input(
    graph: &Graph,
    node: &GraphNode,
    node_data: &serde_json::Map<String, Value>,
) -> Value {
    let mut obj = serde_json::Map::new();
    for edge in graph.inbound_edges(&node.id) {
        let Some(value) = node_data.get(&edge.from_node) else {
            continue;
        };
        obj.entry(edge.to_port.clone())
            .and_modify(|existing| {
                if let Value::Array(arr) = existing {
                    arr.push(value.clone());
                } else {
                    let prior = existing.clone();
                    *existing = Value::Array(vec![prior, value.clone()]);
                }
            })
            .or_insert_with(|| value.clone());
    }
    Value::Object(obj)
}

fn output_hash(node: &GraphNode, input: &Value) -> String {
    use sha2::{Digest, Sha256};
    let canonical =
        serde_json::json!({ "type": node.node_type, "config": node.config, "input": input });
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&canonical).unwrap_or_default());
    format!("{:x}", hasher.finalize())
}

/// §4.4's actual cache-HIT half — `output_hash` is computed and stored on
/// every cacheable node's `node_run` row (has been since the first pass at
/// this plan), but until this function existed nothing ever looked it back
/// up: the mechanism only ever wrote the cache, never read it. Scoped to
/// `definition_version_id` (not global) per §4.4's own framing — "a re-run
/// of an edited graph reuses... prior output," i.e. instances of the SAME
/// published graph, not an accidental hash collision across unrelated
/// workflows. Picks the most recently completed match if more than one
/// exists.
async fn cache_lookup(
    db: &sqlx::PgPool,
    definition_version_id: Uuid,
    hash: &str,
) -> Result<Option<Value>, AppError> {
    sqlx::query_scalar::<_, Value>(
        "SELECT i.node_data -> nr.node_id \
         FROM workflow_node_run nr \
         JOIN workflow_instance i ON i.id = nr.instance_id \
         WHERE nr.output_hash = $1 AND nr.status = 'succeeded' AND i.definition_version_id = $2 \
         ORDER BY nr.completed_at DESC NULLS LAST \
         LIMIT 1",
    )
    .bind(hash)
    .bind(definition_version_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// M3-T2: the idempotency key of one effect: the run, the node and its loop
/// round. Round 0 keeps the key every run had before rounds existed, so a
/// run resumed across the upgrade finds its earlier effects; a later round
/// is a new effect, never a replay of the first.
pub(crate) fn effect_key(instance: Uuid, node_id: &str, round: i32) -> String {
    if round == 0 {
        format!("{instance}:{node_id}")
    } else {
        format!("{instance}:{node_id}:{round}")
    }
}

/// M3-T2: a node round's entry in the checkpoint's `fired_side_effects`
/// (round 0 is the bare node id, as stored before rounds existed).
pub(crate) fn fired_key(node_id: &str, round: i32) -> String {
    if round == 0 {
        node_id.to_owned()
    } else {
        format!("{node_id}#{round}")
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "one node run's context, passed straight to the node's executor"
)]
async fn execute_node(
    state: &EngineState,
    ctx: &std::sync::Arc<SecurityContext>,
    instance: &InstanceRow,
    node: &GraphNode,
    node_type: NodeType,
    input: &Value,
    fired: &mut HashSet<String>,
    round: i32,
) -> Result<NodeOutcome, AppError> {
    // A30-T2: a condition that reads `env.<name>` depends on this
    // deployment's values, which a cached run's output does not record.
    let reads_env = node_type == NodeType::Condition && crate::condition::reads_env(&node.config);
    // T6-T2: so does one that reads a customer flag, which can change (an
    // emergency off) between runs.
    let reads_flags =
        node_type == NodeType::Condition && crate::condition::reads_flags(&node.config);
    if node_type.is_cacheable() && !reads_env && !reads_flags {
        let hash = output_hash(node, input);
        if let Some(cached) =
            cache_lookup(&state.base.db, instance.definition_version_id, &hash).await?
        {
            // Re-derive the branch decision from the cached value rather
            // than caching the decision itself — one fewer thing to keep in
            // sync, and `eval_condition` is a pure, cheap function of
            // `(config, value)` either way.
            return Ok(match node_type {
                NodeType::Condition => {
                    let taken = eval_condition(&node.config, &cached);
                    NodeOutcome::Branch {
                        taken_port: if taken { "true" } else { "false" },
                        output: cached,
                    }
                }
                _ => NodeOutcome::Succeeded { output: cached },
            });
        }
    }

    match node_type {
        NodeType::Trigger => Ok(NodeOutcome::Succeeded {
            output: instance.context.clone(),
        }),
        NodeType::Condition => {
            let mut value = input.get("value").cloned().unwrap_or(Value::Null);
            if reads_env {
                let env = attome_core::env_vars::context_for(&state.base.db).await?;
                value = attome_core::env_vars::with_env(&value, env);
            }
            let flags = if reads_flags {
                attome_core::customer_flags::load(&state.base.db).await?
            } else {
                std::collections::HashMap::new()
            };
            let taken = eval_condition_with_flags(&node.config, &value, &flags);
            Ok(NodeOutcome::Branch {
                taken_port: if taken { "true" } else { "false" },
                output: value,
            })
        }
        NodeType::CreateRecord | NodeType::UpdateRecord => {
            execute_entity_write(state, ctx, instance, node, node_type, input, round).await
        }
        NodeType::RestoreRecord => execute_restore_record(state, ctx, node, input).await,
        NodeType::DuplicateCheck => execute_duplicate_check(state, ctx, node, input).await,
        NodeType::Assign => execute_assign(state, ctx, instance, node, input, round).await,
        NodeType::SendNotification => {
            execute_send_notification(state, instance, node, input, fired, round).await
        }
        NodeType::Webhook => execute_webhook(instance, node, input, fired, round).await,
        NodeType::Approval => execute_approval(state, instance, node, input).await,
        NodeType::Wait => execute_wait(state, node, input).await,
        NodeType::WaitForEvent => execute_wait_for_event(state, node, input).await,
        NodeType::SubWorkflow => execute_sub_workflow(state, instance, node, input).await,
        NodeType::ForEach => execute_for_each(state, instance, node, input).await,
        // Plain passthrough — the fan-out itself is just "more than one
        // outbound edge from this node's output port", which the graph
        // already supported before `Split` existed as a named type.
        NodeType::Split => Ok(NodeOutcome::Succeeded {
            output: input.get("in").cloned().unwrap_or(Value::Null),
        }),
        // `ready_nodes` only ever calls this once `join_mode_and_threshold`
        // says enough branches have settled — `resolve_input` (called by the
        // caller before this match) has already merged whichever of them
        // are present in `node_data` into `input["in"]`, so there is nothing
        // left for this arm to do but pass that merged value on.
        NodeType::Join => Ok(NodeOutcome::Succeeded {
            output: input.get("in").cloned().unwrap_or(Value::Null),
        }),
        NodeType::AgentStep => execute_agent_step(state, ctx, node, input, fired, round).await,
        NodeType::Route => execute_route(state, ctx, node, input).await,
        NodeType::ModuleStep => {
            execute_module_step(state, ctx, instance, node, input, fired, round).await
        }
        NodeType::Connector => execute_connector(state, instance, node, input, fired, round).await,
        NodeType::Map => execute_map(node, input),
    }
}

/// S14-T1: a connector node's system and operation.
pub(crate) fn connector_target(node: &GraphNode) -> Result<(&str, &str), AppError> {
    fn named<'a>(
        node: &GraphNode,
        key: &str,
        value: Option<&'a Value>,
    ) -> Result<&'a str, AppError> {
        value
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::Validation(format!("connector node {:?} names no {key}", node.id))
            })
    }
    Ok((
        named(node, "system", node.config.get("system"))?,
        named(node, "operation", node.config.get("operation"))?,
    ))
}

/// S14-T1: calls the connector operation (`attome_integration::connector::flow`).
/// Fired-marked like a webhook, so a replay after the call does not call
/// again; the effect key goes as the call's `Idempotency-Key` for the
/// window before the checkpoint.
async fn execute_connector(
    state: &EngineState,
    instance: &InstanceRow,
    node: &GraphNode,
    input: &Value,
    fired: &mut HashSet<String>,
    round: i32,
) -> Result<NodeOutcome, AppError> {
    if fired.contains(&fired_key(&node.id, round)) {
        return Ok(NodeOutcome::Succeeded {
            output: serde_json::json!({ "skipped_replay": true }),
        });
    }
    let (system, operation) = connector_target(node)?;
    if !state.modules.load().has(attome_modules::MODULE_INTEGRATION) {
        return Err(AppError::Validation(format!(
            "connector node {:?} needs the integration module, which this deployment is not licensed for",
            node.id
        )));
    }
    let params = input.get("params").cloned().unwrap_or(Value::Null);
    let body = input.get("body").filter(|b| !b.is_null());
    let key = effect_key(instance.id, &node.id, round);
    let output = attome_integration::connector::flow::run_named(
        state,
        system,
        operation,
        &params,
        body,
        Some(&key),
    )
    .await?;
    fired.insert(fired_key(&node.id, round));
    Ok(NodeOutcome::Succeeded { output })
}

/// S14-T1: maps the wired `in` by `config.mapping` (each element of the
/// list at `config.each`, when set). The dry run maps for real too.
pub(crate) fn map_output(node: &GraphNode, input: &Value) -> Result<Value, AppError> {
    let mapping = node.config.get("mapping").cloned().unwrap_or(Value::Null);
    let each = node.config.get("each").and_then(Value::as_str);
    let value = input.get("in").cloned().unwrap_or(Value::Null);
    crate::map::apply(&mapping, each, &value)
        .map_err(|message| AppError::Validation(format!("map node {:?}: {message}", node.id)))
}

fn execute_map(node: &GraphNode, input: &Value) -> Result<NodeOutcome, AppError> {
    Ok(NodeOutcome::Succeeded {
        output: map_output(node, input)?,
    })
}

/// The instance's correlated record, for module steps and kind guards.
async fn correlation_of(state: &EngineState, instance_id: Uuid) -> Result<Option<Uuid>, AppError> {
    Ok(sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT correlation_entity_id FROM workflow_instance WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .flatten())
}

/// E8-T2: the registered handler for a module step, when its module is
/// licensed.
pub(crate) fn module_step_handler<'a>(
    state: &'a EngineState,
    node: &GraphNode,
) -> Result<&'a std::sync::Arc<dyn attome_core::workflow_step::WorkflowStepHandler>, AppError> {
    let key = node
        .config
        .get("handler")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::Validation(format!("module step {:?} names no handler", node.id))
        })?;
    let handler = state.workflow_step_handlers.get(key).ok_or_else(|| {
        AppError::Validation(format!(
            "module step {:?} names handler {key:?}, which no engine registered",
            node.id
        ))
    })?;
    if !state.modules.load().has(handler.module_id()) {
        return Err(AppError::Validation(format!(
            "module step {:?}: handler {key:?} needs a module this deployment is not licensed for",
            node.id
        )));
    }
    Ok(handler)
}

/// E8-T2: runs a module step through its registered handler and maps its
/// outcome. A finished step is fired-marked, so a crash replay does not run
/// it twice; a timed wait runs the handler again when due, and an event
/// wait completes the node when the event arrives (as `WaitForEvent` does); a block either passes on (`continue_after`) or waits
/// `config.retry_after_seconds` (an hour by default); an exit ends the
/// instance.
async fn execute_module_step(
    state: &EngineState,
    ctx: &SecurityContext,
    instance: &InstanceRow,
    node: &GraphNode,
    input: &Value,
    fired: &mut HashSet<String>,
    round: i32,
) -> Result<NodeOutcome, AppError> {
    if fired.contains(&fired_key(&node.id, round)) {
        return Ok(NodeOutcome::Succeeded {
            output: serde_json::json!({ "skipped_replay": true }),
        });
    }
    let handler = module_step_handler(state, node)?;
    let config = node.config.get("config").cloned().unwrap_or(Value::Null);
    let step_input = input.get("input").cloned().unwrap_or(Value::Null);
    // S9-T5: the step claims its effect key in the durable idempotency
    // ledger before the handler runs, so a replay of the run (a crash before
    // the checkpoint recorded the step) serves the step's stored output
    // instead of running the action again. The handler gets the key too
    // (`StepInvocation::idempotency_key`, and the task-scoped
    // `request_scope::idempotency_key` an outbound call reads), for the
    // narrow window the ledger cannot close: a crash after the action ran
    // and before its completion is written, retried once the claim is stale.
    let key = effect_key(instance.id, &node.id, round);
    let body_hash = module_step_body_hash(handler.key(), &config, &step_input);
    let principal = instance.started_by.unwrap_or(ctx.user_id);
    let claim = match idempotency_durable::acquire_or_check(
        &state.base,
        principal,
        "WORKFLOW",
        "workflow.module_step",
        &key,
        &body_hash,
    )
    .await?
    {
        idempotency_durable::AcquireOutcome::Replay(cached) => {
            let output: Value = serde_json::from_slice(&cached.body)
                .map_err(|e| AppError::internal(format!("corrupt idempotency replay body: {e}")))?;
            fired.insert(fired_key(&node.id, round));
            return Ok(NodeOutcome::Succeeded { output });
        }
        idempotency_durable::AcquireOutcome::InProgress => {
            return Err(AppError::Conflict(
                "another attempt at this workflow step is already in progress",
            ));
        }
        idempotency_durable::AcquireOutcome::DifferentRequest => {
            return Err(AppError::internal(
                "workflow step idempotency key reused with different input — the same \
                 (instance_id, node_id, round) must always resolve identical input",
            ));
        }
        idempotency_durable::AcquireOutcome::Acquired { record_id } => record_id,
    };
    let invocation = attome_core::workflow_step::StepInvocation {
        instance_id: instance.id,
        node_id: node.id.clone(),
        correlation_entity_id: correlation_of(state, instance.id).await?,
        config,
        input: step_input,
        simulate: false,
        run_as_user: Some(ctx.user_id),
        idempotency_key: Some(key.clone()),
    };
    let ran = attome_types::request_scope::with_idempotency_key(
        Some(&key),
        handler.run(state, invocation),
    )
    .await;
    let outcome = match ran {
        Ok(outcome) => step_node_outcome(node, &node.id, round, fired, outcome),
        Err(e) => {
            // Nothing to replay: the next attempt claims the key again.
            idempotency_durable::release_on_failure(&state.base, claim).await;
            return Err(e);
        }
    };
    match &outcome {
        NodeOutcome::Succeeded { output } => {
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            idempotency_durable::complete_in_tx(
                &mut tx,
                claim,
                None,
                200,
                &[],
                &serde_json::to_vec(output).unwrap_or_default(),
            )
            .await
            .map_err(AppError::internal)?;
            attome_db::tx::commit(tx).await?;
        }
        // A wait runs the handler again when it is due: not a replay.
        _ => idempotency_durable::release_on_failure(&state.base, claim).await,
    }
    Ok(outcome)
}

/// S9-T5: what a module step's input is, for its idempotency claim.
fn module_step_body_hash(handler: &str, config: &Value, input: &Value) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_vec(&serde_json::json!({
        "handler": handler,
        "config": config,
        "input": input,
    }))
    .unwrap_or_default();
    format!("{:x}", Sha256::digest(&canonical))
}

/// The node outcome a module step's handler outcome gives.
fn step_node_outcome(
    node: &GraphNode,
    node_id: &str,
    round: i32,
    fired: &mut HashSet<String>,
    outcome: attome_core::workflow_step::StepOutcome,
) -> NodeOutcome {
    use attome_core::workflow_step::StepOutcome;
    match outcome {
        StepOutcome::Done(output) => {
            fired.insert(fired_key(node_id, round));
            NodeOutcome::Succeeded { output }
        }
        StepOutcome::Waiting {
            resume_at,
            wait_event,
        } => match wait_event {
            Some(event) => NodeOutcome::Waiting {
                match_type: "entity_event",
                entity_logicalname: None,
                condition: Some(serde_json::json!({ "event": event })),
                resume_at,
                eventual_output: serde_json::json!({ "waited_for": event }),
            },
            // A timed wait runs the handler again when it is due (the
            // retry wait re-executes the node rather than replaying it).
            None => NodeOutcome::Waiting {
                match_type: "schedule",
                entity_logicalname: None,
                condition: Some(serde_json::json!({ "kind": "retry" })),
                resume_at: resume_at.or_else(|| Some(Utc::now())),
                eventual_output: serde_json::json!({ "waited": true }),
            },
        },
        StepOutcome::Blocked {
            reason,
            continue_after: true,
        } => {
            fired.insert(fired_key(node_id, round));
            NodeOutcome::Succeeded {
                output: serde_json::json!({ "blocked": reason }),
            }
        }
        StepOutcome::Blocked {
            reason,
            continue_after: false,
        } => {
            let seconds = node
                .config
                .get("retry_after_seconds")
                .and_then(Value::as_i64)
                .unwrap_or(3600)
                .clamp(60, 30 * 86_400);
            NodeOutcome::Waiting {
                match_type: "schedule",
                entity_logicalname: None,
                condition: Some(serde_json::json!({ "kind": "retry" })),
                resume_at: Some(Utc::now() + chrono::Duration::seconds(seconds)),
                eventual_output: serde_json::json!({ "blocked": reason }),
            }
        }
        StepOutcome::Exit { reason } => NodeOutcome::Exit { reason },
    }
}

/// E8-T2: the guard of the instance's definition kind, if one is registered.
async fn kind_guard(
    state: &EngineState,
    definition_version_id: Uuid,
) -> Result<Option<std::sync::Arc<dyn attome_core::workflow_step::WorkflowKindGuard>>, AppError> {
    if state.workflow_kind_guards.is_empty() {
        return Ok(None);
    }
    let kind: Option<String> = sqlx::query_scalar(
        "SELECT d.kind FROM workflow_definition d \
           JOIN workflow_definition_version v ON v.definition_id = d.id WHERE v.id = $1",
    )
    .bind(definition_version_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(kind.and_then(|k| state.workflow_kind_guards.get(k.as_str()).cloned()))
}

/// [`eval_condition`] with the customer flags a V2 expression's `flag(name)`
/// reads (T6-T2). A legacy comparison reads no flags.
pub(crate) fn eval_condition_with_flags(
    config: &Value,
    value: &Value,
    flags: &std::collections::HashMap<String, bool>,
) -> bool {
    match crate::condition::expression_of(config) {
        Some(expression) => expression
            .as_str()
            .is_some_and(|src| crate::condition::expression_holds_with_flags(src, value, flags)),
        None => eval_condition(config, value),
    }
}

pub(crate) fn eval_condition(config: &Value, value: &Value) -> bool {
    // Z11-T15: a V2 expression wins over the legacy comparison.
    if let Some(expression) = crate::condition::expression_of(config) {
        return expression
            .as_str()
            .is_some_and(|src| crate::condition::expression_holds(src, value));
    }
    let op = config.get("op").and_then(Value::as_str).unwrap_or("eq");
    let expected = config.get("value").cloned().unwrap_or(Value::Null);
    let field = config.get("field").and_then(Value::as_str);
    let actual = match field {
        Some(path) => path
            .split('.')
            .try_fold(value.clone(), |acc, seg| acc.get(seg).cloned())
            .unwrap_or(Value::Null),
        None => value.clone(),
    };
    match op {
        "eq" => actual == expected,
        "neq" => actual != expected,
        "gt" => actual
            .as_f64()
            .zip(expected.as_f64())
            .is_some_and(|(a, b)| a > b),
        "lt" => actual
            .as_f64()
            .zip(expected.as_f64())
            .is_some_and(|(a, b)| a < b),
        "contains" => match (&actual, &expected) {
            (Value::String(a), Value::String(b)) => a.contains(b.as_str()),
            (Value::Array(a), _) => a.contains(&expected),
            _ => false,
        },
        "truthy" => match &actual {
            Value::Bool(b) => *b,
            Value::Null => false,
            _ => true,
        },
        _ => false,
    }
}

/// Maps a resumed Approval node's recorded `decision` (`sla_sweep`'s output,
/// mirroring `attome_approval::ApprovalStatus`) onto which of the two output
/// ports actually fired — `approved` only for a real approval; every other
/// terminal outcome (rejected, expired, cancelled, invalidated) takes the
/// `rejected` port, since none of them mean the approved path should run.
pub(crate) fn approval_taken_port(decision: &str) -> Option<&'static str> {
    match decision {
        "approved" => Some("approved"),
        "rejected" | "expired" | "cancelled" | "invalidated" => Some("rejected"),
        _ => None,
    }
}

/// A18-T8: brings the wired record back from the recycle bin through
/// `restore_record_for`, the path the bin's own restore takes. A record
/// already live succeeds unchanged, which is what makes a crash-replay after
/// the restore committed harmless.
/// A15-T9: the "if a duplicate exists" step. Reads the live record and looks
/// it up under every active duplicate rule of its entity
/// (`attome_records::duplicate_check::find_any`); `found` carries the
/// matches the flow's identity may read and a count of the others.
async fn execute_duplicate_check(
    state: &EngineState,
    ctx: &SecurityContext,
    node: &GraphNode,
    input: &Value,
) -> Result<NodeOutcome, AppError> {
    let entity_name = node
        .config
        .get("entity")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::internal(format!("node {:?} missing config.entity", node.id)))?;
    let entity_id = state
        .entities
        .load()
        .get(entity_name)
        .map(|meta| meta.entity_id)
        .ok_or_else(|| {
            AppError::internal(format!(
                "unknown entity {entity_name:?} in workflow node config"
            ))
        })?;
    let record_id = input
        .get("record_id")
        .and_then(|v| v.as_str().or_else(|| v.get("id").and_then(Value::as_str)))
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            AppError::Validation("duplicate_check node has no resolvable record_id".into())
        })?;
    let row: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT to_jsonb(t) FROM {} t WHERE id = $1 AND is_active = true",
        attome_core::quote_ident(entity_name)
    ))
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    let Some(Value::Object(values)) = row else {
        return Err(AppError::NotFound);
    };
    let found = attome_records::duplicate_check::find_any(
        state,
        ctx,
        entity_id,
        entity_name,
        Some(record_id),
        &values,
    )
    .await?;
    let any = !found.visible.is_empty() || found.hidden > 0;
    Ok(NodeOutcome::Branch {
        taken_port: if any { "found" } else { "none" },
        output: serde_json::json!({
            "id": record_id,
            "matches": found.visible,
            "hidden": found.hidden,
        }),
    })
}

/// M11-T1: picks the owner (`crate::assign`) and writes `owner_ref` through
/// the same entity path, and idempotency key, as `UpdateRecord`.
async fn execute_assign(
    state: &EngineState,
    ctx: &SecurityContext,
    instance: &InstanceRow,
    node: &GraphNode,
    input: &Value,
    round: i32,
) -> Result<NodeOutcome, AppError> {
    use crate::assign::{self, Strategy};
    let entity_name = node
        .config
        .get("entity")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::internal(format!("node {:?} missing config.entity", node.id)))?;
    let strategy = node
        .config
        .get("strategy")
        .and_then(Value::as_str)
        .and_then(Strategy::parse)
        .unwrap_or(Strategy::RoundRobin);
    let uuid_of = |v: Option<&Value>| {
        v.and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
    };
    let team = uuid_of(node.config.get("team_ref"));
    let queue = uuid_of(node.config.get("queue_ref"));
    let role = uuid_of(node.config.get("role_ref"));
    let fallback_queue = node
        .config
        .get("fallback_queue_ref")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok());
    let rules: Vec<Value> = node
        .config
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let required_skills: Vec<String> = node
        .config
        .get("skills")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let territory_field = node
        .config
        .get("territory_field")
        .and_then(Value::as_str)
        .unwrap_or("territory_ref");
    let record_id = input
        .get("record_id")
        .and_then(|v| v.as_str().or_else(|| v.get("id").and_then(Value::as_str)))
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation("assign node has no resolvable record_id".into()))?;
    if state.entities.load().get(entity_name).is_none() {
        return Err(AppError::internal(format!(
            "unknown entity {entity_name:?} in workflow node config"
        )));
    }
    let record: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT to_jsonb(t) FROM {} t WHERE t.id = $1",
        attome_core::quote_ident(entity_name)
    ))
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    let record = record
        .and_then(|r| r.as_object().cloned())
        .ok_or(AppError::NotFound)?;
    let pool = assign::candidates(state, team, queue, role).await?;
    let chosen = match strategy {
        Strategy::Rule => assign::by_rule(&rules, &record),
        Strategy::RoundRobin => {
            assign::round_robin(state, instance.definition_version_id, &node.id, &pool).await?
        }
        Strategy::LeastLoaded => {
            let loads = assign::loads(state, entity_name, &pool).await?;
            assign::least_loaded(&pool, &loads)
        }
        Strategy::Skills => {
            let held = assign::skills(state, &pool).await?;
            assign::best_skilled(&pool, &held, &required_skills)
        }
        Strategy::Territory => match record
            .get(territory_field)
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        {
            Some(territory) => assign::territory_owner(state, territory).await?,
            None => None,
        },
    };
    let chosen = match (chosen, fallback_queue) {
        (Some(user), _) => user,
        (None, Some(queue)) => {
            let members = assign::queue_members(state, queue).await?;
            assign::round_robin(
                state,
                instance.definition_version_id,
                &format!("{}#fallback", node.id),
                &members,
            )
            .await?
            .ok_or_else(|| AppError::Validation("nobody to assign the record to".into()))?
        }
        (None, None) => {
            return Err(AppError::Validation(
                "nobody to assign the record to".into(),
            ));
        }
    };
    let write = serde_json::json!({
        "record_id": record_id.to_string(),
        "data": { "owner_ref": chosen.to_string() },
    });
    execute_entity_write(
        state,
        ctx,
        instance,
        node,
        NodeType::UpdateRecord,
        &write,
        round,
    )
    .await
}

async fn execute_restore_record(
    state: &EngineState,
    ctx: &SecurityContext,
    node: &GraphNode,
    input: &Value,
) -> Result<NodeOutcome, AppError> {
    let entity_name = node
        .config
        .get("entity")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::internal(format!("node {:?} missing config.entity", node.id)))?;
    let append_only = state
        .entities
        .load()
        .get(entity_name)
        .map(|meta| meta.is_append_only)
        .ok_or_else(|| {
            AppError::internal(format!(
                "unknown entity {entity_name:?} in workflow node config"
            ))
        })?;
    if append_only {
        return Err(AppError::Validation(format!(
            "{entity_name} records are never deleted, so none can be restored"
        )));
    }
    let record_id = input
        .get("record_id")
        .and_then(|v| v.as_str().or_else(|| v.get("id").and_then(Value::as_str)))
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            AppError::Validation("restore_record node has no resolvable record_id".into())
        })?;
    let live: Option<bool> = sqlx::query_scalar(&format!(
        "SELECT is_active FROM {} WHERE id = $1",
        attome_core::quote_ident(entity_name)
    ))
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    match live {
        None => return Err(AppError::NotFound),
        Some(true) => {}
        Some(false) => {
            attome_records::entity_crud::restore_record_for(
                state,
                ctx,
                ctx.user_id,
                entity_name,
                record_id,
                None,
            )
            .await?;
        }
    }
    Ok(NodeOutcome::Succeeded {
        output: serde_json::json!({ "id": record_id }),
    })
}

/// A write transaction for an entity-write node. M1-T5: the change event the
/// write produces carries the run's chain depth plus one
/// (`entity_change_event.chain_depth` defaults from this transaction-local
/// setting), so a flow its write triggers knows how deep the chain is.
async fn begin_entity_write<'a>(
    state: &'a EngineState,
    instance: &InstanceRow,
) -> Result<attome_db::Tx<'a>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "SELECT set_config('attome.workflow_chain_depth', \
                COALESCE((SELECT (chain_depth + 1)::text FROM workflow_instance WHERE id = $1), '1'), \
                true)",
    )
    .bind(instance.id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    Ok(tx)
}

/// What an `update_record` node's write came to under its conflict rule.
enum RuleOutcome<'a> {
    Written(
        attome_db::Tx<'a>,
        attome_records::entity_mutation::MutationResult,
    ),
    /// `ask_person`: waiting on the approval request the conflict opened.
    Paused(NodeOutcome),
}

/// A16-T5: an `update_record` node's write under its `config.on_conflict`
/// rule ([`crate::conflict`]). A rule that ends in a failure or a wait
/// releases the node's idempotency slot first, so the write can be made
/// again later (after an approval, or a retry of the node).
#[expect(
    clippy::too_many_arguments,
    reason = "the write's own parts, as execute_entity_write holds them"
)]
async fn update_by_rule<'a>(
    state: &'a EngineState,
    ctx: &SecurityContext,
    instance: &InstanceRow,
    node: &GraphNode,
    meta: &attome_core::EntityMeta,
    input: &Value,
    data: &serde_json::Map<String, Value>,
    idempotency_id: Uuid,
) -> Result<RuleOutcome<'a>, AppError> {
    use crate::conflict::{self, ConflictStep, MergeCheck, OnConflict};

    let entity_name = meta.logicalname.as_str();
    let record_id = input
        .get("record_id")
        .and_then(|v| v.as_str().or_else(|| v.get("id").and_then(Value::as_str)))
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            AppError::Validation("update_record node has no resolvable record_id".into())
        })?;
    let mut rule = OnConflict::from_config(node.config.get("on_conflict"))?;
    // Resuming from an `ask_person` approval: approved applies the changes
    // over the record as it is now; anything else ends the node.
    match conflict::conflict_decision(instance.node_data.get(&node.id)) {
        Some("approved") => rule = OnConflict::RetryFresh,
        Some(decision) => {
            return Err(AppError::Validation(format!(
                "the conflict on {entity_name} {record_id} was not approved ({decision})"
            )));
        }
        None => {}
    }
    let mut write_over: Option<i64> = if rule.writes_over_seen_version() {
        conflict::seen_version(input, &instance.context, record_id)
    } else {
        None
    };
    let mut merged = false;
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        let mut tx = begin_entity_write(state, instance).await?;
        let expected = match write_over {
            Some(version) => version,
            None => sqlx::query_scalar(&format!(
                "SELECT row_version FROM {} WHERE id = $1",
                attome_core::quote_ident(entity_name)
            ))
            .bind(record_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?,
        };
        let result = attome_records::entity_mutation::update_one(
            &mut tx,
            state,
            ctx,
            entity_name,
            meta.entity_id,
            record_id,
            &meta.attrs,
            data,
            ctx.user_id,
            expected,
            attome_records::entity_mutation::MutationMode::Strict,
        )
        .await;
        match result {
            Ok(mutation) => return Ok(RuleOutcome::Written(tx, mutation)),
            Err(AppError::VersionConflict) => drop(tx),
            Err(other) => return Err(other),
        }

        let check = if rule == OnConflict::Merge && !merged {
            attome_records::entity_crud::history::merge_basis(
                state,
                ctx,
                entity_name,
                record_id,
                expected,
            )
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, %record_id, "flow merge basis unavailable");
                None
            })
            .map(|basis| MergeCheck {
                current_version: basis.current_version,
                overlaps: basis.changed.iter().any(|name| data.contains_key(name)),
            })
        } else {
            None
        };
        match conflict::after_conflict(rule, attempt, check.as_ref(), merged) {
            ConflictStep::Retry => write_over = None,
            ConflictStep::MergeAt(version) => {
                merged = true;
                write_over = Some(version);
            }
            ConflictStep::Stop => {
                idempotency_durable::release_on_failure(&state.base, idempotency_id).await;
                return Err(attome_records::entity_crud::history::version_conflict(
                    state,
                    ctx,
                    entity_name,
                    record_id,
                    expected,
                    "workflow",
                )
                .await);
            }
            ConflictStep::AskPerson => {
                idempotency_durable::release_on_failure(&state.base, idempotency_id).await;
                let conflict = attome_records::entity_crud::history::version_conflict(
                    state,
                    ctx,
                    entity_name,
                    record_id,
                    expected,
                    "workflow",
                )
                .await;
                let payload = serde_json::json!({
                    "instance_id": instance.id,
                    "node_id": node.id,
                    "entity": entity_name,
                    "record_id": record_id,
                    "changes": data,
                    "conflict": conflict_body(&conflict),
                });
                let requested_by = instance.started_by.unwrap_or(Uuid::nil());
                let request = attome_approval::submit(
                    &state.base.db,
                    conflict::CONFLICT_ACTION_TYPE,
                    payload,
                    requested_by,
                    1,
                    chrono::Duration::hours(72),
                )
                .await?;
                return Ok(RuleOutcome::Paused(NodeOutcome::Waiting {
                    match_type: "signal",
                    entity_logicalname: None,
                    condition: Some(
                        serde_json::json!({ "kind": "approval", "approval_request_id": request.id }),
                    ),
                    resume_at: None,
                    eventual_output: serde_json::json!({ "approval_request_id": request.id }),
                }));
            }
        }
    }
}

/// The A16-T1 conflict body (`current_version`, `current_state`), for an
/// approval request's payload.
fn conflict_body(error: &AppError) -> Value {
    match error {
        AppError::VersionConflictAt {
            current_version,
            current_state,
        } => serde_json::json!({
            "current_version": current_version,
            "current_state": current_state,
        }),
        _ => Value::Null,
    }
}

/// §4.4 mechanism 1: routes Create/Update Record through
/// `attome_server::middleware::idempotency_durable` — the SAME durable
/// Postgres tier the HTTP `X-Idempotency-Key` mandatory-operation path uses
/// (guidelines §9/§13: reuse, don't invent a second mechanism), keyed on
/// `(instance_id, node_id, round)` ([`effect_key`], M3-T2) instead of an HTTP request identity. A crash
/// between the entity INSERT/UPDATE committing and the workflow checkpoint
/// committing now replays as a cache hit (`AcquireOutcome::Replay`), not a
/// second write: `acquire_or_check`'s claim row and `complete_in_tx`'s
/// completion are separate durable writes, but the completion is atomic
/// with the entity mutation itself (same transaction, same commit).
async fn execute_entity_write(
    state: &EngineState,
    ctx: &SecurityContext,
    instance: &InstanceRow,
    node: &GraphNode,
    node_type: NodeType,
    input: &Value,
    round: i32,
) -> Result<NodeOutcome, AppError> {
    let entity_name = node
        .config
        .get("entity")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::internal(format!("node {:?} missing config.entity", node.id)))?;
    let registry = state.entities.load();
    let meta = registry
        .get(entity_name)
        .ok_or_else(|| {
            AppError::internal(format!(
                "unknown entity {entity_name:?} in workflow node config"
            ))
        })?
        .clone();
    drop(registry);

    let data = input
        .get("data")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let principal_ref = instance.started_by.ok_or_else(|| {
        AppError::internal(
            "entity-write node requires instance.started_by — no system service-account \
             user exists yet for an instance with no starting principal",
        )
    })?;
    // M1-T3: the run-as identity needs the entity privilege itself.
    ctx.require(
        entity_name,
        if matches!(node_type, NodeType::CreateRecord) {
            "create"
        } else {
            "update"
        },
    )?;
    let operation = if matches!(node_type, NodeType::CreateRecord) {
        "workflow.create_record"
    } else {
        "workflow.update_record"
    };
    let client_key = effect_key(instance.id, &node.id, round);
    let body_hash = entity_write_body_hash(&data);

    let record_id = match idempotency_durable::acquire_or_check(
        &state.base,
        principal_ref,
        "WORKFLOW",
        operation,
        &client_key,
        &body_hash,
    )
    .await?
    {
        idempotency_durable::AcquireOutcome::Replay(cached) => {
            let cached_output: Value = serde_json::from_slice(&cached.body)
                .map_err(|e| AppError::internal(format!("corrupt idempotency replay body: {e}")))?;
            return Ok(NodeOutcome::Succeeded {
                output: cached_output,
            });
        }
        idempotency_durable::AcquireOutcome::InProgress => {
            return Err(AppError::Conflict(
                "another attempt at this workflow entity-write is already in progress",
            ));
        }
        idempotency_durable::AcquireOutcome::DifferentRequest => {
            return Err(AppError::internal(
                "workflow entity-write idempotency key reused with different input — \
                 the same (instance_id, node_id) must always resolve identical data",
            ));
        }
        idempotency_durable::AcquireOutcome::Acquired { record_id } => record_id,
    };

    let org_ref = attome_core::ROOT_ORGANIZATION_ID;
    let user_id = ctx.user_id;

    let (mut tx, mutation) = if matches!(node_type, NodeType::CreateRecord) {
        let mut tx = begin_entity_write(state, instance).await?;
        let mutation = attome_records::entity_mutation::create_one(
            &mut tx,
            state,
            ctx,
            entity_name,
            &meta.attrs,
            &data,
            user_id,
            org_ref,
            attome_records::entity_mutation::MutationMode::Strict,
        )
        .await?;
        (tx, mutation)
    } else {
        match update_by_rule(state, ctx, instance, node, &meta, input, &data, record_id).await? {
            RuleOutcome::Written(tx, mutation) => (tx, mutation),
            RuleOutcome::Paused(outcome) => return Ok(outcome),
        }
    };
    let output = serde_json::json!({ "id": mutation.record_id });
    idempotency_durable::complete_in_tx(
        &mut tx,
        record_id,
        Some(mutation.record_id),
        200,
        &[],
        &serde_json::to_vec(&output).unwrap_or_default(),
    )
    .await
    .map_err(AppError::internal)?;

    // C-10: before this, a workflow Create/Update Record node called
    // `create_one`/`update_one` directly and stopped — no creator-share
    // grant, no audit event, no cache invalidation, no rw-pin. The missing
    // share grant was the concrete, named bug (a record a workflow created
    // was invisible to `instance.started_by`, since nobody ever wrote the
    // `record_share` row `grant_creator_share` exists for); the
    // other three were silent gaps in the same shape. Routing through the
    // ring closes all four at once, the same way every other mutation call
    // site in the workspace now does.
    //
    // `user_context` is a synthetic "Workflow Engine" identity, not a
    // `fetch_audit_ctx` lookup of the real human `instance.started_by`
    // names — same convention `commit_checkpoint`'s own node-run audit
    // events already use just above in this file, and `source:
    // AuditSource::Workflow` matches them too. `org_ref` stays
    // `ROOT_ORGANIZATION_ID`, unchanged from the row's own `organization_ref`
    // column above — the audit event should agree with the row it
    // describes, not the acting principal's unrelated home org.
    let actor = MutationActor {
        acting_user_id: user_id,
        user_context: AuditUserContext {
            user_id,
            user_name: "workflow-engine".to_string(),
            user_display_name: "Workflow Engine".to_string(),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        org_ref,
    };
    let mut audit = MutationAudit::new();
    audit.source = AuditSource::Workflow;
    audit.event_comment = Some(format!(
        "workflow instance {} node {}",
        instance.id, node.id
    ));
    // Captured before `mutation` moves into the ring call below — `&row`
    // would otherwise borrow `mutation` for the same call that also moves
    // it (E0505).
    let row = mutation.new_row.clone();

    MutationRing::new(state)
        .commit_mutation(
            tx,
            ctx,
            meta.entity_id,
            entity_name,
            &meta.attrs,
            &actor,
            if matches!(node_type, NodeType::CreateRecord) {
                AuditOperation::Create
            } else {
                AuditOperation::Update
            },
            MutationSideEffects {
                grant_creator_share: matches!(node_type, NodeType::CreateRecord),
                mirror_file_fields: false,
            },
            GrantInvalidation::ByRow(row.as_ref()),
            audit,
            "workflow entity_input",
            mutation,
        )
        .await?;

    Ok(NodeOutcome::Succeeded { output })
}

fn entity_write_body_hash(data: &serde_json::Map<String, Value>) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_vec(data).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    format!("{:x}", hasher.finalize())
}

async fn execute_send_notification(
    state: &EngineState,
    instance: &InstanceRow,
    node: &GraphNode,
    input: &Value,
    fired: &mut HashSet<String>,
    round: i32,
) -> Result<NodeOutcome, AppError> {
    if fired.contains(&fired_key(&node.id, round)) {
        return Ok(NodeOutcome::Succeeded {
            output: serde_json::json!({ "skipped_replay": true }),
        });
    }
    let template_key = node
        .config
        .get("template_key")
        .and_then(Value::as_str)
        .unwrap_or("workflow.generic")
        .to_string();
    let mut variables: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if let Some(obj) = input.get("variables").and_then(Value::as_object) {
        for (k, v) in obj {
            variables.insert(k.clone(), json_to_display(v));
        }
    }
    let req = attome_notification::dispatch::DispatchRequest {
        template_key: Some(template_key),
        locale: node
            .config
            .get("locale")
            .and_then(Value::as_str)
            .unwrap_or("en")
            .to_string(),
        recipient_user_ref: node
            .config
            .get("recipient_user_ref")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok()),
        is_global: node
            .config
            .get("is_global")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        organization_ref: None,
        channels: None, // REVIEW-2026-09-02 finding #3: inherit the platform default (in_app+email), not an in-app-only override
        subject: node
            .config
            .get("subject")
            .and_then(Value::as_str)
            .map(str::to_string),
        body_html: None,
        body_text: node
            .config
            .get("body_text")
            .and_then(Value::as_str)
            .map(str::to_string),
        route: None,
        variables,
        priority: "normal".to_string(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    let dispatch_id = attome_notification::dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        req,
    )
    .await?;
    fired.insert(fired_key(&node.id, round));
    let _ = instance;
    Ok(NodeOutcome::Succeeded {
        output: serde_json::json!({ "dispatch_id": dispatch_id }),
    })
}

fn json_to_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

const WEBHOOK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// T1-11 (TECHNICAL-DUE-DILIGENCE-2026-08-24 §8, closes finding B12): this
/// node used to dial a bare `reqwest::Client` built with only a timeout — no
/// address screening at all. A workflow's author is an admin-level role, but
/// a lower-trust one than the deployment operator, and `config.url` is
/// whatever that author typed: nothing stopped a workflow from pointing a
/// webhook at `169.254.169.254` (cloud metadata) or an internal-only
/// service and having the platform's own server dial it on a schedule or a
/// trigger. `attome_server::ssrf_guard` is the same guard `attome-webcrawl`'s
/// fetcher uses — screens the resolved address before connecting
/// ([`ssrf_guard::validate_url`]) and again at connect time via
/// `GuardedResolver` so a DNS answer that changes between the two can't slip
/// a private address through (see that module's doc comment). Redirects are
/// disabled by the shared client builder, so a webhook target that answers
/// with a `3xx` fails closed here rather than being followed to
/// somewhere unvalidated.
async fn execute_webhook(
    instance: &InstanceRow,
    node: &GraphNode,
    input: &Value,
    fired: &mut HashSet<String>,
    round: i32,
) -> Result<NodeOutcome, AppError> {
    if fired.contains(&fired_key(&node.id, round)) {
        return Ok(NodeOutcome::Succeeded {
            output: serde_json::json!({ "skipped_replay": true }),
        });
    }
    let url = node
        .config
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::internal(format!("webhook node {:?} missing config.url", node.id))
        })?;
    let url = reqwest::Url::parse(url).map_err(|e| {
        AppError::Validation(format!(
            "webhook node {:?} has an invalid url: {e}",
            node.id
        ))
    })?;
    attome_server::ssrf_guard::validate_url(&url)
        .await
        .map_err(|e| {
            AppError::Validation(format!("webhook node {:?} target rejected: {e}", node.id))
        })?;
    let method = node
        .config
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("POST")
        .to_uppercase();
    let body = input.get("body").cloned().unwrap_or(Value::Null);

    let client = attome_server::ssrf_guard::GuardedClient::new(WEBHOOK_TIMEOUT.as_secs())
        .map_err(AppError::internal)?;
    let request = client
        .request(method.parse().unwrap_or(reqwest::Method::POST), url)
        .map_err(|e| {
            AppError::Validation(format!("webhook node {:?} target rejected: {e}", node.id))
        })?
        .header("Idempotency-Key", effect_key(instance.id, &node.id, round))
        .json(&body);
    let response = request.send().await.map_err(AppError::internal)?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(AppError::internal(format!(
            "webhook returned status {status}"
        )));
    }
    fired.insert(fired_key(&node.id, round));
    Ok(NodeOutcome::Succeeded {
        output: serde_json::json!({ "status": status }),
    })
}

/// D-421 / M10 — before falling back to this node's own
/// `action_type`/`ttl_hours` config (the original, still-supported
/// behavior), checks for an active `approval_policy` matching
/// `action_type` and, if one exists, submits through it instead
/// (`attome_approval::submit_with_plan`) — the multi-step/n-of-m/delegation
/// machinery becomes available to a workflow approval node with no change
/// to the node's own config shape, the same "one hook, every gate()-backed
/// flow gets it automatically" wiring `attome_audit::approval::gate` uses for
/// retention/dashboards/schema/etc. A workflow node calls
/// `attome_approval::submit`/`submit_with_plan` directly rather than going
/// through `gate()` itself because a workflow Approval node is not
/// config-gated at all — reaching this node in the graph already means
/// approval is required, unlike `gate()`'s callers, which ask "is this
/// action_type gated right now."
async fn execute_approval(
    state: &EngineState,
    instance: &InstanceRow,
    node: &GraphNode,
    input: &Value,
) -> Result<NodeOutcome, AppError> {
    let action_type = node
        .config
        .get("action_type")
        .and_then(Value::as_str)
        .unwrap_or("workflow.approval");
    let ttl_hours = node
        .config
        .get("ttl_hours")
        .and_then(Value::as_i64)
        .unwrap_or(72);
    // `ttl_hours` is admin-authored node config, and chrono's
    // `Duration::hours` panics out of range: refuse it instead (BAP-16).
    let ttl = chrono::Duration::try_hours(ttl_hours).ok_or_else(|| {
        AppError::Validation(format!(
            "approval node {} has an out-of-range ttl_hours ({ttl_hours})",
            node.id
        ))
    })?;
    let payload = serde_json::json!({
        "instance_id": instance.id,
        "node_id": node.id,
        "input": input,
    });
    let requested_by = instance.started_by.unwrap_or(Uuid::nil());

    // M45 Phase 3 (REVIEW-2026-09-02 finding #8): a policy whose `condition`
    // does not permit this specific `payload` is treated as "no policy
    // matched", same fallback `attome_audit::approval::gate` applies.
    let policy = attome_audit::approval::find_matching_policy(&state.base.db, action_type)
        .await?
        .filter(|p| attome_audit::approval::condition_permits(p.condition.as_deref(), &payload));
    let request = if let Some(policy) = policy {
        let backstop_ttl = attome_audit::approval::plan_backstop_ttl(&policy.plan);
        attome_approval::submit_with_plan(
            &state.base.db,
            action_type,
            payload,
            requested_by,
            policy.plan,
            backstop_ttl,
            Some(policy.id),
        )
        .await?
    } else {
        attome_approval::submit(&state.base.db, action_type, payload, requested_by, 1, ttl).await?
    };

    Ok(NodeOutcome::Waiting {
        match_type: "signal",
        entity_logicalname: None,
        condition: Some(
            serde_json::json!({ "kind": "approval", "approval_request_id": request.id }),
        ),
        resume_at: None,
        eventual_output: serde_json::json!({ "approval_request_id": request.id }),
    })
}

/// M32 Phase 1 (AI Agent Platform, D-450). **Deliberately minimal — invoke,
/// then complete.** Starts a session from `config.agent_definition_ref`
/// through `attome_ai::agent::start_session`, the SAME function this
/// crate's own HTTP route calls (see that module's doc comment for why
/// reusing it, rather than re-parsing the definition's fields here, is the
/// point). Does not yet run a real multi-turn tool loop against the session —
/// no generic write-capable loop exists anywhere in this workspace yet (only
/// `attome_ai::chat`'s read-only bot loop, which this deliberately is not).
/// `task`/`step_budget` are threaded through into the node's output
/// unconsumed, ready for a future phase to act on behind the same session id
/// without changing this node's config/port contract.
///
/// Fired-marker guarded, same pattern as `execute_send_notification`/
/// `execute_webhook` immediately above and below this function in the file:
/// a crash-replay of this node must not open a second session for one
/// logical step.
async fn execute_agent_step(
    state: &EngineState,
    ctx: &std::sync::Arc<SecurityContext>,
    node: &GraphNode,
    input: &Value,
    fired: &mut HashSet<String>,
    round: i32,
) -> Result<NodeOutcome, AppError> {
    if fired.contains(&fired_key(&node.id, round)) {
        return Ok(NodeOutcome::Succeeded {
            output: serde_json::json!({ "skipped_replay": true }),
        });
    }
    let definition_ref = node
        .config
        .get("agent_definition_ref")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            AppError::Validation(format!(
                "agent_step node {:?} has a missing or invalid config.agent_definition_ref",
                node.id
            ))
        })?;
    // Bounds how many tool-loop steps a future phase's real invocation may
    // take — recorded now, enforced once that loop exists. A generous
    // default (`turn::MAX_TOOL_STEPS`'s own six-step reasoning: enough for a
    // genuine multi-hop task, short enough that a looping model costs
    // seconds rather than minutes) so an author who has not thought about it
    // still gets a bounded default rather than an unbounded one.
    let step_budget = node
        .config
        .get("step_budget")
        .and_then(Value::as_u64)
        .unwrap_or(u64::from(attome_ai::turn::MAX_TOOL_STEPS as u32));
    let task = input.get("task").cloned().unwrap_or(Value::Null);

    // M33 Phase 1 (D-460): the structured handoff payload, if this step is
    // downstream of another `AgentStep` (wired through the `handoff` port —
    // see `node_types.rs`'s doc comment for why that is a SEPARATE port from
    // `task`, never the same one). Whatever the upstream node produced —
    // record ids, decision ids, its own `outcome` object — passes through
    // verbatim; this function never inspects or rewrites it beyond reading
    // `tainted` below, so it can never grow into a place that smuggles raw
    // transcript through under a different key.
    let handoff = input.get("handoff").cloned();

    // **Taint does not propagate as trust across a handoff.** If the
    // upstream step that produced this `handoff` was itself tainted (I-10:
    // its own task/handoff carried tool-obtained content), OR the graph
    // author has explicitly marked this step's own input as tainted
    // (`config.tainted_input` — for a step fed directly from a Trigger's
    // entity snapshot or a Webhook body, neither of which flows through
    // another AgentStep's `handoff`), the session THIS step starts must
    // start tainted too. A structured, ids-only payload is not a trust
    // boundary — it is exactly the same untrusted content in a narrower
    // shape, and `ActionContext::for_session` (attome-ai) is what turns
    // this flag back into a real gate decision the moment a future phase's
    // tool loop tries to write anything under this session.
    let upstream_tainted = handoff
        .as_ref()
        .and_then(|h| h.get("tainted"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let declared_tainted = node
        .config
        .get("tainted_input")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let tainted = upstream_tainted || declared_tainted;

    // D-503 §3: the session's constraints are the published node's own —
    // resolved by the same function publish-time escalation review used, so
    // the session cannot run wider than the ceiling a reviewer approved.
    let constraints = attome_ai::agent::SessionConstraints {
        risk_ceiling: crate::node_types::agent_step_risk_ceiling(&node.config),
        allowed_action_ids: crate::node_types::agent_step_allowed_action_ids(&node.config)
            .map_err(|e| AppError::Validation(format!("agent_step node {:?}: {e}", node.id)))?,
    };
    let session = attome_ai::agent::start_session(
        state,
        ctx,
        definition_ref,
        "workflow",
        constraints,
        tainted,
    )
    .await?;

    fired.insert(fired_key(&node.id, round));
    Ok(NodeOutcome::Succeeded {
        output: serde_json::json!({
            "session_id": session.id,
            "agent_definition_ref": definition_ref,
            "step_budget": step_budget,
            "task": task,
            "handoff": handoff,
            "tainted": tainted,
            "status": "session_started",
        }),
    })
}

/// M33 Phase 1 (D-460): `Route` — picks a downstream branch via the
/// read-only `route.classify` action rather than a rule engine (M45 does not
/// exist). Two fixed output ports, same "declining is a valid answer" shape
/// `record.classify`'s `NO_CLASSIFICATION` establishes: `matched` when the
/// model picked one of `config.routes`, `unmatched` when it declined. A
/// graph author composes an actual multi-way choice by chaining `Condition`
/// nodes downstream of `matched` on the returned `route` label — `Route`
/// itself only ever branches two ways (see `node_types.rs`'s doc comment on
/// why the output-port table cannot express graph-instance-specific dynamic
/// branch names).
///
/// Unlike `execute_agent_step`, this genuinely dispatches through
/// `attome_ai::dispatch` — the real gate, the real license/kill-switch
/// check, the real registry — because `route.classify` is a single Read-tier
/// call with no session to start. `surface: WorkflowNodes`, not the generic
/// per-module default `Fields` the HTTP `/actions/{id}/invoke` route derives
/// (`attome_ai::engine::surface_for`): this call genuinely originates from
/// an AI node inside a workflow, which is the surface `AiEnablement`'s own
/// doc comment names for exactly this case, and choosing it here (rather
/// than touching the shared HTTP-route mapping) keeps that generic mapping
/// unaffected for the actions it already serves correctly.
async fn execute_route(
    state: &EngineState,
    ctx: &std::sync::Arc<SecurityContext>,
    node: &GraphNode,
    input: &Value,
) -> Result<NodeOutcome, AppError> {
    let routes: Vec<String> = node
        .config
        .get("routes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if routes.is_empty() {
        return Err(AppError::Validation(format!(
            "route node {:?} has no configured config.routes",
            node.id
        )));
    }
    let context = input.get("context").cloned().unwrap_or(Value::Null);
    let purpose = node
        .config
        .get("purpose")
        .and_then(Value::as_str)
        .map(str::to_owned);

    let args = serde_json::json!({
        "context": context,
        "routes": routes,
        "purpose": purpose,
    });

    let action_ctx = attome_ai::ActionContext::user(std::sync::Arc::clone(ctx));
    let registry = attome_ai::ActionRegistry::new();
    let executors = attome_ai::Executors::new();
    let gate_inputs = attome_ai::GateInputs {
        licensed: state
            .modules
            .load()
            .has(attome_ai::actions::route_classify::descriptor().module),
        ai: &state.base.config.inference.ai,
        surface: Some(attome_config::AiSurface::WorkflowNodes),
        external_effects_enabled: state.base.config.security.external_effects_enabled,
    };

    match attome_ai::dispatch(
        state,
        &registry,
        &executors,
        attome_ai::actions::route_classify::ROUTE_CLASSIFY,
        &action_ctx,
        &gate_inputs,
        &args,
    )
    .await?
    {
        attome_ai::ActionOutcome::Completed { result, .. } => {
            let applies = result
                .get("applies")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if applies {
                Ok(NodeOutcome::Branch {
                    taken_port: "matched",
                    output: result,
                })
            } else {
                Ok(NodeOutcome::Branch {
                    taken_port: "unmatched",
                    output: result,
                })
            }
        }
        // `route.classify` is Read-tier and `Initiator::User` here (the
        // system principal that drives the whole pass, same as every other
        // node — see `system_security_context`), so the gate's matrix
        // (`gate.rs`) can only ever return `Execute` for it once dispatch
        // gets this far — a refusal surfaces as `Err` above via `?`, never
        // as one of these two variants. Kept as a hard error rather than
        // silently routing to `unmatched`, so a misconfiguration (AI
        // disabled, unlicensed) fails the instance loudly instead of being
        // indistinguishable from "the model declined".
        attome_ai::ActionOutcome::ConfirmationRequired { .. }
        | attome_ai::ActionOutcome::ApprovalRequired { .. }
        | attome_ai::ActionOutcome::Scheduled { .. }
        | attome_ai::ActionOutcome::AwaitingReview { .. } => Err(AppError::internal(
            "route.classify is Read-tier and must never require confirmation, approval or an undo window",
        )),
    }
}

/// M10-T3: when a wait of `seconds` that starts at `base` ends: on the
/// business calendar (`business_time`; `calendar_id`, else the deployment's
/// default) or by the clock.
async fn wait_until(
    state: &EngineState,
    node: &GraphNode,
    base: DateTime<Utc>,
    seconds: i64,
) -> Result<DateTime<Utc>, AppError> {
    let duration = chrono::Duration::try_seconds(seconds.max(0))
        .ok_or_else(|| AppError::Validation(format!("node {:?}: the wait is too long", node.id)))?;
    if !node
        .config
        .get("business_time")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(base + duration);
    }
    let calendar_id = match node.config.get("calendar_id").and_then(Value::as_str) {
        Some(raw) => Some(Uuid::parse_str(raw).map_err(|_| {
            AppError::Validation(format!("node {:?}: calendar_id is not an id", node.id))
        })?),
        None => attome_core::calendar::default_calendar_id(&state.base.db).await?,
    };
    let Some(calendar_id) = calendar_id else {
        return Err(AppError::Validation(format!(
            "node {:?} waits in business time but names no calendar and the deployment has no default",
            node.id
        )));
    };
    let loaded = attome_core::calendar::load_calendar(&state.base.db, calendar_id)
        .await?
        .map_err(|e| {
            AppError::Validation(format!("node {:?}: calendar unusable: {e:?}", node.id))
        })?;
    loaded
        .calendar
        .add_business_duration(base, duration)
        .map_err(|e| AppError::Validation(format!("node {:?}: {e}", node.id)))
}

/// M10-T3: the time a wait counts from: the record field named by
/// `config.relative_to` in the wired input (`in.<field>`, or
/// `in.record.<field>` for a trigger that carries the record), else `now`.
pub(crate) fn wait_base(config: &Value, input: &Value, now: DateTime<Utc>) -> DateTime<Utc> {
    let Some(field) = config.get("relative_to").and_then(Value::as_str) else {
        return now;
    };
    let wired = input.get("in");
    wired
        .and_then(|v| v.get(field))
        .or_else(|| {
            wired
                .and_then(|v| v.get("record"))
                .and_then(|r| r.get(field))
        })
        .and_then(Value::as_str)
        .and_then(|raw| {
            DateTime::parse_from_rfc3339(raw)
                .map(|d| d.with_timezone(&Utc))
                .ok()
                .or_else(|| {
                    chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d")
                        .ok()
                        .and_then(|d| d.and_hms_opt(0, 0, 0))
                        .map(|d| d.and_utc())
                })
        })
        .unwrap_or(now)
}

async fn execute_wait(
    state: &EngineState,
    node: &GraphNode,
    input: &Value,
) -> Result<NodeOutcome, AppError> {
    let resume_at = if let Some(iso) = node.config.get("resume_at").and_then(Value::as_str) {
        DateTime::parse_from_rfc3339(iso)
            .ok()
            .map(|d| d.with_timezone(&Utc))
    } else {
        let seconds = node
            .config
            .get("delay_seconds")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let base = wait_base(&node.config, input, Utc::now());
        Some(wait_until(state, node, base, seconds).await?)
    };
    Ok(NodeOutcome::Waiting {
        match_type: "schedule",
        entity_logicalname: None,
        condition: None,
        resume_at,
        eventual_output: Value::Null,
    })
}

/// M10-T3: with `config.timeout_seconds` (in business time when
/// `business_time`), the wait also ends when that time passes; the sweep
/// then resumes it with `{"timed_out": true}` and the node takes its
/// `timeout` port instead of `event`.
async fn execute_wait_for_event(
    state: &EngineState,
    node: &GraphNode,
    input: &Value,
) -> Result<NodeOutcome, AppError> {
    let entity_logicalname = node
        .config
        .get("entity_logicalname")
        .and_then(Value::as_str)
        .map(str::to_string);
    let condition = node.config.get("condition").cloned();
    let resume_at = match node.config.get("timeout_seconds").and_then(Value::as_i64) {
        Some(seconds) => {
            let base = wait_base(&node.config, input, Utc::now());
            Some(wait_until(state, node, base, seconds).await?)
        }
        None => None,
    };
    Ok(NodeOutcome::Waiting {
        match_type: "entity_event",
        entity_logicalname,
        condition,
        resume_at,
        eventual_output: Value::Null,
    })
}

/// M10-T3: the port a resumed `wait_for_event` takes.
pub(crate) fn wait_for_event_taken_port(output: Option<&Value>) -> &'static str {
    if output
        .and_then(|v| v.get("timed_out"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        "timeout"
    } else {
        "event"
    }
}

/// M1-T4: the largest batch a for-each hands one run.
pub(crate) const MAX_FOR_EACH_BATCH: usize = 100;

/// §8 risk ("sub-workflow recursion... an ancestor definition, infinite
/// nesting"): a runtime depth cap, not a static publish-time ancestry-graph
/// walk. A cycle across two definitions (A's sub_workflow points to B, B's
/// sub_workflow points back to A) can't be fully ruled out at publish time
/// anyway — B can be edited/republished to point back at A *after* A->B was
/// validated as fine, since a definition's graph isn't frozen the way a
/// migration is — so the actual, robust mitigation is bounding how deep the
/// chain of real child instances is allowed to go, checked at the one place
/// that's always current: instance start. This does not stack-overflow
/// either way (each child starts via its own apalis job, not a nested
/// synchronous call), so without this cap the failure mode would be
/// unboundedly many instances accumulating over time, not a crash — this
/// cap turns that into a clean, immediate validation error instead.
/// `admin.rs`'s publish-time direct-self-reference check catches the most
/// common authoring mistake (a definition pointing at itself) immediately;
/// this catches every other cycle length, plus simple runaway fan-out.
async fn execute_sub_workflow(
    state: &EngineState,
    instance: &InstanceRow,
    node: &GraphNode,
    input: &Value,
) -> Result<NodeOutcome, AppError> {
    let logicalname = node
        .config
        .get("definition_logicalname")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::internal(format!("sub_workflow node {:?} missing config", node.id))
        })?;

    let depth = nesting_depth(state, instance, node)?;
    let version_id = published_version(state, logicalname).await?;

    let child_context = serde_json::json!({
        "input": input.get("input").cloned().unwrap_or(Value::Null),
        "parent_instance_id": instance.id,
        "parent_node_id": node.id,
        "workflow_depth": depth + 1,
    });
    let child_id = crate::instance_admin::start_instance_internal(
        state,
        version_id,
        None,
        instance.started_by,
        None,
        child_context,
    )
    .await?;

    Ok(NodeOutcome::Waiting {
        match_type: "signal",
        entity_logicalname: None,
        condition: Some(
            serde_json::json!({ "kind": "sub_workflow", "child_instance_id": child_id }),
        ),
        resume_at: None,
        eventual_output: serde_json::json!({ "child_instance_id": child_id }),
    })
}

/// The run's nesting depth, refused at `limits.workflow.max_nesting` (M1-T4;
/// before it, a fixed 20) — likely a cycle between flow definitions.
fn nesting_depth(
    state: &EngineState,
    instance: &InstanceRow,
    node: &GraphNode,
) -> Result<i64, AppError> {
    let depth = instance
        .context
        .get("workflow_depth")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let max_depth = run_limit(state, "workflow.max_nesting");
    if depth >= max_depth {
        return Err(AppError::Validation(format!(
            "sub-workflow nesting exceeded the maximum depth ({max_depth}, \
             limits.workflow.max_nesting) — likely a cycle between workflow definitions (node {:?})",
            node.id
        )));
    }
    Ok(depth)
}

async fn published_version(state: &EngineState, logicalname: &str) -> Result<Uuid, AppError> {
    sqlx::query_scalar(
        "SELECT v.id FROM workflow_definition_version v \
         JOIN workflow_definition d ON d.id = v.definition_id \
         WHERE d.logicalname = $1 AND v.status = 'published' AND d.is_active = TRUE AND d.is_deleted = FALSE",
    )
    .bind(logicalname)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| AppError::Validation(format!("sub-workflow {logicalname:?} has no published version")))
}

/// M1-T4: the items a for-each goes through: the wired `items` array, a
/// single value as a list of one, nothing as an empty list.
pub(crate) fn for_each_items(input: &Value) -> Vec<Value> {
    match input.get("items") {
        Some(Value::Array(items)) => items.clone(),
        Some(Value::Null) | None => Vec::new(),
        Some(other) => vec![other.clone()],
    }
}

/// M1-T4: `config.batch_size`, 1 to [`MAX_FOR_EACH_BATCH`] (the default).
pub(crate) fn for_each_batch_size(config: &Value) -> usize {
    config
        .get("batch_size")
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(MAX_FOR_EACH_BATCH)
        .clamp(1, MAX_FOR_EACH_BATCH)
}

/// M1-T4: what a for-each reports once every batch run ended, or `None`
/// while one is still going (or not yet visible).
pub(crate) fn for_each_summary(statuses: &[String], batch_count: usize) -> Option<Value> {
    if statuses.len() < batch_count
        || statuses
            .iter()
            .any(|s| !matches!(s.as_str(), "completed" | "failed" | "cancelled"))
    {
        return None;
    }
    let count = |status: &str| statuses.iter().filter(|s| *s == status).count();
    Some(serde_json::json!({
        "batch_count": batch_count,
        "completed": count("completed"),
        "failed": count("failed"),
        "cancelled": count("cancelled"),
    }))
}

/// M1-T4: starts one run of the named flow per batch of the items and
/// waits until they all ended ([`resume_parent_after_sub_workflow`] resumes
/// this node with [`for_each_summary`] once the last one does).
async fn execute_for_each(
    state: &EngineState,
    instance: &InstanceRow,
    node: &GraphNode,
    input: &Value,
) -> Result<NodeOutcome, AppError> {
    let logicalname = node
        .config
        .get("definition_logicalname")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::Validation(format!("for_each node {:?} names no flow", node.id))
        })?;
    let items = for_each_items(input);
    let max_items = run_limit(state, "workflow.max_loop_items");
    if i64::try_from(items.len()).unwrap_or(i64::MAX) > max_items {
        return Err(AppError::Validation(format!(
            "for_each node {:?}: {} items is more than {max_items} (limits.workflow.max_loop_items)",
            node.id,
            items.len()
        )));
    }
    if items.is_empty() {
        return Ok(NodeOutcome::Succeeded {
            output: serde_json::json!({
                "batch_count": 0, "completed": 0, "failed": 0, "cancelled": 0,
                "child_instance_ids": [],
            }),
        });
    }
    let depth = nesting_depth(state, instance, node)?;
    let version_id = published_version(state, logicalname).await?;
    let batches: Vec<&[Value]> = items.chunks(for_each_batch_size(&node.config)).collect();
    let batch_count = batches.len();
    let mut children = Vec::with_capacity(batch_count);
    for (batch_index, batch) in batches.into_iter().enumerate() {
        let context = serde_json::json!({
            "input": { "items": batch, "batch_index": batch_index, "batch_count": batch_count },
            "parent_instance_id": instance.id,
            "parent_node_id": node.id,
            "workflow_depth": depth + 1,
        });
        children.push(
            crate::instance_admin::start_instance_internal(
                state,
                version_id,
                None,
                instance.started_by,
                None,
                context,
            )
            .await?,
        );
    }
    Ok(NodeOutcome::Waiting {
        match_type: "signal",
        entity_logicalname: None,
        condition: Some(serde_json::json!({ "kind": "for_each", "child_instance_ids": children })),
        resume_at: None,
        eventual_output: serde_json::json!({
            "child_instance_ids": children,
            "batch_count": batch_count,
        }),
    })
}

/// Generic wait-node resume: flips one `waiting` `node_run` to `succeeded`,
/// records its resolved output, deletes its `trigger_index` wait row, and
/// re-enqueues `WorkflowExecute` — all in one transaction, so the next pass
/// can only ever see a fully-resumed state. Used by `sla_sweep` (schedule
/// waits, and — since `attome_approval` has no push/callback of its own —
/// polled approval waits) and by a future explicit signal endpoint for
/// `WaitForEvent`.
pub async fn resume_node(
    state: &EngineState,
    instance_id: Uuid,
    node_id: &str,
    node_run_id: Uuid,
    output: Value,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let rows = sqlx::query(
        "UPDATE workflow_node_run SET status = 'succeeded', completed_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND status = 'waiting'",
    )
    .bind(node_run_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if rows == 0 {
        // Already resumed by a concurrent sweep/signal — not an error.
        tx.rollback().await.ok();
        return Ok(());
    }

    sqlx::query(
        "UPDATE workflow_instance \
         SET node_data = jsonb_set(node_data, ARRAY[$2], $3::jsonb), row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(instance_id)
    .bind(node_id)
    .bind(&output)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    trigger_index::delete_wait_row(&mut tx, node_run_id)
        .await
        .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::WorkflowExecute { instance_id },
    )
    .await
    .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

/// F095 backoff resume: flips a `waiting`, `kind: "retry"` `node_run` back
/// to `pending` (not `succeeded` — this is not a cached replay, the node
/// re-executes for real on the next pass) so `ready_nodes` picks it up
/// again. Separate from `resume_node` because the state transition and
/// meaning are genuinely different, not just a different output value.
pub async fn resume_retry(
    state: &EngineState,
    instance_id: Uuid,
    node_run_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let rows = sqlx::query(
        "UPDATE workflow_node_run SET status = 'pending', row_version = row_version + 1 \
         WHERE id = $1 AND status = 'waiting'",
    )
    .bind(node_run_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if rows == 0 {
        tx.rollback().await.ok();
        return Ok(());
    }
    // Bump the instance row so a pass that loaded this node as `waiting`
    // before this resume committed cannot checkpoint over it: its
    // `row_version` CAS fails, the checkpoint is discarded, and
    // `execute_instance` re-enqueues — the only thing that keeps this node
    // from being stranded when the job enqueued below is skipped by that
    // pass's still-held `ExecutionClaim`. `resume_node` and
    // `resume_parent_after_sub_workflow` already bump through their
    // `node_data` writes; this path had no instance write of its own.
    sqlx::query("UPDATE workflow_instance SET row_version = row_version + 1 WHERE id = $1")
        .bind(instance_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    trigger_index::delete_wait_row(&mut tx, node_run_id)
        .await
        .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::WorkflowExecute { instance_id },
    )
    .await
    .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

/// Called from a completed/failed child instance's own checkpoint commit
/// path (`instance_admin`) when its `context.parent_instance_id` is set —
/// resumes the parent's `sub_workflow` node_run and re-enqueues it.
pub(crate) async fn resume_parent_after_sub_workflow(
    state: &EngineState,
    parent_instance_id: Uuid,
    parent_node_id: &str,
    child_instance_id: Uuid,
    child_status: &str,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // `FOR UPDATE`: two batch runs of one for-each ending together resume
    // it once (M1-T4).
    let node_run_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM workflow_node_run \
         WHERE instance_id = $1 AND node_id = $2 AND status = 'waiting' FOR UPDATE",
    )
    .bind(parent_instance_id)
    .bind(parent_node_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(node_run_id) = node_run_id else {
        tx.rollback().await.ok();
        return Ok(());
    };

    // A for-each's waiting output lists its batch runs; it resumes only
    // when the last of them ended.
    let waiting: Option<Value> =
        sqlx::query_scalar("SELECT node_data -> $2 FROM workflow_instance WHERE id = $1")
            .bind(parent_instance_id)
            .bind(parent_node_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .flatten();
    let batch_runs: Option<Vec<Uuid>> = waiting
        .as_ref()
        .and_then(|w| w.get("child_instance_ids"))
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .filter_map(|id| Uuid::parse_str(id).ok())
                .collect()
        });
    let output = match batch_runs {
        Some(ids) => {
            let statuses: Vec<String> =
                sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = ANY($1)")
                    .bind(&ids)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
            let Some(mut summary) = for_each_summary(&statuses, ids.len()) else {
                tx.rollback().await.ok();
                return Ok(());
            };
            summary["child_instance_ids"] = serde_json::json!(ids);
            summary
        }
        None => {
            serde_json::json!({ "child_instance_id": child_instance_id, "status": child_status })
        }
    };

    sqlx::query(
        "UPDATE workflow_node_run SET status = 'succeeded', completed_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(node_run_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    sqlx::query(
        "UPDATE workflow_instance \
         SET node_data = jsonb_set(node_data, ARRAY[$2], $3::jsonb), row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(parent_instance_id)
    .bind(parent_node_id)
    .bind(&output)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    trigger_index::delete_wait_row(&mut tx, node_run_id)
        .await
        .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::WorkflowExecute {
            instance_id: parent_instance_id,
        },
    )
    .await
    .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

#[cfg(test)]
mod webhook_ssrf_tests {
    //! T1-11 (TECHNICAL-DUE-DILIGENCE-2026-08-24 §8, closes finding B12):
    //! `execute_webhook` used to dial whatever `config.url` said with a bare
    //! `reqwest::Client` — no address screening. These are unit tests, not
    //! DB-backed integration tests (`execute_webhook` needs no `EngineState`),
    //! and they need no live network either: a URL whose host is an IP
    //! literal is rejected at the pre-flight `ssrf_guard::validate_url` call
    //! before any socket opens, matching exactly what `attome_server::
    //! ssrf_guard`'s own tests already prove about that call in isolation
    //! (`validate_url_rejects_a_loopback_ip_literal`). What is new here is
    //! that a workflow Webhook node definition pointing at a private/
    //! link-local/metadata address is refused through this crate's actual
    //! node-execution path, not just at the shared guard's boundary.
    use super::*;

    fn webhook_node(url: &str) -> GraphNode {
        GraphNode {
            id: "w".into(),
            node_type: "webhook".into(),
            config: serde_json::json!({ "url": url, "method": "POST" }),
            ports: serde_json::Value::Null,
        }
    }

    fn dummy_instance() -> InstanceRow {
        InstanceRow {
            id: Uuid::now_v7(),
            definition_version_id: Uuid::now_v7(),
            status: "running".into(),
            started_by: None,
            context: serde_json::json!({}),
            node_data: serde_json::json!({}),
            fired_side_effects: serde_json::json!([]),
            row_version: 0,
        }
    }

    async fn webhook_rejected(url: &str) -> String {
        let instance = dummy_instance();
        let node = webhook_node(url);
        let mut fired = HashSet::new();
        let err = execute_webhook(&instance, &node, &serde_json::json!({}), &mut fired, 0)
            .await
            .expect_err("a non-routable webhook target must be rejected, not dialed");
        assert!(
            fired.is_empty(),
            "a rejected webhook must never be recorded as fired"
        );
        err.to_string()
    }

    /// The finding's own example: the cloud metadata address.
    #[tokio::test]
    async fn webhook_to_cloud_metadata_address_is_rejected() {
        let msg = webhook_rejected("http://169.254.169.254/latest/meta-data/").await;
        assert!(msg.contains("target rejected"), "unexpected error: {msg}");
    }

    /// Loopback — the other classic SSRF pivot (a service bound to
    /// 127.0.0.1 that trusts same-host callers).
    #[tokio::test]
    async fn webhook_to_loopback_is_rejected() {
        let msg = webhook_rejected("http://127.0.0.1:1/admin").await;
        assert!(msg.contains("target rejected"), "unexpected error: {msg}");
    }

    /// RFC1918 private space — an internal service the workflow author has
    /// no business reaching from a webhook node.
    #[tokio::test]
    async fn webhook_to_private_rfc1918_address_is_rejected() {
        let msg = webhook_rejected("http://10.0.0.5/internal-api").await;
        assert!(msg.contains("target rejected"), "unexpected error: {msg}");
    }

    /// A same-node regression guard: the config-missing-url path must still
    /// return its own distinct error, not be swallowed by the new
    /// validation step.
    #[tokio::test]
    async fn webhook_with_no_url_still_reports_the_original_error() {
        let instance = dummy_instance();
        let mut node = webhook_node("http://example.invalid/");
        node.config = serde_json::json!({});
        let mut fired = HashSet::new();
        let err = execute_webhook(&instance, &node, &serde_json::json!({}), &mut fired, 0)
            .await
            .expect_err("missing config.url must still be an error");
        // `AppError::Internal`'s `Display` is deliberately masked to a fixed
        // "internal error" string (attome-types/src/error.rs) so the original
        // message never leaks through an incidental `.to_string()` call —
        // match the variant's own field instead of the masked message.
        match err {
            AppError::Internal(msg) => {
                assert!(
                    msg.contains("missing config.url"),
                    "unexpected internal error message: {msg}"
                );
            }
            other => panic!("expected AppError::Internal, got: {other:?}"),
        }
    }
}

#[cfg(test)]
mod effect_key_tests {
    use super::*;

    #[test]
    fn round_zero_keeps_the_key_runs_had_before_rounds() {
        let run = Uuid::from_u128(1);
        assert_eq!(
            effect_key(run, "n1", 0),
            "00000000-0000-0000-0000-000000000001:n1"
        );
        assert_eq!(fired_key("n1", 0), "n1");
    }

    #[test]
    fn each_loop_round_is_its_own_effect() {
        let run = Uuid::from_u128(1);
        let keys: HashSet<String> = (0..3).map(|r| effect_key(run, "n1", r)).collect();
        assert_eq!(keys.len(), 3, "a later round never replays an earlier one");
        assert_ne!(fired_key("n1", 1), fired_key("n1", 2));
        assert_ne!(
            effect_key(run, "n1", 1),
            effect_key(Uuid::from_u128(2), "n1", 1),
            "runs never share a key"
        );
    }
}

#[cfg(test)]
mod join_split_tests {
    //! M06 checklist item 1: `Join`'s `all`/`any`/`n_of_m` readiness gate —
    //! pure logic over `ready_nodes`/`join_mode_and_threshold`, no database
    //! needed (unlike most of this crate's execution tests, which need a
    //! throwaway Postgres for the checkpoint write — see `tests/execution.rs`
    //! for an end-to-end `Split` -> parallel branches -> `Join` instance run).
    use super::*;
    use crate::graph::{Graph, GraphEdge, GraphNode};

    fn node(id: &str, ty: &str, config: Value) -> GraphNode {
        GraphNode {
            id: id.into(),
            node_type: ty.into(),
            config,
            ports: Value::Null,
        }
    }

    fn edge(from_node: &str, to_node: &str) -> GraphEdge {
        GraphEdge {
            from_node: from_node.into(),
            from_port: "out".into(),
            to_node: to_node.into(),
            to_port: "in".into(),
        }
    }

    /// `t -> [a, b, c] -> j`, with `a`/`b`/`c` each independently settled to
    /// `succeeded` or left pending by the caller.
    fn three_branch_graph(join_config: Value) -> Graph {
        Graph {
            nodes: vec![
                node("t", "trigger", serde_json::json!({})),
                node("a", "wait", serde_json::json!({})),
                node("b", "wait", serde_json::json!({})),
                node("c", "wait", serde_json::json!({})),
                node("j", "join", join_config),
            ],
            edges: vec![
                edge("t", "a"),
                edge("t", "b"),
                edge("t", "c"),
                edge("a", "j"),
                edge("b", "j"),
                edge("c", "j"),
            ],
        }
    }

    fn succeeded(node_id: &str) -> (String, NodeRunState) {
        let mut nr = new_node_run_state(node_id);
        nr.status = "succeeded".into();
        (node_id.to_string(), nr)
    }

    fn node_data_for(settled: &[&str]) -> serde_json::Map<String, Value> {
        settled
            .iter()
            .map(|id| (id.to_string(), Value::Bool(true)))
            .collect()
    }

    #[test]
    fn join_mode_defaults_to_all() {
        assert_eq!(
            join_mode_and_threshold(&serde_json::json!({}), 3),
            ("all", 3)
        );
    }

    #[test]
    fn join_mode_any_always_needs_exactly_one() {
        assert_eq!(
            join_mode_and_threshold(&serde_json::json!({ "mode": "any" }), 5),
            ("any", 1)
        );
    }

    #[test]
    fn join_mode_n_of_m_clamps_into_range() {
        assert_eq!(
            join_mode_and_threshold(&serde_json::json!({ "mode": "n_of_m", "n": 2 }), 5),
            ("n_of_m", 2)
        );
        // A threshold above the branch count is clamped down to it, not left
        // impossible to satisfy.
        assert_eq!(
            join_mode_and_threshold(&serde_json::json!({ "mode": "n_of_m", "n": 99 }), 3),
            ("n_of_m", 3)
        );
        // Zero/negative is clamped up to 1, not treated as "already done".
        assert_eq!(
            join_mode_and_threshold(&serde_json::json!({ "mode": "n_of_m", "n": 0 }), 3),
            ("n_of_m", 1)
        );
    }

    #[test]
    fn join_all_is_not_ready_until_every_branch_settles() {
        let graph = three_branch_graph(serde_json::json!({ "mode": "all" }));
        let mut runs: HashMap<String, NodeRunState> = [succeeded("a"), succeeded("b")].into();
        let data = node_data_for(&["a", "b"]);
        assert!(
            !ready_nodes(&graph, &runs, &data).contains(&"j".to_string()),
            "all-mode join must wait for the third branch"
        );
        runs.extend([succeeded("c")]);
        let data = node_data_for(&["a", "b", "c"]);
        assert!(
            ready_nodes(&graph, &runs, &data).contains(&"j".to_string()),
            "all-mode join must fire once every branch has settled"
        );
    }

    #[test]
    fn join_any_fires_after_the_first_settled_branch() {
        let graph = three_branch_graph(serde_json::json!({ "mode": "any" }));
        let runs: HashMap<String, NodeRunState> = [succeeded("a")].into();
        let data = node_data_for(&["a"]);
        assert!(
            ready_nodes(&graph, &runs, &data).contains(&"j".to_string()),
            "any-mode join must fire after just one branch settles"
        );
    }

    #[test]
    fn join_n_of_m_fires_only_once_threshold_is_met() {
        let graph = three_branch_graph(serde_json::json!({ "mode": "n_of_m", "n": 2 }));
        let mut runs: HashMap<String, NodeRunState> = [succeeded("a")].into();
        let data = node_data_for(&["a"]);
        assert!(
            !ready_nodes(&graph, &runs, &data).contains(&"j".to_string()),
            "n_of_m(2) join must not fire after only one of three branches"
        );
        runs.extend([succeeded("b")]);
        let data = node_data_for(&["a", "b"]);
        assert!(
            ready_nodes(&graph, &runs, &data).contains(&"j".to_string()),
            "n_of_m(2) join must fire once its threshold is met, without waiting on the third"
        );
    }

    #[test]
    fn join_with_no_inbound_edges_never_fires() {
        // Degenerate graph shape (would also be rejected at publish time by
        // graph::validate's required-input-port check) — defence in depth so
        // `ready_nodes` itself never treats "0 of 0 settled" as satisfied.
        let graph = Graph {
            nodes: vec![node("j", "join", serde_json::json!({}))],
            edges: vec![],
        };
        let runs: HashMap<String, NodeRunState> = HashMap::new();
        let data = serde_json::Map::new();
        assert!(!ready_nodes(&graph, &runs, &data).contains(&"j".to_string()));
    }
}

#[cfg(test)]
mod for_each_tests {
    //! M1-T4: for-each batching, its summary, and the `on_error` port's
    //! liveness — pure logic, no database.
    use super::*;
    use crate::graph::{Graph, GraphEdge, GraphNode};

    fn node(id: &str, ty: &str) -> GraphNode {
        GraphNode {
            id: id.into(),
            node_type: ty.into(),
            config: serde_json::json!({}),
            ports: Value::Null,
        }
    }

    fn edge(from_node: &str, from_port: &str, to_node: &str, to_port: &str) -> GraphEdge {
        GraphEdge {
            from_node: from_node.into(),
            from_port: from_port.into(),
            to_node: to_node.into(),
            to_port: to_port.into(),
        }
    }

    fn settled(id: &str, status: &str) -> (String, NodeRunState) {
        let mut nr = new_node_run_state(id);
        nr.status = status.into();
        (id.to_owned(), nr)
    }

    #[test]
    fn for_each_splits_a_thousand_items_into_batches_of_a_hundred() {
        let items: Vec<Value> = (0..1000).map(|i| serde_json::json!(i)).collect();
        let input = serde_json::json!({ "items": items });
        let list = for_each_items(&input);
        let size = for_each_batch_size(&serde_json::json!({}));
        assert_eq!(size, MAX_FOR_EACH_BATCH);
        assert_eq!(list.chunks(size).count(), 10);
        assert_eq!(
            for_each_batch_size(&serde_json::json!({ "batch_size": 500 })),
            100
        );
        assert_eq!(
            for_each_batch_size(&serde_json::json!({ "batch_size": 0 })),
            1
        );
        assert_eq!(
            for_each_items(&serde_json::json!({ "items": "one" })).len(),
            1
        );
        assert!(for_each_items(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn for_each_resumes_only_when_every_batch_run_ended() {
        let s = |list: &[&str]| list.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(for_each_summary(&s(&["completed", "running"]), 2), None);
        assert_eq!(
            for_each_summary(&s(&["completed"]), 2),
            None,
            "one not visible yet"
        );
        let done = for_each_summary(&s(&["completed", "failed", "completed"]), 3).expect("done");
        assert_eq!(done["completed"], 2);
        assert_eq!(done["failed"], 1);
        assert_eq!(done["batch_count"], 3);
    }

    #[test]
    fn for_each_on_error_port_carries_the_failure() {
        let out = error_output("call_erp", "webhook delivery timed out");
        assert_eq!(out["node_id"], "call_erp");
        assert_eq!(out["error_kind"], "timeout");
        assert_eq!(out["message"], "webhook delivery timed out");
    }

    /// `t -> w`, `w.out -> ok`, `w.on_error -> handler`.
    fn error_graph() -> Graph {
        Graph {
            nodes: vec![
                node("t", "trigger"),
                node("w", "webhook"),
                node("ok", "wait"),
                node("handler", "wait"),
            ],
            edges: vec![
                edge("t", "out", "w", "body"),
                edge("w", "response", "ok", "in"),
                edge("w", ON_ERROR_PORT, "handler", "in"),
            ],
        }
    }

    #[test]
    fn for_each_on_error_handler_is_skipped_when_the_node_succeeds() {
        let graph = error_graph();
        let mut runs: HashMap<String, NodeRunState> =
            [settled("t", "succeeded"), settled("w", "succeeded")]
                .into_iter()
                .collect();
        let mut data = serde_json::Map::new();
        data.insert("t".into(), serde_json::json!({}));
        data.insert("w".into(), serde_json::json!({ "status": 200 }));
        let ready = ready_nodes(&graph, &runs, &data);
        assert_eq!(ready, vec!["ok".to_owned()], "the handler is not ready");
        runs.extend([settled("ok", "succeeded")]);
        assert!(propagate_skips(&graph, &data, &mut runs));
        assert_eq!(runs["handler"].status, "skipped");
    }

    #[test]
    fn for_each_on_error_handler_runs_when_the_node_took_the_port() {
        let graph = error_graph();
        let mut runs: HashMap<String, NodeRunState> =
            [settled("t", "succeeded"), settled("w", "succeeded")]
                .into_iter()
                .collect();
        let mut data = serde_json::Map::new();
        data.insert("t".into(), serde_json::json!({}));
        data.insert("w".into(), error_output("w", "boom"));
        record_error_taken(&mut data, "w");
        mark_untaken_branch(&graph, "w", ON_ERROR_PORT, &mut runs);
        assert_eq!(runs["ok"].status, "skipped", "the normal path is skipped");
        assert_eq!(
            ready_nodes(&graph, &runs, &data),
            vec!["handler".to_owned()]
        );
    }
}

#[cfg(test)]
mod business_wait_tests {
    //! M10-T3: what a wait counts from and which port a timed-out event
    //! wait takes. The calendar arithmetic itself (holidays, weekends) is
    //! `attome_calendar::BusinessCalendar::add_business_duration`'s, tested
    //! there.
    use super::*;

    fn at(raw: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(raw)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_default()
    }

    #[test]
    fn business_wait_counts_from_the_named_record_field() {
        let now = at("2026-10-23T09:00:00Z");
        let config = serde_json::json!({ "relative_to": "due_date" });
        let direct = serde_json::json!({ "in": { "due_date": "2026-11-01T08:00:00Z" } });
        assert_eq!(wait_base(&config, &direct, now), at("2026-11-01T08:00:00Z"));
        let nested = serde_json::json!({ "in": { "record": { "due_date": "2026-11-02" } } });
        assert_eq!(wait_base(&config, &nested, now), at("2026-11-02T00:00:00Z"));
        let missing = serde_json::json!({ "in": {} });
        assert_eq!(wait_base(&config, &missing, now), now);
        assert_eq!(wait_base(&serde_json::json!({}), &direct, now), now);
    }

    #[test]
    fn business_wait_for_event_times_out_down_its_own_port() {
        assert_eq!(
            wait_for_event_taken_port(Some(&serde_json::json!({ "timed_out": true }))),
            "timeout"
        );
        assert_eq!(
            wait_for_event_taken_port(Some(&serde_json::json!({ "record_id": "x" }))),
            "event"
        );
        assert_eq!(wait_for_event_taken_port(None), "event");
    }
}
