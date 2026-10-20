//! Dry-run / simulate (M06 checklist item 2) — executes a workflow graph
//! in-memory against a supplied trigger payload and returns the full node
//! trace, without ever performing a real database write, entity mutation,
//! notification dispatch, webhook call, or approval request. See D-431 for
//! the contract this module exists to uphold: **nothing in this module may
//! produce a real side effect, under any node type, ever.**
//!
//! Deliberately reuses `scheduler`'s graph-traversal primitives
//! (`ready_nodes`, `resolve_input`, `mark_untaken_branch`,
//! `propagate_skips`, `join_mode_and_threshold`, `eval_condition`) rather
//! than re-implementing them: those functions decide *which nodes are ready
//! and in what order*, which is exactly the behavior a dry run needs to
//! prove matches the live engine. Only how a ready node's own side effect
//! (or lack of one) is produced differs — that is this module's
//! `simulate_node`, the dry-run counterpart of `scheduler::execute_node`.
//!
//! Not routed through `attome_ai::Executors`: node execution in this crate
//! was never dispatched through that AI-tool-invocation abstraction to begin
//! with — `scheduler::execute_node` calls `entity_mutation`,
//! `attome_notification::dispatch`, `reqwest`, and `attome_approval` directly, so
//! there is no existing "executor" seam to add a `DryRun` variant to. A
//! native dry-run mode in this crate is the smaller, more honest change than
//! forcing this crate's oldest and most-tested code path through a
//! different abstraction it doesn't otherwise use (guidelines §1: extend an
//! existing boundary, don't relocate a concept to force a fit).
//!
//! **Entirely synchronous.** No node simulated here performs I/O of any
//! kind — not even a read — which is what makes "never a real side effect"
//! true by construction rather than by a per-node discipline that could
//! silently slip: `simulate_entity_write` checks the entity registry
//! (`state.entities`, an in-process `ArcSwap` snapshot, not a query) and
//! nothing else touches the database, the network, or the job queue.

use std::collections::{HashMap, HashSet};

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde_json::Value;
use uuid::Uuid;

use crate::graph::{Graph, GraphNode};
use crate::model::{NodeRunState, SimulateNodeTrace, SimulateRequestBody, SimulateResponse};
use crate::node_types::NodeType;
use crate::scheduler;

/// Same shape as `scheduler::MAX_PASS_ITERATIONS` — a malformed or cyclic
/// draft graph (simulate deliberately does not require full
/// `graph::validate()` first, so a still-being-edited graph can be tested)
/// must fail this bound rather than spin forever on the request thread.
const MAX_SIMULATE_ITERATIONS: usize = 2000;

#[utoipa::path(
    post,
    path = "/api/v1/workflow/definitions/{id}/versions/{version_id}/simulate",
    tag = "workflow",
    params(
        ("id" = Uuid, Path),
        ("version_id" = Uuid, Path),
    ),
    request_body = SimulateRequestBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "D-431: this module executes a workflow graph purely in-memory and may never \
         perform a real database write, entity mutation, notification dispatch, \
         webhook call, or approval request under any node type — nothing here has \
         a persistent effect to audit.",
    )))),
    responses(
        (status = 200, description = "Success", body = SimulateResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn simulate_version(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path((definition_id, version_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<SimulateRequestBody>,
) -> Result<Json<SimulateResponse>, AppError> {
    let graph_json: Value = sqlx::query_scalar(
        "SELECT graph FROM workflow_definition_version WHERE id = $1 AND definition_id = $2",
    )
    .bind(version_id)
    .bind(definition_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let graph = Graph::parse(&graph_json)
        .map_err(|e| AppError::Validation(format!("graph did not parse: {e}")))?;

    let module_steps = dry_run_module_steps(&state, &graph, &body.trigger_payload).await;
    let (status, trace) = run_simulation_with(
        &state,
        &graph,
        body.trigger_payload,
        &body.approval_decisions,
        &module_steps,
    );
    Ok(Json(SimulateResponse { status, trace }))
}

/// E8-T2: what each module step's handler says it would do. The handlers
/// are async and the pass below is not, so they run first, each with
/// `simulate = true` (it changes nothing) and the trigger payload as its
/// input. A node whose handler is missing, unlicensed or refuses its
/// configuration maps to the error the pass reports for it.
pub async fn dry_run_module_steps(
    state: &EngineState,
    graph: &Graph,
    trigger_payload: &Value,
) -> ModuleStepDryRuns {
    let mut out = HashMap::new();
    for node in &graph.nodes {
        if NodeType::parse(&node.node_type) != Some(NodeType::ModuleStep) {
            continue;
        }
        let config = node.config.get("config").cloned().unwrap_or(Value::Null);
        let result = match scheduler::module_step_handler(state, node) {
            Err(e) => Err(e.to_string()),
            Ok(handler) => match handler.validate_config(&config) {
                Err(reason) => Err(reason),
                Ok(()) => handler
                    .run(
                        state,
                        attome_core::workflow_step::StepInvocation {
                            instance_id: Uuid::nil(),
                            node_id: node.id.clone(),
                            correlation_entity_id: None,
                            config,
                            input: trigger_payload.clone(),
                            simulate: true,
                            run_as_user: None,
                        },
                    )
                    .await
                    .map_err(|e| e.to_string()),
            },
        };
        out.insert(node.id.clone(), result);
    }
    out
}

/// Each module step's dry-run outcome, by node id.
pub type ModuleStepDryRuns =
    HashMap<String, Result<attome_core::workflow_step::StepOutcome, String>>;

/// A dry-run node outcome — the `simulate_node` counterpart of
/// `scheduler::NodeOutcome`, minus the wait-resumption metadata a real
/// checkpoint needs (`match_type`/`condition`/`resume_at`), since nothing
/// here is ever actually parked in `workflow_trigger_index`.
enum SimOutcome {
    Succeeded {
        output: Value,
        would_have: Option<String>,
    },
    /// Only `Condition`/`Approval` produce this, same as live.
    Branch {
        taken_port: &'static str,
        output: Value,
        would_have: Option<String>,
    },
    /// What a real pass would have checkpointed as `waiting` — the
    /// simulated branch stops here; nothing downstream of it can run in
    /// this simulate pass, matching how a real `waiting` node_run never
    /// satisfies `upstream_settled`.
    WouldWait {
        reason: String,
        eventual_output: Value,
    },
}

/// Runs `graph` against `trigger_payload` to completion (or the first
/// genuine suspension point / failure), returning the top-level outcome —
/// `"completed"`, `"would_wait"`, or `"failed"` — plus one [`SimulateNodeTrace`]
/// per node the run actually reached.
///
/// `pub`, not `pub(crate)`, on purpose: `tests/execution.rs` calls this
/// directly, the same "bypass the HTTP admin layer, exercise the engine
/// primitive itself" convention `publish_workflow`'s doc comment in that
/// file already documents for `graph::validate`/`trigger_index::
/// rebuild_entry_rows`.
pub fn run_simulation(
    state: &EngineState,
    graph: &Graph,
    trigger_payload: Value,
    approval_decisions: &HashMap<String, String>,
) -> (String, Vec<SimulateNodeTrace>) {
    run_simulation_with(
        state,
        graph,
        trigger_payload,
        approval_decisions,
        &HashMap::new(),
    )
}

/// [`run_simulation`] with each module step's handler outcome from
/// [`dry_run_module_steps`]. A module step missing from `module_steps` is
/// only checked (handler registered, licensed, configuration accepted).
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
pub fn run_simulation_with(
    state: &EngineState,
    graph: &Graph,
    trigger_payload: Value,
    approval_decisions: &HashMap<String, String>,
    module_steps: &ModuleStepDryRuns,
) -> (String, Vec<SimulateNodeTrace>) {
    let Some(entry_node) = graph
        .nodes
        .iter()
        .find(|n| NodeType::parse(&n.node_type) == Some(NodeType::Trigger))
    else {
        return (
            "failed".to_string(),
            vec![SimulateNodeTrace {
                node_id: String::new(),
                node_type: String::new(),
                status: "failed".into(),
                taken_port: None,
                output: Value::Null,
                would_have: None,
                error: Some("graph has no Trigger node".into()),
            }],
        );
    };
    let entry_id = entry_node.id.clone();

    let mut node_runs: HashMap<String, NodeRunState> = HashMap::new();
    let mut node_data: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut trace: Vec<SimulateNodeTrace> = Vec::new();

    {
        let mut nr = scheduler::new_node_run_state(&entry_id);
        nr.status = "succeeded".into();
        node_runs.insert(entry_id.clone(), nr);
    }
    node_data.insert(entry_id.clone(), trigger_payload.clone());
    trace.push(SimulateNodeTrace {
        node_id: entry_id.clone(),
        node_type: entry_node.node_type.clone(),
        status: "succeeded".into(),
        taken_port: None,
        output: trigger_payload,
        would_have: None,
        error: None,
    });

    let mut failed = false;
    let mut iterations = 0usize;

    'pass: loop {
        iterations += 1;
        if iterations > MAX_SIMULATE_ITERATIONS {
            failed = true;
            break 'pass;
        }

        let ready = scheduler::ready_nodes(graph, &node_runs, &node_data);
        if ready.is_empty() {
            if !scheduler::propagate_skips(graph, &node_data, &mut node_runs) {
                break 'pass;
            }
            continue 'pass;
        }

        for node_id in ready {
            let node = graph
                .node(&node_id)
                .expect("ready_nodes only returns real node ids");
            let input = scheduler::resolve_input(graph, node, &node_data);
            node_runs
                .entry(node_id.clone())
                .or_insert_with(|| scheduler::new_node_run_state(&node_id));

            let Some(node_type) = NodeType::parse(&node.node_type) else {
                let msg = format!(
                    "node {:?} has unknown type {:?}: not in this build's node-type registry",
                    node.id, node.node_type
                );
                let entry = node_runs.get_mut(&node_id).expect("just inserted above");
                entry.status = "failed".into();
                entry.last_error = Some(msg.clone());
                trace.push(SimulateNodeTrace {
                    node_id: node_id.clone(),
                    node_type: node.node_type.clone(),
                    status: "failed".into(),
                    taken_port: None,
                    output: Value::Null,
                    would_have: None,
                    error: Some(msg),
                });
                failed = true;
                continue;
            };

            match simulate_node(
                state,
                node,
                node_type,
                &input,
                approval_decisions,
                module_steps,
            ) {
                Ok(SimOutcome::Succeeded { output, would_have }) => {
                    {
                        let entry = node_runs.get_mut(&node_id).expect("inserted above");
                        entry.status = "succeeded".into();
                    }
                    node_data.insert(node_id.clone(), output.clone());
                    trace.push(SimulateNodeTrace {
                        node_id: node_id.clone(),
                        node_type: node.node_type.clone(),
                        status: "succeeded".into(),
                        taken_port: None,
                        output,
                        would_have,
                        error: None,
                    });
                }
                Ok(SimOutcome::Branch {
                    taken_port,
                    output,
                    would_have,
                }) => {
                    {
                        let entry = node_runs.get_mut(&node_id).expect("inserted above");
                        entry.status = "succeeded".into();
                    }
                    node_data.insert(node_id.clone(), output.clone());
                    scheduler::mark_untaken_branch(graph, &node_id, taken_port, &mut node_runs);
                    trace.push(SimulateNodeTrace {
                        node_id: node_id.clone(),
                        node_type: node.node_type.clone(),
                        status: "succeeded".into(),
                        taken_port: Some(taken_port.to_string()),
                        output,
                        would_have,
                        error: None,
                    });
                }
                Ok(SimOutcome::WouldWait {
                    reason,
                    eventual_output,
                }) => {
                    {
                        let entry = node_runs.get_mut(&node_id).expect("inserted above");
                        entry.status = "waiting".into();
                    }
                    trace.push(SimulateNodeTrace {
                        node_id: node_id.clone(),
                        node_type: node.node_type.clone(),
                        status: "waiting".into(),
                        taken_port: None,
                        output: eventual_output,
                        would_have: Some(reason),
                        error: None,
                    });
                }
                Err(e) => {
                    let msg = e.to_string();
                    {
                        let entry = node_runs.get_mut(&node_id).expect("inserted above");
                        entry.status = "failed".into();
                        entry.last_error = Some(msg.clone());
                    }
                    trace.push(SimulateNodeTrace {
                        node_id: node_id.clone(),
                        node_type: node.node_type.clone(),
                        status: "failed".into(),
                        taken_port: None,
                        output: Value::Null,
                        would_have: None,
                        error: Some(msg),
                    });
                    failed = true;
                }
            }
        }

        if failed {
            break 'pass;
        }
    }

    // Skip-propagation (`mark_untaken_branch`/`propagate_skips`) can settle a
    // node without it ever being "ready" in the loop above — record those
    // too, so the trace reflects every node_run the run actually touched,
    // not only the ones that executed.
    let already_traced: HashSet<String> = trace.iter().map(|t| t.node_id.clone()).collect();
    for (node_id, nr) in &node_runs {
        if nr.status == "skipped" && !already_traced.contains(node_id.as_str()) {
            let node_type = graph
                .node(node_id)
                .map(|n| n.node_type.clone())
                .unwrap_or_default();
            trace.push(SimulateNodeTrace {
                node_id: node_id.clone(),
                node_type,
                status: "skipped".into(),
                taken_port: None,
                output: Value::Null,
                would_have: None,
                error: None,
            });
        }
    }

    let waiting_any = node_runs.values().any(|nr| nr.status == "waiting");
    let status = if failed {
        "failed"
    } else if waiting_any {
        "would_wait"
    } else {
        "completed"
    };
    (status.to_string(), trace)
}

fn simulate_node(
    state: &EngineState,
    node: &GraphNode,
    node_type: NodeType,
    input: &Value,
    approval_decisions: &HashMap<String, String>,
    module_steps: &ModuleStepDryRuns,
) -> Result<SimOutcome, AppError> {
    match node_type {
        // Materialized before the pass loop starts (mirrors
        // `scheduler::execute_claimed`'s own entry handling) — `ready_nodes`
        // never returns an entry node, so this arm is unreachable in
        // practice; it exists only so the match stays exhaustive.
        NodeType::Trigger => Ok(SimOutcome::Succeeded {
            output: input.clone(),
            would_have: None,
        }),
        NodeType::Condition => {
            let value = input.get("value").cloned().unwrap_or(Value::Null);
            let taken = scheduler::eval_condition(&node.config, &value);
            Ok(SimOutcome::Branch {
                taken_port: if taken { "true" } else { "false" },
                output: value,
                would_have: None,
            })
        }
        NodeType::Split | NodeType::Join => Ok(SimOutcome::Succeeded {
            output: input.get("in").cloned().unwrap_or(Value::Null),
            would_have: None,
        }),
        NodeType::CreateRecord | NodeType::UpdateRecord => {
            simulate_entity_write(state, node, node_type, input)
        }
        NodeType::RestoreRecord => simulate_restore_record(state, node),
        // M11-T1: a dry run picks nobody and writes nothing.
        NodeType::Assign => Ok(SimOutcome::Succeeded {
            output: input.get("record_id").cloned().unwrap_or(Value::Null),
            would_have: Some(format!(
                "would assign the record by {}",
                node.config
                    .get("strategy")
                    .and_then(Value::as_str)
                    .unwrap_or("round_robin")
            )),
        }),
        // A15-T9: a dry run looks nothing up and follows `none`.
        NodeType::DuplicateCheck => Ok(SimOutcome::Branch {
            taken_port: "none",
            output: serde_json::json!({ "matches": [], "hidden": 0 }),
            would_have: Some("would look the record up under its duplicate rules".to_owned()),
        }),
        NodeType::SendNotification => Ok(simulate_send_notification(node, input)),
        NodeType::Webhook => simulate_webhook(node, input),
        NodeType::Approval => Ok(simulate_approval(node, input, approval_decisions)),
        NodeType::Wait => Ok(simulate_wait(node)),
        NodeType::WaitForEvent => Ok(simulate_wait_for_event(node)),
        NodeType::SubWorkflow => simulate_sub_workflow(node),
        NodeType::AgentStep => simulate_agent_step(node, input),
        NodeType::Route => Ok(simulate_route(node, approval_decisions)),
        NodeType::ModuleStep => simulate_module_step(state, node, module_steps),
    }
}

/// E8-T2: maps the handler's dry-run outcome the way the live scheduler
/// maps the real one.
fn simulate_module_step(
    state: &EngineState,
    node: &GraphNode,
    module_steps: &ModuleStepDryRuns,
) -> Result<SimOutcome, AppError> {
    use attome_core::workflow_step::StepOutcome;
    match module_steps.get(&node.id) {
        Some(Err(reason)) => Err(AppError::Validation(format!(
            "module step {:?}: {reason}",
            node.id
        ))),
        Some(Ok(StepOutcome::Done(output))) => Ok(SimOutcome::Succeeded {
            output: output.clone(),
            would_have: Some("would run the module step".into()),
        }),
        Some(Ok(StepOutcome::Waiting { wait_event, .. })) => Ok(SimOutcome::WouldWait {
            reason: match wait_event {
                Some(event) => format!("would wait for {event}"),
                None => "would wait until the step is due again".into(),
            },
            eventual_output: Value::Null,
        }),
        Some(Ok(StepOutcome::Blocked {
            reason,
            continue_after: true,
        })) => Ok(SimOutcome::Succeeded {
            output: serde_json::json!({ "blocked": reason }),
            would_have: Some(format!("would be blocked ({reason}) and go on")),
        }),
        Some(Ok(StepOutcome::Blocked {
            reason,
            continue_after: false,
        })) => Ok(SimOutcome::WouldWait {
            reason: format!("would be blocked ({reason}) and retry later"),
            eventual_output: serde_json::json!({ "blocked": reason }),
        }),
        Some(Ok(StepOutcome::Exit { reason })) => Ok(SimOutcome::WouldWait {
            reason: format!("would end the instance: {reason}"),
            eventual_output: serde_json::json!({ "exit": reason }),
        }),
        None => {
            let handler = scheduler::module_step_handler(state, node)?;
            handler
                .validate_config(node.config.get("config").unwrap_or(&Value::Null))
                .map_err(AppError::Validation)?;
            Ok(SimOutcome::Succeeded {
                output: Value::Null,
                would_have: Some(format!("would run module step {}", handler.key())),
            })
        }
    }
}

/// M33 Phase 1 (D-460). Never calls `route.classify` — like every other
/// `simulate_*` function, this reports what a real run would validate
/// without spending a model call or logging a suggestion. Reuses the same
/// `decisions` map `simulate_approval` reads, keyed by node id: a caller can
/// pin which route a dry run takes, and an unspecified node defaults to the
/// FIRST configured route (the same "pick an optimistic default" posture
/// `simulate_approval`'s `"approved"` default takes), taking the `matched`
/// port. This never validates the caller's chosen label against
/// `config.routes` — a dry run is not the place to reject an operator's own
/// "what if we routed here" question.
fn simulate_route(node: &GraphNode, decisions: &HashMap<String, String>) -> SimOutcome {
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

    let chosen = decisions
        .get(&node.id)
        .cloned()
        .or_else(|| routes.first().cloned());

    let would_have = Some(match &chosen {
        Some(r) => format!(
            "would classify against {} configured route(s) — auto-decided {r:?} for this simulation",
            routes.len()
        ),
        None => "would classify, but no config.routes are configured".to_string(),
    });

    match chosen {
        Some(route) => SimOutcome::Branch {
            taken_port: "matched",
            output: serde_json::json!({ "route": route, "applies": true, "auto_decided": true }),
            would_have,
        },
        None => SimOutcome::Branch {
            taken_port: "unmatched",
            output: serde_json::json!({ "route": Value::Null, "applies": false }),
            would_have,
        },
    }
}

/// M32 Phase 1 (D-450). Never starts a real session — `dry_run_simulate`'s
/// whole contract is that it writes nothing to the database, and
/// `attome_ai::agent::start_session` always writes a
/// `agent_session` row. Reports what a real run would do without
/// checking that `agent_definition_ref` resolves to an actual `ai_agent`
/// record — `execute_agent_step` does that at run time; a dry run only
/// checks the shape of the config, same "validated, never written" posture
/// `simulate_entity_write` already takes for `CreateRecord`/`UpdateRecord`.
fn simulate_agent_step(node: &GraphNode, input: &Value) -> Result<SimOutcome, AppError> {
    let agent_definition_ref = node
        .config
        .get("agent_definition_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::Validation(format!(
                "agent_step node {:?} has a missing or invalid config.agent_definition_ref",
                node.id
            ))
        })?;
    let step_budget = node.config.get("step_budget").and_then(Value::as_u64);
    let task = input.get("task").cloned().unwrap_or(Value::Null);
    let would_have = Some(format!(
        "would start a session from agent definition {agent_definition_ref} — \
         validated, never started"
    ));
    let output = serde_json::json!({
        "would_start_session": true,
        "agent_definition_ref": agent_definition_ref,
        "step_budget": step_budget,
        "task": task,
    });
    Ok(SimOutcome::Succeeded { output, would_have })
}

/// Validates the target entity exists in this deployment's metadata registry
/// (an in-process `ArcSwap` read, not a database query) and renders what
/// would have been written — `entity_mutation::create_one`/`update_one` is
/// never called.
fn simulate_entity_write(
    state: &EngineState,
    node: &GraphNode,
    node_type: NodeType,
    input: &Value,
) -> Result<SimOutcome, AppError> {
    let entity_name = node
        .config
        .get("entity")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation(format!("node {:?} missing config.entity", node.id)))?;
    let registry = state.entities.load();
    let known = registry.get(entity_name).is_some();
    drop(registry);
    if !known {
        return Err(AppError::Validation(format!(
            "unknown entity {entity_name:?} in workflow node config"
        )));
    }
    let data = input
        .get("data")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let verb = if matches!(node_type, NodeType::CreateRecord) {
        "create"
    } else {
        "update"
    };
    let would_have = Some(format!(
        "would {verb} a {entity_name:?} record with {} field(s) — validated, never written",
        data.len()
    ));
    let output = serde_json::json!({
        "would_write": true,
        "entity": entity_name,
        "fields": data.keys().collect::<Vec<_>>(),
    });
    Ok(SimOutcome::Succeeded { output, would_have })
}

/// A18-T8: names what a `restore_record` node would bring back; nothing is
/// restored.
fn simulate_restore_record(state: &EngineState, node: &GraphNode) -> Result<SimOutcome, AppError> {
    let entity_name = node
        .config
        .get("entity")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation(format!("node {:?} missing config.entity", node.id)))?;
    if state.entities.load().get(entity_name).is_none() {
        return Err(AppError::Validation(format!(
            "unknown entity {entity_name:?} in workflow node config"
        )));
    }
    Ok(SimOutcome::Succeeded {
        output: serde_json::json!({ "would_restore": true, "entity": entity_name }),
        would_have: Some(format!(
            "would restore a deleted {entity_name:?} record — never restored in a dry run"
        )),
    })
}

fn simulate_send_notification(node: &GraphNode, input: &Value) -> SimOutcome {
    let template_key = node
        .config
        .get("template_key")
        .and_then(Value::as_str)
        .unwrap_or("workflow.generic");
    let recipient = node
        .config
        .get("recipient_user_ref")
        .and_then(Value::as_str);
    let is_global = node
        .config
        .get("is_global")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let variables = input.get("variables").cloned().unwrap_or(Value::Null);
    let would_have = Some(format!(
        "would dispatch notification template {template_key:?}{} — rendered, never queued",
        if is_global {
            " (global)".to_string()
        } else {
            recipient.map(|r| format!(" to {r}")).unwrap_or_default()
        }
    ));
    let output = serde_json::json!({
        "would_dispatch": true,
        "template_key": template_key,
        "recipient_user_ref": recipient,
        "is_global": is_global,
        "variables": variables,
    });
    SimOutcome::Succeeded { output, would_have }
}

/// Renders the method/URL/body a live pass would have sent — parses the
/// configured URL for shape only. Deliberately does **not** call
/// `attome_server::ssrf_guard::validate_url` (unlike the live
/// `scheduler::execute_webhook`): that guard resolves DNS, and D-431 bars
/// this module from any network activity at all, screening included — real
/// reachability/SSRF validation only ever runs on a live pass.
fn simulate_webhook(node: &GraphNode, input: &Value) -> Result<SimOutcome, AppError> {
    let url = node
        .config
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::Validation(format!("webhook node {:?} missing config.url", node.id))
        })?;
    let parsed = reqwest::Url::parse(url).map_err(|e| {
        AppError::Validation(format!(
            "webhook node {:?} has an invalid url: {e}",
            node.id
        ))
    })?;
    let method = node
        .config
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("POST")
        .to_uppercase();
    let body = input.get("body").cloned().unwrap_or(Value::Null);
    let would_have = Some(format!(
        "would send {method} {parsed} — request rendered, never sent"
    ));
    let output = serde_json::json!({
        "would_send": true,
        "method": method,
        "url": parsed.to_string(),
        "body": body,
    });
    Ok(SimOutcome::Succeeded { output, would_have })
}

/// Auto-decides per `decisions[node.id]` (default `"approved"`, so a
/// simulate run doesn't dead-end at the first gate a caller didn't
/// pre-decide) instead of calling `attome_approval::submit`/
/// `submit_with_plan` — no real approval request is ever filed.
fn simulate_approval(
    node: &GraphNode,
    input: &Value,
    decisions: &HashMap<String, String>,
) -> SimOutcome {
    let decision = decisions
        .get(&node.id)
        .map(String::as_str)
        .unwrap_or("approved");
    let taken_port = if decision == "approved" {
        "approved"
    } else {
        "rejected"
    };
    let would_have = Some(format!(
        "would file a real approval request and wait for a decision — auto-decided {decision:?} for this simulation"
    ));
    let output = serde_json::json!({
        "decision": decision,
        "auto_decided": true,
        "input": input,
    });
    SimOutcome::Branch {
        taken_port,
        output,
        would_have,
    }
}

/// A `Wait` is a timer, not an external dependency — dry run treats it as an
/// instant passthrough so the simulated run can keep going, rather than a
/// suspension point the way `WaitForEvent`/`SubWorkflow` are below.
fn simulate_wait(node: &GraphNode) -> SimOutcome {
    let would_have = if let Some(iso) = node.config.get("resume_at").and_then(Value::as_str) {
        format!("would pause until {iso}")
    } else {
        let secs = node
            .config
            .get("delay_seconds")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        format!("would pause for {secs}s")
    };
    SimOutcome::Succeeded {
        output: Value::Null,
        would_have: Some(would_have),
    }
}

fn simulate_wait_for_event(node: &GraphNode) -> SimOutcome {
    let entity = node
        .config
        .get("entity_logicalname")
        .and_then(Value::as_str);
    let reason = match entity {
        Some(e) => format!(
            "would wait for an entity event on {e:?} — this simulation has no external event to supply"
        ),
        None => "would wait for an entity event — this simulation has no external event to supply"
            .to_string(),
    };
    SimOutcome::WouldWait {
        reason,
        eventual_output: Value::Null,
    }
}

fn simulate_sub_workflow(node: &GraphNode) -> Result<SimOutcome, AppError> {
    let logicalname = node
        .config
        .get("definition_logicalname")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::Validation(format!("sub_workflow node {:?} missing config", node.id))
        })?;
    Ok(SimOutcome::WouldWait {
        reason: format!(
            "would start child workflow {logicalname:?} — a simulate run never starts a real sub-workflow instance"
        ),
        eventual_output: Value::Null,
    })
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/workflow/definitions/{id}/versions/{version_id}/simulate",
        post(simulate_version),
    )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged upward by `attome_workflow::openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(simulate_version))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
