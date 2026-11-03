//! `model.flow.draft` (roadmap AD3-T1): a building agent drafts a flow from
//! a description, with at least two test cases (the happy path and an edge
//! case), and runs each through the M4 simulation before anyone saves it.
//!
//! One model call answers the graph (the engine's `{nodes, edges}` shape)
//! and the cases (a trigger payload, the status the run should end in, and
//! nodes it should reach). Each case runs through the registered workflow
//! simulator's `simulate_graph` (`attome_core::WorkflowSimulator`, filled by
//! the composition root with `attome-workflow`'s simulator, which this crate
//! cannot call): nothing runs for real and nothing is written. The answer
//! carries each case's result and the two requests that save the flow as a
//! draft version (`POST /api/v1/workflow/definitions`, then
//! `.../{id}/versions` with the graph), made by a person, in their Develop
//! workspace when they work in one (V2-D27). A stage process is drafted with
//! `model.stage_process.edit` (N12).

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const FLOW_DRAFT: &str = "model.flow.draft";
/// Bumped whenever the prompt changes in a way that could move results.
pub const FLOW_PROMPT_VERSION: &str = "model.flow.draft/v1";
/// The fewest test cases a draft carries: the happy path and an edge case.
pub const MIN_CASES: usize = 2;
/// The most cases one draft runs.
const MAX_CASES: usize = 10;

const SCHEMA: &str = r#"{
  "type": "object",
  "required": ["description"],
  "properties": {
    "description": { "type": "string", "description": "What the flow should do, in the person's words." },
    "entity": { "type": "string", "description": "The entity whose records start it, when known." }
  },
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            FLOW_DRAFT,
            "Draft a flow from a description with at least two test cases, and run each case \
             through the flow simulation. Saves nothing; returns the graph, each case's result \
             and the requests that save it as a draft version.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(SCHEMA),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(FlowDraft)]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    description: String,
    #[serde(default)]
    entity: Option<String>,
}

/// One drafted test case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowCase {
    pub name: String,
    #[serde(default)]
    pub payload: Value,
    /// `completed`, `would_wait` or `failed`.
    pub expect: String,
    /// Nodes the run must reach.
    #[serde(default)]
    pub reaches: Vec<String>,
}

/// What the model answers.
#[derive(Debug, Clone, PartialEq, Deserialize)]
struct Drafted {
    graph: Value,
    #[serde(default)]
    cases: Vec<FlowCase>,
}

/// Whether a simulated run meets a case: its status, and every node the case
/// names among those reached. Pure.
pub fn case_passes(case: &FlowCase, status: &str, reached: &[String]) -> bool {
    status == case.expect && case.reaches.iter().all(|n| reached.contains(n))
}

#[derive(Debug)]
pub struct FlowDraft;

impl Action for FlowDraft {
    fn id(&self) -> ActionId {
        ActionId(FLOW_DRAFT)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            // Saving a flow is an administrator's (the workflow routes).
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let args: Args = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid {FLOW_DRAFT} arguments: {e}"))
            })?;
            if args.description.trim().is_empty() {
                return Err(AppError::Validation(
                    "description: say what the flow does".into(),
                ));
            }
            let simulator = state
                .workflow_simulator
                .clone()
                .ok_or(AppError::CapabilityUnavailable("flow simulation"))?;
            let fields: Vec<String> = args
                .entity
                .as_deref()
                .and_then(|e| {
                    state
                        .entities
                        .load()
                        .iter()
                        .find(|m| m.logicalname == e)
                        .map(|m| m.attrs.iter().map(|a| a.logicalname.clone()).collect())
                })
                .unwrap_or_default();
            let system = format!(
                "You draft a workflow. Answer with one JSON object and nothing else: \
                 {{\"graph\": {{\"nodes\": [{{\"id\", \"type\", \"config\"}}], \"edges\": \
                 [{{\"from_node\", \"from_port\", \"to_node\", \"to_port\"}}]}}, \"cases\": \
                 [{{\"name\", \"payload\" (the trigger record's fields), \"expect\" (completed, \
                 would_wait or failed), \"reaches\" (node ids the run must pass)}}]}}. Node types: \
                 trigger (one, first), condition (ports true and false), create_record, \
                 update_record, send_notification, approval, wait, assign. Other nodes have one \
                 output port `out` and one input port `in`. Give at least {MIN_CASES} cases: the \
                 happy path and an edge case."
            );
            let facts = json!({
                "description": args.description,
                "entity": args.entity,
                "fields": fields,
            })
            .to_string();
            let (text, provenance) = crate::actions::metric_draft::generate(
                state,
                ctx,
                FLOW_DRAFT,
                FLOW_PROMPT_VERSION,
                system,
                facts,
            )
            .await?;
            let mut drafted: Drafted = serde_json::from_str(
                crate::actions::metric_draft::strip_fence(&text),
            )
            .map_err(|e| {
                AppError::Validation(format!("the drafted flow is not a graph with cases: {e}"))
            })?;
            drafted.cases.truncate(MAX_CASES);
            let mut results = Vec::new();
            for case in &drafted.cases {
                let run = simulator
                    .simulate_graph(state, &drafted.graph, case.payload.clone())
                    .await?;
                let passed = case_passes(case, &run.status, &run.reached);
                results.push(json!({
                    "name": case.name,
                    "expect": case.expect,
                    "status": run.status,
                    "reached": run.reached,
                    "passed": passed,
                }));
            }
            let all_pass =
                drafted.cases.len() >= MIN_CASES && results.iter().all(|r| r["passed"] == true);
            Ok(ActionResult {
                value: json!({
                    "graph": drafted.graph,
                    "cases": results,
                    "enough_cases": drafted.cases.len() >= MIN_CASES,
                    "all_pass": all_pass,
                    "save": [
                        { "request": "POST /api/v1/workflow/definitions",
                          "body": { "logicalname": "<name>", "name": "<label>", "kind": "flow" } },
                        { "request": "POST /api/v1/workflow/definitions/{id}/versions",
                          "body": { "graph": drafted.graph } },
                    ],
                    "saved": false,
                }),
                provenance,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_case_passes_on_its_status_and_nodes() {
        let case = FlowCase {
            name: "happy".into(),
            payload: json!({ "amount": 10 }),
            expect: "completed".into(),
            reaches: vec!["notify".into()],
        };
        let reached = vec!["start".to_owned(), "check".to_owned(), "notify".to_owned()];
        assert!(case_passes(&case, "completed", &reached));
        assert!(!case_passes(&case, "would_wait", &reached));
        assert!(!case_passes(&case, "completed", &reached[..2]));
    }
}
