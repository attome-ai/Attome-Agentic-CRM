//! Journey actions (roadmap E8-T12), for the marketing module:
//!
//! - `journey.draft` drafts a journey's graph from a description: the model
//!   proposes nodes and edges, which are checked here (one trigger, edges
//!   between known nodes, only the node types a journey may use, and every
//!   module step a registered marketing step whose configuration it
//!   accepts), and returned with a diff against the journey's current draft
//!   (or its live version when it has no draft) and the workflow API call
//!   that would save it as a draft. Nothing is saved: a person opens the
//!   diff and saves it through that call, which is the ordinary draft path
//!   (automation administrators, the open changeset, audited). There is no
//!   publish here, for an agent or anyone: publishing stays the person's,
//!   through the journey's own publish.
//! - `journey.explain_person` reads one person's runs (E8-T9's path, which
//!   answers 404 for a person the caller may not read) and says in a few
//!   lines where they went, where they were blocked and why, and how each
//!   run ended or where it waits.
//! - `journey.suggest` reads the journey's counts and blocks and names the
//!   node most people leave at and the most common block reasons, each with
//!   what to look at.
//!
//! A draft cannot change consent: the node types that write records
//! (`create_record`, `update_record`, `assign`, `restore_record`), call out
//! (`webhook`, `connector`, `custom_action`, `agent_step`) or start other
//! workflows are refused, so a drafted journey can only wait, branch and run
//! marketing steps, and every send still passes the journey rules. Agents
//! have no enrolment action, so they enrol nobody.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_MARKETING;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const DRAFT: &str = "journey.draft";
pub const EXPLAIN_PERSON: &str = "journey.explain_person";
pub const SUGGEST: &str = "journey.suggest";
/// Bumped whenever the draft prompt changes in a way that could move results.
pub const DRAFT_PROMPT_VERSION: &str = "journey.draft/v1";

/// The node types a drafted journey may use.
pub const ALLOWED_NODE_TYPES: [&str; 7] = [
    "trigger",
    "condition",
    "wait",
    "wait_for_event",
    "split",
    "join",
    "module_step",
];

/// Nodes one draft may hold.
const MAX_NODES: usize = 60;
/// Block reasons one suggestion reads.
const TOP_REASONS: i64 = 3;

const DRAFT_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "journey_id": { "type": "string", "format": "uuid", "description": "The marketing journey to draft for." },
    "description": { "type": "string", "description": "What the journey should do, in the person's words." }
  },
  "required": ["journey_id", "description"],
  "additionalProperties": false
}"#;

const EXPLAIN_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "journey_id": { "type": "string", "format": "uuid" },
    "person_id": { "type": "string", "format": "uuid", "description": "The contact or lead." }
  },
  "required": ["journey_id", "person_id"],
  "additionalProperties": false
}"#;

const SUGGEST_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "journey_id": { "type": "string", "format": "uuid" }
  },
  "required": ["journey_id"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            DRAFT,
            "Draft a marketing journey's steps from a description: returns the proposed graph, \
             what changed against the journey's current draft, any problems found, and the call \
             that saves it as a draft. Nothing is saved or published; a person reviews and saves \
             it. Do NOT use this to start, publish or enrol anyone in a journey.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_MARKETING,
            &["marketing_journey.update"],
        )
        .input_schema(DRAFT_SCHEMA),
        ActionDescriptor::new(
            EXPLAIN_PERSON,
            "Explain one person's path through a marketing journey: where they went, where and \
             why they were blocked, and how each run ended or where it waits.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_MARKETING,
            &["marketing_journey.read"],
        )
        .input_schema(EXPLAIN_SCHEMA),
        ActionDescriptor::new(
            SUGGEST,
            "Suggest where to improve a marketing journey from its results: the step most people \
             leave at and the most common reasons sends were blocked. Changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_MARKETING,
            &["marketing_journey.read"],
        )
        .input_schema(SUGGEST_SCHEMA),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(Journey(DRAFT)),
        Box::new(Journey(EXPLAIN_PERSON)),
        Box::new(Journey(SUGGEST)),
    ]
}

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args.get(key)
        .and_then(Value::as_str)
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be an id")))
}

/// A graph's nodes by id and its edges, as the workflow engine stores them.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct DraftGraph {
    #[serde(default)]
    pub nodes: Vec<DraftNode>,
    #[serde(default)]
    pub edges: Vec<DraftEdge>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DraftNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(default)]
    pub config: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct DraftEdge {
    pub from_node: String,
    #[serde(default = "default_out")]
    pub from_port: String,
    pub to_node: String,
    #[serde(default = "default_in")]
    pub to_port: String,
}

fn default_out() -> String {
    "out".to_owned()
}

fn default_in() -> String {
    "in".to_owned()
}

/// What a draft changes against the current graph.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct GraphDiff {
    pub added_nodes: Vec<String>,
    pub removed_nodes: Vec<String>,
    pub changed_nodes: Vec<String>,
    pub added_edges: Vec<DraftEdge>,
    pub removed_edges: Vec<DraftEdge>,
}

/// The diff of `next` against `current`, node ids and edges in order. Pure.
pub fn diff(current: &DraftGraph, next: &DraftGraph) -> GraphDiff {
    let before: BTreeMap<&str, &DraftNode> =
        current.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let after: BTreeMap<&str, &DraftNode> = next.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let edges_before: BTreeSet<&DraftEdge> = current.edges.iter().collect();
    let edges_after: BTreeSet<&DraftEdge> = next.edges.iter().collect();
    GraphDiff {
        added_nodes: after
            .keys()
            .filter(|id| !before.contains_key(*id))
            .map(|id| (*id).to_owned())
            .collect(),
        removed_nodes: before
            .keys()
            .filter(|id| !after.contains_key(*id))
            .map(|id| (*id).to_owned())
            .collect(),
        changed_nodes: after
            .iter()
            .filter(|(id, node)| before.get(*id).is_some_and(|old| old != *node))
            .map(|(id, _)| (*id).to_owned())
            .collect(),
        added_edges: edges_after
            .difference(&edges_before)
            .map(|e| (*e).clone())
            .collect(),
        removed_edges: edges_before
            .difference(&edges_after)
            .map(|e| (*e).clone())
            .collect(),
    }
}

/// The problems with a drafted graph; none means it may be saved as a
/// draft (the workflow API checks it again when it is). `step` answers for
/// a module step's handler key: `None` when no marketing step has that key,
/// otherwise the step's verdict on its configuration. Pure.
pub fn problems(
    graph: &DraftGraph,
    step: &dyn Fn(&str, &Value) -> Option<Result<(), String>>,
) -> Vec<String> {
    let mut out = Vec::new();
    if graph.nodes.is_empty() {
        out.push("the journey has no steps".to_owned());
    }
    if graph.nodes.len() > MAX_NODES {
        out.push(format!(
            "a journey drafted here has at most {MAX_NODES} steps"
        ));
    }
    let mut ids = BTreeSet::new();
    for node in &graph.nodes {
        if node.id.trim().is_empty() || !ids.insert(node.id.as_str()) {
            out.push(format!("step id {:?} is empty or used twice", node.id));
        }
        if !ALLOWED_NODE_TYPES.contains(&node.node_type.as_str()) {
            out.push(format!(
                "step {:?}: a journey cannot use {:?} steps",
                node.id, node.node_type
            ));
            continue;
        }
        if node.node_type == "module_step" {
            let handler = node.config.get("handler").and_then(Value::as_str);
            let config = node.config.get("config").cloned().unwrap_or(Value::Null);
            match handler.map(|h| (h, step(h, &config))) {
                None => out.push(format!("step {:?} names no marketing step", node.id)),
                Some((h, None)) => out.push(format!(
                    "step {:?}: {h:?} is not a marketing step this deployment has",
                    node.id
                )),
                Some((h, Some(Err(problem)))) => {
                    out.push(format!("step {:?} ({h}): {problem}", node.id));
                }
                Some((_, Some(Ok(())))) => {}
            }
        }
    }
    let triggers = graph
        .nodes
        .iter()
        .filter(|n| n.node_type == "trigger")
        .count();
    if triggers != 1 {
        out.push(format!("a journey has one trigger, not {triggers}"));
    }
    for edge in &graph.edges {
        for end in [&edge.from_node, &edge.to_node] {
            if !ids.contains(end.as_str()) {
                out.push(format!(
                    "an edge names step {end:?}, which is not in the journey"
                ));
            }
        }
    }
    out
}

/// The workflow API call that saves `graph` as the journey's draft: the
/// existing draft version updated at its `row_version`, or a new draft
/// version. Never a publish. Pure.
pub fn save_call(definition: Uuid, draft: Option<(Uuid, i64)>, graph: &DraftGraph) -> Value {
    match draft {
        Some((version, row_version)) => json!({
            "method": "PATCH",
            "path": format!("/api/v1/workflow/definitions/{definition}/versions/{version}"),
            "body": { "graph": graph, "row_version": row_version },
        }),
        None => json!({
            "method": "POST",
            "path": format!("/api/v1/workflow/definitions/{definition}/versions"),
            "body": { "graph": graph },
        }),
    }
}

/// The journey's current graph: its draft, or else its newest version;
/// with the draft's id and row version when there is one.
async fn current_graph(
    state: &EngineState,
    definition: Uuid,
) -> Result<(DraftGraph, Option<(Uuid, i64)>), AppError> {
    let row: Option<(Uuid, String, Value, i64)> = sqlx::query_as(
        "SELECT id, status, graph, row_version FROM workflow_definition_version \
          WHERE definition_id = $1 \
          ORDER BY (status = 'draft') DESC, version_number DESC LIMIT 1",
    )
    .bind(definition)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((id, status, graph, row_version)) = row else {
        return Ok((DraftGraph::default(), None));
    };
    let graph = serde_json::from_value(graph).unwrap_or_default();
    Ok((graph, (status == "draft").then_some((id, row_version))))
}

async fn draft(
    state: &EngineState,
    ctx: &ActionContext,
    args: &Value,
) -> Result<ActionResult, AppError> {
    ctx.security.require("marketing_journey", "update")?;
    let journey = uuid_arg(args, "journey_id")?;
    let description = args
        .get("description")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .ok_or_else(|| {
            AppError::Validation("description says what the journey should do".into())
        })?;
    let definition = attome_marketing::journey::routes::definition_of(state, journey).await?;
    let (current, draft_version) = current_graph(state, definition).await?;
    let steps: Vec<&'static str> = {
        let mut keys: Vec<&'static str> = state
            .workflow_step_handlers
            .iter()
            .filter(|(key, h)| {
                h.module_id() == MODULE_MARKETING
                    && !attome_marketing::journey::message_step::UNAVAILABLE_CHANNELS.contains(key)
            })
            .map(|(key, _)| *key)
            .collect();
        keys.sort_unstable();
        keys
    };
    let system = "You draft a marketing journey as a workflow graph. Answer with one JSON object \
        and nothing else: {\"nodes\": [{\"id\", \"type\", \"config\"}], \"edges\": [{\"from_node\", \
        \"from_port\", \"to_node\", \"to_port\"}]}. Exactly one node has type \"trigger\". Other \
        types: condition, wait, wait_for_event, split, join, and module_step, whose config is \
        {\"handler\": one of the marketing steps given, \"config\": that step's settings}. Keep \
        the ids of the current graph's nodes you keep. Use no other node type."
        .to_owned();
    let facts = json!({
        "description": description,
        "current_graph": current,
        "marketing_steps": steps,
    })
    .to_string();
    let (text, provenance) = crate::actions::metric_draft::generate(
        state,
        ctx,
        DRAFT,
        DRAFT_PROMPT_VERSION,
        system,
        facts,
    )
    .await?;
    let proposed: DraftGraph =
        serde_json::from_str(crate::actions::metric_draft::strip_fence(&text)).map_err(|e| {
            AppError::Validation(format!("the drafted journey is not a graph: {e}"))
        })?;
    let issues = problems(&proposed, &|key, config| {
        state
            .workflow_step_handlers
            .get(key)
            .filter(|h| h.module_id() == MODULE_MARKETING)
            .map(|h| h.validate_config(config))
    });
    Ok(ActionResult {
        value: json!({
            "journey_id": journey,
            "graph": proposed,
            "diff": diff(&current, &proposed),
            "valid": issues.is_empty(),
            "problems": issues,
            "save": save_call(definition, draft_version, &proposed),
            "saved": false,
        }),
        provenance,
    })
}

/// A few lines on one run. Pure.
pub fn explain_run(run: &attome_marketing::journey::insight::PersonRun) -> String {
    let mut lines = vec![format!(
        "Entered on {}.",
        run.entered_at.format("%Y-%m-%d %H:%M UTC")
    )];
    let reached: Vec<&str> = run.steps.iter().map(|s| s.node_id.as_str()).collect();
    if !reached.is_empty() {
        lines.push(format!("Went through: {}.", reached.join(" -> ")));
    }
    for block in &run.blocks {
        lines.push(format!(
            "Blocked at {} on {}: {}.",
            block.node_id,
            block.at.format("%Y-%m-%d"),
            block.reason
        ));
    }
    match (&run.ended_at, &run.end_reason) {
        (Some(at), reason) => lines.push(format!(
            "Left on {} ({}).",
            at.format("%Y-%m-%d"),
            reason.as_deref().unwrap_or(&run.status)
        )),
        (None, _) => match run
            .steps
            .iter()
            .rev()
            .find(|s| s.status == "waiting" || s.status == "running")
        {
            Some(step) => lines.push(format!("Still in the journey, at {}.", step.node_id)),
            None => lines.push(format!("Still in the journey ({}).", run.status)),
        },
    }
    lines.join(" ")
}

async fn explain_person(
    state: &EngineState,
    ctx: &ActionContext,
    args: &Value,
) -> Result<Value, AppError> {
    let journey = uuid_arg(args, "journey_id")?;
    let person = uuid_arg(args, "person_id")?;
    let definition = attome_marketing::journey::routes::definition_of(state, journey).await?;
    let runs =
        attome_marketing::journey::insight::person_path(state, &ctx.security, definition, person)
            .await?;
    let explanation: Vec<String> = runs.iter().map(explain_run).collect();
    Ok(json!({
        "journey_id": journey,
        "person_id": person,
        "runs": runs,
        "explanation": if explanation.is_empty() {
            vec!["This person has not been in the journey.".to_owned()]
        } else {
            explanation
        },
    }))
}

/// What to look at for a block reason. Pure.
pub fn advice(reason: &str) -> &'static str {
    match reason {
        "no_consent" => {
            "the audience lacks consent for the step's purpose; check the entry list or the purpose"
        }
        "frequency_cap" => {
            "people hit the weekly message cap; space the messages out or send fewer"
        }
        "suppressed" => {
            "the address is suppressed (a bounce, complaint or unsubscribe); clean the entry list"
        }
        "sunset" => "people stopped engaging and were sunset; narrow the entry to engaged people",
        "no email address" => "people have no email address; filter the entry list on email",
        _ => "look at the step's configuration and the people it blocks",
    }
}

async fn suggest(
    state: &EngineState,
    ctx: &ActionContext,
    args: &Value,
) -> Result<Value, AppError> {
    let journey = uuid_arg(args, "journey_id")?;
    let definition = attome_marketing::journey::routes::definition_of(state, journey).await?;
    let counts =
        attome_marketing::journey::insight::counts(state, &ctx.security, definition).await?;
    let latest = counts.nodes.last().map(|n| n.definition_version_id);
    let nodes: Vec<_> = counts
        .nodes
        .iter()
        .filter(|n| Some(n.definition_version_id) == latest)
        .collect();
    let mut suggestions = Vec::new();
    if let Some(node) = nodes
        .iter()
        .filter(|n| n.exited > 0)
        .max_by_key(|n| (n.exited, std::cmp::Reverse(n.node_id.clone())))
    {
        suggestions.push(json!({
            "kind": "drop_off",
            "node_id": node.node_id,
            "left": node.exited,
            "entered": node.entered,
            "text": format!(
                "Most people leave at {} ({} of {} who reached it); review its condition or timing.",
                node.node_id, node.exited, node.entered
            ),
        }));
    }
    let reasons: Vec<(String, i64)> = sqlx::query_as(
        "SELECT b.reason, COUNT(*) FROM marketing_journey_block b \
           JOIN marketing_journey_enrolment e ON e.instance_id = b.instance_id \
          WHERE e.definition_id = $1 AND NOT e.is_test \
          GROUP BY b.reason ORDER BY COUNT(*) DESC, b.reason LIMIT $2",
    )
    .bind(definition)
    .bind(TOP_REASONS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for (reason, n) in reasons {
        suggestions.push(json!({
            "kind": "block",
            "reason": reason,
            "count": n,
            "text": format!("{n} sends were blocked for {reason}: {}.", advice(&reason)),
        }));
    }
    Ok(json!({
        "journey_id": journey,
        "enrolled": counts.enrolled,
        "conversion": counts.conversion,
        "suggestions": suggestions,
    }))
}

pub(crate) struct Journey(&'static str);

impl Action for Journey {
    fn id(&self) -> ActionId {
        ActionId(self.0)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            match self.0 {
                DRAFT => draft(state, ctx, args).await,
                EXPLAIN_PERSON => {
                    ctx.security.require("marketing_journey", "read")?;
                    Ok(ActionResult::plain(explain_person(state, ctx, args).await?))
                }
                SUGGEST => {
                    ctx.security.require("marketing_journey", "read")?;
                    Ok(ActionResult::plain(suggest(state, ctx, args).await?))
                }
                _ => Err(AppError::NotFound),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(id: &str) -> ActionDescriptor {
        descriptors()
            .into_iter()
            .find(|d| d.id.as_str() == id)
            .expect("registered")
    }

    fn node(id: &str, node_type: &str, config: Value) -> DraftNode {
        DraftNode {
            id: id.into(),
            node_type: node_type.into(),
            config,
        }
    }

    fn edge(from: &str, to: &str) -> DraftEdge {
        DraftEdge {
            from_node: from.into(),
            from_port: "out".into(),
            to_node: to.into(),
            to_port: "in".into(),
        }
    }

    fn marketing_step(key: &str, config: &Value) -> Option<Result<(), String>> {
        (key == "marketing.send_email").then(|| {
            if config.get("design_id").is_some() {
                Ok(())
            } else {
                Err("design_id names a saved email design".into())
            }
        })
    }

    #[test]
    fn draft_never_publishes() {
        let d = descriptor(DRAFT);
        assert_eq!(d.effect, Effect::Read, "a draft writes nothing");
        assert_eq!(d.risk, RiskTier::Read);
        let definition = Uuid::now_v7();
        let graph = DraftGraph::default();
        for draft in [None, Some((Uuid::now_v7(), 4))] {
            let call = save_call(definition, draft, &graph);
            let path = call["path"].as_str().unwrap_or_default();
            assert!(path.contains("/versions"), "{path}");
            assert!(!path.contains("publish"), "{path}");
            assert_ne!(call["method"], json!("DELETE"));
        }
        assert_eq!(
            save_call(definition, Some((Uuid::nil(), 4)), &graph)["body"]["row_version"],
            json!(4),
            "an edit keeps the draft's row version"
        );
        assert!(
            descriptors()
                .iter()
                .all(|d| !d.id.as_str().contains("publish") && !d.id.as_str().contains("enrol")),
            "no publish or enrol action"
        );
    }

    #[test]
    fn explain_requires_person_read() {
        assert_eq!(
            descriptor(EXPLAIN_PERSON).required_privileges,
            &["marketing_journey.read"]
        );
        assert_eq!(
            descriptor(DRAFT).required_privileges,
            &["marketing_journey.update"]
        );
        let run = attome_marketing::journey::insight::PersonRun {
            enrolment_id: Uuid::nil(),
            status: "active".into(),
            entered_at: chrono::DateTime::UNIX_EPOCH,
            ended_at: None,
            end_reason: None,
            steps: vec![attome_marketing::journey::insight::PathStep {
                node_id: "welcome".into(),
                status: "waiting".into(),
                started_at: None,
                completed_at: None,
            }],
            blocks: vec![attome_marketing::journey::insight::PathBlock {
                node_id: "welcome".into(),
                reason: "frequency_cap".into(),
                at: chrono::DateTime::UNIX_EPOCH,
            }],
        };
        let text = explain_run(&run);
        assert!(text.contains("Blocked at welcome"), "{text}");
        assert!(text.contains("Still in the journey, at welcome"), "{text}");
    }

    #[test]
    fn hidden_without_module() {
        for d in descriptors() {
            assert_eq!(d.module, MODULE_MARKETING, "{}", d.id.as_str());
            assert_eq!(d.effect, Effect::Read, "{}", d.id.as_str());
        }
    }

    #[test]
    fn a_draft_uses_journey_steps_only() {
        let good = DraftGraph {
            nodes: vec![
                node("t", "trigger", json!({ "trigger_type": "manual" })),
                node(
                    "mail",
                    "module_step",
                    json!({ "handler": "marketing.send_email",
                            "config": { "design_id": Uuid::nil() } }),
                ),
            ],
            edges: vec![edge("t", "mail")],
        };
        assert_eq!(problems(&good, &marketing_step), Vec::<String>::new());

        let mut bad = good.clone();
        bad.nodes.push(node(
            "w",
            "update_record",
            json!({ "entity_logicalname": "consent" }),
        ));
        bad.nodes.push(node(
            "x",
            "module_step",
            json!({ "handler": "marketing.unknown" }),
        ));
        bad.nodes.push(node(
            "y",
            "module_step",
            json!({ "handler": "marketing.send_email" }),
        ));
        bad.nodes.push(node("t", "trigger", json!({})));
        bad.edges.push(edge("mail", "nowhere"));
        let found = problems(&bad, &marketing_step);
        assert!(
            found
                .iter()
                .any(|p| p.contains("cannot use \"update_record\"")),
            "{found:?}"
        );
        assert!(
            found.iter().any(|p| p.contains("not a marketing step")),
            "{found:?}"
        );
        assert!(found.iter().any(|p| p.contains("design_id")), "{found:?}");
        assert!(found.iter().any(|p| p.contains("used twice")), "{found:?}");
        assert!(found.iter().any(|p| p.contains("one trigger")), "{found:?}");
        assert!(found.iter().any(|p| p.contains("\"nowhere\"")), "{found:?}");
    }

    #[test]
    fn the_diff_names_what_changed() {
        let before = DraftGraph {
            nodes: vec![
                node("t", "trigger", json!({})),
                node("a", "wait", json!({ "seconds": 60 })),
                node("b", "wait", json!({})),
            ],
            edges: vec![edge("t", "a"), edge("a", "b")],
        };
        let after = DraftGraph {
            nodes: vec![
                node("t", "trigger", json!({})),
                node("a", "wait", json!({ "seconds": 120 })),
                node("c", "wait", json!({})),
            ],
            edges: vec![edge("t", "a"), edge("a", "c")],
        };
        let d = diff(&before, &after);
        assert_eq!(d.added_nodes, vec!["c"]);
        assert_eq!(d.removed_nodes, vec!["b"]);
        assert_eq!(d.changed_nodes, vec!["a"]);
        assert_eq!(d.added_edges, vec![edge("a", "c")]);
        assert_eq!(d.removed_edges, vec![edge("a", "b")]);
    }

    #[test]
    fn every_block_reason_gets_advice() {
        assert!(advice("no_consent").contains("consent"));
        assert!(advice("anything else").contains("configuration"));
    }
}
