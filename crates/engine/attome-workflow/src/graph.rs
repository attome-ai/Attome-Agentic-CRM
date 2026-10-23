//! Graph parsing + publish-time validation (P-workflow-engine.md §4.3/§5
//! step 4). Cycle detection and port-type compatibility run once, at the
//! draft->published transition — never at execution time (a bad graph fails
//! fast in the editor, not at 2am in production).

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::node_types::{NodeType, PortType};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct GraphNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(default)]
    pub config: serde_json::Value,
    /// Editor-owned positional/label metadata — opaque passthrough, never
    /// interpreted by the engine (§5 step 3: port compatibility lives in the
    /// registry, not the graph JSON).
    #[serde(default)]
    pub ports: serde_json::Value,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct GraphEdge {
    pub from_node: String,
    pub from_port: String,
    pub to_node: String,
    pub to_port: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct Graph {
    #[serde(default)]
    pub nodes: Vec<GraphNode>,
    #[serde(default)]
    pub edges: Vec<GraphEdge>,
}

impl Graph {
    pub fn parse(value: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value.clone()).map_err(|e| format!("graph did not parse: {e}"))
    }

    pub fn node(&self, id: &str) -> Option<&GraphNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    pub fn inbound_edges<'a>(&'a self, node_id: &'a str) -> impl Iterator<Item = &'a GraphEdge> {
        self.edges.iter().filter(move |e| e.to_node == node_id)
    }

    pub fn outbound_edges<'a>(&'a self, node_id: &'a str) -> impl Iterator<Item = &'a GraphEdge> {
        self.edges.iter().filter(move |e| e.from_node == node_id)
    }
}

/// §8 risk mitigation, called from `admin::publish_version`: rejects a
/// `sub_workflow` node whose `config.definition_logicalname` names the
/// SAME definition this graph belongs to — the cheap, always-catchable half
/// of the "sub-workflow recursion" risk (a cycle across two or more
/// *different* definitions can't be fully ruled out at publish time, since
/// a target definition can be edited/republished later — see
/// `limits.workflow.max_nesting` for that half). Pure and DB-free so
/// it's directly unit-testable, unlike the HTTP handler it's called from.
pub fn reject_self_referencing_sub_workflow(
    graph: &Graph,
    own_logicalname: &str,
) -> Result<(), ValidationError> {
    for node in &graph.nodes {
        // M1-T4: a for-each runs its flow too.
        if node.node_type != "sub_workflow" && node.node_type != "for_each" {
            continue;
        }
        if node
            .config
            .get("definition_logicalname")
            .and_then(serde_json::Value::as_str)
            == Some(own_logicalname)
        {
            return Err(ValidationError(format!(
                "sub_workflow node {:?} points at this workflow's own definition ({own_logicalname:?}) — \
                 a workflow cannot call itself as a sub-workflow",
                node.id
            )));
        }
    }
    Ok(())
}

/// Fingerprint of the built-in node-type/port schema (never of the graph
/// itself) — what `node_schema_hash` on `workflow_definition_version`
/// stores, so a later release that reshapes a node type's ports can detect
/// that an old published graph was validated against a different schema.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
pub fn schema_hash() -> String {
    let mut canonical = Vec::new();
    for t in NodeType::ALL {
        canonical.push((
            t.as_str(),
            t.input_ports()
                .iter()
                .map(|(n, p, r)| (*n, p.as_str(), *r))
                .collect::<Vec<_>>(),
            t.output_ports()
                .iter()
                .map(|(n, p)| (*n, p.as_str()))
                .collect::<Vec<_>>(),
        ));
    }
    let json = serde_json::to_string(&canonical).expect("static schema always serializes");
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError(pub String);

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Cycle detection + port-type compatibility + reachability, run at
/// draft->published (§4.3). Returns the schema hash on success. Deliberately
/// **not** in scope here: cross-graph sub-workflow-ancestry cycle detection
/// (§5 step 4 / §8 risk) — that needs the target definition's own published
/// graph, which this pure/synchronous function has no DB access to fetch;
/// it is checked separately, at the call site in `admin.rs`'s
/// `publish_version`, against already-loaded ancestry.
/// E8-T2: every module step names a registered handler whose module is
/// licensed and which accepts the node's `config.config`. Separate from
/// [`validate`] because it needs the running deployment (its handlers and
/// licence); publish calls both.
pub fn validate_module_steps(
    state: &attome_core::EngineState,
    graph: &Graph,
) -> Result<(), attome_types::AppError> {
    for node in &graph.nodes {
        if NodeType::parse(&node.node_type) != Some(NodeType::ModuleStep) {
            continue;
        }
        let handler = crate::scheduler::module_step_handler(state, node).map_err(|e| {
            attome_types::AppError::Validation(format!("graph validation failed: {e}"))
        })?;
        handler
            .validate_config(
                node.config
                    .get("config")
                    .unwrap_or(&serde_json::Value::Null),
            )
            .map_err(|reason| {
                attome_types::AppError::Validation(format!(
                    "graph validation failed: module step {:?}: {reason}",
                    node.id
                ))
            })?;
    }
    Ok(())
}

pub fn validate(graph: &Graph) -> Result<String, ValidationError> {
    if graph.nodes.is_empty() {
        return Err(ValidationError("graph has no nodes".into()));
    }

    let mut seen_ids = HashSet::new();
    let mut typed: HashMap<&str, NodeType> = HashMap::new();
    for node in &graph.nodes {
        if !seen_ids.insert(node.id.as_str()) {
            return Err(ValidationError(format!("duplicate node id {:?}", node.id)));
        }
        let node_type = NodeType::parse(&node.node_type).ok_or_else(|| {
            ValidationError(format!(
                "node {:?} has unknown type {:?}",
                node.id, node.node_type
            ))
        })?;
        typed.insert(node.id.as_str(), node_type);
        // M1-T4: a for-each names its flow and a batch of 1 to 100.
        if node_type == NodeType::ForEach {
            if node
                .config
                .get("definition_logicalname")
                .and_then(serde_json::Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(ValidationError(format!(
                    "for_each node {:?} must name the flow to run (definition_logicalname)",
                    node.id
                )));
            }
            if let Some(size) = node.config.get("batch_size")
                && !size.as_i64().is_some_and(|n| (1..=100).contains(&n))
            {
                return Err(ValidationError(format!(
                    "for_each node {:?}: batch_size must be a whole number from 1 to 100",
                    node.id
                )));
            }
        }
        // S14-T1: a connector names its system and operation; a map's
        // mapping is well formed.
        if node_type == NodeType::Connector {
            crate::scheduler::connector_target(node).map_err(|e| ValidationError(e.to_string()))?;
        }
        if node_type == NodeType::Map {
            crate::map::check(node.config.get("mapping"), node.config.get("each"))
                .map_err(|message| ValidationError(format!("map node {:?}: {message}", node.id)))?;
        }
        // Z11-T15: a Condition's expression parses at publish.
        if node_type == NodeType::Condition
            && let Some(expression) = crate::condition::expression_of(&node.config)
        {
            let src = expression.as_str().ok_or_else(|| {
                ValidationError(format!("node {:?}: expression must be text", node.id))
            })?;
            crate::condition::check_expression(src)
                .map_err(|message| ValidationError(format!("node {:?}: {message}", node.id)))?;
        }
    }

    let entry_nodes: Vec<&str> = graph
        .nodes
        .iter()
        .filter(|n| typed[n.id.as_str()].is_entry())
        .map(|n| n.id.as_str())
        .collect();
    if entry_nodes.is_empty() {
        return Err(ValidationError(
            "graph has no entry (Trigger) node — nothing can ever start an instance".into(),
        ));
    }

    // Edge referential + port-type validation.
    for edge in &graph.edges {
        let from_type = *typed.get(edge.from_node.as_str()).ok_or_else(|| {
            ValidationError(format!(
                "edge references unknown from_node {:?}",
                edge.from_node
            ))
        })?;
        let to_type = *typed.get(edge.to_node.as_str()).ok_or_else(|| {
            ValidationError(format!(
                "edge references unknown to_node {:?}",
                edge.to_node
            ))
        })?;
        // M1-T4: every node but a trigger has an `on_error` port.
        let error_port = (edge.from_port == crate::node_types::ON_ERROR_PORT
            && !from_type.is_entry())
        .then_some((crate::node_types::ON_ERROR_PORT, PortType::Json));
        let (_, from_port_type) = from_type
            .output_ports()
            .iter()
            .find(|(name, _)| *name == edge.from_port)
            .copied()
            .or(error_port)
            .ok_or_else(|| {
                ValidationError(format!(
                    "node {:?} ({from_type}) has no output port {:?}",
                    edge.from_node, edge.from_port
                ))
            })?;
        let (_, to_port_type, _) = to_type
            .input_ports()
            .iter()
            .find(|(name, _, _)| *name == edge.to_port)
            .copied()
            .ok_or_else(|| {
                ValidationError(format!(
                    "node {:?} ({to_type}) has no input port {:?}",
                    edge.to_node, edge.to_port
                ))
            })?;
        if !from_port_type.compatible_with(to_port_type) {
            return Err(ValidationError(format!(
                "edge {}:{} -> {}:{} is port-type incompatible ({} vs {})",
                edge.from_node,
                edge.from_port,
                edge.to_node,
                edge.to_port,
                from_port_type.as_str(),
                to_port_type.as_str()
            )));
        }
    }

    // An entry node must have no inbound edges; every other node must have
    // at least one (else it can never become ready) — every required input
    // port needs a satisfying edge.
    for node in &graph.nodes {
        let node_type = typed[node.id.as_str()];
        let inbound: Vec<&GraphEdge> = graph.inbound_edges(&node.id).collect();
        if node_type.is_entry() {
            if !inbound.is_empty() {
                return Err(ValidationError(format!(
                    "entry node {:?} must have no inbound edges",
                    node.id
                )));
            }
            continue;
        }
        for (port_name, _, required) in node_type.input_ports() {
            if *required && !inbound.iter().any(|e| e.to_port == *port_name) {
                return Err(ValidationError(format!(
                    "node {:?} ({node_type}) required input port {:?} has no inbound edge",
                    node.id, port_name
                )));
            }
        }
    }

    // Cycle detection — node-level DFS, three-color (white/gray/black).
    #[derive(Clone, Copy, PartialEq)]
    enum Color {
        White,
        Gray,
        Black,
    }
    let mut color: HashMap<&str, Color> = graph
        .nodes
        .iter()
        .map(|n| (n.id.as_str(), Color::White))
        .collect();

    fn visit<'a>(
        node_id: &'a str,
        graph: &'a Graph,
        color: &mut HashMap<&'a str, Color>,
    ) -> Result<(), ValidationError> {
        color.insert(node_id, Color::Gray);
        for edge in graph.outbound_edges(node_id) {
            match color.get(edge.to_node.as_str()) {
                Some(Color::Gray) => {
                    return Err(ValidationError(format!(
                        "graph contains a cycle through node {:?}",
                        edge.to_node
                    )));
                }
                Some(Color::White) => visit(&edge.to_node, graph, color)?,
                _ => {}
            }
        }
        color.insert(node_id, Color::Black);
        Ok(())
    }

    for node in &graph.nodes {
        if color[node.id.as_str()] == Color::White {
            visit(&node.id, graph, &mut color)?;
        }
    }

    // Reachability: every node must be reachable from some entry node, else
    // it is dead weight that can never run or be skipped meaningfully.
    let mut reachable: HashSet<&str> = HashSet::new();
    let mut stack: Vec<&str> = entry_nodes.clone();
    while let Some(id) = stack.pop() {
        if !reachable.insert(id) {
            continue;
        }
        for edge in graph.outbound_edges(id) {
            stack.push(edge.to_node.as_str());
        }
    }
    for node in &graph.nodes {
        if !reachable.contains(node.id.as_str()) {
            return Err(ValidationError(format!(
                "node {:?} is unreachable from any entry (Trigger) node",
                node.id
            )));
        }
    }

    // M06 checklist item 1: every `Split` must have a matching `Join`
    // reachable downstream of it — a fan-out with nowhere to rejoin is
    // authoring error, not a valid parallel branch, and it is cheap to catch
    // here rather than leave dangling branches running forever in
    // production. The graph is already known acyclic by this point (the
    // cycle check above ran first), so this forward walk always terminates.
    for node in &graph.nodes {
        if typed[node.id.as_str()] != NodeType::Split {
            continue;
        }
        let mut seen: HashSet<&str> = HashSet::new();
        let mut stack: Vec<&str> = vec![node.id.as_str()];
        let mut found = false;
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            for edge in graph.outbound_edges(id) {
                if typed[edge.to_node.as_str()] == NodeType::Join {
                    found = true;
                    break;
                }
                stack.push(edge.to_node.as_str());
            }
            if found {
                break;
            }
        }
        if !found {
            return Err(ValidationError(format!(
                "split node {:?} has no reachable Join node — every Split must eventually rejoin",
                node.id
            )));
        }
    }

    Ok(schema_hash())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, ty: &str) -> GraphNode {
        GraphNode {
            id: id.into(),
            node_type: ty.into(),
            config: serde_json::json!({}),
            ports: serde_json::json!({}),
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

    #[test]
    fn empty_graph_is_rejected() {
        let g = Graph::default();
        assert!(validate(&g).is_err());
    }

    #[test]
    fn graph_with_no_trigger_is_rejected() {
        let g = Graph {
            nodes: vec![node("a", "condition")],
            edges: vec![],
        };
        assert!(validate(&g).is_err());
    }

    #[test]
    fn simple_trigger_to_condition_graph_validates() {
        let g = Graph {
            nodes: vec![node("t", "trigger"), node("c", "condition")],
            edges: vec![edge("t", "out", "c", "value")],
        };
        assert!(validate(&g).is_ok());
    }

    #[test]
    fn unknown_node_type_is_rejected() {
        let g = Graph {
            nodes: vec![node("t", "trigger"), node("x", "not_a_real_type")],
            edges: vec![edge("t", "out", "x", "in")],
        };
        assert!(validate(&g).is_err());
    }

    #[test]
    fn port_type_incompatible_edge_is_rejected() {
        // create_record's only output is "record" (RecordId); wiring it into
        // condition's "value" (Any) is fine, but wiring create_record's
        // record straight into another create_record's "data" (Json) is not.
        let g = Graph {
            nodes: vec![
                node("t", "trigger"),
                node("c1", "create_record"),
                node("c2", "create_record"),
            ],
            edges: vec![
                edge("t", "out", "c1", "data"),
                edge("c1", "record", "c2", "data"),
            ],
        };
        assert!(validate(&g).is_err());
    }

    #[test]
    fn cyclic_graph_is_rejected() {
        let g = Graph {
            nodes: vec![node("t", "trigger"), node("a", "wait"), node("b", "wait")],
            edges: vec![
                edge("t", "out", "a", "in"),
                edge("a", "out", "b", "in"),
                edge("b", "out", "a", "in"),
            ],
        };
        assert!(validate(&g).is_err());
    }

    #[test]
    fn unreachable_node_is_rejected() {
        let g = Graph {
            nodes: vec![node("t", "trigger"), node("orphan", "wait")],
            edges: vec![],
        };
        assert!(validate(&g).is_err());
    }

    #[test]
    fn missing_required_input_edge_is_rejected() {
        let g = Graph {
            nodes: vec![node("t", "trigger"), node("u", "update_record")],
            edges: vec![edge("t", "out", "u", "record_id")],
        };
        // update_record also requires "data" — not wired.
        assert!(validate(&g).is_err());
    }

    #[test]
    fn schema_hash_is_stable_across_calls() {
        assert_eq!(schema_hash(), schema_hash());
    }

    /// M32 Phase 1 (D-450): a well-formed `agent_step` graph — task wired
    /// in, output free to leave unwired — validates like any other node.
    #[test]
    fn agent_step_graph_with_task_wired_validates() {
        let g = Graph {
            nodes: vec![node("t", "trigger"), node("a", "agent_step")],
            edges: vec![edge("t", "out", "a", "task")],
        };
        assert!(validate(&g).is_ok());
    }

    /// `agent_step`'s "task" input port is required — an unwired one fails
    /// the same required-input-port check every other node type gets, not a
    /// special case.
    #[test]
    fn agent_step_without_its_required_task_input_is_rejected() {
        let g = Graph {
            nodes: vec![node("t", "trigger"), node("a", "agent_step")],
            edges: vec![],
        };
        assert!(validate(&g).is_err());
    }

    #[test]
    fn self_referencing_sub_workflow_is_rejected() {
        let mut sw = node("sw", "sub_workflow");
        sw.config = serde_json::json!({ "definition_logicalname": "my-own-workflow" });
        let g = Graph {
            nodes: vec![node("t", "trigger"), sw],
            edges: vec![edge("t", "out", "sw", "input")],
        };
        assert!(reject_self_referencing_sub_workflow(&g, "my-own-workflow").is_err());
    }

    #[test]
    fn split_with_no_reachable_join_is_rejected() {
        let g = Graph {
            nodes: vec![
                node("t", "trigger"),
                node("s", "split"),
                node("a", "wait"),
                node("b", "wait"),
            ],
            edges: vec![
                edge("t", "out", "s", "in"),
                edge("s", "out", "a", "in"),
                edge("s", "out", "b", "in"),
            ],
        };
        let err = validate(&g).unwrap_err();
        assert!(err.0.contains("no reachable Join"), "{}", err.0);
    }

    #[test]
    fn split_with_reachable_join_is_accepted() {
        let g = Graph {
            nodes: vec![
                node("t", "trigger"),
                node("s", "split"),
                node("a", "wait"),
                node("b", "wait"),
                node("j", "join"),
            ],
            edges: vec![
                edge("t", "out", "s", "in"),
                edge("s", "out", "a", "in"),
                edge("s", "out", "b", "in"),
                edge("a", "out", "j", "in"),
                edge("b", "out", "j", "in"),
            ],
        };
        assert!(validate(&g).is_ok());
    }

    /// M33 Phase 1 (D-460): a chain of two `AgentStep`s — the first's
    /// `outcome` (Json) wired into the second's `handoff` (Json) — validates.
    /// This is the mechanism "AgentStep chaining" actually rests on: without
    /// this port existing, no graph could ever wire one AgentStep's
    /// structured output into another's input at all, since `outcome`
    /// (Json) and `task` (Text) are deliberately port-incompatible (the next
    /// test).
    #[test]
    fn agent_step_outcome_chains_into_a_second_agent_steps_handoff_port() {
        let g = Graph {
            nodes: vec![
                node("t", "trigger"),
                node("a", "agent_step"),
                node("b", "agent_step"),
            ],
            edges: vec![
                edge("t", "out", "a", "task"),
                edge("t", "out", "b", "task"),
                edge("a", "outcome", "b", "handoff"),
            ],
        };
        assert!(validate(&g).is_ok());
    }

    /// The port-type boundary that makes the handoff port necessary in the
    /// first place: an `AgentStep`'s Json `outcome` cannot be wired directly
    /// into another `AgentStep`'s Text `task` port. A graph author must
    /// route structured agent output through `handoff`, never mistake it for
    /// a literal instruction string.
    #[test]
    fn agent_step_outcome_cannot_wire_directly_into_another_agent_steps_task() {
        let g = Graph {
            nodes: vec![
                node("t", "trigger"),
                node("a", "agent_step"),
                node("b", "agent_step"),
            ],
            edges: vec![
                edge("t", "out", "a", "task"),
                edge("a", "outcome", "b", "task"),
            ],
        };
        assert!(validate(&g).is_err());
    }

    /// `handoff` is optional — an `AgentStep` with only `task` wired (no
    /// chaining) still validates, same as before this port existed.
    #[test]
    fn agent_step_without_a_handoff_edge_still_validates() {
        let g = Graph {
            nodes: vec![node("t", "trigger"), node("a", "agent_step")],
            edges: vec![edge("t", "out", "a", "task")],
        };
        assert!(validate(&g).is_ok());
    }

    /// M33 Phase 1 (D-460): a well-formed `Route` node — `context` wired in,
    /// both `matched`/`unmatched` outputs free to leave unwired (a graph
    /// author may only care about one branch) — validates like `Condition`.
    #[test]
    fn route_graph_with_context_wired_validates() {
        let g = Graph {
            nodes: vec![node("t", "trigger"), node("r", "route")],
            edges: vec![edge("t", "out", "r", "context")],
        };
        assert!(validate(&g).is_ok());
    }

    /// `route`'s "context" input port is required, same as any other node's
    /// required port.
    #[test]
    fn route_without_its_required_context_input_is_rejected() {
        let g = Graph {
            nodes: vec![node("t", "trigger"), node("r", "route")],
            edges: vec![],
        };
        assert!(validate(&g).is_err());
    }

    /// A `Route` node's two outputs can each feed a different downstream
    /// `AgentStep` — the whole point of the type — through the `handoff`
    /// port (Json, matching `matched`/`unmatched`'s own Json output). This
    /// is a full Route -> two-agent shape: whichever branch fires decides
    /// which agent runs next.
    #[test]
    fn route_matched_and_unmatched_can_each_hand_off_to_a_different_agent_step() {
        let g = Graph {
            nodes: vec![
                node("t", "trigger"),
                node("r", "route"),
                node("a", "agent_step"),
                node("b", "agent_step"),
            ],
            edges: vec![
                edge("t", "out", "r", "context"),
                edge("t", "out", "a", "task"),
                edge("t", "out", "b", "task"),
                edge("r", "matched", "a", "handoff"),
                edge("r", "unmatched", "b", "handoff"),
            ],
        };
        assert!(validate(&g).is_ok());
    }

    /// `Route`'s outputs are Json, `AgentStep`'s `task` is Text — wiring a
    /// route decision directly into a literal instruction string is
    /// rejected, the same port-incompatibility direction the AgentStep
    /// chaining tests above establish for `outcome` -> `task`.
    #[test]
    fn route_output_cannot_wire_directly_into_an_agent_steps_task() {
        let g = Graph {
            nodes: vec![
                node("t", "trigger"),
                node("r", "route"),
                node("a", "agent_step"),
            ],
            edges: vec![
                edge("t", "out", "r", "context"),
                edge("r", "matched", "a", "task"),
            ],
        };
        assert!(validate(&g).is_err());
    }

    #[test]
    fn sub_workflow_pointing_at_a_different_definition_is_accepted() {
        let mut sw = node("sw", "sub_workflow");
        sw.config = serde_json::json!({ "definition_logicalname": "some-other-workflow" });
        let g = Graph {
            nodes: vec![node("t", "trigger"), sw],
            edges: vec![edge("t", "out", "sw", "input")],
        };
        assert!(reject_self_referencing_sub_workflow(&g, "my-own-workflow").is_ok());
    }
}
