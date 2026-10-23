//! L5-T2: a flow's lineage edges, captured when a version is published.
//!
//! The flow implements `attome_core::lineage::EdgeSource` here, where its
//! graph is understood:
//! - a trigger on an entity is a `triggers` edge, and its expression or
//!   field condition reads that entity's attributes;
//! - a condition node reads the trigger entity's fields it names;
//! - a create or update record node writes its entity, at attribute level
//!   when its config names the fields it sets (`data`/`fields`), else as
//!   `entity_only` (the values arrive at run time);
//! - any other node naming an entity reads it, `entity_only`.

use attome_core::lineage::capture::ExpressionSource;
use attome_core::lineage::{Edge, EdgeKind, EdgeSource};
use serde_json::Value;

use crate::graph::Graph;

/// The flow edge source.
#[derive(Debug, Clone, Copy, Default)]
pub struct FlowSource;

fn condition_edges(entity: &str, config: &Value, out: &mut Vec<Edge>) {
    if let Some(expression) = config.get("expression") {
        out.extend(
            ExpressionSource {
                entity: entity.to_owned(),
                kind: EdgeKind::Reads,
            }
            .edges(expression),
        );
    }
    for condition in [config.get("condition"), Some(config)]
        .into_iter()
        .flatten()
    {
        if let Some(field) = condition.get("field").and_then(Value::as_str) {
            out.push(Edge::attribute(entity, field, EdgeKind::Reads));
        }
    }
}

impl EdgeSource for FlowSource {
    fn edges(&self, def: &Value) -> Vec<Edge> {
        let Ok(graph) = serde_json::from_value::<Graph>(def.clone()) else {
            return Vec::new();
        };
        let trigger_entity = graph
            .nodes
            .iter()
            .filter(|n| n.node_type == "trigger")
            .find_map(|n| n.config.get("entity_logicalname").and_then(Value::as_str))
            .map(str::to_owned);
        let mut out = Vec::new();
        for node in &graph.nodes {
            match node.node_type.as_str() {
                "trigger" => {
                    if let Some(entity) = node
                        .config
                        .get("entity_logicalname")
                        .and_then(Value::as_str)
                    {
                        out.push(Edge::entity(entity, EdgeKind::Triggers));
                        condition_edges(entity, &node.config, &mut out);
                    }
                }
                "condition" => {
                    if let Some(entity) = &trigger_entity {
                        condition_edges(entity, &node.config, &mut out);
                    }
                }
                "create_record" | "update_record" => {
                    let Some(entity) = node
                        .config
                        .get("entity")
                        .or_else(|| node.config.get("entity_logicalname"))
                        .and_then(Value::as_str)
                    else {
                        continue;
                    };
                    let fields: Vec<&String> = ["data", "fields"]
                        .iter()
                        .filter_map(|k| node.config.get(*k).and_then(Value::as_object))
                        .flat_map(|m| m.keys())
                        .collect();
                    if fields.is_empty() {
                        out.push(Edge::entity_only(entity, EdgeKind::Writes));
                    } else {
                        out.extend(
                            fields
                                .iter()
                                .map(|f| Edge::attribute(entity, f, EdgeKind::Writes)),
                        );
                    }
                }
                _ => {
                    if let Some(entity) = node
                        .config
                        .get("entity_logicalname")
                        .and_then(Value::as_str)
                    {
                        out.push(Edge::entity_only(entity, EdgeKind::Reads));
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::lineage::{Confidence, merge};
    use serde_json::json;

    #[test]
    fn flow_update_is_write_edge() {
        let graph = json!({
            "nodes": [
                { "id": "t", "type": "trigger",
                  "config": { "entity_logicalname": "case", "expression": "priority == \"high\"" } },
                { "id": "c", "type": "condition", "config": { "field": "status", "op": "eq", "value": "open" } },
                { "id": "u", "type": "update_record",
                  "config": { "entity": "case", "data": { "escalated": true } } },
                { "id": "n", "type": "create_record", "config": { "entity": "task" } }
            ],
            "edges": []
        });
        let edges = merge(FlowSource.edges(&graph));
        let find = |entity: &str, attr: Option<&str>| {
            edges
                .iter()
                .find(|e| e.to_entity == entity && e.to_attribute.as_deref() == attr)
                .cloned()
        };
        assert_eq!(find("case", None).map(|e| e.kind), Some(EdgeKind::Triggers));
        assert_eq!(
            find("case", Some("priority")).map(|e| e.kind),
            Some(EdgeKind::Reads)
        );
        assert_eq!(
            find("case", Some("status")).map(|e| e.kind),
            Some(EdgeKind::Reads)
        );
        assert_eq!(
            find("case", Some("escalated")).map(|e| e.kind),
            Some(EdgeKind::Writes)
        );
        let task = find("task", None).expect("the created entity");
        assert_eq!(
            (task.kind, task.confidence),
            (EdgeKind::Writes, Confidence::EntityOnly)
        );
    }
}
