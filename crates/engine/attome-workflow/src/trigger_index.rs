//! `workflow_trigger_index` maintenance (P-workflow-engine.md §4.3/§5
//! step 6) — denormalized, auto-derived, never hand-authored.
//!
//! Entity create/update auto-start (the `entity_logicalname` lookup this
//! module's `entry` rows exist for) is wired: `match_entry_triggers` is called
//! by `entity_trigger::dispatch_pending`, which drains the
//! `entity_change_event` outbox that every entity write records
//! (`crates/server/src/jobs.rs` runs it). The entity write path
//! (`attome-records`) cannot call into `attome-workflow` directly: attome-workflow
//! depends on attome-records for its entity-mutation primitives (§4.4
//! mechanism 1), so the reverse call would be a dependency cycle. Manual/API
//! starts (`instance_admin::start_manual`) and schedule/signal resumption use
//! the same entry/wait-index machinery.

use serde_json::Value;
use sqlx::{Postgres, Transaction};
use std::collections::HashSet;
use uuid::Uuid;

use crate::graph::Graph;
use crate::node_types::NodeType;

/// Publish-time rebuild for `role='entry'` rows, scoped to exactly this
/// `definition_version_id` — never touches any `role='wait'` row (§4.3: a
/// `wait` row belongs to one running instance, not to a definition version).
pub async fn rebuild_entry_rows(
    tx: &mut Transaction<'_, Postgres>,
    definition_version_id: Uuid,
    graph: &Graph,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM workflow_trigger_index \
         WHERE definition_version_id = $1 AND role = 'entry'",
    )
    .bind(definition_version_id)
    .execute(&mut **tx)
    .await?;

    for node in &graph.nodes {
        let Some(NodeType::Trigger) = NodeType::parse(&node.node_type) else {
            continue;
        };
        // Trigger config: {"trigger_type": "create"|"update"|"schedule"|"manual",
        // "entity_logicalname": "...", "condition": {...}, "expression": "..."}
        let trigger_type = node
            .config
            .get("trigger_type")
            .and_then(Value::as_str)
            .unwrap_or("manual")
            .to_owned();
        let entity_logicalname = node
            .config
            .get("entity_logicalname")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let condition = entry_condition(&node.config);

        sqlx::query(
            "INSERT INTO workflow_trigger_index \
                (definition_version_id, node_id, role, match_type, entity_logicalname, condition) \
             VALUES ($1, $2, 'entry', $3, $4, $5)",
        )
        .bind(definition_version_id)
        .bind(&node.id)
        .bind(&trigger_type)
        .bind(&entity_logicalname)
        .bind(&condition)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// The `condition` column of one entry row: the trigger's `condition` object
/// (the `record_id`/`operation` keys `entity_trigger` filters on) with the
/// trigger's attome-rules `expression` (M06 plan §4.2, G3) folded in under the
/// `expression` key, so dispatch reads both from the index row it already
/// fetched instead of re-loading the graph per event. `None` when the trigger
/// carries neither.
pub fn entry_condition(config: &Value) -> Option<Value> {
    let condition = config.get("condition").filter(|c| !c.is_null()).cloned();
    let expression = config.get("expression").and_then(Value::as_str);
    // M1-T1: an update trigger's `attributes` filter rides in the same column.
    let attributes = config
        .get("attributes")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty());
    if expression.is_none() && attributes.is_none() {
        return condition;
    }
    let mut merged = match condition {
        Some(Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    if let Some(expression) = expression {
        merged.insert(
            "expression".to_owned(),
            Value::String(expression.to_owned()),
        );
    }
    if let Some(attributes) = attributes {
        merged.insert("attributes".to_owned(), Value::Array(attributes.clone()));
    }
    Some(Value::Object(merged))
}

/// M18 Data Catalog Phase 1 (D-466) — the entity references a published
/// graph carries, for `metadata_reference` (`from_kind =
/// "workflow"`). Scans every node's `config` for an `entity_logicalname`
/// key, not just `role='entry'` trigger nodes: `rebuild_entry_rows` above
/// only cares about trigger nodes because only a trigger can start an
/// instance, but a record-create/update action node further down the same
/// graph names a target entity in its own `config` under the same key and
/// is just as real a "this workflow touches that entity" fact for the
/// catalog. Entity-level only (Phase 1 scope, same as the query writer) —
/// no attempt to resolve a specific field out of node config.
pub fn collect_entity_lineage(graph: &Graph) -> Vec<attome_core::MetadataReferenceInput> {
    let mut seen = HashSet::new();
    let mut refs = Vec::new();
    for node in &graph.nodes {
        let Some(entity) = node
            .config
            .get("entity_logicalname")
            .and_then(Value::as_str)
        else {
            continue;
        };
        if seen.insert(entity.to_owned()) {
            refs.push(attome_core::MetadataReferenceInput::entity(entity));
        }
    }
    refs
}

/// Inserted the instant a `node_run` transitions to `waiting` (§4.3).
#[allow(clippy::too_many_arguments)]
pub async fn insert_wait_row(
    tx: &mut Transaction<'_, Postgres>,
    definition_version_id: Uuid,
    node_id: &str,
    instance_id: Uuid,
    node_run_id: Uuid,
    match_type: &str,
    entity_logicalname: Option<&str>,
    condition: Option<&Value>,
    resume_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO workflow_trigger_index \
            (definition_version_id, node_id, role, instance_id, node_run_id, \
             match_type, entity_logicalname, condition, resume_at) \
         VALUES ($1, $2, 'wait', $3, $4, $5, $6, $7, $8)",
    )
    .bind(definition_version_id)
    .bind(node_id)
    .bind(instance_id)
    .bind(node_run_id)
    .bind(match_type)
    .bind(entity_logicalname)
    .bind(condition)
    .bind(resume_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Deleted the instant a `node_run` resumes, however it resumed.
pub async fn delete_wait_row(
    tx: &mut Transaction<'_, Postgres>,
    node_run_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM workflow_trigger_index WHERE role = 'wait' AND node_run_id = $1")
        .bind(node_run_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct EntryMatch {
    pub definition_version_id: Uuid,
    pub node_id: String,
    /// The entry row's `condition` ([`entry_condition`]'s shape), returned
    /// unevaluated — `entity_trigger` applies it after this indexed narrow.
    pub condition: Option<Value>,
}

/// "Which workflows should start on this entity event" (§4.3) — the indexed
/// lookup this table exists for. Called from `entity_trigger::
/// dispatch_pending`, not from the entity write path directly — see that
/// module's doc comment for why (attome-workflow depends on attome-records,
/// not the other way round).
pub async fn match_entry_triggers(
    db: &sqlx::PgPool,
    entity_logicalname: &str,
    trigger_type: &str,
) -> Result<Vec<EntryMatch>, sqlx::Error> {
    sqlx::query_as::<_, EntryMatch>(
        "SELECT ti.definition_version_id, ti.node_id, ti.condition \
         FROM workflow_trigger_index ti \
         JOIN workflow_definition_version v ON v.id = ti.definition_version_id \
         JOIN workflow_definition d ON d.id = v.definition_id \
         WHERE ti.role = 'entry' AND ti.entity_logicalname = $1 AND ti.match_type = $2 \
           AND v.status = 'published' AND d.is_active = TRUE AND d.is_deleted = FALSE",
    )
    .bind(entity_logicalname)
    .bind(trigger_type)
    .fetch_all(db)
    .await
}

#[derive(Debug, sqlx::FromRow)]
pub struct WaitMatch {
    pub instance_id: Uuid,
    pub node_id: String,
    pub node_run_id: Uuid,
    pub condition: Option<serde_json::Value>,
}

/// "Which running instance's Wait-for-Event node does this entity event
/// resume" (§4.3) — the `wait`-role sibling of `match_entry_triggers`.
/// Called from `entity_trigger::dispatch_pending`. `condition` is returned
/// unevaluated — the caller applies it as a secondary in-app filter after
/// this indexed narrow (§8 risk mitigation: `entity_logicalname` is the
/// real index; `condition` is never the primary lookup).
pub async fn match_wait_triggers(
    db: &sqlx::PgPool,
    entity_logicalname: &str,
) -> Result<Vec<WaitMatch>, sqlx::Error> {
    sqlx::query_as::<_, WaitMatch>(
        "SELECT instance_id, node_id, node_run_id, condition \
         FROM workflow_trigger_index \
         WHERE role = 'wait' AND match_type = 'entity_event' AND entity_logicalname = $1 \
           AND node_run_id IS NOT NULL",
    )
    .bind(entity_logicalname)
    .fetch_all(db)
    .await
}

#[cfg(test)]
mod catalog_lineage_tests {
    use super::collect_entity_lineage;
    use crate::graph::{Graph, GraphNode};
    use serde_json::json;

    fn node(id: &str, node_type: &str, config: serde_json::Value) -> GraphNode {
        GraphNode {
            id: id.to_owned(),
            node_type: node_type.to_owned(),
            config,
            ports: serde_json::Value::Null,
        }
    }

    #[test]
    fn collects_entity_logicalname_from_a_trigger_node() {
        let graph = Graph {
            nodes: vec![node(
                "n1",
                "trigger",
                json!({"trigger_type": "create", "entity_logicalname": "account"}),
            )],
            edges: vec![],
        };
        let refs = collect_entity_lineage(&graph);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].to_entity, "account");
        assert_eq!(refs[0].to_attribute, None);
    }

    #[test]
    fn collects_entity_logicalname_from_a_non_trigger_action_node_too() {
        // A record-create/update action node further down the graph names a
        // target entity the same way a trigger node does — this is exactly
        // the gap `collect_entity_lineage`'s doc comment explains
        // `rebuild_entry_rows` alone would miss.
        let graph = Graph {
            nodes: vec![node(
                "n2",
                "record_create",
                json!({"entity_logicalname": "opportunity"}),
            )],
            edges: vec![],
        };
        let refs = collect_entity_lineage(&graph);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].to_entity, "opportunity");
    }

    #[test]
    fn deduplicates_the_same_entity_referenced_by_multiple_nodes() {
        let graph = Graph {
            nodes: vec![
                node(
                    "n1",
                    "trigger",
                    json!({"trigger_type": "update", "entity_logicalname": "account"}),
                ),
                node(
                    "n2",
                    "record_update",
                    json!({"entity_logicalname": "account"}),
                ),
            ],
            edges: vec![],
        };
        let refs = collect_entity_lineage(&graph);
        assert_eq!(refs.len(), 1);
    }

    #[test]
    fn ignores_a_node_with_no_entity_logicalname_in_its_config() {
        let graph = Graph {
            nodes: vec![node("n1", "approval", json!({"approver": "manager"}))],
            edges: vec![],
        };
        assert!(collect_entity_lineage(&graph).is_empty());
    }

    #[test]
    fn empty_graph_collects_nothing() {
        assert!(collect_entity_lineage(&Graph::default()).is_empty());
    }
}
