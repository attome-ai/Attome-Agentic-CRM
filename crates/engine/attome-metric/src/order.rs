//! P9-T8: the order KPI trees are computed in — every metric after its
//! children (`parent_ref`) and after the metrics its formula reads — so a
//! formula parent reads its inputs' snapshots from the same run.
//!
//! [`evaluation_order`] is a topological sort (Kahn's, ties broken by key so
//! the order is stable) and refuses a cycle with a 422 naming its metrics.
//! A formula key that names no metric adds no edge: that metric's own
//! compute fails with "unknown metric key" as before, and the rest of the
//! run goes on (the sweep's failure isolation).

use std::collections::{BTreeMap, BTreeSet};

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// One metric as the order sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricNode {
    pub id: Uuid,
    pub key: String,
    /// The metric this one rolls up into.
    pub parent: Option<Uuid>,
    /// The metric keys its formula reads.
    pub inputs: Vec<String>,
}

/// The metrics in computing order: children and formula inputs first.
/// Pure.
pub fn evaluation_order(nodes: &[MetricNode]) -> Result<Vec<Uuid>, AppError> {
    let by_key: BTreeMap<&str, Uuid> = nodes.iter().map(|n| (n.key.as_str(), n.id)).collect();
    let keys: BTreeMap<Uuid, &str> = nodes.iter().map(|n| (n.id, n.key.as_str())).collect();
    // `before[x]` = metrics that must be computed before x.
    let mut before: BTreeMap<Uuid, BTreeSet<Uuid>> =
        nodes.iter().map(|n| (n.id, BTreeSet::new())).collect();
    for node in nodes {
        if let Some(parent) = node
            .parent
            .filter(|p| keys.contains_key(p) && *p != node.id)
        {
            before.entry(parent).or_default().insert(node.id);
        }
        for input in &node.inputs {
            if let Some(&dep) = by_key.get(input.as_str())
                && dep != node.id
            {
                before.entry(node.id).or_default().insert(dep);
            }
        }
    }
    let mut order = Vec::with_capacity(nodes.len());
    let mut done: BTreeSet<Uuid> = BTreeSet::new();
    loop {
        let mut ready: Vec<(&str, Uuid)> = before
            .iter()
            .filter(|(id, deps)| !done.contains(*id) && deps.iter().all(|d| done.contains(d)))
            .map(|(id, _)| (keys.get(id).copied().unwrap_or(""), *id))
            .collect();
        if ready.is_empty() {
            break;
        }
        ready.sort();
        for (_, id) in ready {
            done.insert(id);
            order.push(id);
        }
    }
    if order.len() < before.len() {
        let mut stuck: Vec<&str> = before
            .keys()
            .filter(|id| !done.contains(*id))
            .map(|id| keys.get(id).copied().unwrap_or(""))
            .collect();
        stuck.sort_unstable();
        return Err(AppError::Validation(format!(
            "metrics form a cycle: {}",
            stuck.join(", ")
        )));
    }
    Ok(order)
}

/// The metrics `root` is computed from, itself included: its children and
/// formula inputs, transitively. Pure.
pub fn tree_under(nodes: &[MetricNode], root: Uuid) -> Vec<MetricNode> {
    let by_key: BTreeMap<&str, &MetricNode> = nodes.iter().map(|n| (n.key.as_str(), n)).collect();
    let mut seen: BTreeSet<Uuid> = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        stack.extend(nodes.iter().filter(|n| n.parent == Some(id)).map(|n| n.id));
        if let Some(node) = nodes.iter().find(|n| n.id == id) {
            stack.extend(
                node.inputs
                    .iter()
                    .filter_map(|k| by_key.get(k.as_str()).map(|n| n.id)),
            );
        }
    }
    nodes
        .iter()
        .filter(|n| seen.contains(&n.id))
        .cloned()
        .collect()
}

/// Every live metric as a node; a formula that does not parse reads no
/// inputs (its compute reports the error).
pub async fn load_nodes(db: &DbPool) -> Result<Vec<MetricNode>, AppError> {
    let rows: Vec<(Uuid, String, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT d.id, COALESCE(d.key, d.id::text), to_jsonb(d) FROM dashboard_metric_definition d \
          WHERE d.is_active IS NULL OR d.is_active = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(id, key, row)| {
            let row = row.unwrap_or_default();
            let parent = row
                .get("parent_ref")
                .and_then(serde_json::Value::as_str)
                .and_then(|p| Uuid::parse_str(p).ok());
            let inputs = row
                .get("formula")
                .and_then(serde_json::Value::as_str)
                .filter(|f| !f.trim().is_empty())
                .and_then(|f| crate::metric::formula_metric_keys(f).ok())
                .unwrap_or_default();
            MetricNode {
                id,
                key,
                parent,
                inputs,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(n: u128, key: &str, parent: Option<u128>, inputs: &[&str]) -> MetricNode {
        MetricNode {
            id: Uuid::from_u128(n),
            key: key.to_owned(),
            parent: parent.map(Uuid::from_u128),
            inputs: inputs.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn position(order: &[Uuid], n: u128) -> usize {
        order
            .iter()
            .position(|id| *id == Uuid::from_u128(n))
            .unwrap()
    }

    #[test]
    fn children_before_parent() {
        let nodes = vec![
            node(1, "margin", None, &["revenue", "cost"]),
            node(2, "revenue", Some(1), &[]),
            node(3, "cost", None, &[]),
            node(4, "east_revenue", Some(2), &[]),
            node(5, "missing_input", None, &["no_such_key"]),
        ];
        let order = evaluation_order(&nodes).unwrap();
        assert_eq!(order.len(), 5);
        assert!(position(&order, 4) < position(&order, 2));
        assert!(position(&order, 2) < position(&order, 1));
        assert!(position(&order, 3) < position(&order, 1));
        // Stable: the same input gives the same order.
        assert_eq!(order, evaluation_order(&nodes).unwrap());
    }

    #[test]
    fn cycle_is_reported() {
        let nodes = vec![
            node(1, "a", None, &["b"]),
            node(2, "b", None, &["c"]),
            node(3, "c", None, &["a"]),
            node(4, "free", None, &[]),
        ];
        let Err(AppError::Validation(message)) = evaluation_order(&nodes) else {
            panic!("a cycle must be refused");
        };
        assert_eq!(message, "metrics form a cycle: a, b, c");
    }

    #[test]
    fn tree_under_takes_children_and_inputs() {
        let nodes = vec![
            node(1, "margin", None, &["revenue", "cost"]),
            node(2, "revenue", None, &[]),
            node(3, "cost", None, &[]),
            node(4, "east_margin", Some(1), &[]),
            node(5, "unrelated", None, &[]),
        ];
        let mut ids: Vec<Uuid> = tree_under(&nodes, Uuid::from_u128(1))
            .iter()
            .map(|n| n.id)
            .collect();
        ids.sort();
        assert_eq!(ids, [1, 2, 3, 4].map(Uuid::from_u128).to_vec());
    }
}
