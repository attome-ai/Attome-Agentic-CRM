//! Journey version moves on publish (roadmap E8-T8): when a journey's new
//! version is published, the people already in it either finish on the
//! version they started (`finish_on_old`) or move to the new one where they
//! wait (`move_matching`). [`preview`] counts them first.
//!
//! **Who moves.** Only a run that is `waiting` (never one running a step),
//! with an active enrolment, whose every waiting node exists in the new
//! version and whose every node upstream of those in the new version has
//! already finished on the run. The last rule keeps a node the new version
//! added *before* the waiting point from running for people who are past
//! it (a new email, say, sent to everyone already further along). Anyone
//! else stays on the old version and finishes there.
//!
//! **What changes.** The run's `definition_version_id` (the scheduler reads
//! the graph from it on every pass and caches nothing per run), the
//! enrolment's, and the per-node waiting counts the canvas shows. Node-run
//! history is never touched. Each batch of 1,000 runs is one transaction
//! that takes `pg_try_advisory_xact_lock` on the journey, locks the runs,
//! and re-checks them before moving. The counts moved and kept are written
//! as a Configuration security event.

use std::collections::{BTreeMap, HashMap, HashSet};

use attome_core::EngineState;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// Runs moved per transaction.
pub const BATCH: usize = 1_000;

/// What happens to people already in the journey when a version is published.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum VersionMode {
    /// Everyone finishes on the version they started.
    #[default]
    FinishOnOld,
    /// People waiting at a node the new version keeps move to it.
    MoveMatching,
}

/// People waiting at one node, for the preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct NodeWaiting {
    pub node_id: String,
    pub waiting_count: i64,
    pub exists_in_new: bool,
    /// How many of them `move_matching` would move.
    pub movable_count: i64,
}

/// What a move did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, ToSchema)]
pub struct MoveOutcome {
    pub moved: u64,
    pub kept: u64,
}

/// The graph as far as a move needs it: node ids and each node's sources.
#[derive(Debug, Default)]
pub struct NodeGraph {
    nodes: HashSet<String>,
    sources: HashMap<String, Vec<String>>,
}

#[derive(Deserialize)]
struct RawGraph {
    #[serde(default)]
    nodes: Vec<RawNode>,
    #[serde(default)]
    edges: Vec<RawEdge>,
}

#[derive(Deserialize)]
struct RawNode {
    id: String,
}

#[derive(Deserialize)]
struct RawEdge {
    from_node: String,
    to_node: String,
}

impl NodeGraph {
    /// Reads a version's stored graph; an unreadable one has no nodes, so
    /// nobody moves into it. Pure.
    pub fn parse(graph: &Value) -> Self {
        let Ok(raw) = serde_json::from_value::<RawGraph>(graph.clone()) else {
            return Self::default();
        };
        let mut sources: HashMap<String, Vec<String>> = HashMap::new();
        for e in raw.edges {
            sources.entry(e.to_node).or_default().push(e.from_node);
        }
        Self {
            nodes: raw.nodes.into_iter().map(|n| n.id).collect(),
            sources,
        }
    }

    pub fn contains(&self, node: &str) -> bool {
        self.nodes.contains(node)
    }

    /// Every node upstream of `node`. Pure.
    pub fn upstream(&self, node: &str) -> HashSet<String> {
        let mut seen = HashSet::new();
        let mut stack = vec![node.to_owned()];
        while let Some(n) = stack.pop() {
            for s in self.sources.get(&n).into_iter().flatten() {
                if seen.insert(s.clone()) {
                    stack.push(s.clone());
                }
            }
        }
        seen.remove(node);
        seen
    }
}

/// One run's node runs: the nodes it waits at and the nodes it finished.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RunNodes {
    pub waiting: Vec<String>,
    pub finished: HashSet<String>,
}

impl RunNodes {
    fn from_rows<'a>(rows: impl Iterator<Item = (&'a str, &'a str)>) -> Self {
        let mut out = Self::default();
        for (node, status) in rows {
            match status {
                "waiting" => out.waiting.push(node.to_owned()),
                "succeeded" | "skipped" | "failed" => {
                    out.finished.insert(node.to_owned());
                }
                _ => {}
            }
        }
        out.waiting.sort();
        out.waiting.dedup();
        out
    }
}

/// Whether a waiting run may move to `new`; see the module doc. Pure.
pub fn movable(new: &NodeGraph, run: &RunNodes) -> bool {
    !run.waiting.is_empty()
        && run.waiting.iter().all(|w| {
            new.contains(w)
                && new
                    .upstream(w)
                    .iter()
                    .all(|u| run.finished.contains(u) || run.waiting.contains(u))
        })
}

async fn new_graph(
    state: &EngineState,
    definition_id: Uuid,
    new_version_id: Uuid,
) -> Result<NodeGraph, AppError> {
    let graph: Value = sqlx::query_scalar(
        "SELECT graph FROM workflow_definition_version WHERE id = $1 AND definition_id = $2",
    )
    .bind(new_version_id)
    .bind(definition_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    Ok(NodeGraph::parse(&graph))
}

/// The node runs of `instances`, per run.
async fn node_runs<'c, E>(conn: E, instances: &[Uuid]) -> Result<HashMap<Uuid, RunNodes>, AppError>
where
    E: sqlx::PgExecutor<'c>,
{
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT instance_id, node_id, status FROM workflow_node_run WHERE instance_id = ANY($1)",
    )
    .bind(instances)
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)?;
    let mut by: HashMap<Uuid, Vec<(String, String)>> = HashMap::new();
    for (instance, node, status) in rows {
        by.entry(instance).or_default().push((node, status));
    }
    Ok(by
        .into_iter()
        .map(|(id, rows)| {
            (
                id,
                RunNodes::from_rows(rows.iter().map(|(n, s)| (n.as_str(), s.as_str()))),
            )
        })
        .collect())
}

/// The active enrolments' runs that are waiting on a version other than
/// `new_version_id`.
async fn waiting_runs(
    state: &EngineState,
    definition_id: Uuid,
    new_version_id: Uuid,
) -> Result<Vec<(Uuid, Uuid)>, AppError> {
    sqlx::query_as(
        "SELECT i.id, i.definition_version_id FROM marketing_journey_enrolment e \
           JOIN workflow_instance i ON i.id = e.instance_id \
          WHERE e.definition_id = $1 AND e.status = 'active' AND i.status = 'waiting' \
            AND i.definition_version_id <> $2 \
          ORDER BY i.id",
    )
    .bind(definition_id)
    .bind(new_version_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// People waiting per node, whether the new version has the node, and how
/// many `move_matching` would move. Sorted by node id.
pub async fn preview(
    state: &EngineState,
    definition_id: Uuid,
    new_version_id: Uuid,
) -> Result<Vec<NodeWaiting>, AppError> {
    let graph = new_graph(state, definition_id, new_version_id).await?;
    let runs = waiting_runs(state, definition_id, new_version_id).await?;
    let ids: Vec<Uuid> = runs.iter().map(|(id, _)| *id).collect();
    let nodes = node_runs(&state.base.db, &ids).await?;
    let mut by: BTreeMap<String, NodeWaiting> = BTreeMap::new();
    for id in &ids {
        let Some(run) = nodes.get(id) else { continue };
        let moves = movable(&graph, run);
        for w in &run.waiting {
            let entry = by.entry(w.clone()).or_insert_with(|| NodeWaiting {
                node_id: w.clone(),
                waiting_count: 0,
                exists_in_new: graph.contains(w),
                movable_count: 0,
            });
            entry.waiting_count += 1;
            if moves {
                entry.movable_count += 1;
            }
        }
    }
    Ok(by.into_values().collect())
}

/// Moves people to `new_version_id` as `mode` says; see the module doc.
pub async fn move_to_version(
    state: &EngineState,
    definition_id: Uuid,
    new_version_id: Uuid,
    mode: VersionMode,
    actor: Uuid,
) -> Result<MoveOutcome, AppError> {
    let graph = new_graph(state, definition_id, new_version_id).await?;
    let runs = waiting_runs(state, definition_id, new_version_id).await?;
    let mut outcome = MoveOutcome {
        moved: 0,
        kept: runs.len() as u64,
    };
    if mode == VersionMode::MoveMatching {
        let ids: Vec<Uuid> = runs.iter().map(|(id, _)| *id).collect();
        for batch in ids.chunks(BATCH) {
            let moved = move_batch(state, definition_id, new_version_id, &graph, batch).await?;
            outcome.moved += moved;
            outcome.kept -= moved;
        }
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            actor,
            "workflow_definition",
            Some(definition_id),
        )
        .named("journey.version_move")
        .comment(format!(
            "journey version {new_version_id} published ({}): {} moved, {} kept on their version",
            match mode {
                VersionMode::FinishOnOld => "finish_on_old",
                VersionMode::MoveMatching => "move_matching",
            },
            outcome.moved,
            outcome.kept
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(outcome)
}

/// One batch, one transaction: lock, re-check, move.
async fn move_batch(
    state: &EngineState,
    definition_id: Uuid,
    new_version_id: Uuid,
    graph: &NodeGraph,
    batch: &[Uuid],
) -> Result<u64, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!(
            "attome-marketing/journey_version_move:{definition_id}"
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "this journey's people are already being moved",
        ));
    }
    // Lock the runs still waiting; one that started a step since is left.
    let still: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT id, definition_version_id FROM workflow_instance \
          WHERE id = ANY($1) AND status = 'waiting' AND definition_version_id <> $2 \
          ORDER BY id FOR UPDATE",
    )
    .bind(batch)
    .bind(new_version_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let ids: Vec<Uuid> = still.iter().map(|(id, _)| *id).collect();
    let nodes = node_runs(&mut *tx, &ids).await?;
    let moving: Vec<(Uuid, Uuid, Vec<String>)> = still
        .into_iter()
        .filter_map(|(id, old)| {
            let run = nodes.get(&id)?;
            movable(graph, run).then(|| (id, old, run.waiting.clone()))
        })
        .collect();
    if moving.is_empty() {
        attome_db::tx::commit(tx).await?;
        return Ok(0);
    }
    let moving_ids: Vec<Uuid> = moving.iter().map(|(id, _, _)| *id).collect();
    sqlx::query(
        "UPDATE workflow_instance SET definition_version_id = $2, row_version = row_version + 1 \
          WHERE id = ANY($1)",
    )
    .bind(&moving_ids)
    .bind(new_version_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE marketing_journey_enrolment SET definition_version_id = $2 \
          WHERE instance_id = ANY($1) AND status = 'active'",
    )
    .bind(&moving_ids)
    .bind(new_version_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // The canvas's waiting counts follow the people.
    let mut counts: BTreeMap<(Uuid, String), i64> = BTreeMap::new();
    for (_, old, waiting) in &moving {
        for node in waiting {
            *counts.entry((*old, node.clone())).or_default() += 1;
        }
    }
    for ((old, node), n) in counts {
        sqlx::query(
            "UPDATE marketing_journey_node_count SET waiting = GREATEST(waiting - $3, 0) \
              WHERE definition_version_id = $1 AND node_id = $2",
        )
        .bind(old)
        .bind(&node)
        .bind(n)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query(
            "INSERT INTO marketing_journey_node_count (definition_version_id, node_id, waiting) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (definition_version_id, node_id) \
             DO UPDATE SET waiting = marketing_journey_node_count.waiting + EXCLUDED.waiting",
        )
        .bind(new_version_id)
        .bind(&node)
        .bind(n)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(moving_ids.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn graph() -> NodeGraph {
        // start -> email -> wait -> sms ; v2 inserts "survey" before "wait".
        NodeGraph::parse(&json!({
            "nodes": [{"id": "start", "type": "trigger"}, {"id": "email", "type": "x"},
                      {"id": "survey", "type": "x"}, {"id": "wait", "type": "x"},
                      {"id": "sms", "type": "x"}],
            "edges": [
                {"from_node": "start", "from_port": "out", "to_node": "email", "to_port": "in"},
                {"from_node": "email", "from_port": "out", "to_node": "survey", "to_port": "in"},
                {"from_node": "survey", "from_port": "out", "to_node": "wait", "to_port": "in"},
                {"from_node": "wait", "from_port": "out", "to_node": "sms", "to_port": "in"}
            ]
        }))
    }

    fn run(waiting: &[&str], finished: &[&str]) -> RunNodes {
        RunNodes {
            waiting: waiting.iter().map(|s| s.to_string()).collect(),
            finished: finished.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn upstream_is_every_node_before() {
        let g = graph();
        let up = g.upstream("wait");
        assert_eq!(
            up,
            HashSet::from(["start", "email", "survey"].map(String::from))
        );
        assert!(g.upstream("start").is_empty());
    }

    #[test]
    fn only_runs_past_every_upstream_node_move() {
        let g = graph();
        // Waiting at "email": its upstream (start) is done; it moves.
        assert!(movable(&g, &run(&["email"], &["start"])));
        // Waiting at "wait" but the new "survey" never ran: stays.
        assert!(!movable(&g, &run(&["wait"], &["start", "email"])));
        assert!(movable(&g, &run(&["wait"], &["start", "email", "survey"])));
        // A node the new version removed: stays.
        assert!(!movable(&g, &run(&["gone"], &["start"])));
        // Not waiting at all: never moved.
        assert!(!movable(&g, &run(&[], &["start"])));
        assert!(!movable(
            &NodeGraph::parse(&json!("bad")),
            &run(&["email"], &[])
        ));
    }

    #[test]
    fn node_runs_split_into_waiting_and_finished() {
        let r = RunNodes::from_rows(
            [
                ("a", "succeeded"),
                ("b", "waiting"),
                ("c", "running"),
                ("d", "skipped"),
            ]
            .into_iter(),
        );
        assert_eq!(r.waiting, vec!["b".to_owned()]);
        assert_eq!(r.finished, HashSet::from(["a", "d"].map(String::from)));
    }
}
