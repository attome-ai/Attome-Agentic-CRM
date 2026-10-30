//! L5-T4: reading the lineage graph.
//!
//! Nodes are definitions (`<kind>:<id>`: a flow, stored query, metric,
//! dashboard, model object) and data (`entity:<entity>` or
//! `entity:<entity>.<attribute>`). An edge runs from a definition to what
//! it uses (`metadata_reference`).
//!
//! - **Downstream** of a node is what depends on it: the definitions with
//!   an edge to it (for an attribute, also the entity-only edges to its
//!   entity), then what depends on those.
//! - **Upstream** of a definition is what it uses: its edges' targets,
//!   then theirs when a target is itself a definition (a metric). Upstream
//!   of data is the definitions that write or derive it.
//!
//! [`walk`] goes breadth first, at most [`MAX_DEPTH`] hops and
//! [`MAX_NODES`] nodes, optionally only through definition kinds in
//! `kinds`, and optionally **as of** a graph version: an edge counts at
//! version `v` when it was written at or before `v` and not replaced by
//! then. [`write_edges`](super::write_edges) keeps a replaced edge in
//! `lineage_edge_history` (migration 0224) with the versions it was valid
//! between; edges written by older writers carry version 0 and count at
//! every version. [`compare`] lists the edges added and removed between two
//! versions, and [`cleanup`] the edges to deleted data, the cycles among
//! definitions, and the attributes nothing uses.
//!
//! A node reading a personal attribute is flagged `reads_personal`. Nodes
//! the caller may not see are left out and counted in `hidden`.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use serde::Serialize;
use sqlx::PgConnection;
use uuid::Uuid;

use attome_types::AppError;

/// The deepest walk.
pub const MAX_DEPTH: u8 = 10;
/// The most nodes one walk returns.
pub const MAX_NODES: usize = 2000;
/// The most items one compare or cleanup list returns.
pub const MAX_ITEMS: usize = 2000;

/// The most definition links one lineage read takes: five per item.
const MAX_LINK_ROWS: usize = MAX_ITEMS * 5;

/// The edges valid at `$1` (NULL: the current graph), one row each.
const EDGES_AT: &str = "( \
    SELECT from_kind, from_ref, from_label, to_kind, to_ref, to_entity, to_attribute, \
           edge_kind, confidence \
      FROM metadata_reference WHERE $1::bigint IS NULL OR graph_version <= $1 \
    UNION ALL \
    SELECT from_kind, from_ref, from_label, to_kind, to_ref, to_entity, to_attribute, \
           edge_kind, confidence \
      FROM lineage_edge_history \
     WHERE $1::bigint IS NOT NULL AND valid_from <= $1 AND valid_to > $1 \
)";

/// Which way to walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Up,
    Down,
}

/// A node of the graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, utoipa::ToSchema)]
pub enum NodeRef {
    /// An entity, or one of its attributes.
    Data {
        entity: String,
        attribute: Option<String>,
    },
    /// A definition: its kind and id.
    Definition { kind: String, id: Uuid },
}

impl NodeRef {
    /// `entity:<e>[.<a>]` or `<kind>:<id>`.
    pub fn key(&self) -> String {
        match self {
            NodeRef::Data {
                entity,
                attribute: Some(a),
            } => format!("entity:{entity}.{a}"),
            NodeRef::Data { entity, .. } => format!("entity:{entity}"),
            NodeRef::Definition { kind, id } => format!("{kind}:{id}"),
        }
    }

    /// The node a `{kind}/{ref}` path names: `entity` with `<e>` or
    /// `<e>.<a>`, or a definition kind with its id.
    pub fn parse(kind: &str, reference: &str) -> Option<Self> {
        if kind == "entity" {
            let (entity, attribute) = match reference.split_once('.') {
                Some((e, a)) => (e, Some(a.to_owned())),
                None => (reference, None),
            };
            (!entity.is_empty()).then(|| NodeRef::Data {
                entity: entity.to_owned(),
                attribute: attribute.filter(|a| !a.is_empty()),
            })
        } else {
            let id = Uuid::parse_str(reference).ok()?;
            (!kind.is_empty() && kind.len() <= 64).then(|| NodeRef::Definition {
                kind: kind.to_owned(),
                id,
            })
        }
    }

    /// The node an edge's target names.
    fn target(to_kind: &str, to_ref: Option<Uuid>, to_entity: &str, to_attribute: &str) -> NodeRef {
        if to_kind != "entity"
            && let Some(id) = to_ref
        {
            return NodeRef::Definition {
                kind: to_kind.to_owned(),
                id,
            };
        }
        if let Some((kind, id)) = to_entity.split_once(':')
            && let Ok(id) = Uuid::parse_str(id)
        {
            return NodeRef::Definition {
                kind: kind.to_owned(),
                id,
            };
        }
        NodeRef::Data {
            entity: to_entity.to_owned(),
            attribute: (!to_attribute.is_empty()).then(|| to_attribute.to_owned()),
        }
    }
}

/// A node as a walk reports it.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct Node {
    pub key: String,
    pub node: NodeRef,
    pub label: String,
    pub depth: u8,
    /// A definition that uses a personal attribute.
    pub reads_personal: bool,
}

/// An edge as a walk reports it: `from` uses `to`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, utoipa::ToSchema)]
#[schema(as = LineageGraphEdge)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub edge_kind: String,
    pub confidence: String,
}

/// A walk's result.
#[derive(Debug, Clone, Default, Serialize, utoipa::ToSchema)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<GraphEdge>,
    /// Nodes the caller may not see, counted only.
    pub hidden: usize,
    /// The walk stopped at [`MAX_NODES`].
    pub truncated: bool,
}

type EdgeRow = (
    String,
    Uuid,
    String,
    String,
    Option<Uuid>,
    String,
    String,
    String,
    String,
);

/// The edges into a data node: its entity, or one of its fields.
const DATA_EDGES: &str = "e.to_kind = 'entity' AND e.to_entity = $2 \
     AND ($3::text IS NULL OR e.to_attribute = $3 OR e.to_attribute = '')";

/// The edges into a definition node, by kind and id.
const DEFINITION_EDGES: &str =
    "(e.to_kind = $2 AND e.to_ref = $4) OR e.to_entity = $2 || ':' || $4::text";

async fn edges_into(
    conn: &mut PgConnection,
    node: &NodeRef,
    version: Option<i64>,
) -> Result<Vec<EdgeRow>, AppError> {
    let sql = match node {
        NodeRef::Data { .. } => format!(
            "SELECT from_kind, from_ref, from_label, to_kind, to_ref, to_entity, to_attribute, \
                    edge_kind, confidence FROM {EDGES_AT} e WHERE {DATA_EDGES} LIMIT {MAX_NODES}"
        ),
        NodeRef::Definition { .. } => format!(
            "SELECT from_kind, from_ref, from_label, to_kind, to_ref, to_entity, to_attribute, \
                    edge_kind, confidence FROM {EDGES_AT} e WHERE {DEFINITION_EDGES} \
              LIMIT {MAX_NODES}"
        ),
    };
    let (a, b, c) = match node {
        NodeRef::Data { entity, attribute } => (entity.clone(), attribute.clone(), None),
        NodeRef::Definition { kind, id } => (kind.clone(), None, Some(*id)),
    };
    sqlx::query_as(&sql)
        .bind(version)
        .bind(a)
        .bind(b)
        .bind(c)
        .fetch_all(conn)
        .await
        .map_err(AppError::internal)
}

async fn edges_from(
    conn: &mut PgConnection,
    node: &NodeRef,
    version: Option<i64>,
) -> Result<Vec<EdgeRow>, AppError> {
    let (sql, a, b, c): (String, String, Option<String>, Option<Uuid>) = match node {
        NodeRef::Definition { kind, id } => (
            format!(
                "SELECT from_kind, from_ref, from_label, to_kind, to_ref, to_entity, \
                        to_attribute, edge_kind, confidence FROM {EDGES_AT} e \
                  WHERE e.from_kind = $2 AND e.from_ref = $4 LIMIT {MAX_NODES}"
            ),
            kind.clone(),
            None,
            Some(*id),
        ),
        // What writes or derives the data.
        NodeRef::Data { entity, attribute } => (
            format!(
                "SELECT from_kind, from_ref, from_label, to_kind, to_ref, to_entity, \
                        to_attribute, edge_kind, confidence FROM {EDGES_AT} e \
                  WHERE e.to_kind = 'entity' AND e.to_entity = $2 \
                    AND ($3::text IS NULL OR e.to_attribute = $3) \
                    AND e.edge_kind IN ('writes', 'derives') AND $4::uuid IS NULL \
                  LIMIT {MAX_NODES}"
            ),
            entity.clone(),
            attribute.clone(),
            None,
        ),
    };
    sqlx::query_as(&sql)
        .bind(version)
        .bind(a)
        .bind(b)
        .bind(c)
        .fetch_all(conn)
        .await
        .map_err(AppError::internal)
}

/// Walks the graph from `start`. `visible` says whether the caller may see
/// a node; a hidden node is counted and not walked through.
#[allow(clippy::too_many_arguments)]
pub async fn walk(
    conn: &mut PgConnection,
    start: &NodeRef,
    direction: Direction,
    depth: u8,
    kinds: Option<&[String]>,
    version: Option<i64>,
    visible: impl Fn(&NodeRef) -> bool,
) -> Result<Graph, AppError> {
    let depth = depth.clamp(1, MAX_DEPTH);
    let allowed = |n: &NodeRef| match (n, kinds) {
        (NodeRef::Definition { kind, .. }, Some(kinds)) => kinds.iter().any(|k| k == kind),
        _ => true,
    };
    let mut graph = Graph::default();
    let mut seen: HashSet<String> = HashSet::from([start.key()]);
    let mut hidden: HashSet<String> = HashSet::new();
    let mut edges: BTreeSet<GraphEdge> = BTreeSet::new();
    let mut queue = VecDeque::from([(start.clone(), 0u8)]);
    let label = match start {
        NodeRef::Data { .. } => start.key(),
        NodeRef::Definition { .. } => String::new(),
    };
    graph.nodes.push(Node {
        key: start.key(),
        node: start.clone(),
        label,
        depth: 0,
        reads_personal: false,
    });
    while let Some((node, at)) = queue.pop_front() {
        if at >= depth {
            continue;
        }
        let rows = match direction {
            Direction::Down => edges_into(conn, &node, version).await?,
            Direction::Up => edges_from(conn, &node, version).await?,
        };
        for (from_kind, from_ref, from_label, to_kind, to_ref, to_entity, to_attr, kind, conf) in
            rows
        {
            let source = NodeRef::Definition {
                kind: from_kind,
                id: from_ref,
            };
            let target = NodeRef::target(&to_kind, to_ref, &to_entity, &to_attr);
            let (next, next_label) = match direction {
                // Down from data or a definition: the definition using it.
                Direction::Down => (source.clone(), from_label),
                // Up from a definition: what it uses; up from data: who
                // writes it.
                Direction::Up => match &node {
                    NodeRef::Definition { .. } => (target.clone(), target.key()),
                    NodeRef::Data { .. } => (source.clone(), from_label),
                },
            };
            if !allowed(&next) {
                continue;
            }
            let key = next.key();
            if !visible(&next) {
                hidden.insert(key);
                continue;
            }
            edges.insert(GraphEdge {
                from: source.key(),
                to: target.key(),
                edge_kind: kind,
                confidence: conf,
            });
            if seen.insert(key.clone()) {
                if graph.nodes.len() >= MAX_NODES {
                    graph.truncated = true;
                    continue;
                }
                graph.nodes.push(Node {
                    key,
                    node: next.clone(),
                    label: next_label,
                    depth: at + 1,
                    reads_personal: false,
                });
                queue.push_back((next, at + 1));
            }
        }
    }
    flag_personal(conn, &mut graph.nodes, version).await?;
    graph.hidden = hidden.difference(&seen).count();
    graph.edges = edges.into_iter().collect();
    Ok(graph)
}

/// Marks the definitions that use a personal attribute.
async fn flag_personal(
    conn: &mut PgConnection,
    nodes: &mut [Node],
    version: Option<i64>,
) -> Result<(), AppError> {
    let ids: Vec<Uuid> = nodes
        .iter()
        .filter_map(|n| match &n.node {
            NodeRef::Definition { id, .. } => Some(*id),
            NodeRef::Data { .. } => None,
        })
        .collect();
    if ids.is_empty() {
        return Ok(());
    }
    let personal: Vec<Uuid> = sqlx::query_scalar(&format!(
        "SELECT DISTINCT e.from_ref FROM {EDGES_AT} e \
           JOIN entity_info ei ON ei.logicalname = e.to_entity \
           JOIN attribute_info a ON a.entity_ref = ei.id AND a.logicalname = e.to_attribute \
          WHERE e.from_ref = ANY($2) AND a.data_classification <> 'general'"
    ))
    .bind(version)
    .bind(&ids)
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)?;
    let personal: HashSet<Uuid> = personal.into_iter().collect();
    for node in nodes {
        if let NodeRef::Definition { id, .. } = &node.node {
            node.reads_personal = personal.contains(id);
        }
    }
    Ok(())
}

async fn edges_at(conn: &mut PgConnection, version: i64) -> Result<BTreeSet<GraphEdge>, AppError> {
    let rows: Vec<EdgeRow> = sqlx::query_as(&format!(
        "SELECT from_kind, from_ref, from_label, to_kind, to_ref, to_entity, to_attribute, \
                edge_kind, confidence FROM {EDGES_AT} e"
    ))
    .bind(Some(version))
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(fk, fr, _, tk, tr, te, ta, kind, conf)| GraphEdge {
            from: NodeRef::Definition { kind: fk, id: fr }.key(),
            to: NodeRef::target(&tk, tr, &te, &ta).key(),
            edge_kind: kind,
            confidence: conf,
        })
        .collect())
}

/// L5-T6: one edge of the whole graph, as an export reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    /// The definition that uses `to`.
    pub from: NodeRef,
    pub from_label: String,
    pub to: NodeRef,
    pub edge_kind: String,
    pub confidence: String,
}

/// The most edges one export reads.
pub const MAX_EXPORT_EDGES: usize = 50_000;

/// One more than [`MAX_EXPORT_EDGES`], so a read can tell it was cut short.
const EXPORT_READ_LIMIT: usize = MAX_EXPORT_EDGES + 1;

/// L5-T6: every edge of the current graph, up to [`MAX_EXPORT_EDGES`];
/// `true` when there were more.
pub async fn all_edges(conn: &mut PgConnection) -> Result<(Vec<Edge>, bool), AppError> {
    let sql = format!(
        "SELECT from_kind, from_ref, from_label, to_kind, to_ref, to_entity, to_attribute, \
                edge_kind, confidence FROM {EDGES_AT} e \
          ORDER BY from_kind, from_ref, to_entity, to_attribute LIMIT {EXPORT_READ_LIMIT}"
    );
    let rows: Vec<EdgeRow> = sqlx::query_as(&sql)
        .bind(None::<i64>)
        .fetch_all(conn)
        .await
        .map_err(AppError::internal)?;
    let truncated = rows.len() > MAX_EXPORT_EDGES;
    Ok((
        rows.into_iter()
            .take(MAX_EXPORT_EDGES)
            .map(
                |(
                    from_kind,
                    from_ref,
                    from_label,
                    to_kind,
                    to_ref,
                    to_entity,
                    to_attribute,
                    edge_kind,
                    confidence,
                )| Edge {
                    from: NodeRef::Definition {
                        kind: from_kind,
                        id: from_ref,
                    },
                    from_label,
                    to: NodeRef::target(&to_kind, to_ref, &to_entity, &to_attribute),
                    edge_kind,
                    confidence,
                },
            )
            .collect(),
        truncated,
    ))
}

/// The edges added and removed between two versions.
#[derive(Debug, Clone, Default, Serialize, utoipa::ToSchema)]
pub struct Comparison {
    pub from: i64,
    pub to: i64,
    pub added: Vec<GraphEdge>,
    pub removed: Vec<GraphEdge>,
    pub truncated: bool,
}

/// Compares the graph at `from` with the graph at `to`.
pub async fn compare(conn: &mut PgConnection, from: i64, to: i64) -> Result<Comparison, AppError> {
    let before = edges_at(conn, from).await?;
    let after = edges_at(conn, to).await?;
    let mut out = Comparison {
        from,
        to,
        ..Comparison::default()
    };
    out.added = after.difference(&before).cloned().collect();
    out.removed = before.difference(&after).cloned().collect();
    if out.added.len() > MAX_ITEMS || out.removed.len() > MAX_ITEMS {
        out.truncated = true;
        out.added.truncate(MAX_ITEMS);
        out.removed.truncate(MAX_ITEMS);
    }
    Ok(out)
}

/// What needs tidying in the graph.
#[derive(Debug, Clone, Default, Serialize, utoipa::ToSchema)]
pub struct Cleanup {
    /// Edges to an entity or attribute that no longer exists.
    pub dangling: Vec<GraphEdge>,
    /// Definitions that, through other definitions, depend on themselves.
    pub cycles: Vec<Vec<String>>,
    /// Active attributes no definition uses, as `entity.attribute`.
    pub unused_attributes: Vec<String>,
}

/// The cycles among definition-to-definition edges, each listed once.
pub fn find_cycles(edges: &[(String, String)]) -> Vec<Vec<String>> {
    let mut next: HashMap<&str, Vec<&str>> = HashMap::new();
    for (from, to) in edges {
        next.entry(from.as_str()).or_default().push(to.as_str());
    }
    let mut cycles: BTreeSet<Vec<String>> = BTreeSet::new();
    let starts: BTreeSet<&str> = next.keys().copied().collect();
    for start in starts {
        // Depth-first from `start`, bounded by the edge count.
        let mut stack = vec![(start, vec![start])];
        let mut steps = 0;
        while let Some((at, path)) = stack.pop() {
            steps += 1;
            if steps > 10_000 || cycles.len() >= MAX_ITEMS {
                break;
            }
            for &to in next.get(at).into_iter().flatten() {
                if to == start {
                    // Canonical: rotated to its smallest node.
                    let mut cycle: Vec<String> = path.iter().map(|s| (*s).to_owned()).collect();
                    let min = cycle
                        .iter()
                        .enumerate()
                        .min_by(|a, b| a.1.cmp(b.1))
                        .map_or(0, |(i, _)| i);
                    cycle.rotate_left(min);
                    cycles.insert(cycle);
                } else if !path.contains(&to) && path.len() < usize::from(MAX_DEPTH) {
                    let mut longer = path.clone();
                    longer.push(to);
                    stack.push((to, longer));
                }
            }
        }
    }
    cycles.into_iter().collect()
}

/// The graph's dangling edges, cycles and unused attributes.
pub async fn cleanup(conn: &mut PgConnection) -> Result<Cleanup, AppError> {
    let dangling: Vec<EdgeRow> = sqlx::query_as(&format!(
        "SELECT from_kind, from_ref, from_label, to_kind, to_ref, to_entity, to_attribute, \
                edge_kind, confidence FROM metadata_reference e \
          WHERE e.to_kind = 'entity' AND position(':' in e.to_entity) = 0 \
            AND (NOT EXISTS (SELECT 1 FROM entity_info ei WHERE ei.logicalname = e.to_entity \
                               AND (ei.is_active IS NULL OR ei.is_active)) \
                 OR (e.to_attribute <> '' AND NOT EXISTS ( \
                     SELECT 1 FROM entity_info ei JOIN attribute_info a ON a.entity_ref = ei.id \
                      WHERE ei.logicalname = e.to_entity AND a.logicalname = e.to_attribute \
                        AND (a.is_active IS NULL OR a.is_active)))) \
          ORDER BY e.to_entity, e.to_attribute LIMIT {MAX_ITEMS}"
    ))
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let links: Vec<EdgeRow> = sqlx::query_as(&format!(
        "SELECT from_kind, from_ref, from_label, to_kind, to_ref, to_entity, to_attribute, \
                edge_kind, confidence FROM metadata_reference e \
          WHERE e.to_kind <> 'entity' OR position(':' in e.to_entity) > 0 \
          LIMIT {MAX_LINK_ROWS}"
    ))
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let unused: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT ei.logicalname || '.' || a.logicalname \
           FROM attribute_info a JOIN entity_info ei ON ei.id = a.entity_ref \
          WHERE (a.is_active IS NULL OR a.is_active) AND (ei.is_active IS NULL OR ei.is_active) \
            AND NOT EXISTS (SELECT 1 FROM metadata_reference r \
                             WHERE r.to_entity = ei.logicalname \
                               AND (r.to_attribute = a.logicalname OR r.to_attribute = '')) \
          ORDER BY 1 LIMIT {MAX_ITEMS}"
    ))
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let edge = |(fk, fr, _, tk, tr, te, ta, kind, conf): EdgeRow| GraphEdge {
        from: NodeRef::Definition { kind: fk, id: fr }.key(),
        to: NodeRef::target(&tk, tr, &te, &ta).key(),
        edge_kind: kind,
        confidence: conf,
    };
    let pairs: Vec<(String, String)> = links
        .into_iter()
        .map(edge)
        .map(|e| (e.from, e.to))
        .collect();
    Ok(Cleanup {
        dangling: dangling.into_iter().map(edge).collect(),
        cycles: find_cycles(&pairs),
        unused_attributes: unused,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lineage_nodes_parse_and_key() {
        assert_eq!(
            NodeRef::parse("entity", "invoice.amount").unwrap().key(),
            "entity:invoice.amount"
        );
        assert_eq!(
            NodeRef::parse("entity", "invoice").unwrap().key(),
            "entity:invoice"
        );
        let id = Uuid::now_v7();
        assert_eq!(
            NodeRef::parse("metric", &id.to_string()).unwrap().key(),
            format!("metric:{id}")
        );
        assert!(NodeRef::parse("metric", "not-an-id").is_none());
        assert_eq!(
            NodeRef::target("entity", None, &format!("dashboard:{id}"), ""),
            NodeRef::Definition {
                kind: "dashboard".into(),
                id
            }
        );
        assert_eq!(
            NodeRef::target("metric", Some(id), &format!("metric:{id}"), ""),
            NodeRef::Definition {
                kind: "metric".into(),
                id
            }
        );
    }

    #[test]
    fn lineage_cycles_are_found_once() {
        let e = |a: &str, b: &str| (a.to_owned(), b.to_owned());
        let cycles = find_cycles(&[
            e("metric:b", "metric:a"),
            e("metric:a", "metric:b"),
            e("dashboard:x", "metric:a"),
            e("metric:c", "metric:c"),
        ]);
        assert_eq!(
            cycles,
            vec![
                vec!["metric:a".to_owned(), "metric:b".to_owned()],
                vec!["metric:c".to_owned()],
            ]
        );
    }
}
