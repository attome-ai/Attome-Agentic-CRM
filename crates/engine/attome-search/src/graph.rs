//! M38 Phase 1 — bounded, permission-per-hop graph traversal over rows that
//! already exist (D-410). No second store, no typed relationship registry
//! yet (that is Phase 2) — this walks three sources that are already rows:
//! `Lookup` fields (`EntityMetaRegistry`'s attrs, `field_type_int == 11`),
//! `record_relationship` (the generic polymorphic record↔record link),
//! and the self-referencing hierarchy lookup `entity_crud/hierarchy.rs`
//! already walks for `/ancestors`/`/descendants` — a hierarchy edge is
//! mechanically just a lookup field whose `lookup_entity_ref` is the
//! entity's own id, labelled `hierarchy:{field}` instead of `lookup:{field}`
//! so a caller can tell the two apart in the response.
//!
//! ## Permission at every hop, not at the end
//!
//! Filtering after the walk leaks existence: a path *through* a hidden node
//! proves the node exists even if it is stripped from the final list. So
//! every newly discovered node is checked with
//! [`attome_security::visibility::PolymorphicVisibility`] — the exact same
//! fragment `attome-search`'s own text-retrieval legs push (`legs/mod.rs`,
//! `share_plan.rs`) — **before** it is added to the frontier or emitted as an
//! edge endpoint. A hidden node therefore never becomes a hop: nothing
//! reachable only through it can ever be discovered, which is the property
//! the hidden-intermediate-node test in `tests/graph_traverse.rs` exists to
//! pin. There is exactly one place in this file that decides "is this row
//! visible" ([`filter_visible`]), and every candidate source funnels through
//! it — a second ad hoc check anywhere else would be the drift invariant I-1
//! exists to prevent.
//!
//! ## Why this is a bounded per-hop walk, not one heterogeneous `WITH RECURSIVE`
//!
//! Entity data lives in one physical PostgreSQL table per entity (guidelines
//! §4 — no EAV, no shared JSONB record store), so a *single* SQL statement
//! that could walk from any catalogued entity type to any other would need
//! its recursive term to `UNION ALL` every lookup field of every entity in
//! the whole metadata catalogue, whether or not it is reachable from this
//! request's actual start node — exactly the "recursive CTE plans on wide
//! lookups" cost this module's plan (`document/module-master-plans/
//! M38-knowledge-graph.md` §8) flags for evidence before merging. Instead,
//! [`walk`] runs an explicit bounded BFS in Rust: each hop issues a handful
//! of small, cheap, indexed-by-primary-key queries scoped to *only the
//! entity types actually present in the current frontier* (bounded by the
//! previous hop's own admitted-node cap, never by the whole catalogue), then
//! one grouped, visibility-filtered existence check per newly-discovered
//! entity type. This is still entirely "in PostgreSQL, no graph database" —
//! every row read is a real row in a real table, the security predicate is
//! the same one `PolymorphicVisibility` always pushes, and the whole walk
//! runs inside one transaction with one `SET LOCAL statement_timeout`. A
//! genuine single-statement recursive CTE bounded by a *typed* relationship
//! registry (Phase 2, `relationship_type`) is a fair evidence-driven
//! revisit once that registry exists to bound the union — not before.
//!
//! ## Bounds
//!
//! [`MAX_DEPTH`] hops, [`MAX_FANOUT_PER_HOP`] newly-admitted nodes per hop,
//! [`MAX_TOTAL_NODES`] across the whole walk, and a per-hop statement
//! timeout — the same bounding posture `vector.rs`'s `MAX_SCAN_TUPLES`
//! documents: the caller with the *narrowest* visibility pays the most (every
//! hop's permission filter discards more of what it examines), so the bound
//! is on candidates examined, not on results returned. Hitting any bound sets
//! `truncated: true` on the response rather than silently returning a partial
//! graph (plan §5).

use std::collections::{HashMap, HashSet};

use attome_core::{EngineState, EntityMetaRegistry, quote_ident};
use attome_db::DbPool;
use attome_security::visibility::PolymorphicVisibility;
use attome_security::{FastTierColumns, RecordAction};
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, QueryBuilder};
use utoipa::ToSchema;
use uuid::Uuid;

/// Deepest a traversal may walk.
pub const MAX_DEPTH: u32 = 4;

/// Newly discovered, **visible** nodes admitted per hop. Once a hop's
/// discoveries reach this, the hop stops early rather than examining the
/// whole frontier's fan-out.
pub const MAX_FANOUT_PER_HOP: i64 = 200;

/// Ceiling on total nodes across the whole traversal, independent of the
/// caller-supplied `limit` (which can never exceed this) — the same
/// candidates-examined-not-results-returned reasoning `vector.rs` documents:
/// a caller cannot buy more scanning by raising `limit`.
pub const MAX_TOTAL_NODES: i64 = 1000;

pub const DEFAULT_LIMIT: i64 = 200;

/// Per-hop statement timeout, matching `routes.rs::statement_timeout_ms`'s
/// per-statement budget — a graph hop is exactly what that budget was sized
/// for.
const HOP_STATEMENT_TIMEOUT_MS: i64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Outbound,
    Inbound,
    #[default]
    Both,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct NodeRefInput {
    pub entity: String,
    pub id: Uuid,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct TraverseRequest {
    pub start: NodeRefInput,
    /// Restricts which edges the walk follows — `"lookup:{field}"`,
    /// `"hierarchy:{field}"`, `"relationship:{type}"`, or the bare
    /// `"relationship"` to admit every relationship type. `None` (the
    /// default) follows everything the caller can see.
    #[serde(default)]
    pub edge_types: Option<Vec<String>>,
    #[serde(default)]
    pub direction: Direction,
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_max_depth() -> u32 {
    MAX_DEPTH
}
fn default_limit() -> i64 {
    DEFAULT_LIMIT
}

/// Validates request-controlled bounds before any query runs. Rejects with a
/// named cap rather than silently clamping — the same convention
/// `routes.rs::validate_paging` uses, and for the same reason: a caller who
/// asked for depth 10 and silently got 4 draws the wrong conclusion from an
/// empty-looking tail.
pub fn validate_request(req: &TraverseRequest) -> Result<(), AppError> {
    if req.max_depth < 1 || req.max_depth > MAX_DEPTH {
        return Err(AppError::Validation(format!(
            "max_depth must be between 1 and {MAX_DEPTH}"
        )));
    }
    if req.limit < 1 || req.limit > MAX_TOTAL_NODES {
        return Err(AppError::Validation(format!(
            "limit must be between 1 and {MAX_TOTAL_NODES}"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NodeRef {
    entity: String,
    id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GraphNode {
    pub entity_logicalname: String,
    pub record_id: Uuid,
    pub depth: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct GraphEdge {
    pub from_entity: String,
    pub from_id: Uuid,
    pub to_entity: String,
    pub to_id: Uuid,
    /// `"lookup:{field}"`, `"hierarchy:{field}"`, or `"relationship:{type}"`
    /// — typed by source, per the plan's response contract.
    pub edge_type: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TraverseResponse {
    pub nodes: PaginatedResponse<GraphNode>,
    pub edges: Vec<GraphEdge>,
    /// Set whenever a bound (depth, per-hop fan-out, the overall node cap, or
    /// the statement timeout) cut the walk short. Never silently return a
    /// partial graph.
    pub truncated: bool,
}

/// [`walk`]'s raw result, before it is wrapped in [`PaginatedResponse`] —
/// kept separate so the HTTP route and the `graph.traverse` action (which
/// wraps the identical payload for a model rather than an HTTP client) build
/// the envelope from one place instead of two that could drift.
pub struct TraverseOutcome {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub truncated: bool,
}

impl std::fmt::Debug for TraverseOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraverseOutcome").finish_non_exhaustive()
    }
}

impl TraverseOutcome {
    pub fn into_response(self, limit: i64) -> TraverseResponse {
        let total = self.nodes.len() as i64;
        TraverseResponse {
            nodes: PaginatedResponse::new(self.nodes, total, 1, limit),
            edges: self.edges,
            truncated: self.truncated,
        }
    }
}

// ── The edge catalogue ───────────────────────────────────────────────────────

/// One lookup-derived edge the catalogue knows about: entity `from_entity`
/// has an attribute `field` whose value, when present, is the id of a row in
/// `to_entity`.
#[derive(Debug, Clone)]
struct LookupEdgeMeta {
    from_entity: String,
    field: String,
    is_sensitive: bool,
    to_entity: String,
    /// `lookup_entity_ref == from_entity`'s own id — the self-referencing
    /// shape `entity_crud/hierarchy.rs`'s `/ancestors`/`/descendants` already
    /// walk. Mechanically identical to any other lookup edge; only the label
    /// differs.
    is_hierarchy: bool,
}

fn edge_label(e: &LookupEdgeMeta) -> String {
    if e.is_hierarchy {
        format!("hierarchy:{}", e.field)
    } else {
        format!("lookup:{}", e.field)
    }
}

/// The catalogue: every lookup field on every active entity, resolved
/// **from the already-cached, already-invalidated `EntityMetaRegistry`
/// snapshot** (`caching-and-state` skill) — no second cache, no new
/// invalidation story to get wrong. "At boot" in the plan's checklist means
/// this is derived from state that is pre-warmed at boot and kept current by
/// the metadata change-log doorbell, not that a separate structure is built
/// once and never refreshed.
fn lookup_edges(registry: &EntityMetaRegistry) -> Vec<LookupEdgeMeta> {
    let mut out = Vec::new();
    for meta in registry.iter() {
        for attr in &meta.attrs {
            if attr.field_type_int != 11 {
                continue;
            }
            let Some(target_id) = attr.lookup_entity_ref else {
                continue;
            };
            let Some(target) = registry.get_by_id(target_id) else {
                continue;
            };
            out.push(LookupEdgeMeta {
                from_entity: meta.logicalname.clone(),
                field: attr.logicalname.clone(),
                is_sensitive: attr.is_read_gated(),
                to_entity: target.logicalname.clone(),
                is_hierarchy: target_id == meta.entity_id,
            });
        }
    }
    out
}

fn edge_allowed(label: &str, filter: Option<&HashSet<String>>) -> bool {
    match filter {
        None => true,
        Some(f) => f.contains(label),
    }
}

// ── O6-T1: polymorphic pairs (A8-T1) and many-to-many links (A7-T4) ─────────

/// A polymorphic id attribute: `from_entity.id_field` (with the target
/// entity in `entity_field`) points at a record of one of `targets`.
#[derive(Debug, Clone)]
struct PolymorphicEdgeMeta {
    from_entity: String,
    id_field: String,
    entity_field: String,
    is_sensitive: bool,
    targets: Vec<String>,
}

/// Every polymorphic id attribute in the registry (`options.polymorphic`).
fn polymorphic_edges(registry: &EntityMetaRegistry) -> Vec<PolymorphicEdgeMeta> {
    let mut out = Vec::new();
    for meta in registry.iter() {
        for attr in &meta.attrs {
            let Some(poly) = attr.options.as_ref().and_then(|o| o.get("polymorphic")) else {
                continue;
            };
            let Some(pair) = poly.get("pair").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let mut targets: Vec<String> = poly
                .get("targets")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|t| t.as_str().map(str::to_owned))
                .collect();
            if let Some(base) = poly.get("extends").and_then(serde_json::Value::as_str) {
                targets.push(base.to_owned());
            }
            out.push(PolymorphicEdgeMeta {
                from_entity: meta.logicalname.clone(),
                id_field: attr.logicalname.clone(),
                entity_field: pair.to_owned(),
                is_sensitive: attr.is_read_gated(),
                targets,
            });
        }
    }
    out
}

/// The polymorphic edges leaving (`outbound`) or reaching (`!outbound`)
/// records `ids` of `entity`.
#[allow(clippy::too_many_arguments)]
async fn polymorphic_candidates(
    tx: &mut sqlx::PgConnection,
    edges: &[PolymorphicEdgeMeta],
    registry: &EntityMetaRegistry,
    ctx: &SecurityContext,
    entity: &str,
    ids: &[Uuid],
    outbound: bool,
    edge_filter: Option<&HashSet<String>>,
    cap: i64,
    truncated: &mut bool,
) -> Result<Vec<Candidate>, AppError> {
    let mut out = Vec::new();
    for e in edges {
        let label = format!("polymorphic:{}", e.id_field);
        if !edge_allowed(&label, edge_filter) {
            continue;
        }
        if outbound && e.from_entity != entity {
            continue;
        }
        if !outbound && !e.targets.iter().any(|t| t == entity) {
            continue;
        }
        if !attome_security::field_gate::field_readable(
            ctx,
            &e.from_entity,
            &e.id_field,
            e.is_sensitive,
            None,
            attome_security::field_gate::Surface::Bulk,
        ) {
            continue;
        }
        let table = quote_ident(&e.from_entity);
        let id_field = quote_ident(&e.id_field);
        let entity_field = quote_ident(&e.entity_field);
        if outbound {
            let rows: Vec<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(&format!(
                "SELECT r.id, r.{entity_field}::text, r.{id_field}::text FROM {table} r \
                  WHERE r.id = ANY($1::uuid[]) AND r.{id_field} IS NOT NULL \
                    AND (r.is_active IS NULL OR r.is_active = true) LIMIT $2"
            ))
            .bind(ids)
            .bind(cap)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            if rows.len() as i64 >= cap {
                *truncated = true;
            }
            for (from_id, target_entity, target_id) in rows {
                let (Some(target_entity), Some(target_id)) = (target_entity, target_id) else {
                    continue;
                };
                let Ok(to_id) = Uuid::parse_str(target_id.trim()) else {
                    continue;
                };
                // Only a target the field allows and the registry knows.
                if !e.targets.contains(&target_entity) || registry.get(&target_entity).is_none() {
                    continue;
                }
                out.push(Candidate {
                    from: NodeRef {
                        entity: entity.to_owned(),
                        id: from_id,
                    },
                    to_entity: target_entity,
                    to_id,
                    edge_type: label.clone(),
                });
            }
        } else {
            let texts: Vec<String> = ids.iter().map(Uuid::to_string).collect();
            let rows: Vec<(Uuid, String)> = sqlx::query_as(&format!(
                "SELECT r.id, r.{id_field}::text FROM {table} r \
                  WHERE r.{entity_field}::text = $1 AND r.{id_field}::text = ANY($2::text[]) \
                    AND (r.is_active IS NULL OR r.is_active = true) LIMIT $3"
            ))
            .bind(entity)
            .bind(&texts)
            .bind(cap)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            if rows.len() as i64 >= cap {
                *truncated = true;
            }
            for (from_id, target_id) in rows {
                let Ok(to_id) = Uuid::parse_str(target_id.trim()) else {
                    continue;
                };
                // Walked backward: the newly found node is the record holding
                // the pair; the edge still reads from it to the target.
                out.push(Candidate {
                    from: NodeRef {
                        entity: entity.to_owned(),
                        id: to_id,
                    },
                    to_entity: e.from_entity.clone(),
                    to_id: from_id,
                    edge_type: label.clone(),
                });
            }
        }
    }
    Ok(out)
}

/// The many-to-many links (`relationship_info` join tables) of records `ids`
/// of `entity`, either side, live links only.
#[allow(clippy::too_many_arguments)]
async fn link_candidates(
    tx: &mut sqlx::PgConnection,
    registry: &EntityMetaRegistry,
    entity: &str,
    ids: &[Uuid],
    edge_filter: Option<&HashSet<String>>,
    cap: i64,
    truncated: &mut bool,
) -> Result<Vec<Candidate>, AppError> {
    let relationships: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT name, entity_a, entity_b, join_table FROM relationship_info \
          WHERE (entity_a = $1 OR entity_b = $1) AND is_active = TRUE AND is_deleted IS NOT TRUE \
          ORDER BY name",
    )
    .bind(entity)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let mut out = Vec::new();
    for (name, entity_a, entity_b, join_table) in relationships {
        let label = format!("link:{name}");
        if !edge_allowed(&label, edge_filter) {
            continue;
        }
        let join = quote_ident(&join_table);
        let mut sides = Vec::new();
        if entity_a == entity {
            sides.push(("a_id", "b_id", entity_b.clone()));
        }
        if entity_b == entity {
            sides.push(("b_id", "a_id", entity_a.clone()));
        }
        for (mine, other, other_entity) in sides {
            if registry.get(&other_entity).is_none() {
                continue;
            }
            let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(&format!(
                "SELECT j.{mine}, j.{other} FROM {join} j \
                  WHERE j.{mine} = ANY($1::uuid[]) AND j.is_active = true LIMIT $2"
            ))
            .bind(ids)
            .bind(cap)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            if rows.len() as i64 >= cap {
                *truncated = true;
            }
            for (from_id, to_id) in rows {
                out.push(Candidate {
                    from: NodeRef {
                        entity: entity.to_owned(),
                        id: from_id,
                    },
                    to_entity: other_entity.clone(),
                    to_id,
                    edge_type: label.clone(),
                });
            }
        }
    }
    Ok(out)
}

// ── Candidate discovery — cheap, unfiltered reads from an already-vetted frontier ──

/// One undecided edge: `from` is a node already known to be visible (either
/// the start node or admitted in a previous hop); `(to_entity, to_id)` is a
/// row that might not even exist as active, and has not been checked for
/// visibility yet. Nothing here is trusted until it passes [`filter_visible`].
struct Candidate {
    from: NodeRef,
    to_entity: String,
    to_id: Uuid,
    edge_type: String,
}

fn group_by_entity(frontier: &[NodeRef]) -> HashMap<&str, Vec<Uuid>> {
    let mut m: HashMap<&str, Vec<Uuid>> = HashMap::new();
    for n in frontier {
        m.entry(n.entity.as_str()).or_default().push(n.id);
    }
    m
}

/// `from_entity.field -> to_entity`, walked forward: `entity`'s own rows
/// carry the target id directly.
#[allow(clippy::too_many_arguments)]
async fn outbound_lookup_candidates(
    tx: &mut sqlx::PgConnection,
    edges: &[LookupEdgeMeta],
    ctx: &SecurityContext,
    entity: &str,
    ids: &[Uuid],
    edge_filter: Option<&HashSet<String>>,
    cap: i64,
    truncated: &mut bool,
) -> Result<Vec<Candidate>, AppError> {
    let mut out = Vec::new();
    for e in edges.iter().filter(|e| e.from_entity == entity) {
        let label = edge_label(e);
        if !edge_allowed(&label, edge_filter) {
            continue;
        }
        // Field-level security: the same `is_sensitive && !can_read` gate
        // `select_columns_filtered` applies to a normal record read. A
        // non-sensitive field is never gated (most lookups), matching that
        // convention exactly rather than inventing a stricter one here.
        // D-589: the graph is a bulk surface.
        if !attome_security::field_gate::field_readable(
            ctx,
            entity,
            &e.field,
            e.is_sensitive,
            None,
            attome_security::field_gate::Surface::Bulk,
        ) {
            continue;
        }
        let table = quote_ident(&e.from_entity);
        let field = quote_ident(&e.field);
        let sql = format!(
            "SELECT r.id AS from_id, r.{field} AS to_id FROM {table} r \
             WHERE r.id = ANY($1::uuid[]) AND r.{field} IS NOT NULL \
               AND (r.is_active IS NULL OR r.is_active = true) LIMIT $2"
        );
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(&sql)
            .bind(ids)
            .bind(cap)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        if rows.len() as i64 >= cap {
            *truncated = true;
        }
        for (from_id, to_id) in rows {
            out.push(Candidate {
                from: NodeRef {
                    entity: entity.to_owned(),
                    id: from_id,
                },
                to_entity: e.to_entity.clone(),
                to_id,
                edge_type: label.clone(),
            });
        }
    }
    Ok(out)
}

/// `from_entity.field -> to_entity`, walked backward: `entity` is the
/// *target* side, so this finds `from_entity` rows whose field equals one of
/// `entity`'s frontier ids.
#[allow(clippy::too_many_arguments)]
async fn inbound_lookup_candidates(
    tx: &mut sqlx::PgConnection,
    edges: &[LookupEdgeMeta],
    ctx: &SecurityContext,
    entity: &str,
    ids: &[Uuid],
    edge_filter: Option<&HashSet<String>>,
    cap: i64,
    truncated: &mut bool,
) -> Result<Vec<Candidate>, AppError> {
    let mut out = Vec::new();
    for e in edges.iter().filter(|e| e.to_entity == entity) {
        let label = edge_label(e);
        if !edge_allowed(&label, edge_filter) {
            continue;
        }
        if !attome_security::field_gate::field_readable(
            ctx,
            &e.from_entity,
            &e.field,
            e.is_sensitive,
            None,
            attome_security::field_gate::Surface::Bulk,
        ) {
            continue;
        }
        let table = quote_ident(&e.from_entity);
        let field = quote_ident(&e.field);
        let sql = format!(
            "SELECT r.id AS from_id, r.{field} AS to_id FROM {table} r \
             WHERE r.{field} = ANY($1::uuid[]) \
               AND (r.is_active IS NULL OR r.is_active = true) LIMIT $2"
        );
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(&sql)
            .bind(ids)
            .bind(cap)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        if rows.len() as i64 >= cap {
            *truncated = true;
        }
        for (from_id, to_id) in rows {
            // The newly discovered node is `from_id` (on `e.from_entity`);
            // `to_id` is one of the frontier's own ids (on `entity`) — the
            // edge still reads from -> to in the underlying data even though
            // we are walking it backward here.
            out.push(Candidate {
                from: NodeRef {
                    entity: entity.to_owned(),
                    id: to_id,
                },
                to_entity: e.from_entity.clone(),
                to_id: from_id,
                edge_type: label.clone(),
            });
        }
    }
    Ok(out)
}

/// `record_relationship`, one direction. `outbound == true` reads the
/// frontier as the `from_*` side and discovers the `to_*` side; `false` is
/// the mirror. Record ids are stored as `text` on this table (it is
/// genuinely polymorphic — no single uuid-typed FK could target every
/// entity), so frontier ids are compared as text and cast back on the way
/// out.
async fn relationship_candidates(
    tx: &mut sqlx::PgConnection,
    entity: &str,
    ids: &[Uuid],
    outbound: bool,
    edge_filter: Option<&HashSet<String>>,
    cap: i64,
    truncated: &mut bool,
) -> Result<Vec<Candidate>, AppError> {
    if let Some(filter) = edge_filter {
        // Cheap short-circuit: skip the round trip entirely when the caller
        // asked for specific edge types and none of them could be a
        // relationship edge.
        if !filter
            .iter()
            .any(|f| f == "relationship" || f.starts_with("relationship:"))
        {
            return Ok(Vec::new());
        }
    }

    let id_strs: Vec<String> = ids.iter().map(Uuid::to_string).collect();
    let (from_entity_col, from_col, to_entity_col, to_col) = if outbound {
        (
            "from_entity_name",
            "from_record_id",
            "to_entity_name",
            "to_record_id",
        )
    } else {
        (
            "to_entity_name",
            "to_record_id",
            "from_entity_name",
            "from_record_id",
        )
    };
    let sql = format!(
        "SELECT {from_col}::uuid AS from_id, {to_entity_col} AS to_entity, \
                {to_col}::uuid AS to_id, relationship_type \
         FROM record_relationship \
         WHERE {from_entity_col} = $1 AND {from_col} = ANY($2::text[]) \
           AND (is_active IS NULL OR is_active = true) LIMIT $3"
    );
    let rows: Vec<(Uuid, String, Uuid, Option<String>)> = sqlx::query_as(&sql)
        .bind(entity)
        .bind(&id_strs)
        .bind(cap)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if rows.len() as i64 >= cap {
        *truncated = true;
    }

    Ok(rows
        .into_iter()
        .filter_map(|(from_id, to_entity, to_id, rel_type)| {
            let label = format!(
                "relationship:{}",
                rel_type.as_deref().unwrap_or("unspecified")
            );
            if let Some(filter) = edge_filter
                && !filter.contains("relationship")
                && !filter.contains(&label)
            {
                return None;
            }
            Some(Candidate {
                from: NodeRef {
                    entity: entity.to_owned(),
                    id: from_id,
                },
                to_entity,
                to_id,
                edge_type: label,
            })
        })
        .collect())
}

// ── The one place visibility is decided ─────────────────────────────────────

/// Checks a batch of candidate `(entity, ids)` groups against the caller's
/// visibility, one grouped query per distinct entity — and only that: no
/// caller of this function may add a node to the walk without going through
/// it first.
///
/// `budget` is the number of newly-visible nodes this call may still admit
/// across every group combined ([`MAX_FANOUT_PER_HOP`] at the start of a
/// hop); it decrements as groups are processed, and once it reaches zero the
/// remaining groups are skipped entirely (and reported truncated) rather than
/// examined for free — the per-row `EXISTS` this fragment pushes is not free,
/// and a caller with 40 distinct discovered entity types in one hop must not
/// pay for all 40 groups just to admit the first 200 rows.
async fn filter_visible(
    tx: &mut sqlx::PgConnection,
    visibility: &PolymorphicVisibility<'_>,
    by_entity: &HashMap<String, Vec<Uuid>>,
    mut budget: i64,
) -> Result<(HashSet<(String, Uuid)>, bool), AppError> {
    let mut visible = HashSet::new();
    let mut truncated = false;

    for (entity, ids) in by_entity {
        if budget <= 0 {
            truncated = true;
            break;
        }
        let table = quote_ident(entity);
        let mut qb: QueryBuilder<Postgres> =
            QueryBuilder::new(format!("SELECT t.id FROM {table} t, (SELECT "));
        qb.push_bind(entity.clone());
        qb.push("::text AS name) ent WHERE t.id = ANY(");
        qb.push_bind(ids.clone());
        qb.push("::uuid[]) AND (t.is_active IS NULL OR t.is_active = true)");
        visibility.push(&mut qb, "ent.name", "t.id");
        qb.push(" LIMIT ");
        qb.push_bind(budget);

        let rows: Vec<Uuid> = qb
            .build_query_scalar()
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;

        let found = rows.len() as i64;
        if found >= budget && (ids.len() as i64) > found {
            truncated = true;
        }
        budget -= found;
        for id in rows {
            visible.insert((entity.clone(), id));
        }
        if budget <= 0 {
            truncated = true;
        }
    }

    Ok((visible, truncated))
}

// ── The walk ─────────────────────────────────────────────────────────────────

/// The bounded BFS itself, testable directly against a real database without
/// a full `EngineState` — mirrors `harness::run_query`'s pattern of taking
/// `db`/a manually-built `PolymorphicVisibility` rather than the production
/// entry point's plumbing. [`traverse`] is the thin wrapper that resolves
/// `EngineState`-specific inputs (the registry snapshot, the access map, pool
/// selection) and calls this.
async fn walk(
    db: &DbPool,
    registry: &EntityMetaRegistry,
    ctx: &SecurityContext,
    visibility: &PolymorphicVisibility<'_>,
    req: &TraverseRequest,
) -> Result<TraverseOutcome, AppError> {
    let edges = lookup_edges(registry);
    let poly_edges = polymorphic_edges(registry);
    let edge_filter: Option<HashSet<String>> =
        req.edge_types.as_ref().map(|v| v.iter().cloned().collect());

    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query(&format!(
        "SET LOCAL statement_timeout = {HOP_STATEMENT_TIMEOUT_MS}"
    ))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    // Step 0: the start node itself must be visible. Never leak its
    // existence to a caller who cannot read it — same `NotFound`, not
    // `Forbidden`, convention `entity_crud::access::require_record_access`
    // uses, so a narrowed caller cannot distinguish "doesn't exist" from
    // "exists but I can't see it."
    let mut start_group = HashMap::new();
    start_group.insert(req.start.entity.clone(), vec![req.start.id]);
    let (start_visible, _) = filter_visible(&mut tx, visibility, &start_group, 1).await?;
    if !start_visible.contains(&(req.start.entity.clone(), req.start.id)) {
        return Err(AppError::NotFound);
    }

    let start = NodeRef {
        entity: req.start.entity.clone(),
        id: req.start.id,
    };
    let mut visited: HashSet<(String, Uuid)> = HashSet::new();
    visited.insert((start.entity.clone(), start.id));
    let mut nodes = vec![GraphNode {
        entity_logicalname: start.entity.clone(),
        record_id: start.id,
        depth: 0,
    }];
    let mut all_edges: Vec<GraphEdge> = Vec::new();
    let mut truncated = false;
    let mut frontier = vec![start];
    let mut depth: u32 = 0;

    while depth < req.max_depth && !frontier.is_empty() {
        if nodes.len() as i64 >= req.limit {
            truncated = true;
            break;
        }
        depth += 1;

        // Step A: cheap, unfiltered candidate edges from the already-vetted
        // frontier — the source side needs no re-check, it was admitted
        // through this same gate in a previous hop (or is the start node).
        let mut candidates = Vec::new();
        for (entity, ids) in group_by_entity(&frontier) {
            if matches!(req.direction, Direction::Outbound | Direction::Both) {
                candidates.extend(
                    outbound_lookup_candidates(
                        &mut tx,
                        &edges,
                        ctx,
                        entity,
                        &ids,
                        edge_filter.as_ref(),
                        MAX_FANOUT_PER_HOP,
                        &mut truncated,
                    )
                    .await?,
                );
                candidates.extend(
                    relationship_candidates(
                        &mut tx,
                        entity,
                        &ids,
                        true,
                        edge_filter.as_ref(),
                        MAX_FANOUT_PER_HOP,
                        &mut truncated,
                    )
                    .await?,
                );
            }
            // O6-T1: polymorphic pairs each way, and many-to-many links
            // (which have no direction of their own).
            if matches!(req.direction, Direction::Outbound | Direction::Both) {
                candidates.extend(
                    polymorphic_candidates(
                        &mut tx,
                        &poly_edges,
                        registry,
                        ctx,
                        entity,
                        &ids,
                        true,
                        edge_filter.as_ref(),
                        MAX_FANOUT_PER_HOP,
                        &mut truncated,
                    )
                    .await?,
                );
            }
            if matches!(req.direction, Direction::Inbound | Direction::Both) {
                candidates.extend(
                    polymorphic_candidates(
                        &mut tx,
                        &poly_edges,
                        registry,
                        ctx,
                        entity,
                        &ids,
                        false,
                        edge_filter.as_ref(),
                        MAX_FANOUT_PER_HOP,
                        &mut truncated,
                    )
                    .await?,
                );
            }
            candidates.extend(
                link_candidates(
                    &mut tx,
                    registry,
                    entity,
                    &ids,
                    edge_filter.as_ref(),
                    MAX_FANOUT_PER_HOP,
                    &mut truncated,
                )
                .await?,
            );
            if matches!(req.direction, Direction::Inbound | Direction::Both) {
                candidates.extend(
                    inbound_lookup_candidates(
                        &mut tx,
                        &edges,
                        ctx,
                        entity,
                        &ids,
                        edge_filter.as_ref(),
                        MAX_FANOUT_PER_HOP,
                        &mut truncated,
                    )
                    .await?,
                );
                candidates.extend(
                    relationship_candidates(
                        &mut tx,
                        entity,
                        &ids,
                        false,
                        edge_filter.as_ref(),
                        MAX_FANOUT_PER_HOP,
                        &mut truncated,
                    )
                    .await?,
                );
            }
        }

        if candidates.is_empty() {
            // The graph is genuinely exhausted from here, not truncated —
            // clear the frontier so the post-loop "stopped at the depth cap
            // with more available" check below does not mistake a stale,
            // already-fully-explored frontier for unexplored depth.
            frontier = Vec::new();
            break;
        }

        // Step B: batch-check visibility of every distinct discovered node,
        // grouped by entity — the ONE gate every candidate passes through.
        let mut group: HashMap<String, Vec<Uuid>> = HashMap::new();
        for c in &candidates {
            group.entry(c.to_entity.clone()).or_default().push(c.to_id);
        }
        for ids in group.values_mut() {
            ids.sort_unstable();
            ids.dedup();
        }
        let (visible, hop_truncated) =
            filter_visible(&mut tx, visibility, &group, MAX_FANOUT_PER_HOP).await?;
        if hop_truncated {
            truncated = true;
        }

        // Step C: only a visible target ever becomes an edge or a node. A
        // hidden node is dropped here, silently to the *caller* (never
        // logged as a denial — a caller cannot tell "this node does not
        // exist" from "this node exists and you cannot see it") and
        // therefore never becomes a hop for the next iteration either.
        let mut next_frontier = Vec::new();
        for c in candidates {
            let key = (c.to_entity, c.to_id);
            if !visible.contains(&key) {
                continue;
            }
            let already_visited = visited.contains(&key);
            if !already_visited && nodes.len() as i64 >= req.limit {
                truncated = true;
                continue;
            }
            all_edges.push(GraphEdge {
                from_entity: c.from.entity,
                from_id: c.from.id,
                to_entity: key.0.clone(),
                to_id: key.1,
                edge_type: c.edge_type,
            });
            if visited.insert(key.clone()) {
                nodes.push(GraphNode {
                    entity_logicalname: key.0.clone(),
                    record_id: key.1,
                    depth: depth as i32,
                });
                next_frontier.push(NodeRef {
                    entity: key.0,
                    id: key.1,
                });
            }
        }
        frontier = next_frontier;
    }

    tx.commit().await.map_err(AppError::internal)?;

    if depth >= req.max_depth && !frontier.is_empty() {
        // The depth cap stopped the walk, not an empty frontier — there may
        // be more beyond it.
        truncated = true;
    }

    Ok(TraverseOutcome {
        nodes,
        edges: all_edges,
        truncated,
    })
}

/// The production entry point: resolves the registry snapshot, the access
/// map, and the read pool from `state`, builds the same
/// `PolymorphicVisibility` `search`'s route builds
/// (`routes.rs::search`), and delegates to [`walk`].
pub async fn traverse(
    state: &EngineState,
    ctx: &SecurityContext,
    req: &TraverseRequest,
) -> Result<TraverseOutcome, AppError> {
    validate_request(req)?;

    let registry = state.entities.load();
    if registry.get(&req.start.entity).is_none() {
        // An unknown entity name leaks nothing — it is a name, not a record.
        return Err(AppError::Validation(format!(
            "unknown entity {:?}",
            req.start.entity
        )));
    }

    let access_map = attome_security::resolve_all_entity_access_levels(
        &state.base.db,
        ctx.user_id,
        RecordAction::Read,
    )
    .await?;
    let default_shares = attome_security::resolve_default_share_entities(
        &state.base.db,
        ctx.user_id,
        &ctx.team_ids,
        RecordAction::Read.share_capability().as_i16(),
    )
    .await?;
    let visibility = PolymorphicVisibility::new(
        ctx,
        &access_map,
        &default_shares,
        Some(FastTierColumns {
            organization_ref: "t.organization_ref",
        }),
    );

    let pool = state.base.read_pool(ctx.user_id).await;
    walk(pool, &registry, ctx, &visibility, req).await
}

// ── HTTP route ───────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/api/v1/graph/traverse",
    tag = "graph",
    request_body = TraverseRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "a bounded, permission-filtered relationship traversal; persists nothing",
    )))),
    responses(
        (status = 200, description = "Bounded, permission-filtered traversal", body = TraverseResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "The start record does not exist or is not visible", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn traverse_route(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(req): Json<TraverseRequest>,
) -> Result<Json<TraverseResponse>, AppError> {
    let outcome = traverse(&state, &ctx, &req).await?;
    Ok(Json(outcome.into_response(req.limit)))
}

// ── A7-T5: how two records are connected ─────────────────────────────────

/// The longest path the path search follows.
pub const MAX_PATH_HOPS: u32 = 3;
/// Paths one search answers.
pub const MAX_PATHS: usize = 10;

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct PathsRequest {
    pub from: NodeRefInput,
    pub to: NodeRefInput,
    /// At most 3 (the default).
    #[serde(default = "default_path_hops")]
    pub max_hops: u32,
    #[serde(default)]
    pub edge_types: Option<Vec<String>>,
}

fn default_path_hops() -> u32 {
    MAX_PATH_HOPS
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PathsResponse {
    /// The shortest connections first, each the edges from `from` to `to`
    /// in walking order (an edge may be walked against its direction).
    pub paths: Vec<Vec<GraphEdge>>,
    /// The walk from `from` hit a bound; a longer or wider connection may
    /// exist.
    pub truncated: bool,
}

/// The simple paths of at most `max_hops` edges from `from` to `to` over
/// `edges` (followed either way), shortest first, at most `max_paths`. Pure.
pub fn paths_between(
    edges: &[GraphEdge],
    from: (&str, Uuid),
    to: (&str, Uuid),
    max_hops: usize,
    max_paths: usize,
) -> Vec<Vec<GraphEdge>> {
    let mut adjacent: HashMap<(String, Uuid), Vec<(usize, (String, Uuid))>> = HashMap::new();
    for (i, e) in edges.iter().enumerate() {
        let a = (e.from_entity.clone(), e.from_id);
        let b = (e.to_entity.clone(), e.to_id);
        adjacent.entry(a.clone()).or_default().push((i, b.clone()));
        adjacent.entry(b).or_default().push((i, a));
    }
    let start = (from.0.to_owned(), from.1);
    let goal = (to.0.to_owned(), to.1);
    let mut found = Vec::new();
    // Breadth-first over partial paths, so shorter paths come first.
    let mut queue: std::collections::VecDeque<(Vec<usize>, Vec<(String, Uuid)>)> =
        std::collections::VecDeque::from([(Vec::new(), vec![start])]);
    while let Some((path, visited)) = queue.pop_front() {
        if found.len() >= max_paths {
            break;
        }
        let Some(here) = visited.last() else { continue };
        if *here == goal && !path.is_empty() {
            found.push(path.iter().map(|&i| edges[i].clone()).collect());
            continue;
        }
        if path.len() >= max_hops {
            continue;
        }
        for (edge, next) in adjacent.get(here).into_iter().flatten() {
            if visited.contains(next) {
                continue;
            }
            let mut p = path.clone();
            p.push(*edge);
            let mut v = visited.clone();
            v.push(next.clone());
            queue.push_back((p, v));
        }
    }
    found
}

/// How `from` and `to` are connected, over what the caller can see: the
/// permission-per-hop walk from `from` ([`traverse`]), then the shortest
/// paths to `to` among its edges. A record the caller cannot see is never a
/// hop, so no path reveals one.
pub async fn paths(
    state: &EngineState,
    ctx: &SecurityContext,
    req: &PathsRequest,
) -> Result<PathsResponse, AppError> {
    if req.max_hops < 1 || req.max_hops > MAX_PATH_HOPS {
        return Err(AppError::Validation(format!(
            "max_hops must be between 1 and {MAX_PATH_HOPS}"
        )));
    }
    let walk = traverse(
        state,
        ctx,
        &TraverseRequest {
            start: req.from.clone(),
            edge_types: req.edge_types.clone(),
            direction: Direction::Both,
            max_depth: req.max_hops,
            limit: MAX_TOTAL_NODES,
        },
    )
    .await?;
    let paths = paths_between(
        &walk.edges,
        (&req.from.entity, req.from.id),
        (&req.to.entity, req.to.id),
        req.max_hops as usize,
        MAX_PATHS,
    );
    Ok(PathsResponse {
        paths,
        truncated: walk.truncated,
    })
}

/// How two records are connected
///
/// A7-T5: the shortest connections (at most 3 hops, 10 paths) between two
/// records, over lookups, hierarchies and record relationships the caller
/// can see at every hop.
#[utoipa::path(
    post,
    path = "/api/v1/graph/paths",
    tag = "graph",
    request_body = PathsRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "a bounded, permission-filtered path search; persists nothing",
    )))),
    responses(
        (status = 200, description = "The connections found", body = PathsResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "The start record does not exist or is not visible", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn paths_route(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(req): Json<PathsRequest>,
) -> Result<Json<PathsResponse>, AppError> {
    Ok(Json(paths(&state, &ctx, &req).await?))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/graph/traverse", post(traverse_route))
        .route("/api/v1/graph/paths", post(paths_route))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document, merged in by `engine::openapi`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(traverse_route, paths_route))]
#[derive(Debug)]
pub struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

// ── Testable internals, exposed narrowly for `tests/graph_traverse.rs` ──────

#[doc(hidden)]
pub mod test_support {
    use super::*;

    pub async fn walk_for_test(
        db: &DbPool,
        registry: &EntityMetaRegistry,
        ctx: &SecurityContext,
        visibility: &PolymorphicVisibility<'_>,
        req: &TraverseRequest,
    ) -> Result<TraverseOutcome, AppError> {
        walk(db, registry, ctx, visibility, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::{AttrInfo, EntityMeta, OnTargetDelete};

    fn attr(logicalname: &str, field_type_int: i32, lookup_entity_ref: Option<Uuid>) -> AttrInfo {
        AttrInfo {
            logicalname: logicalname.to_owned(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref,
            on_target_delete: OnTargetDelete::Orphan,
            data_classification: Default::default(),
            sensitivity: Default::default(),
            sensitivity_confirmed: false,
            options: None,
        }
    }

    fn meta(id: Uuid, name: &str, attrs: Vec<AttrInfo>) -> EntityMeta {
        EntityMeta {
            entity_id: id,
            logicalname: name.to_owned(),
            attrs,
            is_append_only: false,
            primary_name_attribute: None,
        }
    }

    #[test]
    fn depth_and_limit_bounds_are_enforced() {
        let mut req = TraverseRequest {
            start: NodeRefInput {
                entity: "account".into(),
                id: Uuid::now_v7(),
            },
            edge_types: None,
            direction: Direction::Both,
            max_depth: 0,
            limit: DEFAULT_LIMIT,
        };
        assert!(validate_request(&req).is_err(), "depth 0 must be rejected");

        req.max_depth = MAX_DEPTH + 1;
        assert!(
            validate_request(&req).is_err(),
            "depth beyond MAX_DEPTH must be rejected, not silently clamped"
        );

        req.max_depth = MAX_DEPTH;
        req.limit = 0;
        assert!(validate_request(&req).is_err());

        req.limit = MAX_TOTAL_NODES + 1;
        assert!(
            validate_request(&req).is_err(),
            "a caller must not be able to buy more scanning by raising limit \
             past MAX_TOTAL_NODES"
        );

        req.limit = DEFAULT_LIMIT;
        assert!(validate_request(&req).is_ok());
    }

    /// A lookup field targeting the entity's own id is labelled `hierarchy:`,
    /// not `lookup:` — the response contract's "typed by source" promise.
    #[test]
    fn a_self_referencing_lookup_is_labelled_hierarchy() {
        let account_id = Uuid::now_v7();
        let contact_id = Uuid::now_v7();
        let registry = EntityMetaRegistry::from_entities(vec![
            meta(
                account_id,
                "account",
                vec![
                    attr("parent_account_id", 11, Some(account_id)),
                    attr("primary_contact_id", 11, Some(contact_id)),
                ],
            ),
            meta(contact_id, "contact", vec![]),
        ]);

        let edges = lookup_edges(&registry);
        let hierarchy = edges
            .iter()
            .find(|e| e.field == "parent_account_id")
            .expect("the self-referencing edge must be catalogued");
        assert!(hierarchy.is_hierarchy);
        assert_eq!(edge_label(hierarchy), "hierarchy:parent_account_id");

        let lookup = edges
            .iter()
            .find(|e| e.field == "primary_contact_id")
            .expect("the cross-entity edge must be catalogued");
        assert!(!lookup.is_hierarchy);
        assert_eq!(edge_label(lookup), "lookup:primary_contact_id");
    }

    /// A lookup field with no `lookup_entity_ref`, or one pointing at an
    /// entity not in the registry, is skipped rather than panicking — D-057's
    /// pre-existing "lookup created before `ensure_attribute` persisted this"
    /// gap, which `AttrInfo`'s own doc comment names.
    #[test]
    fn a_lookup_with_no_resolvable_target_is_skipped_not_panicked() {
        let account_id = Uuid::now_v7();
        let registry = EntityMetaRegistry::from_entities(vec![meta(
            account_id,
            "account",
            vec![
                attr("owner_id", 11, None),
                attr("ghost_id", 11, Some(Uuid::now_v7())),
            ],
        )]);
        assert!(lookup_edges(&registry).is_empty());
    }

    #[test]
    fn edge_filter_admits_only_the_named_labels() {
        let filter: HashSet<String> = ["lookup:owner_id".to_string()].into_iter().collect();
        assert!(edge_allowed("lookup:owner_id", Some(&filter)));
        assert!(!edge_allowed("lookup:parent_account_id", Some(&filter)));
        assert!(edge_allowed("lookup:owner_id", None));
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    fn edge(a: (&str, u128), b: (&str, u128), t: &str) -> GraphEdge {
        GraphEdge {
            from_entity: a.0.into(),
            from_id: Uuid::from_u128(a.1),
            to_entity: b.0.into(),
            to_id: Uuid::from_u128(b.1),
            edge_type: t.into(),
        }
    }

    #[test]
    fn graph_paths_cross_polymorphic_and_link_edges() {
        // task -regarding-> account <-link:account_contacts-> contact
        let edges = vec![
            edge(("task", 1), ("account", 2), "polymorphic:regarding_id"),
            edge(("account", 2), ("contact", 3), "link:account_contacts"),
        ];
        let found = paths_between(
            &edges,
            ("task", Uuid::from_u128(1)),
            ("contact", Uuid::from_u128(3)),
            3,
            10,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0][0].edge_type, "polymorphic:regarding_id");
        assert_eq!(found[0][1].edge_type, "link:account_contacts");
    }

    #[test]
    fn paths_are_shortest_first_and_walk_edges_either_way() {
        // contact 1 -> account 2 <- opportunity 3 ; contact 1 -> case 4 -> opportunity 3
        let edges = vec![
            edge(("contact", 1), ("account", 2), "lookup:account_ref"),
            edge(("opportunity", 3), ("account", 2), "lookup:account_ref"),
            edge(("case", 4), ("contact", 1), "lookup:contact_ref"),
            edge(("case", 4), ("opportunity", 3), "lookup:opportunity_ref"),
        ];
        let found = paths_between(
            &edges,
            ("contact", Uuid::from_u128(1)),
            ("opportunity", Uuid::from_u128(3)),
            3,
            10,
        );
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].len(), 2);
        assert_eq!(found[1].len(), 2);
        assert!(
            paths_between(
                &edges,
                ("contact", Uuid::from_u128(1)),
                ("opportunity", Uuid::from_u128(3)),
                1,
                10
            )
            .is_empty()
        );
        assert!(
            paths_between(
                &edges,
                ("contact", Uuid::from_u128(1)),
                ("lead", Uuid::from_u128(9)),
                3,
                10
            )
            .is_empty()
        );
    }
}
