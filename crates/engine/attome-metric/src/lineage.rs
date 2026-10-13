//! Metric lineage (dashboard 10/10 Phase 3.3) — "what is this KPI made of".
//!
//! `GET /api/v1/metrics/{id}/lineage` walks one metric's composition for a
//! period: its children by `parent_ref` (with each child's `weight`) and, for a
//! formula metric, the metrics its formula references by `key`. Every node
//! carries its latest snapshot for the root's period. The walk is cycle-safe (a
//! visited set marks a repeated metric instead of descending into it) and
//! depth-bounded, so a malformed hierarchy degrades to a truncated tree, never a
//! hang. `parent_ref` gets its first reader here; no new hierarchy model.
use std::collections::HashSet;

use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::auth::MetricRead;
use crate::metric::{SnapshotRow, formula_metric_keys, latest_snapshot, period_start_for};

/// Deepest level the walk descends to (the root is depth 0).
pub const MAX_LINEAGE_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LineageRelation {
    Root,
    /// A metric whose `parent_ref` is its parent node.
    Child,
    /// A metric its parent node's formula references by `key`.
    FormulaInput,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MetricLineageNode {
    /// `None` for a formula reference to a key no active metric carries.
    pub metric_id: Option<Uuid>,
    pub key: Option<String>,
    pub name: Option<String>,
    pub unit: Option<String>,
    pub source_kind: Option<String>,
    pub formula: Option<String>,
    pub period: Option<String>,
    pub relation: LineageRelation,
    /// A child's weight in its parent.
    pub weight: Option<f64>,
    /// The latest snapshot for the lineage period; `null` when none exists.
    pub snapshot: Option<SnapshotRow>,
    /// This metric already appears higher up the tree; it is not expanded again.
    pub cycle: bool,
    /// A formula reference that names no active metric.
    pub missing: bool,
    /// The depth limit stopped the walk here.
    pub truncated: bool,
    /// `no_recursion`: the node is recursive, and without it building the
    /// OpenAPI document expands it inline forever (same fix as
    /// `attome_dashboard::layout::SnapshotSection`).
    #[schema(no_recursion)]
    pub children: Vec<MetricLineageNode>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MetricLineageResponse {
    pub period_start: NaiveDate,
    pub root: MetricLineageNode,
}

#[derive(Deserialize, IntoParams)]
pub struct LineageQuery {
    /// The period to read snapshots for; defaults to the root metric's current
    /// period.
    period_start: Option<NaiveDate>,
}

impl std::fmt::Debug for LineageQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineageQuery").finish_non_exhaustive()
    }
}

#[derive(sqlx::FromRow)]
struct LineageRow {
    id: Uuid,
    key: Option<String>,
    name: Option<String>,
    unit: Option<String>,
    source_kind: Option<String>,
    formula: Option<String>,
    period: Option<String>,
    weight: Option<f64>,
}

const LINEAGE_COLUMNS: &str = "id, key, name, unit, source_kind, formula, period, \
     weight::double precision AS weight";

async fn metric_by_id(db: &DbPool, id: Uuid) -> Result<Option<LineageRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {LINEAGE_COLUMNS} FROM dashboard_metric_definition \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

async fn metric_by_key(db: &DbPool, key: &str) -> Result<Option<LineageRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {LINEAGE_COLUMNS} FROM dashboard_metric_definition \
         WHERE key = $1 AND (is_active IS NULL OR is_active = true)"
    ))
    .bind(key)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

async fn children_of(db: &DbPool, id: Uuid) -> Result<Vec<LineageRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {LINEAGE_COLUMNS} FROM dashboard_metric_definition \
         WHERE parent_ref = $1 AND (is_active IS NULL OR is_active = true) \
         ORDER BY key NULLS LAST, id"
    ))
    .bind(id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

fn node(row: &LineageRow, relation: LineageRelation) -> MetricLineageNode {
    MetricLineageNode {
        metric_id: Some(row.id),
        key: row.key.clone(),
        name: row.name.clone(),
        unit: row.unit.clone(),
        source_kind: row.source_kind.clone(),
        formula: row.formula.clone(),
        period: row.period.clone(),
        relation,
        weight: if relation == LineageRelation::Child {
            row.weight
        } else {
            None
        },
        snapshot: None,
        cycle: false,
        missing: false,
        truncated: false,
        children: Vec::new(),
    }
}

/// Builds the lineage tree depth-first down to [`MAX_LINEAGE_DEPTH`].
/// `ancestors` holds the metric ids on the path from the root, which is what
/// makes a cycle a marked leaf instead of an infinite walk.
fn expand<'a>(
    db: &'a DbPool,
    row: LineageRow,
    relation: LineageRelation,
    period_start: NaiveDate,
    depth: usize,
    ancestors: &'a mut HashSet<Uuid>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<MetricLineageNode, AppError>> + Send + 'a>,
> {
    Box::pin(async move {
        let mut current = node(&row, relation);
        current.snapshot = latest_snapshot(db, row.id, period_start).await?;
        if depth >= MAX_LINEAGE_DEPTH {
            current.truncated = true;
            return Ok(current);
        }
        ancestors.insert(row.id);

        let mut next: Vec<(LineageRow, LineageRelation)> = children_of(db, row.id)
            .await?
            .into_iter()
            .map(|child| (child, LineageRelation::Child))
            .collect();
        if let Some(formula) = row.formula.as_deref().filter(|f| !f.trim().is_empty()) {
            let keys = formula_metric_keys(formula).unwrap_or_default();
            for key in keys {
                match metric_by_key(db, &key).await? {
                    Some(input) => next.push((input, LineageRelation::FormulaInput)),
                    None => current.children.push(MetricLineageNode {
                        metric_id: None,
                        key: Some(key),
                        name: None,
                        unit: None,
                        source_kind: None,
                        formula: None,
                        period: None,
                        relation: LineageRelation::FormulaInput,
                        weight: None,
                        snapshot: None,
                        cycle: false,
                        missing: true,
                        truncated: false,
                        children: Vec::new(),
                    }),
                }
            }
        }

        for (child, child_relation) in next {
            if ancestors.contains(&child.id) {
                let mut repeated = node(&child, child_relation);
                repeated.cycle = true;
                current.children.push(repeated);
                continue;
            }
            let expanded = expand(
                db,
                child,
                child_relation,
                period_start,
                depth + 1,
                ancestors,
            )
            .await?;
            current.children.push(expanded);
        }
        ancestors.remove(&row.id);
        Ok(current)
    })
}

/// The lineage of `metric_id` for `period_start` (default: its current
/// period). Performs no authorization of its own.
pub async fn do_metric_lineage(
    db: &DbPool,
    metric_id: Uuid,
    period_start: Option<NaiveDate>,
) -> Result<MetricLineageResponse, AppError> {
    let root = metric_by_id(db, metric_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let period_start = match period_start {
        Some(p) => p,
        None => period_start_for(root.period.as_deref().unwrap_or("month"), Utc::now())?,
    };
    let mut ancestors = HashSet::new();
    let root = expand(
        db,
        root,
        LineageRelation::Root,
        period_start,
        0,
        &mut ancestors,
    )
    .await?;
    Ok(MetricLineageResponse { period_start, root })
}

#[utoipa::path(
    get,
    path = "/api/v1/metrics/{id}/lineage",
    tag = "dashboard",
    params(("id" = Uuid, Path), LineageQuery),
    responses(
        (status = 200, description = "The metric's children and formula inputs, each with its snapshot for the period", body = MetricLineageResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such metric", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn metric_lineage(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<MetricRead>>,
    Path(metric_id): Path<Uuid>,
    Query(query): Query<LineageQuery>,
) -> Result<Json<MetricLineageResponse>, AppError> {
    do_metric_lineage(&state.base.db, metric_id, query.period_start)
        .await
        .map(Json)
}
