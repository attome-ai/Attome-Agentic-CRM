//! P10-T1: metrics in the L5 lineage graph (`metadata_reference`).
//!
//! A metric records what it reads, under `from_kind = "metric"`: the
//! entities and attributes its stored query reads (copied from the query's
//! own recorded lineage, never re-parsed) and the metrics its formula
//! references. A dashboard widget records the metrics it shows
//! (`attome_api::catalog_admin`). So one lookup answers what a metric is made
//! of and what uses it, and [`impact`] previews what a change to it reaches.
//!
//! References are rewritten whenever a metric changes (the catalog lineage
//! sweep reads the change feed) and backfilled once for metrics defined
//! before this release ([`backfill_catalog_lineage`], kind `metric`).

use std::collections::BTreeMap;

use attome_core::{EngineState, MetadataReferenceInput};
use attome_db::DbPool;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::MetricRead;

/// The lineage kind metrics record under.
pub const FROM_KIND: &str = "metric";

/// Most consumers an impact preview lists.
const MAX_CONSUMERS: i64 = 500;

#[derive(sqlx::FromRow)]
struct MetricSource {
    id: Uuid,
    key: Option<String>,
    name: Option<String>,
    query_ref: Option<String>,
    formula: Option<String>,
}

const SOURCE_COLUMNS: &str = "id, key, name, query_ref, formula";

/// The references one metric records: its stored query's entity lineage and
/// the metrics its formula reads (a key no active metric carries is skipped).
async fn references_of(
    db: &DbPool,
    metric: &MetricSource,
) -> Result<Vec<MetadataReferenceInput>, AppError> {
    let mut refs = Vec::new();
    if let Some(query) = metric
        .query_ref
        .as_deref()
        .and_then(|q| Uuid::parse_str(q).ok())
    {
        refs.extend(attome_core::references_from(db, "query", query).await?);
    }
    if let Some(formula) = metric.formula.as_deref().filter(|f| !f.trim().is_empty())
        && let Ok(keys) = crate::metric::formula_metric_keys(formula)
        && !keys.is_empty()
    {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM dashboard_metric_definition \
             WHERE key = ANY($1) AND (is_active IS NULL OR is_active = true) AND id <> $2",
        )
        .bind(&keys)
        .bind(metric.id)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        refs.extend(ids.into_iter().map(MetadataReferenceInput::metric));
    }
    Ok(refs)
}

fn label(metric: &MetricSource) -> String {
    metric
        .name
        .clone()
        .or_else(|| metric.key.clone())
        .unwrap_or_default()
}

/// Rewrites `metric_id`'s recorded references from its current definition;
/// a deleted or deactivated metric records none.
pub async fn sync_metric_lineage(db: &DbPool, metric_id: Uuid) -> Result<(), AppError> {
    let metric: Option<MetricSource> = sqlx::query_as(&format!(
        "SELECT {SOURCE_COLUMNS} FROM dashboard_metric_definition \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)"
    ))
    .bind(metric_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (label, refs) = match &metric {
        Some(metric) => (label(metric), references_of(db, metric).await?),
        None => (String::new(), Vec::new()),
    };
    let mut tx = attome_db::tx::begin(db).await?;
    attome_core::replace_references(&mut tx, FROM_KIND, metric_id, &label, &refs).await?;
    attome_db::tx::commit(tx).await
}

/// One bounded batch of the backfill for metrics defined before their
/// lineage was recorded, keyset-paginated by id from the `metric` kind's
/// cursor (the same resumable, idempotent shape as the query and workflow
/// backfills). Returns how many metrics it processed (0 once complete).
pub async fn backfill_catalog_lineage(db: &DbPool, batch_limit: i64) -> Result<usize, AppError> {
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let progress = attome_core::backfill_progress(&mut conn, FROM_KIND).await?;
    if progress.completed {
        return Ok(0);
    }
    let cursor = progress.last_ref.unwrap_or(Uuid::nil());
    let rows: Vec<MetricSource> = sqlx::query_as(&format!(
        "SELECT {SOURCE_COLUMNS} FROM dashboard_metric_definition \
         WHERE id > $1 AND (is_active IS NULL OR is_active = true) ORDER BY id LIMIT $2"
    ))
    .bind(cursor)
    .bind(batch_limit)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if rows.is_empty() {
        attome_core::advance_backfill_progress(&mut conn, FROM_KIND, cursor, 0, true).await?;
        return Ok(0);
    }
    drop(conn);
    let mut prepared = Vec::with_capacity(rows.len());
    for metric in &rows {
        prepared.push((metric.id, label(metric), references_of(db, metric).await?));
    }
    let mut tx = attome_db::tx::begin(db).await?;
    let mut last = cursor;
    for (id, label, refs) in &prepared {
        attome_core::replace_references(&mut tx, FROM_KIND, *id, label, refs).await?;
        last = *id;
    }
    let processed = prepared.len();
    let completed = (processed as i64) < batch_limit;
    attome_core::advance_backfill_progress(&mut tx, FROM_KIND, last, processed as i64, completed)
        .await?;
    attome_db::tx::commit(tx).await?;
    Ok(processed)
}

/// One thing a metric reads.
#[derive(Debug, Serialize, ToSchema)]
pub struct MetricInput {
    /// `entity` or `metric`.
    pub kind: String,
    /// The entity's logical name (an entity input).
    pub entity: Option<String>,
    /// The attribute, when the input is one attribute of the entity.
    pub attribute: Option<String>,
    /// The metric's id (a metric input).
    pub metric_id: Option<Uuid>,
}

/// One thing that uses a metric.
#[derive(Debug, Serialize, ToSchema)]
pub struct MetricConsumer {
    /// What it is: `dashboard` (a widget), `metric`, ...
    pub kind: String,
    pub id: Uuid,
    pub label: String,
}

/// What a metric is made of and what a change to it reaches.
#[derive(Debug, Serialize, ToSchema)]
pub struct MetricImpact {
    pub metric_id: Uuid,
    pub upstream: Vec<MetricInput>,
    /// Everything that references the metric, by kind (at most 500).
    pub downstream: Vec<MetricConsumer>,
    /// How many consumers of each kind a change reaches.
    pub impact: BTreeMap<String, usize>,
}

/// The metric's recorded inputs and consumers. Performs no authorization of
/// its own.
pub async fn impact(db: &DbPool, metric_id: Uuid) -> Result<MetricImpact, AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM dashboard_metric_definition \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(metric_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let upstream = attome_core::references_from(db, FROM_KIND, metric_id)
        .await?
        .into_iter()
        .map(|r| {
            if r.to_kind == "metric" {
                MetricInput {
                    kind: "metric".into(),
                    entity: None,
                    attribute: None,
                    metric_id: r.to_ref,
                }
            } else {
                MetricInput {
                    kind: "entity".into(),
                    entity: Some(r.to_entity),
                    attribute: r.to_attribute,
                    metric_id: None,
                }
            }
        })
        .collect();
    let downstream: Vec<MetricConsumer> =
        attome_core::references_to_metric(db, metric_id, MAX_CONSUMERS)
            .await?
            .into_iter()
            .map(|r| MetricConsumer {
                kind: r.from_kind,
                id: r.from_ref,
                label: r.from_label,
            })
            .collect();
    let mut counts = BTreeMap::new();
    for consumer in &downstream {
        *counts.entry(consumer.kind.clone()).or_insert(0) += 1;
    }
    Ok(MetricImpact {
        metric_id,
        upstream,
        downstream,
        impact: counts,
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/metrics/{id}/impact",
    description = "What the metric reads (entities, attributes and other metrics) and what uses it (dashboard widgets, metrics), from the lineage graph; the counts preview what a change reaches (P10-T1).",
    tag = "dashboard",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "The metric's inputs and consumers", body = MetricImpact),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such metric", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn metric_impact(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<MetricRead>>,
    Path(metric_id): Path<Uuid>,
) -> Result<Json<MetricImpact>, AppError> {
    impact(&state.base.db, metric_id).await.map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lineage_label_prefers_the_name_then_the_key() {
        let metric = |name: Option<&str>, key: Option<&str>| MetricSource {
            id: Uuid::nil(),
            key: key.map(str::to_owned),
            name: name.map(str::to_owned),
            query_ref: None,
            formula: None,
        };
        assert_eq!(label(&metric(Some("Revenue"), Some("rev"))), "Revenue");
        assert_eq!(label(&metric(None, Some("rev"))), "rev");
        assert_eq!(label(&metric(None, None)), "");
    }

    #[test]
    fn lineage_metric_references_name_the_metric() {
        let id = Uuid::now_v7();
        let r = MetadataReferenceInput::metric(id);
        assert_eq!(r.to_kind, "metric");
        assert_eq!(r.to_ref, Some(id));
        assert_eq!(r.to_entity, format!("metric:{id}"));
        assert_eq!(MetadataReferenceInput::entity("deal").to_kind, "entity");
    }
}
