//! M18 Data Catalog Phase 1 (D-466) — `EngineJob::CatalogLineageBackfill`'s
//! 'workflow' half: populates `metadata_reference` for every
//! workflow definition published BEFORE this release's lineage writer
//! (`admin.rs`'s `publish` handler) existed. Sibling of
//! `attome_records::query_admin::backfill_catalog_lineage` — same bounded,
//! resumable, idempotent-to-reprocess shape (0357's header), reading each
//! definition's currently-published version's graph and running it through
//! the same `trigger_index::collect_entity_lineage` the live writer uses, so
//! a backfilled row and a freshly-published row are computed identically.

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

use crate::graph::Graph;
use crate::trigger_index::collect_entity_lineage;

/// Processes one bounded batch of `workflow_definition` rows, keyset-
/// paginated by `id` from the 'workflow' kind's backfill cursor. Returns the
/// number of definitions processed this call (0 once complete).
pub async fn backfill_catalog_lineage(db: &DbPool, batch_limit: i64) -> Result<usize, AppError> {
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let progress = attome_core::backfill_progress(&mut conn, "workflow").await?;
    if progress.completed {
        return Ok(0);
    }
    let cursor = progress.last_ref.unwrap_or(Uuid::nil());

    // Only definitions with a currently-published version carry a graph
    // worth recording — a definition still in draft, or one whose only
    // version was deprecated with no replacement, has nothing live to
    // reference (mirrors what `publish` itself would have written: nothing,
    // until it publishes).
    let rows: Vec<(Uuid, String, serde_json::Value)> = sqlx::query_as(
        "SELECT d.id, d.name, v.graph \
         FROM workflow_definition d \
         JOIN workflow_definition_version v \
             ON v.definition_id = d.id AND v.status = 'published' \
         WHERE d.id > $1 AND d.is_active = true AND d.is_deleted = false \
         ORDER BY d.id \
         LIMIT $2",
    )
    .bind(cursor)
    .bind(batch_limit)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;

    if rows.is_empty() {
        attome_core::advance_backfill_progress(&mut conn, "workflow", cursor, 0, true).await?;
        return Ok(0);
    }
    // Release the plain connection before opening a separate transaction —
    // no reason to hold two pool connections for the rest of this call.
    drop(conn);

    let mut tx = attome_db::tx::begin(db).await?;
    let mut last = cursor;
    let processed = rows.len();
    for (id, name, graph_json) in &rows {
        // A graph that fails to parse here would already have failed to
        // publish — but schema drift across a long-since-published version
        // is possible in principle, so skip it (log and continue) rather
        // than stall the whole backfill on one bad historical row, same
        // "one record's failure doesn't stall the sweep" posture
        // `duplicates_match::run_match_sweep` documents.
        match Graph::parse(graph_json) {
            Ok(graph) => {
                attome_core::replace_references(
                    &mut tx,
                    "workflow",
                    *id,
                    name,
                    &collect_entity_lineage(&graph),
                )
                .await?;
            }
            Err(e) => {
                tracing::warn!(
                    definition_id = %id,
                    error = %e,
                    "catalog lineage backfill: workflow graph failed to parse, skipping"
                );
            }
        }
        last = *id;
    }
    let completed = (processed as i64) < batch_limit;
    attome_core::advance_backfill_progress(&mut tx, "workflow", last, processed as i64, completed)
        .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok(processed)
}
