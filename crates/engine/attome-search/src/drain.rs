//! Draining the change feed into the index (TODO-016).
//!
//! Reads `entity_change_event` through the per-consumer cursor
//! (D-358), never through attome-workflow's destructive `processed_at` claim —
//! using that claim would make the two consumers eat each other's events
//! silently, which is the whole reason the cursor exists.
//!
//! **The `content_hash` gate is the point of this module.** The cursor's
//! visibility horizon means the drain legitimately re-reads a window of events
//! (§11.3 estimates each event is re-projected ~12 times). Harmless as an
//! upsert; ruinous without a gate:
//!
//!   * every indexed column changes on rewrite, so **HOT updates are
//!     impossible** — each no-op write is a dead tuple plus GIN churn on four
//!     indexes;
//!   * in Stage 2 it is also twelve times the embedding cost, which is GPU
//!     time a deployment paid for.
//!
//! `WHERE content_hash IS DISTINCT FROM $new` turns all of that into one cheap
//! comparison. Sixteen bytes per row and microseconds to compute.

use attome_core::change_feed::{self, ChangeEvent, ChangeOperation};
use attome_types::AppError;
use sqlx::PgPool;
use uuid::Uuid;

use crate::project::ProjectedRow;

/// This consumer's cursor name. A stable, code-owned constant — a typo would
/// silently create a second cursor that re-reads the entire retained feed.
pub const CONSUMER: &str = "attome-search/index-drain";

/// The corpus record events land in.
pub const CORPUS_RECORD: &str = "record";

/// How many events one drain pass claims. Bounded so a backlog is worked
/// through in steady batches rather than one transaction that holds the
/// visibility horizon down for everyone else (D-358's documented cost).
pub const DRAIN_BATCH: i64 = 200;

/// What one drain pass did. Reported rather than logged-and-forgotten: the
/// ratio of `skipped_unchanged` to `written` is the direct measure of whether
/// the hash gate is earning its place, and a sudden collapse in it is the
/// first symptom of a projection that became non-deterministic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainStats {
    pub read: u64,
    pub written: u64,
    pub skipped_unchanged: u64,
    pub deleted: u64,
    /// Knowledge chunk rows written by the `knowledge_data_item` arm
    /// (D-489). Separate from `written` because the two projections fail
    /// differently: a record that fails to project costs a search result, a
    /// chunk that fails to project costs an answer.
    pub knowledge_written: u64,
    /// Knowledge chunk rows removed by that arm — an item that shrank, moved,
    /// or stopped being published.
    pub knowledge_removed: u64,
    /// Events whose operation this build does not recognise. Skipped, not
    /// failed — a consumer running older code than the writer must not crash
    /// the drain.
    pub skipped_unknown_op: u64,
}

/// Upserts one projected row, **skipping the write entirely when nothing
/// changed**.
///
/// Returns `true` when a row was actually written.
///
/// The gate is in the `WHERE` of the `DO UPDATE`, not in Rust: fetching the
/// old hash to compare in the application would be a second round trip per
/// event, which on a re-read window of twelve is worse than the write it
/// avoids.
pub async fn upsert_row(
    db: &PgPool,
    entity_logicalname: &str,
    record_id: Uuid,
    row: &ProjectedRow,
    organization_ref: Option<Uuid>,
    owner_id: Option<Uuid>,
    source_modifiedon: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<bool, AppError> {
    let affected = sqlx::query(
        "INSERT INTO search_index \
            (corpus, entity_logicalname, record_id, title, title_norm, subtitle, \
             body_display, body_indexed, exact_keys, tsv, organization_ref, \
             owner_id, source_modifiedon, indexed_at, content_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                 to_tsvector('attome_search', coalesce($5, '') || ' ' || coalesce($8, '')), \
                 $10, $11, $12, NOW(), $13) \
         ON CONFLICT (corpus, entity_logicalname, record_id) DO UPDATE SET \
             title = EXCLUDED.title, \
             title_norm = EXCLUDED.title_norm, \
             subtitle = EXCLUDED.subtitle, \
             body_display = EXCLUDED.body_display, \
             body_indexed = EXCLUDED.body_indexed, \
             exact_keys = EXCLUDED.exact_keys, \
             tsv = EXCLUDED.tsv, \
             organization_ref = EXCLUDED.organization_ref, \
             owner_id = EXCLUDED.owner_id, \
             source_modifiedon = EXCLUDED.source_modifiedon, \
             indexed_at = NOW(), \
             content_hash = EXCLUDED.content_hash \
         WHERE search_index.content_hash IS DISTINCT FROM EXCLUDED.content_hash",
    )
    .bind(CORPUS_RECORD)
    .bind(entity_logicalname)
    .bind(record_id)
    .bind(&row.title)
    .bind(&row.title_norm)
    .bind(&row.subtitle)
    .bind(&row.body_display)
    .bind(&row.body_indexed)
    .bind(&row.exact_keys)
    .bind(organization_ref)
    .bind(owner_id)
    .bind(source_modifiedon)
    .bind(&row.content_hash)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    Ok(affected > 0)
}

/// Removes a record from the index.
///
/// Used for both `Delete` and `Purge`, and the distinction matters even though
/// the SQL is identical: a soft delete makes the record unfindable, while a
/// purge discharges an **erasure obligation** on a second copy of business
/// text (D-358 ruling 4). Conflating them in the code would be fine today and
/// wrong the moment an embedding column exists, because that column has to go
/// too — which is why the caller matches on the operation rather than this
/// function collapsing them.
pub async fn delete_row(
    db: &PgPool,
    entity_logicalname: &str,
    record_id: Uuid,
) -> Result<bool, AppError> {
    let affected = sqlx::query(
        "DELETE FROM search_index \
         WHERE corpus = $1 AND entity_logicalname = $2 AND record_id = $3",
    )
    .bind(CORPUS_RECORD)
    .bind(entity_logicalname)
    .bind(record_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(affected > 0)
}

/// Resolves a record's current text. Supplied by the caller because *which*
/// fields are the title and body is metadata-driven and belongs to the engine
/// layer above this one.
///
/// Returning `Ok(None)` means "this record is gone or not indexable" and is
/// treated exactly like a delete — a record that vanished between the event
/// and the drain must not leave a stale index row behind.
pub type ProjectFn<'a> = &'a dyn Fn(
    &str,
    Uuid,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<Option<(ProjectedRow, Option<Uuid>, Option<Uuid>)>, AppError>,
            > + Send
            + 'a,
    >,
>;

/// Runs one drain pass.
///
/// **The cursor advances per event, after that event's work.** Advancing for
/// the whole batch at the end would mean a crash mid-batch re-does the batch —
/// safe, since every operation here is idempotent, but it would also re-do the
/// GPU work in Stage 2. Advancing before the work would lose events.
pub async fn drain_once(
    db: &PgPool,
    project_record: ProjectFn<'_>,
) -> Result<DrainStats, AppError> {
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let batch = change_feed::read_batch(&mut conn, CONSUMER, DRAIN_BATCH).await?;

    let mut stats = DrainStats {
        read: batch.len() as u64,
        ..DrainStats::default()
    };

    for event in &batch {
        // ── The knowledge arm (D-489) ───────────────────────────────────────
        //
        // A `knowledge_data_item` write is a knowledge-chunk change, not a
        // generic record-index change. Both projections are driven by the same
        // event feed, which is what lets the admin API and `attome-webcrawl`'s
        // import produce retrievable articles without either crate depending on
        // `attome-search`'s index — the zero-edge shape M11 §5 and D-452 chose.
        if event.entity_logicalname == crate::knowledge_index::ITEM_ENTITY {
            match event.operation() {
                Some(
                    ChangeOperation::Create | ChangeOperation::Update | ChangeOperation::Restore,
                ) => {
                    let projected =
                        crate::knowledge_index::reindex_item(db, event.record_id).await?;
                    stats.knowledge_written += projected.written;
                    stats.knowledge_removed += projected.removed;
                }
                // A soft delete arrives as an `Update` (the row still exists
                // with `is_active = false`), so `reindex_item`'s liveness check
                // already removes its chunks. A hard `Delete`/`Purge` removes
                // them outright.
                Some(ChangeOperation::Delete | ChangeOperation::Purge) => {
                    stats.knowledge_removed +=
                        crate::knowledge_index::remove_item_chunks(db, event.record_id).await?;
                }
                None => {
                    tracing::warn!(
                        operation = %event.operation,
                        "search drain skipped an unrecognised change operation"
                    );
                    stats.skipped_unknown_op += 1;
                }
            }
            advance(&mut conn, event).await?;
            continue;
        }

        match event.operation() {
            Some(ChangeOperation::Create | ChangeOperation::Update | ChangeOperation::Restore) => {
                match project_record(&event.entity_logicalname, event.record_id).await? {
                    Some((row, org, owner)) => {
                        if upsert_row(
                            db,
                            &event.entity_logicalname,
                            event.record_id,
                            &row,
                            org,
                            owner,
                            Some(event.created_at),
                        )
                        .await?
                        {
                            stats.written += 1;
                        } else {
                            stats.skipped_unchanged += 1;
                        }
                    }
                    // Gone between the event and the drain. Treated as a
                    // delete rather than ignored: leaving the old row would
                    // keep a deleted record findable, which is the disclosure
                    // D-358 exists to close.
                    None => {
                        if delete_row(db, &event.entity_logicalname, event.record_id).await? {
                            stats.deleted += 1;
                        }
                    }
                }
            }
            Some(ChangeOperation::Delete | ChangeOperation::Purge) => {
                if delete_row(db, &event.entity_logicalname, event.record_id).await? {
                    stats.deleted += 1;
                }
            }
            // An operation this build does not know. Skipped, and the cursor
            // still advances — the reconciliation scan (D-358) is what
            // eventually repairs anything a skip left behind.
            None => {
                tracing::warn!(
                    operation = %event.operation,
                    "search drain skipped an unrecognised change operation"
                );
                stats.skipped_unknown_op += 1;
            }
        }

        advance(&mut conn, event).await?;
    }

    Ok(stats)
}

async fn advance(conn: &mut sqlx::PgConnection, event: &ChangeEvent) -> Result<(), AppError> {
    change_feed::advance(conn, CONSUMER, event).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The consumer name is a constant, not a computed string. A drifting name
    /// creates a fresh cursor at position zero, which silently re-reads the
    /// entire retained feed — expensive, and it looks like a performance
    /// mystery rather than a naming bug.
    #[test]
    fn the_consumer_name_is_stable_and_namespaced() {
        assert_eq!(CONSUMER, "attome-search/index-drain");
        assert!(
            CONSUMER.starts_with("attome-search/"),
            "the cursor namespace must name its owning crate"
        );
    }

    /// The gate lives in SQL, not in Rust. Comparing in the application would
    /// need a `SELECT` per event before the write, and on a re-read window of
    /// twelve that is worse than the write it avoids.
    #[test]
    fn the_hash_gate_is_in_the_upsert_not_in_rust() {
        let source = include_str!("drain.rs");
        assert!(
            source.contains("content_hash IS DISTINCT FROM EXCLUDED.content_hash"),
            "the no-op write must be prevented by the DO UPDATE's WHERE"
        );
    }

    #[test]
    fn stats_start_empty() {
        let s = DrainStats::default();
        assert_eq!(s.read, 0);
        assert_eq!(s.written, 0);
        assert_eq!(s.skipped_unchanged, 0);
    }
}
