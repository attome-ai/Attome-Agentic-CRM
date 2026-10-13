//! The knowledge-chunk producer (TODO-032, `P-knowledge-base` §6–§7; D-489).
//!
//! ## Why this is a consumer arm and not a call from the authoring side
//!
//! The obvious design — `attome-content` calls into `attome-search` when a page is
//! published — adds a content→search dependency edge and puts index writes
//! behind an authoring crate. The design here is the other one: the entity
//! engine already emits `entity_change_event` on **every** entity
//! write, so a `knowledge_data_item` write reaches `crate::drain` through
//! the feed that already exists. `attome-webcrawl`'s import is an ordinary entity
//! write, so crawled items are chunked by the same arm without either crate
//! learning about the other (D-365's blast-radius containment is preserved).
//!
//! ## Delete on un-publish, not filter
//!
//! `P-knowledge-base` §7 requires that un-publishing **remove** chunks from
//! retrieval rather than merely hide the article, and §14.1 leaves open whether
//! a draft's chunks are maintained-and-filtered or absent. D-489 takes the
//! absent branch deliberately: every write path here deletes the item's chunks
//! unless the item is `published`, so the disclosure-critical path has no
//! filter to get wrong. `KnowledgeVisibility` still filters `lifecycle` as
//! defence in depth, because the chunk table is readable directly.
//!
//! ## The hash gate is the point
//!
//! The change feed's visibility horizon means a consumer legitimately re-reads
//! a window of events. Harmless as an upsert; ruinous without a gate, for the
//! same reasons `drain.rs` documents: every rewritten row is a dead tuple plus
//! GIN churn, and at Stage 2 it is also re-embedded. The `DO UPDATE ... WHERE`
//! compares sixteen bytes in SQL rather than re-reading in Rust.
//!
//! **The gate also covers `collection_ref`, and that is not an optimisation.**
//! Moving an item to a different Data Source changes its permission anchor
//! without changing its text; a hash-only gate would skip the update and leave
//! the chunk readable under the *old* source. That is a disclosure with no
//! symptom, so the gate is `content_hash IS DISTINCT FROM ... OR
//! collection_ref IS DISTINCT FROM ...`.

use attome_types::AppError;
use sqlx::PgPool;
use uuid::Uuid;

use crate::corpus::knowledge::chunk_article;

/// The entity whose records are chunked. D-489 makes this the canonical
/// knowledge article; the physical table name is also the logical name for a
/// runtime-provisioned entity.
pub const ITEM_ENTITY: &str = "knowledge_data_item";

/// The permission anchor `collection_ref` points at (D-489; `P-knowledge-base`
/// §4.2's "the collection is an ordinary record" model).
pub const COLLECTION_ENTITY: &str = "knowledge_data_source";

/// The lifecycle value that makes an item's chunks retrievable.
pub const PUBLISHED: &str = "published";

/// The source discriminator every row this module writes carries.
pub const SOURCE_TYPE: &str = "article";

/// What one re-projection did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReindexStats {
    /// Chunk rows written (the hash or the collection actually changed).
    pub written: u64,
    /// Chunk rows removed because the item shrank, moved, or stopped being
    /// published.
    pub removed: u64,
}

/// Removes every chunk belonging to one item.
///
/// Used by the drain's `Delete | Purge` arm and by every path that finds the
/// item not-published. Idempotent: deleting zero rows is not an error.
pub async fn remove_item_chunks(db: &PgPool, item_id: Uuid) -> Result<u64, AppError> {
    let removed = sqlx::query(
        r#"DELETE FROM knowledge_chunk
           WHERE source_type = $1 AND source_id = $2"#,
    )
    .bind(SOURCE_TYPE)
    .bind(item_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(removed)
}

/// One item's projection source, as a named shape.
///
/// A named struct rather than a five-element tuple: a tuple this wide is
/// unreadable at the `let` that destructures it, and its column order becomes a
/// silent contract (clippy's `type_complexity` is the mechanical statement of
/// the same point).
#[derive(sqlx::FromRow)]
struct ItemRow {
    title: String,
    text: Option<String>,
    data_source_ref: Option<Uuid>,
    lifecycle: Option<String>,
    is_active: Option<bool>,
}

/// Reads one item and (re)projects its chunks.
///
/// `Ok(ReindexStats::default())` is the normal no-op result for an unchanged
/// published item. A missing, soft-deleted, or non-published item has its
/// chunks removed.
pub async fn reindex_item(db: &PgPool, item_id: Uuid) -> Result<ReindexStats, AppError> {
    let row: Option<ItemRow> = sqlx::query_as(
        r#"SELECT title, text, data_source_ref, lifecycle, is_active
                 FROM knowledge_data_item WHERE id = $1"#,
    )
    .bind(item_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let Some(ItemRow {
        title,
        text: body,
        data_source_ref,
        lifecycle,
        is_active,
    }) = row
    else {
        // Deleted between the event and the drain. Treated as a delete rather
        // than ignored: leaving the old chunks would keep a removed article
        // matchable, which is the same disclosure the record index closes.
        let removed = remove_item_chunks(db, item_id).await?;
        return Ok(ReindexStats {
            written: 0,
            removed,
        });
    };

    // A row that is soft-deleted (`is_active = false`), or not published, is
    // not retrievable. Its chunks are removed rather than hidden.
    let live = is_active.unwrap_or(true);
    let published = lifecycle.as_deref() == Some(PUBLISHED);
    let Some(collection_ref) = data_source_ref.filter(|_| live && published) else {
        let removed = remove_item_chunks(db, item_id).await?;
        return Ok(ReindexStats {
            written: 0,
            removed,
        });
    };

    let chunks = chunk_article(&title, body.as_deref().unwrap_or_default());
    let mut tx = attome_db::tx::begin(db).await?;
    let mut stats = ReindexStats::default();

    // Drop ordinals this projection no longer produces (an article that
    // shrank, or whose headings merged). Without this, a truncated article
    // keeps matching on text it no longer contains.
    let ordinals: Vec<i32> = chunks.iter().map(|c| c.ordinal).collect();
    stats.removed = sqlx::query(
        r#"DELETE FROM knowledge_chunk
           WHERE source_type = $1 AND source_id = $2 AND NOT (ordinal = ANY($3))"#,
    )
    .bind(SOURCE_TYPE)
    .bind(item_id)
    .bind(&ordinals)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    for chunk in &chunks {
        let written = sqlx::query(
            r#"INSERT INTO knowledge_chunk
                   (collection_ref, source_type, source_id, parent_entity, parent_record_id,
                    lifecycle, ordinal, heading_path, text_display, text_indexed, tsv,
                    content_hash, indexed_at)
               VALUES ($1, $2, $3, NULL, NULL, $4, $5, $6, $7, $8,
                       to_tsvector('attome_search', $8), $9, NOW())
               ON CONFLICT (source_type, source_id, ordinal) DO UPDATE SET
                   collection_ref = EXCLUDED.collection_ref,
                   lifecycle = EXCLUDED.lifecycle,
                   heading_path = EXCLUDED.heading_path,
                   text_display = EXCLUDED.text_display,
                   text_indexed = EXCLUDED.text_indexed,
                   tsv = EXCLUDED.tsv,
                   content_hash = EXCLUDED.content_hash,
                   embedding = CASE
                       WHEN knowledge_chunk.content_hash IS DISTINCT FROM EXCLUDED.content_hash
                       THEN NULL ELSE knowledge_chunk.embedding END,
                   embedding_model = CASE
                       WHEN knowledge_chunk.content_hash IS DISTINCT FROM EXCLUDED.content_hash
                       THEN NULL ELSE knowledge_chunk.embedding_model END,
                   embedding_locality = CASE
                       WHEN knowledge_chunk.content_hash IS DISTINCT FROM EXCLUDED.content_hash
                       THEN NULL ELSE knowledge_chunk.embedding_locality END,
                   indexed_at = NOW()
               WHERE knowledge_chunk.content_hash IS DISTINCT FROM EXCLUDED.content_hash
                  OR knowledge_chunk.collection_ref IS DISTINCT FROM EXCLUDED.collection_ref"#,
        )
        .bind(collection_ref)
        .bind(SOURCE_TYPE)
        .bind(item_id)
        .bind(PUBLISHED)
        .bind(chunk.ordinal)
        .bind(&chunk.heading_path)
        .bind(&chunk.text_display)
        .bind(&chunk.text_indexed)
        .bind(&chunk.content_hash)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        stats.written += written;
    }

    tx.commit().await.map_err(AppError::internal)?;
    Ok(stats)
}

/// Projects published items that have no chunks at all.
///
/// This is the catch-up path for items published **before** this producer
/// existed, or while no node was draining. It is deliberately keyed on "no
/// chunks" rather than "changed": after the first complete pass it is one
/// indexed anti-join that returns zero rows, and it cannot resurrect a draft —
/// the WHERE clause requires `published`, and `reindex_item` deletes again even
/// if it is handed one.
pub async fn backfill_missing(db: &PgPool, batch: i64) -> Result<u64, AppError> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT i.id FROM knowledge_data_item i
           WHERE (i.is_active IS NULL OR i.is_active = TRUE)
             AND i.lifecycle = $1
             AND NOT EXISTS (
                 SELECT 1 FROM knowledge_chunk k
                 WHERE k.source_type = $2 AND k.source_id = i.id )
           ORDER BY i.created_at ASC
           LIMIT $3"#,
    )
    .bind(PUBLISHED)
    .bind(SOURCE_TYPE)
    .bind(batch)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut done = 0u64;
    for id in ids {
        reindex_item(db, id).await?;
        done += 1;
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entity and collection names are constants, not computed. A drifting
    /// literal here would chunk nothing (the drain arm would never match) and
    /// the failure would look like "search returns nothing", not like a typo.
    #[test]
    fn the_entity_names_match_the_provisioned_bundle() {
        assert_eq!(ITEM_ENTITY, "knowledge_data_item");
        assert_eq!(COLLECTION_ENTITY, "knowledge_data_source");
        assert_eq!(SOURCE_TYPE, "article");
        assert_eq!(PUBLISHED, "published");
    }

    /// The producer's hash gate must also cover the permission anchor. A
    /// hash-only gate skips the rewrite when an item moves between Data
    /// Sources, leaving its chunks readable under the old one — a disclosure
    /// with no symptom.
    #[test]
    fn the_upsert_gate_covers_the_permission_anchor() {
        let source = include_str!("knowledge_index.rs");
        assert!(
            source.contains("content_hash IS DISTINCT FROM EXCLUDED.content_hash"),
            "the no-op write must be prevented by the DO UPDATE's WHERE"
        );
        assert!(
            source.contains("collection_ref IS DISTINCT FROM EXCLUDED.collection_ref"),
            "moving an item between Data Sources must not be skipped by the hash gate"
        );
    }

    /// Un-publishing is a delete, not a filter — the D-489 branch of §14.1.
    /// Asserted structurally because "maintain and filter" is the tempting
    /// refactor and its symptom is a draft that answers a question.
    #[test]
    fn a_non_published_item_has_its_chunks_removed() {
        let source = include_str!("knowledge_index.rs");
        let guard = source
            .find("let Some(collection_ref) = data_source_ref.filter(|_| live && published)")
            .expect("the published guard must be present");
        let remove = source[guard..]
            .find("remove_item_chunks(db, item_id)")
            .expect("a non-published item must have its chunks removed");
        assert!(
            remove < 200,
            "the removal must be the guard's immediate arm"
        );
    }
}
