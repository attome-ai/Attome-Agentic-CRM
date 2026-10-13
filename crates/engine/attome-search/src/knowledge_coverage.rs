//! The knowledge operator's coverage read (chatbot plan C8).
//!
//! **This is index health, not retrieval quality.** [`crate::coverage`] scores
//! whether an evaluation corpus retrieves the evidence an answer needs; this
//! module answers the operator's plainer question — per Knowledge Base
//! collection, what is published, what is chunked, when it was last indexed,
//! and how much is still waiting for a vector.
//!
//! ## Every number is a count of what is there, never a projection
//!
//! - **Items** are the collection's live `knowledge_data_item` rows by
//!   lifecycle. Only `published` items are ever chunked (D-489's "absent, not
//!   filtered" branch), so a draft count is exactly the work the review queue
//!   has not done yet.
//! - **Chunks** are the collection's `published` chunk rows, and
//!   `last_indexed_at` is the newest `indexed_at` among them — the last time a
//!   projection actually *wrote* one. The hash gate skips unchanged content, so
//!   an old timestamp on a quiet collection is correct, not stale. The drain's
//!   own heartbeat is [`IndexerStatus::drain_last_advanced_at`].
//! - **The embedding backlog** is relative to the model the embedding writer
//!   uses (`crate::scheduler`), because retrieval's vector leg reads only that
//!   model's vectors: a chunk embedded by a previous model is backlog too. When
//!   no model is configured, or semantic search is switched off, there is no
//!   backlog to report — knowledge is lexical-only by configuration — and the
//!   field is `None` rather than a count that could never drain.
//!
//! Admin-only at the route, for the same reason as the gap queue: it reads
//! every collection, which no reader-scoped caller may do.

use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::knowledge_index::{COLLECTION_ENTITY, ITEM_ENTITY, PUBLISHED};

/// One collection's coverage.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CollectionCoverage {
    pub collection_id: Uuid,
    pub name: Option<String>,
    /// Live items in the collection, whatever their lifecycle.
    pub items_total: i64,
    pub items_published: i64,
    /// Items waiting in the draft review queue. Never chunked (D-489).
    pub items_draft: i64,
    pub items_expired: i64,
    /// Retrievable (`published`) chunk rows.
    pub chunks: i64,
    /// The newest `indexed_at` among those chunks; `None` when there are none.
    pub last_indexed_at: Option<DateTime<Utc>>,
    /// Chunks carrying a vector from the configured model. `None` when
    /// knowledge is lexical-only by configuration.
    pub chunks_embedded: Option<i64>,
    /// Chunks still waiting for a vector from the configured model (never
    /// embedded, or embedded by a different one). `None` when knowledge is
    /// lexical-only by configuration.
    pub embedding_backlog: Option<i64>,
}

/// The indexer's own state, shared by every collection.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IndexerStatus {
    /// When the search drain last advanced its cursor over the change feed —
    /// the last time it processed any entity write, knowledge or not (or,
    /// before its first event, when it first started). `None` when no drain
    /// has ever started.
    pub drain_last_advanced_at: Option<DateTime<Utc>>,
    /// The model chunk vectors are written with, or `None` when knowledge is
    /// lexical-only by configuration.
    pub embedding_model: Option<String>,
}

#[derive(sqlx::FromRow)]
struct CoverageRow {
    id: Uuid,
    name: Option<String>,
    items_total: i64,
    items_published: i64,
    items_draft: i64,
    items_expired: i64,
    chunks: i64,
    last_indexed_at: Option<DateTime<Utc>>,
    chunks_embedded: i64,
}

/// Whether the Knowledge Base entities exist. They are runtime-provisioned by
/// the `attome-webcrawl` bundle, so a deployment without it has no collections —
/// an empty page, not an error.
async fn knowledge_base_provisioned(db: &PgPool) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL AND to_regclass($2) IS NOT NULL")
        .bind(COLLECTION_ENTITY)
        .bind(ITEM_ENTITY)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// One page of live collections, by name, with their coverage.
///
/// `embedding_model` is the writer's model ([`IndexerStatus::embedding_model`]),
/// passed in rather than read here so the engine stays free of configuration.
pub async fn collection_coverage(
    db: &PgPool,
    embedding_model: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<CollectionCoverage>, i64), AppError> {
    if !knowledge_base_provisioned(db).await? {
        return Ok((Vec::new(), 0));
    }

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM knowledge_data_source WHERE is_active")
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;

    // Each lateral aggregate returns exactly one row, so no collection drops
    // out for having no items or no chunks. The chunk aggregate is served by
    // `knowledge_chunk_published_idx (collection_ref) WHERE lifecycle =
    // 'published'`.
    let rows: Vec<CoverageRow> = sqlx::query_as(
        r#"SELECT s.id, s.name,
                  i.items_total, i.items_published, i.items_draft, i.items_expired,
                  k.chunks, k.last_indexed_at, k.chunks_embedded
             FROM knowledge_data_source s
             CROSS JOIN LATERAL (
                 SELECT COUNT(*)                                        AS items_total,
                        COUNT(*) FILTER (WHERE it.lifecycle = $1)       AS items_published,
                        COUNT(*) FILTER (WHERE it.lifecycle = 'draft')   AS items_draft,
                        COUNT(*) FILTER (WHERE it.lifecycle = 'expired') AS items_expired
                   FROM knowledge_data_item it
                  WHERE it.data_source_ref = s.id AND it.is_active
             ) i
             CROSS JOIN LATERAL (
                 SELECT COUNT(*)                                        AS chunks,
                        MAX(c.indexed_at)                               AS last_indexed_at,
                        COUNT(*) FILTER (WHERE c.embedding IS NOT NULL
                                           AND c.embedding_model = $2)  AS chunks_embedded
                   FROM knowledge_chunk c
                  WHERE c.collection_ref = s.id AND c.lifecycle = $1
             ) k
            WHERE s.is_active
            ORDER BY s.name NULLS LAST, s.id
            LIMIT $3 OFFSET $4"#,
    )
    .bind(PUBLISHED)
    .bind(embedding_model)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|r| {
            let embedded = embedding_model.map(|_| r.chunks_embedded);
            CollectionCoverage {
                collection_id: r.id,
                name: r.name,
                items_total: r.items_total,
                items_published: r.items_published,
                items_draft: r.items_draft,
                items_expired: r.items_expired,
                chunks: r.chunks,
                last_indexed_at: r.last_indexed_at,
                chunks_embedded: embedded,
                embedding_backlog: embedded.map(|e| r.chunks - e),
            }
        })
        .collect();
    Ok((items, total))
}

/// The drain's last cursor advance and the configured embedding model.
pub async fn indexer_status(
    db: &PgPool,
    embedding_model: Option<&str>,
) -> Result<IndexerStatus, AppError> {
    let drain_last_advanced_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT updated_at FROM change_consumer_cursor WHERE consumer = $1")
            .bind(crate::drain::CONSUMER)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(IndexerStatus {
        drain_last_advanced_at,
        embedding_model: embedding_model.map(str::to_owned),
    })
}
