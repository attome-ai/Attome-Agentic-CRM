//! N15-T2: records, timelines and documents as retrievable passages.
//!
//! The record index (`search_index`, one row per record) finds a record; it
//! cannot hand an answer the paragraph that answers it. This source chunks
//! what a record says at length: a long text or rich-text field, a timeline
//! item (note, communication, activity) and a document's extracted text. It
//! uses the knowledge chunker (`chunk_article`), so splits fall on headings,
//! then paragraphs, then sentences. Each field becomes a section headed by
//! its name, so a passage carries where in the record it came from.
//!
//! ## Its own change-feed consumer
//!
//! [`CONSUMER`] reads `entity_change_event` through its own cursor (Y7,
//! D-358), beside the record drain and on the same tick, so a changed record
//! is re-chunked within the drain interval. A source whose chunks did not
//! change is not rewritten (content hash per chunk). A chunk whose text
//! changed has its vector cleared, and [`embed_pending`] fills it in outside
//! any transaction. A source that is gone, deactivated or no longer long
//! enough has its chunks removed; a purge removes them too.
//!
//! ## Access
//!
//! A chunk keeps the record it came from (`source_entity`, `source_id`). It
//! also keeps the record it belongs to (`entity_logicalname`, `record_id`):
//! the source itself, or for a timeline item the record it is attached to.
//! A reader must pass **both** record checks, as the record API does for a
//! polymorphic child (B-R1): attaching a note to a visible record does not
//! make the note visible. Sensitive attributes are never chunked, as never
//! indexed (S3).

use attome_core::change_feed::{self, ChangeOperation};
use attome_core::sql_ident::quote_ident;
use attome_core::{AttrInfo, EntityMetaRegistry};
use attome_types::AppError;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::knowledge::{ArticleChunk, chunk_article};
use super::{DOCUMENT_ENTITY, POLYMORPHIC_CHILD_ENTITIES, index_value, indexable_attributes};

/// This consumer's cursor name.
pub const CONSUMER: &str = "attome-search/record-chunks";

/// Events one pass reads.
pub const BATCH: i64 = 200;

/// A field shorter than this is left to the record index; chunking a short
/// value only adds a near-duplicate passage.
pub const MIN_FIELD_CHARS: usize = 400;

/// What one pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ChunkStats {
    pub read: u64,
    pub written: u64,
    pub removed: u64,
}

/// The chunker's input for a record: each long field as a section headed by
/// its name, in attribute order.
pub fn record_body(sections: &[(String, String)]) -> String {
    sections
        .iter()
        .map(|(name, text)| format!("## {name}\n\n{}", text.trim()))
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// The long sections of a record: its indexable fields of at least
/// [`MIN_FIELD_CHARS`], and a document's text.
pub fn long_sections(values: Vec<(String, String)>) -> Vec<(String, String)> {
    values
        .into_iter()
        .filter(|(_, text)| text.trim().chars().count() >= MIN_FIELD_CHARS)
        .collect()
}

/// The record a timeline item belongs to, from its `entity_name` and
/// `record_id` pair.
fn owner_of(row: &sqlx::postgres::PgRow) -> Option<(String, Uuid)> {
    let entity: Option<String> = row.try_get("entity_name").ok().flatten();
    let record: Option<Uuid> = row
        .try_get::<Option<Uuid>, _>("record_id")
        .ok()
        .flatten()
        .or_else(|| {
            row.try_get::<Option<String>, _>("record_id")
                .ok()
                .flatten()
                .and_then(|s| Uuid::parse_str(&s).ok())
        });
    Some((entity.filter(|e| !e.is_empty())?, record?))
}

/// Removes every chunk of a source.
pub async fn remove_source(db: &PgPool, entity: &str, id: Uuid) -> Result<u64, AppError> {
    sqlx::query("DELETE FROM record_chunk WHERE source_entity = $1 AND source_id = $2")
        .bind(entity)
        .bind(id)
        .execute(db)
        .await
        .map_err(AppError::internal)
        .map(|r| r.rows_affected())
}

/// Re-chunks one source from its current row; (written, removed).
pub async fn reindex_source(
    db: &PgPool,
    registry: &EntityMetaRegistry,
    entity: &str,
    id: Uuid,
) -> Result<(u64, u64), AppError> {
    let Some(meta) = registry.get(entity) else {
        return Ok((0, remove_source(db, entity, id).await?));
    };
    let indexable: Vec<&AttrInfo> = indexable_attributes(&meta.attrs);
    let is_child = POLYMORPHIC_CHILD_ENTITIES.contains(&entity);
    let mut columns: Vec<String> = indexable
        .iter()
        .map(|a| {
            format!(
                "{}::text AS {}",
                quote_ident(&a.logicalname),
                quote_ident(&a.logicalname)
            )
        })
        .collect();
    if is_child {
        columns.push("entity_name::text AS entity_name".into());
        columns.push("record_id".into());
    }
    if columns.is_empty() && entity != DOCUMENT_ENTITY {
        return Ok((0, remove_source(db, entity, id).await?));
    }
    columns.push("id".into());
    let sql = format!(
        "SELECT {} FROM {} WHERE id = $1 AND is_active = true",
        columns.join(", "),
        quote_ident(entity)
    );
    let Some(row) = sqlx::query(&sql)
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
    else {
        return Ok((0, remove_source(db, entity, id).await?));
    };
    let owner = if is_child {
        match owner_of(&row) {
            Some(owner) => owner,
            None => return Ok((0, remove_source(db, entity, id).await?)),
        }
    } else {
        (entity.to_owned(), id)
    };
    let mut values: Vec<(String, String)> = indexable
        .iter()
        .filter_map(|a| {
            let raw: Option<String> = row.try_get(a.logicalname.as_str()).ok().flatten();
            raw.map(|v| (a.logicalname.clone(), index_value(a, v)))
        })
        .collect();
    if entity == DOCUMENT_ENTITY {
        let text: Option<String> = sqlx::query_scalar(
            "SELECT t.content_text FROM attome_document d \
               JOIN document_text t ON t.file_key = d.file WHERE d.id = $1",
        )
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        if let Some(text) = text {
            values.push(("content".to_owned(), text));
        }
    }
    let sections = long_sections(values);
    if sections.is_empty() {
        return Ok((0, remove_source(db, entity, id).await?));
    }
    let title = meta
        .primary_name_attribute
        .as_deref()
        .and_then(|p| row.try_get::<Option<String>, _>(p).ok().flatten())
        .unwrap_or_else(|| entity.to_owned());
    let chunks = chunk_article(&title, &record_body(&sections));
    write_chunks(db, entity, id, &owner, &chunks).await
}

/// Upserts `chunks` for a source and removes the ones past the new end, in
/// one short transaction. A chunk whose text is unchanged is not rewritten;
/// one whose text changed loses its vector.
async fn write_chunks(
    db: &PgPool,
    entity: &str,
    id: Uuid,
    owner: &(String, Uuid),
    chunks: &[ArticleChunk],
) -> Result<(u64, u64), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let mut written = 0;
    for chunk in chunks {
        written += sqlx::query(
            "INSERT INTO record_chunk \
                 (entity_logicalname, record_id, source_entity, source_id, ordinal, heading_path, \
                  text_display, tsv, content_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, to_tsvector('attome_search', $8), $9) \
             ON CONFLICT (source_entity, source_id, ordinal) DO UPDATE SET \
                 entity_logicalname = EXCLUDED.entity_logicalname, \
                 record_id = EXCLUDED.record_id, \
                 heading_path = EXCLUDED.heading_path, \
                 text_display = EXCLUDED.text_display, \
                 tsv = EXCLUDED.tsv, \
                 content_hash = EXCLUDED.content_hash, \
                 embedding = NULL, embedding_model = NULL, embedding_locality = NULL, \
                 indexed_at = now() \
             WHERE record_chunk.content_hash IS DISTINCT FROM EXCLUDED.content_hash \
                OR record_chunk.record_id IS DISTINCT FROM EXCLUDED.record_id",
        )
        .bind(&owner.0)
        .bind(owner.1)
        .bind(entity)
        .bind(id)
        .bind(chunk.ordinal)
        .bind(&chunk.heading_path)
        .bind(&chunk.text_display)
        .bind(&chunk.text_indexed)
        .bind(&chunk.content_hash)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    }
    let removed = sqlx::query(
        "DELETE FROM record_chunk WHERE source_entity = $1 AND source_id = $2 AND ordinal >= $3",
    )
    .bind(entity)
    .bind(id)
    .bind(i32::try_from(chunks.len()).unwrap_or(i32::MAX))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    attome_db::tx::commit(tx).await?;
    Ok((written, removed))
}

/// One pass over the change feed: re-chunk every changed source.
pub async fn drain_once(
    db: &PgPool,
    registry: &EntityMetaRegistry,
) -> Result<ChunkStats, AppError> {
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let batch = change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?;
    let mut stats = ChunkStats {
        read: batch.len() as u64,
        ..ChunkStats::default()
    };
    for event in &batch {
        match event.operation() {
            Some(ChangeOperation::Create | ChangeOperation::Update | ChangeOperation::Restore) => {
                let (written, removed) =
                    reindex_source(db, registry, &event.entity_logicalname, event.record_id)
                        .await?;
                stats.written += written;
                stats.removed += removed;
            }
            Some(ChangeOperation::Delete | ChangeOperation::Purge) => {
                stats.removed +=
                    remove_source(db, &event.entity_logicalname, event.record_id).await?;
            }
            None => {}
        }
        change_feed::advance(&mut conn, CONSUMER, event).await?;
    }
    Ok(stats)
}

type PendingChunk = (Uuid, Option<Vec<u8>>, String, Vec<String>, String);

/// Embeds up to `batch` chunks that lack a vector from `client`'s model,
/// as the knowledge embedding pass does; the vectors written.
pub async fn embed_pending(
    db: &PgPool,
    client: &attome_inference::EmbeddingClient,
    batch: i64,
) -> Result<u64, AppError> {
    use crate::embedding_writer::{LOCALITY_LOCAL, embedding_text, vector_literal};
    let model = client.model_id();
    let pending: Vec<PendingChunk> = sqlx::query_as(
        "SELECT id, content_hash, source_entity, heading_path, text_display FROM record_chunk \
          WHERE embedding IS NULL OR embedding_model IS DISTINCT FROM $1 \
          ORDER BY id LIMIT $2",
    )
    .bind(model)
    .bind(batch)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if pending.is_empty() {
        return Ok(0);
    }
    let texts: Vec<String> = pending
        .iter()
        .map(|(_, _, entity, path, text)| embedding_text(entity, path, text))
        .collect();
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let (vectors, _usage) = client
        .embed(&refs, attome_inference::EmbedKind::Document)
        .await
        .map_err(|e| AppError::internal(format!("record chunk embedding request failed: {e}")))?;
    let literals = vectors
        .iter()
        .map(|v| vector_literal(v))
        .collect::<Result<Vec<String>, AppError>>()?;
    let ids: Vec<Uuid> = pending.iter().map(|(id, ..)| *id).collect();
    let hashes: Vec<Option<Vec<u8>>> = pending.iter().map(|(_, hash, ..)| hash.clone()).collect();
    sqlx::query(
        "UPDATE record_chunk c \
            SET embedding = u.embedding::halfvec, embedding_model = $4, embedding_locality = $5 \
           FROM unnest($1::uuid[], $2::text[], $3::bytea[]) AS u(id, embedding, content_hash) \
          WHERE c.id = u.id AND c.content_hash IS NOT DISTINCT FROM u.content_hash",
    )
    .bind(&ids)
    .bind(&literals)
    .bind(&hashes)
    .bind(model)
    .bind(LOCALITY_LOCAL)
    .execute(db)
    .await
    .map_err(AppError::internal)
    .map(|r| r.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_feed_chunks_long_fields_as_sections() {
        let long = "The customer asked for a phased rollout. ".repeat(20);
        let sections = long_sections(vec![
            ("subject".into(), "Short".into()),
            ("description".into(), long.clone()),
        ]);
        assert_eq!(
            sections.len(),
            1,
            "a short field is left to the record index"
        );
        let body = record_body(&sections);
        assert!(body.starts_with("## description\n\n"));
        let chunks = chunk_article("Renewal", &body);
        assert!(!chunks.is_empty());
        assert!(
            chunks
                .iter()
                .all(|c| c.heading_path.iter().any(|h| h == "description")),
            "every passage knows the field it came from"
        );
    }

    #[test]
    fn corpus_feed_consumer_has_its_own_cursor() {
        assert_eq!(CONSUMER, "attome-search/record-chunks");
        assert_ne!(CONSUMER, crate::drain::CONSUMER);
    }
}
