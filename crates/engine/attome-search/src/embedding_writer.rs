//! The knowledge embedding writer (D-498 step 5; D-506, local-only phase).
//!
//! ## A separate pass, not part of `reindex_item`
//!
//! `reindex_item` runs inside the drain, one event at a time, with a
//! transaction open for its upsert. An embedding is a network call to a model
//! server. Guidelines §10 keep external I/O out of transactions, and a slow or
//! absent model must not hold up lexical indexing. So the chunk producer writes
//! text and clears a stale vector when a chunk's text changes, and this pass
//! fills vectors in afterwards from the table's own state.
//!
//! ## Idempotent and race-safe
//!
//! A pass selects published chunks whose vector is missing or was produced by
//! a different model, embeds them in one batch, and writes each vector only if
//! the chunk's content hash still matches what was read. A chunk edited between
//! the read and the write keeps its empty vector for the next pass, so a vector
//! can never describe text the chunk no longer holds.
//!
//! ## Failure leaves lexical search intact
//!
//! An unreachable or misbehaving model fails the pass with an error for the
//! caller to log; the chunks stay lexical-only and the next pass retries.
//! Nothing here reads or changes a chunk's text, lifecycle or permissions.
//!
//! ## Provenance
//!
//! Every written vector records the model that produced it and
//! `embedding_locality = 'local'` (D-506 §4, migration 0465). External
//! embedding is refused at boot and in the client until D-506's administrator
//! opt-in exists, so `local` is the only value this pass writes.

use attome_inference::{EmbedKind, EmbeddingClient};
use attome_types::AppError;
use sqlx::PgPool;
use uuid::Uuid;

/// Chunks embedded per model call.
pub const EMBED_BATCH: i64 = 32;

/// The vector width `knowledge_chunk.embedding` stores (`halfvec(1024)`,
/// migration 0122).
pub const EMBEDDING_DIM: usize = 1024;

/// The only locality this pass writes (D-506, local-only phase).
pub const LOCALITY_LOCAL: &str = "local";

/// What one pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmbedStats {
    /// Chunks read that needed a vector.
    pub selected: u64,
    /// Vectors written.
    pub embedded: u64,
    /// Chunks whose text changed between the read and the write.
    pub skipped_changed: u64,
}

/// The text embedded for one chunk: the article title, its section's heading
/// path, and the passage.
///
/// The title and headings are included for the same reason `chunk_article`
/// prepends them to the lexical index: a passage from the middle of an article
/// otherwise carries no signal about which document or section it belongs to.
pub fn embedding_text(title: &str, heading_path: &[String], text: &str) -> String {
    if heading_path.is_empty() {
        format!("{title}\n\n{text}")
    } else {
        format!("{title}\n{}\n\n{text}", heading_path.join(" > "))
    }
}

/// A pgvector literal (`[0.1,0.2,…]`) for one vector, or an error when the
/// model returned the wrong width or a non-finite value.
///
/// Bound as text and cast in SQL: the workspace carries no pgvector Rust type,
/// and a literal is the representation pgvector itself parses.
pub fn vector_literal(vector: &[f32]) -> Result<String, AppError> {
    if vector.len() != EMBEDDING_DIM {
        return Err(AppError::internal(format!(
            "the embedding model returned {} dimensions; the knowledge index stores {EMBEDDING_DIM}",
            vector.len()
        )));
    }
    if vector.iter().any(|v| !v.is_finite()) {
        return Err(AppError::internal(
            "the embedding model returned a non-finite value",
        ));
    }
    let values: Vec<String> = vector.iter().map(|v| v.to_string()).collect();
    Ok(format!("[{}]", values.join(",")))
}

type PendingChunk = (Uuid, Option<Vec<u8>>, String, Vec<String>, String);

/// Embeds up to `batch` published chunks that lack a vector from `client`'s
/// model. One model call per pass; returns what it did.
pub async fn embed_pending_chunks(
    db: &PgPool,
    client: &EmbeddingClient,
    batch: i64,
) -> Result<EmbedStats, AppError> {
    let model = client.model_id();
    let pending: Vec<PendingChunk> = sqlx::query_as(
        r#"SELECT k.id, k.content_hash, i.title, k.heading_path, k.text_display
             FROM knowledge_chunk k
             JOIN knowledge_data_item i ON i.id = k.source_id
            WHERE k.source_type = $1
              AND k.lifecycle = $2
              AND (k.embedding IS NULL OR k.embedding_model IS DISTINCT FROM $3)
            ORDER BY k.id
            LIMIT $4"#,
    )
    .bind(crate::knowledge_index::SOURCE_TYPE)
    .bind(crate::knowledge_index::PUBLISHED)
    .bind(model)
    .bind(batch)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut stats = EmbedStats {
        selected: pending.len() as u64,
        ..EmbedStats::default()
    };
    if pending.is_empty() {
        return Ok(stats);
    }

    let texts: Vec<String> = pending
        .iter()
        .map(|(_, _, title, path, text)| embedding_text(title, path, text))
        .collect();
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let (vectors, _usage) = client
        .embed(&refs, EmbedKind::Document)
        .await
        .map_err(|e| AppError::internal(format!("knowledge embedding request failed: {e}")))?;

    let literals = vectors
        .iter()
        .map(|v| vector_literal(v))
        .collect::<Result<Vec<String>, AppError>>()?;
    let ids: Vec<Uuid> = pending.iter().map(|(id, ..)| *id).collect();
    let hashes: Vec<Option<Vec<u8>>> = pending.iter().map(|(_, hash, ..)| hash.clone()).collect();

    // One statement, no transaction held across the model call above. The
    // content-hash match is the race guard: a chunk rewritten since it was
    // read is left for the next pass.
    let written = sqlx::query(
        r#"UPDATE knowledge_chunk k
              SET embedding = u.embedding::halfvec,
                  embedding_model = $4,
                  embedding_locality = $5
             FROM unnest($1::uuid[], $2::text[], $3::bytea[]) AS u(id, embedding, content_hash)
            WHERE k.id = u.id
              AND k.content_hash IS NOT DISTINCT FROM u.content_hash"#,
    )
    .bind(&ids)
    .bind(&literals)
    .bind(&hashes)
    .bind(model)
    .bind(LOCALITY_LOCAL)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    stats.embedded = written;
    stats.skipped_changed = stats.selected.saturating_sub(written);
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_text_carries_the_title_and_heading_path() {
        assert_eq!(
            embedding_text("Leave", &["Annual Leave".into()], "Thirty days."),
            "Leave\nAnnual Leave\n\nThirty days."
        );
        assert_eq!(
            embedding_text("Leave", &["Refunds".into(), "Exceptions".into()], "x"),
            "Leave\nRefunds > Exceptions\n\nx"
        );
        assert_eq!(embedding_text("Leave", &[], "Intro."), "Leave\n\nIntro.");
    }

    #[test]
    fn a_vector_of_the_stored_width_becomes_a_pgvector_literal() {
        let literal = vector_literal(&vec![0.5; EMBEDDING_DIM]).expect("valid width");
        assert!(literal.starts_with("[0.5,0.5,") && literal.ends_with("0.5]"));
        assert_eq!(literal.matches(',').count(), EMBEDDING_DIM - 1);
    }

    /// A model with a different width must never write into the index: a
    /// 768-dimension vector cast into `halfvec(1024)` is an error at best and a
    /// silently wrong index at worst.
    #[test]
    fn a_vector_of_the_wrong_width_or_with_a_non_finite_value_is_refused() {
        assert!(vector_literal(&vec![0.5; 768]).is_err());
        let mut bad = vec![0.5; EMBEDDING_DIM];
        bad[3] = f32::NAN;
        assert!(vector_literal(&bad).is_err());
    }
}
