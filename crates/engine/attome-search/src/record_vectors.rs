//! N16-T1: searching records by meaning.
//!
//! For the entities named in the setting [`SETTING`] (none by default), each
//! record's index row (`search_index`, the drain's projection: its title,
//! subtitle and indexed field values) is embedded with the deployment's
//! local embedding model into `search_index.embedding` (`halfvec(1024)`, with
//! its HNSW index). Global search then adds a dense leg, [`VectorLeg`], to the
//! hybrid route's fused statement: the records nearest the query's own
//! embedding, scored `1 - cosine distance` and fused by RRF with the exact,
//! prefix and lexical legs, under the same visibility fragment as every leg.
//!
//! ## Writing vectors
//!
//! [`embed_pending_records`] works like the knowledge writer
//! (`embedding_writer`): it reads rows with no vector, or one from another
//! model, embeds them in one model call outside any transaction, and writes
//! each vector only if the row's content hash is still the one read. The
//! drain clears a row's vector when its content changes, so a changed record
//! is embedded again on a later pass. A model that fails leaves rows
//! lexical-only for the next pass. Locality is always `local` (D-506).
//!
//! ## Reading
//!
//! The leg takes the [`CANDIDATES`] nearest rows of the configured entities
//! (an index-ordered scan) and only then applies the caller's visibility, so a
//! narrowly scoped caller may see fewer semantic matches than exist; the
//! lexical legs are unaffected. A query that cannot be embedded (no model,
//! semantic search switched off, a model error) runs without the leg.

use attome_core::EngineState;
use attome_inference::{EmbedKind, EmbeddingClient};
use attome_types::AppError;
use sqlx::{PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

use crate::embedding_writer::{EmbedStats, LOCALITY_LOCAL, vector_literal};
use crate::legs::{LegPhase, SqlLeg};

/// The setting naming the entities whose records are embedded.
pub const SETTING: &str = "search.semantic_entities";

/// Nearest rows the leg takes before visibility.
pub const CANDIDATES: i64 = 400;

/// Characters of a record's text embedded; the rest is left out.
pub const MAX_TEXT_CHARS: usize = 2_000;

/// How long a query's embedding may take before the search goes on without
/// the leg.
pub const QUERY_EMBED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// The entities named in [`SETTING`]; empty when unset.
pub fn configured_entities(state: &EngineState) -> Vec<String> {
    let store = state.settings.load();
    attome_core::setting_registry()
        .get(SETTING)
        .map(|d| store.resolve(d, None, None).0)
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

/// The text embedded for one record: its title, subtitle and indexed
/// values, blank parts left out, cut to [`MAX_TEXT_CHARS`]. Pure.
pub fn record_text(title: Option<&str>, subtitle: Option<&str>, body: Option<&str>) -> String {
    let parts: Vec<&str> = [title, subtitle, body]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    parts.join("\n").chars().take(MAX_TEXT_CHARS).collect()
}

type PendingRow = (
    String,
    String,
    Uuid,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Embeds up to `batch` index rows of `entities` that lack a vector from
/// `client`'s model. One model call per pass.
pub async fn embed_pending_records(
    db: &PgPool,
    client: &EmbeddingClient,
    entities: &[String],
    batch: i64,
) -> Result<EmbedStats, AppError> {
    if entities.is_empty() {
        return Ok(EmbedStats::default());
    }
    let model = client.model_id();
    let pending: Vec<PendingRow> = sqlx::query_as(
        "SELECT t.corpus, t.entity_logicalname, t.record_id, t.content_hash, \
                t.title, t.subtitle, t.body_display \
           FROM search_index t \
          WHERE t.entity_logicalname = ANY($1) \
            AND (t.embedding IS NULL OR t.embedding_model IS DISTINCT FROM $2) \
          ORDER BY t.entity_logicalname, t.record_id \
          LIMIT $3",
    )
    .bind(entities)
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
        .map(|(_, entity, _, _, title, subtitle, body)| {
            let text = record_text(title.as_deref(), subtitle.as_deref(), body.as_deref());
            // A model refuses empty input; a record with no text is its kind.
            if text.is_empty() {
                entity.clone()
            } else {
                text
            }
        })
        .collect();
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let (vectors, _usage) = client
        .embed(&refs, EmbedKind::Document)
        .await
        .map_err(|e| AppError::internal(format!("record embedding request failed: {e}")))?;
    let literals = vectors
        .iter()
        .map(|v| vector_literal(v))
        .collect::<Result<Vec<String>, AppError>>()?;
    let corpora: Vec<String> = pending.iter().map(|r| r.0.clone()).collect();
    let names: Vec<String> = pending.iter().map(|r| r.1.clone()).collect();
    let ids: Vec<Uuid> = pending.iter().map(|r| r.2).collect();
    let hashes: Vec<Option<Vec<u8>>> = pending.iter().map(|r| r.3.clone()).collect();
    // No transaction across the model call; the content hash is the race
    // guard, as in the knowledge writer.
    let written = sqlx::query(
        "UPDATE search_index t \
            SET embedding = u.embedding::halfvec, \
                embedding_model = $6, \
                embedding_locality = $7 \
           FROM unnest($1::text[], $2::text[], $3::uuid[], $4::text[], $5::bytea[]) \
                AS u(corpus, entity_logicalname, record_id, embedding, content_hash) \
          WHERE t.corpus = u.corpus \
            AND t.entity_logicalname = u.entity_logicalname \
            AND t.record_id = u.record_id \
            AND t.content_hash IS NOT DISTINCT FROM u.content_hash",
    )
    .bind(&corpora)
    .bind(&names)
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

/// The dense leg: the configured entities' records nearest the query.
pub struct VectorLeg {
    /// The query's embedding, as a pgvector literal.
    pub vector_literal: String,
    pub entities: Vec<String>,
}

impl std::fmt::Debug for VectorLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VectorLeg").finish_non_exhaustive()
    }
}

impl SqlLeg for VectorLeg {
    fn id(&self) -> &'static str {
        "R4.vector"
    }
    fn phase(&self) -> LegPhase {
        LegPhase::Immediate
    }
    fn push_candidates(&self, qb: &mut QueryBuilder<'_, Postgres>) {
        // The inner query orders by the distance itself so the HNSW index
        // serves it; the outer one carries the columns the visibility
        // fragment reads, under the alias every leg uses.
        qb.push(
            "SELECT t.record_id, t.entity_logicalname, (1 - t.distance)::real AS score \
             FROM (SELECT s.record_id, s.entity_logicalname, s.organization_ref, \
                          s.embedding <=> ",
        );
        qb.push_bind(self.vector_literal.clone());
        qb.push("::halfvec AS distance FROM search_index s WHERE s.embedding IS NOT NULL AND s.entity_logicalname = ANY(");
        qb.push_bind(self.entities.clone());
        qb.push("::text[]) ORDER BY s.embedding <=> ");
        qb.push_bind(self.vector_literal.clone());
        qb.push("::halfvec LIMIT ");
        qb.push_bind(CANDIDATES);
        qb.push(") t WHERE t.distance IS NOT NULL");
    }
}

/// The leg for `query`, when entities are configured and the query can be
/// embedded in time; `None` otherwise, and the search runs without it.
pub async fn query_leg(state: &EngineState, query: &str) -> Option<VectorLeg> {
    let entities = configured_entities(state);
    if entities.is_empty() || query.trim().is_empty() {
        return None;
    }
    if !attome_core::ai_runtime_switch::allows(
        &state.base.config.inference.ai,
        attome_config::AiSurface::SemanticSearch,
    ) {
        return None;
    }
    let client = crate::knowledge::ranking_embedder()?;
    let embedded = tokio::time::timeout(
        QUERY_EMBED_TIMEOUT,
        client.embed(&[query], EmbedKind::Query),
    )
    .await;
    let vector = match embedded {
        Ok(Ok((mut vectors, _))) if !vectors.is_empty() => vectors.swap_remove(0),
        Ok(Ok(_)) => return None,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "search: the query could not be embedded; no semantic leg");
            return None;
        }
        Err(_) => {
            tracing::warn!("search: the query embedding timed out; no semantic leg");
            return None;
        }
    };
    match vector_literal(&vector) {
        Ok(vector_literal) => Some(VectorLeg {
            vector_literal,
            entities,
        }),
        Err(e) => {
            tracing::warn!(error = %e, "search: the query embedding is unusable; no semantic leg");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_vectors_text_joins_the_parts_and_skips_blanks() {
        assert_eq!(
            record_text(Some("Acme"), Some(" "), Some("Riyadh, steel")),
            "Acme\nRiyadh, steel"
        );
        assert_eq!(record_text(None, None, None), "");
        let long = "x".repeat(MAX_TEXT_CHARS + 50);
        assert_eq!(
            record_text(Some(&long), None, None).chars().count(),
            MAX_TEXT_CHARS
        );
    }

    #[test]
    fn record_vectors_leg_orders_by_distance_inside_and_keeps_visibility_columns() {
        let leg = VectorLeg {
            vector_literal: "[0.1]".into(),
            entities: vec!["account".into()],
        };
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("");
        leg.push_candidates(&mut qb);
        let sql = qb.into_sql();
        assert!(sql.contains("ORDER BY s.embedding <=> $"), "{sql}");
        assert!(sql.contains("s.organization_ref"), "{sql}");
        assert!(sql.contains(") t WHERE "), "{sql}");
        assert_eq!(leg.id(), "R4.vector");
        assert_eq!(leg.phase(), LegPhase::Immediate);
    }
}
