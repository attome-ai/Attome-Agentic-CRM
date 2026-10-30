//! A25-T6 (V2-D1429): image search with an image-text model (SigLIP 2,
//! `inference.image_embedding`).
//!
//! **Indexing.** On the node that holds the drain lock, each tick embeds up
//! to [`IMAGE_PASSES`] × [`IMAGE_BATCH`] image files: a live document's clean
//! upload of a PNG, JPEG, WebP or GIF of at most 5 MB, attached to a record
//! of an entity whose search setting `image_embedding` is on. A file on a
//! field labelled sensitive is never sent to the model; it, and a file the
//! model cannot take, gets a row with no vector and the reason, so it is not
//! tried again until the document names another file. Rows are keyed by
//! document, file and model: a new model re-embeds everything.
//!
//! **Search.** [`nearest_images`] compares a vector with the configured
//! model's vectors of the same size and keeps the images whose record the
//! caller may read, by the record's search index row and the same visibility
//! fragment as passage search, before any is returned.

use std::sync::OnceLock;

use attome_core::EngineState;
use attome_inference::image_embed::{self, ImageEmbeddingClient, Modality};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

use crate::corpus::document_attachment;

/// Image files embedded in one model call.
pub const IMAGE_BATCH: usize = 8;
/// Batches embedded per drain tick.
pub const IMAGE_PASSES: usize = 4;
/// The largest image file embedded.
pub const MAX_IMAGE_BYTES: i64 = image_embed::MAX_IMAGE_BYTES as i64;
/// Nearest images read before visibility.
const CANDIDATES: i64 = 400;

static CLIENT: OnceLock<Option<ImageEmbeddingClient>> = OnceLock::new();

/// The image embedding client, when `inference.image_embedding` names one and
/// semantic search is on. Built once per process.
pub fn image_embedder(state: &EngineState) -> Option<&'static ImageEmbeddingClient> {
    CLIENT
        .get_or_init(|| {
            let inference = &state.base.config.inference;
            if inference.image_embedding.base_url.trim().is_empty()
                || !inference
                    .ai
                    .allows(attome_config::AiSurface::SemanticSearch)
            {
                return None;
            }
            match ImageEmbeddingClient::new(inference) {
                Ok(client) => {
                    tracing::info!(model = client.model_id(), "image search enabled");
                    Some(client)
                }
                Err(error) => {
                    tracing::error!(%error, "the image embedding client could not be built; image search is off");
                    None
                }
            }
        })
        .as_ref()
}

/// `[v1,v2,…]`, the pgvector text form, for a vector of any size.
pub fn vector_text(vector: &[f32]) -> Result<String, AppError> {
    if vector.is_empty() || vector.iter().any(|v| !v.is_finite()) {
        return Err(AppError::internal(
            "an image embedding is empty or not a number",
        ));
    }
    let parts: Vec<String> = vector.iter().map(f32::to_string).collect();
    Ok(format!("[{}]", parts.join(",")))
}

/// One image file waiting for its vector.
#[derive(sqlx::FromRow)]
struct Pending {
    id: Uuid,
    entity_name: String,
    record_id: Uuid,
    file: String,
}

/// Embeds one batch of image files waiting for `client`'s model. Returns how
/// many files it settled (embedded or skipped).
pub async fn embed_pending(
    state: &EngineState,
    client: &ImageEmbeddingClient,
) -> Result<u64, AppError> {
    let db = &state.base.db;
    let model = client.model_id().to_owned();
    let pending: Vec<Pending> = sqlx::query_as(
        "SELECT d.id, d.entity_name::text AS entity_name, d.record_id::uuid AS record_id, \
                d.file::text AS file \
           FROM attome_document d \
           JOIN upload_session u ON u.final_key = d.file::text AND u.status = 'clean' \
                AND NOT u.is_deleted \
           JOIN search_entity_setting s ON s.entity_logicalname = d.entity_name::text \
                AND s.image_embedding \
          WHERE d.is_active AND d.file IS NOT NULL \
            AND d.record_id::text ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
            AND u.actual_content_type IN ('image/png', 'image/jpeg', 'image/webp', 'image/gif') \
            AND NOT EXISTS (SELECT 1 FROM record_image_embedding e \
                             WHERE e.source_id = d.id AND e.file_key = d.file::text \
                               AND e.embedding_model = $1) \
          ORDER BY d.id \
          LIMIT $2",
    )
    .bind(&model)
    .bind(i64::try_from(IMAGE_BATCH).unwrap_or(8))
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if pending.is_empty() {
        return Ok(0);
    }

    let registry = arc_swap::Guard::into_inner(state.entities.load());
    let mut inputs = Vec::new();
    let mut embedded: Vec<&Pending> = Vec::new();
    let mut skipped: Vec<(&Pending, &str)> = Vec::new();
    for row in &pending {
        let allowed = document_attachment(db, &registry, row.id)
            .await?
            .is_some_and(|a| a.text_allowed);
        if !allowed {
            skipped.push((row, "the file is labelled sensitive"));
            continue;
        }
        let bytes = match attome_storage::mirror::read_object(&state.base.storage, &row.file).await
        {
            Ok(bytes) => bytes,
            Err(error) => {
                // Storage may be back next tick; nothing is recorded.
                tracing::warn!(document = %row.id, %error, "image search: the file could not be read");
                continue;
            }
        };
        match image_embed::image_input(&bytes) {
            Some(input) => {
                inputs.push(input);
                embedded.push(row);
            }
            None => skipped.push((row, "not an image the model reads, or larger than 5 MB")),
        }
    }

    let vectors = if inputs.is_empty() {
        Vec::new()
    } else {
        client
            .embed(&inputs, Modality::Image)
            .await
            .map_err(|error| AppError::internal(format!("image embedding failed: {error}")))?
    };
    let mut tx = attome_db::tx::begin(db).await?;
    for (row, vector) in embedded.iter().zip(&vectors) {
        sqlx::query(
            "INSERT INTO record_image_embedding \
                 (source_id, file_key, embedding_model, entity_logicalname, record_id, embedding) \
             VALUES ($1, $2, $3, $4, $5, $6::vector) \
             ON CONFLICT (source_id, file_key, embedding_model) DO UPDATE \
                SET entity_logicalname = EXCLUDED.entity_logicalname, \
                    record_id = EXCLUDED.record_id, embedding = EXCLUDED.embedding, \
                    skipped = NULL, created_at = now()",
        )
        .bind(row.id)
        .bind(&row.file)
        .bind(&model)
        .bind(&row.entity_name)
        .bind(row.record_id)
        .bind(vector_text(vector)?)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    for (row, reason) in &skipped {
        sqlx::query(
            "INSERT INTO record_image_embedding \
                 (source_id, file_key, embedding_model, entity_logicalname, record_id, skipped) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (source_id, file_key, embedding_model) DO NOTHING",
        )
        .bind(row.id)
        .bind(&row.file)
        .bind(&model)
        .bind(&row.entity_name)
        .bind(row.record_id)
        .bind(*reason)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok((vectors.len() + skipped.len()) as u64)
}

/// Runs up to [`IMAGE_PASSES`] indexing batches, stopping at a short one or
/// a failure, which is logged; the files stay waiting for a later tick.
pub async fn run_passes(state: &EngineState) {
    let Some(client) = image_embedder(state) else {
        return;
    };
    for _ in 0..IMAGE_PASSES {
        match embed_pending(state, client).await {
            Ok(settled) if settled < IMAGE_BATCH as u64 => break,
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "image search indexing pass failed; retrying next tick");
                break;
            }
        }
    }
}

/// One image near the source.
#[derive(Debug, Clone)]
pub struct NearImage {
    pub entity_logicalname: String,
    pub record_id: Uuid,
    pub document_id: Uuid,
    /// The document's name.
    pub name: String,
    pub score: f64,
}

/// The images nearest `vector` that `ctx` may see, nearest first; the
/// document `exclude` left out.
pub async fn nearest_images(
    state: &EngineState,
    ctx: &SecurityContext,
    model: &str,
    vector: &[f32],
    exclude: Option<Uuid>,
    limit: i64,
) -> Result<Vec<NearImage>, AppError> {
    let access_map = attome_security::resolve_all_entity_access_levels(
        &state.base.db,
        ctx.user_id,
        attome_security::RecordAction::Read,
    )
    .await?;
    let default_shares = attome_security::resolve_default_share_entities(
        &state.base.db,
        ctx.user_id,
        &ctx.team_ids,
        attome_security::RecordAction::Read
            .share_capability()
            .as_i16(),
    )
    .await?;
    let visibility = attome_security::visibility::PolymorphicVisibility::new(
        ctx,
        &access_map,
        &default_shares,
        Some(attome_security::FastTierColumns {
            organization_ref: "t.organization_ref",
        }),
    );
    let literal = vector_text(vector)?;
    let dims = i32::try_from(vector.len()).unwrap_or(i32::MAX);

    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
        "SELECT t.entity_logicalname, t.record_id, t.source_id, t.name, \
                (1 - t.distance)::float8 AS score \
           FROM (SELECT e.entity_logicalname, e.record_id, e.source_id, d.name::text AS name, \
                        i.organization_ref, e.embedding <=> ",
    );
    qb.push_bind(literal.clone());
    qb.push(
        "::vector AS distance \
           FROM record_image_embedding e \
           JOIN attome_document d ON d.id = e.source_id AND d.is_active \
                AND d.file::text = e.file_key \
           JOIN search_index i ON i.corpus = 'record' \
                AND i.entity_logicalname = e.entity_logicalname AND i.record_id = e.record_id \
          WHERE e.embedding IS NOT NULL AND e.embedding_model = ",
    );
    qb.push_bind(model.to_owned());
    qb.push(" AND vector_dims(e.embedding) = ");
    qb.push_bind(dims);
    qb.push(
        " AND EXISTS (SELECT 1 FROM search_entity_setting s \
              WHERE s.entity_logicalname = e.entity_logicalname AND s.image_embedding)",
    );
    if let Some(id) = exclude {
        qb.push(" AND e.source_id <> ");
        qb.push_bind(id);
    }
    qb.push(" ORDER BY e.embedding <=> ");
    qb.push_bind(literal);
    qb.push("::vector LIMIT ");
    qb.push_bind(CANDIDATES);
    qb.push(") t WHERE t.distance IS NOT NULL");
    visibility.push(&mut qb, "t.entity_logicalname", "t.record_id");
    qb.push(" ORDER BY t.distance LIMIT ");
    qb.push_bind(limit);

    let pool = state.base.read_pool(ctx.user_id).await;
    let rows: Vec<(String, Uuid, Uuid, String, f64)> = qb
        .build_query_as()
        .fetch_all(pool)
        .await
        .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(entity_logicalname, record_id, document_id, name, score)| NearImage {
                entity_logicalname,
                record_id,
                document_id,
                name,
                score,
            },
        )
        .collect())
}

/// The bytes of a document the caller names as the source, read under their
/// permissions: 404 when they cannot read it, 422 when its file is labelled
/// sensitive or is not an image the model reads.
pub async fn document_image(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<String, AppError> {
    let db = &state.base.db;
    if !crate::routes::readable_documents(state, ctx, &[id])
        .await
        .contains(&id)
    {
        return Err(AppError::NotFound);
    }
    let registry = arc_swap::Guard::into_inner(state.entities.load());
    let attachment = document_attachment(db, &registry, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !attachment.text_allowed {
        return Err(AppError::Validation(
            "this document's file is labelled sensitive and is never compared".into(),
        ));
    }
    let file: Option<String> =
        sqlx::query_scalar("SELECT file::text FROM attome_document WHERE id = $1 AND is_active")
            .bind(id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .flatten();
    let file = file.ok_or_else(|| AppError::Validation("this document has no file".into()))?;
    let bytes = attome_storage::mirror::read_object(&state.base.storage, &file)
        .await
        .map_err(AppError::internal)?;
    image_embed::image_input(&bytes).ok_or_else(|| {
        AppError::Validation("this document's file is not an image of at most 5 MB".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectors_of_any_size_are_written_as_text() {
        assert_eq!(vector_text(&[1.0, -0.5]).unwrap_or_default(), "[1,-0.5]");
        assert!(vector_text(&[]).is_err());
        assert!(vector_text(&[f32::NAN]).is_err());
    }
}
