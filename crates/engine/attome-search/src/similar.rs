//! A25-T6: passages that read like a given record, file or description.
//!
//! `POST /api/v1/search/similar` embeds what it is given with the
//! deployment's local embedding model and returns the nearest record
//! passages (`record_chunk`, N15-T2): a record's own long fields and the
//! file text of the documents attached to it, a document's passages only
//! when its parent entity's search setting `document_embedding` is on.
//!
//! ## Access first
//!
//! A passage belongs to a record (`entity_logicalname`, `record_id`): the
//! record itself, or for a document the record it is attached to, whose
//! visibility is the document's. The nearest [`CANDIDATES`] passages are read
//! through the index row of that record (`search_index`, for its
//! organization) and filtered by the same visibility fragment global search
//! uses, before any is returned. Passages from timeline items (notes,
//! communications) are left out: they carry their own row security on top of
//! the parent's, which this fragment cannot check.
//!
//! The source given is read under the caller's own permissions first: a
//! record the caller cannot read, or a document attached to one, answers 404.
//!
//! ## Images
//!
//! Image similarity needs an image-text embedding model, and no deployment
//! configures one: an `image` answers 503 `feature_unavailable`, whatever the
//! entity's `image_embedding` setting says.

use attome_core::EngineState;
use attome_inference::EmbedKind;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Postgres, QueryBuilder};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::corpus::{DOCUMENT_ENTITY, PAGE_BREAK, document_attachment};
use crate::embedding_writer::vector_literal;

/// Passages returned when the request names no limit.
pub const DEFAULT_LIMIT: i64 = 10;
/// The most passages one request returns.
pub const MAX_LIMIT: i64 = 50;
/// Nearest passages read before visibility.
pub const CANDIDATES: i64 = 400;
/// The longest description accepted, and the most of a record's or file's
/// text embedded as the source.
pub const MAX_SOURCE_CHARS: usize = 4_000;
/// The most of a passage returned.
pub const MAX_PASSAGE_CHARS: usize = 500;
/// How long embedding the source may take.
pub const EMBED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A record to find passages like.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SimilarRecord {
    /// The entity's logical name; `attome_document` for a file.
    pub entity: String,
    pub id: Uuid,
}

/// Exactly one of `record`, `text` or `image`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SimilarRequest {
    /// Passages like this record's text, or like this document's file.
    #[serde(default)]
    pub record: Option<SimilarRecord>,
    /// Passages like this description (at most 4,000 characters).
    #[serde(default)]
    pub text: Option<String>,
    /// Passages like this image (base64). No image-text model is supported
    /// yet, so this answers 503 `feature_unavailable`.
    #[serde(default)]
    pub image: Option<String>,
    /// Passages to return, 1 to 50; 10 when absent.
    #[serde(default)]
    pub limit: Option<i64>,
}

/// One passage near the source.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SimilarPassage {
    /// The record the passage belongs to.
    pub entity_logicalname: String,
    pub record_id: Uuid,
    /// Where it came from: the record itself, or a document attached to it.
    pub source_entity: String,
    pub source_id: Uuid,
    /// For a document's PDF, the one-based page the passage is on.
    pub page: Option<i32>,
    /// The headings above the passage, outermost first.
    pub heading_path: Vec<String>,
    /// The passage, cut to 500 characters.
    pub text: String,
    /// One minus the cosine distance to the source; higher is nearer.
    pub score: f64,
}

/// What a request asks to compare against. Pure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimilarSource {
    Record { entity: String, id: Uuid },
    Text(String),
    Image,
}

/// The source a request names, or why it is refused. Pure.
pub fn parse_source(req: &SimilarRequest) -> Result<SimilarSource, AppError> {
    let given = [
        req.record.is_some(),
        req.text.is_some(),
        req.image.is_some(),
    ]
    .iter()
    .filter(|given| **given)
    .count();
    if given != 1 {
        return Err(AppError::Validation(
            "give exactly one of record, text or image".into(),
        ));
    }
    if req.image.is_some() {
        return Ok(SimilarSource::Image);
    }
    if let Some(record) = &req.record {
        return Ok(SimilarSource::Record {
            entity: record.entity.clone(),
            id: record.id,
        });
    }
    let text = req.text.as_deref().unwrap_or_default().trim();
    if text.is_empty() {
        return Err(AppError::Validation("text must not be empty".into()));
    }
    if text.chars().count() > MAX_SOURCE_CHARS {
        return Err(AppError::Validation(format!(
            "text is limited to {MAX_SOURCE_CHARS} characters"
        )));
    }
    Ok(SimilarSource::Text(text.to_owned()))
}

/// The limit a request asks for, within 1 to [`MAX_LIMIT`]. Pure.
pub fn limit_of(req: &SimilarRequest) -> i64 {
    req.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

fn cut(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// The text to embed for a record the caller names, read under their
/// permissions: a document's file text (only with its parent record
/// readable), any other record's index text. 404 for a record the caller
/// cannot read.
async fn record_source_text(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    id: Uuid,
) -> Result<String, AppError> {
    let db = &state.base.db;
    if entity == DOCUMENT_ENTITY {
        if !crate::routes::readable_documents(state, ctx, &[id])
            .await
            .contains(&id)
        {
            return Err(AppError::NotFound);
        }
        let registry = state.entities.load_full();
        let attachment = document_attachment(db, &registry, id)
            .await?
            .ok_or(AppError::NotFound)?;
        if !attachment.text_allowed {
            return Err(AppError::Validation(
                "this document's file is labelled sensitive and is never compared".into(),
            ));
        }
        let text: Option<String> = sqlx::query_scalar(
            "SELECT t.content_text FROM attome_document d \
               JOIN document_text t ON t.file_key = d.file WHERE d.id = $1",
        )
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let text = text.ok_or_else(|| {
            AppError::Validation("this document has no extracted text yet".into())
        })?;
        return Ok(cut(&text.replace(PAGE_BREAK, " "), MAX_SOURCE_CHARS));
    }
    if !attome_records::entity_crud::referenced_record_visible(state, ctx, entity, id).await? {
        return Err(AppError::NotFound);
    }
    let row: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT title, subtitle, body_display FROM search_index \
          WHERE corpus = 'record' AND entity_logicalname = $1 AND record_id = $2",
    )
    .bind(entity)
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (title, subtitle, body) =
        row.ok_or_else(|| AppError::Validation("this record is not in the search index".into()))?;
    let text =
        crate::record_vectors::record_text(title.as_deref(), subtitle.as_deref(), body.as_deref());
    if text.is_empty() {
        return Err(AppError::Validation(
            "this record has no text to compare".into(),
        ));
    }
    Ok(cut(&text, MAX_SOURCE_CHARS))
}

type NeighbourRow = (
    String,
    Uuid,
    String,
    Uuid,
    Option<i32>,
    Vec<String>,
    String,
    f64,
);

/// The nearest passages to `vector_literal` of `model` the caller may see,
/// leaving out the source itself.
async fn neighbours(
    state: &EngineState,
    ctx: &SecurityContext,
    vector_literal: &str,
    model: &str,
    exclude: Option<(&str, Uuid)>,
    limit: i64,
) -> Result<Vec<SimilarPassage>, AppError> {
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

    // The inner query orders by the distance itself so the vector index
    // serves it; the outer one applies visibility under the alias `t`.
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
        "SELECT t.entity_logicalname, t.record_id, t.source_entity, t.source_id, t.page, \
                t.heading_path, t.text_display, (1 - t.distance)::float8 AS score \
           FROM (SELECT c.entity_logicalname, c.record_id, c.source_entity, c.source_id, \
                        c.page, c.heading_path, c.text_display, i.organization_ref, \
                        c.embedding <=> ",
    );
    qb.push_bind(vector_literal.to_owned());
    qb.push(
        "::halfvec AS distance \
           FROM record_chunk c \
           JOIN search_index i ON i.corpus = 'record' \
                AND i.entity_logicalname = c.entity_logicalname AND i.record_id = c.record_id \
          WHERE c.embedding IS NOT NULL AND c.embedding_model = ",
    );
    qb.push_bind(model.to_owned());
    qb.push(" AND c.entity_logicalname <> ");
    qb.push_bind(DOCUMENT_ENTITY);
    qb.push(" AND (c.source_entity = c.entity_logicalname OR (c.source_entity = ");
    qb.push_bind(DOCUMENT_ENTITY);
    qb.push(
        " AND EXISTS (SELECT 1 FROM search_entity_setting s \
              WHERE s.entity_logicalname = c.entity_logicalname AND s.document_embedding)))",
    );
    if let Some((entity, id)) = exclude {
        qb.push(" AND NOT (c.source_entity = ");
        qb.push_bind(entity.to_owned());
        qb.push(" AND c.source_id = ");
        qb.push_bind(id);
        qb.push(")");
    }
    qb.push(" ORDER BY c.embedding <=> ");
    qb.push_bind(vector_literal.to_owned());
    qb.push("::halfvec LIMIT ");
    qb.push_bind(CANDIDATES);
    qb.push(") t WHERE t.distance IS NOT NULL");
    visibility.push(&mut qb, "t.entity_logicalname", "t.record_id");
    qb.push(" ORDER BY t.distance LIMIT ");
    qb.push_bind(limit);

    let pool = state.base.read_pool(ctx.user_id).await;
    let rows: Vec<NeighbourRow> = qb
        .build_query_as()
        .fetch_all(pool)
        .await
        .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(
                entity_logicalname,
                record_id,
                source_entity,
                source_id,
                page,
                heading_path,
                text,
                score,
            )| {
                SimilarPassage {
                    entity_logicalname,
                    record_id,
                    source_entity,
                    source_id,
                    page,
                    heading_path,
                    text: cut(&text, MAX_PASSAGE_CHARS),
                    score,
                }
            },
        )
        .collect())
}

/// Finds the passages nearest what `req` names, for `ctx`.
pub async fn find_similar(
    state: &EngineState,
    ctx: &SecurityContext,
    req: &SimilarRequest,
) -> Result<Vec<SimilarPassage>, AppError> {
    let source = parse_source(req)?;
    let limit = limit_of(req);
    if source == SimilarSource::Image {
        return Err(AppError::FeatureUnavailable);
    }
    if !attome_core::ai_runtime_switch::allows(
        &state.base.config.inference.ai,
        attome_config::AiSurface::SemanticSearch,
    ) {
        return Err(AppError::FeatureUnavailable);
    }
    let client = crate::knowledge::ranking_embedder().ok_or(AppError::FeatureUnavailable)?;
    let (text, exclude) = match &source {
        SimilarSource::Record { entity, id } => (
            record_source_text(state, ctx, entity, *id).await?,
            Some((entity.as_str(), *id)),
        ),
        SimilarSource::Text(text) => (text.clone(), None),
        SimilarSource::Image => return Err(AppError::FeatureUnavailable),
    };
    let embedded = tokio::time::timeout(
        EMBED_TIMEOUT,
        client.embed(&[text.as_str()], EmbedKind::Query),
    )
    .await;
    let vector = match embedded {
        Ok(Ok((mut vectors, _))) if !vectors.is_empty() => vectors.swap_remove(0),
        Ok(Ok(_)) => return Err(AppError::CapabilityUnavailable("embedding")),
        Ok(Err(error)) => {
            tracing::warn!(%error, "search similar: the source could not be embedded");
            return Err(AppError::CapabilityUnavailable("embedding"));
        }
        Err(_) => {
            tracing::warn!("search similar: embedding the source timed out");
            return Err(AppError::CapabilityUnavailable("embedding"));
        }
    };
    let literal = vector_literal(&vector)?;
    neighbours(state, ctx, &literal, client.model_id(), exclude, limit).await
}

/// Find passages like a record, file or description
///
/// Embeds the record's text, the document's file text or the description and returns the nearest
/// record passages the caller may read: records' long fields and, for entities whose search setting
/// turns document embeddings on, the text of the files attached to them, with the page of a PDF.
/// An image answers 503 until an image-text model is supported.
#[utoipa::path(
    post,
    path = "/api/v1/search/similar",
    tag = "search",
    request_body = SimilarRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "a bounded, permission-filtered nearest-passage search; persists nothing",
    )))),
    responses(
        (status = 200, description = "The nearest readable passages, nearest first", body = PaginatedResponse<SimilarPassage>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Search is not licensed", body = ErrorResponse),
        (status = 404, description = "The record or document does not exist or is not readable", body = ErrorResponse),
        (status = 422, description = "Not exactly one source, or a source with no text", body = ErrorResponse),
        (status = 503, description = "No embedding model, semantic search switched off, or an image was given", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn similar_route(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(req): Json<SimilarRequest>,
) -> Result<Json<PaginatedResponse<SimilarPassage>>, AppError> {
    let limit = limit_of(&req);
    let items = find_similar(&state, &ctx, &req).await?;
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, limit)))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/search/similar", post(similar_route))
}

/// This file's slice of the workspace OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(similar_route))]
#[derive(Debug)]
pub struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn request(record: bool, text: Option<&str>, image: bool) -> SimilarRequest {
        SimilarRequest {
            record: record.then(|| SimilarRecord {
                entity: "account".into(),
                id: Uuid::nil(),
            }),
            text: text.map(str::to_owned),
            image: image.then(|| "aGVsbG8=".to_owned()),
            limit: None,
        }
    }

    #[test]
    fn similar_takes_exactly_one_source() {
        assert!(parse_source(&request(false, None, false)).is_err());
        assert!(parse_source(&request(true, Some("x"), false)).is_err());
        assert_eq!(
            parse_source(&request(false, Some("  late delivery  "), false)).ok(),
            Some(SimilarSource::Text("late delivery".into()))
        );
        assert!(parse_source(&request(false, Some("   "), false)).is_err());
        let long = "x".repeat(MAX_SOURCE_CHARS + 1);
        assert!(parse_source(&request(false, Some(&long), false)).is_err());
        assert!(matches!(
            parse_source(&request(true, None, false)),
            Ok(SimilarSource::Record { .. })
        ));
    }

    /// No image-text model is supported, so an image is never embedded.
    #[test]
    fn image_embedding_off_by_default() {
        assert_eq!(
            parse_source(&request(false, None, true)).ok(),
            Some(SimilarSource::Image)
        );
        let mut req = request(false, Some("x"), false);
        req.limit = Some(500);
        assert_eq!(limit_of(&req), MAX_LIMIT);
        req.limit = Some(0);
        assert_eq!(limit_of(&req), 1);
        assert_eq!(limit_of(&request(false, Some("x"), false)), DEFAULT_LIMIT);
    }
}
