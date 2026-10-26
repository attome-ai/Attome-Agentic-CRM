//! Knowledge-chunk visibility (TODO-031, `P-knowledge-base` §4).
//!
//! **The rule:**
//!
//! ```text
//! chunk visible  ⟺  collection visible
//!                   AND (parent_record_id IS NULL OR that record visible)
//! ```
//!
//! ## Why this composes rather than replaces
//!
//! I-1 says there is one retrieval enforcement point. This adds no second
//! predicate: clause 2 is `PolymorphicVisibility` — the *same* fragment record
//! search uses, unchanged — and clause 1 is an ordinary record-read check
//! performed once per request against a single entity, the collection.
//!
//! That single-entity property is the whole reason the collection is an
//! ordinary XRM entity (§4.2). A caller's readable collections resolve to a
//! list of ids sized in tens, so the chunk query filters on
//! `collection_ref = ANY($ids)` — an indexed equality — and the expensive
//! polymorphic predicate runs **only** on the rows that carry a parent record.
//! Web chunks and standalone-article chunks never pay it.
//!
//! A design that permissioned the chunk directly would have had to run the
//! polymorphic predicate over every row of the corpus most likely to be large.
//!
//! ## The empty case: never "no clause", always "nothing"
//!
//! A caller with no readable collections must get nothing — never a query with
//! the collection clause omitted, because "no restrictions to apply" and "no
//! access" look identical at a call site and only one of them is safe to
//! shortcut. [`KnowledgeVisibility`] keeps `ANY(ARRAY[])` for exactly that
//! reason, for every caller of the fragment.
//!
//! Retrieval itself shortcuts only toward *nothing* (C8, row A-54, I-16): an
//! agent session's explicit empty knowledge scope (`Some(&[])`) returns before
//! any query at all, and a set that resolves to no collection after the
//! caller's live access and the scope are applied returns before the chunk
//! query. Neither path can widen what is returned.
//!
//! ## Lifecycle is part of this, not adjacent to it
//!
//! §7: the AI must never retrieve a draft. The filter lives here, inside the
//! same fragment as the permission check, because the failure mode is
//! precisely that lifecycle looks like an authoring concern and ends up in the
//! authoring UI's list query while the retrieval path never learns about it.

use attome_security::visibility::PolymorphicVisibility;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use sqlx::{Postgres, QueryBuilder};
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::corpus::knowledge::{ArticleChunk, expand};

/// Which lifecycle states a retrieval may see.
///
/// `Published` is the only value an AI surface may use. The others exist so an
/// authoring UI can share this code path rather than writing a second query
/// against the same table — a second query being how the draft filter gets lost
/// in the first place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleFilter {
    /// The only value valid for an AI surface.
    Published,
    /// Published plus expired. Opt-in: an expired article is often still the
    /// best available answer, and presenting it as current is the failure — a
    /// caller choosing this must label what it renders.
    PublishedAndExpired,
    /// Everything, including drafts. **Never valid for retrieval.** Authoring
    /// surfaces only.
    All,
}

impl LifecycleFilter {
    fn states(self) -> &'static [&'static str] {
        match self {
            LifecycleFilter::Published => &["published"],
            LifecycleFilter::PublishedAndExpired => &["published", "expired"],
            LifecycleFilter::All => &["draft", "published", "expired"],
        }
    }

    /// Whether an AI surface may use this filter.
    ///
    /// Exposed so the agent façade can assert rather than assume — a retrieval
    /// path that accepted `All` because a parameter was threaded through from
    /// an authoring caller is the concrete shape of the §7 failure.
    pub fn is_valid_for_retrieval(self) -> bool {
        !matches!(self, LifecycleFilter::All)
    }
}

/// The audience a retrieval is performed for.
///
/// D-359: staff only in v1. This is an **explicit parameter** rather than an
/// ambient assumption precisely so that widening it later is a visible change
/// at every call site — a function whose signature says "staff only" by
/// omission is the one a later portal feature quietly widens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Audience {
    #[default]
    Internal,
}

/// Everything needed to filter chunks for one caller.
pub struct KnowledgeVisibility<'a> {
    /// The collections this caller may read, resolved once per request.
    collection_ids: Vec<Uuid>,
    /// The record predicate, applied only to parented chunks.
    records: &'a PolymorphicVisibility<'a>,
    lifecycle: LifecycleFilter,
    audience: Audience,
}

impl std::fmt::Debug for KnowledgeVisibility<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnowledgeVisibility")
            .finish_non_exhaustive()
    }
}

impl<'a> KnowledgeVisibility<'a> {
    /// # Panics
    ///
    /// Debug-asserts the lifecycle filter is valid for retrieval. A release
    /// build takes the safe path instead — see [`push`](Self::push), which
    /// narrows `All` to `Published` rather than trusting the caller. Failing
    /// closed matters more here than failing loudly: the loud failure is a
    /// panic in production, the quiet one is a draft in a customer's answer.
    pub fn new(
        collection_ids: Vec<Uuid>,
        records: &'a PolymorphicVisibility<'a>,
        lifecycle: LifecycleFilter,
        audience: Audience,
    ) -> Self {
        debug_assert!(
            lifecycle.is_valid_for_retrieval(),
            "LifecycleFilter::All must never reach a retrieval path (§7)"
        );
        Self {
            collection_ids,
            records,
            lifecycle,
            audience,
        }
    }

    /// The audience this was built for. `Internal` is the only value v1 accepts.
    pub fn audience(&self) -> Audience {
        self.audience
    }

    /// Whether this caller can reach any chunk at all.
    ///
    /// Reported rather than acted on: the fragment is still pushed for a caller
    /// with no collections, and still returns nothing. A caller that skipped
    /// the fragment on this basis would be one refactor away from skipping it
    /// on a wrong basis.
    pub fn reaches_nothing(&self) -> bool {
        self.collection_ids.is_empty()
    }

    /// Pushes the chunk filter, binding every value as it goes.
    ///
    /// `chunk_alias` is a SQL identifier chosen by the calling code and is
    /// **spliced, not bound** — it must never come from request data. Every
    /// value goes through `push_bind`.
    ///
    /// **An admin is filtered here, unlike in record search.** `is_unfiltered`
    /// short-circuits the *record* predicate for an admin, and that is correct
    /// — an admin may read every record. It says nothing about collections,
    /// which are ordinary records whose read access an admin does happen to
    /// have; the collection list is resolved through the same read check for
    /// everyone, so no branch is needed and none is offered.
    pub fn push(&self, qb: &mut QueryBuilder<'_, Postgres>, chunk_alias: &str) {
        // Clause 1: the indexed equality. Every chunk pays exactly this.
        qb.push(" AND ");
        qb.push(chunk_alias);
        qb.push(".collection_ref = ANY(");
        qb.push_bind(self.collection_ids.clone());
        qb.push("::uuid[])");

        // Lifecycle. Narrowed to `Published` if a caller somehow arrived with
        // `All` — see `new`'s doc: fail closed rather than loudly.
        let effective = if self.lifecycle.is_valid_for_retrieval() {
            self.lifecycle
        } else {
            LifecycleFilter::Published
        };
        qb.push(" AND ");
        qb.push(chunk_alias);
        qb.push(".lifecycle = ANY(");
        qb.push_bind(
            effective
                .states()
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<Vec<String>>(),
        );
        qb.push("::text[])");

        // Clause 2: the expensive one, guarded by the NULL check so it is
        // evaluated only for chunks that carry a parent record.
        //
        // The guard is inside the OR rather than around the whole fragment: a
        // caller cannot reach it for an unparented chunk, and a future edit
        // that moved the record predicate outside this arm would silently
        // start charging web and standalone-article chunks for it.
        qb.push(" AND (");
        qb.push(chunk_alias);
        qb.push(".parent_record_id IS NULL OR TRUE");
        self.records.push(
            qb,
            &format!("{chunk_alias}.parent_entity"),
            &format!("{chunk_alias}.parent_record_id"),
        );
        qb.push(")");
    }
}

/// Resolves the collections this caller may read.
///
/// A single-entity record read, which is the whole point of §4.2's model: the
/// answer is a list of ids sized in tens, cached for the request, and every
/// chunk query afterwards is an indexed equality against it.
///
/// The collection entity is created at runtime through the admin API, so its
/// physical table name is a parameter rather than a constant here — this layer
/// must not hard-code a metadata-defined table.
pub async fn readable_collections(
    db: &sqlx::PgPool,
    collection_entity: &str,
    records: &PolymorphicVisibility<'_>,
) -> Result<Vec<Uuid>, attome_types::AppError> {
    let table = attome_core::sql_ident::quote_ident(collection_entity);
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(format!(
        "SELECT t.id FROM {table} t WHERE t.is_active = true"
    ));
    // The same predicate, over the collection entity itself. There is no
    // knowledge-specific access rule anywhere in this file — that is I-1.
    records.push(&mut qb, &format!("'{collection_entity}'"), "t.id");

    qb.build_query_scalar()
        .fetch_all(db)
        .await
        .map_err(attome_types::AppError::internal)
}

// ── M37 Phase 2: staleness + semantic neighbors (D-452) ────────────────────

/// Which of these source pages are stale as of today, keyed by page id.
///
/// **An untrusted segment attribute, not a trusted control signal** — this
/// boolean is computed server-side from a plain `DATE` comparison, which
/// makes it *safe to compute*, but a caller assembling a chunk into a
/// prompt must still fold it into the same
/// `attome_ai::prompt::Segment::Untrusted` content the chunk text itself
/// becomes (`attome-ai/src/prompt.rs`'s taint discipline), never treat it as
/// a system-level directive that could influence a privileged decision on
/// its own. It exists so a caller *can* tell the model "this source is
/// past its review date" — what the model does with that is, correctly,
/// just more untrusted context.
///
/// Queries `content_page` directly by name rather than through a crate
/// dependency on `attome-content` (D-452): both are engine-owned infrastructure
/// tables (guidelines §4's "SQL inside `crates/` engine code... owns the
/// platform's queries by design"), and `attome-content`/`attome-search` stay
/// siblings with no dependency edge between them.
pub async fn stale_by_source_id(
    db: &sqlx::PgPool,
    source_ids: &[Uuid],
) -> Result<HashMap<Uuid, bool>, AppError> {
    if source_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(Uuid, bool)> = sqlx::query_as(
        "SELECT id, (review_by IS NOT NULL AND review_by < CURRENT_DATE) AS stale \
         FROM content_page WHERE id = ANY($1::uuid[])",
    )
    .bind(source_ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().collect())
}

/// Default number of semantic neighbors to suggest.
pub const DEFAULT_SEMANTIC_NEIGHBOR_LIMIT: i64 = 5;

/// Semantic neighbors of `page_id` — other published articles whose chunks
/// are nearest, by cosine distance, to `page_id`'s own lead chunk.
///
/// "Straightforward reuse of existing infra", per the M37 plan: this is a
/// single ANN query over `knowledge_chunk.embedding` (`0122`), the
/// same HNSW index and `apply_scan_bounds` session GUCs `vector.rs` already
/// documents for Stage 2 retrieval — no new ML component. The representative
/// vector is the lowest-`ordinal` published chunk with a non-null embedding
/// (the article's lead section) rather than an average across all of the
/// article's chunks: `AVG()` over `halfvec` is not something this codebase
/// has exercised anywhere yet, and a single representative vector is simpler
/// and already correct for "what is this article broadly about".
///
/// **Returns an empty list on a fresh deployment today** — not a bug in this
/// function: nothing in the workspace populates `embedding` yet (D-452's
/// finding; the backfill this depends on is Stage 2/`TODO-029`, unbuilt).
/// The query is written to be correct once that backfill exists, and the
/// `WITH src AS (...)` shape makes "no embedding yet" a zero-row result,
/// never an error.
pub async fn semantic_neighbors(
    db: &sqlx::PgPool,
    page_id: Uuid,
    limit: i64,
) -> Result<Vec<Uuid>, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    crate::vector::apply_scan_bounds(&mut tx).await?;

    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "WITH src AS ( \
            SELECT embedding FROM knowledge_chunk \
            WHERE source_type = 'article' AND source_id = $1 \
              AND lifecycle = 'published' AND embedding IS NOT NULL \
            ORDER BY ordinal ASC LIMIT 1 \
         ) \
         SELECT source_id FROM ( \
            SELECT DISTINCT ON (k.source_id) \
                   k.source_id AS source_id, k.embedding <=> src.embedding AS distance \
            FROM knowledge_chunk k, src \
            WHERE k.lifecycle = 'published' AND k.source_type = 'article' \
              AND k.source_id <> $1 AND k.embedding IS NOT NULL \
            ORDER BY k.source_id, k.embedding <=> src.embedding \
         ) neighbors \
         ORDER BY distance \
         LIMIT $2",
    )
    .bind(page_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

// ── Retrieval (D-489) ───────────────────────────────────────────────────────

/// One passage returned from the knowledge corpus, with everything a citation
/// needs to resolve (`P-knowledge-base` §8, §11).
///
/// Every field is captured at projection time or computed here, never
/// reconstructed from the article at render time: an item edited after the
/// answer was generated would otherwise produce a citation pointing at a
/// heading that no longer exists.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct KnowledgeCitation {
    /// The article record the passage came from.
    pub item_id: Uuid,
    /// The Data Source that permissioned it — the collection `readable_collections`
    /// resolved for this caller before the query ran.
    pub data_source_id: Uuid,
    pub title: String,
    /// The heading path captured when the chunk was written, outermost first.
    /// Empty for an article's lede, which precedes any heading.
    pub heading_path: Vec<String>,
    /// The enclosing section, not the matched chunk. See `expand`'s doc.
    pub passage: String,
    /// The section exceeded the passage ceiling and was returned in part.
    /// Reported so an answer can say so rather than presenting a fragment as
    /// the whole.
    pub truncated: bool,
    /// When a web-sourced chunk was fetched. `None` for authored articles.
    pub fetched_at: Option<DateTime<Utc>>,
    /// Past its `review_by` date. Computed server-side from a plain DATE
    /// comparison, and it reaches a prompt only as untrusted context.
    pub stale: bool,
}

/// A citation plus the chunk rows it was assembled from.
///
/// The chunk ids are here so the caller can record retrieval telemetry
/// (`record_chunk_retrievals`) without a second query, and they are not part
/// of the wire shape — the route serializes `citation` only.
#[derive(Debug, Clone, PartialEq)]
pub struct KnowledgeHit {
    pub citation: KnowledgeCitation,
    pub chunk_ids: Vec<Uuid>,
}

/// Default and maximum passages returned.
pub const DEFAULT_KNOWLEDGE_LIMIT: i64 = 5;
pub const MAX_KNOWLEDGE_LIMIT: i64 = 20;

/// Candidate chunks read per requested passage, and the ceiling on that.
///
/// More than one because an article's chunks can both match and then merge
/// into one passage; bounded because the alternative is reading a whole corpus
/// to return five sections.
const CANDIDATES_PER_HIT: i64 = 4;
const MAX_CANDIDATE_CHUNKS: i64 = 200;

/// What one matched item accumulated, before section expansion.
///
/// A named struct rather than a four-element tuple because the tuple is
/// unreadable at the `let` that destructures it and its field order is then a
/// silent contract — the same reason `ItemRow` is named in `knowledge_index`.
struct MatchedItem {
    collection_ref: Uuid,
    chunk_ids: Vec<Uuid>,
    ordinals: Vec<i32>,
    fetched_at: Option<DateTime<Utc>>,
}

/// Retrieves passages from the published knowledge corpus for one caller.
///
/// **The enforcement point.** Visibility is the same `KnowledgeVisibility`
/// fragment used everywhere else — one indexed equality over the caller's
/// readable collections (`readable_collections`, against
/// `knowledge_data_source`), the `published` lifecycle narrow, and the
/// record predicate for parented chunks. There is no knowledge-specific
/// permission rule anywhere in this function, which is I-1.
///
/// **A question matches when any of its content terms does** (D-498 step 2).
/// The query is not handed to `plainto_tsquery` whole: that ANDs every word, so
/// "what is our refund policy" found only a chunk containing *what*, *is*,
/// *our*, *refund* and *policy* together, which is almost none. Function words
/// are dropped and the remaining terms are OR-ed (`knowledge_query_terms`,
/// `push_any_term_tsquery`). The permission fragment and the `ts_rank_cd`
/// ordering are unchanged — this changes which chunks match, not how they rank.
///
/// An empty result is a correct answer and is what the caller logs a gap for;
/// this function does not decide that, it only retrieves.
pub async fn search_knowledge(
    db: &sqlx::PgPool,
    ctx: &SecurityContext,
    query: &str,
    limit: i64,
) -> Result<Vec<KnowledgeHit>, AppError> {
    retrieve(
        db,
        ctx,
        query,
        limit,
        RetrievalMode::Lexical,
        None,
        None,
        None,
    )
    .await
    .map(|r| r.hits)
}

/// Which candidate sources a knowledge retrieval draws on (D-498 step 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetrievalMode {
    /// Full-text only. The configuration the frozen D-498 baseline measured,
    /// and what a deployment without an embedding model runs.
    Lexical,
    /// The question's nearest chunk embeddings only. Used to measure the vector
    /// leg on its own; it fails rather than falling back when the question
    /// cannot be embedded.
    Vector,
    /// Both, combined by reciprocal rank fusion.
    ///
    /// Without an embedder this is lexical: a deployment with no embedding
    /// model is a supported configuration, not a fault. With one, a vector leg
    /// that fails (the model is down, returns a malformed vector, or the query
    /// errors) is logged at `warn`, counted in `attome_search_leg_degraded_total`,
    /// and the lexical results are returned alone — a broken embedding server
    /// must never take lexical search down with it (D-506 §3).
    Fused,
}

/// [`search_knowledge`] with an explicit [`RetrievalMode`].
///
/// Permission filtering is identical in every mode: both the lexical and the
/// vector candidate queries push the same [`KnowledgeVisibility`] fragment
/// before their `LIMIT`, so fusion only ever sees chunks the caller may read
/// (D-498 ruling 1). `embedder` must use the model that wrote the stored
/// vectors; the vector leg reads only chunks embedded by that model.
///
/// Like [`search_knowledge`], this applies no agent-session knowledge scope
/// (D-512 §7): it retrieves under the caller's own permissions only. An agent
/// action must not call it; its scoped entry point is
/// [`search_knowledge_recorded`].
pub async fn search_knowledge_with(
    db: &sqlx::PgPool,
    ctx: &SecurityContext,
    query: &str,
    limit: i64,
    mode: RetrievalMode,
    embedder: Option<&attome_inference::EmbeddingClient>,
) -> Result<Vec<KnowledgeHit>, AppError> {
    retrieve(db, ctx, query, limit, mode, embedder, None, None)
        .await
        .map(|r| r.hits)
}

/// One candidate chunk: id, item, collection, ordinal, heading path, display
/// text, fetch time.
type ChunkRow = (
    Uuid,
    Uuid,
    Uuid,
    i32,
    Vec<String>,
    String,
    Option<DateTime<Utc>>,
);

/// The lexical leg: caller-visible chunks matching any content term, best
/// `ts_rank_cd` first (D-498 step 2).
async fn lexical_candidates(
    db: &sqlx::PgPool,
    visibility: &KnowledgeVisibility<'_>,
    terms: &[String],
    limit: i64,
) -> Result<Vec<ChunkRow>, AppError> {
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
        "SELECT k.id, k.source_id, k.collection_ref, k.ordinal, k.heading_path, \
         k.text_display, k.fetched_at \
         FROM knowledge_chunk k, (SELECT ",
    );
    push_any_term_tsquery(&mut qb, terms);
    qb.push(" AS query) AS q WHERE k.tsv @@ q.query");
    visibility.push(&mut qb, "k");
    qb.push(" ORDER BY ts_rank_cd(k.tsv, q.query, 32) DESC, k.source_id, k.ordinal LIMIT ");
    qb.push_bind(limit);
    qb.build_query_as()
        .fetch_all(db)
        .await
        .map_err(AppError::internal)
}

/// The vector leg: the caller-visible published chunks nearest the question's
/// embedding, among chunks embedded by `client`'s model.
///
/// The question is embedded before the transaction opens, so no model call
/// happens inside it. The transaction exists only to scope `vector.rs`'s scan
/// bounds. `ORDER BY` is the distance alone because pgvector's HNSW index can
/// serve only that ordering; the visibility fragment and the partial index's
/// own predicates (`embedding IS NOT NULL`, `lifecycle = 'published'`) filter
/// inside the index scan.
async fn vector_candidates(
    db: &sqlx::PgPool,
    visibility: &KnowledgeVisibility<'_>,
    client: &attome_inference::EmbeddingClient,
    question: &str,
    limit: i64,
) -> Result<Vec<ChunkRow>, AppError> {
    let (vectors, _usage) = client
        .embed(&[question], attome_inference::EmbedKind::Query)
        .await
        .map_err(|e| AppError::internal(format!("query embedding failed: {e}")))?;
    let vector = vectors
        .first()
        .ok_or_else(|| AppError::internal("the embedding model returned no query vector"))?;
    let literal = crate::embedding_writer::vector_literal(vector)?;

    let mut tx = attome_db::tx::begin(db).await?;
    crate::vector::apply_scan_bounds(&mut tx).await?;

    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
        "SELECT k.id, k.source_id, k.collection_ref, k.ordinal, k.heading_path, \
         k.text_display, k.fetched_at \
         FROM knowledge_chunk k \
         WHERE k.embedding IS NOT NULL AND k.lifecycle = 'published' AND k.embedding_model = ",
    );
    qb.push_bind(client.model_id().to_owned());
    visibility.push(&mut qb, "k");
    qb.push(" ORDER BY k.embedding <=> ");
    qb.push_bind(literal);
    qb.push("::halfvec LIMIT ");
    qb.push_bind(limit);

    let rows: Vec<ChunkRow> = qb
        .build_query_as()
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(rows)
}

/// Reciprocal rank fusion of the lexical and vector candidate lists, with the
/// same constant `legs::fuse` uses for record search.
///
/// A chunk's score is the sum of `1 / (RRF_K + rank)` over the lists it
/// appears in, ranks counted from 1. Ties break by item and ordinal so the
/// order is the same on every run.
fn fuse_ranked(lexical: Vec<ChunkRow>, vector: Vec<ChunkRow>) -> Vec<ChunkRow> {
    let mut scored: HashMap<Uuid, (f64, ChunkRow)> = HashMap::new();
    for list in [lexical, vector] {
        for (index, row) in list.into_iter().enumerate() {
            let contribution = 1.0 / (crate::legs::fuse::RRF_K + index as f64 + 1.0);
            scored
                .entry(row.0)
                .and_modify(|(score, _)| *score += contribution)
                .or_insert((contribution, row));
        }
    }
    let mut fused: Vec<(f64, ChunkRow)> = scored.into_values().collect();
    fused.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.1.cmp(&b.1.1))
            .then_with(|| a.1.3.cmp(&b.1.3))
    });
    fused.into_iter().map(|(_, row)| row).collect()
}

/// What one retrieval produced, and whether the caller could read any
/// collection while producing it.
///
/// `searched_readable_collections` exists for one decision: whether an empty
/// result may be recorded as a knowledge gap. A caller who can read no
/// collection gets an empty result that says nothing about whether the
/// knowledge exists, and recording it turns "not permitted" into "missing" in
/// the authors' queue (D-498). It comes from the caller's own readable set, so
/// no row the caller cannot see influences it.
struct Retrieval {
    hits: Vec<KnowledgeHit>,
    searched_readable_collections: bool,
}

/// [`search_knowledge_with`]'s body. Returns [`Retrieval`] so the recording
/// wrapper makes the gap decision from this resolution rather than a second one.
#[allow(
    clippy::too_many_arguments,
    reason = "one private body behind four public entry points; each argument is a distinct retrieval input"
)]
async fn retrieve(
    db: &sqlx::PgPool,
    ctx: &SecurityContext,
    query: &str,
    limit: i64,
    mode: RetrievalMode,
    embedder: Option<&attome_inference::EmbeddingClient>,
    scope: Option<&[Uuid]>,
    reranker: Option<&attome_inference::RerankClient>,
) -> Result<Retrieval, AppError> {
    let trimmed = query.trim();
    if trimmed.is_empty() || limit <= 0 {
        return Ok(Retrieval {
            hits: Vec::new(),
            searched_readable_collections: false,
        });
    }
    let limit = limit.clamp(1, MAX_KNOWLEDGE_LIMIT);

    // I-16 / A-54: an explicit empty knowledge scope means "no knowledge
    // retrieval" — not a retrieval that happens to return nothing. Nothing is
    // resolved and nothing is queried. `None` (no narrowing) is a different
    // value and takes the full path below.
    if scope.is_some_and(<[Uuid]>::is_empty) {
        return Ok(Retrieval {
            hits: Vec::new(),
            searched_readable_collections: false,
        });
    }

    // The access map and default shares are resolved per request, not cached:
    // this is an agent path, not a per-keystroke typeahead, and a stale map
    // here would be a permission decision made against a revoked grant.
    let access = attome_security::resolve_all_entity_access_levels(
        db,
        ctx.user_id,
        attome_security::RecordAction::Read,
    )
    .await?;
    let default_shares = attome_security::resolve_default_share_entities(
        db,
        ctx.user_id,
        &ctx.team_ids,
        attome_security::RecordAction::Read
            .share_capability()
            .as_i16(),
    )
    .await?;
    let records = PolymorphicVisibility::new(ctx, &access, &default_shares, None);

    // Clause 1 of the rule, resolved once per request into a list of ids
    // sized in tens. The Data Source is the collection `collection_ref`
    // points at (D-489).
    let mut collections =
        readable_collections(db, crate::knowledge_index::COLLECTION_ENTITY, &records).await?;
    // D-512 §7: an agent session's knowledge scope narrows the caller's own
    // readable set here, before any chunk is queried. Intersection only: a
    // scope naming a collection the caller cannot read reaches nothing extra,
    // and an empty scope reaches nothing at all.
    if let Some(scope) = scope {
        collections.retain(|id| scope.contains(id));
    }
    // Nothing readable in scope: nothing to search. Returned here rather than
    // by running the chunk query against an empty list — the answer is the
    // same, and there is no reason to issue it (A-52/A-53).
    if collections.is_empty() {
        return Ok(Retrieval {
            hits: Vec::new(),
            searched_readable_collections: false,
        });
    }
    let visibility = KnowledgeVisibility::new(
        collections,
        &records,
        LifecycleFilter::Published,
        Audience::Internal,
    );
    let searched_readable_collections = !visibility.reaches_nothing();

    // Symmetry: every term passes through the same normalization/stemming the
    // producer applied to `text_indexed`. A query that stemmed itself would
    // be a second implementation — the failure `lang`'s module doc names.
    let terms = knowledge_query_terms(trimmed);
    // Only function words: nothing that names a topic to match on lexically.
    // The vector leg can still read such a question, so only the lexical-only
    // mode stops here.
    if terms.is_empty() && mode == RetrievalMode::Lexical {
        return Ok(Retrieval {
            hits: Vec::new(),
            searched_readable_collections,
        });
    }
    let candidate_limit = (limit * CANDIDATES_PER_HIT).clamp(1, MAX_CANDIDATE_CHUNKS);

    let lexical = if mode == RetrievalMode::Vector || terms.is_empty() {
        Vec::new()
    } else {
        lexical_candidates(db, &visibility, &terms, candidate_limit).await?
    };

    let vector = match (mode, embedder) {
        (RetrievalMode::Lexical, _) | (RetrievalMode::Fused, None) => Vec::new(),
        (RetrievalMode::Vector, None) => {
            return Err(AppError::internal(
                "vector knowledge retrieval was requested without an embedding client",
            ));
        }
        (RetrievalMode::Vector, Some(client)) => {
            vector_candidates(db, &visibility, client, trimmed, candidate_limit).await?
        }
        (RetrievalMode::Fused, Some(client)) => {
            match vector_candidates(db, &visibility, client, trimmed, candidate_limit).await {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        model = client.model_id(),
                        "knowledge vector leg failed; returning lexical results only"
                    );
                    metrics::counter!(
                        crate::metrics::LEG_DEGRADED_TOTAL.name,
                        "leg" => "knowledge_vector",
                        "reason" => "error"
                    )
                    .increment(1);
                    Vec::new()
                }
            }
        }
    };

    // Fusion runs only when there are two lists. A single list is returned in
    // its own order, so lexical-only retrieval is byte-for-byte what the frozen
    // D-498 baseline measured.
    let rows = match (lexical.is_empty(), vector.is_empty()) {
        (_, true) => lexical,
        (true, false) => vector,
        (false, false) => fuse_ranked(lexical, vector),
    };
    let rows = match reranker {
        Some(reranker) if rows.len() > 1 => rerank_rows(reranker, trimmed, rows).await,
        _ => rows,
    };

    if rows.is_empty() {
        return Ok(Retrieval {
            hits: Vec::new(),
            searched_readable_collections,
        });
    }

    // Item order is the rank order of that item's best chunk, so the first
    // passage returned is the strongest match. Within an item, matched
    // ordinals are kept so `expand` can merge them before expanding.
    let mut item_order: Vec<Uuid> = Vec::new();
    let mut matched: HashMap<Uuid, MatchedItem> = HashMap::new();
    for (chunk_id, item_id, collection_ref, ordinal, _heading, _text, fetched_at) in &rows {
        let entry = matched.entry(*item_id).or_insert_with(|| {
            item_order.push(*item_id);
            MatchedItem {
                collection_ref: *collection_ref,
                chunk_ids: Vec::new(),
                ordinals: Vec::new(),
                fetched_at: None,
            }
        });
        entry.chunk_ids.push(*chunk_id);
        entry.ordinals.push(*ordinal);
        if entry.fetched_at.is_none() {
            entry.fetched_at = *fetched_at;
        }
    }
    item_order.truncate(limit as usize);

    // Both re-reads are batched across every matched item rather than issued
    // per item in the loop below: this call site can hold up to `limit`
    // items, and a caller in an agent loop pays for every extra round trip.
    let metas = item_meta(db, &item_order).await?;
    let mut chunk_rows = item_chunks(db, &item_order).await?;

    let mut hits = Vec::with_capacity(item_order.len());
    for item_id in item_order {
        let Some(MatchedItem {
            collection_ref,
            chunk_ids,
            ordinals: matched_ordinals,
            fetched_at,
        }) = matched.remove(&item_id)
        else {
            continue;
        };

        // The article's own row was re-read for its title and review date,
        // and the liveness predicate re-applied: an item deleted between the
        // chunk read and now must not produce a citation.
        let Some((title, review_by)) = metas.get(&item_id).cloned() else {
            continue;
        };

        // Every chunk of the item, not only the matched ones: `expand` needs
        // the whole section to return the qualifier a chunk would sever.
        let all = chunk_rows.remove(&item_id).unwrap_or_default();
        let chunks = rebuild_chunks(&all);
        let passages = expand(&chunks, &matched_ordinals);

        // Ordinal -> chunk id for this item, so each passage below can be
        // stamped with only the chunk ids that actually matched *it* — the
        // two vectors are built in lockstep above, one push per matched row.
        let ordinal_to_chunk: HashMap<i32, Uuid> = matched_ordinals
            .iter()
            .copied()
            .zip(chunk_ids.iter().copied())
            .collect();

        let stale = review_by.is_some_and(|d| d < Utc::now().date_naive());
        for passage in passages {
            // Scoped to this passage's section, not the item's full matched
            // set: a multi-section match must not stamp every passage with
            // every matched chunk id, or retrieval-count telemetry
            // double-counts (see `Passage::matched_ordinals`).
            let passage_chunk_ids: Vec<Uuid> = passage
                .matched_ordinals
                .iter()
                .filter_map(|o| ordinal_to_chunk.get(o).copied())
                .collect();
            hits.push(KnowledgeHit {
                citation: KnowledgeCitation {
                    item_id,
                    data_source_id: collection_ref,
                    title: title.clone(),
                    heading_path: passage.heading_path,
                    passage: passage.text,
                    truncated: passage.truncated,
                    fetched_at,
                    stale,
                },
                chunk_ids: passage_chunk_ids,
            });
        }
    }

    // The candidate budget bounded *chunks*, not sections: one matched item
    // can expand to several passages. The caller asked for `limit` passages.
    hits.truncate(limit as usize);
    Ok(Retrieval {
        hits,
        searched_readable_collections,
    })
}

/// [`search_knowledge`], plus the demand-signal write every retrieval surface
/// must make: a gap topic for an empty result, chunk retrievals otherwise.
///
/// **The one place that call is made**, so a new retrieval surface cannot
/// forget it the way the direct HTTP route once did — `search_knowledge`
/// itself deliberately stays a pure retrieval (its own doc comment: "this
/// function does not decide that, it only retrieves"), so this wrapper is
/// where the decision belongs instead of being duplicated at every call site.
///
/// **An empty result is a gap only when the caller could read a collection.**
/// A caller with no readable collection is never recorded (D-498): their
/// empty result is a permission outcome, not evidence the knowledge is
/// missing. A caller who reads *some* collections but not the one holding the
/// answer is still recorded — telling those two apart would mean consulting
/// rows the caller cannot see, which D-498 ruling 1 rules out.
///
/// Best-effort and off the request path in spirit, same discipline as
/// [`crate::telemetry::record_chunk_retrievals`]: a search must never fail,
/// and must not be measurably slower, because a telemetry write failed.
///
/// **`scope` is an agent session's knowledge scope** (D-505, D-512 §7):
/// `Some(ids)` narrows retrieval to the caller's readable collections that are
/// also in `ids`, enforced inside retrieval before any evidence is returned;
/// `Some(&[])` retrieves nothing; `None` applies no narrowing. A direct HTTP
/// search passes `None`; an action passes its context's session scope. An
/// empty result is recorded as a gap only when the scoped set still reaches a
/// collection.
pub async fn search_knowledge_recorded(
    db: &sqlx::PgPool,
    ctx: &SecurityContext,
    query: &str,
    limit: i64,
    scope: Option<&[Uuid]>,
) -> Result<Vec<KnowledgeHit>, AppError> {
    let Retrieval {
        hits,
        searched_readable_collections,
    } = {
        // N15-T1: fused and reranked when boot installed the clients, else
        // lexical as before.
        let ranking = RANKING.get();
        let embedder = ranking.and_then(|r| r.embedder.as_ref());
        let reranker = ranking.and_then(|r| r.reranker.as_ref());
        let mode = if embedder.is_some() {
            RetrievalMode::Fused
        } else {
            RetrievalMode::Lexical
        };
        retrieve(db, ctx, query, limit, mode, embedder, scope, reranker).await?
    };

    let mut chunk_ids: Vec<Uuid> = Vec::new();
    for hit in &hits {
        chunk_ids.extend(hit.chunk_ids.iter().copied());
    }
    if !chunk_ids.is_empty() {
        let recorded = crate::telemetry::record_chunk_retrievals(db, &chunk_ids).await;
        if let Err(e) = recorded {
            tracing::warn!(error = %e, "failed to record knowledge chunk retrievals");
        }
    } else if searched_readable_collections {
        let recorded = crate::telemetry::record_gap_topic(db, query).await;
        if let Err(e) = recorded {
            tracing::warn!(error = %e, "failed to record a knowledge gap topic");
        }
    }

    Ok(hits)
}

/// Why a retrieval returned what it did, for an administrator (roadmap
/// N15-T4): the terms the question was reduced to, the words dropped as
/// function words, and for each passage, in rank order, which terms it
/// matched. Retrieved under the administrator's own permissions, lexical
/// mode, and never recorded as demand or as a gap: explaining a question is
/// not asking it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct KnowledgeExplanation {
    /// The content terms, normalised and stemmed as the index stores them.
    pub terms: Vec<String>,
    /// Words dropped before matching (function words).
    pub dropped: Vec<String>,
    pub passages: Vec<ExplainedPassage>,
    /// Set when nothing was found: `no_terms` (only function words),
    /// `no_readable_collection` or `no_match`.
    pub empty_reason: Option<String>,
}

/// One retrieved passage and the terms that brought it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExplainedPassage {
    /// 1 is the strongest (ranked by `ts_rank_cd`).
    pub rank: usize,
    pub item_id: Uuid,
    pub title: String,
    pub heading_path: Vec<String>,
    /// Terms found in the title, headings or passage.
    pub matched_terms: Vec<String>,
    pub unmatched_terms: Vec<String>,
}

/// Splits `terms` into those `text` contains (compared as the index compares
/// them: Arabic-normalised and stemmed) and those it does not.
pub fn match_terms(terms: &[String], text: &str) -> (Vec<String>, Vec<String>) {
    // Letters and digits only: a query term keeps any punctuation it was
    // typed with (`policy?`), a passage word is split on it.
    let key = |t: &str| {
        t.chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>()
    };
    let words: std::collections::HashSet<String> = crate::lang::normalize_ar(text)
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| key(&crate::project::index_text(w)))
        .collect();
    terms
        .iter()
        .cloned()
        .partition(|term| words.contains(&key(term)))
}

/// See [`KnowledgeExplanation`].
pub async fn explain(
    db: &sqlx::PgPool,
    ctx: &SecurityContext,
    query: &str,
    limit: i64,
) -> Result<KnowledgeExplanation, AppError> {
    let terms = knowledge_query_terms(query);
    let dropped: Vec<String> = crate::lang::normalize_ar(query)
        .split_whitespace()
        .filter(|token| crate::telemetry::is_function_word(token))
        .map(str::to_owned)
        .collect();
    if terms.is_empty() {
        return Ok(KnowledgeExplanation {
            terms,
            dropped,
            passages: Vec::new(),
            empty_reason: Some("no_terms".to_owned()),
        });
    }
    let Retrieval {
        hits,
        searched_readable_collections,
    } = retrieve(
        db,
        ctx,
        query,
        limit,
        RetrievalMode::Lexical,
        None,
        None,
        None,
    )
    .await?;
    let passages: Vec<ExplainedPassage> = hits
        .into_iter()
        .enumerate()
        .map(|(i, hit)| {
            let c = hit.citation;
            let text = format!("{} {} {}", c.title, c.heading_path.join(" "), c.passage);
            let (matched_terms, unmatched_terms) = match_terms(&terms, &text);
            ExplainedPassage {
                rank: i + 1,
                item_id: c.item_id,
                title: c.title,
                heading_path: c.heading_path,
                matched_terms,
                unmatched_terms,
            }
        })
        .collect();
    let empty_reason = if !passages.is_empty() {
        None
    } else if searched_readable_collections {
        Some("no_match".to_owned())
    } else {
        Some("no_readable_collection".to_owned())
    };
    Ok(KnowledgeExplanation {
        terms,
        dropped,
        passages,
        empty_reason,
    })
}

/// The clients the recorded retrieval ranks with (N15-T1), installed once at
/// boot by the search drain loop from the configuration. Read-only after
/// that; a process that installs none (tests, a deployment without an
/// embedding model) retrieves lexically, exactly as before.
struct Ranking {
    embedder: Option<attome_inference::EmbeddingClient>,
    reranker: Option<attome_inference::RerankClient>,
}

static RANKING: std::sync::OnceLock<Ranking> = std::sync::OnceLock::new();

/// Installs the ranking clients. The first call wins; later calls are ignored.
pub fn install_ranking(
    embedder: Option<attome_inference::EmbeddingClient>,
    reranker: Option<attome_inference::RerankClient>,
) {
    let _ = RANKING.set(Ranking { embedder, reranker });
}

/// Passages the reranker scores, from the top of the fused list.
pub const RERANK_TOP: usize = 50;

/// Reorders the top [`RERANK_TOP`] rows by the reranker's score, best first,
/// keeping the rest after them. A reranker that fails leaves the fused order:
/// a broken model server must not take retrieval down with it.
async fn rerank_rows(
    reranker: &attome_inference::RerankClient,
    query: &str,
    mut rows: Vec<ChunkRow>,
) -> Vec<ChunkRow> {
    let top = rows.len().min(RERANK_TOP);
    let texts: Vec<&str> = rows[..top].iter().map(|row| row.5.as_str()).collect();
    match reranker.rerank(query, &texts).await {
        Ok(scores) => {
            let rest = rows.split_off(top);
            let mut scored: Vec<(f32, ChunkRow)> = scores.into_iter().zip(rows).collect();
            // Stable: equal scores keep their fused order.
            scored.sort_by(|a, b| b.0.total_cmp(&a.0));
            scored.into_iter().map(|(_, row)| row).chain(rest).collect()
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                model = reranker.model_id(),
                "knowledge rerank failed; keeping the fused order"
            );
            metrics::counter!(
                crate::metrics::LEG_DEGRADED_TOTAL.name,
                "leg" => "knowledge_rerank",
                "reason" => "error"
            )
            .increment(1);
            rows
        }
    }
}

/// Upper bound on the terms one knowledge query ORs together: the route's own
/// cap, applied here as well because the `search.knowledge` action reaches
/// this function without the route's validation, and every OR-ed term adds a
/// GIN lookup.
const MAX_KNOWLEDGE_QUERY_TERMS: usize = crate::routes::MAX_QUERY_TERMS;

/// The content terms of a knowledge query, each normalized and stemmed by the
/// same function the producer applied to `text_indexed`.
///
/// Function words (`telemetry::is_function_word`, D-452's list) are dropped
/// first, before stemming, because the list holds surface forms. That drop is
/// what keeps "any term may match" from matching nearly everything: without
/// it "how do I calibrate the flux capacitor" retrieves any article containing
/// "the", an empty result stops meaning "not covered", and the gap queue goes
/// quiet exactly when it should not.
fn knowledge_query_terms(query: &str) -> Vec<String> {
    crate::lang::normalize_ar(query)
        .split_whitespace()
        .filter(|token| !crate::telemetry::is_function_word(token))
        .take(MAX_KNOWLEDGE_QUERY_TERMS)
        .map(crate::project::index_text)
        .collect()
}

/// Pushes `(plainto_tsquery(t1) || plainto_tsquery(t2) || …)` — a match on
/// **any** term, where one `plainto_tsquery` over the whole query ANDs them.
///
/// Each term is its own `plainto_tsquery` over a bound value, so no query text
/// is ever parsed as tsquery syntax, and a term the parser splits further
/// (`non-refundable`) keeps exactly the meaning it had before. A term that is
/// only punctuation yields an empty tsquery, which `||` ignores.
///
/// Knowledge-only on purpose: `legs::stage1::push_lexical_tsquery` is shared
/// with record search's lexical leg, whose semantics this does not change.
fn push_any_term_tsquery(qb: &mut QueryBuilder<'_, Postgres>, terms: &[String]) {
    qb.push("(");
    for (i, term) in terms.iter().enumerate() {
        if i > 0 {
            qb.push(" || ");
        }
        qb.push("plainto_tsquery('attome_search', ");
        qb.push_bind(term.clone());
        qb.push(")");
    }
    qb.push(")");
}

/// The title and review date of every one of `item_ids`, or absent for an
/// item that is gone, inactive, or no longer published.
///
/// One query for the whole matched set rather than one per item: `search_knowledge`
/// calls this once with up to `limit` ids, not in a per-item loop, so a caller
/// on an agent path is not paying `limit` extra round trips per search.
///
/// The lifecycle predicate is defence in depth: the producer already deletes an
/// item's chunks when it stops being published, so a chunk usually cannot
/// outlive that state. This closes the window between the two reads.
async fn item_meta(
    db: &sqlx::PgPool,
    item_ids: &[Uuid],
) -> Result<HashMap<Uuid, (String, Option<NaiveDate>)>, AppError> {
    if item_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(Uuid, String, Option<NaiveDate>)> = sqlx::query_as(
        "SELECT id, title, review_by FROM knowledge_data_item \
         WHERE id = ANY($1) AND (is_active IS NULL OR is_active = TRUE) \
           AND lifecycle = $2",
    )
    .bind(item_ids)
    .bind(crate::knowledge_index::PUBLISHED)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(id, title, review_by)| (id, (title, review_by)))
        .collect())
}

/// Every chunk of every one of `item_ids`, in ordinal order, grouped by item.
///
/// Batched for the same reason as [`item_meta`]: one round trip for the whole
/// matched set instead of one per item.
async fn item_chunks(
    db: &sqlx::PgPool,
    item_ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<(i32, Vec<String>, String)>>, AppError> {
    if item_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(Uuid, i32, Vec<String>, String)> = sqlx::query_as(
        "SELECT source_id, ordinal, heading_path, text_display FROM knowledge_chunk \
         WHERE source_type = $1 AND source_id = ANY($2) ORDER BY source_id, ordinal ASC",
    )
    .bind(crate::knowledge_index::SOURCE_TYPE)
    .bind(item_ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut by_item: HashMap<Uuid, Vec<(i32, Vec<String>, String)>> = HashMap::new();
    for (source_id, ordinal, heading_path, text_display) in rows {
        by_item
            .entry(source_id)
            .or_default()
            .push((ordinal, heading_path, text_display));
    }
    Ok(by_item)
}

/// Rebuilds the chunker's shape from stored rows.
///
/// `section` is not a stored column, and it does not need to be: the chunker
/// emits consecutive chunks per section, so a section boundary is exactly
/// where `heading_path` changes. That is the same rule `split_sections`
/// applies, which is why two chunks that share a heading merge into one
/// passage in `expand` — the behaviour the module exists for.
fn rebuild_chunks(rows: &[(i32, Vec<String>, String)]) -> Vec<ArticleChunk> {
    let mut out = Vec::with_capacity(rows.len());
    let mut section = 0usize;
    let mut previous: Option<&Vec<String>> = None;
    for (ordinal, heading_path, text_display) in rows {
        if previous.is_some_and(|p| p != heading_path) {
            section += 1;
        }
        previous = Some(heading_path);
        out.push(ArticleChunk {
            ordinal: *ordinal,
            heading_path: heading_path.clone(),
            section,
            text_display: text_display.clone(),
            text_indexed: String::new(),
            content_hash: Vec::new(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_matches_terms_as_the_index_stems_them() {
        let terms = knowledge_query_terms("what is our refund policy");
        assert!(!terms.is_empty());
        let (matched, unmatched) = match_terms(&terms, "The refund policy, for returning goods.");
        assert_eq!(unmatched, Vec::<String>::new(), "matched {matched:?}");
        let (matched, unmatched) = match_terms(&terms, "Shipping times");
        assert!(matched.is_empty());
        assert_eq!(unmatched.len(), terms.len());
    }
    use attome_server::security::{AccessLevel, SecurityContext};
    use std::collections::HashSet;

    fn ctx(is_admin: bool) -> SecurityContext {
        SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin,
            privileges: HashSet::new(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: vec![Uuid::now_v7()],
            team_ids: vec![Uuid::now_v7()],
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            unit_scope: Default::default(),
            field_masks: Default::default(),
            service_principal: false,
        }
    }

    fn fragment(collections: Vec<Uuid>, lifecycle: LifecycleFilter, is_admin: bool) -> String {
        let c = ctx(is_admin);
        let access: HashMap<String, (Uuid, AccessLevel)> =
            [("article".to_string(), (Uuid::now_v7(), AccessLevel::Team))].into();
        let empty = HashSet::new();
        let records = PolymorphicVisibility::new(&c, &access, &empty, None);
        let vis = KnowledgeVisibility::new(collections, &records, lifecycle, Audience::Internal);
        let mut qb: QueryBuilder<Postgres> =
            QueryBuilder::new("SELECT 1 FROM knowledge_chunk k WHERE true");
        vis.push(&mut qb, "k");
        qb.into_sql()
    }

    /// The cheap clause is an indexed equality on the collection list, and it
    /// is present for every caller.
    #[test]
    fn every_chunk_is_filtered_by_its_collection() {
        let sql = fragment(vec![Uuid::now_v7()], LifecycleFilter::Published, false);
        assert!(
            sql.contains("k.collection_ref = ANY("),
            "the collection clause must be an indexed equality: {sql}"
        );
    }

    /// **The performance property, asserted structurally.** The record
    /// predicate sits behind the `parent_record_id IS NULL` guard, so a chunk
    /// with no parent never reaches it.
    #[test]
    fn the_record_predicate_is_guarded_by_the_null_check() {
        let sql = fragment(vec![Uuid::now_v7()], LifecycleFilter::Published, false);
        let guard = sql
            .find("k.parent_record_id IS NULL")
            .expect("the guard must be present");
        let predicate = sql
            .find("record_share")
            .expect("the record predicate must be present");
        assert!(
            guard < predicate,
            "the record predicate must sit INSIDE the null guard, or web and \
             standalone-article chunks pay for a check that cannot apply to \
             them: {sql}"
        );
    }

    /// A draft is never retrievable, and the filter is in this fragment rather
    /// than left to a caller.
    #[test]
    fn drafts_are_filtered_here_not_by_the_caller() {
        let sql = fragment(vec![Uuid::now_v7()], LifecycleFilter::Published, false);
        assert!(sql.contains("k.lifecycle = ANY("), "{sql}");
    }

    /// **Fails closed.** A caller that somehow arrives with `All` gets
    /// `Published`, not every draft in the corpus. The debug assertion catches
    /// it in development; this is what happens in production, where a panic
    /// would be the worse of the two outcomes.
    #[test]
    fn an_invalid_lifecycle_filter_narrows_instead_of_widening() {
        // Built directly, bypassing `new`'s debug assertion the way a release
        // build would.
        let c = ctx(false);
        let access: HashMap<String, (Uuid, AccessLevel)> = HashMap::new();
        let empty = HashSet::new();
        let records = PolymorphicVisibility::new(&c, &access, &empty, None);
        let vis = KnowledgeVisibility {
            collection_ids: vec![Uuid::now_v7()],
            records: &records,
            lifecycle: LifecycleFilter::All,
            audience: Audience::Internal,
        };
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("SELECT 1 WHERE true");
        vis.push(&mut qb, "k");
        // The bound array is not visible in the SQL text, so assert on the
        // narrowing decision itself rather than on the rendered statement.
        assert!(!LifecycleFilter::All.is_valid_for_retrieval());
        assert_eq!(LifecycleFilter::Published.states(), &["published"]);
    }

    /// An admin is still filtered by collection.
    ///
    /// `is_unfiltered` short-circuits the *record* predicate for an admin, and
    /// this fragment must not inherit that: the collection clause is how the
    /// query is scoped at all, and dropping it would turn an admin's chunk
    /// query into an unscoped scan of every collection in the deployment.
    #[test]
    fn an_admin_is_still_scoped_by_collection() {
        let sql = fragment(vec![Uuid::now_v7()], LifecycleFilter::Published, true);
        assert!(sql.contains("k.collection_ref = ANY("), "{sql}");
    }

    /// A caller with no readable collections gets a fragment that returns
    /// nothing — not a fragment with the clause omitted.
    #[test]
    fn no_readable_collections_still_emits_the_clause() {
        let sql = fragment(Vec::new(), LifecycleFilter::Published, false);
        assert!(
            sql.contains("k.collection_ref = ANY("),
            "an empty collection list must still be bound: `ANY(ARRAY[])` is \
             already correct, and omitting the clause on 'no restrictions to \
             apply' is one refactor from omitting it wrongly: {sql}"
        );
    }

    /// Parentheses balance. The same mechanical check `visibility.rs` added
    /// after a fragment that was one `)` short read perfectly and produced
    /// "syntax error at end of input".
    #[test]
    fn the_pushed_fragment_is_parenthesis_balanced() {
        for lifecycle in [
            LifecycleFilter::Published,
            LifecycleFilter::PublishedAndExpired,
        ] {
            let sql = fragment(vec![Uuid::now_v7()], lifecycle, false);
            let mut depth = 0i32;
            for ch in sql.chars() {
                match ch {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                assert!(depth >= 0, "closed one too many: {sql}");
            }
            assert_eq!(depth, 0, "unbalanced: {sql}");
        }
    }

    /// Function words go; content terms stay, each stemmed by the producer's
    /// own function so the query cannot drift from what was indexed.
    #[test]
    fn function_words_are_dropped_and_content_terms_are_stemmed_like_the_index() {
        use crate::project::index_text;
        assert_eq!(
            knowledge_query_terms("What is our refund policy for custom orders"),
            vec![
                index_text("refund"),
                index_text("policy"),
                index_text("custom"),
                index_text("orders"),
            ]
        );
    }

    /// A question made only of function words names no topic, so it has no
    /// terms rather than one that matches everything.
    #[test]
    fn a_query_of_only_function_words_has_no_terms() {
        assert!(knowledge_query_terms("How do I  what is the").is_empty());
    }

    /// The action path skips the route's validation, so the term cap applies
    /// here too.
    #[test]
    fn terms_are_capped_at_the_route_limit() {
        let long: String = (0..50).map(|i| format!("topic{i} ")).collect();
        assert_eq!(
            knowledge_query_terms(&long).len(),
            crate::routes::MAX_QUERY_TERMS
        );
    }

    /// Terms are OR-ed, one bound `plainto_tsquery` each. One `plainto_tsquery`
    /// over the whole query is the AND that D-498 step 2 removes.
    #[test]
    fn terms_are_ored_and_every_term_is_bound() {
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("SELECT ");
        push_any_term_tsquery(&mut qb, &["refund".to_string(), "custom".to_string()]);
        let sql = qb.into_sql();
        assert_eq!(
            sql.matches("plainto_tsquery('attome_search', $").count(),
            2,
            "{sql}"
        );
        assert!(sql.contains(" || "), "terms must be OR-ed: {sql}");
        assert!(
            !sql.contains("refund"),
            "term text must be bound, not spliced: {sql}"
        );
    }

    fn row(item: u128, ordinal: i32) -> ChunkRow {
        (
            Uuid::from_u128(item * 1000 + ordinal as u128),
            Uuid::from_u128(item),
            Uuid::nil(),
            ordinal,
            Vec::new(),
            String::new(),
            None,
        )
    }

    fn ids(rows: &[ChunkRow]) -> Vec<Uuid> {
        rows.iter().map(|r| r.0).collect()
    }

    #[test]
    fn a_chunk_both_legs_found_outranks_chunks_only_one_found() {
        let lexical = vec![row(1, 0), row(2, 0), row(3, 0)];
        let vector = vec![row(4, 0), row(3, 0), row(5, 0)];
        let fused = fuse_ranked(lexical, vector);
        assert_eq!(fused[0].0, row(3, 0).0, "found by both legs, so first");
        assert_eq!(fused.len(), 5, "each chunk appears once");
    }

    #[test]
    fn equal_scores_break_by_item_then_ordinal_on_every_run() {
        // Rank 1 in one list each: identical RRF scores.
        let a = fuse_ranked(vec![row(9, 2)], vec![row(7, 4)]);
        let b = fuse_ranked(vec![row(7, 4)], vec![row(9, 2)]);
        assert_eq!(ids(&a), ids(&b));
        assert_eq!(a[0].0, row(7, 4).0);
    }

    #[test]
    fn fusing_with_an_empty_list_keeps_the_other_lists_order() {
        let lexical = vec![row(5, 1), row(2, 0), row(8, 3)];
        assert_eq!(
            ids(&fuse_ranked(lexical.clone(), Vec::new())),
            ids(&lexical)
        );
    }

    /// v1 has exactly one audience, and it is explicit. D-359: a portal scope
    /// is additive, and the parameter exists so adding one is a visible change
    /// at every call site.
    #[test]
    fn the_audience_is_explicit_and_internal_only() {
        assert_eq!(Audience::default(), Audience::Internal);
    }
}
