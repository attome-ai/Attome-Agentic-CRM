//! Impression and interaction logging (TODO-021), and the query fingerprint
//! that keeps raw query text out of it (TODO-019).
//!
//! **Unbackfillable.** Every later ranking improvement, and any online
//! evaluation at all, trains on logs kept from day one. "Which results were
//! shown, in what order, and which one did the user pick" cannot be
//! reconstructed later — the ranking that produced them no longer exists, and
//! neither does the user's intent. Deferring this does not delay learned
//! ranking; it forecloses it.
//!
//! **Off the request path, always.** A search must never be slower, and must
//! never *fail*, because telemetry is unavailable. Every write here is spawned
//! by the caller and its failure is logged and dropped: losing one data point
//! is a bad day, failing a user's search because a log table is locked is a
//! worse product.

use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::lang::normalize_ar;

/// Bytes of the query fingerprint.
pub const FINGERPRINT_LEN: usize = 16;

/// How query text is classified under the platform's **existing** scheme
/// (migration `0087`), not a new one invented for search.
///
/// `Personal`, not `General`: a query is whatever the user typed into a box
/// next to a customer list, which in practice is names, phone numbers,
/// national IDs, and reference codes. It is not
/// `SensitiveSpecialCategory` — that narrower tier is health, religion,
/// biometric, and criminal-record data, and a query only *sometimes* contains
/// those. Over-classifying would put every search under handling rules meant
/// for the strictest category and, predictably, get the classification
/// switched off.
///
/// The operative consequence is already enforced everywhere it matters:
/// **query text is never stored and never logged.** The impression log holds
/// only [`query_fingerprint`]'s output, and `attome_server::app::request_span`
/// records `uri.path()` alone (asserted by
/// `the_request_span_never_records_a_query_string`). This constant exists so
/// the classification is stated in code rather than inferred, and so a future
/// feature that wants to retain queries has to argue with it first.
pub const QUERY_TEXT_CLASSIFICATION: attome_core::DataClassification =
    attome_core::DataClassification::Personal;

/// Derives the fingerprint key for this deployment.
///
/// Domain-separated from whatever secret it is handed, so the key used here
/// cannot be confused with — or used to attack — the secret's primary purpose.
/// A dedicated config value would be marginally cleaner and would also be one
/// more required secret every deployment has to provision before search works
/// at all; deriving keeps search from adding a boot requirement, and the
/// separator makes the derivation explicit rather than incidental.
///
/// This key never leaves the data plane and is never stored with the
/// fingerprints, which is what makes the fingerprints useless outside it.
pub fn derive_fingerprint_key(deployment_secret: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    // Null-terminated: the separator must be a byte that cannot appear at
    // the end of the label, or two different labels could produce the same
    // hash input.
    hasher.update(b"attome/search/query-fingerprint/v1\x00");
    hasher.update(deployment_secret.as_bytes());
    hasher.finalize().to_vec()
}

/// Hashes a query so the log can group by it without retaining it.
///
/// **Keyed**, not a bare hash. An unkeyed hash of a short, low-entropy string
/// is not anonymisation: the space of plausible customer names is small enough
/// to enumerate, so anyone with the log and a name list can recover the
/// queries. The deployment's own secret makes that infeasible without it, and
/// keeps the fingerprint useless outside the plane it was computed in.
///
/// The query is normalized first, so `مُحَمَّد` and `محمد` produce the same
/// fingerprint. That is not incidental — grouping by fingerprint is meant to
/// answer "did this *query* get clicked differently", and two spellings of one
/// name are one query.
pub fn query_fingerprint(raw_query: &str, key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(b"\x00query\x00");
    hasher.update(normalize_ar(raw_query).as_bytes());
    hasher.finalize()[..FINGERPRINT_LEN].to_vec()
}

/// One row as it was shown.
pub struct ImpressionRow {
    pub rank: i32,
    pub entity_logicalname: String,
    pub record_id: Uuid,
    /// The ranking signals **as at display time**. See the migration's comment
    /// for why these are stored rather than recomputed.
    pub feature_vector: serde_json::Value,
}

impl std::fmt::Debug for ImpressionRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImpressionRow").finish_non_exhaustive()
    }
}

/// One search, as it was served.
pub struct Impression<'a> {
    pub query_fingerprint: Vec<u8>,
    pub route: &'a str,
    pub ranker_id: &'a str,
    pub audience: &'a str,
    /// Per-leg completeness from the fused statement. A degraded impression is
    /// evidence the retrieval was incomplete, not that the ranking was bad —
    /// and a training set that conflates the two teaches a ranker to
    /// compensate for outages.
    pub completeness: serde_json::Value,
    pub caller_ref: Option<Uuid>,
    pub organization_ref: Option<Uuid>,
    pub latency_ms: Option<i32>,
    pub rows: Vec<ImpressionRow>,
}

impl std::fmt::Debug for Impression<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Impression").finish_non_exhaustive()
    }
}

/// Records one impression and its rows.
///
/// One transaction: an impression whose rows failed to write is worse than no
/// impression, because it looks like a search that returned nothing and would
/// be read as a zero-result event.
pub async fn record_impression(db: &PgPool, impression: &Impression<'_>) -> Result<Uuid, AppError> {
    record_impression_with_id(db, Uuid::now_v7(), impression).await
}

/// Records an impression under an id the caller already holds.
///
/// The handler needs the id **synchronously** — the response carries it so a
/// later click can be reported against it — while the write itself is spawned
/// and not awaited. Generating the id in Rust rather than letting the column
/// default to `uuidv7()` is what makes those two facts compatible; without it
/// the response could only carry an id by waiting for the write, which is
/// exactly what "off the request path" rules out.
pub async fn record_impression_with_id(
    db: &PgPool,
    id: Uuid,
    impression: &Impression<'_>,
) -> Result<Uuid, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO search_impression \
            (id, query_fingerprint, route, ranker_id, audience, completeness, \
             caller_ref, organization_ref, result_count, latency_ms) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
    )
    .bind(id)
    .bind(&impression.query_fingerprint)
    .bind(impression.route)
    .bind(impression.ranker_id)
    .bind(impression.audience)
    .bind(&impression.completeness)
    .bind(impression.caller_ref)
    .bind(impression.organization_ref)
    .bind(impression.rows.len() as i32)
    .bind(impression.latency_ms)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    if !impression.rows.is_empty() {
        // One multi-row insert. A loop would be one round trip per displayed
        // result, on a path that must not be measurable.
        let ranks: Vec<i32> = impression.rows.iter().map(|r| r.rank).collect();
        let entities: Vec<String> = impression
            .rows
            .iter()
            .map(|r| r.entity_logicalname.clone())
            .collect();
        let record_ids: Vec<Uuid> = impression.rows.iter().map(|r| r.record_id).collect();
        let features = serde_json::Value::Array(
            impression
                .rows
                .iter()
                .map(|r| r.feature_vector.clone())
                .collect(),
        );

        sqlx::query(
            "INSERT INTO search_impression_row \
                (impression_ref, rank, entity_logicalname, record_id, feature_vector) \
             SELECT $1, u.rank, u.entity, u.record_id, $5::jsonb -> (u.ord - 1)::int \
             FROM unnest($2::int[], $3::text[], $4::uuid[]) \
                  WITH ORDINALITY AS u(rank, entity, record_id, ord)",
        )
        .bind(id)
        .bind(&ranks)
        .bind(&entities)
        .bind(&record_ids)
        .bind(&features)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }

    tx.commit().await.map_err(AppError::internal)?;
    Ok(id)
}

/// Records that the caller acted on a result.
///
/// `dwell_ms` is optional because it arrives later than the click and often
/// never — a caller who navigates away gives no closing signal. Recording the
/// click without it is still worth having; refusing to record until dwell is
/// known would silently drop most interactions.
pub async fn record_interaction(
    db: &PgPool,
    impression_ref: Uuid,
    rank: i32,
    entity_logicalname: &str,
    record_id: Uuid,
    dwell_ms: Option<i32>,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO search_interaction \
            (impression_ref, rank, entity_logicalname, record_id, dwell_ms) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(impression_ref)
    .bind(rank)
    .bind(entity_logicalname)
    .bind(record_id)
    .bind(dwell_ms)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

// ── M37 Phase 2: chunk retrieval telemetry (D-452) ─────────────────────────
//
// **No production caller yet.** `search.knowledge` is not a registered
// `ActionDescriptor` (`attome-ai/src/actions/mod.rs`) — the chat retrieval
// loop this function is meant to be called from does not exist in this
// workspace today (verified 2026-08-28, D-452). It is built and tested now
// so that work has a landing spot: once a caller assembles chunk results for
// an answer, it calls this once per turn with every chunk actually handed to
// the model (not merely fetched from the DB before ranking/floor-filtering —
// D-452's whole point is a genuine usage count, not a query-volume proxy).

/// Records that each of these chunks was retrieved and used in an answer.
///
/// **Off the request path**, same discipline as [`record_impression`]: a
/// search/answer must never be slower, and must never fail, because
/// telemetry is unavailable. Callers should `tokio::spawn` this rather than
/// await it inline — it is not spawned here because spawning needs a
/// `'static` future and this function borrows `chunk_ids`; the caller owns
/// the ids already and can clone them into the spawned task trivially.
///
/// No query text, no fingerprint, no caller identity — only which chunks
/// were used and when. See D-452 for why that boundary is structural
/// (a separate table, `knowledge_chunk_retrieval`) rather than a
/// column added onto a table that also carries text.
pub async fn record_chunk_retrievals(db: &PgPool, chunk_ids: &[Uuid]) -> Result<(), AppError> {
    if chunk_ids.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO knowledge_chunk_retrieval (chunk_ref) \
         SELECT * FROM unnest($1::uuid[])",
    )
    .bind(chunk_ids)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Retrieval counts since `since`, grouped by the chunk's source record —
/// the rollup composition step's only query into this crate's tables.
///
/// Grouped by `source_id` rather than by chunk: a page is chunked into many
/// rows, and `content_page_stats.retrievals` is a per-*page* count. Only
/// `source_type = 'article'` is counted — web and attachment chunks have no
/// `content_page` row for the composition step to attribute them to.
pub async fn retrieval_counts_by_source(
    db: &PgPool,
    since: DateTime<Utc>,
) -> Result<HashMap<Uuid, i64>, AppError> {
    let rows: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT k.source_id, COUNT(*) \
         FROM knowledge_chunk_retrieval r \
         JOIN knowledge_chunk k ON k.id = r.chunk_ref \
         WHERE k.source_type = 'article' AND r.retrieved_at >= $1 \
         GROUP BY k.source_id",
    )
    .bind(since)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().collect())
}

// ── M37 Phase 2: knowledge-gap topic logging (D-452) ───────────────────────

/// A small, fixed stopword list — English and Arabic function words that
/// carry no topic signal. Not exhaustive by design (D-452): the digit/shape
/// rules in [`normalize_gap_phrase`] carry the actual privacy weight, not
/// this list.
const GAP_STOPWORDS: &[&str] = &[
    "the",
    "a",
    "an",
    "is",
    "are",
    "do",
    "does",
    "did",
    "how",
    "what",
    "why",
    "when",
    "where",
    "i",
    "my",
    "our",
    "your",
    "of",
    "to",
    "for",
    "and",
    "or",
    "on",
    "in",
    "at",
    "can",
    "you",
    "please",
    "می",
    "في",
    "من",
    "هل",
    "كيف",
    "ما",
    "لماذا",
    "متى",
    "أين",
];

/// Whether `token`, already passed through [`normalize_ar`], is one of the
/// function words above.
///
/// Shared with knowledge retrieval (`knowledge::knowledge_query_terms`), which
/// drops the same words before OR-ing a question's remaining terms: one list
/// of "words that carry no topic signal" for this crate, so a word the gap
/// queue discards as noise is never the only thing a retrieval matched on.
pub(crate) fn is_function_word(token: &str) -> bool {
    GAP_STOPWORDS.contains(&token)
}

/// Maximum tokens kept in a stored gap phrase (D-452 step 5).
const GAP_PHRASE_MAX_TOKENS: usize = 6;
/// Hard byte cap on the stored phrase (D-452 step 5), a backstop behind the
/// token cap for a language whose words run long.
const GAP_PHRASE_MAX_BYTES: usize = 80;
/// Below this many surviving tokens, nothing is stored (D-452 step 6).
const GAP_PHRASE_MIN_TOKENS: usize = 2;
/// A token longer than this with no internal whitespace is treated as an
/// identifier/pasted-token shape, not a topic word (D-452 step 4).
const GAP_TOKEN_IDENTIFIER_LEN: usize = 24;

/// D-452's best-effort topic scrubber. Returns `None` when what survives is
/// too short to be a useful, sufficiently-scrubbed topic — the caller must
/// treat `None` as "do not store anything", not as an error.
///
/// **Not a redaction guarantee.** An ordinary-looking name in sentence
/// position ("is Fatima Al-Rashid allowed remote access") is not caught by
/// any rule here. D-452 records why that residual risk is accepted
/// (`Personal` classification, admin-only queue) rather than pretending this
/// function achieves anonymisation the way [`query_fingerprint`] does for
/// the impression log.
pub fn normalize_gap_phrase(raw_query: &str) -> Option<String> {
    let normalized = normalize_ar(raw_query);
    let tokens: Vec<&str> = normalized
        .split_whitespace()
        .filter(|t| !GAP_STOPWORDS.contains(t))
        .filter(|t| !t.chars().any(|c| c.is_ascii_digit()))
        .filter(|t| !t.contains('@'))
        .filter(|t| t.chars().count() <= GAP_TOKEN_IDENTIFIER_LEN)
        .take(GAP_PHRASE_MAX_TOKENS)
        .collect();

    if tokens.len() < GAP_PHRASE_MIN_TOKENS {
        return None;
    }

    let mut phrase = tokens.join(" ");
    if phrase.len() > GAP_PHRASE_MAX_BYTES {
        // Truncate on a char boundary, never mid-character.
        let mut end = GAP_PHRASE_MAX_BYTES;
        while !phrase.is_char_boundary(end) {
            end -= 1;
        }
        phrase.truncate(end);
    }
    Some(phrase)
}

/// Logs one occurrence of a gap topic, or no-ops if [`normalize_gap_phrase`]
/// scrubbed it down to nothing.
///
/// **Call only when a search returned nothing or nothing above the score
/// floor** — never on a degraded search (an incomplete search is not evidence
/// of a content gap, D-452) and never on an answered turn.
pub async fn record_gap_topic(db: &PgPool, raw_query: &str) -> Result<(), AppError> {
    let Some(phrase) = normalize_gap_phrase(raw_query) else {
        return Ok(());
    };
    sqlx::query(
        "INSERT INTO knowledge_gap_topic (normalized_phrase) VALUES ($1) \
         ON CONFLICT (normalized_phrase) \
         DO UPDATE SET hit_count = knowledge_gap_topic.hit_count + 1, \
                        last_seen_at = NOW()",
    )
    .bind(&phrase)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// A row of the authors' knowledge-gap queue (D-452; surfaced by D-489).
///
/// The phrase is the scrubbed topic, never the caller's raw question — read
/// [`normalize_gap_phrase`]'s doc before widening anything here, and D-452
/// before changing what a row stores.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, ToSchema)]
pub struct GapTopic {
    pub id: Uuid,
    pub normalized_phrase: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub hit_count: i64,
    /// `open | addressed | dismissed`.
    pub status: String,
    /// The content page that addressed this gap, from the 0263 shape.
    pub addressed_page_ref: Option<Uuid>,
    /// The Knowledge Base item that addressed this gap (D-489, migration
    /// 0300). No FK: the target is a runtime-provisioned entity table.
    pub addressed_item_ref: Option<Uuid>,
}

/// The only legal triage states. Rejected loudly rather than coerced: a typo
/// that silently wrote an unrecognized status would drop the row out of every
/// filtered queue view and re-surface it as if it had never been triaged.
pub const GAP_STATUSES: [&str; 3] = ["open", "addressed", "dismissed"];

/// Reads the queue, most-recently-seen first.
///
/// Admin-only at the route layer; this function trusts its caller's status
/// argument only after validating it, so a bad value is a 422 rather than an
/// empty page.
pub async fn list_gap_topics(
    db: &PgPool,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<GapTopic>, i64), AppError> {
    if let Some(status) = status
        && !GAP_STATUSES.contains(&status)
    {
        return Err(AppError::Validation(format!(
            "status must be one of open, addressed, dismissed; got: {status}"
        )));
    }
    let items = sqlx::query_as::<_, GapTopic>(
        "SELECT id, normalized_phrase, first_seen_at, last_seen_at, hit_count, \
         status, addressed_page_ref, addressed_item_ref \
         FROM knowledge_gap_topic \
         WHERE ($1::text IS NULL OR status = $1) \
         ORDER BY last_seen_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(status)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM knowledge_gap_topic \
         WHERE ($1::text IS NULL OR status = $1)",
    )
    .bind(status)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok((items, total))
}

/// Sets one gap topic's triage state, returning the updated row or `None`
/// when the id does not exist.
///
/// `addressed_item_ref` is written only for `addressed`; every other status
/// clears it, so a row cannot carry a stale link that says an article answers
/// a gap the queue no longer considers closed.
pub async fn triage_gap_topic(
    db: &PgPool,
    id: Uuid,
    status: &str,
    addressed_item_ref: Option<Uuid>,
) -> Result<Option<GapTopic>, AppError> {
    if !GAP_STATUSES.contains(&status) {
        return Err(AppError::Validation(format!(
            "status must be one of open, addressed, dismissed; got: {status}"
        )));
    }
    let item_ref = if status == "addressed" {
        addressed_item_ref
    } else {
        None
    };
    sqlx::query_as::<_, GapTopic>(
        "UPDATE knowledge_gap_topic SET status = $2, addressed_item_ref = $3 \
         WHERE id = $1 \
         RETURNING id, normalized_phrase, first_seen_at, last_seen_at, hit_count, \
                   status, addressed_page_ref, addressed_item_ref",
    )
    .bind(id)
    .bind(status)
    .bind(item_ref)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}
#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"a-deployment-secret";

    /// The same query fingerprints the same way — otherwise grouping by
    /// fingerprint, which is the log's whole analytical purpose, answers
    /// nothing.
    #[test]
    fn the_fingerprint_is_stable() {
        let a = query_fingerprint("acme trading", KEY);
        assert_eq!(a, query_fingerprint("acme trading", KEY));
        assert_eq!(a.len(), FINGERPRINT_LEN);
    }

    /// Different queries fingerprint differently.
    #[test]
    fn different_queries_fingerprint_differently() {
        assert_ne!(
            query_fingerprint("acme", KEY),
            query_fingerprint("acme trading", KEY)
        );
    }

    /// Normalization runs first, so two spellings of one Arabic name are ONE
    /// query in the log. Without this, the moat language is the one the
    /// analytics can least reason about.
    #[test]
    fn arabic_spelling_variants_share_a_fingerprint() {
        assert_eq!(
            query_fingerprint("مُحَمَّد", KEY),
            query_fingerprint("محمد", KEY)
        );
        assert_eq!(
            query_fingerprint("ACME Trading", KEY),
            query_fingerprint("acme   trading", KEY)
        );
    }

    /// **Keyed.** An unkeyed hash of a short, low-entropy string is not
    /// anonymisation — the space of plausible customer names is small enough
    /// to enumerate, so anyone holding the log and a name list recovers the
    /// queries. Two deployments must not produce comparable fingerprints.
    #[test]
    fn the_fingerprint_is_keyed_to_the_deployment() {
        assert_ne!(
            query_fingerprint("acme", b"deployment-one"),
            query_fingerprint("acme", b"deployment-two"),
            "an unkeyed fingerprint is reversible by enumeration for exactly \
             the short queries this log is full of"
        );
    }

    /// The raw text must not be recoverable from, or visible in, the
    /// fingerprint. Trivially true of a hash — asserted because the failure
    /// mode being guarded against is someone "simplifying" this to store the
    /// query directly.
    #[test]
    fn the_fingerprint_contains_no_plaintext() {
        let fp = query_fingerprint("national-id-1234567890", KEY);
        let as_text = String::from_utf8_lossy(&fp);
        assert!(!as_text.contains("national"));
        assert!(!as_text.contains("1234567890"));
    }

    /// An empty query still fingerprints rather than panicking — a search box
    /// submits one.
    #[test]
    fn an_empty_query_is_safe() {
        assert_eq!(query_fingerprint("", KEY).len(), FINGERPRINT_LEN);
    }

    /// Query text is `Personal`, not `SensitiveSpecialCategory`.
    ///
    /// Over-classifying is not the safe direction it looks like: it would put
    /// every search under handling rules meant for health and biometric data,
    /// and rules that are obviously disproportionate get switched off.
    #[test]
    fn query_text_is_classified_personal_under_the_existing_scheme() {
        assert_eq!(
            QUERY_TEXT_CLASSIFICATION,
            attome_core::DataClassification::Personal
        );
    }

    /// The derived key is domain-separated and deterministic, so two
    /// deployments sharing a secret for some other purpose still produce
    /// unrelated fingerprint keys.
    #[test]
    fn the_fingerprint_key_is_domain_separated_and_stable() {
        let a = derive_fingerprint_key("deployment-secret");
        assert_eq!(a, derive_fingerprint_key("deployment-secret"));
        assert_ne!(a, derive_fingerprint_key("another-secret"));
        // And it is not the secret itself, however it is encoded.
        assert!(!a.starts_with(b"deployment-secret"));
    }

    // ── normalize_gap_phrase (D-452) ────────────────────────────────────

    /// The common case: a real question reduces to its content words.
    #[test]
    fn a_question_reduces_to_its_topic_words() {
        assert_eq!(
            normalize_gap_phrase("what is our policy on remote access"),
            Some("policy remote access".to_string())
        );
    }

    /// Digit-bearing tokens are dropped outright — D-452's highest-value
    /// rule, since phone numbers, national IDs, and reference codes are
    /// exactly what a support query tends to contain.
    #[test]
    fn tokens_with_digits_are_dropped() {
        let phrase = normalize_gap_phrase("what is the status of ticket 48213 refund").unwrap();
        assert!(!phrase.contains("48213"));
    }

    /// An email-shaped token is dropped.
    #[test]
    fn email_shaped_tokens_are_dropped() {
        let phrase =
            normalize_gap_phrase("can you update alice@example.com billing address").unwrap();
        assert!(!phrase.contains('@'));
    }

    /// A long, whitespace-free token (a pasted id/token shape) is dropped —
    /// exercised with a purely alphabetic token so the digit rule above
    /// cannot be the one actually doing the work.
    #[test]
    fn long_unbroken_tokens_are_dropped() {
        let long_token = "a".repeat(GAP_TOKEN_IDENTIFIER_LEN + 1);
        let phrase =
            normalize_gap_phrase(&format!("policy for account {long_token} refund")).unwrap();
        assert!(!phrase.contains(&long_token));
    }

    /// Fewer than two surviving tokens stores nothing at all, rather than a
    /// single, disproportionately identifying word.
    #[test]
    fn too_few_surviving_tokens_stores_nothing() {
        assert_eq!(normalize_gap_phrase("what is 12345"), None);
        assert_eq!(normalize_gap_phrase(""), None);
    }

    /// Only the first six surviving tokens are kept.
    #[test]
    fn the_token_count_is_capped() {
        let phrase =
            normalize_gap_phrase("alpha beta gamma delta epsilon zeta eta theta iota").unwrap();
        assert_eq!(phrase.split_whitespace().count(), GAP_PHRASE_MAX_TOKENS);
    }

    /// The byte cap truncates on a char boundary — never panics on
    /// multi-byte (e.g. Arabic) content.
    #[test]
    fn the_byte_cap_truncates_on_a_char_boundary() {
        let long_word = "س".repeat(60);
        let phrase = normalize_gap_phrase(&format!("سياسة {long_word} استرداد")).unwrap();
        assert!(phrase.len() <= GAP_PHRASE_MAX_BYTES);
    }
}
