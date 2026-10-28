//! Suggestions/autocomplete (M11 gap list) — `GET /api/v1/search/suggest?q=`.
//!
//! Backed by `search_suggestion` (migration `0276`), a materialized
//! table rebuilt periodically by [`refresh`]
//! (`EngineJob::SearchSuggestionRefresh`, wired in `crates/server/src/
//! jobs.rs`) from two sources: every registered entity's display name, and
//! every active `saved_search` record's `query_text`.
//!
//! **Deliberately not sourced from search telemetry.** The module plan's
//! original wording ("frequent successful queries... from existing
//! interaction telemetry") assumed the impression/interaction log holds query
//! text. It does not, on purpose: `telemetry.rs`'s `query_fingerprint` is a
//! one-way, deployment-keyed hash, and `QUERY_TEXT_CLASSIFICATION` records
//! query text as `Personal` data that is "never stored and never logged" —
//! a deliberate, tested privacy invariant (`the_fingerprint_contains_no_
//! plaintext`, `query_text_is_classified_personal_under_the_existing_
//! scheme`), not an oversight this feature gets to route around. Reversing
//! that invariant to source suggestions would be exactly the kind of
//! silent architecture change guidelines §15 requires evidence and
//! confirmation for, not something this gap-list implementation does on its
//! own judgement. Saved searches are the one place a caller's own query text
//! already persists in plain text, under the platform's ordinary audited
//! record-security model (see `saved_search.rs`) — so they are the
//! substitute "frequent queries" source, until/unless a product decision
//! explicitly revisits telemetry's privacy design. See
//! `document/module-master-plans/M11-search.md`'s updated note.
//!
//! ## The critical rule: a cached candidate is not a gated candidate
//!
//! [`SUGGEST_CACHE_TTL`]'s Redis entry holds raw candidate rows straight out
//! of the materialized table — **unfiltered by any one caller's
//! visibility**, because the cache is shared across every caller who types
//! the same prefix (keying it per-caller would explode cardinality for a
//! per-keystroke path and defeats the point of caching at all). [`serve`]
//! re-checks every candidate on every request, after the cache lookup,
//! before any of it reaches the response:
//!
//! * `entity` rows: the caller must hold `{logicalname}.read` (or be admin).
//!   Cheap — a `HashSet` membership check against the already-resolved
//!   `SecurityContext`, no query.
//! * `saved_search` rows: re-checked against `record_share`/access
//!   level through [`attome_security::visibility::PolymorphicVisibility`] —
//!   the exact same mechanism `saved_search::load_visible_query_text` and
//!   `/api/v1/search` itself use. One caller's shared/owned saved searches
//!   are never offered to another as a suggestion.

use std::time::Duration;

use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::lang::normalize_ar;

/// `{crate}:{purpose}:{id}` per guidelines §5.
const REDIS_PREFIX: &str = "attome-search:suggest";
/// Short — suggestions are a typeahead convenience, not a security control
/// (D-027's "coherence concern", not "fails closed"): a stale entry for up to
/// this long shows a slightly outdated candidate LIST, never an
/// under-visibility-checked one, since [`serve`] re-checks every candidate on
/// every request regardless of whether it came from cache or a fresh query.
const SUGGEST_CACHE_TTL: Duration = Duration::from_secs(30);
/// Bounds a slow/unreachable Redis from adding latency on top of a
/// per-keystroke path — same reasoning and same order of magnitude as
/// `attome-security::cache`'s `OP_TIMEOUT`. Deliberately 200 ms, below
/// `attome_cache::timeouts::REQUEST_PATH` (300 ms): a cache miss only costs a
/// recompute.
const REDIS_OP_TIMEOUT: Duration = Duration::from_millis(200);
/// How many raw candidates the cache/query layer fetches per prefix, before
/// the per-caller visibility recheck narrows it — deliberately higher than
/// [`SUGGEST_LIMIT`] because the recheck can only ever remove rows.
const CANDIDATE_FETCH_LIMIT: i64 = 25;
/// How many suggestions are returned to the caller.
pub const SUGGEST_LIMIT: usize = 10;
/// Shortest prefix worth querying — a one-character prefix against a
/// trigram/prefix index on a shared table is cheap, but returns candidates so
/// generic they are not useful; this also caps how often the coldest cache
/// keys (the shortest prefixes, hit by every user's first keystroke) get
/// rebuilt.
pub const MIN_PREFIX_LEN: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
struct RawCandidate {
    kind: String,
    suggestion_text: String,
    entity_logicalname: String,
    record_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(as = SearchSuggestion)]
pub struct Suggestion {
    pub text: String,
    /// `"entity"` | `"saved_search"`.
    pub kind: String,
    /// For `"entity"`: the entity to route to. For `"saved_search"`: always
    /// `"saved_search"` — pair with `record_id` to call `run`.
    pub entity_logicalname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SuggestResponse {
    pub items: Vec<Suggestion>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SuggestParams {
    /// The text typed so far.
    pub q: String,
}

fn redis_key(prefix_norm: &str) -> String {
    format!("{REDIS_PREFIX}:{prefix_norm}")
}

/// Reads cached raw candidates for a normalized prefix, degrading to `None`
/// (meaning: go to the database) on any Redis error or timeout — a coherence
/// cache per D-027, never a security control.
async fn cache_get(redis: &attome_cache::Store, prefix_norm: &str) -> Option<Vec<RawCandidate>> {
    let raw: Option<String> =
        tokio::time::timeout(REDIS_OP_TIMEOUT, redis.get(&redis_key(prefix_norm)))
            .await
            .ok()?
            .ok()?;
    raw.and_then(|json| serde_json::from_str(&json).ok())
}

async fn cache_put(redis: &attome_cache::Store, prefix_norm: &str, candidates: &[RawCandidate]) {
    let Ok(json) = serde_json::to_string(candidates) else {
        return;
    };
    let _ = tokio::time::timeout(
        REDIS_OP_TIMEOUT,
        redis.set(&redis_key(prefix_norm), &json, Some(SUGGEST_CACHE_TTL)),
    )
    .await;
}

async fn query_candidates(db: &DbPool, prefix_norm: &str) -> Result<Vec<RawCandidate>, AppError> {
    // Same LIKE-escaping discipline as `legs::stage1::PrefixLeg` — the query
    // is bound and the wildcard concatenated in SQL, so a prefix containing
    // `%`/`_` is matched literally rather than becoming a leading-wildcard
    // scan.
    sqlx::query_as(
        "SELECT kind, suggestion_text, entity_logicalname, record_id \
           FROM search_suggestion \
          WHERE suggestion_norm LIKE (replace(replace(replace($1, '\\', '\\\\'), '%', '\\%'), '_', '\\_') || '%') \
          ORDER BY weight DESC, suggestion_text ASC \
          LIMIT $2",
    )
    .bind(prefix_norm)
    .bind(CANDIDATE_FETCH_LIMIT)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// The visibility recheck this module's doc comment calls "the critical
/// rule". Splits candidates into privilege-gated `entity` rows (cheap, no
/// query) and record-gated `saved_search` rows (one batched query, same
/// `PolymorphicVisibility` mechanism `/api/v1/search` and
/// `saved_search::run` both use), then returns only what this caller, right
/// now, is actually allowed to see.
async fn filter_visible(
    state: &EngineState,
    ctx: &SecurityContext,
    candidates: Vec<RawCandidate>,
) -> Vec<Suggestion> {
    let mut visible = Vec::new();
    let mut saved_search_ids: Vec<Uuid> = Vec::new();

    for c in &candidates {
        if c.kind == "entity" {
            let allowed = ctx.is_admin
                || ctx
                    .privileges
                    .contains(&format!("{}.read", c.entity_logicalname));
            if allowed {
                visible.push(Suggestion {
                    text: c.suggestion_text.clone(),
                    kind: c.kind.clone(),
                    entity_logicalname: c.entity_logicalname.clone(),
                    record_id: None,
                });
            }
        } else if let Some(id) = c.record_id {
            saved_search_ids.push(id);
        }
    }

    if !saved_search_ids.is_empty() {
        let ok_ids = visible_saved_search_ids(state, ctx, &saved_search_ids).await;
        for c in &candidates {
            if c.kind == "saved_search"
                && let Some(id) = c.record_id
                && ok_ids.contains(&id)
            {
                visible.push(Suggestion {
                    text: c.suggestion_text.clone(),
                    kind: c.kind.clone(),
                    entity_logicalname: c.entity_logicalname.clone(),
                    record_id: Some(id),
                });
            }
        }
    }

    visible.truncate(SUGGEST_LIMIT);
    visible
}

/// Batch visibility recheck against `saved_search`, mirroring
/// `saved_search::load_visible_query_text`'s single-row version. A failure
/// degrades to "no saved-search suggestions this request" rather than
/// failing the whole suggest call — same reasoning
/// `routes::fetch_display_text` gives for its own failure path.
async fn visible_saved_search_ids(
    state: &EngineState,
    ctx: &SecurityContext,
    ids: &[Uuid],
) -> std::collections::HashSet<Uuid> {
    let access_map = match attome_security::resolve_all_entity_access_levels(
        &state.base.db,
        ctx.user_id,
        attome_security::RecordAction::Read,
    )
    .await
    {
        Ok(m) => m,
        Err(_) => return std::collections::HashSet::new(),
    };
    let default_shares = match attome_security::resolve_default_share_entities(
        &state.base.db,
        ctx.user_id,
        &ctx.team_ids,
        attome_security::RecordAction::Read
            .share_capability()
            .as_i16(),
    )
    .await
    {
        Ok(s) => s,
        Err(_) => return std::collections::HashSet::new(),
    };
    let visibility = attome_security::visibility::PolymorphicVisibility::new(
        ctx,
        &access_map,
        &default_shares,
        Some(attome_security::FastTierColumns {
            organization_ref: "t.organization_ref",
        }),
    );

    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> =
        sqlx::QueryBuilder::new("SELECT t.id FROM saved_search t WHERE t.id = ANY(");
    qb.push_bind(ids.to_vec());
    qb.push("::uuid[]) AND t.is_active IS NOT FALSE");
    visibility.push(&mut qb, "'saved_search'", "t.id");

    qb.build_query_scalar::<Uuid>()
        .fetch_all(&state.base.db)
        .await
        .map(|rows| rows.into_iter().collect())
        .unwrap_or_default()
}

/// The suggest endpoint's actual work — separated from the HTTP handler
/// (thin: extract, delegate, respond) same as `routes::execute_search`.
pub async fn serve(
    state: &EngineState,
    ctx: &SecurityContext,
    q: &str,
) -> Result<SuggestResponse, AppError> {
    let trimmed = q.trim();
    if trimmed.chars().count() < MIN_PREFIX_LEN {
        return Ok(SuggestResponse { items: Vec::new() });
    }
    let prefix_norm = normalize_ar(trimmed);
    if prefix_norm.is_empty() {
        return Ok(SuggestResponse { items: Vec::new() });
    }

    let candidates = match cache_get(&state.base.redis, &prefix_norm).await {
        Some(cached) => cached,
        None => {
            let fresh = query_candidates(&state.base.db, &prefix_norm).await?;
            cache_put(&state.base.redis, &prefix_norm, &fresh).await;
            fresh
        }
    };

    let items = filter_visible(state, ctx, candidates).await;
    Ok(SuggestResponse { items })
}

/// Suggest search terms
///
/// Completions for what the caller has typed, from a suggestion table rebuilt periodically.
#[utoipa::path(
    get,
    path = "/api/v1/search/suggest",
    tag = "search",
    params(SuggestParams),
    responses(
        (status = 200, description = "Prefix suggestions this caller may act on", body = SuggestResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn suggest(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(params): Query<SuggestParams>,
) -> Result<Json<SuggestResponse>, AppError> {
    let response = serve(&state, &ctx, &params.q).await?;
    Ok(Json(response))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/search/suggest", get(suggest))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(suggest))]
#[derive(Debug)]
pub struct ApiDocFragment;

// ── Refresh job ──────────────────────────────────────────────────────────

/// Advisory-lock key for the refresh tick.
const REFRESH_LOCK_KEY: &str = "attome-search/suggest:refresh";
/// Bounds how many saved searches contribute a suggestion row per refresh —
/// guidelines §9's bounded-batch rule. A deployment with more than this many
/// active saved searches gets the most recently touched ones; a full
/// unbounded scan on every tick is exactly the "durable work needs bounded
/// batches" case this ceiling exists for.
const MAX_SAVED_SEARCH_SUGGESTIONS: i64 = 5_000;

#[derive(Debug, Default, Clone, Copy)]
pub struct RefreshStats {
    pub entity_rows: i64,
    pub saved_search_rows: i64,
}

/// Rebuilds `search_suggestion` from its two sources (this module's
/// doc comment). A full rebuild inside one transaction, not an incremental
/// diff: the table is small (bounded by the number of registered entities
/// plus [`MAX_SAVED_SEARCH_SUGGESTIONS`]), so the simplicity of "delete
/// everything, reinsert everything" is worth more than the complexity of a
/// correct incremental update for a table this size — the same trade-off
/// `access_cache`'s module doc makes for a differently-shaped problem.
pub async fn refresh(state: &EngineState) -> Result<RefreshStats, AppError> {
    let db = &state.base.db;
    let mut tx = attome_db::tx::begin(db).await?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(REFRESH_LOCK_KEY)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !acquired {
        return Ok(RefreshStats::default());
    }

    sqlx::query("DELETE FROM search_suggestion")
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    // `entity_info.name` is the entity's DISPLAY name (`0000_core_
    // bootstrap.sql`) — not to be confused with `logicalname`, the stable
    // machine identifier. `aggregate.rs::resolve_entity` reads the same
    // table with the same `(is_active IS NULL OR is_active = true) AND
    // logicalname IS NOT NULL` predicate.
    let entities: Vec<(String, String)> = sqlx::query_as(
        "SELECT logicalname, name FROM entity_info \
          WHERE (is_active IS NULL OR is_active = true) AND logicalname IS NOT NULL",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let mut entity_rows = 0i64;
    for (logicalname, display_name) in &entities {
        let norm = normalize_ar(display_name);
        if norm.is_empty() {
            continue;
        }
        sqlx::query(
            "INSERT INTO search_suggestion \
                (kind, suggestion_text, suggestion_norm, entity_logicalname, record_id, weight) \
             VALUES ('entity', $1, $2, $3, NULL, 10)",
        )
        .bind(display_name)
        .bind(&norm)
        .bind(logicalname)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        entity_rows += 1;
    }

    // `saved_search` may not exist yet on a database mid-upgrade between
    // this migration landing and `saved_search::seed` running for the first
    // time — tolerate that rather than fail the whole refresh tick.
    let saved_searches: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, query_text FROM saved_search \
          WHERE is_active IS NOT FALSE \
          ORDER BY modified_at DESC NULLS LAST, created_at DESC NULLS LAST \
          LIMIT $1",
    )
    .bind(MAX_SAVED_SEARCH_SUGGESTIONS)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();

    let mut saved_search_rows = 0i64;
    for (id, query_text) in &saved_searches {
        let norm = normalize_ar(query_text);
        if norm.is_empty() {
            continue;
        }
        sqlx::query(
            "INSERT INTO search_suggestion \
                (kind, suggestion_text, suggestion_norm, entity_logicalname, record_id, weight) \
             VALUES ('saved_search', $1, $2, 'saved_search', $3, 5)",
        )
        .bind(query_text)
        .bind(&norm)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        saved_search_rows += 1;
    }

    tx.commit().await.map_err(AppError::internal)?;
    Ok(RefreshStats {
        entity_rows,
        saved_search_rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_redis_key_is_namespaced() {
        assert_eq!(redis_key("acm"), "attome-search:suggest:acm".to_owned());
    }

    #[test]
    fn the_refresh_lock_key_is_namespaced_and_scoped() {
        assert!(REFRESH_LOCK_KEY.starts_with("attome-search/"));
        assert!(REFRESH_LOCK_KEY.contains(':'));
    }

    #[test]
    fn candidate_fetch_exceeds_the_returned_limit() {
        // The recheck can only remove rows, never add them — fetching more
        // than we return is what keeps a heavily-filtered caller from seeing
        // a short list purely because the raw fetch was too small.
        assert!(CANDIDATE_FETCH_LIMIT as usize > SUGGEST_LIMIT);
    }

    #[test]
    fn the_batch_size_is_bounded() {
        const _: () = assert!(MAX_SAVED_SEARCH_SUGGESTIONS > 0);
        const _: () = assert!(MAX_SAVED_SEARCH_SUGGESTIONS <= 1_000_000);
    }

    /// A one-character prefix returns no suggestions rather than querying —
    /// see `MIN_PREFIX_LEN`'s doc comment. `serve` itself needs a live
    /// `EngineState` (DB + Redis) to test end to end — this pins the pure
    /// length gate it checks first.
    #[test]
    fn a_too_short_prefix_would_short_circuit() {
        let trimmed = "a".trim();
        assert!(trimmed.chars().count() < MIN_PREFIX_LEN);
    }
}
