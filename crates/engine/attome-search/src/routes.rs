//! The query surface (TODO-017), with the caps that keep it affordable
//! (TODO-018).
//!
//! ## Why `Total` is an enum
//!
//! The earlier plan mandated `PaginatedResponse` — which carries an exact
//! `total` — **and** a 500-row candidate ceiling. Both cannot hold. An exact
//! total is a second full pass with the whole permission predicate applied,
//! which on a 100k-row match is ~400 ms *by itself* — over the fast-read pool's
//! 500 ms `statement_timeout` before any of the actual work.
//!
//! So the contract says what is true: [`Total::Exact`] when the match set was
//! genuinely bounded, [`Total::AtLeast`] when it was cut off. A UI that renders
//! "about 500+" is honest; one that renders "500" because that is where the
//! ceiling fell is not, and users make decisions on that number.
//!
//! ## Why the caps are not optional
//!
//! Search is the most expensive endpoint in the product and typeahead fires
//! per keystroke. GIN cost is roughly linear in term count, so **a 500-term
//! `tsquery` is a cheap authenticated denial of service** — no exploit, just a
//! long paste into a search box. [`MAX_QUERY_BYTES`] and [`MAX_QUERY_TERMS`]
//! reject it before it reaches PostgreSQL, rather than after.

use std::sync::LazyLock;

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, SelfService, area};
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::{
    AppError, DEFAULT_PAGE_SIZE, ErrorResponse, OnePageQuery, PageBase, PageWindow,
    PaginatedResponse,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, patch},
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::access_cache::AccessMapCache;
use crate::knowledge::{DEFAULT_KNOWLEDGE_LIMIT, KnowledgeCitation, MAX_KNOWLEDGE_LIMIT};
use crate::legs::fuse::{build_phase_with_shape, interpret_counts};
use crate::legs::stage1::{ExactKeyLeg, FuzzyLeg, LexicalLeg, PhoneKeyLeg, PrefixLeg};
use crate::legs::{LegPhase, SqlLeg};
use crate::router::{Audience, Route};
use crate::telemetry::GapTopic;

/// An owner id and name as the facet read gives them.
type OwnerRow = (Option<Uuid>, Option<String>);

/// Process-local, keyed on `"{user_id}:{epoch}"`. A static rather than state on
/// `EngineState` because it holds nothing per-deployment and needs no wiring —
/// see `access_cache`'s header for why in-process is correct here.
static ACCESS_MAPS: LazyLock<AccessMapCache> = LazyLock::new(AccessMapCache::new);

/// The ranker that produced an ordering, recorded on every impression.
///
/// A log spanning a ranker change is otherwise one population pretending to be
/// two — every later comparison silently averages across a change nobody can
/// see in the data. Bump this whenever the ordering logic changes in a way
/// that could move results.
const RANKER_ID: &str = "rrf/v2";

/// Per-route statement timeout.
///
/// Tightened from the pool's 500 ms baseline rather than replacing it —
/// `pool.rs` records what removing that baseline cost last time. Typeahead
/// gets less than a full search because a keystroke that takes 400 ms is worse
/// than one that returns nothing.
fn statement_timeout_ms(route: &Route) -> i64 {
    match route {
        Route::Exact | Route::NameLookup => 250,
        _ => 500,
    }
}

/// The legs a route runs.
///
/// Building them here, from the route, is what makes "the router selects among
/// strategies" concrete — a leg set assembled anywhere else would be a second
/// routing decision.
fn legs_for(
    route: &Route,
    normalized: &str,
    stemmed: &str,
    synonyms: &[String],
    phone: Option<&str>,
) -> Vec<Box<dyn SqlLeg>> {
    let mut legs = legs_for_route(route, normalized, stemmed, synonyms);
    // A25-T2: a phone typed locally also finds its international key.
    if let Some(phone) = phone.filter(|p| *p != normalized)
        && legs.iter().any(|l| l.id() == "R1.exact")
    {
        legs.push(Box::new(PhoneKeyLeg {
            phone_key: phone.to_owned(),
        }));
    }
    legs
}

fn legs_for_route(
    route: &Route,
    normalized: &str,
    stemmed: &str,
    synonyms: &[String],
) -> Vec<Box<dyn SqlLeg>> {
    match route {
        // An exact hit short-circuits ranking entirely: someone who pastes an
        // invoice number wants that invoice, not the best textual match.
        Route::Exact => vec![Box::new(ExactKeyLeg {
            normalized_query: normalized.to_owned(),
        })],
        // A user who quotes has said they mean these words in this order.
        // Relaxing that with a fuzzy leg is the most irritating thing a search
        // box does.
        Route::Phrase => vec![Box::new(LexicalLeg {
            stemmed_query: stemmed.to_owned(),
        })],
        Route::NameLookup => vec![
            Box::new(ExactKeyLeg {
                normalized_query: normalized.to_owned(),
            }),
            Box::new(PrefixLeg {
                normalized_query: normalized.to_owned(),
            }),
            Box::new(FuzzyLeg {
                normalized_query: normalized.to_owned(),
                deferred: true,
                ..FuzzyLeg::default()
            }),
        ],
        Route::Aggregation { .. } => Vec::new(),
        Route::Hybrid => {
            let mut legs: Vec<Box<dyn SqlLeg>> = vec![
                Box::new(ExactKeyLeg {
                    normalized_query: normalized.to_owned(),
                }),
                Box::new(PrefixLeg {
                    normalized_query: normalized.to_owned(),
                }),
                Box::new(LexicalLeg {
                    stemmed_query: stemmed.to_owned(),
                }),
                Box::new(FuzzyLeg {
                    normalized_query: normalized.to_owned(),
                    deferred: true,
                    ..FuzzyLeg::default()
                }),
            ];
            // C10-T1: the glossary's other names for what the query names.
            if !synonyms.is_empty() {
                legs.push(Box::new(crate::legs::stage1::SynonymLeg {
                    stemmed_alternatives: synonyms.to_vec(),
                }));
            }
            legs
        }
    }
}

/// Longest query accepted, in bytes.
pub const MAX_QUERY_BYTES: usize = 512;

/// Most terms accepted.
///
/// GIN cost is roughly linear in term count; past a few dozen the query is not
/// a search, it is a paste. Rejecting is strictly better than truncating —
/// silently dropping half a user's query and returning results for the rest is
/// the kind of behaviour nobody can debug from the outside.
pub const MAX_QUERY_TERMS: usize = 32;

/// Deep-paging cap, **documented rather than discovered**.
///
/// Past this the candidate ceiling means later pages are not meaningfully
/// ranked — the ordering is an artifact of where the cut fell. Returning
/// silently-empty pages instead would look like "no more results", which is a
/// different and wrong statement.
pub const MAX_PAGE: i64 = 50;

/// How many matches there are.
#[derive(Debug, Clone, Copy, Serialize, ToSchema, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Total {
    /// The match set was bounded, so this is the real number.
    Exact { value: u64 },
    /// The match set hit the candidate ceiling. There are at least this many;
    /// counting the rest would cost a second full-predicate pass.
    AtLeast { value: u64 },
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SearchParams {
    /// The query. Capped — see [`MAX_QUERY_BYTES`]/[`MAX_QUERY_TERMS`].
    pub q: String,
    /// One-based: page 1 is the first page.
    #[serde(default = "default_page")]
    #[param(minimum = 1)]
    pub page: i64,
    /// Rows per page.
    #[serde(default = "default_page_size")]
    pub page_size: i64,
    /// `human` (default) or `agent`. Selects tuning only, never the
    /// enforcement path — see `router`.
    #[serde(default)]
    pub audience: Option<String>,
    /// A25-T4: explain each result's score. Only administrators and holders
    /// of `metadata.read` get explanations; for anyone else this is ignored.
    #[serde(default)]
    pub explain: bool,
    /// A25-T9: also count the results by entity, owner and month changed.
    #[serde(default)]
    pub facets: bool,
    /// A25-T7: `ask` reads the query as words. It becomes a filter over one
    /// entity, shown in `ask.filter` and applied; a question also gets a
    /// direct answer from the top results. Page 1 only. Absent is a plain
    /// search.
    #[serde(default)]
    pub mode: Option<String>,
}

/// A25-T9: what a search computes beside its page.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SearchOptions {
    /// Each hit's [`crate::explain::ScoreParts`] (the caller checked
    /// [`crate::explain::may_explain`]).
    pub explain: bool,
    /// The response's [`SearchFacets`].
    pub facets: bool,
}

/// One facet value and how many results have it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct FacetCount {
    pub value: String,
    pub count: i64,
}

/// A25-T9: the results counted by entity, owner (user id) and the month
/// they last changed (`YYYY-MM`), over every result the caller may see, not
/// only the page; the most common 20 of each.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
pub struct SearchFacets {
    pub entity: Vec<FacetCount>,
    pub owner: Vec<FacetCount>,
    pub modified_month: Vec<FacetCount>,
}

/// The most values one facet lists.
pub const MAX_FACET_VALUES: usize = 20;

/// Counts `values`, most common first (ties by value), at most
/// [`MAX_FACET_VALUES`]. Pure.
pub fn facet_counts<I: IntoIterator<Item = String>>(values: I) -> Vec<FacetCount> {
    let mut counts: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
    for v in values {
        *counts.entry(v).or_default() += 1;
    }
    let mut out: Vec<FacetCount> = counts
        .into_iter()
        .map(|(value, count)| FacetCount { value, count })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.value.cmp(&b.value)));
    out.truncate(MAX_FACET_VALUES);
    out
}

fn default_page() -> i64 {
    1
}
fn default_page_size() -> i64 {
    25
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SearchHit {
    pub entity_logicalname: String,
    pub record_id: Uuid,
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub score: f64,
    /// Which legs matched this row. Useful to a human debugging relevance and
    /// to the impression log's feature vector.
    pub matched_legs: Vec<String>,
    /// A25-T4: how the score came about, when asked for and allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explain: Option<crate::explain::ScoreParts>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResponse {
    pub items: Vec<SearchHit>,
    pub total: Total,
    pub page: i64,
    pub page_size: i64,
    pub has_more: bool,
    /// Which route the query took. Exposed deliberately: "why did this query
    /// return that" is the single most common search support question, and the
    /// answer is almost always the route.
    pub route: String,
    /// Legs that did not run to completion. **Reported, never swallowed** — a
    /// result set silently missing a leg looks like "no more matches", which
    /// is indistinguishable from a correct empty answer.
    pub degraded: Vec<String>,
    /// Set when the query was routed away from retrieval — an aggregation
    /// question, which retrieval answers badly (see `router::Route`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_hint: Option<RouteHintDto>,
    /// The handle a later interaction is reported against (TODO-021). `None`
    /// when the impression could not be logged, which must not fail the
    /// search.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impression_id: Option<Uuid>,
    /// AB5-T5: the index was down, so this is a short prefix match on each
    /// readable entity's title from the database (route `fallback`), not a
    /// ranked search. Sent only when true.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub limited: bool,
    /// A25-T9: the facets, when asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facets: Option<SearchFacets>,
    /// A25-T7: what asking in words did, for `mode=ask`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask: Option<crate::ask::AskResult>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RouteHintDto {
    pub tool: String,
}

/// Validates and normalizes the caller's query.
///
/// Rejects rather than truncates, and says which limit was hit — a 422 naming
/// the cap is actionable; a silently shortened query is not.
pub fn validate_query(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation("q must not be empty".into()));
    }
    if trimmed.len() > MAX_QUERY_BYTES {
        return Err(AppError::Validation(format!(
            "q must not exceed {MAX_QUERY_BYTES} bytes"
        )));
    }
    let terms = trimmed.split_whitespace().count();
    if terms > MAX_QUERY_TERMS {
        return Err(AppError::Validation(format!(
            "q must not exceed {MAX_QUERY_TERMS} terms"
        )));
    }
    Ok(trimmed.to_owned())
}

/// Validates pagination.
///
/// A page beyond [`MAX_PAGE`] is a 422 rather than an empty page: past the
/// candidate ceiling the ordering is an artifact of where the cut fell, so
/// "here is page 200" would be a confident presentation of noise.
pub fn validate_paging(page: i64, page_size: i64) -> Result<(), AppError> {
    if page < 1 {
        return Err(AppError::Validation("page must be at least 1".into()));
    }
    if page > MAX_PAGE {
        return Err(AppError::Validation(format!(
            "page must not exceed {MAX_PAGE}; narrow the query instead — \
             beyond this the candidate ceiling makes ordering arbitrary"
        )));
    }
    if !(1..=100).contains(&page_size) {
        return Err(AppError::Validation(
            "page_size must be between 1 and 100".into(),
        ));
    }
    Ok(())
}

pub fn parse_audience(raw: Option<&str>) -> Result<Audience, AppError> {
    match raw {
        None | Some("human") => Ok(Audience::Human),
        Some("agent") => Ok(Audience::Agent),
        Some(other) => Err(AppError::Validation(format!(
            "audience must be 'human' or 'agent', got {other:?}"
        ))),
    }
}

/// Decides whether a count is exact or a floor.
///
/// The rule is mechanical on purpose: if the candidate set filled the ceiling,
/// there may be more and we do not know how many. Anything cleverer would be
/// guessing, and a guess presented as a total is worse than an honest floor.
pub fn total_for(found: u64, ceiling: u64) -> Total {
    if found >= ceiling {
        Total::AtLeast { value: found }
    } else {
        Total::Exact { value: found }
    }
}

pub fn route_name(route: &Route) -> &'static str {
    match route {
        Route::Exact => "exact",
        Route::Phrase => "phrase",
        Route::NameLookup => "name_lookup",
        Route::Aggregation { .. } => "aggregation",
        Route::Hybrid => "hybrid",
    }
}

/// The search route.
///
/// Stage 1 mounts this as the only query surface. It is declared here with its
/// contract so the OpenAPI document and the Angular client exist before the
/// executor is wired to the fused statement — the handler currently validates,
/// routes, and reports, which is the half that has a testable contract.
#[utoipa::path(
    get,
    path = "/api/v1/search",
    tag = "search",
    params(SearchParams),
    responses(
        (status = 200, description = "A bounded page of results", body = SearchResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "Query or pagination outside the documented caps, an unknown mode, or a page past 1 with mode=ask", body = ErrorResponse),
        (status = 503, description = "mode=ask on a deployment where asking in words is unavailable", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn search(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(params): Query<SearchParams>,
) -> Result<Json<SearchResponse>, AppError> {
    let ctx = ctx.into_inner();
    let q = validate_query(&params.q)?;
    validate_paging(params.page, params.page_size)?;
    let audience = parse_audience(params.audience.as_deref())?;
    let ask = match params.mode.as_deref() {
        None => false,
        Some("ask") => true,
        Some(other) => {
            return Err(AppError::Validation(format!(
                "mode: {other} is not a search mode; the one mode is ask"
            )));
        }
    };

    // AB5-T5: with the index confirmed down, answer from the tables instead.
    if state
        .base
        .capabilities
        .state(attome_server::capability::Capability::SearchIndex)
        == attome_server::capability::CapabilityState::Unavailable
    {
        let response =
            crate::fallback::fallback_search(&state, &ctx, &q, params.page, params.page_size)
                .await?;
        return Ok(Json(response));
    }
    let options = SearchOptions {
        explain: params.explain && crate::explain::may_explain(&ctx),
        facets: params.facets,
    };
    if ask {
        let response = crate::ask::ask_search(
            &state,
            ctx,
            &q,
            params.page,
            params.page_size,
            audience,
            options,
        )
        .await?;
        return Ok(Json(response));
    }
    let response = execute_search_with(
        &state,
        &ctx,
        &q,
        params.page,
        params.page_size,
        audience,
        options,
    )
    .await?;
    Ok(Json(response))
}

/// The search route's actual work, reusable by any caller that already holds
/// a validated query and a `SecurityContext` — the HTTP handler above, a
/// saved search's "run" action (`saved_search::run`), and the saved-search
/// alert sweep (`saved_search::sweep_alerts`), which re-runs a saved query
/// **as its owner** on a schedule, not on a request. All three must apply the
/// identical visibility composition (invariant I-1) — this is that one path,
/// not a second one with the same shape.
///
/// `q` must already have passed [`validate_query`]; `page`/`page_size` must
/// already have passed [`validate_paging`] — this function does not
/// re-validate, so every caller goes through those first, same as the HTTP
/// handler above.
pub async fn execute_search(
    state: &EngineState,
    ctx: &SecurityContext,
    q: &str,
    page: i64,
    page_size: i64,
    audience: Audience,
) -> Result<SearchResponse, AppError> {
    execute_search_with(
        state,
        ctx,
        q,
        page,
        page_size,
        audience,
        SearchOptions::default(),
    )
    .await
}

/// A25-T4, A25-T9: [`execute_search`] with explanations and facets as
/// `options` asks. Nothing is computed for either unless asked.
pub async fn execute_search_with(
    state: &EngineState,
    ctx: &SecurityContext,
    q: &str,
    page: i64,
    page_size: i64,
    audience: Audience,
    options: SearchOptions,
) -> Result<SearchResponse, AppError> {
    let explain = options.explain;
    let route = crate::router::route(q, audience);

    // An aggregation question is answered by a stored query, not by retrieval.
    // Returning the hint rather than ten plausible rows is the whole point of
    // rule 4 — see `router::Route::Aggregation`.
    if let Route::Aggregation { hint } = &route {
        return Ok(SearchResponse {
            items: Vec::new(),
            total: Total::Exact { value: 0 },
            page,
            page_size,
            has_more: false,
            route: route_name(&route).to_owned(),
            degraded: Vec::new(),
            route_hint: Some(RouteHintDto {
                tool: hint.tool.to_owned(),
            }),
            impression_id: None,
            limited: false,
            facets: None,
            ask: None,
        });
    }

    let started = std::time::Instant::now();
    let tuning = audience.tuning(&route);

    // The DSL layer (M11 gap list) — `field:value`, quotes, `-exclude`. Parses
    // to plain data (`dsl`'s module doc); `free_text` feeds the SAME
    // normalize/stem/route pipeline every other query goes through — an
    // ordinary query with no DSL syntax produces `free_text == q`, so this is
    // a no-op for every query that used to work. `route` above was computed
    // off the RAW `q`, deliberately: an all-DSL query (`"type:account"`, no
    // free text at all) still routes off real input rather than an empty
    // string.
    let parsed = crate::dsl::parse(q);
    let text_for_pipeline = if parsed.free_text.is_empty() {
        q
    } else {
        parsed.free_text.as_str()
    };
    // A25-T3: the administrator's synonyms, stop words, boosts and pins. A
    // snapshot that cannot be read leaves this search untuned.
    let controls = match crate::controls::load(&state.base.db).await {
        Ok(controls) => controls,
        Err(error) => {
            tracing::warn!(?error, "search: ranking controls unavailable");
            std::sync::Arc::new(crate::controls::Controls::default())
        }
    };
    let without_stopwords = controls.without_stopwords(text_for_pipeline);
    let text_for_pipeline = without_stopwords.as_str();
    let normalized = crate::normalize_ar(text_for_pipeline);
    let stemmed = crate::project::index_text(text_for_pipeline);

    // The access map, from cache when this caller has one at this epoch. A
    // typeahead firing per keystroke must not rebuild it ten times for one
    // name, and the epoch in the key means a revoked caller cannot reach the
    // entry they had before the revocation (TODO-020).
    let access_map = match ACCESS_MAPS.get(ctx).await {
        Some(cached) => cached,
        None => {
            let resolved = attome_security::resolve_all_entity_access_levels(
                &state.base.db,
                ctx.user_id,
                attome_security::RecordAction::Read,
            )
            .await?;
            ACCESS_MAPS.put(ctx, resolved).await
        }
    };
    // U1: polymorphic child entities are never matchable, including rows an
    // earlier drain indexed before they stopped being indexed.
    let access_map = without_polymorphic_children(access_map);

    let default_shares = attome_security::resolve_default_share_entities(
        &state.base.db,
        ctx.user_id,
        &ctx.team_ids,
        attome_security::RecordAction::Read
            .share_capability()
            .as_i16(),
    )
    .await?;

    // The fast tier is available here and NOT on the audit paths, for the
    // reason D-357 records: the rows being filtered carry `organization_ref`
    // themselves. `t` is the index table's alias inside every leg.
    let visibility = attome_security::visibility::PolymorphicVisibility::new(
        ctx,
        &access_map,
        &default_shares,
        Some(attome_security::FastTierColumns {
            organization_ref: "t.organization_ref",
        }),
    );

    // C10-T1: glossary synonyms widen a full search. A glossary that cannot
    // be read widens nothing; the search itself goes ahead.
    let mut synonyms: Vec<String> = match crate::glossary::approved_terms(&state.base.db).await {
        Ok(terms) => crate::glossary::alternatives(text_for_pipeline, &terms)
            .iter()
            .map(|a| crate::project::index_text(a))
            .filter(|a| !a.trim().is_empty())
            .collect(),
        Err(error) => {
            tracing::warn!(?error, "search: glossary synonyms unavailable");
            Vec::new()
        }
    };
    // A25-T3: the search synonyms widen it the same way.
    for alternative in controls.alternatives(&normalized) {
        let stemmed_alt = crate::project::index_text(&alternative);
        if !stemmed_alt.trim().is_empty() && !synonyms.contains(&stemmed_alt) {
            synonyms.push(stemmed_alt);
        }
    }
    let synonyms_used = if explain {
        synonyms.clone()
    } else {
        Vec::new()
    };
    let default_country = attome_core::setting_registry()
        .get("core.default_country")
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let phone = crate::corpus::phone_query_key(text_for_pipeline, &default_country);
    let owned_legs = legs_for(&route, &normalized, &stemmed, &synonyms, phone.as_deref());
    let leg_refs: Vec<&dyn SqlLeg> = owned_legs.iter().map(|l| l.as_ref()).collect();

    // Which of the two equivalent visibility shapes to use (TODO-053). A
    // share-only caller gets no organization fast tier, so the standard
    // fragment re-checks the share table once per candidate — tens of thousands
    // of rows to fill one page, on typeahead too, for exactly the narrowed
    // users the design protects. The estimate decides *whether* to invert and
    // never *what* is visible: an eligibility check upstream of it guarantees
    // the two shapes are equivalent for this caller.
    let shape = crate::plan_visibility_shape(
        &state.base.db,
        &visibility,
        ctx.user_id,
        &ctx.team_ids,
        &ctx.subordinate_user_ids,
    )
    .await;

    let offset = (page - 1) * page_size;
    let Some(mut qb) = build_phase_with_shape(
        &leg_refs,
        LegPhase::Immediate,
        &visibility,
        shape,
        "t.entity_logicalname",
        "t.record_id",
        tuning.ceiling,
    ) else {
        // A route with no legs returns an empty page rather than an error —
        // it is a correct answer to a query nothing can match.
        return Ok(empty_response(&route, page, page_size));
    };

    // The fused statement runs inside a transaction so `SET LOCAL` bounds it.
    // Read-only, on the pinned-aware read pool: a caller who just wrote must
    // not be sent to a replica that has not caught up.
    let pool = state.base.read_pool(ctx.user_id).await;
    let mut tx = attome_db::tx::begin(pool).await?;
    sqlx::query(&format!(
        "SET LOCAL statement_timeout = {}",
        statement_timeout_ms(&route)
    ))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let mut fused: Vec<(Uuid, String, f64, Vec<String>, serde_json::Value)> =
        qb.build_query_as().fetch_all(&mut *tx).await.map_err(|e| {
            tracing::warn!(error = %e, route = route_name(&route), "search query failed");
            AppError::internal("search failed")
        })?;
    let leg_counts = fused
        .first()
        .map(|(_, _, _, _, counts)| counts.clone())
        .unwrap_or_else(|| serde_json::json!({}));
    let mut per_leg = interpret_counts(&leg_refs, LegPhase::Immediate, &leg_counts);
    // AA6-T1: the deferred legs (the fuzzy typo leg) run only when the exact,
    // prefix and lexical legs found nothing, in the same transaction.
    if fused.is_empty()
        && let Some(mut later) = build_phase_with_shape(
            &leg_refs,
            LegPhase::AfterEmbedding,
            &visibility,
            shape,
            "t.entity_logicalname",
            "t.record_id",
            tuning.ceiling,
        )
    {
        fused = later.build_query_as().fetch_all(&mut *tx).await.map_err(|e| {
            tracing::warn!(error = %e, route = route_name(&route), "search fallback query failed");
            AppError::internal("search failed")
        })?;
        let later_counts = fused
            .first()
            .map(|(_, _, _, _, counts)| counts.clone())
            .unwrap_or_else(|| serde_json::json!({}));
        per_leg.extend(interpret_counts(
            &leg_refs,
            LegPhase::AfterEmbedding,
            &later_counts,
        ));
    }
    tx.commit().await.map_err(AppError::internal)?;
    let degraded: Vec<String> = per_leg
        .iter()
        .filter(|(_, c)| **c != crate::Completeness::Complete)
        .map(|(id, _)| (*id).to_owned())
        .collect();

    // DSL post-fusion narrowing (`dsl`'s module doc explains why this is safe
    // and why it is *not* a second enforcement path): `entity_filter` is a
    // pure in-memory comparison against a column the fused statement already
    // projected — no SQL, no visibility question at all. Required
    // phrases/excluded terms need one extra bounded read of already-fetched,
    // already visibility-filtered candidates — `apply_text_narrowing`
    // re-applies the SAME visibility fragment, never a looser one.
    if let Some(entity_name) = &parsed.entity_filter {
        fused.retain(|(_, entity_logicalname, ..)| entity_logicalname == entity_name);
    }
    if !parsed.required_phrases.is_empty() || !parsed.excluded_terms.is_empty() {
        fused = apply_text_narrowing(
            state,
            ctx,
            &access_map,
            &default_shares,
            fused,
            &parsed.required_phrases,
            &parsed.excluded_terms,
        )
        .await;
    }

    // A25-T3: boosts and personal ranking re-order what the caller may see,
    // then the query's pins take their places (each one read through the
    // visibility fragment first when it was not already a result).
    let weights = personal_weights(state);
    let personal = if weights.is_off() {
        std::collections::HashMap::new()
    } else {
        personal_signals(state, ctx, &fused).await
    };
    // A25-T4: the fused scores before tuning, for an explanation.
    let fused_before: std::collections::HashMap<(String, Uuid), f64> = if explain {
        fused.iter().map(|r| ((r.1.clone(), r.0), r.2)).collect()
    } else {
        std::collections::HashMap::new()
    };
    crate::controls::rerank(&mut fused, &controls, weights, &personal);
    let pins = controls.pins_for(&normalized);
    if !pins.is_empty() {
        let missing: Vec<crate::controls::FusedRow> = pins
            .iter()
            .filter(|p| !fused.iter().any(|r| r.0 == p.record_id && r.1 == p.entity))
            .map(|p| {
                (
                    p.record_id,
                    p.entity.clone(),
                    0.0,
                    Vec::new(),
                    serde_json::Value::Null,
                )
            })
            .collect();
        let readable = fetch_display_text(state, ctx, &access_map, &default_shares, &missing).await;
        let mut visible: std::collections::HashSet<(String, Uuid)> =
            fused.iter().map(|r| (r.1.clone(), r.0)).collect();
        visible.extend(readable.keys().cloned());
        crate::controls::place_pins(&mut fused, pins, &visible);
    }

    let found = fused.len() as u64;
    let facets = if options.facets {
        Some(facets_of(state, &fused).await)
    } else {
        None
    };
    // The score floor is the crude half of the abstention contract: a human
    // ignores an irrelevant fourth result, a model cites it.
    let page_rows: Vec<_> = fused
        .into_iter()
        .filter(|(_, _, score, _, _)| *score >= tuning.score_floor)
        .skip(offset as usize)
        .take(page_size as usize)
        .collect();
    let has_more = found > (offset + page_size) as u64;

    // Display text for the page, in a second read.
    //
    // Not projected out of the fused statement: `title`/`subtitle` would ride
    // through every leg's CTE, the `UNION ALL`, and the `GROUP BY` for every
    // candidate up to the ceiling — hundreds of rows of text carried through a
    // fusion that then discards all but a page of it. This reads at most
    // `page_size` rows, by primary key.
    //
    // **The visibility fragment is applied again here**, even though these ids
    // came out of a filtered query moments ago. Re-filtering a page's worth of
    // rows costs nothing measurable, and the alternative establishes a pattern
    // — "these ids are already trusted" — that is correct exactly until someone
    // reuses this read from a path where they are not.
    let display = fetch_display_text(state, ctx, &access_map, &default_shares, &page_rows).await;

    let items: Vec<SearchHit> = page_rows
        .into_iter()
        .map(
            |(record_id, entity_logicalname, score, matched_legs, leg_values)| {
                let key = (entity_logicalname.clone(), record_id);
                let text = display.get(&key);
                let explain = explain.then(|| {
                    let pinned = matched_legs.iter().any(|l| l == "pin")
                        || controls
                            .pins_for(&normalized)
                            .iter()
                            .any(|p| p.record_id == record_id && p.entity == entity_logicalname);
                    let mut parts = crate::explain::parts(
                        fused_before.get(&key).copied().unwrap_or(0.0),
                        controls.boost(&entity_logicalname),
                        personal.get(&key),
                        weights,
                        pinned,
                        &matched_legs,
                        &leg_values,
                        &synonyms_used,
                    );
                    // A pin sets the place, not the score: report the score shown.
                    parts.score = score;
                    parts
                });
                SearchHit {
                    entity_logicalname,
                    record_id,
                    title: text.and_then(|(t, _)| t.clone()),
                    subtitle: text.and_then(|(_, s)| s.clone()),
                    score,
                    matched_legs,
                    explain,
                }
            },
        )
        .collect();

    let elapsed_ms = i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX);
    let impression_id = spawn_impression(
        state,
        ImpressionInputs {
            ctx,
            query: q,
            route: &route,
            audience,
            completeness: serde_json::to_value(&per_leg).unwrap_or_else(|_| serde_json::json!({})),
            latency_ms: elapsed_ms,
            hits: &items,
        },
    );

    tracing::debug!(
        route = route_name(&route),
        found,
        elapsed_ms = started.elapsed().as_millis() as u64,
        degraded = degraded.len(),
        "search served"
    );

    Ok(SearchResponse {
        total: total_for(found, tuning.ceiling as u64),
        page,
        page_size,
        has_more,
        route: route_name(&route).to_owned(),
        degraded,
        route_hint: None,
        impression_id,
        limited: false,
        facets,
        ask: None,
        items,
    })
}

/// A25-T9: the facets of every result the caller may see (`fused` is
/// already permission-filtered). Owner and month come from the index rows; a
/// read that fails leaves those two empty and is logged.
async fn facets_of(state: &EngineState, fused: &[crate::controls::FusedRow]) -> SearchFacets {
    let entity = facet_counts(fused.iter().map(|r| r.1.clone()));
    if fused.is_empty() {
        return SearchFacets {
            entity,
            ..SearchFacets::default()
        };
    }
    let entities: Vec<String> = fused.iter().map(|r| r.1.clone()).collect();
    let ids: Vec<Uuid> = fused.iter().map(|r| r.0).collect();
    let rows: Result<Vec<OwnerRow>, sqlx::Error> = sqlx::query_as(
        "SELECT i.owner_id, to_char(date_trunc('month', i.source_modifiedon), 'YYYY-MM') \
           FROM search_index i \
           JOIN UNNEST($1::text[], $2::uuid[]) AS u(entity, id) \
             ON i.entity_logicalname = u.entity AND i.record_id = u.id \
          WHERE i.corpus = $3",
    )
    .bind(&entities)
    .bind(&ids)
    .bind(crate::drain::CORPUS_RECORD)
    .fetch_all(&state.base.db)
    .await;
    match rows {
        Ok(rows) => SearchFacets {
            entity,
            owner: facet_counts(rows.iter().filter_map(|(o, _)| o.map(|o| o.to_string()))),
            modified_month: facet_counts(rows.iter().filter_map(|(_, m)| m.clone())),
        },
        Err(error) => {
            tracing::warn!(%error, "search: owner and month facets unavailable");
            SearchFacets {
                entity,
                ..SearchFacets::default()
            }
        }
    }
}

/// A25-T3: `search.personal_weights`, all zero unless set.
fn personal_weights(state: &EngineState) -> crate::controls::PersonalWeights {
    attome_core::setting_registry()
        .get("search.personal_weights")
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .map(|v| crate::controls::PersonalWeights::from_setting(&v))
        .unwrap_or_default()
}

/// A25-T3: for each candidate, whether the caller owns it, a team of theirs
/// owns it, or they opened it from a search in the last 30 days. Ranking
/// signals only: every candidate already passed the visibility filter. A
/// read that fails leaves the ranking unpersonalised.
async fn personal_signals(
    state: &EngineState,
    ctx: &SecurityContext,
    fused: &[crate::controls::FusedRow],
) -> std::collections::HashMap<(String, Uuid), crate::controls::Personal> {
    let mut out = std::collections::HashMap::new();
    if fused.is_empty() {
        return out;
    }
    let entities: Vec<String> = fused.iter().map(|r| r.1.clone()).collect();
    let ids: Vec<Uuid> = fused.iter().map(|r| r.0).collect();
    let pool = state.base.read_pool(ctx.user_id).await;
    let owners: Result<Vec<(String, Uuid, Option<Uuid>)>, sqlx::Error> = sqlx::query_as(
        "SELECT t.entity_logicalname, t.record_id, t.owner_id FROM search_index t \
           JOIN unnest($1::text[], $2::uuid[]) AS c(entity_logicalname, record_id) \
             ON c.entity_logicalname = t.entity_logicalname AND c.record_id = t.record_id",
    )
    .bind(&entities)
    .bind(&ids)
    .fetch_all(pool)
    .await;
    let opened: Result<Vec<(String, Uuid)>, sqlx::Error> = sqlx::query_as(
        "SELECT DISTINCT i.entity_logicalname, i.record_id FROM search_interaction i \
           JOIN search_impression m ON m.id = i.impression_ref \
           JOIN unnest($2::text[], $3::uuid[]) AS c(entity_logicalname, record_id) \
             ON c.entity_logicalname = i.entity_logicalname AND c.record_id = i.record_id \
          WHERE m.caller_ref = $1 AND i.created_at >= now() - interval '30 days'",
    )
    .bind(ctx.user_id)
    .bind(&entities)
    .bind(&ids)
    .fetch_all(pool)
    .await;
    match owners {
        Ok(rows) => {
            for (entity, id, owner) in rows {
                let entry: &mut crate::controls::Personal = out.entry((entity, id)).or_default();
                entry.owned = owner == Some(ctx.user_id);
                entry.team_owned = owner.is_some_and(|o| ctx.team_ids.contains(&o));
            }
        }
        Err(error) => tracing::warn!(?error, "search: owners for personal ranking unavailable"),
    }
    match opened {
        Ok(rows) => {
            for key in rows {
                out.entry(key).or_default().opened = true;
            }
        }
        Err(error) => tracing::warn!(
            ?error,
            "search: opened records for personal ranking unavailable"
        ),
    }
    out
}

/// DSL post-fusion narrowing (`dsl`'s module doc) — required phrases and
/// excluded terms, checked against `title`/`subtitle` only. Same two columns
/// [`fetch_display_text`] reads, for the same cost reason: reading the full
/// `body_indexed` for the whole candidate set (rather than one page) is the
/// read-amplification that function's doc comment explains why it avoids —
/// this is real, but it is a real, disclosed scope limit: a phrase appearing
/// only in a document's body, not its title/subtitle, is not caught here.
///
/// Runs over the FULL candidate set (up to `tuning.ceiling`), before
/// pagination — a required phrase must be able to promote a row from beyond
/// the page cut, and an excluded term must be able to remove one without
/// leaving a page short. **The visibility fragment is applied again here**,
/// same discipline as `fetch_display_text` — these ids came out of a
/// filtered fused query moments ago, but re-filtering is what keeps this from
/// quietly becoming a second, unaudited way to read `title`/`subtitle`.
///
/// A failure here degrades to "no narrowing applied" (the unfiltered
/// candidate set), not to a failed search — same reasoning as
/// `fetch_display_text`: the fused query's own visibility filtering already
/// ran and is unaffected either way.
async fn apply_text_narrowing(
    state: &EngineState,
    ctx: &SecurityContext,
    access_map: &std::collections::HashMap<String, (Uuid, AccessLevel)>,
    default_shares: &std::collections::HashSet<Uuid>,
    candidates: Vec<(Uuid, String, f64, Vec<String>, serde_json::Value)>,
    required_phrases: &[String],
    excluded_terms: &[String],
) -> Vec<(Uuid, String, f64, Vec<String>, serde_json::Value)> {
    if candidates.is_empty() {
        return candidates;
    }
    let display = fetch_display_text(state, ctx, access_map, default_shares, &candidates).await;

    candidates
        .into_iter()
        .filter(|(record_id, entity_logicalname, ..)| {
            let (title, subtitle) = display
                .get(&(entity_logicalname.clone(), *record_id))
                .cloned()
                .unwrap_or((None, None));
            let haystack = format!(
                "{} {}",
                title.unwrap_or_default(),
                subtitle.unwrap_or_default()
            )
            .to_lowercase();

            let has_all_required = required_phrases
                .iter()
                .all(|phrase| haystack.contains(&phrase.to_lowercase()));
            let has_none_excluded = excluded_terms
                .iter()
                .all(|term| !haystack.contains(&term.to_lowercase()));

            has_all_required && has_none_excluded
        })
        .collect()
}

/// Fetches `title`/`subtitle` for one page of hits, re-applying visibility.
///
/// Keyed by `(entity_logicalname, record_id)` because `record_id` alone is not
/// unique in the index — the primary key is `(corpus, entity_logicalname,
/// record_id)`, and two entities can legitimately carry the same record id.
/// Keying on the id alone would occasionally show one record's title on
/// another's row, which is both wrong and unreproducible.
///
/// A failure here degrades to untitled rows rather than failing the search: the
/// hits, their order, and their identity are all correct without it, and a
/// results list that renders is strictly better than an error page.
/// Drops the polymorphic child entities (`corpus::POLYMORPHIC_CHILD_ENTITIES`)
/// from a caller's access map. An entity absent from the map excludes its rows
/// from `PolymorphicVisibility` outright. Clones only when there is something
/// to remove; the cached map itself is never mutated.
fn without_polymorphic_children(
    map: std::sync::Arc<crate::access_cache::AccessMap>,
) -> std::sync::Arc<crate::access_cache::AccessMap> {
    let children = crate::corpus::POLYMORPHIC_CHILD_ENTITIES;
    if !children.iter().any(|entity| map.contains_key(*entity)) {
        return map;
    }
    let mut filtered = (*map).clone();
    filtered.retain(|entity, _| !children.contains(&entity.as_str()));
    std::sync::Arc::new(filtered)
}

async fn fetch_display_text(
    state: &EngineState,
    ctx: &SecurityContext,
    access_map: &std::collections::HashMap<String, (Uuid, AccessLevel)>,
    default_shares: &std::collections::HashSet<Uuid>,
    page: &[(Uuid, String, f64, Vec<String>, serde_json::Value)],
) -> std::collections::HashMap<(String, Uuid), (Option<String>, Option<String>)> {
    use std::collections::HashMap;
    if page.is_empty() {
        return HashMap::new();
    }

    let ids: Vec<Uuid> = page.iter().map(|(id, ..)| *id).collect();
    let entities: Vec<String> = page.iter().map(|(_, e, ..)| e.clone()).collect();

    let visibility = attome_security::visibility::PolymorphicVisibility::new(
        ctx,
        access_map,
        default_shares,
        Some(attome_security::FastTierColumns {
            organization_ref: "t.organization_ref",
        }),
    );

    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
        "SELECT t.entity_logicalname, t.record_id, t.title, t.subtitle \
         FROM search_index t \
         WHERE t.corpus = 'record' AND t.record_id = ANY(",
    );
    qb.push_bind(ids);
    qb.push("::uuid[]) AND t.entity_logicalname = ANY(");
    qb.push_bind(entities);
    qb.push("::text[])");
    visibility.push(&mut qb, "t.entity_logicalname", "t.record_id");

    match qb
        .build_query_as::<(String, Uuid, Option<String>, Option<String>)>()
        .fetch_all(&state.base.db)
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|(entity, id, title, subtitle)| ((entity, id), (title, subtitle)))
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "search display projection failed; returning untitled hits");
            HashMap::new()
        }
    }
}

/// Records the impression **off the request path** (TODO-021).
///
/// Spawned, never awaited. A search must not be slower, and must not *fail*,
/// because a log table is busy — losing one data point is a bad day, failing a
/// user's search for telemetry is a worse product. The failure is logged at
/// `error` rather than swallowed, because a systematically failing write would
/// otherwise degrade the log invisibly, and the log is the one thing here that
/// cannot be reconstructed later.
///
/// Returns the id synchronously so the response can carry it: a caller
/// reporting a click needs the handle, and generating it here rather than in
/// the spawned task is what makes that possible without awaiting the write.
///
/// Takes a struct rather than eight positional arguments, for the reason
/// `RlsBinds` gives for the same choice: several of these are strings and
/// several are ids, and a transposed pair would produce a log that looks
/// entirely normal and describes the wrong search.
struct ImpressionInputs<'a> {
    ctx: &'a attome_server::security::SecurityContext,
    query: &'a str,
    route: &'a Route,
    audience: Audience,
    completeness: serde_json::Value,
    latency_ms: i32,
    hits: &'a [SearchHit],
}

fn spawn_impression(state: &EngineState, inputs: ImpressionInputs<'_>) -> Option<Uuid> {
    let ImpressionInputs {
        ctx,
        query,
        route,
        audience,
        completeness,
        latency_ms,
        hits,
    } = inputs;
    // Derived, not stored. See `telemetry::derive_fingerprint_key`.
    let secret = state.base.config.auth.jwt_secret.active()?;
    let key = crate::telemetry::derive_fingerprint_key(secret);
    let fingerprint = crate::telemetry::query_fingerprint(query, &key);

    let rows: Vec<crate::telemetry::ImpressionRow> = hits
        .iter()
        .enumerate()
        .map(|(i, hit)| crate::telemetry::ImpressionRow {
            rank: (i + 1) as i32,
            entity_logicalname: hit.entity_logicalname.clone(),
            record_id: hit.record_id,
            // The signals AS AT display time — recomputing them later would
            // describe a world that no longer exists.
            feature_vector: serde_json::json!({
                "rrf": hit.score,
                "matched_legs": hit.matched_legs,
            }),
        })
        .collect();

    // Generated here, not by the column default: the response must carry it
    // synchronously while the write is spawned.
    let impression_id = Uuid::now_v7();
    let db = state.base.db.clone();
    let route_name = route_name(route).to_owned();
    let audience_name = match audience {
        Audience::Human => "human",
        Audience::Agent => "agent",
    };
    let caller = ctx.user_id;

    tokio::spawn(async move {
        let impression = crate::telemetry::Impression {
            query_fingerprint: fingerprint,
            route: &route_name,
            ranker_id: RANKER_ID,
            audience: audience_name,
            completeness,
            caller_ref: Some(caller),
            organization_ref: None,
            latency_ms: Some(latency_ms),
            rows,
        };
        if let Err(e) =
            crate::telemetry::record_impression_with_id(&db, impression_id, &impression).await
        {
            tracing::error!(
                error = %e,
                "search impression was not recorded — this data point is unrecoverable"
            );
        }
    });

    Some(impression_id)
}

fn empty_response(route: &Route, page: i64, page_size: i64) -> SearchResponse {
    SearchResponse {
        items: Vec::new(),
        total: Total::Exact { value: 0 },
        page,
        page_size,
        has_more: false,
        route: route_name(route).to_owned(),
        degraded: Vec::new(),
        route_hint: None,
        impression_id: None,
        limited: false,
        facets: None,
        ask: None,
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct RelatedKnowledgeParams {
    /// The `content_page` id to find semantic neighbors for.
    page_id: Uuid,
    /// The most rows to return.
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Serialize, ToSchema)]
struct RelatedKnowledgeResponse {
    /// Neighbor page ids, nearest first. Empty on a deployment where no
    /// chunk has an embedding yet (D-452) — Stage 2's backfill is what
    /// populates `knowledge_chunk.embedding`; this route does not
    /// depend on anything else that is unbuilt.
    page_ids: Vec<Uuid>,
}

const MAX_RELATED_KNOWLEDGE_LIMIT: i64 = 20;

/// M37 Phase 2 (D-452) — semantic related-page suggestions for the content
/// admin UI, distinct from `attome-content`'s manual `related_page_ids`
/// full-set-replace endpoint. Admin-gated like every content-authoring
/// surface, even though the query itself only ever returns page ids: this is
/// an authoring tool, not a retrieval-serving route, and has no reason to be
/// reachable by a caller who cannot already manage content.
#[utoipa::path(
    get,
    path = "/api/v1/search/knowledge/related",
    tag = "search",
    params(RelatedKnowledgeParams),
    responses(
        (status = 200, description = "Semantic neighbor pages, nearest first", body = RelatedKnowledgeResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Search is not licensed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn related_knowledge(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
    Query(params): Query<RelatedKnowledgeParams>,
) -> Result<Json<RelatedKnowledgeResponse>, AppError> {
    let limit = params
        .limit
        .unwrap_or(crate::knowledge::DEFAULT_SEMANTIC_NEIGHBOR_LIMIT)
        .clamp(1, MAX_RELATED_KNOWLEDGE_LIMIT);
    let page_ids =
        crate::knowledge::semantic_neighbors(&state.base.db, params.page_id, limit).await?;
    Ok(Json(RelatedKnowledgeResponse { page_ids }))
}

// ── Knowledge retrieval and the gap queue (D-489) ───────────────────────────

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct KnowledgeParams {
    /// The question or topic. Held to the same byte/term caps as `/search`:
    /// GIN cost is roughly linear in term count, so a long paste must be
    /// rejected before it reaches PostgreSQL.
    q: String,
    /// The most rows to return.
    #[serde(default)]
    limit: Option<i64>,
}

/// M37 (D-489) — passages from the published knowledge corpus, each with a
/// citation that resolves to the item and heading it came from.
///
/// `SelfService` rather than `Admin`: this is the reader surface the agent
/// action also calls, and its permission check is the same
/// `KnowledgeVisibility` fragment record search uses (I-1) — not a route-level
/// admin gate standing in for one.
#[utoipa::path(
    get,
    path = "/api/v1/search/knowledge",
    tag = "search",
    params(KnowledgeParams),
    responses(
        (status = 200, description = "Passages with citations, strongest first", body = PaginatedResponse<KnowledgeCitation>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Search is not licensed", body = ErrorResponse),
        (status = 422, description = "Query outside the documented caps", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn knowledge_search(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(params): Query<KnowledgeParams>,
) -> Result<Json<PaginatedResponse<KnowledgeCitation>>, AppError> {
    let q = validate_query(&params.q)?;
    let limit = params
        .limit
        .unwrap_or(DEFAULT_KNOWLEDGE_LIMIT)
        .clamp(1, MAX_KNOWLEDGE_LIMIT);
    // A direct search has no agent session, so no session knowledge scope.
    let hits =
        crate::knowledge::search_knowledge_recorded(&state.base.db, &ctx, &q, limit, None).await?;
    let items: Vec<KnowledgeCitation> = hits.into_iter().map(|hit| hit.citation).collect();
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 0, limit)))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct GapQuery {
    /// Filter to one triage state; omit for the whole queue.
    status: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// Why a question retrieves what it does (roadmap N15-T4): its terms, the
/// words dropped, and each passage's matched terms in rank order. Admin-only,
/// retrieved under the administrator's own permissions, and never recorded as
/// demand or as a gap.
#[utoipa::path(
    get,
    path = "/api/v1/admin/knowledge/explain",
    tag = "search",
    params(KnowledgeParams),
    responses(
        (status = 200, description = "The question's terms and why each passage ranked", body = crate::knowledge::KnowledgeExplanation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Search is not licensed", body = ErrorResponse),
        (status = 422, description = "Query outside the documented caps", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn explain_knowledge(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Query(params): Query<KnowledgeParams>,
) -> Result<Json<crate::knowledge::KnowledgeExplanation>, AppError> {
    let q = validate_query(&params.q)?;
    let limit = params
        .limit
        .unwrap_or(DEFAULT_KNOWLEDGE_LIMIT)
        .clamp(1, MAX_KNOWLEDGE_LIMIT);
    Ok(Json(
        crate::knowledge::explain(&state.base.db, &ctx, &q, limit).await?,
    ))
}

/// The authors' gap queue (M37 Phase 2, D-452; the front door added by D-489).
///
/// Admin-only: the phrases are classified `Personal` (D-452), so the queue has
/// no reader-scoped audience at all.
#[utoipa::path(
    get,
    path = "/api/v1/admin/knowledge/gaps",
    tag = "search",
    params(GapQuery),
    responses(
        (status = 200, description = "Gap topics, most recently seen first", body = PaginatedResponse<GapTopic>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Search is not licensed", body = ErrorResponse),
        (status = 422, description = "Unknown status filter", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_gaps(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
    Query(q): Query<GapQuery>,
) -> Result<Json<PaginatedResponse<GapTopic>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);
    let (items, total) =
        crate::telemetry::list_gap_topics(&state.base.db, q.status.as_deref(), page_size, offset)
            .await?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Deserialize, ToSchema)]
struct TriageGapBody {
    /// `open | addressed | dismissed`.
    status: String,
    /// The Knowledge Base item that answers this gap. Written only when
    /// `status = "addressed"`; ignored otherwise.
    #[serde(default)]
    addressed_item_ref: Option<Uuid>,
}

/// Triages one gap topic. An explicit author decision, never a delete, so the
/// queue does not re-surface a topic without showing it was already judged
/// (D-452's rationale for the status column).
#[utoipa::path(
    patch,
    path = "/api/v1/admin/knowledge/gaps/{id}",
    tag = "search",
    params(("id" = Uuid, Path)),
    request_body = TriageGapBody,
    responses(
        (status = 200, description = "Success", body = GapTopic),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Search is not licensed", body = ErrorResponse),
        (status = 404, description = "Gap topic not found", body = ErrorResponse),
        (status = 422, description = "Unknown status", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn triage_gap(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path(id): Path<Uuid>,
    Json(body): Json<TriageGapBody>,
) -> Result<Json<GapTopic>, AppError> {
    let topic = crate::telemetry::triage_gap_topic(
        &state.base.db,
        id,
        &body.status,
        body.addressed_item_ref,
    )
    .await?
    .ok_or(AppError::NotFound)?;
    attome_audit::write_business_event(
        &state,
        "knowledge_gap_topic",
        id,
        attome_audit::AuditOperation::Update,
        "knowledge_gap.triage",
        ctx.user_id,
        None,
        None,
        format!("triaged to status \"{}\"", body.status),
    )
    .await;
    Ok(Json(topic))
}
/// Per-collection knowledge coverage for the operator (chatbot plan C8): live
/// items by lifecycle, retrievable chunks, the last index write, and the
/// embedding backlog against the configured model. See
/// [`crate::knowledge_coverage`] for what each number counts.
///
/// Admin-only, like the gap queue: it reads every collection.
#[utoipa::path(
    get,
    path = "/api/v1/admin/knowledge/coverage",
    tag = "search",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Live collections by name, with their coverage", body = PaginatedResponse<crate::knowledge_coverage::CollectionCoverage>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Search is not licensed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn knowledge_coverage(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<crate::knowledge_coverage::CollectionCoverage>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = q.window();
    let (items, total) = crate::knowledge_coverage::collection_coverage(
        &state.base.db,
        crate::scheduler::configured_embedding_model(&state),
        page_size,
        offset,
    )
    .await?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// The knowledge indexer's shared state: when the search drain last advanced,
/// and which embedding model chunk vectors are written with (`null` when
/// knowledge is lexical-only by configuration).
#[utoipa::path(
    get,
    path = "/api/v1/admin/knowledge/coverage/indexer",
    tag = "search",
    responses(
        (status = 200, description = "The indexer's state", body = crate::knowledge_coverage::IndexerStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Search is not licensed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn knowledge_indexer_status(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
) -> Result<Json<crate::knowledge_coverage::IndexerStatus>, AppError> {
    let status = crate::knowledge_coverage::indexer_status(
        &state.base.db,
        crate::scheduler::configured_embedding_model(&state),
    )
    .await?;
    Ok(Json(status))
}

/// A25-T5: one entity's share of the search index, as last measured.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct IndexSize {
    pub entity_logicalname: String,
    pub row_count: i64,
    pub bytes: i64,
    pub measured_at: chrono::DateTime<chrono::Utc>,
}

/// A25-T5: how far the index is behind, and its size per entity.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchStatus {
    pub backlog: crate::drain::Backlog,
    /// Per entity, largest first, from the daily upkeep.
    pub sizes: Vec<IndexSize>,
}

/// Search index status
///
/// How far the search index is behind the change feed (unread events and the
/// age of the oldest) and its rows and bytes per entity from the daily
/// measurement. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/search/status",
    tag = "search",
    responses(
        (status = 200, description = "The index's backlog and size", body = SearchStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Search is not licensed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn search_status(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
) -> Result<Json<SearchStatus>, AppError> {
    let backlog = crate::drain::backlog(&state.base.db).await?;
    let sizes: Vec<IndexSize> = sqlx::query_as(
        "SELECT entity_logicalname, row_count, bytes, measured_at FROM search_index_size           ORDER BY bytes DESC, entity_logicalname LIMIT 500",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(SearchStatus { backlog, sizes }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/search/status", get(search_status))
        .route("/api/v1/search", get(search))
        .route("/api/v1/search/knowledge", get(knowledge_search))
        .route("/api/v1/search/knowledge/related", get(related_knowledge))
        .route("/api/v1/admin/knowledge/explain", get(explain_knowledge))
        .route("/api/v1/admin/knowledge/gaps", get(list_gaps))
        .route("/api/v1/admin/knowledge/gaps/{id}", patch(triage_gap))
        .route("/api/v1/admin/knowledge/coverage", get(knowledge_coverage))
        .route(
            "/api/v1/admin/knowledge/coverage/indexer",
            get(knowledge_indexer_status),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    search,
    knowledge_search,
    related_knowledge,
    explain_knowledge,
    list_gaps,
    triage_gap,
    knowledge_coverage,
    knowledge_indexer_status,
    search_status
))]
#[derive(Debug)]
pub struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facet_counts_are_most_common_first_and_bounded() {
        let values = ["b", "a", "b", "c", "b", "a"]
            .iter()
            .map(|v| (*v).to_owned());
        let counts = facet_counts(values);
        assert_eq!(
            counts,
            vec![
                FacetCount {
                    value: "b".into(),
                    count: 3
                },
                FacetCount {
                    value: "a".into(),
                    count: 2
                },
                FacetCount {
                    value: "c".into(),
                    count: 1
                },
            ]
        );
        assert_eq!(
            facet_counts((0..50).map(|i| i.to_string())).len(),
            MAX_FACET_VALUES
        );
    }

    /// A long paste is rejected before it reaches PostgreSQL. GIN cost is
    /// roughly linear in term count, so a 500-term tsquery is a cheap
    /// authenticated denial of service — no exploit needed, just a paste.
    #[test]
    fn an_oversized_query_is_rejected_not_executed() {
        let many_terms = "term ".repeat(200);
        assert!(validate_query(&many_terms).is_err());

        let long = "x".repeat(MAX_QUERY_BYTES + 1);
        assert!(validate_query(&long).is_err());

        // And the boundary is inclusive on the accepting side.
        assert!(validate_query(&"x".repeat(MAX_QUERY_BYTES)).is_ok());
        assert!(validate_query(&"a ".repeat(MAX_QUERY_TERMS)).is_ok());
    }

    /// Rejected, never truncated. Silently dropping half a user's query and
    /// returning results for the rest is behaviour nobody can debug from
    /// outside.
    /// Rejected, never truncated — and the error names the cap that was hit.
    ///
    /// Note the input: `"a "` repeated, not `"term "`. Many short tokens stay
    /// under the byte cap and trip the TERM cap, which is the one being
    /// asserted. `"term "` repeated 200 times is 1000 bytes and trips the byte
    /// cap first — a detail that made this test pass for the wrong reason
    /// until it did not.
    #[test]
    fn an_oversized_query_names_the_limit_it_hit() {
        let many_short_terms = "a ".repeat(MAX_QUERY_TERMS + 20);
        assert!(many_short_terms.len() <= MAX_QUERY_BYTES);

        let err = validate_query(&many_short_terms).unwrap_err();
        let message = format!("{err:?}");
        assert!(
            message.contains("terms"),
            "the error must say which cap was hit: {message}"
        );

        let long = "x".repeat(MAX_QUERY_BYTES + 1);
        let err = validate_query(&long).unwrap_err();
        let message = format!("{err:?}");
        assert!(
            message.contains("bytes"),
            "the error must say which cap was hit: {message}"
        );
    }

    #[test]
    fn an_empty_query_is_rejected() {
        assert!(validate_query("").is_err());
        assert!(validate_query("   ").is_err());
    }

    /// Deep paging is a 422, not an empty page. Past the candidate ceiling the
    /// ordering is an artifact of where the cut fell, so "here is page 200"
    /// would present noise confidently.
    #[test]
    fn paging_beyond_the_cap_is_rejected_rather_than_silently_empty() {
        assert!(validate_paging(MAX_PAGE, 25).is_ok());
        assert!(validate_paging(MAX_PAGE + 1, 25).is_err());
        assert!(validate_paging(0, 25).is_err());
        assert!(validate_paging(1, 0).is_err());
        assert!(validate_paging(1, 101).is_err());
    }

    /// The contract the whole file exists for: a count that filled the ceiling
    /// is a FLOOR, not a total. A UI rendering "500" because that is where the
    /// cut fell is lying to someone making a decision on the number.
    #[test]
    fn a_count_at_the_ceiling_is_reported_as_a_floor() {
        assert_eq!(total_for(10, 500), Total::Exact { value: 10 });
        assert_eq!(total_for(499, 500), Total::Exact { value: 499 });
        assert_eq!(total_for(500, 500), Total::AtLeast { value: 500 });
        assert_eq!(total_for(1_000, 500), Total::AtLeast { value: 1_000 });
    }

    /// `Total` serialises as a tagged union, so a client cannot read a floor
    /// as an exact number by ignoring a sibling boolean it never noticed.
    #[test]
    fn total_serialises_with_its_kind() {
        let exact = serde_json::to_string(&Total::Exact { value: 7 }).unwrap();
        let at_least = serde_json::to_string(&Total::AtLeast { value: 500 }).unwrap();
        assert!(exact.contains("\"kind\":\"exact\""), "{exact}");
        assert!(at_least.contains("\"kind\":\"at_least\""), "{at_least}");
    }

    #[test]
    fn the_audience_parameter_is_validated() {
        assert_eq!(parse_audience(None).unwrap(), Audience::Human);
        assert_eq!(parse_audience(Some("human")).unwrap(), Audience::Human);
        assert_eq!(parse_audience(Some("agent")).unwrap(), Audience::Agent);
        assert!(parse_audience(Some("root")).is_err());
    }

    /// Every route has a stable wire name. These reach the impression log's
    /// `route` column, and a renamed value silently splits one population into
    /// two in every later analysis.
    #[test]
    fn route_names_are_stable() {
        assert_eq!(route_name(&Route::Exact), "exact");
        assert_eq!(route_name(&Route::Phrase), "phrase");
        assert_eq!(route_name(&Route::NameLookup), "name_lookup");
        assert_eq!(route_name(&Route::Hybrid), "hybrid");
        assert_eq!(
            route_name(&Route::Aggregation {
                hint: crate::router::RouteHint {
                    tool: "query_records"
                }
            }),
            "aggregation"
        );
    }
}
