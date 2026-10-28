//! Saved searches (M11 gap list) — a normal XRM entity, not a dedicated
//! engine table.
//!
//! Same reasoning `attome-report`'s `dashboard` entity gives for itself: a saved
//! search is `saved_search`, a runtime-provisioned entity, so generic
//! entity CRUD, per-entity privileges, audit, and — the whole point —
//! **the existing generic per-record sharing mechanism**
//! (`record_share`) all apply with zero code here. The module plan's
//! wording ("owner, `is_shared`") maps onto that mechanism exactly:
//! `owner_ref` is the standard column every provisioned entity carries, and
//! "shared" is whatever the Permissions tab / `record_share`
//! already means for any other entity — there is no bespoke `is_shared`
//! column here, on purpose, per the plan's own instruction not to invent new
//! sharing logic.
//!
//! What this file *does* own, because generic CRUD cannot express it:
//!
//! * `run` (`GET /api/v1/search/saved/{id}/run`) — reads the saved search's
//!   `query_text` (re-checking the CALLER's own visibility — never the
//!   creator's, see [`run`]'s doc comment) and re-issues it through
//!   [`crate::routes::execute_search`], the exact same enforcement path
//!   `/api/v1/search` uses. "Run" is never a stored, replayed result set.
//! * [`sweep_alerts`] — the bounded, scheduled alert-on-new-results job
//!   (`EngineJob::SearchSavedSearchAlertSweep`, wired in
//!   `crates/server/src/jobs.rs`). See its own doc comment for why "new
//!   results" is a result-count high-water mark rather than a per-row
//!   timestamp comparison.

use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::router::Audience;
use crate::routes::{SearchResponse, parse_audience, validate_paging, validate_query};

// `saved_search`'s entity/attribute/view provisioning lives in
// `platform-bundles/attome-search-saved-search.json`, applied from
// `crates/server/src/boot.rs` via `attome_api::bundle::
// apply_platform_bundle` BEFORE `EngineSystem::builder(state)....build()`
// (D-478 seeds-to-bundles, second pass; this file's old `seed()` was
// proven a pure no-op against that bundle first). It applies from
// `boot.rs` rather than `system.rs` because `attome-api`'s dependency on
// `attome-search` is dev-only, so the bundle's `include_str!` and watermark
// key (`attome-search-saved-search`, unchanged) are owned by the binary.

// ── "Run" action ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RunSavedSearchParams {
    /// One-based: page 1 is the first page.
    #[serde(default = "one")]
    #[param(minimum = 1)]
    pub page: i64,
    /// Rows per page.
    #[serde(default = "twenty_five")]
    pub page_size: i64,
    /// Who the results are for.
    #[serde(default)]
    pub audience: Option<String>,
}
fn one() -> i64 {
    1
}
fn twenty_five() -> i64 {
    25
}

/// Reads one saved search's `query_text`, re-checking **the caller's own**
/// visibility — this is not the record's owner's visibility, and must never
/// be. A saved search that is shared (via the ordinary Permissions
/// mechanism) can legitimately be *run* by someone other than its owner, and
/// when it is, the results must be exactly what that caller could see by
/// typing the same query themselves. Replaying the owner's visibility here
/// would be a privilege-escalation path disguised as a convenience feature.
async fn load_visible_query_text(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<Option<String>, AppError> {
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

    // `'saved_search'` is spliced (per `PolymorphicVisibility::push`'s own
    // contract), never bound — and it is a fixed Rust string literal, never
    // request data, exactly what that contract requires.
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> =
        sqlx::QueryBuilder::new("SELECT t.query_text FROM saved_search t WHERE t.id = ");
    qb.push_bind(id);
    qb.push(" AND t.is_active IS NOT FALSE");
    visibility.push(&mut qb, "'saved_search'", "t.id");

    qb.build_query_scalar::<String>()
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)
}

/// Run a saved search
///
/// Runs a saved search now, under the caller's own access.
#[utoipa::path(
    get,
    path = "/api/v1/search/saved/{id}/run",
    tag = "search",
    params(("id" = Uuid, Path, description = "Saved search id"), RunSavedSearchParams),
    responses(
        (status = 200, description = "A bounded page of results, as this caller would see them today", body = SearchResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No saved search with that id is visible to the caller", body = ErrorResponse),
        (status = 422, description = "The saved query text or pagination is outside the documented caps", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn run(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Query(params): Query<RunSavedSearchParams>,
) -> Result<Json<SearchResponse>, AppError> {
    let stored = load_visible_query_text(&state, &ctx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let q = validate_query(&stored)?;
    validate_paging(params.page, params.page_size)?;
    let audience = parse_audience(params.audience.as_deref())?;

    let response =
        crate::routes::execute_search(&state, &ctx, &q, params.page, params.page_size, audience)
            .await?;
    Ok(Json(response))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/search/saved/{id}/run", get(run))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(run))]
#[derive(Debug)]
pub struct ApiDocFragment;

// ── Alert sweep ──────────────────────────────────────────────────────────

/// Advisory-lock key for the sweep tick. `{crate}/{operation}:{resource}` per
/// guidelines §2, in `attome-search`'s own namespace (`ADVISORY_LOCK_NAMESPACE`,
/// registered in `crates/server/tests/advisory_lock_namespaces.rs`).
const ALERT_SWEEP_LOCK_KEY: &str = "attome-search/saved-search:alert-sweep";

/// Bounded per tick — guidelines §9: durable/bulk background work needs
/// bounded batch sizes, not an unbounded scan. The plan's own instruction
/// ("bounded — don't build unbounded polling") is the same constraint from
/// the product side.
const ALERT_SWEEP_BATCH: i64 = 100;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AlertSweepStats {
    pub checked: i64,
    pub notified: i64,
}

/// One row of `sweep_alerts`'s batch read: `(id, name, query_text, owner_ref,
/// last_seen_result_count)`. Named so clippy's `type_complexity` lint (and
/// the next reader) doesn't have to parse the tuple shape twice.
type AlertSweepRow = (Uuid, String, String, Option<Uuid>, Option<i64>);

struct AlertCandidate {
    id: Uuid,
    name: String,
    query_text: String,
    owner_ref: Uuid,
    last_seen_result_count: Option<i64>,
}

/// The bounded, scheduled saved-search alert sweep
/// (`EngineJob::SearchSavedSearchAlertSweep`).
///
/// **"New results" is a result-COUNT high-water mark, not a per-row
/// timestamp comparison.** The alternative — comparing each hit's
/// `indexed_at` against a stored watermark — needs `indexed_at` projected out
/// of the fused statement, which `legs`/`fuse.rs` deliberately do not do (the
/// module plan is explicit that this gap list must not touch core
/// ranking/router logic beyond the fuzzy leg). Comparing the *count* instead
/// needs nothing from the fused statement beyond what
/// [`crate::routes::execute_search`] already returns
/// (`SearchResponse::total`), so this reuses that function completely
/// unchanged and stays entirely outside `legs`/`fuse`/`router`.
///
/// **Runs as the saved search's OWNER, never as "whoever happens to run the
/// sweep."** There is no live caller for a scheduled job to impersonate, and
/// the owner is the one principal a background alert can legitimately act
/// on behalf of — `attome_security::resolver::resolve_uncached` resolves a real,
/// current `SecurityContext` for them (not a cached one, so a revoked owner's
/// alert stops immediately rather than up to a stale TTL later), and the
/// alert is delivered to that same owner. A search shared with other people
/// still alerts only its owner; sharing a saved search shares the ability to
/// *run* it, not its alert subscription.
pub async fn sweep_alerts(state: &EngineState) -> Result<AlertSweepStats, AppError> {
    let db = &state.base.db;
    let mut lock_tx = attome_db::tx::begin(db).await?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(ALERT_SWEEP_LOCK_KEY)
        .fetch_one(&mut *lock_tx)
        .await
        .map_err(AppError::internal)?;
    if !acquired {
        // Another node is already running this tick's sweep — nothing to
        // wait for, same reasoning as the search drain's own try-lock.
        return Ok(AlertSweepStats::default());
    }

    let rows: Vec<AlertSweepRow> = sqlx::query_as(
        "SELECT id, name, query_text, owner_ref, last_seen_result_count::bigint \
           FROM saved_search \
          WHERE alert_enabled = TRUE AND is_active IS NOT FALSE AND owner_ref IS NOT NULL \
          ORDER BY last_seen_result_count ASC NULLS FIRST, id \
          LIMIT $1",
    )
    .bind(ALERT_SWEEP_BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut stats = AlertSweepStats::default();
    for (id, name, query_text, owner_ref, last_seen_result_count) in rows {
        let Some(owner_ref) = owner_ref else {
            continue;
        };
        stats.checked += 1;
        let candidate = AlertCandidate {
            id,
            name,
            query_text,
            owner_ref,
            last_seen_result_count,
        };
        match check_and_notify(state, &candidate).await {
            Ok(true) => stats.notified += 1,
            Ok(false) => {}
            Err(e) => {
                // Loud, and NOT fatal to the tick — one owner's revoked
                // access, malformed saved query, or a transient DB error must
                // not stop the rest of the batch. The next tick retries this
                // row (nothing here is consumed/dequeued on failure).
                tracing::warn!(
                    error = %e,
                    saved_search_id = %id,
                    "saved search alert check failed; skipping for this tick"
                );
            }
        }
    }

    lock_tx.commit().await.map_err(AppError::internal)?;
    Ok(stats)
}

/// One saved search's alert check. Returns whether a notification was sent.
async fn check_and_notify(
    state: &EngineState,
    candidate: &AlertCandidate,
) -> Result<bool, AppError> {
    // The real, current resolve — not the request-path L1/L2 cache — so a
    // revoked owner's alert stops on the very next tick rather than up to a
    // stale cache TTL later. See `attome_security::resolver::resolve_uncached`'s
    // own doc comment: exactly the "long-running worker" case it exists for.
    let owner_ctx =
        attome_security::resolver::resolve_uncached(&state.base.db, candidate.owner_ref).await?;

    let q = match validate_query(&candidate.query_text) {
        Ok(q) => q,
        Err(_) => {
            // A saved query that no longer validates (caps tightened since it
            // was saved, for instance) is not an error worth retrying every
            // tick forever — skip it silently rather than warn-spamming an
            // operator about someone's stored text.
            return Ok(false);
        }
    };

    let response =
        crate::routes::execute_search(state, &owner_ctx, &q, 1, 1, Audience::Human).await?;
    let new_count = match response.total {
        crate::routes::Total::Exact { value } | crate::routes::Total::AtLeast { value } => {
            value as i64
        }
    };

    let baseline = candidate.last_seen_result_count.unwrap_or(0);
    if new_count <= baseline {
        return Ok(false);
    }

    let req = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale: "en".to_owned(),
        recipient_user_ref: Some(candidate.owner_ref),
        is_global: false,
        organization_ref: None,
        channels: None, // REVIEW-2026-09-02 finding #3: inherit the platform default (in_app+email), not an in-app-only override
        subject: Some(format!("New results: \"{}\"", candidate.name)),
        body_html: None,
        body_text: Some(format!(
            "Your saved search \"{}\" now matches {new_count} result(s).",
            candidate.name
        )),
        route: None,
        variables: std::collections::HashMap::new(),
        priority: "normal".to_owned(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    attome_notification::dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        req,
    )
    .await?;

    sqlx::query("UPDATE saved_search SET last_seen_result_count = $1 WHERE id = $2")
        .bind(new_count)
        .bind(candidate.id)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_key_is_namespaced_and_scoped() {
        assert!(ALERT_SWEEP_LOCK_KEY.starts_with("attome-search/"));
        assert!(ALERT_SWEEP_LOCK_KEY.contains(':'));
    }

    #[test]
    fn the_batch_size_is_actually_bounded() {
        const _: () = assert!(ALERT_SWEEP_BATCH > 0);
        const _: () = assert!(ALERT_SWEEP_BATCH <= 1000);
    }
}
