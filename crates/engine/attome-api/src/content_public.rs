//! Content Management public page-view route — the platform's first
//! unauthenticated, anonymous-facing data-serving route. Its path
//! (`/api/v1/content/view`) is registered as a bypass path in
//! `attome_server::middleware::bypass::EXACT_BYPASS_PATHS`, so it skips both
//! `AuthnLayer`/`AuthzLayer` AND `ModelRegistry`'s automatic license-gate
//! middleware (this route is merged directly in `system.rs`, not mounted
//! through an `EngineModel`) — it therefore performs its own manual license and
//! publish-status check below, and returns a plain `AppError::NotFound` on
//! either an unlicensed deployment or a missing/unpublished page. An
//! anonymous caller must never be able to tell "no such page" apart from
//! "this deployment doesn't have Content Management" — see D-367.
//!
//! There is no privilege/RLS context for an anonymous request to be scoped
//! to, so this handler runs its own hand-written, read-only query rather
//! than reusing any privileged path (`entity_crud`, etc).

use attome_content::model::{PublicPageView, VoteBody};
use attome_core::EngineState;
use attome_modules::MODULE_CONTENT;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::Deserialize;
use std::net::SocketAddr;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Deserialize, IntoParams)]
struct ViewQuery {
    /// The page's custom URL, e.g. `/guide/templates` — a query parameter
    /// rather than a path segment so this stays a single, easily-reasoned
    /// `EXACT_BYPASS_PATHS` entry instead of a `BYPASS_SUBTREE_PREFIXES`
    /// wildcard (see `bypass.rs`'s own doc comment on why subtree bypasses
    /// need much more careful "does this shadow a protected route"
    /// reasoning).
    path: String,
}

/// A published page's view-serving row, plus `id` (which `PublicPageView`
/// itself deliberately omits from the wire response — D-452 needs it only
/// to spawn the view-count write below).
#[derive(sqlx::FromRow)]
struct ViewRow {
    id: Uuid,
    title: String,
    #[sqlx(rename = "blocks_published")]
    blocks: serde_json::Value,
    seo_title: Option<String>,
    seo_description: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/content/view",
    tag = "content",
    params(ViewQuery),
    responses(
        (status = 200, description = "Success", body = PublicPageView),
        (status = 404, description = "No published page at this path (identical response whether the page doesn't exist, isn't published, or Content Management isn't licensed on this deployment)", body = ErrorResponse),
    ),
)]
async fn view_page(
    State(state): State<EngineState>,
    Query(q): Query<ViewQuery>,
) -> Result<Json<PublicPageView>, AppError> {
    if state.license.load().require(MODULE_CONTENT).is_err() {
        return Err(AppError::NotFound);
    }

    let row: Option<ViewRow> = sqlx::query_as(
        "SELECT id, title, blocks_published, seo_title, seo_description \
             FROM content_page \
             WHERE url_path = $1 AND status = 'published' AND is_deleted = FALSE",
    )
    .bind(&q.path)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;

    // M37 Phase 2 (D-452): off the request path, same discipline
    // `attome-search/telemetry.rs`'s impression logging documents — a page
    // render must never be slower, and must never fail, because analytics
    // are unavailable.
    let db = state.base.db.clone();
    let page_id = row.id;
    tokio::spawn(async move {
        if let Err(e) = attome_content::analytics::record_page_view(&db, page_id).await {
            tracing::error!(error = %e, "content page view was not recorded — this data point is unrecoverable");
        }
    });

    Ok(Json(PublicPageView {
        title: row.title,
        blocks: row.blocks,
        seo_title: row.seo_title,
        seo_description: row.seo_description,
    }))
}

/// A "was this useful" body-less struct wrapper isn't needed: `VoteBody`
/// (`attome-content::model`) already carries `url_path` + `useful`. Same
/// D-367 posture as `view_page` — identical 404 whether the page doesn't
/// exist, isn't published, or Content Management isn't licensed.
#[derive(serde::Serialize, ToSchema)]
struct VoteAck {
    recorded: bool,
}

const VOTE_LIMIT_PER_MINUTE: i32 = 5;

#[utoipa::path(
    post,
    path = "/api/v1/content/vote",
    tag = "content",
    request_body = VoteBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Telemetry,
        None,
        "an anonymous, rate-limited helpful/not-helpful vote on a published page; no identity, no business or security effect",
    )))),
    responses(
        (status = 200, description = "Success", body = VoteAck),
        (status = 404, description = "No published page at this path (identical response whether the page doesn't exist, isn't published, or Content Management isn't licensed on this deployment)", body = ErrorResponse),
        (status = 429, description = "Too many votes for this page from this address", body = ErrorResponse),
    ),
)]
async fn vote_on_page(
    State(state): State<EngineState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<VoteBody>,
) -> Result<Json<VoteAck>, AppError> {
    if state.license.load().require(MODULE_CONTENT).is_err() {
        return Err(AppError::NotFound);
    }

    let page_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM content_page \
         WHERE url_path = $1 AND status = 'published' AND is_deleted = FALSE",
    )
    .bind(&body.url_path)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;

    // Rate-limited per (page, caller address) via `attome_cache::rate_limit`
    // (guidelines §5 — reuse, do not build a second mechanism). Keyed by the
    // resolved page id rather than the raw url_path so the bucket survives a
    // page rename.
    let ip = attome_server::middleware::client_ip::client_ip_from_parts(
        peer.ip(),
        &headers,
        &state.base.config,
    );
    let key = format!("content:rl:vote:{page_id}:{ip}");
    let outcome = attome_cache::rate_limit::check(
        &state.base.redis_coordination,
        &key,
        VOTE_LIMIT_PER_MINUTE,
    )
    .await?;
    if !outcome.allowed {
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    }

    attome_content::analytics::record_helpfulness_vote(&state.base.db, page_id, body.useful)
        .await?;
    Ok(Json(VoteAck { recorded: true }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/content/view", get(view_page))
        .route("/api/v1/content/vote", post(vote_on_page))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(view_page, vote_on_page))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
