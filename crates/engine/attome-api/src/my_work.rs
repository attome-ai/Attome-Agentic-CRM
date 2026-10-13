//! Dashboard 10/10 Phase 6 ("My Work and Action Center") — the aggregation
//! route over every registered `attome_core::MyWorkProvider`. Composition
//! only: each handler here just fans out to `state.my_work_providers` and
//! shapes the response; the actual eligibility/visibility logic lives in
//! each provider (`crate::my_work_approvals` today).
//!
//! `Authorized<SelfService>`, same posture `sidebar.rs::get_sidebar` already
//! documents for "the caller's own menu, filtered by the caller's own
//! privileges" — here it's "the caller's own actionable work", and every
//! provider is required (by the trait's own doc) to filter to what this
//! specific caller may act on, so the route itself needs no further gate.

use std::collections::HashMap;

use attome_core::{EngineState, MyWorkAction, MyWorkPage};
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;

/// `?cursor=&limit=` on `GET /api/v1/my-work/{provider}` — mirrors
/// `PaginatedResponse`'s own `page_size` bounds (guidelines §12) even though
/// the envelope here is cursor-shaped, not page-numbered (§12's
/// `query/execute` exception: a large, provider-owned scan, not a bounded
/// structural walk).
#[derive(Deserialize, IntoParams)]
struct MyWorkListQuery {
    cursor: Option<String>,
    limit: Option<i64>,
}

/// Every open item this caller has, across every registered provider.
/// Cheap: each provider's `count` is documented to skip item bodies.
#[utoipa::path(
    get,
    path = "/api/v1/my-work/counts",
    tag = "my-work",
    responses(
        (status = 200, description = "Success", body = HashMap<String, usize>),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn counts(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<HashMap<String, usize>>, AppError> {
    let mut out = HashMap::new();
    for provider in state.my_work_providers.iter() {
        let count = provider.count(&state, &ctx).await?;
        out.insert(provider.name().to_string(), count);
    }
    Ok(Json(out))
}

/// A page of this caller's open items from one named provider
/// (`MyWorkProvider::name()`, e.g. `"approvals"`).
#[utoipa::path(
    get,
    path = "/api/v1/my-work/{provider}",
    tag = "my-work",
    params(("provider" = String, Path), MyWorkListQuery),
    responses(
        (status = 200, description = "Success", body = MyWorkPage),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 404, description = "No such provider", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_provider(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(provider_name): Path<String>,
    Query(query): Query<MyWorkListQuery>,
) -> Result<Json<MyWorkPage>, AppError> {
    let provider = find_provider(&state, &provider_name)?;
    let limit = query
        .limit
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE) as usize;
    let page = provider
        .list(&state, &ctx, query.cursor.as_deref(), limit)
        .await?;
    Ok(Json(page))
}

/// The actions this caller may take on one specific item right now,
/// re-resolved fresh (never `list`'s earlier snapshot — the trait's own
/// concurrency posture).
#[utoipa::path(
    get,
    path = "/api/v1/my-work/{provider}/{record_id}/actions",
    tag = "my-work",
    params(("provider" = String, Path), ("record_id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = Vec<MyWorkAction>),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 404, description = "No such provider", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn item_actions(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((provider_name, record_id)): Path<(String, Uuid)>,
) -> Result<Json<Vec<MyWorkAction>>, AppError> {
    let provider = find_provider(&state, &provider_name)?;
    let actions = provider.actions(&state, &ctx, record_id).await?;
    Ok(Json(actions))
}

fn find_provider<'a>(
    state: &'a EngineState,
    name: &str,
) -> Result<&'a dyn attome_core::MyWorkProvider, AppError> {
    state
        .my_work_providers
        .iter()
        .map(AsRef::as_ref)
        .find(|p| p.name() == name)
        .ok_or(AppError::NotFound)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/my-work/counts", get(counts))
        .route("/api/v1/my-work/{provider}", get(list_provider))
        .route(
            "/api/v1/my-work/{provider}/{record_id}/actions",
            get(item_actions),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document, same split `sidebar.rs` documents (private handlers need their
/// own fragment; `openapi.rs` merges every fragment back together).
#[derive(utoipa::OpenApi)]
// `MyWorkItem` is registered by hand: `MyWorkPage`'s generic envelope inlines
// it, and the Angular client names it (BTY-12).
#[openapi(
    paths(counts, list_provider, item_actions),
    components(schemas(attome_core::MyWorkItem))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
