//! Work Intake self-service portal public routes (M70, D-423) — public
//! offering browsing and request-status-by-token lookup, no auth beyond the
//! token. Same shape as `content_public.rs` (that file's module doc has the
//! full reasoning): both paths are in `bypass::EXACT_BYPASS_PATHS`, merged
//! directly in `system.rs` rather than through `ServiceModel::routes()` (the
//! latter would go through `ModelRegistry`'s automatic per-module license
//! gate, `AppError::FeatureHidden`, which would leak licensing state to an
//! anonymous caller), and each handler runs its own manual license check so
//! an unlicensed deployment and a "just nothing here" state are
//! indistinguishable from outside.
//!
//! All business logic (the actual queries, the anti-enumeration token
//! verification) lives in `attome_service::portal` — this file is transport
//! only: manual license check, call, shape the response.

use attome_core::EngineState;
use attome_modules::MODULE_SERVICE;
use attome_service::portal::{PortalStatus, PublicOffering};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use serde::Deserialize;
use utoipa::IntoParams;

#[utoipa::path(
    get,
    path = "/api/v1/service-portal/offerings",
    tag = "service",
    responses(
        (status = 200, description = "Public, active offerings — empty on an unlicensed deployment, same as genuinely having none configured", body = Vec<PublicOffering>),
    ),
)]
async fn list_offerings(
    State(state): State<EngineState>,
) -> Result<Json<Vec<PublicOffering>>, AppError> {
    let active = state.license.load();
    let licensed = active.require(MODULE_SERVICE).is_ok();
    drop(active);
    if !licensed {
        // Not a 404: a list endpoint's natural "nothing configured" state is
        // an empty array, and it must be indistinguishable from "this
        // deployment isn't licensed for Work Intake" — the same anonymous
        // caller must never learn which is true.
        return Ok(Json(Vec::new()));
    }

    let offerings = attome_service::portal::list_public_offerings(&state.base.db).await?;
    Ok(Json(offerings))
}

#[derive(Deserialize, IntoParams)]
struct StatusQuery {
    /// The `{public_id}.{secret}` bearer handed back once, at creation, by
    /// `POST /api/v1/service-offering/{id}/create-work-request`.
    token: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/service-portal/status",
    tag = "service",
    params(StatusQuery),
    responses(
        (status = 200, description = "Success", body = PortalStatus),
        (status = 404, description = "No such token — identical response whether the token is malformed, unknown, wrong, or the deployment isn't licensed for this module", body = ErrorResponse),
    ),
)]
async fn lookup_status(
    State(state): State<EngineState>,
    Query(q): Query<StatusQuery>,
) -> Result<Json<PortalStatus>, AppError> {
    let active = state.license.load();
    let licensed = active.require(MODULE_SERVICE).is_ok();
    drop(active);
    if !licensed {
        return Err(AppError::NotFound);
    }

    let status =
        attome_service::portal::lookup_status(&state.base.db, &q.token, &state.base.pepper_ring())
            .await?
            .ok_or(AppError::NotFound)?;
    Ok(Json(status))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/service-portal/offerings", get(list_offerings))
        .route("/api/v1/service-portal/status", get(lookup_status))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_offerings, lookup_status))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
