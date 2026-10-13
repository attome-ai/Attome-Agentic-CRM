//! Phase 2/3 route stubs — `/bottlenecks`, `/conformance`, `/findings`.
//! Explicitly deferred by the module plan's Phase 1 scope (`document/
//! module-master-plans/M41-process-intelligence.md` §6): bottleneck/rework/
//! waste finders, conformance replay against `workflow_definition_
//! version`'s published graph, and findings→decisions integration (M28) all
//! need real computation this workspace does not have yet. Mounted and
//! documented now (so the route surface + OpenAPI contract are stable and
//! `generate:api` produces real client types for them) but every one always
//! answers `501 Not Implemented` with a `not_computable`-shaped body — the
//! same honest-stub pattern `attome-dashboard::scenario`'s formula-backed-metric
//! result already uses for "the mechanism this needs is not implemented in
//! this workspace yet" (see that module's `evaluate_one_metric`).

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::ErrorResponse;
use axum::{Json, Router, extract::Path, http::StatusCode, routing::get};
use uuid::Uuid;

use crate::model::NotComputableResponse;

fn not_computable(reason: &str) -> (StatusCode, Json<NotComputableResponse>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(NotComputableResponse {
            status: "not_computable",
            reason: reason.to_string(),
        }),
    )
}

#[utoipa::path(
    get,
    path = "/api/v1/process/case-defs/{id}/bottlenecks",
    tag = "process",
    params(("id" = Uuid, Path, description = "Case definition id")),
    responses(
        (status = 200, description = "Planned Phase 2 response shape", body = NotComputableResponse),
        (status = 501, description = "Not implemented in Phase 1 — see attome-process::stubs' doc comment", body = NotComputableResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn bottlenecks(
    _ctx: Authorized<Admin>,
    Path(_id): Path<Uuid>,
) -> (StatusCode, Json<NotComputableResponse>) {
    not_computable(
        "bottleneck detection is M41 Phase 2 (waiting-time ranking over process_event) — \
         not implemented in this workspace yet. See document/module-master-plans/\
         M41-process-intelligence.md §6.",
    )
}

#[utoipa::path(
    get,
    path = "/api/v1/process/case-defs/{id}/conformance",
    tag = "process",
    params(("id" = Uuid, Path, description = "Case definition id")),
    responses(
        (status = 200, description = "Planned Phase 2 response shape", body = NotComputableResponse),
        (status = 501, description = "Not implemented in Phase 1 — see attome-process::stubs' doc comment", body = NotComputableResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn conformance(
    _ctx: Authorized<Admin>,
    Path(_id): Path<Uuid>,
) -> (StatusCode, Json<NotComputableResponse>) {
    not_computable(
        "conformance checking (replaying each variant against the published \
         workflow_definition_version graph) is M41 Phase 2 — not implemented in this \
         workspace yet. See document/module-master-plans/M41-process-intelligence.md §6.",
    )
}

#[utoipa::path(
    get,
    path = "/api/v1/process/case-defs/{id}/findings",
    tag = "process",
    params(("id" = Uuid, Path, description = "Case definition id")),
    responses(
        (status = 200, description = "Planned Phase 2 response shape", body = NotComputableResponse),
        (status = 501, description = "Not implemented in Phase 1 — see attome-process::stubs' doc comment", body = NotComputableResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn findings(
    _ctx: Authorized<Admin>,
    Path(_id): Path<Uuid>,
) -> (StatusCode, Json<NotComputableResponse>) {
    not_computable(
        "bottleneck/rework/waste findings and their M28 findings-to-decisions integration are \
         M41 Phase 2/3 — not implemented in this workspace yet. See document/\
         module-master-plans/M41-process-intelligence.md §6.",
    )
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/process/case-defs/{id}/bottlenecks",
            get(bottlenecks),
        )
        .route(
            "/api/v1/process/case-defs/{id}/conformance",
            get(conformance),
        )
        .route("/api/v1/process/case-defs/{id}/findings", get(findings))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(bottlenecks, conformance, findings))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
