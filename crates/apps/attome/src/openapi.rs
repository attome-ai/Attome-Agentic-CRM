//! P-api-contract Phase 1 — the workspace's single OpenAPI composition point.
//!
//! This crate is the only one that can see every layer at once (guidelines §3's
//! "assembly is centralized"), so the final merge lives here rather than in
//! `attome-api`: the engine layer cannot name `crates/server`'s auth handlers,
//! and it cannot name an engine that is mounted into `ModelRegistry` from
//! outside it (`attome-workflow`).
//!
//! Two consumers, one document:
//!   * `GET /api/v1/openapi.json` (mounted below, behind the normal
//!     authenticated middleware stack — deliberately *not* bypass-listed, per
//!     P-api-contract §4: no public-SDK consumer justifies handing the full
//!     route/schema map to an unauthenticated caller on a self-hosted
//!     deployment);
//!   * `server --print-openapi` (`main.rs`), the offline path Angular's
//!     `generate:api` codegen and CI's drift check use, so neither needs a
//!     live authenticated server just to read the contract.

use attome_auth::session::SessionClaims;
use attome_server::AppState;
use attome_types::ErrorResponse;
use axum::{Extension, Json, Router, routing::get};
use std::sync::{Arc, LazyLock};

/// Built once per process: assembling the document walks every generated
/// fragment, and it cannot change at runtime. `Arc` so the handler clones a
/// pointer rather than the whole document per request.
static DOCUMENT: LazyLock<Arc<utoipa::openapi::OpenApi>> = LazyLock::new(|| Arc::new(build()));

fn build() -> utoipa::openapi::OpenApi {
    // `attome_api::openapi_document()` already carries attome-server's root
    // identity/security schemes and the whole engine layer it can reach.
    let mut doc = attome_api::openapi_document();
    // Engines mounted through `ModelRegistry` from this crate — keep this list
    // in step with `boot`'s model registrations.
    doc.merge(attome_workflow::openapi());
    doc.merge(attome_ai::openapi());
    doc.merge(attome_portal::openapi());
    doc.merge(attome_sales::openapi());
    doc.merge(attome_callintel::openapi());
    doc.merge(attome_marketing::openapi());
    doc.merge(attome_billing::openapi());
    doc.merge(attome_commission::openapi());
    doc.merge(attome_partner::openapi());
    doc.merge(attome_fulfilment::openapi());
    doc.merge(attome_workforce::openapi());
    doc.merge(attome_contract::openapi());
    doc.merge(attome_offline::openapi());
    doc.merge(attome_search::engine::openapi());
    doc.merge(attome_report::openapi());
    doc.merge(attome_integration::openapi());
    // M41 Phase 1 (Process Intelligence, D-462) — same reasoning as the
    // engines above: `.register(attome_process::ProcessModel)` happens in
    // `boot.rs` (this crate), and `attome-process` has no dependency on
    // `attome-api` to merge this fragment from that layer instead.
    doc.merge(attome_process::openapi());
    // M57 Phase 1 (Document Generation, D-463) — same reasoning as
    // attome-process above.
    doc.merge(attome_docgen::openapi());
    // M36 Phase 0+1 (Predictive Intelligence, D-473) — same reasoning as
    // attome-process/attome-docgen above.
    doc.merge(attome_predict::openapi());
    // Trading Platform Phase 1 (document/TRADING-PLATFORM-PLAN.md) — same
    // reasoning as attome-process/attome-docgen/attome-predict above:
    // `.register(trd_engine::TrdModel)` happens in `boot.rs` (this crate),
    // and `trd-engine` sits above `attome-api` in the layer stack, so it has
    // no dependency on `attome-api` to merge this fragment from that layer
    // instead.
    // This crate's own auth surface.
    doc.merge(crate::auth::openapi());
    // M53 Phase 1 (Omnichannel, web chat only, D-474) — the public web chat
    // widget endpoint, mounted directly in `main.rs` for the same reason
    // `crate::auth::openapi()` is merged from here rather than from
    // `attome-api`.
    doc.merge(crate::omnichannel::openapi());
    doc.merge(<SelfDoc as utoipa::OpenApi>::openapi());
    // M61 Phase 1 (API Management, D-438) — applied last, against the fully
    // merged document: attome_server::middleware::deprecation::DEPRECATED_PATHS
    // is the single source of truth for both halves of a deprecation notice
    // (response headers, applied per-request by that module's middleware;
    // `deprecated: true` + `x-sunset`/`x-replacement` here), and a registry
    // entry can name a path mounted by any layer, so this can't run any
    // earlier than the point where every layer's paths are already present.
    attome_server::middleware::deprecation::apply_to_openapi(&mut doc);
    // S2-T8: the document names the release it describes.
    doc.info.version = env!("CARGO_PKG_VERSION").to_owned();
    // Z14-T2: every error code, as one enum the SDK can generate.
    doc.components
        .get_or_insert_with(Default::default)
        .schemas
        .insert(
            "ErrorCode".to_owned(),
            attome_types::error_codes::openapi_schema(),
        );
    doc
}

/// The assembled document. Cheap after the first call.
pub fn document() -> Arc<utoipa::openapi::OpenApi> {
    Arc::clone(&DOCUMENT)
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(openapi_json))]
struct SelfDoc;

#[utoipa::path(
    get,
    path = "/api/v1/openapi.json",
    tag = "operations",
    summary = "This API's own OpenAPI 3.1 document",
    responses(
        (status = 200, description = "The generated OpenAPI 3.1 document"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn openapi_json(
    // Not read — its presence is what makes the route unreachable without a
    // valid session/API key, matching every other non-bypass-listed route.
    Extension(_claims): Extension<SessionClaims>,
) -> Json<Arc<utoipa::openapi::OpenApi>> {
    Json(document())
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/v1/openapi.json", get(openapi_json))
}

#[cfg(test)]
mod tests {
    /// S2-T8: the version is the release's, not a placeholder.
    #[test]
    fn document_version_is_package_version() {
        assert_eq!(super::document().info.version, env!("CARGO_PKG_VERSION"));
        assert!(super::document().info.license.is_some());
    }

    /// Every operation has its own `operationId`. utoipa takes the handler's
    /// function name, so two `start_run` handlers collide, and the generated
    /// TypeScript then refuses to compile (duplicate identifier).
    #[test]
    fn operation_ids_are_unique() {
        let doc = serde_json::to_value(&*super::document()).unwrap();
        let mut seen = std::collections::BTreeMap::new();
        let mut duplicates = Vec::new();
        for (path, item) in doc["paths"].as_object().unwrap() {
            for (method, operation) in item.as_object().unwrap() {
                if let Some(id) = operation["operationId"].as_str() {
                    let here = format!("{} {path}", method.to_uppercase());
                    if let Some(first) = seen.insert(id.to_owned(), here.clone()) {
                        duplicates.push(format!("{id}: {first} and {here}"));
                    }
                }
            }
        }
        assert!(
            duplicates.is_empty(),
            "give each a distinct `operation_id = \"...\"` in its #[utoipa::path]: {duplicates:#?}"
        );
    }
}
