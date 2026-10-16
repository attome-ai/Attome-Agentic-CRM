pub mod auth;
pub mod change_calendar;
pub mod clock;
pub mod convert;
mod intake;
pub mod model;
pub mod offering;
pub mod portal;
pub mod queue;
pub mod routing;
pub mod seed;
pub mod sla;
pub mod timeline;
pub mod token;

pub use model::ServiceModel;

/// D-351 — this crate's advisory-lock namespace (`"attome-service/…"` keys),
/// registered in `crates/server/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 14;

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document. Merged in by `attome_api::openapi_document()`, same composition
/// point as `attome_project::openapi()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = convert::openapi_fragment();
    doc.merge(sla::openapi_fragment());
    doc.merge(offering::openapi_fragment());
    doc.merge(clock::openapi_fragment());
    doc.merge(timeline::openapi_fragment());
    doc.merge(queue::openapi_fragment());
    doc
}
