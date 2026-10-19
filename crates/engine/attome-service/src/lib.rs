pub mod auth;
/// G7-T1: the case-specific steps of a ticket merge.
pub mod case_merge;
pub mod change_calendar;
pub mod clock;
pub mod cmdb_impact;
pub mod cmdb_reconcile;
pub mod convert;
pub mod entitlement;
/// G8-T1: escalation rule sets compiled into M10 timers.
pub mod escalation;
mod intake;
pub mod model;
pub mod offering;
pub mod oncall;
/// G3-T2: cart orders.
pub mod order;
pub mod portal;
pub mod queue;
pub mod routing;
pub mod seed;
pub mod sla;
pub mod supplier_sla;
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
    doc.merge(order::openapi_fragment());
    doc.merge(clock::openapi_fragment());
    doc.merge(timeline::openapi_fragment());
    doc.merge(queue::openapi_fragment());
    doc
}
