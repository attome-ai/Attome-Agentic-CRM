pub mod auth;
/// G7-T1: the case-specific steps of a ticket merge.
pub mod case_merge;
pub mod change_calendar;
pub mod clock;
pub mod cmdb_impact;
pub mod cmdb_reconcile;
pub mod convert;
/// G1-T2: inbound email joins the right case.
pub mod email_threading;
pub mod entitlement;
/// G8-T1: escalation rule sets compiled into M10 timers.
pub mod escalation;
/// G5-T3: agent presence and record viewers.
pub mod inbox;
mod intake;
pub mod inventory;
pub mod maintenance;
pub mod major_incident;
pub mod model;
pub mod offering;
pub mod oncall;
/// G3-T2: cart orders.
pub mod order;
pub mod portal;
pub mod presence;
pub mod queue;
pub mod returns;
pub mod routing;
pub mod schedule_candidates;
pub mod seed;
pub mod sla;
pub mod status_page;
pub mod status_static;
pub mod supplier_sla;
pub mod timeline;
pub mod token;
pub mod warranty;
pub mod work_order;

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
    doc.merge(presence::openapi_fragment());
    doc.merge(inbox::openapi_fragment());
    doc.merge(status_page::openapi_fragment());
    doc.merge(warranty::openapi_fragment());
    doc.merge(inventory::openapi_fragment());
    doc.merge(returns::openapi_fragment());
    doc.merge(schedule_candidates::openapi_fragment());
    doc.merge(major_incident::openapi_fragment());
    doc
}
