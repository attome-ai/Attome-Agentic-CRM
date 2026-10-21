//! `attome-report` — the Reporting Engine (F211-F215,
//! `document/XRM_Implementation_Plan.txt`'s Phase 4 "Reporting Engine"):
//! `attome_report`/`report_schedule`, scheduled CSV/XLSX report generation
//! over a stored query. `MODULE_REPORT` (id 9, `attome-modules/src/modules.rs`)
//! was reserved since the initial module map; this is the first crate to
//! claim it.
//!
//! D-479 (M26 R-09) retired this crate's other, older feature — the legacy
//! `dashboard` entity and its own widget-type catalog
//! (`widget_catalog.rs`/`GET /api/v1/report/widget-types`, both deleted).
//! `attome-dashboard`'s `attome_dashboard`/`widget_registry` is the one remaining
//! dashboard product and widget catalog. The one-shot legacy migration job
//! (`attome-api::dashboard_migration`) was deleted outright (D-790).
//!
//! Deliberately thin. `attome_report`/`report_schedule` are normal XRM
//! entities (`seed.rs::seed_reports`), so generic entity CRUD, per-entity
//! privileges, audit, and the existing generic per-record sharing mechanism
//! (`record_share`) all apply with zero code here.

pub mod auth;
pub mod delivery;
pub mod model;
pub mod render;
pub mod report_admin;
pub mod run;
pub mod schedule_admin;
pub mod scheduler;
pub mod seed;

pub use model::ReportModel;

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document, merged in by `server::openapi::document`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = report_admin::openapi_fragment();
    doc.merge(run::openapi_fragment());
    doc.merge(schedule_admin::openapi_fragment());
    doc
}
