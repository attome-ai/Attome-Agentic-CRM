//! M27 Phase 1 — KPI & Metrics (`document/module-master-plans/
//! M27-kpi-metrics.md`). Split out of `attome-dashboard` by D-480 (M26
//! R-14): metrics are the dependency root both M28 (Decision Intelligence)
//! and M48 (Scenario & Simulation) read (`attome-dashboard`'s `decision_seed.rs`/
//! `scenario.rs` depend on this crate for exactly that), while M26 dashboards
//! only ever reach a metric value indirectly through a widget's
//! `scorecard`/`trendline` config — no Rust-level dependency. See D-480 for
//! why M28/M48 themselves stay in `attome-dashboard`.
pub mod auth;
pub mod lineage;
pub mod metric;
pub mod model;
pub mod principal;

pub use model::MetricModel;

/// D-351 — this crate's advisory-lock namespace (`"attome-metric/…"` keys),
/// registered in `crates/server/tests/advisory_lock_namespaces.rs`. Was
/// namespace 15 (`"attome-dashboard/…"`) before D-480's split; advisory-lock
/// keys are process-local, so re-prefixing carries no rolling-upgrade
/// concern (see that file's own doc comment for the contrasting "borrowed
/// namespace" case, which does).
pub const ADVISORY_LOCK_NAMESPACE: i32 = 22;

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document. Merged in by `attome_api::openapi_document()`, next to
/// `attome_dashboard::openapi()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    metric::openapi_fragment()
}
