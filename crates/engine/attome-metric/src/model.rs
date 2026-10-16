//! `EngineModel` registration for M27 (KPI & Metrics) — D-480 (M26 R-14) split
//! this crate out of `attome-dashboard`. Gated on `MODULE_DASHBOARD`, the same
//! module bit `attome_dashboard::DashboardModel` (and `attome_ai::decision::
//! DecisionExecutionModel`) already gate — see D-480 for why a metrics-only
//! crate shares the dashboard license bit rather than getting its own.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_DASHBOARD, ModuleId};
use axum::Router;

/// Registered via `EngineSystem::builder(state).register(MetricModel)` — only
/// mounted when `dashboard` is a licensed module bit (D-010), next to
/// `attome_dashboard::DashboardModel` in `crates/server/src/boot.rs`.
#[derive(Debug)]
pub struct MetricModel;

impl EngineModel for MetricModel {
    fn name(&self) -> &'static str {
        "attome-metric"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_DASHBOARD
    }

    /// D-383 — every entity `crate::metric_seed` provisions.
    /// `metric_snapshot` is deliberately excluded: it's an infrastructure
    /// table (migration `0160_metric_snapshot.sql`), not a provisioned
    /// entity, so it carries no `entity_info` row for this list to
    /// name.
    fn owned_entities(&self) -> &'static [&'static str] {
        &[
            "dashboard_metric_definition",
            "dashboard_metric_target",
            // P9-T1: `platform-bundles/attome-metric-governance.json`.
            "metric_scorecard",
            "metric_scorecard_item",
            "metric_comment",
        ]
    }

    // `engine_managed_fields` is left at the trait's default (`&[]`, R-03) —
    // no bespoke route of this crate transitions a field generic entity CRUD
    // must not also be allowed to set directly.

    fn routes(&self) -> Router<EngineState> {
        crate::metric::routes()
    }
}
