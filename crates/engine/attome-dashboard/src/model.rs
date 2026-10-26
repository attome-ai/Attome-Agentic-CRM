//! `EngineModel` registration for the Attome Decision Intelligence Platform.
//! Phases 1-5 (partial past Phase 3) only (see `document/
//! XRM-Dashboard-Module.md`): dashboard CRUD and its Draft -> Review ->
//! Approved -> Published -> Archived lifecycle (Phase 1), pages and a
//! section/layout tree per page (Phase 2), widgets placed on a section via
//! a built-in chart/text/operational/geospatial registry plus the
//! `scorecard`/`trendline` KPI widget types backed by `attome-metric`'s
//! `metric_snapshot` (D-480, M26 R-14 — see `widget_registry.rs`'s doc
//! comment; a separate `xrm-kpi` crate was never required and still doesn't
//! exist) (Phase 3), a widget's optional reference to an existing
//! admin-authored stored query — no from-scratch query builder (Phase 4's
//! "SQL power-user mode" slice only), and built-in/declared variable
//! resolution (Phase 5). Every entity `crate::seed::seed` registers gets
//! generic entity CRUD for free — including page/section/widget reordering
//! and move/resize (plain field updates) and page-level permission (the
//! existing generic per-record sharing mechanism) — so
//! `crate::lifecycle`/`crate::widget_actions` only add the transitions and
//! multi-widget actions the generic engine cannot express,
//! `crate::widget_registry` adds the one read-only capability listing
//! endpoint, and `crate::context` adds the one read-only variable
//! resolution endpoint.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_DASHBOARD, ModuleId};
use axum::Router;

/// Registered via `EngineSystem::builder(state).register(DashboardModel)` —
/// only mounted when `dashboard` is a licensed module bit (D-010).
#[derive(Debug)]
pub struct DashboardModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for DashboardModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-dashboard"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_DASHBOARD
    }

    /// D-383 — every entity `crate::seed` provisions.
    fn owned_entities(&self) -> &'static [&'static str] {
        &[
            "attome_dashboard",
            "dashboard_version",
            "dashboard_page",
            "dashboard_section",
            "dashboard_section_breakpoint",
            "dashboard_widget",
            "dashboard_variable",
            "dashboard_parameter",
            // M27 Phase 1 (KPI & Metrics) moved to its own `attome-metric` crate
            // and `MetricModel::owned_entities` (D-480, M26 R-14) —
            // `dashboard_metric_definition`/`dashboard_metric_target` are no longer
            // claimed here.
            // M28 Phase 1 (`decision.rs`/`decision_seed.rs`) — Decision
            // Intelligence records. `attome_ai::decision`'s own
            // `DecisionExecutionModel` (a separate `EngineModel`, see that
            // module's doc comment) owns no entities of its own; these three
            // stay claimed here so the generic entity path and this crate's
            // bespoke `approve` route agree about which module gates them.
            "dashboard_decision",
            "dashboard_decision_option",
            "dashboard_decision_dependency",
            // M48 Phase 1 (Scenario & Simulation scaffolding, `scenario.rs`/
            // `scenario_seed.rs`) — `dashboard_scenario_result` is a bounded,
            // per-scenario provisioned entity (not an infrastructure table
            // like `metric_snapshot`), so it belongs in this list.
            "dashboard_scenario",
            "dashboard_scenario_assumption",
            "dashboard_scenario_metric",
            "dashboard_scenario_result",
        ]
    }

    /// R-03 (`document/xrm/module/M26-dashboard/remediation.md`) —
    /// fields whose transition a bespoke route of this crate owns, so
    /// generic entity CRUD's `PATCH` must not be allowed to set them
    /// directly: `attome_dashboard.lifecycle_status`
    /// (`lifecycle.rs::do_publish_dashboard` et al. — advisory lock,
    /// `row_version`, the D-195 four-eyes gate, the version row, lifecycle
    /// audit) and `dashboard_decision.status` (`decision.rs::do_approve` —
    /// advisory lock, chosen-option ownership check, row_version guard).
    ///
    /// `dashboard_scenario.status` is deliberately absent: unlike the two above,
    /// nothing in `scenario.rs` ever transitions it after create (grep
    /// confirms the only `UPDATE dashboard_scenario` in this crate is absent —
    /// `status` is set once, at `do_clone`'s INSERT, and stays there; see
    /// `scenario_seed.rs`'s own doc comment on why it is "a plain Choice
    /// field rather than a boot-seeded M07 state model"). There is no
    /// bespoke route for generic CRUD to bypass, so guarding it here would
    /// only block an otherwise-ordinary field edit with no security benefit.
    fn engine_managed_fields(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("attome_dashboard", "lifecycle_status"),
            // D-521 — the live-version pointer only publish, activate,
            // unpublish and archive move. No initial value: it must be unset
            // on create.
            ("attome_dashboard", "published_version_id"),
            ("dashboard_decision", "status"),
        ]
    }

    /// D-524 — a dashboard is born `draft` and a decision `proposed`, on every
    /// create path (generic POST, bulk, upsert, staged import, S2S, bundle
    /// record sets). Anything else is refused by `entity_mutation::create_one`.
    fn engine_managed_initial_values(
        &self,
    ) -> &'static [(&'static str, &'static str, &'static str)] {
        &[
            ("attome_dashboard", "lifecycle_status", "draft"),
            ("dashboard_decision", "status", "proposed"),
        ]
    }

    /// Dashboard 10/10 Phase 2.1 — a widget's structured `config.data` and
    /// `config.bindings` are validated on every generic create and update.
    fn record_validators(&self) -> &'static [(&'static str, attome_core::model::RecordValidator)] {
        &[("dashboard_widget", crate::execution::validate_widget_record)]
    }

    fn routes(&self) -> Router<EngineState> {
        crate::lifecycle::routes()
            .merge(crate::layout::routes())
            .merge(crate::pages::routes())
            .merge(crate::widget_data::routes())
            .merge(crate::drill::routes())
            .merge(crate::widget_registry::routes())
            .merge(crate::widget_actions::routes())
            .merge(crate::declarative_widget::routes())
            .merge(crate::context::routes())
            .merge(crate::health::routes())
            .merge(crate::decision::routes())
            .merge(crate::scenario::routes())
            .merge(crate::embed::routes())
    }
}
