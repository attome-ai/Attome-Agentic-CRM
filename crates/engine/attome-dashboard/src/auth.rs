//! Compile-time privilege key for this crate's bespoke lifecycle routes —
//! ordinary field reads/writes on `attome_dashboard`/`dashboard_version` go
//! through generic entity CRUD, which already enforces
//! `attome_dashboard.{read,create,update,delete,bulk}` itself; the
//! state-machine transitions in `lifecycle.rs` are business actions, not
//! field updates, so they need their own compile-time policy — same shape as
//! `attome-service::auth::WorkRequestUpdate`.
use attome_server::authz::PrivilegeKey;

#[derive(Debug)]
pub struct DashboardUpdate;

impl PrivilegeKey for DashboardUpdate {
    const KEY: &'static str = "attome_dashboard.update";
}

/// `attome_dashboard.create` — the compile-time policy for `layout.rs`'s
/// `create_from_layout` route (single-call dashboard + full page/section/
/// widget tree creation, e.g. from an AI-authored layout document). Distinct
/// from `DashboardUpdate`: this route creates a brand new `attome_dashboard` row
/// rather than transitioning or mutating an existing one, so it wants the
/// CRUD create privilege, same convention `lifecycle.rs::clone_dashboard`
/// already uses via `ctx.require_key("attome_dashboard.create")`.
#[derive(Debug)]
pub struct DashboardCreate;

impl PrivilegeKey for DashboardCreate {
    const KEY: &'static str = "attome_dashboard.create";
}

/// `dashboard_widget.update` — the compile-time policy for
/// `widget_actions`'s duplicate route. `duplicate` also
/// requires `dashboard_widget.create`, checked with `ctx.require_key`
/// inside the handler (same `Authorized<P>`-only-composes-one-policy
/// reasoning as `attome-service::convert`).
#[derive(Debug)]
pub struct WidgetUpdate;

impl PrivilegeKey for WidgetUpdate {
    const KEY: &'static str = "dashboard_widget.update";
}

/// `attome_dashboard.read` — the compile-time policy for `context`'s
/// resolve-variables route. Read-only and dashboard-specific (it also
/// returns that dashboard's own declared `dashboard_variable`/
/// `dashboard_parameter` default values), so it wants the read
/// privilege, not `DashboardUpdate` and not bare authentication.
#[derive(Debug)]
pub struct DashboardRead;

impl PrivilegeKey for DashboardRead {
    const KEY: &'static str = "attome_dashboard.read";
}

/// `dashboard_decision.update` — the compile-time policy for `decision.rs`'s
/// `approve` transition (M28 Phase 1). Same "reuse the CRUD update privilege
/// for a bespoke business action" convention `DashboardUpdate`/
/// `attome_metric::auth::MetricUpdate` already use. `attome_ai::decision`'s own `execute` route declares its own
/// copy of this same string (it cannot import this type — see that module's
/// doc comment for why) rather than depending on this crate for one marker
/// type.
#[derive(Debug)]
pub struct DecisionUpdate;

impl PrivilegeKey for DecisionUpdate {
    const KEY: &'static str = "dashboard_decision.update";
}

/// `dashboard_scenario.read` — the compile-time policy for `scenario.rs`'s
/// read-only `compare` route (M48 Phase 1 scaffolding).
#[derive(Debug)]
pub struct ScenarioRead;

impl PrivilegeKey for ScenarioRead {
    const KEY: &'static str = "dashboard_scenario.read";
}

/// `dashboard_scenario.update` — the compile-time policy for `scenario.rs`'s
/// `evaluate`/`clone` business actions. Same "reuse the CRUD update
/// privilege for a bespoke business action" convention `DashboardUpdate`/
/// `DecisionUpdate` already use in this crate (and `attome_metric::auth::
/// MetricUpdate` in the crate this one depends on).
#[derive(Debug)]
pub struct ScenarioUpdate;

impl PrivilegeKey for ScenarioUpdate {
    const KEY: &'static str = "dashboard_scenario.update";
}
