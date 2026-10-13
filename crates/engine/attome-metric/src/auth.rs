//! Compile-time privilege keys for this crate's routes — moved verbatim from
//! `attome-dashboard::auth` by D-480 (M26 R-14).
use attome_server::authz::PrivilegeKey;

/// `dashboard_metric_definition.read` — the compile-time policy for `metric.rs`'s
/// list/snapshots routes (M27 Phase 1). Metric values are visible to anyone
/// who may read the definition (plan §5) — the underlying query's own
/// privileges apply at compute time, under the service principal, not at
/// read time here.
#[derive(Debug)]
pub struct MetricRead;

impl PrivilegeKey for MetricRead {
    const KEY: &'static str = "dashboard_metric_definition.read";
}

/// `dashboard_metric_definition.update` — the compile-time policy for `metric.rs`'s
/// on-demand `/compute` route. Reuses the CRUD update privilege for a
/// bespoke business action, same convention `attome_dashboard::auth::
/// DashboardUpdate` uses for `lifecycle.rs`'s transitions.
#[derive(Debug)]
pub struct MetricUpdate;

impl PrivilegeKey for MetricUpdate {
    const KEY: &'static str = "dashboard_metric_definition.update";
}
