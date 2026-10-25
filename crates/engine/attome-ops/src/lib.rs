//! The reliability engine (roadmap AB4-T1).
//!
//! Every reliability feature builds here: cluster status and switchover
//! (AB2), recovery drills (AB3), incident pages (AB8), crash-point checks
//! (AB9), disaster declaration (AB11) and upgrades (U8). All of them are
//! opt-in (V2-D100): one server is the normal deployment, and with the
//! `ops` module off nothing here is mounted. Settings are `config.ops`
//! (`attome_config::OpsSection`); privileges and the Operations and Auditor
//! roles come from the `attome-ops` platform bundle.

/// AB2-T6: failovers and switchovers recorded from Patroni.
pub mod cluster;
/// AB3-T7: declared disasters under two-person control.
pub mod disasters;
/// AB4-T6: drill evidence stored in the deployment.
pub mod drills;
pub mod error;
/// AB4-T2: the signed `attome-evidence/v1` record every drill writes.
pub mod evidence;
pub mod model;
/// AB2-T7: the cluster's status and failover history routes.
pub mod status;
/// AB2-T8: planned switchover under two-person control.
pub mod switchover;
/// AB8-T6: the upgrade record and its routes.
pub mod upgrades;

pub use error::OpsError;
pub use model::OpsModel;

/// This crate's advisory-lock namespace (`"attome-ops/…"` keys), registered
/// in `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 46;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = upgrades::openapi_fragment();
    doc.merge(disasters::openapi_fragment());
    doc.merge(status::openapi_fragment());
    doc.merge(drills::openapi_fragment());
    doc.merge(switchover::openapi_fragment());
    doc
}
