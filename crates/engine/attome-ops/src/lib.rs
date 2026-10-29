//! The reliability engine (roadmap AB4-T1).
//!
//! Every reliability feature builds here: cluster status and switchover
//! (AB2), recovery drills (AB3), incident pages (AB8), crash-point checks
//! (AB9), disaster declaration (AB11) and upgrades (U8). All of them are
//! opt-in (V2-D100): one server is the normal deployment, and with the
//! `ops` module off nothing here is mounted. Settings are `config.ops`
//! (`attome_config::OpsSection`); privileges and the Operations and Auditor
//! roles come from the `attome-ops` platform bundle.

/// AB3-T7: declared disasters under two-person control.
/// AB4-T10: the auditor pack of signed drill evidence.
pub mod auditor_pack;
/// AB2-T6: failovers and switchovers recorded from Patroni.
pub mod cluster;
pub mod disasters;
/// AB3-T8: the generated disaster runbook.
pub mod dr_runbook;
/// AB4-T7: when each kind of drill is due.
pub mod drill_schedules;
/// AB4-T6: drill evidence stored in the deployment.
pub mod drills;
pub mod error;
/// AB4-T2: the signed `attome-evidence/v1` record every drill writes.
pub mod evidence;
/// AB4-T9: how fresh each kind of drill is.
pub mod freshness;
/// AB11-T3: incident drafts, bilingual updates, corrections and resolution.
pub mod incidents;
/// AB3-T2: the live recovery point from three sources.
pub mod live_rpo;
/// AB11-T5: planned maintenance windows and their SLA exclusions.
pub mod maintenance;
pub mod model;
/// AB11-T2: component status and the status banner for signed-in users.
pub mod public_status;
/// AB3-T1: recovery targets per profile and scenario, with their proof.
pub mod recovery_targets;
/// AB2-T9: promoting the standby region.
pub mod standby;
/// AB2-T7: the cluster's status and failover history routes.
pub mod status;
/// AB11-T4: draft incidents for components that stay down.
pub mod status_watch;
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
    doc.merge(public_status::openapi_fragment());
    doc.merge(incidents::openapi_fragment());
    doc.merge(maintenance::openapi_fragment());
    doc.merge(drills::openapi_fragment());
    doc.merge(drill_schedules::openapi_fragment());
    doc.merge(auditor_pack::openapi_fragment());
    doc.merge(freshness::openapi_fragment());
    doc.merge(recovery_targets::openapi_fragment());
    doc.merge(dr_runbook::openapi_fragment());
    doc.merge(live_rpo::openapi_fragment());
    doc.merge(switchover::openapi_fragment());
    doc
}
