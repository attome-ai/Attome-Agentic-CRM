//! `EngineModel` registration: mounted only when the `ops` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_OPS, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct OpsModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for OpsModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-ops"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_OPS
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
            .merge(crate::upgrades::routes())
            .merge(crate::disasters::routes())
            .merge(crate::status::routes())
            .merge(crate::public_status::routes())
            .merge(crate::incidents::routes())
            .merge(crate::drills::routes())
            .merge(crate::drill_schedules::routes())
            .merge(crate::auditor_pack::routes())
            .merge(crate::freshness::routes())
            .merge(crate::recovery_targets::routes())
            .merge(crate::dr_runbook::routes())
            .merge(crate::live_rpo::routes())
            .merge(crate::switchover::routes())
    }
}
