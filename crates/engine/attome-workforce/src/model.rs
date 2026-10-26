//! `EngineModel` registration: mounted only when the `workforce` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_WORKFORCE, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct WorkforceModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for WorkforceModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-workforce"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_WORKFORCE
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        crate::admin::routes()
            .merge(crate::what_if::routes())
            .merge(crate::self_service::routes())
            .merge(crate::intraday::routes())
    }
}
