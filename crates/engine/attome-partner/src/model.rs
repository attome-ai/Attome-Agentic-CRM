//! `EngineModel` registration: mounted only when the `partner` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_PARTNER, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct PartnerModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for PartnerModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-partner"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_PARTNER
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        crate::registration::routes().merge(crate::mdf::routes())
    }
}
