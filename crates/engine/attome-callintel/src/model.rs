//! `EngineModel` registration: mounted only when the `callintel` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_CALLINTEL, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct CallintelModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for CallintelModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-callintel"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_CALLINTEL
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        // D22-T2: `platform-bundles/attome-callintel.json`.
        &[
            "call_analysis",
            "call_tracker",
            "call_finding",
            "call_scorecard",
            "call_scorecard_answer",
            "call_comment",
            "call_library",
            "call_library_item",
            "call_daily_aggregate",
        ]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
    }
}
