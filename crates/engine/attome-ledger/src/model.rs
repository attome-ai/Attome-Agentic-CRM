//! `EngineModel` registration: mounted only when the `ledger` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_LEDGER, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct LedgerModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for LedgerModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-ledger"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_LEDGER
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        // The records live in the ledger pack (product layer).
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        crate::posting::routes()
            .merge(crate::intercompany::routes())
            .merge(crate::statements::routes())
            .merge(crate::revrec::contract::routes())
            .merge(crate::revrec::allocation::routes())
    }
}
