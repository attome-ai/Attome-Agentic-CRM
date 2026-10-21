//! `EngineModel` registration: mounted only when the `procurement` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_PROCUREMENT, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct ProcurementModel;

impl EngineModel for ProcurementModel {
    fn name(&self) -> &'static str {
        "attome-procurement"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_PROCUREMENT
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        // The records live in the procurement pack (product layer).
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        crate::po::routes()
    }
}
