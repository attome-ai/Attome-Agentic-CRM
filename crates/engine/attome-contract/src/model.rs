//! `EngineModel` registration: mounted only when the `contract` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_CONTRACT, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct ContractModel;

impl EngineModel for ContractModel {
    fn name(&self) -> &'static str {
        "attome-contract"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_CONTRACT
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
    }
}
