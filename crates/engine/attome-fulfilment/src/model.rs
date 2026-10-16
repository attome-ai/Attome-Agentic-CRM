//! `EngineModel` registration: mounted only when the `fulfilment` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_FULFILMENT, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct FulfilmentModel;

impl EngineModel for FulfilmentModel {
    fn name(&self) -> &'static str {
        "attome-fulfilment"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_FULFILMENT
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
    }
}
