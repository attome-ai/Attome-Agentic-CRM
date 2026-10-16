//! `EngineModel` registration: mounted only when the `callintel` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_CALLINTEL, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct CallintelModel;

impl EngineModel for CallintelModel {
    fn name(&self) -> &'static str {
        "attome-callintel"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_CALLINTEL
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
    }
}
