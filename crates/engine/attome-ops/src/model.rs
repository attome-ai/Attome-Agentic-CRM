//! `EngineModel` registration: mounted only when the `ops` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_OPS, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct OpsModel;

impl EngineModel for OpsModel {
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
    }
}
