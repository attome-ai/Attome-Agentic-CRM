//! `EngineModel` registration: mounted only when the `offline` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_OFFLINE, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct OfflineModel;

impl EngineModel for OfflineModel {
    fn name(&self) -> &'static str {
        "attome-offline"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_OFFLINE
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
    }
}
