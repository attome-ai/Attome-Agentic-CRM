//! `EngineModel` registration: mounted only when the `partner` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_PARTNER, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct PartnerModel;

impl EngineModel for PartnerModel {
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
        Router::new()
    }
}
