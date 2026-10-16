//! `EngineModel` registration: mounted only when the `marketing` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_MARKETING, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct MarketingModel;

impl EngineModel for MarketingModel {
    fn name(&self) -> &'static str {
        "attome-marketing"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_MARKETING
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
    }
}
