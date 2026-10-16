//! `EngineModel` registration: mounted only when the `billing` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_BILLING, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct BillingModel;

impl EngineModel for BillingModel {
    fn name(&self) -> &'static str {
        "attome-billing"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_BILLING
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
    }
}
