//! `EngineModel` registration: mounted only when the `commission` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_COMMISSION, ModuleId};
use axum::{Router, routing::post};

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct CommissionModel;

impl EngineModel for CommissionModel {
    fn name(&self) -> &'static str {
        "attome-commission"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_COMMISSION
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new().route(
            "/api/v1/commission/periods/{id}/runs",
            post(crate::run::post_run),
        )
    }
}
