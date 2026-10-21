//! `EngineModel` registration: mounted only when the `workforce` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_WORKFORCE, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct WorkforceModel;

impl EngineModel for WorkforceModel {
    fn name(&self) -> &'static str {
        "attome-workforce"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_WORKFORCE
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        crate::admin::routes().merge(crate::what_if::routes())
    }
}
