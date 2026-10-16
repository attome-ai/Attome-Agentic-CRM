//! `EngineModel` registration: mounted with the core module, like the
//! human-resources pack it acts on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_CORE, ModuleId};
use axum::{
    Router,
    routing::{get, post},
};

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct HrModel;

impl EngineModel for HrModel {
    fn name(&self) -> &'static str {
        "attome-hr"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_CORE
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        // The records live in the human-resources pack (product layer).
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
            .route(
                "/api/v1/hr/leave-requests/{id}/submit",
                post(crate::leave::post_hr_leave_submit),
            )
            .route(
                "/api/v1/hr/availability",
                get(crate::leave::get_hr_availability),
            )
            .route(
                "/api/v1/hr/payroll-export",
                get(crate::payroll_export::get_hr_payroll_export),
            )
    }
}
