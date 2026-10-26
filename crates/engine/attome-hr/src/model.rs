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

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for HrModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

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
            .route(
                "/api/v1/hr/payroll-handoff",
                post(crate::payroll_export::post_hr_payroll_handoff),
            )
            .route(
                "/api/v1/hr/payroll-handoff/confirm",
                post(crate::payroll_export::post_hr_payroll_confirm),
            )
            .route(
                "/api/v1/hr/offers/{id}/hire",
                post(crate::hire::post_hr_hire),
            )
    }
}
