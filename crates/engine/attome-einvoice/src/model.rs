//! `EngineModel` registration: e-invoicing is part of invoicing, so it is
//! mounted only when the `billing` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_BILLING, ModuleId};
use axum::{
    Router,
    routing::{get, post},
};

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct EinvoiceModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for EinvoiceModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-einvoice"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_BILLING
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
            .route(
                "/api/v1/einvoice/devices",
                get(crate::routes::get_devices).post(crate::routes::post_device),
            )
            .route(
                "/api/v1/einvoice/devices/{id}/onboard",
                post(crate::routes::post_onboard),
            )
    }
}
