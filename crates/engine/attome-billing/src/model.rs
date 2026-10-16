//! `EngineModel` registration: mounted only when the `billing` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_BILLING, ModuleId};
use axum::{Router, routing::post};

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
        // F3-T7: metered usage ingest.
        Router::new().route("/api/v1/billing/usage", post(crate::usage::post_usage))
    }
}
