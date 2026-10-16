//! `EngineModel` registration for the sales engine: mounted only when the
//! `sales` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_SALES, ModuleId};
use axum::{
    Router,
    routing::{post, put},
};

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct SalesModel;

impl EngineModel for SalesModel {
    fn name(&self) -> &'static str {
        "attome-sales"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_SALES
    }

    /// The sales records are the pack's metadata, not this crate's seed;
    /// the points models are `platform-bundles/attome-sales-scoring.json`.
    fn owned_entities(&self) -> &'static [&'static str] {
        &["points_model", "points_rule", "points_score"]
    }

    /// D7-T4: splits are written only through `PUT .../splits`, which checks
    /// their rules and stores their amounts.
    fn engine_owned_entities(&self) -> &'static [&'static str] {
        &["opportunity_split"]
    }

    fn engine_managed_fields(&self) -> &'static [(&'static str, &'static str)] {
        &[("opportunity_split", "amount")]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
            .route(
                "/api/v1/sales/call-lists/{id}/claim",
                post(crate::dialer::claim::post_claim),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/splits",
                put(crate::split_store::put_sales_splits),
            )
    }
}
