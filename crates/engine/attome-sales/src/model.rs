//! `EngineModel` registration for the sales engine: mounted only when the
//! `sales` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_SALES, ModuleId};
use axum::{
    Router,
    routing::{patch, post, put},
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
    /// their rules and stores their amounts. D7-T2: team members only
    /// through the team routes, which grant and revoke their share of the
    /// deal in the same transaction.
    fn engine_owned_entities(&self) -> &'static [&'static str] {
        &["opportunity_split", "opportunity_team_member"]
    }

    fn engine_managed_fields(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("opportunity_split", "amount"),
            ("opportunity_team_member", "share_id"),
        ]
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
            .route(
                "/api/v1/sales/opportunities/{id}/team",
                post(crate::team::post_sales_team_member),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/team/copy-account-team",
                post(crate::team_defaults::post_sales_copy_account_team),
            )
            .route(
                "/api/v1/sales/default-team/preview",
                post(crate::team_defaults::post_sales_default_team_preview),
            )
            .route(
                "/api/v1/sales/default-team/apply",
                post(crate::team_defaults::post_sales_default_team_apply),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/team/{member_id}",
                patch(crate::team::patch_sales_team_member)
                    .delete(crate::team::delete_sales_team_member),
            )
    }
}
