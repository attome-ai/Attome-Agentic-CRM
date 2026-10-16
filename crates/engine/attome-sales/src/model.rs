//! `EngineModel` registration for the sales engine: mounted only when the
//! `sales` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_SALES, ModuleId};
use axum::{
    Router,
    routing::{get, patch, post, put},
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
        &[
            "opportunity_split",
            "opportunity_team_member",
            "opportunity_line",
        ]
    }

    fn engine_managed_fields(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("opportunity_split", "amount"),
            ("opportunity_team_member", "share_id"),
            ("opportunity_line", "line_total"),
            ("opportunity_line", "list_price"),
            ("opportunity", "has_lines"),
            ("opportunity", "one_time_total"),
            ("opportunity", "recurring_annual"),
            ("opportunity", "total_contract_value"),
        ]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
            .route(
                "/api/v1/sales/call-lists/{id}/claim",
                post(crate::dialer::claim::post_claim),
            )
            .route(
                "/api/v1/sales/call-lists/{id}/build",
                post(crate::dialer::build::post_sales_build_list),
            )
            .route(
                "/api/v1/sales/call-list-members/{id}/outcome",
                post(crate::dialer::outcome::post_sales_call_outcome),
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
                "/api/v1/sales/opportunity-lines/{line_id}/schedule",
                post(crate::schedules::post_sales_line_schedule),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/schedules/shift",
                post(crate::schedules::post_sales_schedule_shift),
            )
            .route(
                "/api/v1/sales/price-lists/{id}/products",
                get(crate::catalogue::get_sales_price_list_products),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/lines",
                get(crate::opportunity_lines::get_sales_lines)
                    .post(crate::opportunity_lines::post_sales_line),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/lines/{line_id}",
                patch(crate::opportunity_lines::patch_sales_line)
                    .delete(crate::opportunity_lines::delete_sales_line),
            )
            .route(
                "/api/v1/sales/undo/{snapshot_id}",
                post(crate::undo::post_sales_undo),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/sync",
                post(crate::quote_sync::post_sales_quote_sync),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/deal-discount",
                post(crate::opportunity_lines::post_sales_deal_discount),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/change-owner",
                post(crate::owner_change::post_sales_change_owner),
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
