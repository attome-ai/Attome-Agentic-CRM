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
            // D23-T4: reporting lines change only through the org chart route.
            ("contact", "reports_to"),
            ("contact", "dotted_line_ref"),
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
                "/api/v1/sales/territories/realign/preview",
                post(crate::territory::post_preview),
            )
            .route(
                "/api/v1/sales/territories/realign",
                post(crate::territory::post_realign),
            )
            .route(
                "/api/v1/sales/call-lists/{id}/dial",
                post(crate::dialer::telephony::post_dial),
            )
            .route(
                "/api/v1/sales/call-lists/{id}/voicemail",
                post(crate::dialer::telephony::post_voicemail),
            )
            .route(
                "/api/v1/sales/call-list-members/{id}/outcome",
                post(crate::dialer::outcome::post_sales_call_outcome),
            )
            .route(
                "/api/v1/sales/call-list-members/{id}/skip",
                post(crate::dialer::skip::post_sales_call_skip),
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
            // D10-T2: orders from quotes and won deals, and confirmation.
            .route(
                "/api/v1/sales/quotes/{id}/order",
                post(crate::order::post_sales_quote_order),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/order",
                post(crate::order::post_sales_opportunity_order),
            )
            .route(
                "/api/v1/sales/orders/{id}/confirm",
                post(crate::order::post_sales_order_confirm),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/sync",
                post(crate::quote_sync::post_sales_quote_sync),
            )
            .route(
                "/api/v1/sales/quotes/{id}/reprice",
                post(crate::quote::post_sales_quote_reprice),
            )
            .route(
                "/api/v1/sales/quotes/{id}/versions",
                post(crate::quote::post_sales_quote_version),
            )
            .route(
                "/api/v1/sales/quotes/{id}/primary",
                post(crate::quote::post_sales_quote_primary),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/deal-discount",
                post(crate::opportunity_lines::post_sales_deal_discount),
            )
            .route(
                "/api/v1/sales/competitor-mentions/{id}/confirm",
                post(crate::competitor_routes::post_sales_mention_confirm),
            )
            .route(
                "/api/v1/sales/competitor-mentions/{id}/reject",
                post(crate::competitor_routes::post_sales_mention_reject),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/battlecards",
                get(crate::competitor_routes::get_sales_battlecards),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/plays",
                get(crate::plays::get_sales_plays),
            )
            .route(
                "/api/v1/sales/cpq/validate",
                post(crate::cpq::post_sales_cpq_validate),
            )
            .route(
                "/api/v1/sales/contacts/{id}/manager",
                put(crate::orgchart::put_sales_contact_manager),
            )
            .route(
                "/api/v1/sales/contacts/{id}/left",
                post(crate::orgchart::post_sales_contact_left),
            )
            .route(
                "/api/v1/sales/accounts/{id}/org-chart",
                get(crate::orgchart::get_sales_org_chart),
            )
            .route(
                "/api/v1/sales/accounts/{id}/org-chart/export",
                post(crate::orgchart::post_sales_org_chart_export),
            )
            .route(
                "/api/v1/sales/opportunities/{id}/committee-map",
                get(crate::orgchart::get_sales_committee_map),
            )
            .route(
                "/api/v1/sales/accounts/{id}/org-chart/propose",
                post(crate::orgchart::post_sales_org_chart_propose),
            )
            .route(
                "/api/v1/sales/orgchart-drafts/{id}/decide",
                post(crate::orgchart::post_sales_orgchart_draft_decide),
            )
            .route(
                "/api/v1/sales/competitors/{id}/head-to-head",
                get(crate::competitor_routes::get_sales_head_to_head),
            )
            .route(
                "/api/v1/sales/competitors/{id}/card",
                get(crate::competitor_routes::get_sales_competitor_card),
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
