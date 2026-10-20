//! `EngineModel` registration: mounted only when the `commission` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_COMMISSION, ModuleId};
use axum::{
    Router,
    routing::{get, post},
};

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
        Router::new()
            .route(
                "/api/v1/commission/periods/{id}/runs",
                post(crate::run::commission_post_run),
            )
            .route(
                "/api/v1/commission/statements/me",
                get(crate::statement::commission_get_my_statement),
            )
            .route(
                "/api/v1/commission/statements",
                get(crate::statement::commission_get_statements),
            )
            .route(
                "/api/v1/commission/estimate",
                post(crate::statement::commission_post_estimate),
            )
            .route(
                "/api/v1/commission/disputes",
                post(crate::dispute::commission_post_dispute),
            )
            .route(
                "/api/v1/commission/disputes/{id}/decision",
                post(crate::dispute::commission_post_decision),
            )
            .route(
                "/api/v1/commission/adjustments",
                post(crate::dispute::commission_post_adjustment),
            )
            .route(
                "/api/v1/commission/periods/{id}/recalc/apply",
                post(crate::recalc::commission_post_recalc_apply),
            )
            .route(
                "/api/v1/commission/plans/{id}/publish",
                post(crate::plan_admin::commission_post_publish),
            )
            .route(
                "/api/v1/commission/plans/{id}/send-for-acceptance",
                post(crate::acceptance::commission_post_send_for_acceptance),
            )
            .route(
                "/api/v1/commission/periods/{id}/submit",
                post(crate::close::commission_post_submit),
            )
    }
}
