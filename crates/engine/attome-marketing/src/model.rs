//! `EngineModel` registration: mounted only when the `marketing` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_MARKETING, ModuleId};
use axum::{Router, routing::get};

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct MarketingModel;

impl EngineModel for MarketingModel {
    fn name(&self) -> &'static str {
        "attome-marketing"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_MARKETING
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
            .route(
                "/api/v1/marketing/lists/{id}/count",
                get(crate::segment_insight::get_marketing_list_count),
            )
            .route(
                "/api/v1/marketing/lists/{id}/sample",
                get(crate::segment_insight::get_marketing_list_sample),
            )
            .route(
                "/api/v1/marketing/lists/{id}/explain/{person_id}",
                get(crate::segment_insight::get_marketing_list_explain),
            )
            .route(
                "/api/v1/marketing/lists/{id}/members-as-of",
                get(crate::segment_insight::get_marketing_list_members_as_of),
            )
    }
}
