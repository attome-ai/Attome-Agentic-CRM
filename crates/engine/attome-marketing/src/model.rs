//! `EngineModel` registration: mounted only when the `marketing` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_MARKETING, ModuleId};
use axum::{
    Router,
    routing::{get, post},
};

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct MarketingModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for MarketingModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-marketing"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_MARKETING
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    /// E8-T3: a journey's status moves only through the journey engine
    /// (publish, pause); a new journey starts as a draft.
    fn engine_managed_fields(&self) -> &'static [(&'static str, &'static str)] {
        &[("marketing_journey", "status")]
    }

    fn engine_managed_initial_values(
        &self,
    ) -> &'static [(&'static str, &'static str, &'static str)] {
        &[("marketing_journey", "status", "draft")]
    }

    /// E6-T6: an email address with a syntax error is refused on every
    /// generic write of a contact or lead; the softer findings are warnings
    /// from `address_check::check_address`, never a refusal.
    fn record_validators(&self) -> &'static [(&'static str, attome_core::model::RecordValidator)] {
        &[
            ("contact", crate::address_check::validate_email_record),
            ("lead", crate::address_check::validate_email_record),
        ]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
            .route(
                "/api/v1/marketing/events/{id}/registrations",
                post(crate::events::post_marketing_registration),
            )
            .route(
                "/api/v1/marketing/events/{id}/registrations/{registration_id}/cancel",
                post(crate::events::post_marketing_registration_cancel),
            )
            .route(
                "/api/v1/marketing/events/{id}/check-in",
                post(crate::events::post_marketing_check_in),
            )
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
            .route(
                "/api/v1/marketing/lists/{id}/sms/estimate",
                post(crate::sms_campaign::post_sms_estimate),
            )
            .route(
                "/api/v1/marketing/lists/{id}/sms/send",
                post(crate::sms_campaign::post_sms_send),
            )
            .route(
                "/api/v1/marketing/lists/{id}/email/send",
                post(crate::email_campaign::post_email_send),
            )
            .merge(crate::deliverability::routes::routes())
            .merge(crate::static_list::routes())
            .merge(crate::campaign::routes())
            .merge(crate::dynamic_blocks::routes())
            .merge(crate::landing::routes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E1-T2: the engine mounts as `attome-marketing` under the marketing
    /// module, so switching the module off in Module Management unmounts
    /// every marketing route; it declares its manifest (Y4).
    #[test]
    fn health_marketing_engine_mounts_under_its_module() {
        let model = MarketingModel;
        assert_eq!(model.name(), "attome-marketing");
        assert_eq!(model.module_id(), MODULE_MARKETING);
        let manifest = model.manifest().expect("a manifest");
        assert_eq!(manifest.version, env!("CARGO_PKG_VERSION"));
        assert!(manifest.depends_on.is_empty());
    }
}
