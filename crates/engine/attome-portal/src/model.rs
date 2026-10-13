//! `EngineModel` registration for web portals (D-576).
use attome_core::model::RecordValidator;
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_PORTAL, ModuleId};
use axum::Router;

/// Registered via `EngineSystem::builder(state).register(PortalModel)`; its routes
/// are mounted only when `portal` is a licensed module bit (D-010).
#[derive(Debug)]
pub struct PortalModel;

impl EngineModel for PortalModel {
    fn name(&self) -> &'static str {
        "attome-portal"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_PORTAL
    }

    /// D-383: generic CRUD on these entities carries the same licence check
    /// as this model's routes.
    fn owned_entities(&self) -> &'static [&'static str] {
        &["webportal", "webportal_user"]
    }

    /// Refuses the security-relevant fields on every generic write, in every
    /// mutation mode (see [`crate::guard`]).
    fn record_validators(&self) -> &'static [(&'static str, RecordValidator)] {
        &[
            ("webportal", crate::guard::validate_webportal_record),
            (
                "webportal_user",
                crate::guard::validate_webportal_user_record,
            ),
        ]
    }

    fn routes(&self) -> Router<EngineState> {
        // D-779: the S2S-only trusted server login rides with the staff
        // routes (staff authn/authz, licence gating), never the portal router.
        crate::admin::routes().merge(crate::router::trusted::routes())
    }
}
