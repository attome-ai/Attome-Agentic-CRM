//! `EngineModel` registration for Integration & Connectors (M59) — mounts the
//! system admin CRUD + credential/test-connection routes (`admin.rs`) and
//! the inbound webhook route (`webhook.rs`).
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_INTEGRATION, ModuleId};
use axum::Router;

/// Registered via `EngineSystem::builder(state).register(IntegrationModel)` —
/// only mounted when `integration` is a licensed module bit (D-010). Shares
/// `MODULE_INTEGRATION` with `attome-events` (M62/D-403) — see this crate's
/// `lib.rs` doc comment for why that is a deliberate shared bit, not a
/// collision.
#[derive(Debug)]
pub struct IntegrationModel;

impl EngineModel for IntegrationModel {
    fn name(&self) -> &'static str {
        "attome-integration"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_INTEGRATION
    }

    /// `platform-bundles/attome-integration.json` provisions these two entities —
    /// `integration_credential` (migration `0195`) is deliberately never
    /// registered as a browsable entity, same reasoning `attome-s2s` withholds
    /// `s2s_client_key`.
    fn owned_entities(&self) -> &'static [&'static str] {
        &["integration_system", "integration_event"]
    }

    fn routes(&self) -> Router<EngineState> {
        crate::admin::routes().merge(crate::webhook::routes())
    }
}
