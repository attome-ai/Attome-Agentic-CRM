//! `EngineModel` registration for Document Generation (M57 Phase 1). Mounts
//! the render-trigger/status API (`crate::render`); `docgen_template`
//! itself is browsed/edited through generic entity CRUD — no bespoke admin
//! CRUD route exists for it, same shape as `attome-workflow`'s
//! `workflow_definition` (this crate's `seed.rs` registers it, nothing
//! more).
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_DOCGEN, ModuleId};
use axum::Router;

/// Registered via `EngineSystem::builder(state).register(DocgenModel)` — only
/// mounted when `docgen` is a licensed module bit (D-010).
#[derive(Debug)]
pub struct DocgenModel;

impl EngineModel for DocgenModel {
    fn name(&self) -> &'static str {
        "attome-docgen"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_DOCGEN
    }

    /// D-383 — closes the generic-CRUD licence hole: without this,
    /// `docgen_template` records would stay readable/writable through
    /// `/api/v1/docgen_template` on any licence holding `MODULE_CORE`,
    /// even with `docgen`'s own routes correctly gated.
    fn owned_entities(&self) -> &'static [&'static str] {
        &["docgen_template"]
    }

    fn routes(&self) -> Router<EngineState> {
        crate::render::routes().merge(crate::preview::routes())
    }
}
