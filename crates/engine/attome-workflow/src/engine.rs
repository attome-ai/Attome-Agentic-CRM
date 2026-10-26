//! `EngineModel` registration for the Workflow Engine (P2.9,
//! `document/detailed-plans/P-workflow-engine.md`) — mounts both the
//! definition/version admin CRUD (`admin.rs`) and the instance admin API
//! (`instance_admin.rs`); the execution engine itself
//! (`scheduler`/`sla_sweep`) runs off the job queue, not an HTTP route.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_WORKFLOW, ModuleId};
use axum::Router;

/// Registered via `EngineSystem::builder(state).register(WorkflowModel)` — only
/// mounted when `workflow` is a licensed module bit (D-010).
#[derive(Debug)]
pub struct WorkflowModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for WorkflowModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-workflow"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_WORKFLOW
    }

    /// D-383. `platform-bundles/attome-workflow.json` provisions exactly this one entity; the other
    /// workflow tables (`..._version`, `..._instance`, `..._node_run`) are
    /// deliberately never registered as browsable entities, so generic CRUD
    /// cannot reach them at all — see that module's header.
    fn owned_entities(&self) -> &'static [&'static str] {
        &["workflow_definition"]
    }

    fn routes(&self) -> Router<EngineState> {
        crate::admin::routes()
            .merge(crate::instance_admin::routes())
            .merge(crate::instance_control::routes())
            .merge(crate::dead_letter_admin::routes())
            .merge(crate::simulate::routes())
    }
}
