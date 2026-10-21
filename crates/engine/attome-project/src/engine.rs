//! `EngineModel` registration for Project Management — mounts the two read-only
//! aggregation endpoints this engine adds on top of the generic entity CRUD
//! every `project_*` entity already gets for free once `seed::seed` has
//! registered it (see that module's doc comment for why the seed call lives
//! in `attome-api`'s `EngineSystem::build()` rather than this crate).
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_PROJECT, ModuleId};
use axum::Router;

/// Registered via `EngineSystem::builder(state).register(ProjectModel)` — only
/// mounted when `project` is a licensed module bit (D-010).
#[derive(Debug)]
pub struct ProjectModel;

impl EngineModel for ProjectModel {
    fn name(&self) -> &'static str {
        "attome-project"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_PROJECT
    }

    /// D-383 — every entity `crate::seed` provisions. This engine is the
    /// clearest case for the gate: six entities of real customer project
    /// data, whose only bespoke routes are the summary/work-plan reads, so
    /// before D-383 essentially the whole module was reachable through
    /// `/api/v1/{entity}` on a core-only licence. `project_customer`,
    /// `project_customer_contact`, `project_team_member`, and
    /// `project_communication` were retired in favor of the platform's
    /// own `organization`/`user_account`/`team`/
    /// `communication` — see `seed.rs`'s module doc.
    fn owned_entities(&self) -> &'static [&'static str] {
        &[
            "attome_project",
            "project_team",
            "project_work_item",
            "project_work_item_dependency",
            "project_baseline",
            "project_baseline_item",
            "project_resource_rate",
            "project_timesheet",
            "project_time_entry",
            "project_deliverable",
            "project_issue",
            "project_change_request",
            "project_meeting",
            "project_lesson",
            "project_template",
            "project_portfolio",
            "project_program",
            "resource_allocation",
        ]
    }

    fn routes(&self) -> Router<EngineState> {
        crate::summary::routes()
            .merge(crate::work_plan::routes())
            .merge(crate::portfolio_program::routes())
            .merge(crate::capacity::routes())
            .merge(crate::baseline::routes())
            .merge(crate::change_request::routes())
            .merge(crate::timesheet::routes())
            .merge(crate::budget_link::routes())
    }
}
