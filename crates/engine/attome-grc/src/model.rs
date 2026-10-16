//! `EngineModel` registration for Governance, Risk & Compliance. Every
//! `grc_*` entity `crate::seed::seed` registers gets generic entity CRUD
//! for free; `crate::lifecycle` adds the two bespoke status-transition
//! routes the checklist names.
//!
//! **Why an interim `status` Choice, not M07 state models, for Phase 1.**
//! M20-grc.md §3 lists "all with M07 state models" as the target design, but
//! `attome-state` (M07) is itself only Phase 1 today (route-mounting/licence-
//! gating, no entry-action mechanism wired into the generic entity engine —
//! see `attome-state`'s own model doc and `boot.rs`'s registration comment).
//! There is nothing yet to attach a real state model *to*. Modeling
//! lifecycle as an ordinary `choice` attribute (the same convention
//! `attome_project`/`project_work_item`/`service_ticket` already use for their
//! own `status`) ships a working Phase 1 model now and is a strict subset of
//! the M07 shape: migrating a `choice` column to a real state model later is
//! additive, not a breaking change to callers that already read `status` as
//! a string.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_GRC, ModuleId};
use axum::Router;

/// Registered via `EngineSystem::builder(state).register(GrcModel)` — only
/// mounted when `grc` is a licensed module bit (D-010).
#[derive(Debug)]
pub struct GrcModel;

impl EngineModel for GrcModel {
    fn name(&self) -> &'static str {
        "attome-grc"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_GRC
    }

    /// D-383 — every entity `crate::seed` provisions. Deliberately does NOT
    /// include `project_issue`: `seed::seed` only adds an *additive*
    /// `risk_ref` lookup attribute to that already-existing, attome-project-
    /// owned entity — it does not create or own the entity itself, so
    /// `project_issue` stays claimed by `attome-project`'s own
    /// `owned_entities` (D-383's "who owns it" question is about entity
    /// registration, not about which engine happens to add one attribute).
    fn owned_entities(&self) -> &'static [&'static str] {
        &[
            "grc_regulation",
            "grc_requirement",
            "grc_control",
            "grc_control_requirement",
            "grc_assessment",
            "grc_assessment_item",
            "grc_finding",
            "grc_evidence",
            "grc_risk",
            "grc_risk_dependency",
            "grc_policy",
            "grc_policy_ack",
            // R12-T1: `platform-bundles/attome-grc-regulatory-change.json`.
            "grc_regulatory_change",
            "grc_regulatory_change_link",
        ]
    }

    fn routes(&self) -> Router<EngineState> {
        crate::lifecycle::routes()
    }
}
