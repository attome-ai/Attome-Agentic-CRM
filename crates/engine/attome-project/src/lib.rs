pub mod access;
pub mod auth;
pub mod baseline;
pub mod budget_link;
pub mod capacity;
pub mod change_request;
pub mod change_signoff;
pub mod critical_path;
pub mod engine;
pub mod model;
pub mod portfolio_program;
pub mod risk;
pub mod seed;
pub mod summary;
pub mod tasks;
pub mod timesheet;
pub mod utilization;
pub(crate) mod variance;
pub mod work_plan;

pub use engine::ProjectModel;

/// This crate's own advisory-lock namespace — see
/// `crates/server/tests/advisory_lock_namespaces.rs`'s registry table
/// (id 24, `attome-project/`) for the collision-freedom proof. Declared here
/// rather than in `baseline.rs` alone since a future second lock-taking
/// module in this crate (e.g. change-request approval) reuses the same
/// namespace, not a new one — one namespace per crate, keyed further by the
/// lock string's own `{operation}:{resource}` suffix (guidelines §2).
pub const ADVISORY_LOCK_NAMESPACE: i32 = 24;

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document. Merged in by `attome_api::openapi_document()` (this crate is a
/// direct dependency of `attome-api`, unlike `attome-workflow`/`attome-ai`/
/// `attome-search` — see `seed.rs`'s module doc for why `attome-project::seed`
/// itself has to be called from inside `attome-api`'s `EngineSystem::build()`),
/// not `crates/server`'s own `openapi.rs` — same composition point as
/// `attome_security::openapi()`/`attome_notification::openapi()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = summary::openapi_fragment();
    doc.merge(work_plan::openapi_fragment());
    doc.merge(portfolio_program::openapi_fragment());
    doc.merge(capacity::openapi_fragment());
    doc.merge(baseline::openapi_fragment());
    doc.merge(change_request::openapi_fragment());
    doc.merge(timesheet::openapi_fragment());
    doc.merge(budget_link::openapi_fragment());
    doc.merge(change_signoff::openapi_fragment());
    doc
}
