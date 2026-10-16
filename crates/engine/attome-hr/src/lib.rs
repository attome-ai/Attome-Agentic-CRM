//! The human resources engine (roadmap W6): leave requests with their
//! approval and balances, people's availability for scheduling and routing,
//! and the payroll hand-off per period. The records are the human-resources
//! pack's metadata; this crate holds the engine code that acts on them.
//! Mounted with the core module, as the pack is.

pub mod leave;
pub mod model;
pub mod payroll_export;

pub use model::HrModel;

/// This crate's advisory-lock namespace (`"attome-hr/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 43;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = <leave::ApiDocFragment as utoipa::OpenApi>::openapi();
    doc.merge(<payroll_export::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc
}
