//! The workforce management engine (roadmap G17-T1).
//!
//! Workforce management: planning groups, shifts, schedules and adherence (G17). The records are
//! metadata from the matching pack; this crate holds the engine code that acts on them as later
//! tasks add it. Gated on the `workforce` module.

pub mod model;
pub mod rules;
pub mod staffing;

pub use model::WorkforceModel;

/// This crate's advisory-lock namespace (`"attome-workforce/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 39;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`. Empty until the first route lands.
pub fn openapi() -> utoipa::openapi::OpenApi {
    utoipa::openapi::OpenApiBuilder::new().build()
}
