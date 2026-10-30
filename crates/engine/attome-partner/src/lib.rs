//! The partner relationship management (F9) engine (roadmap F9-T1).
//!
//! Partner relationship management (F9). The records are metadata from the matching pack; this
//! crate holds the engine code that acts on them as later tasks add it. Gated on the `partner`
//! module.

pub mod model;
/// F9-T3: deal registration conflicts, decisions and lapse.
pub mod registration;

pub use model::PartnerModel;

/// This crate's advisory-lock namespace (`"attome-partner/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 37;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    <registration::RegistrationApiDoc as utoipa::OpenApi>::openapi()
}
