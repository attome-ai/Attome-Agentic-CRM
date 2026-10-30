//! The partner relationship management (F9) engine (roadmap F9-T1).
//!
//! Partner relationship management (F9). The records are metadata from the matching pack; this
//! crate holds the engine code that acts on them as later tasks add it. Gated on the `partner`
//! module.

/// F9-T7: certifications warn before they expire.
pub mod certification;
/// F9-T7: market development fund requests and claims.
pub mod mdf;
pub mod model;
/// F9-T3: deal registration conflicts, decisions and lapse.
pub mod registration;
mod support;

pub use model::PartnerModel;

/// This crate's advisory-lock namespace (`"attome-partner/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 37;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = <registration::RegistrationApiDoc as utoipa::OpenApi>::openapi();
    doc.merge(<mdf::MdfApiDoc as utoipa::OpenApi>::openapi());
    doc
}
