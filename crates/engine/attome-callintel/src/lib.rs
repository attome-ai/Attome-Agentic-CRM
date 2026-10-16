//! The call intelligence engine (roadmap D22-T1).
//!
//! Call intelligence: analysis of recorded sales calls (D22). The records are metadata from the
//! matching pack; this crate holds the engine code that acts on them as later tasks add it. Gated
//! on the `callintel` module.

pub mod analysis;
pub mod model;

pub use model::CallintelModel;

/// This crate's advisory-lock namespace (`"attome-callintel/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 33;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`. Empty until the first route lands.
pub fn openapi() -> utoipa::openapi::OpenApi {
    utoipa::openapi::OpenApiBuilder::new().build()
}
