//! The offline use engine (roadmap B18-T1).
//!
//! Offline use: what a device keeps, sync and conflict resolution (B18). The records are metadata
//! from the matching pack; this crate holds the engine code that acts on them as later tasks add
//! it. Gated on the `offline` module.

pub mod model;

pub use model::OfflineModel;

/// This crate's advisory-lock namespace (`"attome-offline/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 41;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`. Empty until the first route lands.
pub fn openapi() -> utoipa::openapi::OpenApi {
    utoipa::openapi::OpenApiBuilder::new().build()
}
