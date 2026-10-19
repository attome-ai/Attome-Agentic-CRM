//! The offline use engine (roadmap B18-T1).
//!
//! Offline use: what a device keeps, sync and conflict resolution (B18). The records are metadata
//! from the matching pack; this crate holds the engine code that acts on them as later tasks add
//! it. Gated on the `offline` module.

pub mod model;
/// B18-T4: the caller's offline profile.
pub mod profile;

pub use model::OfflineModel;

/// This crate's advisory-lock namespace (`"attome-offline/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 41;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(profile::get_offline_profile))]
struct ApiDocFragment;
