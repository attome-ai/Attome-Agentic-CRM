//! The procurement engine (roadmap W3-T1).
//!
//! Purchase requisitions, purchase orders, goods receipts and vendor bills.
//! The records are metadata from the procurement pack
//! (`packs/procurement`); this crate holds the engine code that acts on them
//! as later tasks add it (three-way match, approval routing, budget checks).
//! Gated on the `procurement` module.

pub mod model;

pub use model::ProcurementModel;

/// This crate's advisory-lock namespace (`"attome-procurement/…"` keys),
/// registered in `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 42;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`. Empty until the first route lands.
pub fn openapi() -> utoipa::openapi::OpenApi {
    utoipa::openapi::OpenApiBuilder::new().build()
}
