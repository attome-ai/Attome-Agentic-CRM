//! The fulfilment engine (roadmap F6-T1).
//!
//! Fulfilment: fulfilment orders, shipments and delivery (F6). The records are metadata from the
//! matching pack; this crate holds the engine code that acts on them as later tasks add it. Gated
//! on the `fulfilment` module.

pub mod model;
pub mod sourcing;

pub use model::FulfilmentModel;

/// This crate's advisory-lock namespace (`"attome-fulfilment/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 38;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`. Empty until the first route lands.
pub fn openapi() -> utoipa::openapi::OpenApi {
    utoipa::openapi::OpenApiBuilder::new().build()
}
