//! The sales commissions and incentives (F10) engine (roadmap F10-T1).
//!
//! Sales commissions and incentives (F10). The records are metadata from the matching pack; this
//! crate holds the engine code that acts on them as later tasks add it. Gated on the `commission`
//! module.

pub mod model;

pub use model::CommissionModel;

/// This crate's advisory-lock namespace (`"attome-commission/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 36;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`. Empty until the first route lands.
pub fn openapi() -> utoipa::openapi::OpenApi {
    utoipa::openapi::OpenApiBuilder::new().build()
}
