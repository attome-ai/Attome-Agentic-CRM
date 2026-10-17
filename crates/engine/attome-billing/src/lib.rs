//! The billing engine (roadmap F4-T1).
//!
//! Billing: invoices, tax determination, payments and subscriptions (F3, F4, F5). The records are
//! metadata from the matching pack; this crate holds the engine code that acts on them as later
//! tasks add it. Gated on the `billing` module.

pub mod deposit;
pub mod invoice;
pub mod issue;
pub mod metrics;
pub mod model;
pub mod notes;
pub mod payment;
pub mod requests;
pub mod subscription;
pub mod tax;
pub mod usage;

pub use model::BillingModel;

/// This crate's advisory-lock namespace (`"attome-billing/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 35;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = <usage::ApiDocFragment as utoipa::OpenApi>::openapi();
    doc.merge(<metrics::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<invoice::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<issue::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<notes::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<deposit::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<requests::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc
}
