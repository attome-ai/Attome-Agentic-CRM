//! The contract lifecycle management engine (roadmap W1-T1).
//!
//! Contract lifecycle management: versions, comparison, playbooks and imports (W1); the contract,
//! clause, amendment and obligation records stay in the vertical pack. The records are metadata
//! from the matching pack; this crate holds the engine code that acts on them as later tasks add
//! it. Gated on the `contract` module.

pub mod amendment;
pub mod counterparty;
pub mod dates;
pub mod model;
pub mod retention;

pub use model::ContractModel;

/// This crate's advisory-lock namespace (`"attome-contract/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 40;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    <counterparty::ApiDocFragment as utoipa::OpenApi>::openapi()
}
