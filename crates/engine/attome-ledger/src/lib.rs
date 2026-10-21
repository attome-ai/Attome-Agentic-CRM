//! The general ledger engine (roadmap W5-T1).
//!
//! Accounts, journals, periods and posting rules are metadata from the
//! ledger pack (`packs/ledger`); this crate holds the posting engine
//! ([`posting`]): balanced double entries in exact decimals, written once per
//! source document into an open period, and never changed afterwards.
//! Gated on the `ledger` module.

pub mod model;
pub mod posting;

pub use model::LedgerModel;

/// This crate's advisory-lock namespace (`"attome-ledger/…"` keys),
/// registered in `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 45;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    posting::openapi_fragment()
}
