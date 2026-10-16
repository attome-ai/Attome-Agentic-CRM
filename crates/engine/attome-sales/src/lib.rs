//! The sales engine (roadmap D6-T1): the Rust behind the sales pack
//! (`packs/sales`), for what metadata alone cannot express. The sales
//! records themselves (opportunities, quotes, products, price lists) are
//! metadata from the pack; this crate holds the engines that act on them as
//! later sales tasks add them (D21 call lists and dialer, D6 quote lines and
//! schedules, D23-D25 forecasting and territories). Gated on the `sales`
//! module.

pub mod attainment;
pub mod competitors;
pub mod dialer;
pub mod enrichment;
pub mod flags;
pub mod model;
pub mod orgchart;
pub mod pricing;
pub mod scoring;
pub mod splits;

pub use model::SalesModel;

/// This crate's advisory-lock namespace (`"attome-sales/…"` keys), registered
/// in `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 32;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`. Empty until the first sales route lands.
pub fn openapi() -> utoipa::openapi::OpenApi {
    utoipa::openapi::OpenApiBuilder::new().build()
}
