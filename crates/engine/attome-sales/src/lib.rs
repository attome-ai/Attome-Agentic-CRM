//! The sales engine (roadmap D6-T1): the Rust behind the sales pack
//! (`packs/sales`), for what metadata alone cannot express. The sales
//! records themselves (opportunities, quotes, products, price lists) are
//! metadata from the pack; this crate holds the engines that act on them as
//! later sales tasks add them (D21 call lists and dialer, D6 quote lines and
//! schedules, D23-D25 forecasting and territories). Gated on the `sales`
//! module.

pub mod attainment;
pub mod catalogue;
pub mod competitors;
pub mod cpq;
pub mod cpq_pricing;
pub mod deal_risk;
pub mod dialer;
pub mod discount_policy;
pub mod enrichment;
pub mod flags;
pub mod forecast;
pub mod model;
pub mod opportunity_lines;
pub mod orgchart;
pub mod owner_change;
pub mod price_resolution;
pub mod pricing;
pub mod quote_sync;
pub mod schedules;
pub mod scoring;
pub mod scoring_run;
pub mod split_store;
pub mod splits;
pub mod team;
pub mod team_defaults;
pub mod undo;

pub use model::SalesModel;

/// This crate's advisory-lock namespace (`"attome-sales/…"` keys), registered
/// in `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 32;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = <dialer::claim::ApiDocFragment as utoipa::OpenApi>::openapi();
    doc.merge(<split_store::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<team::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<team_defaults::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<owner_change::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<opportunity_lines::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<catalogue::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<schedules::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<quote_sync::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<undo::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc
}
