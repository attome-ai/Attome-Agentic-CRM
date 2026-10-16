//! The marketing engine (roadmap E6-T1).
//!
//! Marketing: campaigns, email, segments, journeys, forms and pages (E1-E31). The records are
//! metadata from the matching pack; this crate holds the engine code that acts on them as later
//! tasks add it. Gated on the `marketing` module.

pub mod ab_test;
pub mod abm;
pub mod address_check;
pub mod attribution;
pub mod deliverability;
pub mod handoff_sla;
pub mod loyalty;
pub mod model;
pub mod nurture_tracks;
pub mod referral;
pub mod segment;
pub mod segment_insight;
pub mod send_time;
pub mod tracking;

pub use model::MarketingModel;

/// This crate's advisory-lock namespace (`"attome-marketing/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 34;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    <segment_insight::ApiDocFragment as utoipa::OpenApi>::openapi()
}
