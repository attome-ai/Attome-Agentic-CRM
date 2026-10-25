//! The marketing engine (roadmap E6-T1).
//!
//! Marketing: campaigns, email, segments, journeys, forms and pages (E1-E31). The records are
//! metadata from the matching pack; this crate holds the engine code that acts on them as later
//! tasks add it. Gated on the `marketing` module.

pub mod ab_test;
pub mod abm;
pub mod address_check;
pub mod alerts;
pub mod attribution;
pub mod blocklist;
pub mod deliverability;
/// E6-T7: DMARC aggregate reports.
pub mod dmarc;
/// E25-T1: dynamic blocks chosen per recipient.
pub mod dynamic_blocks;
/// E16-T1: SMS campaigns with consent, an estimate and quiet hours.
/// E3-T1: email campaigns on the bulk stream, with one-click unsubscribe.
pub mod email_campaign;
/// E2-T2: email designs to email-safe HTML and plain text.
pub mod email_render;
pub mod events;
/// E10-T1: marketing forms and their public submission.
pub mod forms;
pub mod handoff_sla;
pub mod journey;
pub mod landing;
pub mod loyalty;
pub mod model;
pub mod nurture_tracks;
pub mod precheck;
/// E23-T1: profile events and their retention.
pub mod profile_events;
pub mod referral;
pub mod reputation;
pub mod segment;
pub mod segment_insight;
/// E7-T6: live segments re-checked from the change feed.
pub mod segment_live;
pub mod send_time;
pub mod sms_campaign;
pub mod social_publish;
/// E7-T5: static list members by hand, view, form, flow and import.
pub mod static_list;
pub mod tracking;
/// E14-T4: the website tracking script.
pub mod tracking_script;
pub mod webinar_sync;

pub use model::MarketingModel;

/// This crate's advisory-lock namespace (`"attome-marketing/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 34;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = <segment_insight::ApiDocFragment as utoipa::OpenApi>::openapi();
    doc.merge(<events::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<sms_campaign::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<email_campaign::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<deliverability::routes::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<static_list::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<forms::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<dynamic_blocks::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<tracking_script::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<tracking::collect::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<landing::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc
}
