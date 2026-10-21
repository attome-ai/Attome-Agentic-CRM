//! The billing engine (roadmap F4-T1).
//!
//! Billing: invoices, tax determination, payments and subscriptions (F3, F4, F5). The records are
//! metadata from the matching pack; this crate holds the engine code that acts on them as later
//! tasks add it. Gated on the `billing` module.

/// F3-T8: subscription charges and billing runs.
pub mod billing_run;
pub mod deposit;
pub mod document;
pub mod einvoice;
pub mod gateway;
/// F3-T11: subscription events handed to revenue and churn after commit.
pub mod handoff;
pub mod invoice;
pub mod issue;
pub mod lookup;
pub mod metrics;
pub mod model;
pub mod notes;
pub mod payment;
/// F3-T9: renewals and trials, swept nightly.
pub mod renewal;
pub mod requests;
pub(crate) mod scope;
pub mod statements;
pub mod status;
pub mod subscription;
pub mod tax;
pub mod usage;
pub mod writeoff;

pub use model::BillingModel;

/// This crate's advisory-lock namespace (`"attome-billing/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 35;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = <usage::ApiDocFragment as utoipa::OpenApi>::openapi();
    doc.merge(<subscription::routes::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<billing_run::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<metrics::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<invoice::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<issue::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<notes::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<deposit::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<requests::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<statements::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<writeoff::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<einvoice::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<payment::service::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<gateway::webhook::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<payment::link::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<payment::refund::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<payment::dispute::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<payment::credit::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc
}
