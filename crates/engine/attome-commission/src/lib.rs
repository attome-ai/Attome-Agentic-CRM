//! The sales commissions and incentives (F10) engine (roadmap F10-T1).
//!
//! Sales commissions and incentives (F10). The records are metadata from the matching pack; this
//! crate holds the engine code that acts on them as later tasks add it. Gated on the `commission`
//! module.

pub mod acceptance;
pub mod close;
pub mod credit;
pub mod dispute;
pub mod draw;
pub mod model;
pub mod partner_pay;
pub mod plan_admin;
pub mod recalc;
pub mod rules;
pub mod run;
pub mod statement;

pub use model::CommissionModel;

/// This crate's advisory-lock namespace (`"attome-commission/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 36;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = <run::ApiDocFragment as utoipa::OpenApi>::openapi();
    doc.merge(<statement::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<dispute::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<close::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<plan_admin::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<recalc::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<acceptance::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc
}
