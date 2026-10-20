//! Attome's e-invoicing (roadmap AG2, AG3): the documents tax authorities
//! receive, written, hashed and stamped in Rust, with no native XML-security
//! library in the binary (V2-D471). Billing (attome-billing) calls it from
//! the issue step.

pub mod asn1;
pub mod crypto;
pub mod device;
pub mod document;
pub mod model;
pub(crate) mod routes;
pub mod uae;
pub mod zatca;

pub use model::EinvoiceModel;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    <routes::ApiDocFragment as utoipa::OpenApi>::openapi()
}
