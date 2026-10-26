//! The fulfilment engine (roadmap F6-T1).
//!
//! Fulfilment: fulfilment orders, shipments and delivery (F6). The records are metadata from the
//! matching pack; this crate holds the engine code that acts on them as later tasks add it. Gated
//! on the `fulfilment` module.

/// F6-T5: available-to-promise dates.
pub mod atp;
/// F6-T7: backorders and partial shipments.
pub mod backorder;
/// F6-T9: booking and tracking shipments with a carrier.
pub mod carrier;
/// F6-T11: delivery by the own fleet with proof, a delivery code and cash on delivery.
pub mod delivery;
/// F6-T14: late and stuck orders as exceptions.
pub mod exceptions;
/// F6-T6: holds that stop a release, and releasing.
pub mod hold;
pub mod model;
/// F6-T8: pick lists and packing.
pub mod pack;
/// F6-T12: non-goods and drop-ship lines handed to their owners.
pub mod routing;
pub mod sourcing;
/// F6-T3: confirmed orders split into fulfilment orders.
pub mod split;
/// F6-T10: shipment status following the carrier, applied once.
pub mod tracking;

pub use model::FulfilmentModel;

/// This crate's advisory-lock namespace (`"attome-fulfilment/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 38;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = hold::openapi_fragment();
    doc.merge(backorder::openapi_fragment());
    doc.merge(pack::openapi_fragment());
    doc.merge(carrier::openapi_fragment());
    doc.merge(delivery::openapi_fragment());
    doc
}
