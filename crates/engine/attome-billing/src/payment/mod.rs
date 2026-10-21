//! Customer payments (roadmap F5): allocation over open invoices (pure
//! code) and the payment service built on it.

pub mod allocate;
/// F5-T12: credit limits and credit hold.
pub mod credit;
pub mod dispute;
pub mod link;
pub mod reconcile;
pub mod recurring;
pub mod refund;
pub mod service;
