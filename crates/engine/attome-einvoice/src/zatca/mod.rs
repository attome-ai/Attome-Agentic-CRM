//! ZATCA e-invoicing for Saudi Arabia (Fatoora phase 2, roadmap AG2).
//!
//! - [`xml`]: the UBL 2.1 invoice written from an invoice's data (AG2-T1).
//! - [`c14n`]: the canonical form the hash is taken over (AG2-T1).
//! - [`hash`]: the invoice hash and the per-device hash chain (AG2-T1).

pub mod c14n;
pub mod hash;
pub mod xml;
