//! Attome's e-invoicing (roadmap AG2, AG3): the documents tax authorities
//! receive, written, hashed and stamped in Rust, with no native XML-security
//! library in the binary (V2-D471). Billing (attome-billing) calls it from
//! the issue step.

pub mod zatca;
