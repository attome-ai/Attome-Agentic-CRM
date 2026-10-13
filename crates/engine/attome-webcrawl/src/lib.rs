//! Web Crawling for Knowledge Base (D-365) — extends D-363's
//! `knowledge_data_source`/`knowledge_data_item` with a "website"
//! source: an admin submits a URL, a background job (`crate::crawl`) walks
//! it same-origin through an SSRF-hardened fetcher (`crate::safety`), and
//! selected crawled pages are promoted into `knowledge_data_item` rows.
//!
//! This is the platform's first feature that makes an outbound HTTP request
//! to an arbitrary, user-supplied URL — see `crate::safety`'s doc comment
//! for the SSRF contract. No license module bit gates it (Knowledge Base
//! itself has none, and no free module id fit — see D-365); the admin HTTP
//! surface (`attome-api/src/webcrawl_admin.rs`) is `Authorized<Admin>`, and
//! `config.webcrawl.enabled` (default off) is a deployment-level kill
//! switch, matching the air-gap posture `P-knowledge-base.md` §5 documents
//! for the platform's (separate, larger, not-yet-built) web-ingestion plan.

pub mod crawl;
pub mod model;
pub mod safety;

/// D-351 — this crate's advisory-lock namespace (`"webcrawl/…"` keys),
/// registered in `crates/server/tests/advisory_lock_namespaces.rs`. Locked
/// from `attome-api/src/webcrawl_admin.rs` (the key's prefix, not the crate
/// the SQL is written in, decides the namespace — see that test file's doc
/// comment).
pub const ADVISORY_LOCK_NAMESPACE: i32 = 12;
