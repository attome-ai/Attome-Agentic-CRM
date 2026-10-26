//! M59 Phase 1 — Integration & Connectors. External-system registry
//! (`integration_system`), a closed connector catalogue (REST adapter +
//! mailbox skeleton), envelope-encrypted credential storage, and the inbound
//! webhook route that lands events through the generic entity API path
//! (D-425) rather than a bespoke write.
//!
//! Out of scope here (M59 Phase 2, see the module plan): sync runs, conflict
//! policy, cursors, adapter versioning, and real esign/calendar
//! implementations. M53 Phase 1 (D-474) gave `channel` its first real
//! adapter (`adapters::webchat`) — see that module's own doc comment for why
//! web chat is not shaped like the other, still-unbuilt kinds.
//! `integration_event` (this crate's `seed`) is the durable inbox Phase
//! 2's sync engine will read from.

pub mod admin;
/// F6-T9: booking and tracking shipments with a carrier.
pub mod carrier;
pub mod connection;
pub mod connector;
pub mod credential;
mod crypto;
/// L9-T1: the enrichment runner: proposals with provenance, per-provider budgets.
pub mod enrich;
pub mod guard;
/// M14-T1: checks a builder-defined inbound hook's call passes.
pub mod inbound;
/// M14-T4: inbound hook handlers: event-type routes and upsert by key.
pub mod inbound_handlers;
/// J2-T2: routing rules for shared mailboxes.
pub mod inbound_mail;
/// D15-T2: which personal emails are captured, onto which addresses.
pub mod mail_capture;
pub mod model;
/// Z1-T11: OAuth 2.0 tokens, stored encrypted and renewed before expiry.
pub mod oauth;
/// E13-T10: Google and Bing statistics and IndexNow pings for connected sites.
pub mod search_console;
/// J4-T1: SMS sending and delivery receipts.
pub mod sms;
pub mod system;
/// P13-T1: incremental Parquet export of record changes for a warehouse.
pub mod warehouse_export;
/// P13-T2: load scripts for Snowflake and BigQuery over the export.
pub mod warehouse_load;
pub mod webhook;

/// D-351 — this crate's advisory-lock namespace (registry:
/// `crates/server/tests/advisory_lock_namespaces.rs`). Used by `admin.rs`'s
/// credential rotate/create paths (`pg_try_advisory_xact_lock($1,
/// hashtext($2))`, key `"attome-integration/system:{id}"`).
pub const ADVISORY_LOCK_NAMESPACE: i32 = 17;

pub use model::IntegrationModel;

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document, merged in by `attome_api::openapi_document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = admin::openapi_fragment();
    doc.merge(webhook::openapi_fragment());
    doc.merge(sms::openapi_fragment());
    doc.merge(connector::adapters::user_mail_sync::openapi_fragment());
    doc.merge(connector::adapters::video::openapi_fragment());
    doc.merge(warehouse_load::openapi_fragment());
    doc
}
