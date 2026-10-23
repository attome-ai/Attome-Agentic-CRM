//! M62 — Event Bus, Phase 1: subscriptions + webhook delivery
//! (D-403/D-409). Let anything react to anything without the producer
//! knowing who listens — durable, retried, and (from Phase 2) replayable
//! and monitored.
//!
//! D-403 placed this in its own engine crate rather than folding it into
//! `attome-api` alongside `jobs_admin.rs` — see that decision entry's
//! reasoning. Structured after `attome-s2s`, its closest sibling: an
//! admin-route-bundle crate over its own infrastructure tables (not an
//! `EngineModel`/provisioned-entity engine — subscriptions and deliveries are
//! infrastructure the way S2S clients/keys are, not customer-configurable
//! metadata), mounted directly by `attome-api`'s `system.rs` and
//! license-gated on `MODULE_INTEGRATION`.
//!
//! # Module map
//! - [`admin`] — `/api/v1/admin/events/subscriptions*` + `/deliveries`.
//! - [`dispatch`] — the scheduled tick that reads the outbox and enqueues
//!   deliveries (`EngineJob::EventsDispatchTick`).
//! - [`audit_dispatch`] — M19 gap list: the parallel tick for `kind =
//!   'audit'` subscriptions, reading `audit_header` directly instead of
//!   the entity-change outbox (same `EngineJob::EventsDispatchTick`
//!   handler runs both).
//! - [`delivery`] — signs, SSRF-guards, sends, and records one delivery
//!   (`EngineJob::EventsDeliverWebhook`).
//! - [`filter`] — subscription filter matching: entity, operation and
//!   event-name lists plus the M45 `filter_expression` over the event's own
//!   fields (implemented; see its module doc for the scope).
//! - [`payload`] — owner-scoped record projection for a delivered payload.
//! - [`crypto`] — webhook secret custody + HMAC signing.
//! - [`telemetry`] — M62 E1 metrics (plan §4.3), closed label sets only.
//!
//! Domain events are live: `event_name` on the outbox (migration `0145`) is
//! published by engines such as attome-service's SLA clock (`sla.breached`) and
//! matched by the `filter_event_names`/`filter_expression` filters.
//!
//! # Deferred to Phase 2
//! - Replay (`POST .../subscriptions/{id}/replay`).
//! - The per-subscription monitoring page + the `integration_status_widget`
//!   (E3; the E1 metrics are in [`telemetry`]).
//! - Migrating attome-search/attome-workflow's hardcoded outbox consumers onto
//!   `kind = 'internal'` subscriptions.

pub mod admin;
pub mod audit_dispatch;
pub mod auto_pause;
pub mod crypto;
pub mod dead_letter_source;
pub mod delivery;
pub mod dispatch;
pub mod filter;
/// L1-T7: the `master` object of a golden-record change's webhook body.
pub mod master;
pub mod payload;
pub mod telemetry;
