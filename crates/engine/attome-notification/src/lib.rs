pub mod admin;
pub mod approval_timeouts;
pub mod communication;
mod consent_gate;
pub mod dispatch;
pub mod engine;
pub mod follows;
pub mod model;
pub mod poller;
pub mod preferences;
/// J12-T1: Web Push, APNs and FCM.
pub mod push;
pub mod recipient;
pub mod reminders;
pub mod seed;
pub mod service;
/// D16-T1: email open and click tracking.
pub mod tracking;

pub use engine::NotificationModel;
pub use model::{Notification, NotificationType};
pub use service::NotificationInbox;

/// Advisory-lock namespace for every key taken under the
/// `"attome-notification/…"` prefix (guidelines §2's
/// `"{crate}/{operation}:{resource}"` convention) — today only
/// `recipient::prune_old_partitions`'s retention lock.
///
/// Bound as the first argument of the two-argument
/// `pg_try_advisory_xact_lock($1, hashtext($2))` so a `hashtext` collision
/// between two unrelated keys can only happen *within* this subsystem, never
/// across subsystems (L-1 / TODO-027). The workspace-wide assignment table,
/// and the test that proves the ids stay distinct, live in
/// `crates/server/tests/advisory_lock_namespaces.rs`. Never reuse or renumber
/// an id.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 6;

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document, merged in by `attome_api::openapi_document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = engine::openapi_fragment();
    doc.merge(tracking::openapi_fragment());
    doc
}
