pub mod admin;
pub mod catalog_backfill;
pub mod dead_letter_admin;
pub mod engine;
pub mod entity_trigger;
pub mod escalation;
pub mod graph;
pub mod instance_admin;
pub mod model;
pub mod node_types;
pub mod scheduler;
pub mod simulate;
pub mod sla_sweep;
pub mod trigger_index;

pub use engine::WorkflowModel;

/// Advisory-lock namespace for every key taken under the `"attome-workflow/…"`
/// prefix (guidelines §2's `"{crate}/{operation}:{resource}"` convention) —
/// `admin.rs`'s definition-create, version-create, and version-publish locks.
///
/// Bound as the first argument of the two-argument
/// `pg_try_advisory_xact_lock($1, hashtext($2))` so a `hashtext` collision
/// between two unrelated keys can only happen *within* this subsystem, never
/// across subsystems (L-1 / TODO-027). The workspace-wide assignment table,
/// and the test that proves the ids stay distinct, live in
/// `crates/server/tests/advisory_lock_namespaces.rs`. Never reuse or renumber
/// an id.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 7;

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document, merged in by `attome_api::openapi_document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = admin::openapi_fragment();
    doc.merge(instance_admin::openapi_fragment());
    doc.merge(dead_letter_admin::openapi_fragment());
    doc.merge(simulate::openapi_fragment());
    doc
}
