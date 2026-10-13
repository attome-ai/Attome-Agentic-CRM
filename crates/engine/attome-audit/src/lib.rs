pub mod admin;
pub mod anchor;
pub mod approval;
/// Audit plan item 3.10 / D-541 rule 5: bulk parent `BulkAccepted`/
/// `BulkCompleted` events (C13/I13).
pub mod bulk;
/// Audit plan 3.6 / D-062: the in-transaction `BusinessEvent` writer.
pub mod business;
pub mod canonical;
pub mod chainer;
pub mod checkpoint;
pub mod erasure;
pub mod initiator;
mod model;
pub mod policy_resolver;
/// Phase 4 item 4.1: ambient per-request context (correlation id, IP, UA),
/// read by `AuditService::write_in_tx_with_extras` — see its module doc.
/// Internal: nothing outside this crate calls it directly.
mod request_ctx;
/// D-541 rule 4 / D-542 rule 4 (audit plan 3.2): the one writer for the
/// mandatory categories, which never consults `audit_config`.
pub mod security;
pub mod seed;
pub mod service;
/// D-442 / M58 Phase 1 (Digital Signature) — decision-digest computation and
/// recording. See that module's own doc comment for scope and rationale.
pub mod signoff;
mod user_ctx;
pub mod value_mode;
pub mod verify;

pub use anchor::{anchor_root, fetch_anchored_root};
pub use bulk::{write_bulk_accepted, write_bulk_completed_once};
pub use business::{BusinessEvent, write_business_event_in_tx};
pub use erasure::{ERASED_MARKER, decrypt_field, destroy_key};
pub use model::{
    AuditCategory, AuditEvent, AuditFieldChange, AuditOperation, AuditOutcome, AuditRequestContext,
    AuditSource, AuditUserContext, EventExtras,
};
pub use seed::seed;
pub use service::AuditService;
pub use user_ctx::{audit_service, fetch_audit_ctx, write_business_event};

/// Advisory-lock namespace for every key taken under the `"attome-audit/…"`
/// prefix (guidelines §2's `"{crate}/{operation}:{resource}"` convention) —
/// the synchronous chain-append lock and the chainer's per-org batch lock
/// here, plus `"attome-audit/erasure:{record_id}"` taken from `attome-server`'s
/// erasure admin, which is why the constant is public.
///
/// Bound as the first argument of the two-argument
/// `pg_try_advisory_xact_lock($1, hashtext($2))` so a `hashtext` collision
/// between two unrelated keys can only happen *within* this subsystem, never
/// across subsystems (L-1 / TODO-027). The workspace-wide assignment table,
/// and the test that proves the ids stay distinct, live in
/// `crates/server/tests/advisory_lock_namespaces.rs`. Never reuse or renumber
/// an id.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 5;
/// Plan 5.2: the `audit_config` entity's own logicalname, checked by
/// `attome-records::mutation_ring` to write a mandatory `Configuration`
/// event whenever the audit policy table itself changes.
pub const AUDIT_CONFIG_ENTITY: &str = "audit_config";
/// Re-exported for convenience — `AuditSigner` lives in attome-core (not
/// here) so `EngineState` can hold one without attome-core depending on
/// attome-audit (attome-audit already depends on attome-metadata, which depends on
/// attome-core — the reverse edge would be a cycle).
pub use attome_core::AuditSigner;

pub use initiator::{Attribution, Initiator};
