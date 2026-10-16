pub mod accounts;
pub mod admin;
pub mod api_keys;
pub mod cache;
pub mod conditions;
pub mod context;
pub mod db;
pub mod entity_privileges;
pub mod field_gate;
pub mod mfa;
pub mod mfa_policy;
pub mod model;
pub mod reconcile;
pub mod resolver;
pub mod revalidation;
pub mod rls;
pub mod rls_fragment;
/// D-792 — the fleet console's rollout privilege and role.
pub mod rollout;
pub mod seed;
pub mod session_policy;
pub mod strict_authz;
pub mod visibility;

pub use cache::SECURITY_VERSION_CHANNEL;
pub use context::{SecurityContextExt, record_action};
pub use db::{
    RecordAction, resolve_all_entity_access_levels, resolve_default_share_entities,
    resolve_entity_access_level, resolve_owner_visible,
};
pub use resolver::{EngineSecurityResolver, resolve_uncached};
pub use rls::{
    Capability, ConditionAwarePredicate, FastTierColumns, PolymorphicAuditPredicate, RlsPredicate,
    polymorphic_audit_predicate, rls_predicate, rls_predicate_by_column,
    rls_predicate_with_conditions,
};
pub use rls_fragment::{RLS_BIND_COUNT, bind_rls_predicate};
pub use rollout::{METADATA_ROLLOUT_PRIVILEGE_KEY, MetadataRollout};
pub use visibility::PolymorphicVisibility;

/// Advisory-lock namespace for every key taken under the `"attome-security/…"`
/// prefix (guidelines §2's `"{crate}/{operation}:{resource}"` convention) —
/// `reconcile:{role}` in `reconcile.rs` so far (C-19). Bound as the first
/// argument of the two-argument `pg_try_advisory_xact_lock($1,
/// hashtext($2))` so a `hashtext` collision between two unrelated keys can
/// only happen *within* this subsystem, never across subsystems (L-1/
/// TODO-027). The workspace-wide assignment table, and the test that proves
/// the ids stay distinct, live in
/// `crates/server/tests/advisory_lock_namespaces.rs`. Never reuse or
/// renumber an id.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 23;

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document, merged in by `attome_server::openapi_document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = admin::openapi();
    doc.merge(api_keys::openapi_fragment());
    doc.merge(mfa::openapi_fragment());
    doc
}
