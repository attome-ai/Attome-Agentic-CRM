pub mod accounts;
pub mod admin;
pub mod api_keys;
/// Q1-T7: who may sign in with a password.
pub mod auth_policy;
pub mod cache;
/// U12-T1 — company walls in the record filter.
pub mod company_walls;
pub mod conditions;
pub mod conflicts;
pub mod context;
pub mod db;
pub mod delegation;
pub mod entity_privileges;
pub mod explain;
pub mod field_gate;
pub mod grant_expiry;
/// Q12-T3: a delegated administrator cannot grant more than they hold.
pub mod grants;
pub mod impersonation;
pub mod mfa;
pub mod mfa_policy;
pub mod model;
/// T2-T2: the caller's own role names.
pub mod my_roles;
pub mod parent_access;
pub mod permission_sets;
pub mod reconcile;
pub mod resolver;
pub mod revalidation;
pub mod rls;
pub mod rls_fragment;
/// D-792 — the fleet console's rollout privilege and role.
pub mod rollout;
/// Q3-T1: SCIM 2.0 provisioning of users and teams.
pub mod scim;
pub mod seed;
pub mod session_policy;
pub mod sharing_rules;
/// Q9-T1 — the sign-in network, hours and country rules of held roles.
pub mod sign_in_rules;
pub mod strict_authz;
pub mod usage;
pub mod view_log;
pub mod visibility;

pub use cache::SECURITY_VERSION_CHANNEL;
pub use context::{SecurityContextExt, record_action};
pub use db::{
    RecordAction, allowed_entity_actions, require_operation_level,
    resolve_all_entity_access_levels, resolve_default_share_entities, resolve_entity_access_level,
    resolve_owner_visible,
};
pub use resolver::{EngineSecurityResolver, resolve_uncached};
pub use rls::{
    Capability, ConditionAwarePredicate, FastTierColumns, PolymorphicAuditPredicate, RlsPredicate,
    polymorphic_audit_predicate, rls_predicate, rls_predicate_by_column,
    rls_predicate_with_conditions,
};
pub use rls_fragment::{RLS_BIND_COUNT, bind_rls_predicate, bind_rls_predicate_as};
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
    doc.merge(my_roles::openapi_fragment());
    doc.merge(mfa::openapi_fragment());
    doc
}
