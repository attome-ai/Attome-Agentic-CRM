pub mod autovalue;
pub mod kinds;
pub mod provision;
pub mod purge;

pub use autovalue::{AutoValue, ResetScope};
pub use provision::{ensure_attribute, ensure_entity, sync_attribute_index};
pub use purge::{propose_purge_actions, scrub_record};

/// Advisory-lock namespace for every key taken under the `"attome-metadata/…"`
/// prefix (guidelines §2's `"{crate}/{operation}:{resource}"` convention) —
/// `provision-entity`, `provision-attribute`, `attribute-index` here, plus
/// `"attome-metadata/hierarchy:{entity}"` taken from `attome-server`'s
/// `entity_mutation`, which is why the constant is public.
///
/// Bound as the first argument of the two-argument
/// `pg_try_advisory_xact_lock($1, hashtext($2))` (and of the session-scoped
/// `pg_try_advisory_lock`/`pg_advisory_unlock` pair the index build uses) so a
/// `hashtext` collision between two unrelated keys can only happen *within*
/// this subsystem, never across subsystems (L-1 / TODO-027). The
/// workspace-wide assignment table, and the test that proves the ids stay
/// distinct, live in `crates/server/tests/advisory_lock_namespaces.rs`. Never
/// reuse or renumber an id.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 4;
