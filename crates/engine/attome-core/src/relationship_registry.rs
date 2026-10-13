//! M01 Core P3 gap (D-455) — the in-memory snapshot of
//! `relationship_info`, the generic many-to-many relationship
//! metadata object.
//!
//! **Cache shape.** A small, admin-authored table (relationships change by
//! human edit, not by request volume), so this mirrors `state_registry`'s
//! simpler full-snapshot-reload pattern rather than `EntityMetaRegistry`'s
//! incremental `metadata_change_log` catch-up machinery: an
//! `ArcSwap`-backed `MetadataCache` pre-warmed at boot, refreshed in full on
//! a Redis pub/sub doorbell (`RELATIONSHIP_VERSION_CHANNEL`) and on
//! subscriber reconnect (`attome-server/src/system.rs`) — never a per-request
//! DB read on the record-link/query-join hot path.
//!
//! **Why this lives in `attome-core` rather than `attome-server`.** The
//! record-level `/related/{relationship}` handlers live in `attome-server`
//! (that's where `entity_crud` lives — see CLAUDE.md's name/content note),
//! but `attome-metadata`'s runtime provisioning (`provision::provision_join_table`)
//! also needs to resolve a relationship by name at apply/bundle time, and
//! `attome-metadata` cannot depend on `attome-server` (guidelines §1, the layering
//! is one-way). `attome-core` sits below both, so the registry (and the
//! `EngineState` field that holds it) lives here, following the same D-394
//! "Option B" shape `state_registry` already established for the same
//! problem.

use std::collections::HashMap;

use attome_db::DbPool;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Redis pub/sub channel: any node that writes `relationship_info`
/// best-effort publishes here so every other node's `EngineState::relationships`
/// cache reloads promptly instead of only on its next reconnect. Payload is
/// unused (a doorbell, not an instruction) — same posture as
/// `attome_core::STATE_MODEL_VERSION_CHANNEL`.
pub const RELATIONSHIP_VERSION_CHANNEL: &str = "relationship_version";

/// The `cascade` column's vocabulary — deliberately reuses `OnTargetDelete`'s
/// three-way shape (D-088) for a consistent policy vocabulary across lookup
/// fields and M:M relationships, rather than inventing a second one.
///
/// **Metadata-only in this phase.** The value is stored, validated (a
/// Postgres `CHECK` constraint backs it, same defensive posture as
/// `OnTargetDelete::from_db_str`), and returned to admin callers, but
/// nothing yet enforces it at entity-delete time — that is relationship
/// *semantics* beyond simple link/unlink, explicitly out of scope for this
/// change (M38's territory). The one required behavior — "soft-deleting
/// either side hides the link" — holds regardless of this policy, because
/// every `/related/{relationship}` read filters `is_active` on both endpoint
/// rows independent of `cascade`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationshipCascade {
    /// Reserved for a future enforcement pass: block deactivating either
    /// side while a live link still references it.
    Restrict,
    /// Today's actual behavior for every relationship regardless of the
    /// stored value: a soft-deleted endpoint simply drops out of every
    /// `/related/{relationship}` read (both-sides `is_active` filter), and
    /// the join row itself is left untouched.
    #[default]
    Orphan,
    /// Reserved for a future enforcement pass: deactivate the join row too
    /// when either endpoint deactivates.
    CascadeDeactivate,
}

impl RelationshipCascade {
    /// Never fails — an unrecognized stored string (there shouldn't be one;
    /// the column has a `CHECK` constraint) degrades to `Orphan`, the
    /// current real behavior, rather than rejecting the read — same
    /// defensive posture as `OnTargetDelete::from_db_str`.
    ///
    /// C-21 (M01 §7): the canonical spelling is hyphenated
    /// (`"cascade-deactivate"`), matching `OnTargetDelete`'s existing D-088
    /// vocabulary (`meta_registry::OnTargetDelete::from_db_str`) — this
    /// enum's original underscore spelling was an accidental divergence
    /// from that already-public convention, not a deliberate second one.
    /// The underscore spelling is still accepted here for one release, so a
    /// row written (or a bundle exported) before this fix keeps parsing
    /// correctly; `as_db_str` below only ever writes the hyphenated form
    /// from this point forward.
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "restrict" => Self::Restrict,
            "cascade-deactivate" | "cascade_deactivate" => Self::CascadeDeactivate,
            _ => Self::Orphan,
        }
    }

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Restrict => "restrict",
            Self::Orphan => "orphan",
            Self::CascadeDeactivate => "cascade-deactivate",
        }
    }
}

/// One `relationship_info` row — a named M:M relationship
/// definition between `entity_a` and `entity_b`, backed by the physical
/// join table `join_table` (`mm_{name}`, provisioned by
/// `attome_metadata::provision::provision_join_table`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationshipDef {
    pub id: Uuid,
    pub name: String,
    pub entity_a: String,
    pub entity_b: String,
    /// Display label for A's role in the relationship, from B's point of
    /// view (e.g. "Projects" on a project<->member relationship).
    pub role_a: String,
    /// Display label for B's role, from A's point of view (e.g. "Members").
    pub role_b: String,
    pub join_table: String,
    pub cascade: RelationshipCascade,
    pub is_customized: bool,
    /// Business enable/disable toggle, distinct from the row's own
    /// soft-delete (`is_deleted`, never loaded into this snapshot at all) —
    /// same split `StateModelDef::is_active` uses.
    pub is_active: bool,
    pub row_version: i64,
}

impl RelationshipDef {
    /// Given one endpoint's logicalname, resolves which side it is and what
    /// the *other* side's join-table column/entity is — the lookup every
    /// `/related/{relationship}` handler needs regardless of which side the
    /// route's `{entity}` segment named. `None` when `entity_logicalname`
    /// is neither side of this relationship.
    pub fn other_side(&self, entity_logicalname: &str) -> Option<OtherSide<'_>> {
        if entity_logicalname == self.entity_a {
            Some(OtherSide {
                this_column: "a_id",
                other_column: "b_id",
                other_entity: &self.entity_b,
                other_role: &self.role_b,
            })
        } else if entity_logicalname == self.entity_b {
            Some(OtherSide {
                this_column: "b_id",
                other_column: "a_id",
                other_entity: &self.entity_a,
                other_role: &self.role_a,
            })
        } else {
            None
        }
    }
}

/// The resolved shape of "the side that is NOT `entity_logicalname`" —
/// see [`RelationshipDef::other_side`].
pub struct OtherSide<'a> {
    /// The join table's column holding the *given* entity's record id.
    pub this_column: &'static str,
    /// The join table's column holding the *other* entity's record id.
    pub other_column: &'static str,
    pub other_entity: &'a str,
    pub other_role: &'a str,
}

impl std::fmt::Debug for OtherSide<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtherSide").finish_non_exhaustive()
    }
}

/// Snapshot of every live (`is_deleted = false`) `relationship_info`
/// row, keyed by `name`. Swapped in atomically by `EngineState::relationships` —
/// see `attome-server/src/system.rs`'s pre-warm + pub/sub reload, mirroring
/// `StateModelRegistry`'s own wiring.
#[derive(Clone, Debug, Default)]
pub struct RelationshipRegistry {
    by_name: HashMap<String, RelationshipDef>,
}

impl RelationshipRegistry {
    pub fn from_entries(defs: Vec<RelationshipDef>) -> Self {
        Self {
            by_name: defs.into_iter().map(|d| (d.name.clone(), d)).collect(),
        }
    }

    /// `None` means no relationship by this name is configured (or it was
    /// retired) — callers treat that as a 404/422, never as "no relations".
    pub fn get(&self, name: &str) -> Option<&RelationshipDef> {
        self.by_name.get(name)
    }

    /// Every relationship (either side) touching `entity_logicalname` — the
    /// set an entity-editor "Relationships" panel or a schema response would
    /// list. Business-disabled (`is_active = false`) relationships are
    /// excluded, same posture as `StateModelRegistry`'s equivalent callers
    /// deciding not to enforce a disabled model.
    pub fn for_entity(&self, entity_logicalname: &str) -> Vec<&RelationshipDef> {
        self.by_name
            .values()
            .filter(|d| {
                d.is_active
                    && (d.entity_a == entity_logicalname || d.entity_b == entity_logicalname)
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

#[derive(sqlx::FromRow)]
struct RelationshipRow {
    id: Uuid,
    name: String,
    entity_a: String,
    entity_b: String,
    role_a: String,
    role_b: String,
    join_table: String,
    cascade: String,
    is_customized: bool,
    is_active: bool,
    row_version: i64,
}

/// Builds a full registry snapshot from Postgres: one query, no N+1. Only
/// live (`is_deleted = false`) rows; a relationship's own `is_active` flag
/// (business enable/disable) is loaded but not filtered on here — callers
/// (`for_entity`) decide whether a disabled relationship still counts.
pub async fn load(db: &DbPool) -> Result<RelationshipRegistry, AppError> {
    let rows: Vec<RelationshipRow> = sqlx::query_as(
        "SELECT id, name, entity_a, entity_b, role_a, role_b, join_table, cascade, \
                is_customized, is_active, row_version \
         FROM relationship_info WHERE is_deleted = false",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let defs = rows
        .into_iter()
        .map(|r| RelationshipDef {
            id: r.id,
            name: r.name,
            entity_a: r.entity_a,
            entity_b: r.entity_b,
            role_a: r.role_a,
            role_b: r.role_b,
            join_table: r.join_table,
            cascade: RelationshipCascade::from_db_str(&r.cascade),
            is_customized: r.is_customized,
            is_active: r.is_active,
            row_version: r.row_version,
        })
        .collect();

    Ok(RelationshipRegistry::from_entries(defs))
}

/// C-18 — `spawn_doorbell_reload::<RelationshipRegistry>` (`attome-server/src/
/// system.rs`) is the only caller of this impl's `load`; every other call
/// site keeps calling the free `load` fn above directly (unchanged).
impl crate::snapshot_source::SnapshotSource for RelationshipRegistry {
    const CHANNEL: &'static str = RELATIONSHIP_VERSION_CHANNEL;

    fn load(db: &DbPool) -> crate::snapshot_source::BoxFuture<'_, Result<Self, AppError>> {
        Box::pin(load(db))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot_source::SnapshotSource;

    #[test]
    fn snapshot_source_channel_matches_the_public_constant() {
        assert_eq!(
            <RelationshipRegistry as SnapshotSource>::CHANNEL,
            RELATIONSHIP_VERSION_CHANNEL
        );
    }

    fn def(name: &str, a: &str, b: &str) -> RelationshipDef {
        RelationshipDef {
            id: Uuid::now_v7(),
            name: name.to_owned(),
            entity_a: a.to_owned(),
            entity_b: b.to_owned(),
            role_a: "As".to_owned(),
            role_b: "Bs".to_owned(),
            join_table: format!("mm_{name}"),
            cascade: RelationshipCascade::Orphan,
            is_customized: true,
            is_active: true,
            row_version: 0,
        }
    }

    #[test]
    fn cascade_round_trips_through_db_str() {
        for c in [
            RelationshipCascade::Restrict,
            RelationshipCascade::Orphan,
            RelationshipCascade::CascadeDeactivate,
        ] {
            assert_eq!(RelationshipCascade::from_db_str(c.as_db_str()), c);
        }
    }

    /// C-21 (M01 §7) — `as_db_str` now writes the hyphenated spelling
    /// (matching `OnTargetDelete`'s D-088 vocabulary), but the original
    /// underscore spelling must still parse for one release: an
    /// already-stored row or an already-exported bundle written before this
    /// fix used it.
    #[test]
    fn cascade_deactivate_accepts_both_the_canonical_and_legacy_spelling() {
        assert_eq!(
            RelationshipCascade::from_db_str("cascade-deactivate"),
            RelationshipCascade::CascadeDeactivate
        );
        assert_eq!(
            RelationshipCascade::from_db_str("cascade_deactivate"),
            RelationshipCascade::CascadeDeactivate
        );
        assert_eq!(
            RelationshipCascade::CascadeDeactivate.as_db_str(),
            "cascade-deactivate",
            "as_db_str always writes the canonical hyphenated spelling"
        );
    }

    #[test]
    fn unrecognized_cascade_string_degrades_to_orphan() {
        assert_eq!(
            RelationshipCascade::from_db_str("garbage"),
            RelationshipCascade::Orphan
        );
    }

    #[test]
    fn other_side_resolves_from_either_endpoint() {
        let d = def("project_members", "attome_project", "user_account");
        let from_a = d.other_side("attome_project").unwrap();
        assert_eq!(from_a.this_column, "a_id");
        assert_eq!(from_a.other_column, "b_id");
        assert_eq!(from_a.other_entity, "user_account");

        let from_b = d.other_side("user_account").unwrap();
        assert_eq!(from_b.this_column, "b_id");
        assert_eq!(from_b.other_column, "a_id");
        assert_eq!(from_b.other_entity, "attome_project");

        assert!(d.other_side("team").is_none());
    }

    #[test]
    fn registry_get_and_for_entity() {
        let reg = RelationshipRegistry::from_entries(vec![
            def("project_members", "attome_project", "user_account"),
            def("project_watchers", "attome_project", "user_account"),
            def("team_members", "team", "user_account"),
        ]);
        assert!(reg.get("project_members").is_some());
        assert!(reg.get("missing").is_none());

        let touching_project = reg.for_entity("attome_project");
        assert_eq!(touching_project.len(), 2);

        let touching_user = reg.for_entity("user_account");
        assert_eq!(touching_user.len(), 3);
    }

    #[test]
    fn for_entity_excludes_business_disabled_relationships() {
        let mut disabled = def("archived_link", "attome_project", "user_account");
        disabled.is_active = false;
        let reg = RelationshipRegistry::from_entries(vec![disabled]);
        assert!(reg.for_entity("attome_project").is_empty());
        assert!(
            reg.get("archived_link").is_some(),
            "get() still finds a disabled row"
        );
    }
}
