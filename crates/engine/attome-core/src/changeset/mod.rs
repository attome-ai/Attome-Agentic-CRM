//! Solution 7 Phase 1 (D-785) — the changeset recorder core.
//!
//! Every metadata admin write is recorded as one typed operation in a
//! changeset, in the write's own transaction; a closed changeset is the
//! promotion artifact (`attome-changeset/v1`). Spec:
//! `document/general/SOLUTION-7-PHASE-1-DESIGN.md` §2–§4.
//!
//! This module holds what every writer crate needs, which is why it lives in
//! attome-core (every writer already depends on it; no crate edge is
//! added):
//!
//! - [`model`] — owner [`Layer`]s, [`OpPhase`], the v1 [`Op`] catalogue and
//!   the [`RecordedOp`] a writer builds;
//! - [`recorder`] — [`Recording`]: `preflight`, `stamp`, `check_owner`,
//!   `record`, and automatic changesets;
//! - [`extract`] — the [`RecordingCtx`] axum extractor;
//! - [`store`] — open / read / lock / close / abandon / seal over
//!   `changeset` and `changeset_operation`;
//! - [`errors`] — the stable refusal messages.
//!
//! Close's translation into logical keys, the v1 document, the routes and the
//! apply engine live in `attome-server` (they need the bundle model).

pub mod errors;
pub mod extract;
/// Solution 7 Phase 2 (D-788) — the field reference-hook registry.
pub mod field_hooks;
pub mod model;
pub mod recorder;
/// Solution 7 Phase 2 (D-787 rule 7) — the ambient recording of generic
/// writes to reference-data entities (`upsert_record`).
pub mod reference;
pub mod store;

/// Every metadata table that carries `owner_layer` (migration 0520 added it;
/// 0525 dropped its `'project'` default, so every insert must name a layer).
/// Generic entity CRUD reads this to stamp the layer on the registered
/// entities among them (`role`, `privilege`,
/// `workflow_definition`), whose attribute metadata does not list the
/// column. Pinned by a test to migration 0525's tables minus those a later
/// migration drops (0536 drops `form`: forms are code, D-788/D-790).
pub const OWNER_LAYER_TABLES: &[&str] = &[
    "entity_info",
    "attribute_info",
    "relationship_info",
    "view",
    "sql_query",
    "rule",
    "state_model",
    "state_transition",
    "workflow_definition",
    "process_case_def",
    "sidebar",
    "app",
    "calendar",
    "calendar_holiday",
    "calendar_exception",
    "privilege",
    "role",
    "role_mm_privilege",
    "role_privilege_condition",
    "role_mm_entity_access",
    "role_bulk_field",
    "field_security_profile",
    "field_security_profile_field",
    "role_mm_field_security_profile",
    "entity_default_share",
    "metadata_label",
    "data_domain",
    "content_template",
    "content_space",
];

pub use extract::{CHANGESET_HEADER, RecordingCtx};
pub use model::{ChangesetStatus, Layer, Op, OpPhase, Origin, RecordedOp, RecordingMode};
pub use recorder::{Recording, RequestContext, RequestRecording, Resolved};
pub use store::{ChangesetRow, NewChangeset, OperationRow, Seal};

#[cfg(test)]
mod owner_layer_tables_tests {
    use super::OWNER_LAYER_TABLES;

    /// Tables a migration after 0525 drops (`DROP TABLE IF EXISTS <name>`).
    const DROPPED_LATER: &[&str] = &[include_str!(
        "../../../../server/migrations/0536_drop_xrm_core_form.sql"
    )];

    /// The list must match migration 0525 (one `ALTER TABLE` per owner-layer
    /// table) minus the tables a later migration dropped, so a table added to
    /// the set cannot be missed here and a dropped one cannot linger.
    #[test]
    fn matches_migration_0525_minus_later_drops() {
        let sql = include_str!("../../../../server/migrations/0525_owner_layer_drop_default.sql");
        let dropped: Vec<&str> = DROPPED_LATER
            .iter()
            .flat_map(|m| m.lines())
            .filter_map(|l| l.trim_start().strip_prefix("DROP TABLE IF EXISTS "))
            .filter_map(|rest| rest.split([' ', ';']).next())
            .collect();
        assert!(dropped.contains(&"form"), "0536 drops form");
        let mut in_migration: Vec<&str> = sql
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix("ALTER TABLE "))
            .filter_map(|rest| rest.split_whitespace().next())
            .filter(|t| !dropped.contains(t))
            .collect();
        in_migration.sort_unstable();
        let mut listed = OWNER_LAYER_TABLES.to_vec();
        listed.sort_unstable();
        assert_eq!(listed, in_migration);
    }
}
