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
/// the column has no default, so every insert must name a layer).
/// Generic entity CRUD reads this to stamp the layer on the registered
/// entities among them (`role`, `privilege`,
/// `workflow_definition`), whose attribute metadata does not list the
/// column. A test pins it against the engine baseline migration.
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

    /// The engine baseline migration: every table with an `owner_layer`
    /// column declares it `NOT NULL` with no default.
    const ENGINE_MIGRATION: &str =
        include_str!("../../../../apps/attome/migrations/0006_engine.sql");

    /// Every table the engine baseline gives an `owner_layer` column must be
    /// listed, so a new one cannot be missed. Module tables (content,
    /// workflow, process) are listed ahead of their own migrations.
    #[test]
    fn lists_every_owner_layer_table_of_the_baseline() {
        let missing: Vec<&str> = ENGINE_MIGRATION
            .split("CREATE TABLE IF NOT EXISTS ")
            .skip(1)
            .filter(|block| {
                let body = block
                    .split(
                        "
);",
                    )
                    .next()
                    .unwrap_or("");
                body.contains(
                    "
    owner_layer text NOT NULL",
                )
            })
            .filter_map(|block| block.split_whitespace().next())
            .filter(|table| !OWNER_LAYER_TABLES.contains(table))
            .collect();
        assert!(
            missing.is_empty(),
            "owner-layer tables not listed: {missing:?}"
        );
    }
}
