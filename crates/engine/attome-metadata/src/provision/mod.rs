//! Standalone entity and attribute registration.
//! Called by the attome-server admin HTTP handlers AND by crates like attome-audit
//! that need to seed system entities at startup — without going through HTTP.
//!
//! Split into one file per use case / policy boundary (item 25 of the
//! platform's file-size cleanup list): `identifiers` (name validation and
//! field-type mapping), `ddl` (low-level locked-DDL execution primitives),
//! `table` (physical table/column provisioning), `attribute` (entity/
//! attribute metadata registration and attribute-index sync), `grants`
//! (`attome_readonly` SELECT grant maintenance), `schema_change`
//! (P-online-schema-change's durable async column-contract evolution),
//! `reconcile` (P-environment-promotion's declarative create-or-update
//! primitives that `ensure_entity`/`ensure_attribute` are now thin wrappers
//! over), and `default_query` (default list-view seeding). This file only
//! wires the submodules and re-exports every item that was previously
//! reachable as `attome_metadata::provision::<name>`.

mod attribute;
mod bundle_walk;
/// Solution 7 Phase 2 (D-787 rule 7, D-791 rule 7) — entity business keys:
/// declaration, the `uxbk_` unique index, key references, the rename/delete
/// reference hook.
pub mod business_key;
mod category_backfill;
/// Y12-T3 — how a proposed structure change will run, with an estimate.
pub mod change_plan;
/// Solution 7 Phase 1 (D-785) — owner-layer stamping and changeset recording
/// for the entity, attribute and relationship primitives.
pub mod changeset;
mod ddl;
mod default_query;
/// Solution 7 Phase 2 (D-788) — rename in place, real delete with the
/// recovery archive, in-place type conversion, choice values, run ledger.
pub mod field_change;
mod fixture_gate;
mod grants;
mod identifiers;
/// AA3-T1: indexes for the attributes views and definitions filter and sort on.
pub mod index_advisor;
/// Y11-T7: listing and resolving upgrade conflicts.
pub mod layer_conflicts;
/// Y2-T4 — the orphan scan: lookup values that point at no record.
pub mod lookup_fk;
/// L1-T2: a master entity's contribution and provenance side tables.
pub mod master;
/// Y12-T6 — backfill batch sizes that follow the load.
pub mod pacing;
mod property_layer;
mod reconcile;
/// A27-T1 — the `record_type` attribute an entity gets with its first type.
pub mod record_type;
/// Y12-T11: rehearse a field change on a copy database.
pub mod rehearse;
/// M01 Core P3 gap (D-455) — physical join-table provisioning for the
/// generic many-to-many relationship metadata object.
mod relationship;
mod schema_change;
/// A1-T1: write an attribute's or entity's sensitivity label.
pub mod sensitivity;
pub mod stage_process;
mod table;

#[cfg(test)]
mod tests;

pub use attribute::{
    MAX_ATTRIBUTES_PER_ENTITY, attribute_index_requires_async, backfill_lookup_indexes,
    count_duplicate_values, ensure_attribute, ensure_entity, lookup_columns_without_index,
    sync_attribute_index, sync_attribute_index_on_connection, sync_external_id_index,
    sync_field_constraints, sync_trigram_index, sync_trigram_index_on_connection,
    table_row_count_exceeds, trigram_index_candidates,
};
pub use bundle_walk::seed_bundle_for_tests;
pub use business_key::{
    BusinessKey, BusinessKeyHook, DeclareOutcome, IndexSync, KeyIndexState,
    business_key_index_status, declare_business_key_recorded, ensure_business_key_index,
    read_business_key, sync_business_key_index,
};
pub use category_backfill::backfill_entity_category;
pub use changeset::RecordAs;
pub use default_query::{
    ensure_default_query, ensure_entity_list_views, ensure_secondary_view,
    reject_unsafe_default_query_sql, resync_seeded_query_sql, set_default_query_display_column,
};
pub use fixture_gate::run_bundle_fixture;
pub use grants::{backfill_readonly_grants, grant_readonly_select};
pub use identifiers::{
    MAX_IDENTIFIER_LEN, attribute_index_name, external_id_index_name, is_multi_valued,
    physical_field_type, trigram_index_name, valid_field_type, valid_identifier,
};
pub use reconcile::{
    AttributeDesc, EntityDesc, RECONCILE_SCHEMA_CHANGE_INLINE_ROW_LIMIT, ReconcileOutcome,
    ReconcilePolicy, reactivate_attribute, reactivate_attribute_recorded, reactivate_entity,
    reactivate_entity_recorded, reconcile_attribute, reconcile_attribute_recorded,
    reconcile_attribute_with_id, reconcile_entity, reconcile_entity_recorded,
    reconcile_entity_with_id, retire_attribute, retire_attribute_recorded, retire_entity,
    retire_entity_recorded,
};
pub use relationship::{
    RelationshipDesc, RelationshipDetail, drop_join_table, ensure_link_columns,
    provision_join_table, reconcile_relationship, reconcile_relationship_recorded,
    retire_relationship, retire_relationship_by_name, retire_relationship_by_name_recorded,
    retire_relationship_recorded,
};
pub use schema_change::{
    ChangeClassification, SchemaChangePlanRequest, apply_schema_change_plan,
    classify_schema_change, evolve_attribute_schema, queue_contract_change,
    queue_contract_change_recorded, queue_schema_change_plan, queue_schema_change_plan_in_tx,
    validate_backfill_default,
};
pub use table::{backfill_rls_columns, drop_table};

// Not part of the public surface — brought into this module's own namespace
// (private `use`, not `pub use`) purely so `tests` (a child module of this
// one) can resolve them via `super::NAME`, exactly as it did when everything
// lived in one file. Requires `ATTRIBUTE_INDEX_CONNECTION_LIMIT` to be
// `pub(super)` in `attribute` and `default_display_query_sql`/
// `seeded_view_sql` to be `pub(super)` in `default_query`.
// `reject_unsafe_default_query_sql` is NOT re-listed here — it is `pub` and
// already brought in by the `pub use default_query::{...}` above, which
// `tests` (a child module) also sees via `super::`.
#[cfg(test)]
use attribute::ATTRIBUTE_INDEX_CONNECTION_LIMIT;
#[cfg(test)]
use default_query::{default_display_query_sql, seeded_view_sql};
#[cfg(test)]
use reconcile::{RowStatus, WriteStep, decide_step, managed_value};
