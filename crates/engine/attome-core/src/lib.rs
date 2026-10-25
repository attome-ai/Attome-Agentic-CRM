/// The deployment's single default ("root") organization, seeded by migration
/// `0102_default_root_organization.sql`.
///
/// Deliberately the nil UUID rather than a `uuidv7()` value: every write path
/// has always stamped `Uuid::nil()` when a user had no `organization_ref`, so
/// every pre-existing entity record and audit row already carries it. Adopting
/// it as the root org's real id meant no backfill across provisioned entity
/// tables and no discontinuity in the per-organization audit hash chain — see
/// that migration's header for the full reasoning, including why
/// `verify_audit_chain`'s org discovery forced the choice.
///
/// Use this in preference to a bare `Uuid::nil()` wherever the value means
/// "the organization to file this under", so the intent is legible and the
/// sites are greppable if a deployment ever needs more than one root.
pub const ROOT_ORGANIZATION_ID: uuid::Uuid = uuid::Uuid::nil();

/// Advisory-lock namespace for every key taken under the
/// `"attome-core/…"` prefix (guidelines §2's
/// `"{crate}/{operation}:{resource}"` convention) — today only
/// `change_log::METADATA_WRITE_LOCK_KEY`.
///
/// Bound as the first argument of the two-argument
/// `pg_try_advisory_xact_lock($1, hashtext($2))` so a `hashtext` collision
/// between two unrelated keys can only happen *within* this subsystem, never
/// across subsystems (L-1 / TODO-027). The workspace-wide assignment table,
/// and the test that proves the ids stay distinct, live in
/// `crates/server/tests/advisory_lock_namespaces.rs`. Never reuse or renumber
/// an id.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 3;

/// Non-blocking `pg_try_advisory_xact_lock` under [`ADVISORY_LOCK_NAMESPACE`]
/// (guidelines §2's two-argument form) — the shared body every
/// resource-scoped write lock in this crate used to hand-copy independently
/// (`change_log::acquire_metadata_write_lock`,
/// `setting_store::acquire_setting_write_lock`,
/// `label_store::acquire_label_write_lock`, and the inline lock inside
/// `metadata_reference::replace_references`, C-18). `key` is the caller's
/// own `"{crate}/{operation}:{resource}"`-shaped string; `conflict_msg` is
/// returned verbatim as `AppError::Conflict` on failure to acquire, so each
/// caller keeps its own wording.
pub async fn try_xact_lock(
    tx: &mut attome_db::Tx<'_>,
    key: &str,
    conflict_msg: &'static str,
) -> Result<(), attome_types::AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(ADVISORY_LOCK_NAMESPACE)
        .bind(key)
        .fetch_one(&mut **tx)
        .await
        .map_err(attome_types::AppError::internal)?;
    if !locked {
        return Err(attome_types::AppError::Conflict(conflict_msg));
    }
    Ok(())
}

/// AK3-T1: the agent an engine write is made for, read by the audit and
/// change-feed writers.
pub mod agent_scope;
/// B5-T3: writes whose change events start no automation.
pub mod quiet_scope;
/// L7-T2: the channel and flow run an engine write came from, read by the
/// change-feed writers.
pub mod provenance_scope;
pub mod quiet_window;
/// L5-T2: lineage edges captured at publish.
pub mod lineage;
/// C11 B5 (P-5) — the runtime AI switch's read side: `config AND runtime`,
/// failing closed, consulted by every AI surface.
pub mod ai_runtime_switch;
pub mod audit_signing;
/// Business rules (D-789, D-791) — the condition tree, policies, audience and
/// lock precedence; `compile_condition` (one attome-rules program, typed
/// parameters) and `validate_rule`.
pub mod business_rules;
/// Z3-T5 — cross-node cache invalidation from the change feed.
pub mod cache_invalidation;
/// Z3-T3 — how a cache must keep an entity's fields.
pub mod cache_sensitivity;
/// D-517 — the single `calendar` loader: strict parsing into a
/// `attome_calendar::BusinessCalendar`, typed unresolved reasons, content hash.
pub mod calendar;
pub mod change_feed;
pub mod change_log;
/// Solution 7 Phase 1 (D-785) — the changeset recorder core: layers, the v1
/// operation catalogue, `Recording`/`RecordingCtx`, and the changeset store.
pub mod changeset;
pub mod chart_view_metadata;
/// E27-T2: the marketing consent rule, shared by every sender.
pub mod consent_rules;
/// ARCH-1a-i — generic metadata-driven record insert, moved here from
/// `attome-metadata`. Its only XRM dependency was ever `quote_ident`, and its own
/// header always described it as cross-crate ("callable from other crates
/// without going through HTTP"), so it was a shared primitive filed in an
/// engine crate. Living here means `attome-audit` no longer needs `attome-metadata`
/// for it — one of the edges that makes ARCH-1 a dependency cycle.
pub mod credential_columns;
pub mod crud;
pub mod data_definition;
pub mod data_domain;
/// L6-T8: reading stored data profiles.
pub mod data_profile;
/// M5-T1: one shape for dead letters from every source.
pub mod dead_letter;
pub mod defaults_scope;
/// A30-T2: environment variables in rules and flows, as `env.<name>`.
pub mod env_vars;
/// T6-T2: customer flags, read by rules and flows as `flag('name')`.
pub mod customer_flags;
/// T6-T3: A/B variants of a feature flag and their recorded outcomes.
pub mod experiment;
/// M95/D-430 — the closed `FeatureFlag` catalogue. Split from
/// `feature_flag_catalog` (the hand-written list) the same way
/// `setting_descriptor`/`setting_catalog` are split, for the same reason:
/// the catalogue grows, the registry machinery does not.
mod feature_flag_catalog;
pub mod feature_flag_descriptor;
pub mod feature_flag_store;
pub mod field_type;
pub mod filter;
/// M05 Phase 1 (D-426) — per-locale `metadata_label` resolution
/// (requested locale -> deployment default -> base `display_name`), cached
/// the same way `setting_store` is.
/// Basic-units U9 / B-R6 (D-604) — formula fields: options shape, the
/// field-type -> rules-type map, and the save-time compile check.
pub mod formula;
pub mod hijri_store;
/// The engine's job kinds (V2-D481).
pub mod jobs;
pub mod label_store;
pub mod legal_hold;
/// Dashboard 10/10 Phase 6 — the `MyWorkProvider` trait every
/// actionable-work-owning engine implements, and the types the aggregation
/// route composes across them.
pub mod match_normalize;
pub mod match_rule;
pub mod meta_registry;
/// M18 Data Catalog Phase 1 (D-466) — the shared writer/reader for
/// `metadata_reference`, the generalized lineage table. Lives here
/// for the same reason `change_feed`/`data_domain` do: more than one engine
/// (`attome-server` for queries, `attome-workflow` for workflows) writes it.
pub mod metadata_reference;
pub mod model;
pub mod my_work;
pub mod partition_maintenance;
/// R1-T1: restriction of processing, shared by every processing path.
pub mod processing_restriction;
pub mod reconcile;
/// Solution 7 Phase 2 (D-788 rule 9) — the 30-day encrypted recovery archive.
pub mod recovery_archive;
/// M01 Core P3 gap (D-455) — the generic many-to-many relationship-metadata
/// registry snapshot, consulted by `attome-server`'s `/related/{relationship}`
/// handlers and `attome-metadata`'s bundle-apply reconcile path.
pub mod relationship_registry;
/// Solution 7 Phase 2 (D-788 Topic 14, D-791) — the release report store and
/// the record baseline (the three-way "customer wins" rule).
pub mod release_report;
pub mod rule_registry;
/// Z11-T10: the SQL-safe part of a rule expression as a bound predicate.
pub mod rules_sql;
pub mod run_payload;
/// Boot-cost fix — skip-gate wrapping the ~30 `*::seed::seed(db)` functions
/// called from `crates/server/src/boot.rs`/`EngineSystem::build()`, backed by
/// `seed_watermark` (migration `0388_seed_watermark.sql`).
pub mod seed_gate;
pub mod services;
/// M02/D-412 — the closed `SettingDescriptor` catalogue. Split from
/// `setting_descriptor` (the registry/type definitions) the same way
/// `attome-ai`'s `actions/mod.rs` is split from `descriptor.rs` — the
/// catalogue is the thing that grows as new settings are registered, the
/// registry machinery does not.
mod setting_catalog;
pub mod setting_descriptor;
pub mod setting_store;
/// C5 (chatbot plan) — the `WorkflowStarter` seam `attome-ai`'s `workflow.start`
/// reaches `attome-workflow` through without a dependency cycle.
pub mod settings_write;
/// C-18 — the shared `SnapshotSource` trait + `spawn_doorbell_reload`
/// helper for the small-admin-authored-table caches
/// (`state_registry`/`relationship_registry`/`rule_registry`).
pub mod snapshot_source;
pub mod sql_ident;
pub mod state;
/// M07 Phase 1 (D-406) — the state-lifecycle registry snapshot and the
/// enforcement checks `attome-server::entity_mutation` and `attome-state` share.
pub mod state_registry;
/// F6-T5: what a location holds of a product, without the inventory engine.
pub mod stock_seam;
pub mod theme_store;
pub mod theme_tokens;
pub mod timer;
pub mod transfer_gate;
pub mod workflow_start;
/// E8-T1: engine-contributed workflow steps and kind guards.
pub mod workflow_step;

pub use audit_signing::AuditSigner;
pub use business_rules::{
    AppliesTo, BusinessRuleDef, BusinessRuleOp, CompiledCondition, ConditionOutcome, ConditionTree,
    FieldLock, LockEffect, PolicyDef, PolicyEffect, PolicyType, RuleAudience, RuleIssue, SetMode,
    Severity,
};
pub use change_feed::{ChangeEvent, ChangeOperation, CursorPosition};
pub use change_log::{
    ChangeKind, ChangeLogRow, METADATA_CHANGE_CHANNEL, acquire_metadata_write_lock,
    append_change_log, changes_since, log_watermark,
};
pub use data_domain::resolve_steward_for_domain;
pub use feature_flag_descriptor::{
    FeatureFlag, FeatureFlagRegistry, registry as feature_flag_registry,
};
pub use feature_flag_store::{
    ExpiredFlag, FeatureFlagPolicy, FeatureFlags, ScheduledChange, expired_flags,
    feature_flag_cache_key, validate_flag_dependencies,
};
pub use field_type::{ALL_FIELD_TYPES, FORMULA_RESULT_TYPES, FieldType};
pub use filter::{
    Bind, FieldCastError, Filter, FilterSchema, cast_for_attr, compile as compile_filter,
    is_multi_choice_attr, multi_choice_filter_values, parameter_cast, scalar_filter_value,
    text_array_literal,
};
pub use label_store::{
    KNOWN_OBJECT_KINDS, LabelRow, LabelSnapshot, acquire_label_write_lock, append_label_change_log,
    is_valid_locale_tag, label_log_watermark, label_write_lock_key, load_all as load_all_labels,
};
pub use legal_hold::{LegalHoldInfo, record_is_held};
pub use meta_registry::{
    AttrInfo, DataClassification, EntityMeta, EntityMetaRegistry, OnTargetDelete, SchemaEntity,
    Sensitivity,
    SchemaField, apply_change_log, build_registry, fetch_entity_snapshot, fetch_entity_snapshots,
    fetch_schema_facts, load_snapshot, save_snapshot, verify_ids_exist,
};
pub use metadata_reference::{
    BackfillProgress, MetadataReferenceInput, MetadataReferenceRow, advance_backfill_progress,
    backfill_progress, references_from, references_to_entity, references_to_metric,
    replace_references,
};
pub use model::{EngineModel, EntityModuleMap, EntityModuleOwner};
pub use my_work::{MyWorkAction, MyWorkFuture, MyWorkItem, MyWorkPage, MyWorkProvider};
pub use relationship_registry::{
    OtherSide, RELATIONSHIP_VERSION_CHANNEL, RelationshipCascade, RelationshipDef,
    RelationshipRegistry,
};
pub use rule_registry::{InvalidRule, RULE_VERSION_CHANNEL, RuleDef, RuleEntry, RuleRegistry};
pub use services::{NoopNotifications, NotificationService, ServiceError};
pub use setting_descriptor::{
    SettingDescriptor, SettingRegistry, SettingScope, SettingSource, registry as setting_registry,
};
pub use setting_store::{
    SettingRow, SettingsSnapshot, acquire_setting_write_lock, append_setting_change_log,
    load_all as load_all_settings, setting_log_watermark, setting_write_lock_key,
    validate_against_schema,
};
pub use settings_write::SettingsWriter;
pub use snapshot_source::{SnapshotSource, spawn_doorbell_reload};
pub use sql_ident::{
    ALL_SYSTEM_COLS, live_row_predicate, quote_ident, select_columns, select_columns_filtered,
    select_columns_where,
};
pub use state::{
    AUDIT_USER_VERSION_CHANNEL, AuditUserInfo, EngineState, FEATURE_FLAG_VERSION_CHANNEL,
    audit_user_cache_key,
};
pub use state_registry::{
    ACTION_STATE_TRANSITION, STATE_MODEL_VERSION_CHANNEL, StateModelDef, StateModelEntry,
    StateModelRegistry, TransitionApprovalPayload, TransitionDef, available_transitions,
    check_initial_state, check_transition, check_transition_with,
};
pub use transfer_gate::{TransferDecision, assert_transfer_allowed};
pub use workflow_start::{WorkflowStartFuture, WorkflowStartRequest, WorkflowStarter};
