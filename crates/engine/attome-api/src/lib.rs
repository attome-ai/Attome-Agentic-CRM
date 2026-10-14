// Deep async call graphs (an agent turn runs actions that run turns)
// overflow the default query depth.
#![recursion_limit = "512"]
mod admin;
/// The changeset-recorder helpers the UI metadata admin files share (D-785).
mod admin_hooks;
/// M61 Phase 1 (API Management, D-438) — `/api/v1/admin/api-usage/summary`.
/// No other module needs to reach into this one, same shape as
/// `approval_admin`/`jobs_admin`.
mod api_usage_admin;
/// M65 Phase 1 — Application Builder: `/api/v1/admin/apps*` CRUD + the
/// self-service `/api/v1/apps` switcher read. `pub` for the same reason
/// `view_admin`/`calendar_admin` are — `bundle` reconciles it.
pub mod app_admin;
mod approval_admin;
mod approval_policy_admin;
/// audit-10-10 Phase 6 items 6.1-6.3 — self-service record history and my-
/// activity read APIs over the audit ledger. `mod`, not `pub`: nothing else
/// in this crate reaches into it, same posture as `communication`/
/// `bulk_transform`'s route files.
mod audit_read;
/// M04 Phase 2 (LIC-F2) — the `--bootstrap-admin` flow's licence-gated
/// composition. `pub` because `crates/server`'s CLI (the only caller) lives in
/// a different crate.
pub mod bootstrap_admin;
/// M12 — in-place bulk field transform. `pub` only for `process`.
pub mod bulk_transform;
/// P-environment-promotion: the `attome-bundle/v1` engine (model, canonical
/// hash, export, plan). `pub` because the routes, the apply job, and
/// `crates/bundle-tool` consume its types.
pub mod bundle;
/// D-404 / M83 Phase 1: `/api/v1/admin/calendars*` CRUD + the
/// `reconcile_calendar`/`retire_calendar` service reconcile API `bundle`
/// calls. `pub` for that same reason `view_admin` is.
pub mod calendar_admin;
mod capability_probe;
/// M18 Data Catalog Phase 1 (D-466) — `/api/v1/catalog/entities*` +
/// the dashboard-lineage outbox sweep + usage rollup jobs. `pub` for the two
/// job handlers (`run_dashboard_lineage_sweep`, `run_usage_rollup`), which
/// `crates/server/src/jobs.rs` calls; the route handlers stay
/// module-private, same shape as `duplicates_admin`/`duplicates_match`.
pub mod catalog_admin;
/// M89 Change Intelligence, item 1 (see the module master plan) —
/// `/api/v1/admin/changes`. No other module needs to reach into this one,
/// same shape as `api_usage_admin`.
mod changes_admin;
/// Solution 7 Phase 1 (D-785) — the changeset service: open / list / show /
/// close / abandon / export under `/api/v1/admin/changesets`, the close-time
/// translation, the JCS checksum and the review summary. `pub` for the same
/// reason `bundle` is: the apply engine and `crates/server` consume it.
pub mod changeset;
// `kind = "chart"` view_metadata schema/validator. D-528 moved it to
// `attome-core` so the dashboard crate can share its types;
// `view_admin::validate_view_kind_metadata` keeps its crate-local path.
use attome_core::chart_view_metadata;
/// D-789 §6.1 — `/api/v1/admin/business-rules` (CRUD, validate, test,
/// publish). Replaces `/api/v1/admin/rules*` (D-790).
pub mod business_rule_admin;
/// D-789 §8 — the `business_rules` field-reference hook (rename, delete,
/// retype) registered in `field_hooks`.
pub mod business_rule_hooks;
/// M52 Phase 1 (D-465) — outbound compose/reply routes for `communication`
/// (email + internal channels, threading). `pub` because
/// `openapi_document` and `server`'s router composition need the module's
/// `router()`/`openapi()`.
pub mod communication;
/// M52 Phase 1 (D-465) — delivery-status timeline child entity
/// (`communication_event`). Seed-only, same shape as `communication_seed`.
mod content_public;
/// M12 (data management) — record export. `pub` only for `process`, which
/// `crates/server/src/jobs.rs`'s `EngineJob::DataExport` arm calls; the
/// route handlers stay module-private.
pub mod data_export;
/// M12 — the shared field-mapping model admin surface. `pub` for the same
/// reason as `data_export` — none of its handlers are called directly, but
/// keeping the module visibility consistent with its sibling M12 modules.
pub mod data_mapping_admin;
/// M12 — data profiling admin surface + job. `pub` only for `process`.
pub mod data_profile_admin;
/// D-432 / M13 (Master Data Management, scoped to dedup + survivorship
/// only) — `/api/v1/admin/data/match-rules`, `/survivorship-rules`,
/// `/duplicates*`. `pub` only for `ACTION_MDM_AUTO_MERGE`, which
/// `approval_admin::execute_approved` and `duplicates_match` both need;
/// handlers stay module-private.
pub mod duplicates_admin;
/// D-432 / M13 — the matching job (`EngineJob::DataMatchSweep`'s handler).
/// `pub` only for `run_match_sweep`, which `crates/server/src/jobs.rs`
/// calls; everything else stays module-private.
pub mod duplicates_match;
mod email_admin;
/// `pub` only for the two re-exports below (`read_record`,
/// `resolve_entity_public`), which `attome-ai` calls so a read action reuses
/// this crate's own authorization path instead of growing a second one. Every
/// other item in the module stays `pub(crate)`/`pub(super)`.
pub mod features_admin;
/// Solution 7 Phase 2 (D-788) — the structure-change executors (rename in
/// place, real delete with the recovery archive, in-place type conversion,
/// choice values) shared by the admin routes and the changeset applier.
pub mod field_changes;
/// Solution 7 Phase 2 (D-788) — the field reference-hook registry.
pub mod field_hooks;
/// M18 Data Catalog Phase 1 (D-466) — idempotent `glossary_term`
/// registration; see that module's doc.
mod jobs_admin;
mod license_admin;
/// M02/D-412 — `/api/v1/admin/settings` + `/api/v1/settings/me`. `pub` only
/// for `openapi_fragment` (mounted by `openapi.rs`) and `routes` (mounted by
/// `system.rs`); handlers stay module-private.
pub mod live;
/// M05 Phase 1 (D-426) — `/api/v1/admin/entities/{entity_id}/labels` CRUD.
/// `pub` only for `openapi_fragment` (mounted by `openapi.rs`) and `routes`
/// (mounted by `system.rs`); handlers stay module-private, same shape as
/// `settings_admin`.
pub mod metadata_label_admin;
pub mod metrics;
/// M17 (data migration, D-433) — `migration_project`/`migration_run`
/// admin CRUD + the rollback job. `pub` only for `process_rollback`, which
/// `crates/server/src/jobs.rs`'s `EngineJob::RollbackMigrationRun` arm
/// calls; the route handlers stay module-private, same shape as
/// `data_export`/`data_profile_admin`.
pub mod migration;
pub mod model_admin;
/// A1-T11 — `/api/v1/admin/model/health`.
pub mod model_health;
/// Dashboard 10/10 Phase 6 — `GET /api/v1/my-work/*` aggregation route over
/// every registered `MyWorkProvider`. `pub` only for `openapi_fragment`/
/// `routes`, same shape as `omnichannel_metrics` below.
pub mod my_work;
/// Dashboard 10/10 Phase 6 — the Approvals `MyWorkProvider`. `pub` so
/// `crates/server/src/boot.rs` can register it via
/// `EngineSystem::builder(...).register_my_work_provider(...)`.
pub mod my_work_approvals;
/// Dashboard 10/10 Phase 6 — the Decisions `MyWorkProvider` (`dashboard_decision`
/// rows still `proposed`). `pub` for the same reason `my_work_approvals` is.
pub mod my_work_decisions;
/// Dashboard 10/10 Phase 6 — the Project work `MyWorkProvider` (change
/// requests, timesheets and the caller's own work items). `pub` for the same
/// reason `my_work_approvals` is.
pub mod my_work_project;
/// Dashboard 10/10 Phase 6 — the Service work `MyWorkProvider`. `pub` for
/// the same reason `my_work_approvals` is.
pub mod my_work_service;
/// Dashboard 10/10 Phase 6 — the Workflow `MyWorkProvider` (approval-wait
/// case only — see the module's own doc comment for what's deliberately
/// out of scope). `pub` for the same reason `my_work_approvals` is.
pub mod my_work_workflow;
/// M53 Phase 1 (Omnichannel, web chat only, D-474) — `/api/v1/admin/omnichannel/
/// metrics` (per-channel volume/response-time/CSAT, M27). `pub` only for
/// `openapi_fragment`/`routes`, same shape as `metadata_label_admin`. The
/// public widget endpoint itself lives in `crates/server::omnichannel`, not
/// here — see that module's own doc comment for the dependency-cycle
/// reasoning this route does not share.
pub mod omnichannel_metrics;
mod openapi;
mod profiler_admin;
/// `profiler_finding` entity provisioning — see that file's own doc
/// comment (`document/module-feature-moat/PROFILER-2026-09-09.md` group G).
/// `pub` only for `seed`, called from `system.rs`'s `.build()`, same shape
/// as `sidebar_seed`.
/// M14 Phase 1 (Data Quality, D-468) — `/api/v1/admin/data/quality*`
/// (scores, trend, issues). `pub` only for `openapi_fragment` (mounted by
/// `openapi.rs`) and `routes` (mounted by `system.rs`); handlers stay
/// module-private, same shape as `duplicates_admin`.
pub mod quality_admin;
/// M14 Phase 1 (Data Quality) — the scoring sweep
/// (`EngineJob::DataQualityScoreSweep`'s handler). `pub` only for
/// `run_sweep`, which `crates/server/src/jobs.rs` calls; everything else
/// stays module-private, same shape as `duplicates_match`.
pub mod quality_score;
/// `pub` only for `execute_stored_query` and the wire types it names, which
/// `attome-ai`'s `query.execute` calls so a model-selected stored query runs
/// through this crate's own gate, scoping, pool, and timeout instead of a
/// second implementation. Everything else in the module stays private.
mod registry;
/// M01 Core P3 gap (D-455) — `/api/v1/admin/relationships*` CRUD for the
/// generic many-to-many relationship metadata object
/// (`relationship_info`). `pub` only for `openapi_fragment`
/// (mounted by `openapi.rs`) and `routes` (mounted by `system.rs`);
/// handlers stay module-private, same shape as `metadata_label_admin`.
pub mod relationship_admin;
/// D-602 (basic-units U4) — the recipient read check the notification
/// poller's reminder sweep runs (`EngineReminderAccess`). `pub` so the
/// reminder integration tests can drive the sweep with the real check.
pub mod reminder_access;
/// M45 (D-472), business rules (D-789, D-790, D-791) — the `rule`
/// store: wire types, validation, warnings, writes, `reconcile_rule`,
/// `retire_rule` and the export mapping. `pub` for the bundle/changeset
/// appliers' `reconcile_rule`/`retire_rule`/`export_defs`.
pub mod rule_admin;
/// M45 Phase 2 (D-472) — schema-building, field-security-on-authoring, the
/// compiled-rule cache, and rule evaluation shared by `rule_admin` (CRUD/
/// test/publish) and `entity_mutation` (the create/update retrofit). `pub`
/// so `entity_mutation.rs` (a sibling module in this crate) can call it;
/// nothing outside this crate depends on it.
mod schema;
mod seed_support;
mod service_public;
pub mod settings_admin;
/// `pub` for the service reconcile API (`reconcile_sidebar_item` & co.,
/// P-environment-promotion §5 step 13) — the handlers stay module-private.
pub mod sidebar;
mod sidebar_seed;
/// D-442 / M58 Phase 1 (Digital Signature, internal sign-off) —
/// `GET /api/v1/signoff/{decision_id}/verify`. Same visibility shape as
/// `approval_admin`: nothing outside this crate needs it, so the module
/// itself stays private — `routes`/`openapi_fragment` are reached via
/// `crate::signoff::…` from `system.rs`/`openapi.rs`.
mod signoff;
mod system;
mod system_health;
/// Core platform tagging (`tag_category`/`tag_item`) — see that
/// module's own doc comment. No `EngineModel`/licence gate, same posture as
/// `note_seed`/`follow_seed`.
mod tag_seed;
pub mod view_admin;
mod webcrawl_admin;

pub use approval_admin::{
    AutoExecution, KNOWN_ACTION_TYPES, PRODUCTION_MANDATORY_ACTIONS, execute_approved_request,
};
pub use bootstrap_admin::bootstrap_admin_gated;
pub use capability_probe::spawn_capability_refresh;
pub use metrics::{
    spawn_approval_expiry_sweep, spawn_chainer_lag_refresh, spawn_ingest_backlog_refresh,
    spawn_partition_bloat_refresh, spawn_s2s_telemetry_lag_refresh,
    spawn_upload_scan_backlog_refresh,
};
pub use openapi::openapi_document;
pub use registry::ModelRegistry;
pub use system::{EngineSystem, EngineSystemBuilder, apply_s2s_layer, load_license};

/// Advisory-lock namespace for every key taken under the `"attome-api/…"`
/// prefix (guidelines §2's `"{crate}/{operation}:{resource}"` convention) —
/// the S2S client-create and key-generate locks and the retention
/// action/purge locks.
///
/// Bound as the first argument of the two-argument
/// `pg_try_advisory_xact_lock($1, hashtext($2))` so a `hashtext` collision
/// between two unrelated keys can only happen *within* this subsystem, never
/// across subsystems (L-1 / TODO-027). The workspace-wide assignment table,
/// and the test that proves the ids stay distinct, live in
/// `crates/server/tests/advisory_lock_namespaces.rs`. Never reuse or renumber
/// an id.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 8;

// FILES_ADVISORY_LOCK_NAMESPACE moved to attome-records by D-477 (T3-2) —
// entity_mutation.rs's file-version lock and this crate's files.rs both bind
// it, and entity_mutation.rs moved. See attome_records::
// FILES_ADVISORY_LOCK_NAMESPACE's doc comment; same value (9), same key.
