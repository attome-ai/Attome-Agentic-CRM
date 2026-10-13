//! M41 Phase 1 (Process Intelligence, D-462) — event-log extraction from the
//! event log the platform already emits (`workflow_node_run`,
//! `audit_header`/`_detail`), directly-follows-graph discovery,
//! variant clustering, and cycle-time analysis.
//!
//! **Read-only by construction.** This engine never writes to a business
//! table — its own tables (`process_case_def`, `process_event`,
//! `process_dfg_snapshot`) are entirely derived and rebuildable from the
//! source event log (`document/decisions/data/D-462.md`).
//!
//! **Why this crate reads `attome-workflow`'s and `attome-audit`'s tables without
//! depending on either crate.** `workflow_node_run`/`workflow_
//! instance`/`workflow_definition_version` and `audit_header`/
//! `_detail` are migration-owned infrastructure tables (not runtime-
//! provisioned entities gated behind `EntityMetaRegistry`), so reading them
//! by table name via plain SQL needs no metadata lookup and no dependency on
//! the crate that happens to own the table today — the same "infra table,
//! not runtime-provisioned entity" reasoning `attome-state` already applies to
//! its own `state_model`/`state_transition`. This keeps
//! `attome-process` at the same layer as `attome-state`: no dependency on
//! `attome-workflow` (which itself depends on `attome-api`) or on `attome-api`,
//! so `attome-api` is free to depend on `attome-process` for OpenAPI merging
//! and route composition the same way it already depends on `attome-state`.
//!
//! **What Phase 1 explicitly defers** (module plan §6 Phase 2/3, mounted as
//! honest 501 stubs by [`stubs`] so the route surface and OpenAPI contract
//! are stable now): bottleneck/rework/waste finders, conformance-checking
//! replay against `workflow_definition_version`, and findings→decisions
//! (M28) integration.

pub mod case_def_admin;
pub mod discovery;
pub mod extraction;
pub mod model;
pub mod stubs;

use attome_core::EngineState;
use attome_modules::ModuleId;
use axum::Router;

/// Advisory-lock namespace for every key taken under the `"attome-process/…"`
/// prefix (guidelines §2's `"{crate}/{operation}:{resource}"` convention) —
/// `case_def_admin.rs`'s admin writes and `extraction.rs`'s per-case-def
/// extraction lock. Bound as the first argument of the two-argument
/// `pg_try_advisory_xact_lock($1, hashtext($2))`. The workspace-wide
/// assignment table, and the test that proves the ids stay distinct, live in
/// `crates/server/tests/advisory_lock_namespaces.rs`. Never reuse or
/// renumber an id.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 20;

#[derive(Debug)]
pub struct ProcessModel;

impl attome_core::EngineModel for ProcessModel {
    fn name(&self) -> &'static str {
        "process"
    }

    fn module_id(&self) -> ModuleId {
        attome_modules::MODULE_PROCESS
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
            .merge(case_def_admin::routes())
            .merge(discovery::routes())
            .merge(stubs::routes())
    }

    // Deliberately `&[]` (the default): `process_case_def`/
    // `process_event`/`process_dfg_snapshot` are migration-owned
    // infrastructure tables (0296/0297/0298), not runtime-provisioned
    // entities — there is no `entity_info` row for any of them, so
    // D-383's owned-entities licence gate has nothing to claim here. Same
    // posture as `attome_state::StateModel`.
}

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document, merged in by `attome_api::openapi_document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = case_def_admin::openapi_fragment();
    doc.merge(discovery::openapi_fragment());
    doc.merge(stubs::openapi_fragment());
    doc
}
