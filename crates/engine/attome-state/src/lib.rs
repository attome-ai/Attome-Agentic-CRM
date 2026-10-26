//! M07 Phase 1 (D-405/D-406) — the state-lifecycle engine.
//!
//! The enforcement primitives every entity write consults
//! (`check_initial_state`/`check_transition`/the `StateModelRegistry` cache)
//! live in `attome_core::state_registry`, not here — see that module's
//! doc comment for why. This crate is the licensed engine: admin CRUD for
//! `state_model`/`state_transition`
//! (`/api/v1/admin/state-models*`), the per-record routes that drive UI
//! buttons and enforce the identical check a raw field write goes through
//! (`/api/v1/{entity}/{id}/transitions`, `/api/v1/{entity}/{id}/transition`),
//! and the bundle-import primitive `reconcile::reconcile_state_model`
//! (`attome-api/src/bundle/apply.rs`).

pub mod admin;
pub mod approval;
/// M8-T3: transitions that happen by themselves.
pub mod auto_transitions;
pub mod model;
pub mod reconcile;
pub mod record_routes;
/// M8-T1: a transition's exit and entry actions, run after it commits.
pub mod transition_actions;

use attome_core::EngineState;
use attome_modules::ModuleId;
use axum::Router;

/// Advisory-lock namespace for every key taken under the `"attome-state/…"`
/// prefix (guidelines §2's `"{crate}/{operation}:{resource}"` convention) —
/// `admin.rs`'s model/transition writes and `reconcile.rs`'s bundle-apply
/// writes. Bound as the first argument of the two-argument
/// `pg_try_advisory_xact_lock($1, hashtext($2))`. The workspace-wide
/// assignment table, and the test that proves the ids stay distinct, live in
/// `crates/server/tests/advisory_lock_namespaces.rs`. Never reuse or
/// renumber an id.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 16;

#[derive(Debug)]
pub struct StateModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl attome_core::EngineModel for StateModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "state"
    }

    fn module_id(&self) -> ModuleId {
        attome_modules::MODULE_STATE
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
            .merge(admin::routes())
            .merge(record_routes::routes())
    }

    // Deliberately `&[]` (the default): `state_model`/
    // `state_transition` are migration-owned infrastructure tables
    // (D-406's Phase 1 migration), not runtime-provisioned entities — there
    // is no `entity_info` row for either, so D-383's
    // owned-entities licence gate has nothing to claim here. The governed
    // entities themselves (e.g. `service_ticket`) keep whatever module already
    // owns them; attome-state only adds a guard on their state field, not a new
    // owner.
}

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document, merged in by `attome_api::openapi_document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = admin::openapi_fragment();
    doc.merge(record_routes::openapi_fragment());
    doc
}
