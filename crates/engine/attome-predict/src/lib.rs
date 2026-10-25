//! M36 Phase 0+1 (Predictive Intelligence, D-473) — SLA-breach prediction:
//! training a per-entity classifier from labeled ticket history, scoring
//! open tickets on a schedule, and recording each prediction's eventual
//! accuracy into M97's outcome ledger (`outcome`).
//!
//! `prediction_model`/`prediction` (migrations `0420`/`0421`) are
//! migration-owned infrastructure tables, not runtime-provisioned entities
//! (see 0420's own header for why: their JSONB-shaped columns can't be
//! expressed by the provisioned-entity FieldType set) — so, like
//! `attome-state`/`attome-process`, this crate has no `seed()` and needs no
//! pre-`.build()` ordering in `boot.rs`, just `.register(PredictModel)`.
//!
//! Zero dependency on `attome-service` or `attome-ai`, by construction:
//! `attome-service::sla`'s policy-resolution helpers are `pub(crate)` (only
//! `apply_policy`/the two pure business-hours functions are public), and the
//! established cross-engine pattern for reaching a table you don't own the
//! seed of is bound SQL against the table by name, not a Cargo dependency
//! (`attome_ai::outcome`'s own module doc names this precedent for a future
//! `attome-dashboard` producer; this crate is the second). `features.rs` reads
//! `service_ticket`/`service_sla_policy` directly; `score.rs` writes
//! `outcome` directly.
//!
//! Module layout:
//! - [`model`] — shared row/wire types (`FeatureDescriptor`, `ModelArtifact`,
//!   `PredictionModelRow`).
//! - [`features`] — ticket feature extraction, identical code path for
//!   training and scoring (train/serve consistency).
//! - [`train`] — the training job: builds the labeled set, fits a
//!   `smartcore::LogisticRegression` in `spawn_blocking`, holds out, and only
//!   activates a model that beats a majority-class baseline.
//! - [`score`] — the scoring sweep (new open tickets) and the outcome-fill
//!   sweep (predictions whose horizon has passed).
//! - [`admin`] — `/api/v1/admin/predict/models*`.
//! - [`predictions`] — `GET /api/v1/predictions`.

pub mod admin;
pub mod causal;
pub mod features;
pub mod model;
/// O1-T1: generic model definitions compiled through the secured compiler.
pub mod model_def;
pub mod predictions;
pub mod score;
pub mod train;

use attome_core::{EngineModel, EngineState};
use attome_modules::ModuleId;
use axum::Router;

/// Advisory-lock namespace for every key taken under the `"attome-predict/…"`
/// prefix (guidelines §2's `"{crate}/{operation}:{resource}"` convention) —
/// `train.rs`'s per-model training-run lock and `admin.rs`'s
/// create/train/retire writes. Bound as the first argument of the
/// two-argument `pg_try_advisory_xact_lock($1, hashtext($2))`. The
/// workspace-wide assignment table, and the test that proves the ids stay
/// distinct, live in `crates/server/tests/advisory_lock_namespaces.rs`.
/// Never reuse or renumber this id.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 21;

/// Phase 1's one supported target — `prediction_model.target`, checked
/// at model-create time. `0420`'s CHECK constraint already accepts
/// `capacity_shortfall`/`anomaly`/`custom_metric:<ref>` for Phase 2/3, but
/// this crate's own training/scoring code only implements this one target
/// against this one entity so far.
pub const TARGET_SLA_BREACH: &str = "sla_breach";
pub const ENTITY_TICKET: &str = "service_ticket";

#[derive(Debug)]
pub struct PredictModel;

impl EngineModel for PredictModel {
    fn name(&self) -> &'static str {
        "predict"
    }

    fn module_id(&self) -> ModuleId {
        attome_modules::MODULE_PREDICT
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
            .merge(admin::routes())
            .merge(predictions::routes())
    }

    // Deliberately `&[]` (the default): `prediction_model`/
    // `prediction` are migration-owned infrastructure tables, not
    // provisioned entities — there is no `entity_info` row for
    // either, so D-383's owned-entities licence gate has nothing to claim
    // here. `service_ticket` (the entity these predictions are *about*) keeps
    // whatever module already owns it (`MODULE_SERVICE`); this crate only
    // adds a read on it, not a new owner.
}

/// P-api-contract Phase 1 — merged into `server::openapi::document` via
/// `crates/server/src/openapi.rs`, same shape as `attome_process::openapi()`/
/// `attome_docgen::openapi()` (both real dependencies of `crates/server`, not
/// mounted from inside `attome-api`, for the same "this crate has no
/// dependency on attome-api" reason).
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = admin::openapi_fragment();
    doc.merge(predictions::openapi_fragment());
    doc
}
