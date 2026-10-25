//! Governance, Risk & Compliance (M20, owns M21 Risk and M22 Policy) —
//! regulations, requirements, controls and their mapping, assessments,
//! findings, evidence, an enterprise risk register, and policies governed
//! as objects over `attome-content` pages. See
//! `document/module-master-plans/M20-grc.md` for the target design and
//! `document/decisions/product/D-427.md` for the one-graph decision this
//! crate implements.
//!
//! **Phase 1 (this crate, today): the model.** Every `grc_*` entity gets
//! generic entity CRUD for free once `seed::seed` registers it; `lifecycle`
//! adds the two bespoke routes the checklist names
//! (`/grc/assessments/{id}/start`, `/grc/findings/{id}/remediate`) as thin
//! status transitions, not a full state-model wiring — this module uses an
//! interim `status` Choice attribute on each lifecycle-bearing entity rather
//! than M07 state models, deliberately (see `model.rs`'s doc comment).
//!
//! **Explicitly deferred to Phase 2/3** (M20-grc.md §5): assessment/finding
//! lifecycle automation beyond the two thin transitions here, the
//! technical-control evidence-collection job, M27 score metrics, M51 review
//! reminders, the acknowledgement-expiry sweep, and `policy_rule` (blocked on
//! M45 Phase 2/3, which has not shipped).
pub mod auth;
/// R11-T1: evidence collectors writing evidence and findings.
pub mod collectors;
pub mod lifecycle;
pub mod mapping;
pub mod model;
/// R9-T1: policy reviews, attestation campaigns and exceptions.
pub mod policy;
pub mod reg_change;
pub mod risk;
pub mod seed;
/// R14-T1: vendor questionnaires, answers, scores and assessment cadence.
pub mod tprm;

pub use model::GrcModel;

/// D-351 — this crate's advisory-lock namespace (`"attome-grc/…"` keys),
/// registered in `crates/server/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 18;

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document. Merged in by `attome_api::openapi_document()` (this crate is a
/// direct dependency of `attome-api`, same reasoning `attome-project`'s own
/// `lib.rs` doc comment gives: `seed::seed` must run from inside
/// `EngineSystem::build()`, so this crate cannot live outside `attome-api`'s
/// dependency graph).
pub fn openapi() -> utoipa::openapi::OpenApi {
    lifecycle::openapi_fragment()
}
