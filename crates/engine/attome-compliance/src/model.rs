//! `EngineModel` registration for the entities `attome-compliance` provisions
//! directly (`consent_seed`, `legal_matter_seed`) — added after ARCH-5's
//! "no entity metadata of its own" description of this crate (see the
//! module-level comment in `Cargo.toml`, now stale for exactly these three
//! entities). `routes()` is deliberately empty: every one of this crate's
//! HTTP surfaces (`retention_admin`, `dsr_admin`, `legal_hold_admin`,
//! `archive_admin`, `legal_matter_admin`, `governance_admin`,
//! `rewrap_admin`, `consent_admin`, `erasure_admin`) is already mounted
//! directly in `attome-api/src/system.rs`, each behind its own
//! `strict_authz` privilege check — this model's only job is closing the
//! generic-CRUD licence hole D-383 names: `audit_consent`/`audit_consent_purpose`
//! (M24, D-428) and `audit_legal_matter` (M23, D-456) are ordinary
//! provisioned entities reachable through `/api/v1/{entity}`, and until now
//! nothing declared them to `ModelRegistry` so that generic path carried no
//! licence check at all — reachable on any licence holding `MODULE_CORE`,
//! regardless of whether it holds `MODULE_AUDIT`.
//!
//! `MODULE_AUDIT` matches exactly what `attome-api/src/system.rs`'s
//! `license_gate(..., MODULE_AUDIT, "audit")` already enforces on
//! `attome_audit::admin::routes()` and M58's `signoff::routes()` — the generic and bespoke paths must never
//! disagree about whether a module is licensed (see `EngineModel::owned_entities`'s
//! own doc comment).
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_AUDIT, ModuleId};
use axum::Router;

#[derive(Debug)]
pub struct ComplianceModel;

impl EngineModel for ComplianceModel {
    fn name(&self) -> &'static str {
        "attome-compliance"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_AUDIT
    }

    /// D-383. Deliberately does NOT include any retention/DSR/erasure/legal-
    /// hold table: those are infra migration tables behind their own admin
    /// routes, never reachable through generic entity CRUD in the first
    /// place, so there is no hole for `owned_entities` to close there.
    fn owned_entities(&self) -> &'static [&'static str] {
        &[
            "audit_consent",
            "audit_consent_purpose",
            "audit_legal_matter",
        ]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
    }
}
