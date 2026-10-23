//! Data-protection and governance surface of the XRM platform — the
//! `system.admin` route bundles and job entry points for retention, data
//! subject requests (DSR), legal hold, crypto-shredding erasure, and
//! encryption-key rewrap.
//!
//! Extracted from `attome-api` under ARCH-5 (PLATFORM-REVIEW-2026-08-24),
//! where these lived as six loose top-level modules. This is a pure code
//! move: every route path, wire type, advisory-lock key and audit event is
//! byte-identical to what `attome-api` served before, and nothing here is
//! licence-gated that was not gated before (none of it was — adding a
//! `ModuleId` during an extraction would be inventing pricing policy inside
//! a refactor; if compliance is to become a licensed engine, that is a
//! product decision with its own entry).
//!
//! What stays in `attome-api`, deliberately: the four-eyes *dispatch*
//! (`approval_admin::execute_approved`, `KNOWN_ACTION_TYPES`,
//! `PRODUCTION_MANDATORY_ACTIONS`). It has to name every gated flow's `do_*`
//! across every engine crate, which only the composition layer can. The
//! *gate* those flows call at the top of their handlers is
//! `attome_audit::approval::gate`, moved down the stack in the same change so
//! this crate (and `attome-security`) can reach it without a reverse edge.
//!
//! Its `EngineModel` (`model::ComplianceModel`, `MODULE_AUDIT`) exists only to
//! licence-gate the provisioned entities it owns on the generic CRUD path
//! (D-383); its `routes()` is empty and it mounts no sidebar — the admin
//! bundles are mounted directly in `attome-api/src/system.rs`. Most of the
//! tables it reads and writes (`retention_policy`,
//! `dsr_request`, `legal_hold`, `core_erasure_key`, …) are
//! migration-owned infrastructure tables, same as before the move.
//!
//! **One deliberate exception (M24, D-428):** `consent_seed`/`consent_admin`
//! register `audit_consent_purpose`/`audit_consent` as ordinary generic-CRUD
//! entities via `attome_metadata::provision` (the same "self-register at boot"
//! shape `attome-project`/`attome-webcrawl`/… use), so `/api/v1/audit_consent[/…]`
//! works through the platform's generic entity engine rather than a bespoke
//! admin surface like this crate's other six modules. `consent_admin.rs`
//! only adds the two things the generic engine can't express: an explicit
//! withdrawal endpoint (append-only — D-428) and a public capture route.

pub mod archive;
pub mod archive_admin;
/// Z1-T7 — node starts and their configuration fingerprints.
pub mod config_admin;
pub mod config_starts;
pub mod consent;
pub mod consent_admin;
pub mod consent_seed;
pub mod double_opt_in;
pub mod dsr_admin;
/// R1-T1: restriction and rectification requests.
pub mod dsr_restriction;
pub mod erasure_admin;
pub mod erasure_replay;
pub mod governance_admin;
/// L3-T2: governance roles, policies, exceptions and certifications.
pub mod governance_policy;
pub mod legal_hold_admin;
pub mod legal_matter_admin;
pub mod model;
/// E26-T1: the public preference page behind a signed link.
pub mod preference_centre;
pub mod retention;
pub mod retention_admin;
/// R3-T1: retention rules per entity and their disposition proposals.
pub mod retention_rules;
pub mod rewrap_admin;
/// Z1-T8 — the secret inventory: names, key ids and ages, never values.
pub mod secret_inventory;

/// M23 Records Management (D-456) — this crate's own advisory-lock namespace
/// (registry id 19, `crates/server/tests/advisory_lock_namespaces.rs`), for
/// every `"attome-compliance/…"` key: `"attome-compliance/archive-restore:{id}"`
/// (`archive::restore_archived_record`),
/// `"attome-compliance/legal-matter:{matter_id}"`
/// (`legal_matter_admin::collect`/`release`), `"attome-compliance/retention:{id}"`
/// (`retention_admin`) and `"attome-compliance/retention-purge:{record_id}"`
/// (`retention`).
pub const ADVISORY_LOCK_NAMESPACE: i32 = 19;
