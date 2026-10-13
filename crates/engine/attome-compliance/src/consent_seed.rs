//! Entity metadata for Consent Management (M24, D-428) —
//! `audit_consent_purpose` (the catalog of things a subject can be asked to
//! consent to) and `audit_consent` (the append-only ledger of grant/withdrawal
//! events).
//!
//! Registered as ordinary generic-CRUD entities, unlike
//! the rest of this crate's infrastructure-table pattern
//! (`dsr_admin`/`erasure_admin`/`retention_admin`/…, which are
//! migration-owned tables behind a bespoke admin surface): the target design
//! calls for `POST/GET/PATCH /api/v1/audit_consent[/…]` to work through the
//! platform's generic entity CRUD engine, so `/consents/withdraw` and the
//! public capture route (`consent_admin.rs`) only need to add the *workflow*
//! (append-only insert semantics, the anonymous entry point) on top of what
//! `entity_crud` already does for free. See this crate's own `lib.rs` doc
//! comment for why that makes consent a deliberate exception to "not an
//! EngineModel engine."
//!
//! `audit_consent` is registered `is_append_only = true`: a withdrawal is
//! always a NEW row (D-428), never an UPDATE of the row that recorded the
//! grant. The generic entity engine has no PATCH/DELETE path onto an
//! append-only table (`entity_crud`/`provision/table.rs`'s `is_active`
//! phase is skipped for it, same as `project_baseline`), so that
//! invariant is enforced structurally by the table's own registration, not
//! merely by every caller's good behavior.
//!
//! `regarding_entity`/`regarding_id` are the polymorphic "who this consent
//! is about" reference, stored as plain `text` rather than a `lookup` —
//! exactly `note`'s `entity_name`/`record_id` convention (see that
//! module's own doc comment): a `lookup` field needs one fixed target
//! entity, and a consent's subject can be any contact-like entity. Both are
//! optional because a public capture submission (`consent_admin::capture`)
//! may have no live CRM record to point at yet — only the raw
//! `subject_reference` below, mirroring `dsr_request`'s own
//! `subject_reference` shape (an email address, typically) so a consent
//! event can always be correlated to a DSR request by the same key.
//!
//! **Test fixture only (D-478).** The metadata lives in
//! `platform-bundles/attome-compliance-consent.json`, which `EngineSystem::build()` applies at boot through
//! `attome_api::bundle::apply_platform_bundle`. This function walks the same
//! file with `attome_metadata::provision::seed_bundle_for_tests`, so a DB-backed
//! test below `attome-api` gets identical metadata from a bare `DbPool`
//! without a second, hand-maintained copy. Add a field in the bundle, never
//! here.

use attome_db::DbPool;
use attome_types::AppError;

const BUNDLE: &str = include_str!("../../../../platform-bundles/attome-compliance-consent.json");

/// See the module doc. Skipped when the `tests:attome-compliance-consent` stamp matches this bundle's
/// content and its declared state is still live
/// (`attome_metadata::provision::fixture_gate`).
pub async fn seed(db: &DbPool) -> Result<(), AppError> {
    attome_metadata::provision::run_bundle_fixture(
        db,
        "tests:attome-compliance-consent",
        BUNDLE,
        || {
            attome_metadata::provision::seed_bundle_for_tests(
                db,
                "attome-compliance-consent",
                BUNDLE,
            )
        },
    )
    .await
}
