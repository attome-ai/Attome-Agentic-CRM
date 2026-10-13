//! Every `grc_*` entity is a browsable XRM entity (M20-grc.md's Phase 1
//! checklist), so Regulations/Requirements/Controls/Control Mapping/
//! Assessments/Assessment Items/Findings/Evidence/Risks/Risk Dependencies/
//! Policies/Policy Acks all render through the generic metadata-driven
//! list/form pages exactly like every other entity.
//!
//! **Risk generalization (M20-grc.md §5 Phase 1, D-427).** Rather than
//! duplicating `project_issue`'s project-scoped risk data, the bundle adds
//! one *additive* `risk_ref` lookup attribute onto that already-existing,
//! attome-project-owned entity, pointing at `grc_risk` (its
//! `attribute_patches` entry). A project-scoped
//! risk that also belongs on the enterprise register sets that lookup; the
//! project issue's own fields (probability/impact/mitigation/owner) are not
//! copied anywhere. This is why this crate takes no Cargo dependency on
//! attome-project: the patch resolves `project_issue` by logicalname.
//!
//! **Ordering.** `EngineSystem::build()` applies the bundle after
//! attome-project's, because `risk_ref` needs `project_issue` registered and
//! several entities carry an owner/user lookup to `user_account`. A
//! test calling [`seed`] must seed both of those first.
//!
//! **Policy `document_ref` is a plain `text` field, not a `lookup`.**
//! `content_page` is a migration-owned, admin-API-managed infrastructure
//! table (`0127_content_pages.sql`) with no `entity_info` row, so it
//! cannot be a generic-entity `lookup` target — the same reason
//! `service_sla_policy.calendar_ref` stores an `calendar.id` as `text`
//! rather than a `lookup` (`attome-service::sla`'s own module doc). `applies_to`
//! and `exceptions` are JSON-encoded strings for the same "structured but
//! scalar" reason `project_meeting.attendees` already uses.
//!
//! **Test fixture only (D-478).** The metadata lives in
//! `platform-bundles/attome-grc.json`, which `EngineSystem::build()` applies at boot through
//! `attome_api::bundle::apply_platform_bundle`. This function walks the same
//! file with `attome_metadata::provision::seed_bundle_for_tests`, so a DB-backed
//! test below `attome-api` gets identical metadata from a bare `DbPool`
//! without a second, hand-maintained copy. Add a field in the bundle, never
//! here.

use attome_db::DbPool;
use attome_types::AppError;

const BUNDLE: &str = include_str!("../../../../platform-bundles/attome-grc.json");

/// See the module doc. Skipped when the `tests:attome-grc` stamp matches this bundle's
/// content and its declared state is still live
/// (`attome_metadata::provision::fixture_gate`).
pub async fn seed(db: &DbPool) -> Result<(), AppError> {
    attome_metadata::provision::run_bundle_fixture(db, "tests:attome-grc", BUNDLE, || {
        attome_metadata::provision::seed_bundle_for_tests(db, "attome-grc", BUNDLE)
    })
    .await
}
