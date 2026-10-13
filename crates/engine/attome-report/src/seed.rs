//! Entity metadata for the Reporting Engine (M25 Phase 1, D-440):
//! `attome_report`/`report_schedule`. `report_run` is a migration-owned
//! infra table, not provisioned here (`0240_xrm_report_run.sql`).
//!
//! D-479 (M26 R-09) deleted this file's other seed, `seed()` (the legacy
//! `dashboard` entity); see this crate's `lib.rs` doc comment for where the
//! platform's one dashboard product lives now.
//!
//! **Test fixture only (D-478).** The metadata lives in
//! `platform-bundles/attome-report-reports.json`, which `crates/server/src/boot.rs` (after `.build()`) applies at boot through
//! `attome_api::bundle::apply_platform_bundle`. This function walks the same
//! file with `attome_metadata::provision::seed_bundle_for_tests`, so a DB-backed
//! test below `attome-api` gets identical metadata from a bare `DbPool`
//! without a second, hand-maintained copy. Add a field in the bundle, never
//! here.
//!
//! `owner`/`run_as` are lookups onto `user_account`, so that entity
//! must be live first (`attome_security::seed::seed_for_tests`).

use attome_db::DbPool;
use attome_types::AppError;

const BUNDLE: &str = include_str!("../../../../platform-bundles/attome-report-reports.json");

/// See the module doc. Skipped when the `tests:attome-report-reports` stamp matches this bundle's
/// content and its declared state is still live
/// (`attome_metadata::provision::fixture_gate`).
pub async fn seed_reports(db: &DbPool) -> Result<(), AppError> {
    attome_metadata::provision::run_bundle_fixture(
        db,
        "tests:attome-report-reports",
        BUNDLE,
        || attome_metadata::provision::seed_bundle_for_tests(db, "attome-report-reports", BUNDLE),
    )
    .await
}
