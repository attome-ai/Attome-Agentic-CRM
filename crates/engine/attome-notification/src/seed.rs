//! The admin-managed `notification_template` entity (F164 —
//! template-based, bilingual notifications).
//!
//! Delivery infrastructure (`notification_dispatch`) is NOT registered
//! here — it's a migration-owned infra table (D-005), not an admin-editable
//! entity; see `attome-website/crates/server/migrations/0030_notification_engine.sql`.
//!
//! **Test fixture only (D-478).** The metadata lives in
//! `platform-bundles/attome-notification.json`, which `EngineSystem::build()` applies at boot through
//! `attome_api::bundle::apply_platform_bundle`. This function walks the same
//! file with `attome_metadata::provision::seed_bundle_for_tests`, so a DB-backed
//! test below `attome-api` gets identical metadata from a bare `DbPool`
//! without a second, hand-maintained copy. Add a field in the bundle, never
//! here.

use attome_db::DbPool;
use attome_types::AppError;

const BUNDLE: &str = include_str!("../../../../platform-bundles/attome-notification.json");

/// See the module doc. Skipped when the `tests:attome-notification` stamp matches this bundle's
/// content and its declared state is still live
/// (`attome_metadata::provision::fixture_gate`).
pub async fn seed(db: &DbPool) -> Result<(), AppError> {
    attome_metadata::provision::run_bundle_fixture(db, "tests:attome-notification", BUNDLE, || {
        attome_metadata::provision::seed_bundle_for_tests(db, "attome-notification", BUNDLE)
    })
    .await
}
