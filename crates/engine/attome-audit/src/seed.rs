//! The audit entities (`audit_header`/`_detail`/`_snapshot`/`_config`).
//!
//! **Test fixture only (D-478).** The metadata lives in
//! `platform-bundles/attome-audit.json`, which `crates/server/src/boot.rs` and `EngineSystem::build()` applies at boot through
//! `attome_server::bundle::apply_platform_bundle`. This function walks the same
//! file with `attome_metadata::provision::seed_bundle_for_tests`, so a DB-backed
//! test below `attome-server` gets identical metadata from a bare `DbPool`
//! without a second, hand-maintained copy. Add a field in the bundle, never
//! here.

use attome_db::DbPool;
use attome_types::AppError;

const BUNDLE: &str = include_str!("../seed/audit.json");

/// See the module doc. Skipped when the `tests:attome-audit` stamp matches this bundle's
/// content and its declared state is still live
/// (`attome_metadata::provision::fixture_gate`).
pub async fn seed(db: &DbPool) -> Result<(), AppError> {
    attome_metadata::provision::run_bundle_fixture(db, "tests:attome-audit", BUNDLE, || {
        attome_metadata::provision::seed_bundle_for_tests(db, "attome-audit", BUNDLE)
    })
    .await
}
