//! The closed catalogue of registered [`FeatureFlag`]s (M95, D-430).
//!
//! Mirrors `setting_catalog.rs`'s `all()` — a hand-written `Vec`, not
//! distributed registration, so the set of valid flag keys is a code review,
//! not a runtime surprise. Add a new flag by adding it to `core_flags()` (or
//! a new `fn` grouped by owning concern, pushed into `all()` below) — never
//! by constructing a row directly, and never by inventing a key at write
//! time (`attome-server::features_admin` rejects anything `registry().get(key)`
//! can't find).
//!
//! Every flag added here needs a matching `SettingDescriptor` at
//! `"feature.{key}"` in `setting_catalog.rs`'s `feature_flag_settings()` —
//! `FeatureFlagRegistry::new()` asserts this at boot.

use attome_modules::{MODULE_CORE, MODULE_PROJECT};

use crate::feature_flag_descriptor::FeatureFlag;

pub(crate) fn all() -> Vec<FeatureFlag> {
    let mut all = core_flags();
    all.extend(scan_flags());
    all
}

/// B16-T9: scanning stays hidden until a deployment switches it on; acting
/// on a scan and continuous scanning each need scanning on too.
fn scan_flags() -> Vec<FeatureFlag> {
    vec![
        FeatureFlag::new(
            "scan.enabled",
            MODULE_CORE,
            "Scanning barcodes and QR codes into fields and to find records.",
            false,
            &[],
        ),
        FeatureFlag::new(
            "scan.actions_enabled",
            MODULE_CORE,
            "Running the action bound to a scanned code's pattern.",
            false,
            &["scan.enabled"],
        ),
        FeatureFlag::new(
            "scan.continuous_enabled",
            MODULE_CORE,
            "Continuous scanning: a running count of codes read one after another.",
            false,
            &["scan.enabled"],
        ),
    ]
}

fn core_flags() -> Vec<FeatureFlag> {
    vec![
        FeatureFlag::new(
            "core.beta_ui",
            MODULE_CORE,
            "Enables the in-progress beta admin UI shell for early testers. \
             Deployment-, role-, and user-scoped, with an optional \
             progressive-rollout percentage.",
            false,
            &[],
        ),
        FeatureFlag::new(
            "core.beta_ui_advanced_panels",
            MODULE_CORE,
            "Advanced panels within the beta UI shell — meaningless without \
             core.beta_ui also enabled, so it declares that as a \
             requirement: enabling this deployment-wide while core.beta_ui \
             is off is rejected at write time.",
            false,
            &["core.beta_ui"],
        ),
        // Deliberately gated on MODULE_PROJECT (a paid-tier module a
        // self-hosted deployment may not hold) rather than MODULE_CORE — the
        // one flag in this catalogue whose evaluation the license-invariant
        // test exercises directly: an admin turning this flag fully on can
        // never make it evaluate true for a deployment whose license doesn't
        // hold MODULE_PROJECT.
        FeatureFlag::new(
            "project.gantt_v2_preview",
            MODULE_PROJECT,
            "Early-access Gantt v2 rendering in the Project module.",
            false,
            &[],
        ),
    ]
}

#[cfg(test)]
mod tests {
    /// B16-T9: the scan flags exist and are off until switched on.
    #[test]
    fn scan_flags_registered_and_off_by_default() {
        let registry = crate::feature_flag_descriptor::registry();
        for key in [
            "scan.enabled",
            "scan.actions_enabled",
            "scan.continuous_enabled",
        ] {
            let flag = registry
                .get(key)
                .unwrap_or_else(|| panic!("{key} is registered"));
            assert!(!flag.default, "{key} is off by default");
        }
        assert_eq!(
            registry.get("scan.actions_enabled").map(|f| f.requires),
            Some(&["scan.enabled"][..])
        );
    }
}
