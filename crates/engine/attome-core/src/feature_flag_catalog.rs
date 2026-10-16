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

use attome_modules::{MODULE_CONTENT, MODULE_CORE, MODULE_MARKETING, MODULE_PROJECT, MODULE_SALES};

use crate::feature_flag_descriptor::FeatureFlag;

pub(crate) fn all() -> Vec<FeatureFlag> {
    let mut all = core_flags();
    all.extend(scan_flags());
    all.extend(e13_flags());
    all.extend(e14_flags());
    all.extend(d6_flags());
    all
}

/// D6-T13: opportunity lines and what builds on them stay off until
/// switched on; a deployment without them keeps the typed amount.
fn d6_flags() -> Vec<FeatureFlag> {
    vec![
        FeatureFlag::new(
            "sales.opportunity_lines",
            MODULE_SALES,
            "Product lines on opportunities, priced and totalled; off keeps the typed amount.",
            false,
            &[],
        ),
        FeatureFlag::new(
            "sales.recurring_lines",
            MODULE_SALES,
            "Recurring values on opportunity lines (per period over a term).",
            false,
            &["sales.opportunity_lines"],
        ),
        FeatureFlag::new(
            "sales.schedules",
            MODULE_SALES,
            "Revenue and quantity schedules on opportunity lines.",
            false,
            &["sales.opportunity_lines"],
        ),
        FeatureFlag::new(
            "sales.quote_sync",
            MODULE_SALES,
            "Sync between an opportunity's lines and its primary quote.",
            false,
            &["sales.opportunity_lines"],
        ),
        FeatureFlag::new(
            "sales.product_suggestions",
            MODULE_SALES,
            "Agent-drafted product suggestions for an opportunity.",
            false,
            &["sales.opportunity_lines"],
        ),
    ]
}

/// E14-T1: website tracking, off until switched on; every part of it needs
/// tracking itself on.
fn e14_flags() -> Vec<FeatureFlag> {
    vec![
        FeatureFlag::new(
            "marketing.tracking",
            MODULE_MARKETING,
            "Track visits to Attome-served pages, anonymously until a visitor is known.",
            false,
            &[],
        ),
        FeatureFlag::new(
            "marketing.tracking_external_sites",
            MODULE_MARKETING,
            "Track the customer's own websites through a tracking script.",
            false,
            &["marketing.tracking"],
        ),
        FeatureFlag::new(
            "marketing.tracking_identify",
            MODULE_MARKETING,
            "Link a visitor to a contact when they fill a form or click a tracked email.",
            false,
            &["marketing.tracking"],
        ),
        FeatureFlag::new(
            "marketing.tracking_company",
            MODULE_MARKETING,
            "Identify a visitor's company from its network address.",
            false,
            &["marketing.tracking"],
        ),
        FeatureFlag::new(
            "marketing.tracking_custom_events",
            MODULE_MARKETING,
            "Record custom events sent from a tracked page.",
            false,
            &["marketing.tracking"],
        ),
        FeatureFlag::new(
            "marketing.tracking_alerts",
            MODULE_MARKETING,
            "Alert a contact's owner when a known visitor comes back.",
            false,
            &["marketing.tracking"],
        ),
    ]
}

/// E13-T2: the search-optimisation parts of content, off until switched on;
/// topic clusters build on the page audit.
fn e13_flags() -> Vec<FeatureFlag> {
    vec![
        FeatureFlag::new(
            "content.seo_audit",
            MODULE_CONTENT,
            "Page SEO audit on save and nightly, with page and site scores.",
            false,
            &[],
        ),
        FeatureFlag::new(
            "content.seo_clusters",
            MODULE_CONTENT,
            "SEO topics with pillar and cluster pages and link-gap checks.",
            false,
            &["content.seo_audit"],
        ),
        FeatureFlag::new(
            "content.search_console",
            MODULE_CONTENT,
            "Daily Google Search Console and Bing Webmaster data per page through the customer's own connection.",
            false,
            &[],
        ),
        FeatureFlag::new(
            "content.instant_indexing",
            MODULE_CONTENT,
            "IndexNow and sitemap pings on publish and removal.",
            false,
            &[],
        ),
        FeatureFlag::new(
            "content.seo_arabic_paths",
            MODULE_CONTENT,
            "Arabic url_path values for Arabic translations.",
            false,
            &[],
        ),
        FeatureFlag::new(
            "content.seo_agent",
            MODULE_CONTENT,
            "Agent drafting of search titles, descriptions and FAQ blocks.",
            false,
            &[],
        ),
    ]
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
    /// E13-T2: the SEO flags exist and are off until switched on.
    #[test]
    fn e13_flags_registered_and_off_by_default() {
        let registry = crate::feature_flag_descriptor::registry();
        for key in [
            "content.seo_audit",
            "content.seo_clusters",
            "content.search_console",
            "content.instant_indexing",
            "content.seo_arabic_paths",
            "content.seo_agent",
        ] {
            let flag = registry
                .get(key)
                .unwrap_or_else(|| panic!("{key} is registered"));
            assert!(!flag.default, "{key} is off by default");
        }
        assert_eq!(
            registry.get("content.seo_clusters").map(|f| f.requires),
            Some(&["content.seo_audit"][..])
        );
    }

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
