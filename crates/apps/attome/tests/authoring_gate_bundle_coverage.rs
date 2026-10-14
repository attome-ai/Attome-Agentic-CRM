//! attome-server plan B4 (BSV-F02 / BSV-D2) — every metadata section a bundle
//! can carry is either gated on the production profile (its admin route
//! prefix is in `METADATA_AUTHORING_PREFIXES`) or a named exemption.
//!
//! A new `Bundle` section fails this test until someone decides which it is,
//! so production never again gains an ungated way to author bundle-applied
//! metadata by hand. No services needed:
//! `cargo test -p server --test authoring_gate_bundle_coverage`.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::bundle::model::Bundle;
use attome_server::middleware::authoring_gate::{
    METADATA_AUTHORING_PREFIXES, is_metadata_authoring_path,
};

/// Section → the admin prefix that authors it by hand.
const GATED: &[(&str, &str)] = &[
    ("entities", "/api/v1/admin/entities"),
    // A patch adds a field; fields are authored under the entity routes.
    ("attribute_patches", "/api/v1/admin/entities"),
    ("queries", "/api/v1/admin/queries"),
    ("views", "/api/v1/admin/views"),
    ("calendars", "/api/v1/admin/calendars"),
    ("sidebar", "/api/v1/sidebar/admin"),
    ("roles", "/api/v1/admin/security/roles"),
    (
        "field_security_profiles",
        "/api/v1/admin/security/field-profiles",
    ),
    ("state_models", "/api/v1/admin/state-models"),
    ("relationships", "/api/v1/admin/relationships"),
    ("apps", "/api/v1/admin/apps"),
    ("rules", "/api/v1/admin/business-rules"),
];

/// Sections deliberately left writable on production (BSV-D2): export-only
/// deployment state (`settings`, `labels`), the fixed privilege catalogue,
/// and reference data (`record_sets`), which flows through the record API.
const EXEMPT: &[&str] = &["settings", "labels", "privileges", "record_sets"];

fn bundle_sections() -> Vec<String> {
    let minimal = serde_json::json!({
        "format": "attome-bundle/v1",
        "requires": { "platform_version": ">=0.0.0", "schema_version": 0 }
    });
    let bundle: Bundle = serde_json::from_value(minimal).expect("a minimal bundle deserializes");
    let value = serde_json::to_value(&bundle).expect("a bundle serializes");
    let object = value.as_object().expect("a bundle serializes as an object");
    // Identity and `requires` are scalars/objects; every section is a list.
    object
        .iter()
        .filter(|(_, v)| v.is_array())
        .map(|(k, _)| k.clone())
        .collect()
}

#[test]
fn every_bundle_section_is_gated_or_a_named_exemption() {
    let sections = bundle_sections();
    assert!(!sections.is_empty(), "found no bundle sections at all");

    for section in &sections {
        let gated = GATED.iter().find(|(name, _)| name == section);
        let exempt = EXEMPT.contains(&section.as_str());
        assert!(
            gated.is_some() != exempt,
            "bundle section `{section}` must be in exactly one of GATED or EXEMPT"
        );
        if let Some((_, prefix)) = gated {
            assert!(
                METADATA_AUTHORING_PREFIXES.contains(prefix),
                "`{section}` maps to {prefix}, which is not in METADATA_AUTHORING_PREFIXES"
            );
            assert!(
                is_metadata_authoring_path(&format!("{prefix}/some-id")),
                "a write under {prefix} must be gated"
            );
        }
    }

    for (name, _) in GATED {
        assert!(
            sections.iter().any(|s| s == name),
            "GATED names `{name}`, which is no longer a bundle section"
        );
    }
    for name in EXEMPT {
        assert!(
            sections.iter().any(|s| s == name),
            "EXEMPT names `{name}`, which is no longer a bundle section"
        );
    }
}
