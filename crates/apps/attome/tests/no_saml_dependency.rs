//! Q2-T6: SAML stays out (V2-D471). Single sign-on is OpenID Connect; no SAML
//! route is served and no SAML or XML-signature crate is in the build. A
//! change that brings either back fails here. No database needed.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root is three levels above crates/apps/attome")
        .to_path_buf()
}

/// Crates that would bring SAML or XML signature handling into the build.
const FORBIDDEN_CRATES: &[&str] = &["samael", "xmlsec", "libxml", "xml-sec", "saml2"];

#[test]
fn q2_no_saml_crates_in_lockfile() {
    let lock = std::fs::read_to_string(workspace_root().join("Cargo.lock")).expect("Cargo.lock");
    let found: Vec<&str> = FORBIDDEN_CRATES
        .iter()
        .copied()
        .filter(|name| lock.contains(&format!("name = \"{name}\"")))
        .collect();
    assert!(
        found.is_empty(),
        "SAML / XML-signature crates are not allowed (V2-D471): {found:?}"
    );
}

#[test]
fn q2_no_saml_routes_in_openapi() {
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(workspace_root().join("openapi.json")).expect("openapi.json"),
    )
    .expect("openapi.json parses");
    let saml: Vec<&String> = doc["paths"]
        .as_object()
        .expect("paths")
        .keys()
        .filter(|path| path.to_ascii_lowercase().contains("/saml"))
        .collect();
    assert!(
        saml.is_empty(),
        "no SAML route may be served (V2-D471): {saml:?}"
    );
}
