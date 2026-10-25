//! T8-T1: a package is a bundle with a manifest saying who published it,
//! under which namespace, at which version, what it needs and how it is
//! installed, signed with the publisher's Ed25519 key.
//!
//! ```json
//! { "format": "attome-package/v1",
//!   "manifest": { "id": "com.example.fleet", "publisher": "Example Co",
//!                 "namespace": "exf", "version": "1.2.0",
//!                 "depends": [{ "id": "com.attome.sales", "version": ">=1.0.0" }],
//!                 "platform": ">=0.1.0", "contents": ["entities", "views"],
//!                 "mode": "managed" },
//!   "bundle": { … attome-bundle/v1 … },
//!   "signature": "<base64 Ed25519>" }
//! ```
//!
//! - [`check_manifest`] names every problem in a manifest at once.
//! - [`check_namespace`]: an entity the package adds, and an attribute it
//!   adds to an entity it does not own, starts with `<namespace>_`, so two
//!   publishers cannot collide; an entity the target already has is
//!   extended, not owned.
//! - [`signing_payload`] is the RFC 8785 canonical JSON of the format, the
//!   manifest and the bundle's content hash; [`sign`] signs it and
//!   [`verify`] checks it against the publisher's trusted key, so neither
//!   the manifest nor the bundle can change after signing.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::canonical::bundle_hash;
use super::model::Bundle;

/// The format of a package document.
pub const PACKAGE_FORMAT: &str = "attome-package/v1";

/// How a package is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageMode {
    /// Its objects are owned by the package: the target edits them only by
    /// installing a newer version.
    Managed,
    /// Its objects become the target's own after install.
    Unmanaged,
}

/// A package another package needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub id: String,
    /// A floor, `>=MAJOR.MINOR.PATCH`.
    pub version: String,
}

/// What a package says about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Reverse-DNS, such as `com.example.fleet`.
    pub id: String,
    pub publisher: String,
    /// The prefix the package's own entities and attributes carry.
    pub namespace: String,
    /// `MAJOR.MINOR.PATCH`.
    pub version: String,
    #[serde(default)]
    pub depends: Vec<Dependency>,
    /// The platform versions it runs on: `>=A.B.C`, optionally `,<X.Y.Z`.
    pub platform: String,
    /// The bundle components it carries, such as `entities` or `views`.
    #[serde(default)]
    pub contents: Vec<String>,
    pub mode: PackageMode,
}

/// A package document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Package {
    pub format: String,
    pub manifest: Manifest,
    pub bundle: Bundle,
    #[serde(default)]
    pub signature: Option<String>,
}

/// The components a manifest's `contents` may name.
pub const CONTENTS: [&str; 10] = [
    "entities",
    "queries",
    "views",
    "rules",
    "workflows",
    "apps",
    "roles",
    "sidebar",
    "calendars",
    "records",
];

fn semver(s: &str) -> Option<(u64, u64, u64)> {
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    parts.next().is_none().then_some((major, minor, patch))
}

fn floor(s: &str) -> Option<(u64, u64, u64)> {
    semver(s.trim().strip_prefix(">=")?.trim())
}

fn reverse_dns(id: &str) -> bool {
    let segments: Vec<&str> = id.split('.').collect();
    segments.len() >= 2
        && id.len() <= 200
        && segments.iter().all(|s| {
            !s.is_empty()
                && s.starts_with(|c: char| c.is_ascii_lowercase())
                && s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

/// Every problem in `manifest`; empty when it is valid. Pure.
pub fn check_manifest(manifest: &Manifest) -> Vec<String> {
    let mut problems = Vec::new();
    if !reverse_dns(&manifest.id) {
        problems.push("id is a reverse-DNS name such as com.example.fleet".to_owned());
    }
    let publisher = manifest.publisher.trim();
    if publisher.is_empty() || publisher.chars().count() > 100 {
        problems.push("publisher is a name of 1 to 100 characters".to_owned());
    }
    let ns = &manifest.namespace;
    if !(2..=12).contains(&ns.len())
        || !ns.starts_with(|c: char| c.is_ascii_lowercase())
        || !ns
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        problems.push(
            "namespace is 2 to 12 lowercase letters and digits, starting with a letter".to_owned(),
        );
    }
    if semver(&manifest.version).is_none() {
        problems.push("version is MAJOR.MINOR.PATCH".to_owned());
    }
    let platform_ok = match manifest.platform.split_once(',') {
        Some((low, high)) => {
            let high = high
                .trim()
                .strip_prefix('<')
                .map(str::trim)
                .and_then(semver);
            matches!((floor(low), high), (Some(l), Some(h)) if l < h)
        }
        None => floor(&manifest.platform).is_some(),
    };
    if !platform_ok {
        problems.push("platform is >=A.B.C, optionally followed by ,<X.Y.Z above it".to_owned());
    }
    let mut seen = std::collections::BTreeSet::new();
    for (i, d) in manifest.depends.iter().enumerate() {
        if !reverse_dns(&d.id) || floor(&d.version).is_none() {
            problems.push(format!(
                "depends[{i}] names a package id and a >=MAJOR.MINOR.PATCH floor"
            ));
        }
        if d.id == manifest.id {
            problems.push(format!("depends[{i}] is the package itself"));
        }
        if !seen.insert(&d.id) {
            problems.push(format!("depends[{i}] repeats {}", d.id));
        }
    }
    for item in &manifest.contents {
        if !CONTENTS.contains(&item.as_str()) {
            problems.push(format!(
                "contents names `{item}`; it is one of {}",
                CONTENTS.join(", ")
            ));
        }
    }
    problems
}

/// Every entity and attribute the package adds without its namespace
/// prefix. `existing` answers whether the target already has an entity by
/// that name (the package extends it; only the attributes it adds there
/// need the prefix). Pure.
pub fn check_namespace(
    manifest: &Manifest,
    bundle: &Bundle,
    existing: &dyn Fn(&str) -> bool,
) -> Vec<String> {
    let prefix = format!("{}_", manifest.namespace);
    let mut problems = Vec::new();
    for entity in &bundle.entities {
        if existing(&entity.logicalname) {
            for attr in &entity.attributes {
                if !attr.logicalname.starts_with(&prefix) {
                    problems.push(format!(
                        "{}.{} extends an entity the package does not own and must start with {prefix}",
                        entity.logicalname, attr.logicalname
                    ));
                }
            }
        } else if !entity.logicalname.starts_with(&prefix) {
            problems.push(format!(
                "entity {} must start with {prefix}",
                entity.logicalname
            ));
        }
    }
    problems
}

/// The bytes a package's signature covers: the canonical JSON of its
/// format, manifest and bundle hash.
pub fn signing_payload(
    format: &str,
    manifest: &Manifest,
    bundle: &Bundle,
) -> Result<Vec<u8>, String> {
    let manifest = serde_json::to_value(manifest).map_err(|e| e.to_string())?;
    let doc = json!({
        "format": format,
        "manifest": manifest,
        "bundle_sha256": bundle_hash(bundle),
    });
    attome_model::canonical::canonicalize(&doc).map(String::into_bytes)
}

/// Signs `package` with the publisher's key.
pub fn sign(package: &mut Package, key: &SigningKey) -> Result<(), String> {
    let payload = signing_payload(&package.format, &package.manifest, &package.bundle)?;
    let signature = key.sign(&payload);
    package.signature =
        Some(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()));
    Ok(())
}

/// Checks `package`'s format, manifest and signature against the trusted
/// key (base64) of its publisher, from `trusted` (`(publisher, key)` pairs).
pub fn verify(package: &Package, trusted: &[(String, String)]) -> Result<(), String> {
    if package.format != PACKAGE_FORMAT {
        return Err(format!("format is {PACKAGE_FORMAT}"));
    }
    let problems = check_manifest(&package.manifest);
    if !problems.is_empty() {
        return Err(problems.join("; "));
    }
    let key_b64 = trusted
        .iter()
        .find(|(publisher, _)| publisher == &package.manifest.publisher)
        .map(|(_, key)| key)
        .ok_or_else(|| format!("{} is not a trusted publisher", package.manifest.publisher))?;
    let engine = base64::engine::general_purpose::STANDARD;
    let key_bytes: [u8; 32] = engine
        .decode(key_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("the publisher's key is not a 32-byte base64 Ed25519 key")?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| "the publisher's key is not a valid Ed25519 key")?;
    let signature: [u8; 64] = package
        .signature
        .as_deref()
        .and_then(|s| engine.decode(s).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or("the package is not signed")?;
    let payload = signing_payload(&package.format, &package.manifest, &package.bundle)?;
    key.verify(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| "the signature does not match the package".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            id: "com.example.fleet".into(),
            publisher: "Example Co".into(),
            namespace: "exf".into(),
            version: "1.2.0".into(),
            depends: vec![Dependency {
                id: "com.attome.sales".into(),
                version: ">=1.0.0".into(),
            }],
            platform: ">=0.1.0".into(),
            contents: vec!["entities".into()],
            mode: PackageMode::Managed,
        }
    }

    fn bundle() -> Bundle {
        serde_json::from_value(json!({
            "format": "attome-bundle/v1",
            "requires": { "platform_version": ">=0.1.0", "schema_version": 1 },
            "entities": [
                { "logicalname": "exf_vehicle", "display_name": "Vehicle",
                  "attributes": [{ "logicalname": "plate", "display_name": "Plate", "field_type": "text" }] },
                { "logicalname": "account", "display_name": "Account",
                  "attributes": [{ "logicalname": "exf_fleet_size", "display_name": "Fleet", "field_type": "number" }] }
            ]
        }))
        .expect("bundle")
    }

    #[test]
    fn a_manifest_names_every_problem() {
        assert!(check_manifest(&manifest()).is_empty());
        let mut bad = manifest();
        bad.id = "fleet".into();
        bad.namespace = "X".into();
        bad.version = "1.2".into();
        bad.platform = ">=1.0.0,<0.9.0".into();
        bad.contents = vec!["secrets".into()];
        assert_eq!(check_manifest(&bad).len(), 5, "{:?}", check_manifest(&bad));
    }

    #[test]
    fn new_entities_and_added_attributes_carry_the_namespace() {
        let existing = |name: &str| name == "account";
        assert!(check_namespace(&manifest(), &bundle(), &existing).is_empty());
        let mut b = bundle();
        b.entities[0].logicalname = "vehicle".into();
        b.entities[1].attributes[0].logicalname = "fleet_size".into();
        assert_eq!(check_namespace(&manifest(), &b, &existing).len(), 2);
    }

    #[test]
    fn a_package_signs_and_verifies_and_tampering_fails() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let trusted = vec![(
            "Example Co".to_owned(),
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes()),
        )];
        let mut package = Package {
            format: PACKAGE_FORMAT.into(),
            manifest: manifest(),
            bundle: bundle(),
            signature: None,
        };
        assert!(verify(&package, &trusted).is_err(), "unsigned");
        sign(&mut package, &key).expect("sign");
        assert_eq!(verify(&package, &trusted), Ok(()));

        let mut bumped = package.clone();
        bumped.manifest.version = "1.3.0".into();
        assert!(verify(&bumped, &trusted).is_err(), "manifest changed");
        let mut edited = package.clone();
        edited.bundle.entities[0].display_name = "Truck".into();
        assert!(verify(&edited, &trusted).is_err(), "bundle changed");
        assert!(verify(&package, &[]).is_err(), "untrusted publisher");
    }
}
