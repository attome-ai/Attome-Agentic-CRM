//! AB8-T1: the signed release manifest (`attome-release-manifest/v1`).
//!
//! Each release ships a manifest saying what an upgrade to it needs: the
//! versions it upgrades from, whether it pauses writes and for how long,
//! the features it removes and how to check for them, the contract SQL it
//! runs later and when, the digest of every artifact, and the impact per
//! module in English and Arabic. The release key signs it; the binary
//! carries the public keys it trusts (`attome::release_keys`, two slots for
//! rotation), so an upgrade refuses a manifest that is unsigned, altered or
//! signed by any other key.
//!
//! The signed bytes are the manifest's canonical JSON ([`canonical_json`],
//! the same form drill evidence is signed in); the key id is the first 16
//! hex characters of the SHA-256 of the public key
//! ([`crate::evidence::key_id`]). `schemas/attome-release-manifest-v1.schema.json`
//! describes the file.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};

use crate::error::OpsError;
use crate::evidence::{key_id, verifying_key};

/// The format tag.
pub const SCHEMA: &str = "attome-release-manifest/v1";

/// The canonical JSON of `value`: serialized to a `serde_json::Value`
/// (whose maps are sorted) and written compactly. What release manifests
/// and drill evidence are signed over. Pure.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, OpsError> {
    let value = serde_json::to_value(value).map_err(|e| OpsError::Internal(e.to_string()))?;
    serde_json::to_vec(&value).map_err(|e| OpsError::Internal(e.to_string()))
}

/// A feature the release removes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deprecated {
    pub feature: String,
    /// The version that removes it.
    pub removed_in: String,
    /// How an operator finds out whether they use it.
    pub how_to_check: String,
}

/// A contract (cleanup) SQL file the release runs once its period passes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractSql {
    pub file: String,
    /// Lowercase hex SHA-256 of the file.
    pub sha256: String,
    /// Days after the upgrade before it may run.
    pub eligible_after_days: u32,
}

/// A file the release ships.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub name: String,
    /// Lowercase hex SHA-256 of the file.
    pub sha256: String,
}

/// What the release changes for one module, in both languages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Impact {
    pub module: String,
    pub en: String,
    pub ar: String,
}

/// The release manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    /// Always [`SCHEMA`].
    pub schema: String,
    /// `MAJOR.MINOR.PATCH`.
    pub version: String,
    /// The oldest version this release upgrades from.
    pub min_from_version: String,
    /// How many minor versions one upgrade may skip.
    pub max_skip_minor: u32,
    /// Whether the upgrade pauses writes.
    pub requires_pause: bool,
    /// How long the pause is expected to last.
    #[serde(default)]
    pub pause_estimate_seconds: Option<u32>,
    #[serde(default)]
    pub deprecated: Vec<Deprecated>,
    #[serde(default)]
    pub contract_sql: Vec<ContractSql>,
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
    #[serde(default)]
    pub impact: Vec<Impact>,
}

/// A manifest with its signature, as the release ships it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReleaseManifest {
    pub manifest: ReleaseManifest,
    /// The first 16 hex characters of the SHA-256 of the signing key's
    /// public half.
    pub key_id: String,
    /// Base64 Ed25519 signature of the manifest's canonical JSON.
    pub signature: String,
}

fn semver(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.parse::<u64>().is_ok())
}

fn sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Every problem in `manifest`; empty when it is well formed. Pure.
pub fn check(manifest: &ReleaseManifest) -> Vec<String> {
    let mut problems = Vec::new();
    if manifest.schema != SCHEMA {
        problems.push(format!("schema is {SCHEMA}"));
    }
    for (field, value) in [
        ("version", &manifest.version),
        ("min_from_version", &manifest.min_from_version),
    ] {
        if !semver(value) {
            problems.push(format!("{field} is MAJOR.MINOR.PATCH"));
        }
    }
    if manifest.requires_pause && manifest.pause_estimate_seconds.is_none() {
        problems.push("a release that pauses writes says for how long".into());
    }
    for sql in &manifest.contract_sql {
        if !sha256_hex(&sql.sha256) {
            problems.push(format!(
                "contract_sql {}: sha256 is 64 lowercase hex",
                sql.file
            ));
        }
    }
    for artifact in &manifest.artifacts {
        if !sha256_hex(&artifact.sha256) {
            problems.push(format!(
                "artifact {}: sha256 is 64 lowercase hex",
                artifact.name
            ));
        }
    }
    for impact in &manifest.impact {
        if impact.en.trim().is_empty() || impact.ar.trim().is_empty() {
            problems.push(format!(
                "impact {}: needs English and Arabic",
                impact.module
            ));
        }
    }
    problems
}

/// Signs `manifest` with the release key.
pub fn sign(
    manifest: &ReleaseManifest,
    key: &SigningKey,
) -> Result<SignedReleaseManifest, OpsError> {
    let problems = check(manifest);
    if !problems.is_empty() {
        return Err(OpsError::Validation(problems.join("; ")));
    }
    let signature = key.sign(&canonical_json(manifest)?);
    Ok(SignedReleaseManifest {
        manifest: manifest.clone(),
        key_id: key_id(&key.verifying_key()),
        signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    })
}

/// Reads a signed manifest file and checks it against `keys` (base64
/// Ed25519 public keys, the binary's `RELEASE_PUBLIC_KEYS`). An unsigned,
/// malformed or altered manifest, or one signed by a key not listed, is
/// refused.
pub fn verify_manifest(bytes: &[u8], keys: &[&str]) -> Result<ReleaseManifest, OpsError> {
    let signed: SignedReleaseManifest = serde_json::from_slice(bytes)
        .map_err(|e| OpsError::Validation(format!("not a signed release manifest: {e}")))?;
    let key = keys
        .iter()
        .filter_map(|k| verifying_key(k).ok())
        .find(|k| key_id(k) == signed.key_id)
        .ok_or_else(|| {
            OpsError::Validation(
                "the release manifest is signed by a key this binary does not trust".into(),
            )
        })?;
    let signature: [u8; 64] = base64::engine::general_purpose::STANDARD
        .decode(&signed.signature)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            OpsError::Validation("the release manifest signature is malformed".into())
        })?;
    key.verify(
        &canonical_json(&signed.manifest)?,
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| {
        OpsError::Validation("the release manifest does not match its signature".into())
    })?;
    let problems = check(&signed.manifest);
    if !problems.is_empty() {
        return Err(OpsError::Validation(problems.join("; ")));
    }
    Ok(signed.manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::public_key_base64;

    fn manifest() -> ReleaseManifest {
        ReleaseManifest {
            schema: SCHEMA.into(),
            version: "2.3.0".into(),
            min_from_version: "2.1.0".into(),
            max_skip_minor: 2,
            requires_pause: true,
            pause_estimate_seconds: Some(45),
            deprecated: vec![Deprecated {
                feature: "legacy export".into(),
                removed_in: "2.4.0".into(),
                how_to_check: "GET /api/v1/admin/usage?feature=legacy_export".into(),
            }],
            contract_sql: vec![ContractSql {
                file: "contract/0001.sql".into(),
                sha256: "a".repeat(64),
                eligible_after_days: 7,
            }],
            artifacts: vec![Artifact {
                name: "attome-windows-x64.zip".into(),
                sha256: "b".repeat(64),
            }],
            impact: vec![Impact {
                module: "sales".into(),
                en: "Splits move to the deal team".into(),
                ar: "تنتقل التقسيمات إلى فريق الصفقة".into(),
            }],
        }
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn file(signed: &SignedReleaseManifest) -> Vec<u8> {
        serde_json::to_vec_pretty(signed).unwrap()
    }

    #[test]
    fn manifest_round_trip_verifies() {
        let signing = key(7);
        let public = public_key_base64(&signing);
        let signed = sign(&manifest(), &signing).unwrap();
        let other = public_key_base64(&key(9));
        // Either rotation slot may hold the key.
        let read = verify_manifest(&file(&signed), &[other.as_str(), public.as_str()]).unwrap();
        assert_eq!(read, manifest());
    }

    #[test]
    fn altered_manifest_is_refused() {
        let signing = key(7);
        let public = public_key_base64(&signing);
        let mut signed = sign(&manifest(), &signing).unwrap();
        signed.manifest.requires_pause = false;
        assert!(verify_manifest(&file(&signed), &[public.as_str()]).is_err());
        let unsigned = serde_json::to_vec(&manifest()).unwrap();
        assert!(verify_manifest(&unsigned, &[public.as_str()]).is_err());
    }

    #[test]
    fn unknown_key_is_refused() {
        let signed = sign(&manifest(), &key(7)).unwrap();
        let stranger = public_key_base64(&key(9));
        assert!(verify_manifest(&file(&signed), &[stranger.as_str()]).is_err());
        assert!(verify_manifest(&file(&signed), &[]).is_err());
    }

    #[test]
    fn a_malformed_manifest_names_its_problems() {
        let mut bad = manifest();
        bad.version = "2.3".into();
        bad.pause_estimate_seconds = None;
        bad.impact[0].ar = String::new();
        assert_eq!(check(&bad).len(), 3, "{:?}", check(&bad));
        assert!(sign(&bad, &key(7)).is_err());
    }
}
