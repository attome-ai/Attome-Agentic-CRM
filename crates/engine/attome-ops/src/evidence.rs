//! AB4-T2: the `attome-evidence/v1` record every drill writes (restore,
//! failover, chaos, upgrade, secrets, recovery, drain), and its Ed25519
//! signature, so an auditor can check that a report is the one the drill
//! produced and that nothing in it changed since.
//!
//! The signed bytes are the record's canonical JSON: the record serialized
//! to a `serde_json::Value` (whose maps are sorted) and written compactly.
//! The key id is the first 16 hex characters of the SHA-256 of the public
//! key. A file holds the [`SignedEvidence`] as pretty JSON; [`write_signed`]
//! answers the SHA-256 of the bytes it wrote, for the drill's ledger.
//!
//! v2 has no drill reports from before this format, so there is no reader
//! for an older shape.

use std::path::Path;

use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, Verifier};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::OpsError;

/// The format tag.
pub const SCHEMA: &str = "attome-evidence/v1";

/// What a drill exercised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Restore,
    Failover,
    Chaos,
    Upgrade,
    Secrets,
    Recovery,
    Drain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    Pass,
    Fail,
    Skipped,
}

/// One check a drill ran.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Check {
    pub name: String,
    pub result: CheckResult,
    #[serde(default)]
    pub detail: Option<String>,
}

/// One drill's evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Evidence {
    /// Always [`SCHEMA`].
    pub schema: String,
    pub kind: EvidenceKind,
    pub drill_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub platform_version: String,
    #[serde(default)]
    pub image_digest: Option<String>,
    #[serde(default)]
    pub deployment_id: Option<String>,
    pub checks: Vec<Check>,
    /// Data lost, measured: the recovery point.
    #[serde(default)]
    pub rpo_seconds: Option<f64>,
    /// Time to serve again, measured: the recovery time.
    #[serde(default)]
    pub rto_seconds: Option<f64>,
    #[serde(default)]
    pub data_size_bytes: Option<u64>,
    pub restore_ok: bool,
    pub provenance_ok: bool,
    pub overall_ok: bool,
    /// What a kind records beyond these fields.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub extra: Map<String, Value>,
}

impl Evidence {
    /// Sets `overall_ok`: no check failed or was skipped, and for a restore
    /// the restore and its provenance held too.
    pub fn compute_overall(&mut self) {
        let checks_ok = self.checks.iter().all(|c| c.result == CheckResult::Pass);
        self.overall_ok = match self.kind {
            EvidenceKind::Restore => checks_ok && self.restore_ok && self.provenance_ok,
            _ => checks_ok,
        };
    }

    /// The bytes the signature covers. Pure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OpsError> {
        let value = serde_json::to_value(self).map_err(|e| OpsError::Internal(e.to_string()))?;
        serde_json::to_vec(&value).map_err(|e| OpsError::Internal(e.to_string()))
    }
}

/// Evidence with its signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SignedEvidence {
    pub evidence: Evidence,
    /// The first 16 hex characters of the SHA-256 of the public key.
    pub key_id: String,
    /// Base64 Ed25519 signature of the evidence's canonical bytes.
    pub signature: String,
}

/// A public key's id. Pure.
pub fn key_id(key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
        .chars()
        .take(16)
        .collect()
}

/// Signs `evidence` with `key`.
pub fn sign(evidence: &Evidence, key: &SigningKey) -> Result<SignedEvidence, OpsError> {
    let signature = key.sign(&evidence.canonical_bytes()?);
    Ok(SignedEvidence {
        evidence: evidence.clone(),
        key_id: key_id(&key.verifying_key()),
        signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    })
}

/// Checks `signed` against the trusted key its key id names. A key id no
/// trusted key has, a malformed signature or any change since signing is
/// refused.
pub fn verify(signed: &SignedEvidence, trusted: &[VerifyingKey]) -> Result<(), OpsError> {
    let key = trusted
        .iter()
        .find(|k| key_id(k) == signed.key_id)
        .ok_or_else(|| OpsError::Validation("the evidence is signed by an untrusted key".into()))?;
    let signature: [u8; 64] = base64::engine::general_purpose::STANDARD
        .decode(&signed.signature)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| OpsError::Validation("the evidence signature is malformed".into()))?;
    key.verify(
        &signed.evidence.canonical_bytes()?,
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| OpsError::Validation("the evidence does not match its signature".into()))
}

/// A trusted key from its base64 form (`config.ops.drill_public_keys`).
pub fn verifying_key(base64_key: &str) -> Result<VerifyingKey, OpsError> {
    let bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(base64_key.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| OpsError::Validation("a drill public key is 32 bytes of base64".into()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| OpsError::Validation("a drill public key is not an Ed25519 key".into()))
}

/// Signs `evidence`, writes it to `path` as pretty JSON and answers the
/// lowercase hex SHA-256 of the bytes written.
pub fn write_signed(
    path: &Path,
    evidence: &Evidence,
    key: &SigningKey,
) -> Result<String, OpsError> {
    let signed = sign(evidence, key)?;
    let mut bytes =
        serde_json::to_vec_pretty(&signed).map_err(|e| OpsError::Internal(e.to_string()))?;
    bytes.push(b'\n');
    std::fs::write(path, &bytes).map_err(|e| OpsError::Internal(e.to_string()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// AB4-T3: a signing key file's contents: the 32-byte seed in base64, one
/// line. Pure.
pub fn encode_signing_key(key: &SigningKey) -> String {
    format!(
        "{}
",
        base64::engine::general_purpose::STANDARD.encode(key.to_bytes())
    )
}

/// The public half of `key` in the base64 form `config.ops.drill_public_keys`
/// and `--public-key` files take. Pure.
pub fn public_key_base64(key: &SigningKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes())
}

/// A signing key from a key file's contents ([`encode_signing_key`]). Pure.
pub fn decode_signing_key(text: &str) -> Result<SigningKey, OpsError> {
    let seed: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| OpsError::Validation("a drill signing key is 32 bytes of base64".into()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Reads the signing key file at `path`.
pub fn read_signing_key(path: &Path) -> Result<SigningKey, OpsError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| OpsError::Validation(format!("{}: {e}", path.display())))?;
    decode_signing_key(&text)
}

/// Reads a signed evidence file ([`write_signed`]).
pub fn read_signed(path: &Path) -> Result<SignedEvidence, OpsError> {
    let bytes = std::fs::read(path)
        .map_err(|e| OpsError::Validation(format!("{}: {e}", path.display())))?;
    serde_json::from_slice(&bytes).map_err(|e| {
        OpsError::Validation(format!("{} is not attome-evidence/v1: {e}", path.display()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(kind: EvidenceKind, results: &[CheckResult]) -> Evidence {
        let at = DateTime::parse_from_rfc3339("2026-10-25T10:00:00Z")
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or_default();
        let mut e = Evidence {
            schema: SCHEMA.into(),
            kind,
            drill_id: Uuid::nil(),
            started_at: at,
            finished_at: at,
            platform_version: "2.0.0".into(),
            image_digest: None,
            deployment_id: Some("riyadh-1".into()),
            checks: results
                .iter()
                .enumerate()
                .map(|(i, r)| Check {
                    name: format!("check-{i}"),
                    result: *r,
                    detail: None,
                })
                .collect(),
            rpo_seconds: Some(4.0),
            rto_seconds: Some(120.0),
            data_size_bytes: Some(1_000_000),
            restore_ok: true,
            provenance_ok: true,
            overall_ok: false,
            extra: Map::new(),
        };
        e.compute_overall();
        e
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    #[test]
    fn sign_then_verify_ok() {
        let e = evidence(EvidenceKind::Restore, &[CheckResult::Pass]);
        assert!(e.overall_ok);
        let signed = sign(&e, &key()).unwrap();
        assert_eq!(signed.key_id.len(), 16);
        assert!(verify(&signed, &[key().verifying_key()]).is_ok());
        let other = SigningKey::from_bytes(&[3u8; 32]).verifying_key();
        assert!(verify(&signed, &[other]).is_err(), "untrusted key");
        let public =
            base64::engine::general_purpose::STANDARD.encode(key().verifying_key().as_bytes());
        assert_eq!(verifying_key(&public).unwrap(), key().verifying_key());
    }

    #[test]
    fn tampered_field_fails_verify() {
        let e = evidence(EvidenceKind::Failover, &[CheckResult::Pass]);
        let mut signed = sign(&e, &key()).unwrap();
        signed.evidence.rto_seconds = Some(30.0);
        assert!(verify(&signed, &[key().verifying_key()]).is_err());
        let mut forged = sign(&e, &key()).unwrap();
        forged.signature = "not base64".into();
        assert!(verify(&forged, &[key().verifying_key()]).is_err());
    }

    #[test]
    fn skipped_check_makes_overall_false() {
        assert!(
            !evidence(
                EvidenceKind::Chaos,
                &[CheckResult::Pass, CheckResult::Skipped]
            )
            .overall_ok
        );
        assert!(!evidence(EvidenceKind::Upgrade, &[CheckResult::Fail]).overall_ok);
        let mut restore = evidence(EvidenceKind::Restore, &[CheckResult::Pass]);
        restore.provenance_ok = false;
        restore.compute_overall();
        assert!(!restore.overall_ok);
    }

    #[test]
    fn written_file_hash_matches_its_bytes() {
        let e = evidence(EvidenceKind::Secrets, &[CheckResult::Pass]);
        let path = std::env::temp_dir().join(format!("attome-evidence-{}.json", Uuid::now_v7()));
        let digest = write_signed(&path, &e, &key()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(digest, hex::encode(Sha256::digest(&bytes)));
        let back: SignedEvidence = serde_json::from_slice(&bytes).unwrap();
        assert!(verify(&back, &[key().verifying_key()]).is_ok());
    }
}
