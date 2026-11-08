//! AB3-T5 (V2-D1932): the ransomware-mode guard of `attome drill recover
//! --immutable-only --recovery-credential-file <file>`.
//!
//! A recovery that reads from the immutable (Object Lock) copy must use a
//! credential that someone holding the production credential could not have
//! used to alter that copy. So the credential is refused unless
//!
//! 1. its access key id differs from the production storage credential's, and
//! 2. a `DeleteObject` on a probe key under `drill-probe/` is denied by its
//!    bucket (a probe that succeeds means the credential can delete). The probe
//!    key names no real object, so nothing real is deleted.
//!
//! A probe that fails for any other reason (the bucket is unreachable, or an
//! Object Lock rejection that is not a permission error) is refused too, with
//! the reason: the credential is not shown to be read-only.
//!
//! The credential file is JSON:
//! `{"endpoint": "...", "region": "...", "bucket": "...", "access_key": "...",
//!   "secret_key": "...", "verify_ssl": true}`. No part of it is printed.

use std::path::Path;

use serde::Deserialize;
use uuid::Uuid;

/// The recovery credential file. No `Debug`: it holds a secret.
#[derive(Deserialize)]
pub struct RecoveryCredential {
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    #[serde(default = "yes")]
    pub verify_ssl: bool,
}

fn yes() -> bool {
    true
}

/// Parses the credential file. The error never carries the file's content. Pure.
pub fn parse_credential(bytes: &[u8]) -> Result<RecoveryCredential, String> {
    let credential: RecoveryCredential = serde_json::from_slice(bytes)
        .map_err(|_| "the credential file is not the expected JSON".to_owned())?;
    if credential.bucket.is_empty()
        || credential.access_key.is_empty()
        || credential.secret_key.is_empty()
    {
        return Err("the credential file needs bucket, access_key and secret_key".into());
    }
    Ok(credential)
}

/// Why a credential with this access key id may not stand in for the
/// production one. Pure.
pub fn isolation_refusal(recovery_access_key: &str, production_access_key: &str) -> Option<String> {
    (recovery_access_key == production_access_key).then(|| {
        "the recovery credential is the production storage credential; use a separate read-only one"
            .to_owned()
    })
}

/// What deleting the probe key did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// The delete was accepted: the credential can delete.
    CanDelete,
    /// The bucket refused it as a permission matter: the credential cannot.
    Denied,
    /// Anything else, with the store's reason.
    Unclear(String),
}

/// Why a probe outcome refuses the credential, if it does. Pure.
pub fn probe_refusal(probe: &Probe) -> Option<String> {
    match probe {
        Probe::Denied => None,
        Probe::CanDelete => {
            Some("the recovery credential can delete objects; use a read-only one".to_owned())
        }
        Probe::Unclear(why) => Some(format!(
            "the delete probe failed for a reason other than permissions, so the credential is not shown to be read-only: {why}"
        )),
    }
}

/// The probe key: under `drill-probe/`, never a real object's. Pure.
pub fn probe_key(id: Uuid) -> String {
    format!("drill-probe/{id}")
}

fn classify(result: &Result<(), attome_storage::StorageError>) -> Probe {
    match result {
        Ok(()) => Probe::CanDelete,
        Err(error) => {
            let text = error.to_string();
            let lower = text.to_ascii_lowercase();
            let permission = lower.contains("permission")
                || lower.contains("access denied")
                || lower.contains("accessdenied")
                || lower.contains("forbidden")
                || lower.contains("unauthenticated")
                || lower.contains("403");
            if permission {
                Probe::Denied
            } else {
                Probe::Unclear(text)
            }
        }
    }
}

/// Runs the guard: `Ok` when the credential is isolated, else the refusal.
pub async fn guard(
    credential_file: &Path,
    config: &attome_config::AppConfig,
) -> Result<(), String> {
    let bytes = tokio::fs::read(credential_file)
        .await
        .map_err(|e| format!("{}: {e}", credential_file.display()))?;
    let credential = parse_credential(&bytes)?;
    if let Some(why) = isolation_refusal(&credential.access_key, &config.storage.s3_access_key) {
        return Err(why);
    }
    let target = attome_config::S3Target {
        endpoint: &credential.endpoint,
        public_endpoint: "",
        region: &credential.region,
        bucket: &credential.bucket,
        access_key: &credential.access_key,
        secret_key: &credential.secret_key,
        verify_ssl: credential.verify_ssl,
    };
    let client = attome_storage::create_storage_client_for(target, "recovery_credential")
        .await
        .map_err(|e| format!("the recovery credential's bucket: {e}"))?;
    let outcome = attome_storage::mirror::delete_object(&client, &probe_key(Uuid::now_v7())).await;
    match probe_refusal(&classify(&outcome)) {
        None => Ok(()),
        Some(why) => Err(why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_access_key_is_refused() {
        assert!(isolation_refusal("AKIA1", "AKIA1").is_some());
        assert!(isolation_refusal("AKIA2", "AKIA1").is_none());
    }

    #[test]
    fn a_credential_that_can_delete_or_is_unclear_is_refused() {
        assert!(probe_refusal(&Probe::Denied).is_none());
        assert!(
            probe_refusal(&Probe::CanDelete)
                .unwrap()
                .contains("can delete")
        );
        assert!(
            probe_refusal(&Probe::Unclear("timeout".into()))
                .unwrap()
                .contains("timeout")
        );
    }

    #[test]
    fn probe_key_is_under_the_probe_prefix_and_the_file_is_checked() {
        assert!(probe_key(Uuid::now_v7()).starts_with("drill-probe/"));
        let ok = br#"{"bucket":"b","access_key":"a","secret_key":"s"}"#;
        let c = parse_credential(ok).unwrap();
        assert!(c.verify_ssl);
        assert!(parse_credential(br#"{"bucket":"","access_key":"a","secret_key":"s"}"#).is_err());
        let err = parse_credential(b"not json").err().unwrap();
        assert!(!err.contains("not json"));
    }
}
