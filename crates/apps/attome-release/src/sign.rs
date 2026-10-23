//! Signing the gate reports (roadmap AC4-T9, D-673).
//!
//! Before `attome release tag` tags a commit, each operating system's gate
//! report (`target/release-gate/gate-<os>.json`) is signed with the release
//! key, `cosign sign-blob --key $COSIGN_KEY`, into `gate-<os>.json.sig`, and
//! the signature is verified against the public key committed at
//! `deploy/cosign.pub`. A failure of either refuses the tag.
//!
//! Nothing goes to a transparency log (`--tlog-upload=false`), so signing
//! and verifying work offline, as D-673 item 5 requires (cosign 2.x).
//!
//! The private key never lives in the repository (D-673 item 2): a
//! `COSIGN_KEY` whose resolved path is inside the working tree is refused
//! before cosign runs. Without `deploy/cosign.pub` the tag is refused with a
//! pointer to `docs/release-signing.md`, which says how the key pair is made
//! and kept.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The public key every signature is verified against.
pub const PUBLIC_KEY: &str = "deploy/cosign.pub";
/// The environment variable naming the private key's path.
pub const KEY_ENV: &str = "COSIGN_KEY";

/// The private key's resolved path, refused when it is inside `repo` or
/// cannot be resolved.
pub fn key_path(key: &Path, repo: &Path) -> Result<PathBuf, String> {
    let key = key.canonicalize().map_err(|error| {
        format!(
            "{KEY_ENV} names {}, which cannot be read: {error}",
            key.display()
        )
    })?;
    let repo = repo.canonicalize().map_err(|error| {
        format!(
            "cannot resolve the repository at {}: {error}",
            repo.display()
        )
    })?;
    if key.starts_with(&repo) {
        return Err(format!(
            "{KEY_ENV} is inside the repository ({}); keep the release key outside the working tree (D-673)",
            key.display()
        ));
    }
    Ok(key)
}

/// The signature file beside `report`.
pub fn signature_path(report: &Path) -> PathBuf {
    let mut name = report.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

fn cosign(root: &Path, args: &[&str], what: &str) -> Result<(), String> {
    let status = Command::new("cosign")
        .args(args)
        .current_dir(root)
        .status()
        .map_err(|error| {
            format!("cannot run cosign ({error}); install it from https://docs.sigstore.dev/cosign/system_config/installation/")
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("cosign {what} exited with {status}"))
    }
}

/// Signs each report and verifies the signature; the first failure refuses.
pub fn sign_reports(root: &Path, reports: &[PathBuf]) -> Result<(), String> {
    let public = root.join(PUBLIC_KEY);
    if !public.is_file() {
        return Err(format!(
            "{PUBLIC_KEY} is missing: make the release key pair as docs/release-signing.md says, \
             keep the private key in custody and commit the public key"
        ));
    }
    let key = std::env::var_os(KEY_ENV)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            format!(
                "{KEY_ENV} is not set: name the release private key's path (outside the repository)"
            )
        })?;
    let key = key_path(Path::new(&key), root)?;
    let key = key.to_string_lossy().into_owned();
    let public = public.to_string_lossy().into_owned();
    for report in reports {
        let signature = signature_path(report);
        let report = report.to_string_lossy().into_owned();
        let signature = signature.to_string_lossy().into_owned();
        cosign(
            root,
            &[
                "sign-blob",
                "--yes",
                "--tlog-upload=false",
                "--key",
                &key,
                "--output-signature",
                &signature,
                &report,
            ],
            "sign-blob",
        )?;
        cosign(
            root,
            &[
                "verify-blob",
                "--insecure-ignore-tlog=true",
                "--key",
                &public,
                "--signature",
                &signature,
                &report,
            ],
            "verify-blob",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory under the system temp directory.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "attome-sign-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("create the scratch directory");
        dir
    }

    #[test]
    fn key_inside_repo_is_refused() {
        let repo = scratch("inside");
        std::fs::create_dir_all(repo.join("keys")).expect("keys dir");
        let key = repo.join("keys").join("cosign.key");
        std::fs::write(&key, "key").expect("write key");
        let error = key_path(&key, &repo).expect_err("a key in the repository is refused");
        assert!(error.contains("inside the repository"), "{error}");
        // Through a relative detour too.
        let detour = repo.join("keys").join("..").join("keys").join("cosign.key");
        assert!(key_path(&detour, &repo).is_err());
        std::fs::remove_dir_all(&repo).ok();
    }

    #[test]
    fn key_outside_repo_is_accepted() {
        let base = scratch("outside");
        let repo = base.join("repo");
        let vault = base.join("vault");
        std::fs::create_dir_all(&repo).expect("repo dir");
        std::fs::create_dir_all(&vault).expect("vault dir");
        let key = vault.join("cosign.key");
        std::fs::write(&key, "key").expect("write key");
        let resolved = key_path(&key, &repo).expect("a key outside the repository is accepted");
        assert!(resolved.ends_with("cosign.key"));
        assert_eq!(
            signature_path(Path::new("gate-windows.json")),
            PathBuf::from("gate-windows.json.sig")
        );
        std::fs::remove_dir_all(&base).ok();
    }
}
