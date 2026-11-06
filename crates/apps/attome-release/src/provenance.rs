//! SLSA provenance for a release (roadmap AC7-T6), attested with the release
//! key.
//!
//! At `attome release tag`, after the files are signed (AC7-T5), the gate
//! writes `target/release-gate/provenance.json`, a SLSA v1 provenance
//! predicate: the builder (this machine's name and operating system), the
//! source (the tag and commit), the resolved dependencies (`Cargo.lock` and
//! `web/package-lock.json` by SHA-256) and the gate reports' SHA-256s. Each
//! signed file is then attested with it, `cosign attest-blob --type
//! slsaprovenance1` into `<file>.intoto.jsonl`, and each release binary also
//! with the Rust SBOM (`--type cyclonedx`). Nothing goes to a transparency
//! log, so verifying works offline (D-673 item 5).
//!
//! Adjusted from the task: v2 ships binaries and installers, not container
//! images (V2-D471), so the attestations are on the files, not on images.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

/// The predicate type of SLSA provenance v1.
pub const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
/// What kind of build this is, for a verifier's policy.
pub const BUILD_TYPE: &str = "https://attome.io/release-gate/v1";
/// The provenance file, in the gate directory.
pub const FILE: &str = "provenance.json";

/// The SLSA v1 provenance predicate. `materials` are `(path, sha256)` of the
/// lockfiles; `reports` of the gate reports. Pure.
pub fn predicate(
    builder_id: &str,
    tag: &str,
    commit: &str,
    materials: &[(String, String)],
    reports: &[(String, String)],
    finished_on: &str,
) -> Value {
    let digest = |list: &[(String, String)]| -> Vec<Value> {
        list.iter()
            .map(|(name, sha)| json!({ "name": name, "digest": { "sha256": sha } }))
            .collect()
    };
    json!({
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": { "source": { "tag": tag, "commit": commit } },
            "resolvedDependencies": digest(materials),
        },
        "runDetails": {
            "builder": { "id": builder_id },
            "metadata": { "invocationId": format!("{tag}@{commit}"), "finishedOn": finished_on },
            "byproducts": digest(reports),
        },
    })
}

/// This machine's builder id: its name and operating system.
pub fn builder_id() -> String {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".to_owned());
    format!("{host}/{}", std::env::consts::OS)
}

/// Writes the predicate for `tag` at `commit` into `gate_dir`; its path.
pub fn write(
    root: &Path,
    gate_dir: &Path,
    tag: &str,
    commit: &str,
    reports: &[PathBuf],
    finished_on: &str,
) -> Result<PathBuf, String> {
    let hash = |path: &Path| crate::repro::sha2_free::sha256_file(path);
    let mut materials = Vec::new();
    for rel in ["Cargo.lock", "web/package-lock.json"] {
        let path = root.join(rel);
        if path.is_file() {
            materials.push((rel.to_owned(), hash(&path)?));
        }
    }
    let mut hashed = Vec::new();
    for report in reports {
        let name = report
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        hashed.push((name, hash(report)?));
    }
    let doc = predicate(&builder_id(), tag, commit, &materials, &hashed, finished_on);
    let path = gate_dir.join(FILE);
    let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())? + "\n";
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// The attestation file beside `blob`.
pub fn attestation_path(blob: &Path, kind: &str) -> PathBuf {
    let mut name = blob.as_os_str().to_owned();
    name.push(format!(".{kind}.intoto.jsonl"));
    PathBuf::from(name)
}

fn attest(root: &Path, key: &str, predicate: &Path, kind: &str, blob: &Path) -> Result<(), String> {
    let (cosign_type, suffix) = match kind {
        "slsa" => ("slsaprovenance1", "slsa"),
        _ => ("cyclonedx", "sbom"),
    };
    let out = attestation_path(blob, suffix);
    let status = Command::new("cosign")
        .args([
            "attest-blob",
            "--yes",
            "--tlog-upload=false",
            "--key",
            key,
            "--type",
            cosign_type,
        ])
        .arg("--predicate")
        .arg(predicate)
        .arg("--output-attestation")
        .arg(&out)
        .arg(blob)
        .current_dir(root)
        .status()
        .map_err(|error| format!("cannot run cosign ({error})"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "cosign attest-blob ({cosign_type}) exited with {status} for {}",
            blob.display()
        ))
    }
}

/// Attests every blob with the provenance, and each binary also with the
/// Rust SBOM; the first failure refuses the tag.
pub fn attest_all(
    root: &Path,
    gate_dir: &Path,
    provenance: &Path,
    blobs: &[PathBuf],
) -> Result<(), String> {
    let key = std::env::var_os(crate::sign::KEY_ENV)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{} is not set", crate::sign::KEY_ENV))?;
    let key = crate::sign::key_path(Path::new(&key), root)?
        .to_string_lossy()
        .into_owned();
    let sbom = gate_dir.join("sbom-rust.cdx.json");
    for blob in blobs {
        attest(root, &key, provenance, "slsa", blob)?;
        let is_binary = blob.file_stem().is_some_and(|stem| stem == "attome")
            && blob.parent().is_some_and(|p| p.ends_with("release"));
        if is_binary && sbom.is_file() {
            attest(root, &key, &sbom, "sbom", blob)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicate_names_commit_and_gate_hash() {
        let p = predicate(
            "build-box/windows",
            "v2.1.0",
            "0d172a229abc",
            &[("Cargo.lock".into(), "aa".repeat(32))],
            &[("gate-windows.json".into(), "bb".repeat(32))],
            "2026-11-06T10:00:00Z",
        );
        assert_eq!(
            p["buildDefinition"]["externalParameters"]["source"]["commit"],
            "0d172a229abc"
        );
        assert_eq!(
            p["buildDefinition"]["externalParameters"]["source"]["tag"],
            "v2.1.0"
        );
        assert_eq!(p["runDetails"]["builder"]["id"], "build-box/windows");
        assert_eq!(
            p["runDetails"]["byproducts"][0]["name"],
            "gate-windows.json"
        );
        assert_eq!(
            p["runDetails"]["byproducts"][0]["digest"]["sha256"],
            "bb".repeat(32)
        );
        assert_eq!(
            p["buildDefinition"]["resolvedDependencies"][0]["digest"]["sha256"],
            "aa".repeat(32)
        );
    }

    #[test]
    fn attestations_sit_beside_their_file() {
        let p = attestation_path(Path::new("target/release/attome.exe"), "slsa");
        assert_eq!(
            p,
            PathBuf::from("target/release/attome.exe.slsa.intoto.jsonl")
        );
    }
}
