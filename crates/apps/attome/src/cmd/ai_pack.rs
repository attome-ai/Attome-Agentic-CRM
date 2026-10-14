//! AI model packs for `attome init --ai <profile>` (roadmap N26-T2).
//!
//! The pack manifest (`deploy/model-servers/ai-packs.json`, compiled in)
//! lists profiles of local models: each model's id, role, server address,
//! licence, the tasks it was tested on with their scores, and its weight
//! files with SHA-256 and size. A profile is installable only once it is
//! `approved`, which requires every file's checksum and size: a pack nobody
//! has tested is listed and refused.
//!
//! Weights are never downloaded by `init`. They come from an offline bundle
//! directory (`--ai-dir`, default the `--from-bundle` directory), where every
//! file is checked against the manifest before the configuration names the
//! models; a missing file or a wrong checksum refuses the install. The model
//! servers themselves start from `deploy/model-servers/docker-compose.yml`
//! with the profile's compose profiles.

use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The compiled-in manifest.
pub const MANIFEST: &str = include_str!("../../../../../deploy/model-servers/ai-packs.json");

#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub format: String,
    pub profiles: Vec<Profile>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub approved: bool,
    #[serde(default)]
    pub compose_profiles: Vec<String>,
    pub models: Vec<Model>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Model {
    pub id: String,
    /// `generation` or `embedding`.
    pub role: String,
    pub base_url: String,
    pub licence: String,
    #[serde(default)]
    pub tested_tasks: Vec<String>,
    #[serde(default)]
    pub scores: Value,
    #[serde(default)]
    pub files: Vec<PackFile>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PackFile {
    /// Relative to the bundle directory.
    pub path: String,
    #[serde(default)]
    pub url: Option<String>,
    pub sha256: Option<String>,
    pub bytes: Option<u64>,
}

/// Parses and checks a manifest: the format, unique profile names, a known
/// role and a licence on every model, safe relative paths, and on an
/// approved profile a 64-hex checksum and a size on every file.
pub fn parse(text: &str) -> Result<Manifest, String> {
    let manifest: Manifest = serde_json::from_str(text)
        .map_err(|e| format!("the AI pack manifest does not parse: {e}"))?;
    if manifest.format != "attome-ai-packs/v1" {
        return Err(format!(
            "unknown AI pack manifest format {}",
            manifest.format
        ));
    }
    let mut problems = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for profile in &manifest.profiles {
        if !names.insert(profile.name.as_str()) {
            problems.push(format!("profile {} is listed twice", profile.name));
        }
        for model in &profile.models {
            if !matches!(model.role.as_str(), "generation" | "embedding") {
                problems.push(format!("{}: unknown role {}", model.id, model.role));
            }
            if model.licence.trim().is_empty() {
                problems.push(format!("{}: no licence", model.id));
            }
            for file in &model.files {
                let path = Path::new(&file.path);
                if path.is_absolute()
                    || path
                        .components()
                        .any(|c| !matches!(c, std::path::Component::Normal(_)))
                {
                    problems.push(format!("{}: unsafe path {}", model.id, file.path));
                }
                if profile.approved {
                    let hex_ok = file
                        .sha256
                        .as_deref()
                        .is_some_and(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()));
                    if !hex_ok || file.bytes.is_none() {
                        problems.push(format!(
                            "{}: {} needs a sha256 and a size in an approved profile",
                            model.id, file.path
                        ));
                    }
                }
            }
        }
    }
    if problems.is_empty() {
        Ok(manifest)
    } else {
        Err(problems.join("; "))
    }
}

/// The SHA-256 of a file, read in blocks.
fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Checks every weight file of `profile` in `dir`. Returns the problems:
/// empty means the bundle matches the manifest.
pub fn verify_dir(profile: &Profile, dir: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    for model in &profile.models {
        for file in &model.files {
            let path = dir.join(&file.path);
            let Ok(meta) = std::fs::metadata(&path) else {
                problems.push(format!("{} is missing", file.path));
                continue;
            };
            if let Some(bytes) = file.bytes
                && meta.len() != bytes
            {
                problems.push(format!(
                    "{} is {} bytes, expected {bytes}",
                    file.path,
                    meta.len()
                ));
                continue;
            }
            match (sha256_file(&path), file.sha256.as_deref()) {
                (Ok(actual), Some(expected)) if actual.eq_ignore_ascii_case(expected) => {}
                (Ok(_), Some(_)) => problems.push(format!("{} has the wrong checksum", file.path)),
                (Ok(_), None) => {
                    problems.push(format!("{} has no checksum in the manifest", file.path))
                }
                (Err(e), _) => problems.push(e),
            }
        }
    }
    problems
}

/// The `inference` configuration a profile's models give: AI on, generation
/// and embeddings pointed at the local model servers.
pub fn inference_config(profile: &Profile) -> Value {
    let endpoint = |role: &str| {
        profile
            .models
            .iter()
            .find(|m| m.role == role)
            .map(|m| json!({ "base_url": m.base_url, "model": m.id }))
            .unwrap_or_else(|| json!({}))
    };
    json!({
        "ai": { "enabled": true, "fields": true, "chat": true, "semantic_search": true, "workflow_nodes": false },
        "generation": endpoint("generation"),
        "embedding": endpoint("embedding"),
    })
}

/// Finds `name` in the compiled manifest, refusing an unapproved profile,
/// and checks its weights in `dir`.
pub fn prepare(name: &str, dir: &Path) -> Result<Profile, String> {
    let manifest = parse(MANIFEST)?;
    let known: Vec<&str> = manifest.profiles.iter().map(|p| p.name.as_str()).collect();
    let profile = manifest
        .profiles
        .iter()
        .find(|p| p.name == name)
        .cloned()
        .ok_or_else(|| {
            format!(
                "no AI profile {name}; the profiles are {}",
                known.join(", ")
            )
        })?;
    if !profile.approved {
        return Err(format!(
            "AI profile {name} is not approved yet: its weights have not been checksummed and tested"
        ));
    }
    let problems = verify_dir(&profile, dir);
    if !problems.is_empty() {
        return Err(format!(
            "the AI weights in {} do not match: {}",
            dir.display(),
            problems.join("; ")
        ));
    }
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approved(sha256: &str, bytes: u64) -> String {
        json!({
            "format": "attome-ai-packs/v1",
            "profiles": [{
                "name": "t", "approved": true,
                "models": [{
                    "id": "m", "role": "generation", "base_url": "http://127.0.0.1:1/v1", "licence": "MIT",
                    "files": [{ "path": "w.bin", "sha256": sha256, "bytes": bytes }]
                }]
            }]
        })
        .to_string()
    }

    #[test]
    fn the_shipped_manifest_parses_and_lists_unapproved_profiles() {
        let manifest = parse(MANIFEST).unwrap();
        assert!(!manifest.profiles.is_empty());
        assert!(
            manifest.profiles.iter().all(|p| !p.approved
                || p.models
                    .iter()
                    .all(|m| m.files.iter().all(|f| f.sha256.is_some()))),
            "an approved profile carries checksums"
        );
        assert!(
            prepare("cpu", Path::new("."))
                .unwrap_err()
                .contains("not approved")
        );
        assert!(
            prepare("nope", Path::new("."))
                .unwrap_err()
                .contains("no AI profile")
        );
    }

    #[test]
    fn an_approved_profile_needs_checksums_and_safe_paths() {
        assert!(
            parse(&approved("abc", 1))
                .unwrap_err()
                .contains("needs a sha256")
        );
        let unsafe_path = approved(&"0".repeat(64), 1).replace("w.bin", "../w.bin");
        assert!(parse(&unsafe_path).unwrap_err().contains("unsafe path"));
    }

    #[test]
    fn weights_are_checked_against_the_manifest() {
        let dir = std::env::temp_dir().join(format!("attome-ai-pack-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("w.bin"), b"weights").unwrap();
        let good = hex::encode(Sha256::digest(b"weights"));
        let manifest = parse(&approved(&good, 7)).unwrap();
        assert!(verify_dir(&manifest.profiles[0], &dir).is_empty());
        let wrong = parse(&approved(&"0".repeat(64), 7)).unwrap();
        assert_eq!(
            verify_dir(&wrong.profiles[0], &dir),
            ["w.bin has the wrong checksum"]
        );
        let short = parse(&approved(&good, 8)).unwrap();
        assert!(verify_dir(&short.profiles[0], &dir)[0].contains("expected 8"));
        std::fs::remove_file(dir.join("w.bin")).unwrap();
        assert_eq!(
            verify_dir(&manifest.profiles[0], &dir),
            ["w.bin is missing"]
        );
        let _ = std::fs::remove_dir_all(&dir);
        let config = inference_config(&manifest.profiles[0]);
        assert_eq!(config["generation"]["model"], "m");
        assert_eq!(config["ai"]["enabled"], true);
    }
}
