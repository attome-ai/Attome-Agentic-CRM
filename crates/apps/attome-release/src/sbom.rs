//! Software bills of materials (roadmap AC7-T4), in CycloneDX 1.5 JSON.
//!
//! The Rust SBOM is built from `Cargo.lock` alone: every registry package
//! becomes a library component with its `pkg:cargo/...` package URL and the
//! SHA-256 checksum the lock file already records; the workspace's own crates
//! are listed under the application component. No extra tool is needed, and
//! the result is exactly what the build resolved. The web app's SBOM comes
//! from npm itself (`npm sbom --sbom-format cyclonedx`) in the `--web` step.

use std::path::Path;

use serde_json::{Value, json};

/// One `[[package]]` entry of `Cargo.lock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub checksum: Option<String>,
}

/// The packages in a `Cargo.lock`.
pub fn parse_lock(text: &str) -> Vec<LockedPackage> {
    let mut out = Vec::new();
    let mut current: Option<LockedPackage> = None;
    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            out.extend(current.take());
            current = Some(LockedPackage {
                name: String::new(),
                version: String::new(),
                source: None,
                checksum: None,
            });
            continue;
        }
        let Some(package) = current.as_mut() else {
            continue;
        };
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_owned();
        match key.trim() {
            "name" => package.name = value,
            "version" => package.version = value,
            "source" => package.source = Some(value),
            "checksum" => package.checksum = Some(value),
            _ => {}
        }
    }
    out.extend(current);
    out
}

/// The CycloneDX document for the workspace. `serial` and `timestamp` are
/// passed in so the output is reproducible in tests.
pub fn rust_sbom(
    packages: &[LockedPackage],
    version: &str,
    serial: &str,
    timestamp: &str,
) -> Value {
    let mut workspace = Vec::new();
    let mut libraries = Vec::new();
    for package in packages {
        let purl = format!("pkg:cargo/{}@{}", package.name, package.version);
        match &package.source {
            None => workspace.push(json!({
                "type": "library",
                "bom-ref": purl,
                "name": package.name,
                "version": package.version,
                "purl": purl,
            })),
            Some(source) => {
                let mut component = json!({
                    "type": "library",
                    "bom-ref": purl,
                    "name": package.name,
                    "version": package.version,
                    "purl": purl,
                    "externalReferences": [{ "type": "distribution", "url": source }],
                });
                if let Some(checksum) = &package.checksum {
                    component["hashes"] = json!([{ "alg": "SHA-256", "content": checksum }]);
                }
                libraries.push(component);
            }
        }
    }
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:{serial}"),
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": "application",
                "bom-ref": format!("pkg:cargo/attome@{version}"),
                "name": "attome",
                "version": version,
                "licenses": [{ "license": { "id": "AGPL-3.0-only" } }],
                "components": workspace,
            },
        },
        "components": libraries,
    })
}

/// Writes `sbom-rust.cdx.json` into `out` from the workspace's `Cargo.lock`.
pub fn write_rust_sbom(
    root: &Path,
    out: &Path,
    serial: &str,
    timestamp: &str,
) -> Result<(), String> {
    let lock = std::fs::read_to_string(root.join("Cargo.lock"))
        .map_err(|error| format!("Cargo.lock: {error}"))?;
    let cargo = std::fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|error| format!("Cargo.toml: {error}"))?;
    let version = workspace_version(&cargo).unwrap_or_else(|| "0.0.0".to_owned());
    let document = rust_sbom(&parse_lock(&lock), &version, serial, timestamp);
    std::fs::create_dir_all(out).map_err(|error| format!("{}: {error}", out.display()))?;
    let text = serde_json::to_string_pretty(&document).map_err(|error| error.to_string())?;
    let path = out.join("sbom-rust.cdx.json");
    std::fs::write(&path, text + "\n").map_err(|error| format!("{}: {error}", path.display()))
}

/// `[workspace.package] version` from `Cargo.toml`.
pub fn workspace_version(cargo_toml: &str) -> Option<String> {
    let mut in_package = false;
    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[workspace.package]";
        } else if in_package && trimmed.starts_with("version") {
            return trimmed.split('"').nth(1).map(str::to_owned);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = "version = 4\n\n[[package]]\nname = \"attome\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde\",\n]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"abc123\"\n";

    #[test]
    fn registry_packages_become_hashed_components() {
        let packages = parse_lock(LOCK);
        assert_eq!(packages.len(), 2);
        let sbom = rust_sbom(
            &packages,
            "0.1.0",
            "00000000-0000-0000-0000-000000000000",
            "2026-10-14T00:00:00Z",
        );
        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["components"].as_array().unwrap().len(), 1);
        assert_eq!(sbom["components"][0]["purl"], "pkg:cargo/serde@1.0.0");
        assert_eq!(sbom["components"][0]["hashes"][0]["content"], "abc123");
        assert_eq!(
            sbom["metadata"]["component"]["components"][0]["name"], "attome",
            "workspace crates sit under the application"
        );
    }

    #[test]
    fn the_real_lock_file_parses() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .unwrap();
        let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();
        let packages = parse_lock(&lock);
        assert!(packages.len() > 100);
        assert!(
            packages
                .iter()
                .any(|p| p.name == "serde" && p.checksum.is_some())
        );
        let cargo = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert!(workspace_version(&cargo).is_some());
    }
}
