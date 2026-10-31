//! T8-T4: `attome package keygen|build|publish|install` — packages
//! (T8-T1's signed `attome-package/v1` documents) from the command line.
//!
//! - `keygen --out <file>` writes a publisher signing key (a base64 Ed25519
//!   seed; keep it secret) and prints its public key, the value targets
//!   trust the publisher by.
//! - `build <folder> --key <file> [--out <file>]` reads `package.json` (the
//!   manifest) and `bundle.json` (an `attome-bundle/v1`) from the folder,
//!   checks the manifest and signs the package.
//! - `publish <package file> --to <folder>` adds a signed package to a
//!   catalogue folder: `<id>/<version>.attome-package.json` plus
//!   `index.json`. A published version never changes.
//! - `install <package file> | <id>[@<version>] --from <folder>` checks the
//!   signature against `--trust <publisher>=<public key>` (or a
//!   `--trust-file` of those pairs), checks the namespace against the
//!   target's live metadata, and shows the target's plan for it. With
//!   `--yes` (and `--confirm-target` on a production target) it applies the
//!   plan through `/api/v1/admin/metadata/import`, under that route's own
//!   permission, approval gate and audit.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use attome_api::bundle::Bundle;
use attome_api::bundle::package::{
    self, Package, check_manifest, check_namespace, public_key_of, sign_with_seed,
};
use serde_json::{Value, json};

use crate::cmd::login::{Auth, credentials};
use crate::cmd::output::{confirm, envelope, take_flag, take_value};

const DEFAULT_URL: &str = "http://127.0.0.1:7865";
const USAGE: &str = "usage: attome package keygen --out <file>\n       attome package build <folder> --key <file> [--out <file>]\n       attome package publish <package file> --to <folder>\n       attome package install <package file> | <id>[@<version>] --from <folder>\n         --trust <publisher>=<public key> ... | --trust-file <file>\n         [--target <name> | --url <url>] [--yes] [--confirm-target <name>]\n  each with [--json]";

/// The catalogue folder's index format.
pub const CATALOGUE_FORMAT: &str = "attome-package-catalogue/v1";

/// One published version in a catalogue.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CatalogueEntry {
    pub id: String,
    pub version: String,
    pub publisher: String,
    /// Relative to the catalogue folder.
    pub path: String,
}

fn semver(s: &str) -> Option<(u64, u64, u64)> {
    let mut parts = s.split('.');
    let v = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(v)
}

/// `<publisher>=<public key>` pairs (the publisher may hold spaces). Pure.
pub fn parse_trust(pairs: &[String]) -> Result<Vec<(String, String)>, String> {
    pairs
        .iter()
        .map(|pair| {
            let (publisher, key) = pair
                .split_once('=')
                .filter(|(p, k)| !p.trim().is_empty() && !k.trim().is_empty())
                .ok_or_else(|| format!("`{pair}` is not <publisher>=<public key>"))?;
            Ok((publisher.trim().to_owned(), key.trim().to_owned()))
        })
        .collect()
}

/// A trust file: `{"<publisher>": "<public key>", ...}`. Pure.
pub fn parse_trust_file(text: &str) -> Result<Vec<(String, String)>, String> {
    let map: BTreeMap<String, String> =
        serde_json::from_str(text).map_err(|e| format!("the trust file: {e}"))?;
    Ok(map.into_iter().collect())
}

/// The package a folder describes, unsigned: `package.json` is the
/// manifest, `bundle.json` the bundle. Pure over the two texts.
pub fn assemble(manifest: &str, bundle: &str) -> Result<Package, String> {
    let manifest: package::Manifest =
        serde_json::from_str(manifest).map_err(|e| format!("package.json: {e}"))?;
    let problems = check_manifest(&manifest);
    if !problems.is_empty() {
        return Err(format!("package.json: {}", problems.join("; ")));
    }
    let bundle: Bundle = serde_json::from_str(bundle).map_err(|e| format!("bundle.json: {e}"))?;
    Ok(Package {
        format: package::PACKAGE_FORMAT.to_owned(),
        manifest,
        bundle,
        signature: None,
    })
}

/// The file name a package is written and published under. Pure.
pub fn file_name(package: &Package) -> String {
    format!(
        "{}-{}.attome-package.json",
        package.manifest.id, package.manifest.version
    )
}

/// `entries` with `entry` added, ordered by id then version; the same id
/// and version already there is refused (a published version never
/// changes). Pure.
pub fn add_to_index(
    mut entries: Vec<CatalogueEntry>,
    entry: CatalogueEntry,
) -> Result<Vec<CatalogueEntry>, String> {
    if entries
        .iter()
        .any(|e| e.id == entry.id && e.version == entry.version)
    {
        return Err(format!(
            "{} {} is already published; publish a new version",
            entry.id, entry.version
        ));
    }
    entries.push(entry);
    entries.sort_by(|a, b| {
        a.id.cmp(&b.id)
            .then_with(|| semver(&a.version).cmp(&semver(&b.version)))
    });
    Ok(entries)
}

/// The catalogue entry `wanted` (`<id>` for the newest version, or
/// `<id>@<version>`) names. Pure.
pub fn resolve<'a>(
    entries: &'a [CatalogueEntry],
    wanted: &str,
) -> Result<&'a CatalogueEntry, String> {
    let (id, version) = match wanted.split_once('@') {
        Some((id, version)) => (id, Some(version)),
        None => (wanted, None),
    };
    entries
        .iter()
        .filter(|e| e.id == id && version.is_none_or(|v| e.version == v))
        .max_by_key(|e| semver(&e.version))
        .ok_or_else(|| match version {
            Some(v) => format!("the catalogue has no {id} {v}"),
            None => format!("the catalogue has no {id}"),
        })
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    std::fs::write(path, text).map_err(|e| format!("write {}: {e}", path.display()))
}

fn read_index(folder: &Path) -> Result<Vec<CatalogueEntry>, String> {
    let path = folder.join("index.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let doc: Value =
        serde_json::from_str(&read(&path)?).map_err(|e| format!("{}: {e}", path.display()))?;
    if doc["format"] != CATALOGUE_FORMAT {
        return Err(format!(
            "{} is not a {CATALOGUE_FORMAT} index",
            path.display()
        ));
    }
    serde_json::from_value(doc["packages"].clone()).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_package(path: &Path) -> Result<Package, String> {
    serde_json::from_str(&read(path)?).map_err(|e| format!("{}: {e}", path.display()))
}

fn report(json: bool, kind: &str, fields: Value, line: &str) {
    if json {
        println!("{}", envelope(kind, fields));
    } else {
        println!("{line}");
    }
}

/// Runs `attome package ...`.
pub fn run(args: &[String]) -> Result<(), String> {
    let mut args = args.to_vec();
    let json = take_flag(&mut args, "--json");
    let yes = take_flag(&mut args, "--yes");
    let confirm_target = take_value(&mut args, "--confirm-target")?;
    let target = take_value(&mut args, "--target")?;
    let url = take_value(&mut args, "--url")?;
    let out = take_value(&mut args, "--out")?;
    let key = take_value(&mut args, "--key")?;
    let to = take_value(&mut args, "--to")?;
    let from = take_value(&mut args, "--from")?;
    let trust_file = take_value(&mut args, "--trust-file")?;
    let mut trust = Vec::new();
    while let Some(pair) = take_value(&mut args, "--trust")? {
        trust.push(pair);
    }
    if let Some(unknown) = args.iter().find(|a| a.starts_with("--")) {
        return Err(format!("unknown flag `{unknown}`\n{USAGE}"));
    }
    match args.as_slice() {
        [verb] if verb == "keygen" => {
            let out = PathBuf::from(out.ok_or_else(|| format!("keygen needs --out\n{USAGE}"))?);
            if out.exists() {
                return Err(format!(
                    "{} exists; a signing key is never overwritten",
                    out.display()
                ));
            }
            let mut seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
            let seed = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, seed);
            write(&out, &format!("{seed}\n"))?;
            let public = public_key_of(&seed)?;
            report(
                json,
                "package_key",
                json!({ "key_file": out.display().to_string(), "public_key": public }),
                &format!("wrote {}; public key {public}", out.display()),
            );
            Ok(())
        }
        [verb, folder] if verb == "build" => {
            let folder = PathBuf::from(folder);
            let key = key.ok_or_else(|| format!("build needs --key <file>\n{USAGE}"))?;
            let seed = read(Path::new(&key))?;
            let mut package = assemble(
                &read(&folder.join("package.json"))?,
                &read(&folder.join("bundle.json"))?,
            )?;
            sign_with_seed(&mut package, &seed)?;
            // The package must verify under the key it was signed with.
            package::verify(
                &package,
                &[(package.manifest.publisher.clone(), public_key_of(&seed)?)],
            )?;
            let out = out.map_or_else(|| PathBuf::from(file_name(&package)), PathBuf::from);
            let text = serde_json::to_string_pretty(&package).map_err(|e| e.to_string())?;
            write(&out, &format!("{text}\n"))?;
            report(
                json,
                "package_build",
                json!({ "file": out.display().to_string(), "id": package.manifest.id, "version": package.manifest.version }),
                &format!(
                    "built {} {} -> {}",
                    package.manifest.id,
                    package.manifest.version,
                    out.display()
                ),
            );
            Ok(())
        }
        [verb, file] if verb == "publish" => {
            let folder =
                PathBuf::from(to.ok_or_else(|| format!("publish needs --to <folder>\n{USAGE}"))?);
            let text = read(Path::new(file))?;
            let package: Package =
                serde_json::from_str(&text).map_err(|e| format!("{file}: {e}"))?;
            let problems = check_manifest(&package.manifest);
            if !problems.is_empty() {
                return Err(problems.join("; "));
            }
            if package.signature.is_none() {
                return Err("only a signed package is published (attome package build)".into());
            }
            let path = format!(
                "{}/{}.attome-package.json",
                package.manifest.id, package.manifest.version
            );
            let entries = add_to_index(
                read_index(&folder)?,
                CatalogueEntry {
                    id: package.manifest.id.clone(),
                    version: package.manifest.version.clone(),
                    publisher: package.manifest.publisher.clone(),
                    path: path.clone(),
                },
            )?;
            write(&folder.join(&path), &text)?;
            let index = json!({ "format": CATALOGUE_FORMAT, "packages": entries });
            let index = serde_json::to_string_pretty(&index).map_err(|e| e.to_string())?;
            write(&folder.join("index.json"), &format!("{index}\n"))?;
            report(
                json,
                "package_publish",
                json!({ "catalogue": folder.display().to_string(), "path": path }),
                &format!("published {path} to {}", folder.display()),
            );
            Ok(())
        }
        [verb, what] if verb == "install" => {
            let path = match &from {
                Some(folder) => {
                    let folder = PathBuf::from(folder);
                    let entries = read_index(&folder)?;
                    folder.join(&resolve(&entries, what)?.path)
                }
                None => PathBuf::from(what),
            };
            let package = read_package(&path)?;
            let mut trusted = parse_trust(&trust)?;
            if let Some(file) = &trust_file {
                trusted.extend(parse_trust_file(&read(Path::new(file))?)?);
            }
            package::verify(&package, &trusted)?;
            install(
                &package,
                InstallTo {
                    url,
                    target,
                    yes,
                    confirm_target,
                    json,
                },
            )
        }
        _ => Err(USAGE.to_owned()),
    }
}

struct InstallTo {
    url: Option<String>,
    target: Option<String>,
    yes: bool,
    confirm_target: Option<String>,
    json: bool,
}

fn install(package: &Package, to: InstallTo) -> Result<(), String> {
    let url = to
        .url
        .or_else(|| std::env::var("ATTOME_URL").ok())
        .unwrap_or_else(|| DEFAULT_URL.to_owned());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start the runtime: {error}"))?;
    runtime.block_on(async {
        let api_key = std::env::var("ATTOME_API_KEY").ok();
        let (url, auth) =
            credentials(url.trim_end_matches('/').to_owned(), api_key, to.target.clone()).await?;
        // The namespace, against the entities the target already has.
        let live = send(&url, &auth, reqwest::Method::GET, "/api/v1/admin/metadata/export", None)
            .await?;
        let existing: std::collections::HashSet<String> = live["entities"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| e["logicalname"].as_str().map(str::to_owned))
            .collect();
        let problems = check_namespace(&package.manifest, &package.bundle, &|name| {
            existing.contains(name)
        });
        if !problems.is_empty() {
            return Err(problems.join("; "));
        }
        let bundle = serde_json::to_value(&package.bundle).map_err(|e| e.to_string())?;
        let plan = send(
            &url,
            &auth,
            reqwest::Method::POST,
            "/api/v1/admin/metadata/import?mode=plan",
            Some(json!({ "bundle": bundle })),
        )
        .await?;
        let summary = &plan["summary"];
        let preview = format!(
            "{} {}: {} to create, {} to update, {} unchanged, {} blocked (plan {})",
            package.manifest.id,
            package.manifest.version,
            summary["creates"],
            summary["updates"],
            summary["noops"],
            summary["blocked"],
            plan["plan_id"].as_str().unwrap_or_default()
        );
        if plan["applicable"] != true {
            return Err(format!("{preview}; the target cannot apply it: {}", plan["blocked"]));
        }
        if !to.yes {
            report(
                to.json,
                "package_install",
                json!({ "id": package.manifest.id, "version": package.manifest.version, "plan": plan, "applied": false }),
                &format!("{preview}\nrun again with --yes to install"),
            );
            return Ok(());
        }
        let named = to
            .target
            .as_deref()
            .map(|t| (t, crate::cmd::login::is_production(Some(t))));
        confirm("installing a package", to.yes, to.confirm_target.as_deref(), named)?;
        let accepted = send(
            &url,
            &auth,
            reqwest::Method::POST,
            "/api/v1/admin/metadata/import?mode=apply",
            Some(json!({ "plan_id": plan["plan_id"] })),
        )
        .await?;
        let line = if accepted["approval_pending"] == true {
            format!("{preview}\nwaiting for a second administrator's approval")
        } else {
            format!("{preview}\ninstall {}", accepted["status"].as_str().unwrap_or("queued"))
        };
        report(
            to.json,
            "package_install",
            json!({ "id": package.manifest.id, "version": package.manifest.version, "plan": plan, "applied": true, "accepted": accepted }),
            &line,
        );
        Ok(())
    })
}

/// `url` is the operator's own deployment, named on the command line.
fn client(url: &str) -> Result<attome_outbound::http::Outbound, String> {
    let purpose = attome_outbound::http::Purpose::public("cli-package").with_private_urls([url]);
    attome_outbound::http::client(purpose, |b| b.timeout(std::time::Duration::from_secs(120)))
        .map_err(|error| format!("build the HTTP client: {error}"))
}

async fn send(
    url: &str,
    auth: &Auth,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let mut request = client(url)?.request(method, format!("{url}{path}"));
    if let Some(value) = auth {
        request = request.header("authorization", value);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("reach {url}: {error}"))?;
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .map_err(|error| format!("read the response: {error}"))?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!("the server answered {status}: {body}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"{ "id": "com.example.fleet", "publisher": "Example Co", "namespace": "exf",
        "version": "1.2.0", "platform": ">=0.1.0", "contents": ["entities"], "mode": "managed" }"#;
    const BUNDLE: &str = r#"{ "format": "attome-bundle/v1",
        "requires": { "platform_version": ">=0.1.0", "schema_version": 1 },
        "entities": [{ "logicalname": "exf_vehicle", "display_name": "Vehicle",
          "attributes": [{ "logicalname": "plate", "display_name": "Plate", "field_type": "text" }] }] }"#;
    const SEED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    fn entry(id: &str, version: &str) -> CatalogueEntry {
        CatalogueEntry {
            id: id.into(),
            version: version.into(),
            publisher: "Example Co".into(),
            path: format!("{id}/{version}.attome-package.json"),
        }
    }

    #[test]
    fn a_folder_builds_a_package_that_verifies_only_under_its_publisher() {
        let mut package = assemble(MANIFEST, BUNDLE).expect("assemble");
        assert_eq!(
            file_name(&package),
            "com.example.fleet-1.2.0.attome-package.json"
        );
        sign_with_seed(&mut package, SEED).expect("sign");
        let public = public_key_of(SEED).expect("public key");
        let trusted = parse_trust(&[format!("Example Co={public}")]).expect("trust");
        assert!(package::verify(&package, &trusted).is_ok());
        assert!(package::verify(&package, &[]).is_err());
        // Changed after signing: refused.
        package.manifest.version = "1.2.1".into();
        assert!(package::verify(&package, &trusted).is_err());
    }

    #[test]
    fn a_bad_manifest_or_trust_pair_is_refused() {
        assert!(assemble(&MANIFEST.replace("com.example.fleet", "fleet"), BUNDLE).is_err());
        assert!(parse_trust(&["no-key".into()]).is_err());
        assert_eq!(
            parse_trust_file(r#"{"Example Co": "abc"}"#).unwrap(),
            vec![("Example Co".to_owned(), "abc".to_owned())]
        );
    }

    #[test]
    fn a_catalogue_keeps_versions_immutable_and_resolves_the_newest() {
        let index = add_to_index(Vec::new(), entry("com.example.fleet", "1.10.0")).unwrap();
        let index = add_to_index(index, entry("com.example.fleet", "1.9.0")).unwrap();
        assert!(add_to_index(index.clone(), entry("com.example.fleet", "1.9.0")).is_err());
        assert_eq!(
            resolve(&index, "com.example.fleet").unwrap().version,
            "1.10.0"
        );
        assert_eq!(
            resolve(&index, "com.example.fleet@1.9.0").unwrap().version,
            "1.9.0"
        );
        assert!(resolve(&index, "com.example.fleet@2.0.0").is_err());
        assert!(resolve(&index, "com.other").is_err());
    }
}
