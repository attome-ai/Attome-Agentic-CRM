//! T3-T4 step 2: `attome dev <folder>` on a component project (one that
//! `attome new component` made: it holds `component.json`) builds the
//! component whenever its source changes and loads it into the target, or
//! the Develop workspace `attome workspace switch` chose, so a page there
//! shows the new build at its next load.
//!
//! Each good build (`npm run build`, which writes the module under `dist/`):
//!
//! 1. becomes a package of one file, the module, under the package id the
//!    manifest's `module` names (`com.example.credit/gauge.js` is the file
//!    `gauge.js` of `com.example.credit`), at version `0.0.<seconds>` so
//!    each build is newer, unmanaged, with no metadata;
//! 2. is signed with the folder's development key, `.attome/dev.key`
//!    (made on first use; keep `.attome/` out of version control), under
//!    the publisher [`DEV_PUBLISHER`];
//! 3. is installed through `POST /api/v1/admin/packages/preview` and the
//!    plan's apply, the same checks as any package: the target must trust
//!    the development key, so a deployment that has not chosen to never
//!    runs a developer's code (the first failure prints the
//!    `packages.trusted_publishers` entry to add, for a workspace or a
//!    development deployment only);
//! 4. publishes `component.json` as the component object
//!    (`component/<app>/<name>.json` through `POST /api/v1/admin/model/import`
//!    and the draft's publish), app `components` unless `--app` names one.
//!
//! A failed build prints npm's output and loads nothing. `--once` builds and
//! loads one time and stops.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use attome_api::bundle::Bundle;
use attome_api::bundle::package::{
    self, Manifest, PACKAGE_FORMAT, Package, PackageMode, public_key_of, sign_with_seed,
};
use base64::Engine as _;
use serde_json::{Value, json};

use crate::cmd::login::{Auth, credentials};

/// The publisher a development build is signed as.
pub const DEV_PUBLISHER: &str = "Local development";
/// The namespace of a development package (it adds no metadata).
pub const DEV_NAMESPACE: &str = "devlocal";
/// Where the development key lives in the project.
pub const DEV_KEY: &str = ".attome/dev.key";
/// The app the component object is published under, unless `--app` says.
pub const DEFAULT_APP: &str = "components";

/// Whether `folder` is a component project. Pure over the file system.
pub fn is_component_project(folder: &Path) -> bool {
    folder.join("component.json").is_file()
}

/// The package id and file path a manifest's `module` names; the id must be
/// a reverse-DNS package id. Pure.
pub fn module_parts(manifest: &Value) -> Result<(String, String), String> {
    let module = manifest["module"].as_str().unwrap_or_default();
    let (package_id, path) = module
        .split_once('/')
        .ok_or_else(|| format!("component.json: module `{module}` is not <package id>/<path>"))?;
    if !package_id.contains('.') {
        return Err(format!(
            "component.json: module `{module}` must start with a reverse-DNS package id such as com.example.{package_id}; \
             rename it there (and in the build output) before loading it"
        ));
    }
    if !package::is_file_path(path) {
        return Err(format!(
            "component.json: `{path}` is not a plain relative path"
        ));
    }
    Ok((package_id.to_owned(), path.to_owned()))
}

/// The development build's package: one file, no metadata, unmanaged,
/// unsigned. `seconds` makes the version. Pure.
pub fn dev_package(
    package_id: &str,
    path: &str,
    module: &[u8],
    seconds: u64,
) -> Result<Package, String> {
    let bundle: Bundle = serde_json::from_value(json!({
        "format": "attome-bundle/v1",
        "requires": { "platform_version": ">=0.1.0", "schema_version": 1 },
        "partial": true,
    }))
    .map_err(|e| format!("the empty bundle: {e}"))?;
    let package = Package {
        format: PACKAGE_FORMAT.to_owned(),
        manifest: Manifest {
            id: package_id.to_owned(),
            publisher: DEV_PUBLISHER.to_owned(),
            namespace: DEV_NAMESPACE.to_owned(),
            version: format!("0.0.{seconds}"),
            depends: Vec::new(),
            platform: ">=0.1.0".to_owned(),
            contents: Vec::new(),
            mode: PackageMode::Unmanaged,
            extension_points: Vec::new(),
        },
        bundle,
        files: BTreeMap::from([(
            path.to_owned(),
            base64::engine::general_purpose::STANDARD.encode(module),
        )]),
        signature: None,
    };
    let problems = package::check_manifest(&package.manifest);
    if !problems.is_empty() {
        return Err(problems.join("; "));
    }
    package::check_files(&package.files).map_err(|p| p.join("; "))?;
    Ok(package)
}

/// The component object's model file path. Pure.
pub fn model_path(app: &str, manifest: &Value) -> String {
    let name = manifest["tag"]
        .as_str()
        .unwrap_or("component")
        .replace('-', "_");
    format!("component/{app}/{name}.json")
}

/// The development key, made on first use; its base64 seed.
fn dev_key(folder: &Path) -> Result<String, String> {
    let path = folder.join(DEV_KEY);
    if let Ok(seed) = std::fs::read_to_string(&path) {
        return Ok(seed.trim().to_owned());
    }
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let seed = base64::engine::general_purpose::STANDARD.encode(seed);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::write(&path, format!("{seed}\n")).map_err(|e| format!("{}: {e}", path.display()))?;
    println!(
        "made the development key {} (keep .attome/ out of version control)",
        path.display()
    );
    Ok(seed)
}

fn npm() -> &'static str {
    if cfg!(windows) { "npm.cmd" } else { "npm" }
}

/// Every source file with its modification time; `node_modules/`, `dist/`,
/// `.attome/` and `.git/` left out.
fn sources(folder: &Path) -> BTreeMap<PathBuf, SystemTime> {
    crate::cmd::dev::snapshot(folder)
        .into_iter()
        .filter(|(path, _)| {
            !path.components().any(|c| {
                matches!(
                    c.as_os_str().to_str(),
                    Some("node_modules" | "dist" | ".attome" | ".git")
                )
            })
        })
        .collect()
}

/// One `attome dev` session on a component project.
pub struct ComponentDev {
    pub folder: PathBuf,
    pub app: String,
    pub url: String,
    pub target: Option<String>,
}

impl ComponentDev {
    /// Builds and loads once; a failure is printed, never fatal.
    pub fn cycle(&self, runtime: &tokio::runtime::Runtime) {
        match self
            .build()
            .and_then(|(manifest, package)| runtime.block_on(self.load(&manifest, package)))
        {
            Ok(line) => println!("{line}"),
            Err(error) => println!("not loaded: {error}"),
        }
    }

    fn build(&self) -> Result<(Value, Package), String> {
        let output = std::process::Command::new(npm())
            .args(["run", "build"])
            .current_dir(&self.folder)
            .output()
            .map_err(|e| format!("run npm: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "the build failed:\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let text = std::fs::read_to_string(self.folder.join("component.json"))
            .map_err(|e| format!("component.json: {e}"))?;
        let manifest: Value =
            serde_json::from_str(&text).map_err(|e| format!("component.json: {e}"))?;
        let (package_id, path) = module_parts(&manifest)?;
        let built = self.folder.join("dist").join(&path);
        let module = std::fs::read(&built).map_err(|e| format!("{}: {e}", built.display()))?;
        let seconds = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let mut package = dev_package(&package_id, &path, &module, seconds)?;
        let seed = dev_key(&self.folder)?;
        sign_with_seed(&mut package, &seed)?;
        Ok((manifest, package))
    }

    async fn load(&self, manifest: &Value, package: Package) -> Result<String, String> {
        let api_key = std::env::var("ATTOME_API_KEY").ok();
        let (url, auth): (String, Auth) = credentials(
            self.url.trim_end_matches('/').to_owned(),
            api_key,
            self.target.clone(),
        )
        .await?;
        let document = serde_json::to_value(&package).map_err(|e| e.to_string())?;
        let preview = crate::cmd::package::send(
            &url,
            &auth,
            reqwest::Method::POST,
            "/api/v1/admin/packages/preview",
            Some(json!({ "package": document })),
        )
        .await
        .map_err(|error| {
            if error.contains("not a trusted publisher") {
                let key = std::fs::read_to_string(self.folder.join(DEV_KEY))
                    .ok()
                    .and_then(|seed| public_key_of(seed.trim()).ok())
                    .unwrap_or_default();
                format!(
                    "{error}\nthe target does not trust this development key; on a workspace or a \
                     development deployment only, add to its configuration:\n  \
                     \"packages\": {{ \"trusted_publishers\": {{ \"{DEV_PUBLISHER}\": \"{key}\" }} }}"
                )
            } else {
                error
            }
        })?;
        let plan_id = preview["plan"]["plan_id"].clone();
        crate::cmd::package::send(
            &url,
            &auth,
            reqwest::Method::POST,
            "/api/v1/admin/metadata/import?mode=apply",
            Some(json!({ "plan_id": plan_id })),
        )
        .await?;
        // The component object, as the manifest says.
        let text = serde_json::to_string_pretty(manifest).map_err(|e| e.to_string())?;
        let path = model_path(&self.app, manifest);
        let staging = tempdir_with(&path, &text)?;
        let body =
            crate::cmd::model_files::import_files(&url, auth.clone(), staging.path()).await?;
        for draft in body["drafts"].as_array().into_iter().flatten() {
            if let Some(id) = draft["id"].as_str() {
                crate::cmd::model_files::publish_object(&url, auth.clone(), "component", id)
                    .await?;
            }
        }
        Ok(format!(
            "loaded {} {} ({})",
            manifest["tag"].as_str().unwrap_or_default(),
            package.manifest.version,
            package.manifest.id
        ))
    }
}

/// A scratch folder holding `relative` with `text`, removed when dropped.
struct Staging(PathBuf);

impl Staging {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir_with(relative: &str, text: &str) -> Result<Staging, String> {
    let dir = std::env::temp_dir().join(format!("attome-dev-{}", uuid::Uuid::now_v7().simple()));
    let file = dir.join(relative);
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    std::fs::write(&file, text).map_err(|e| format!("{}: {e}", file.display()))?;
    Ok(Staging(dir))
}

/// Watches `dev`'s sources and rebuilds after each settled change.
pub fn watch(dev: &ComponentDev, runtime: &tokio::runtime::Runtime, once: bool) {
    let mut seen = sources(&dev.folder);
    dev.cycle(runtime);
    if once {
        return;
    }
    println!("watching {} (Ctrl+C stops)", dev.folder.display());
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let now = sources(&dev.folder);
        if now == seen {
            continue;
        }
        let mut settled = now;
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let again = sources(&dev.folder);
            if again == settled {
                break;
            }
            settled = again;
        }
        seen = settled;
        dev.cycle(runtime);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures")]

    use super::*;

    #[test]
    fn the_module_names_a_reverse_dns_package_and_a_plain_path() {
        let ok =
            json!({ "tag": "acme-credit-gauge", "module": "com.acme.credit/acme-credit-gauge.js" });
        assert_eq!(
            module_parts(&ok).unwrap(),
            (
                "com.acme.credit".to_owned(),
                "acme-credit-gauge.js".to_owned()
            )
        );
        assert!(module_parts(&json!({ "module": "acme-credit/gauge.js" })).is_err());
        assert!(module_parts(&json!({ "module": "com.acme/../x.js" })).is_err());
        assert_eq!(
            model_path("components", &ok),
            "component/components/acme_credit_gauge.json"
        );
    }

    #[test]
    fn a_development_build_is_one_signed_file_and_no_metadata() {
        let mut package =
            dev_package("com.acme.credit", "gauge.js", b"export {};", 1_790_000_000).unwrap();
        assert_eq!(package.manifest.version, "0.0.1790000000");
        assert_eq!(package.manifest.mode, PackageMode::Unmanaged);
        assert_eq!(package.files.len(), 1);
        let seed = base64::engine::general_purpose::STANDARD.encode([3u8; 32]);
        sign_with_seed(&mut package, &seed).unwrap();
        let trusted = vec![(DEV_PUBLISHER.to_owned(), public_key_of(&seed).unwrap())];
        assert_eq!(package::verify(&package, &trusted), Ok(()));
    }
}
