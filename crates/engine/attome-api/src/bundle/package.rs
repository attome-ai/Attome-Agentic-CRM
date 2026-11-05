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
//! - [`managed_locks`] (T8-T2): what a managed package locks once installed.
//!   Its own entities (named with its namespace) are `locked`, or
//!   `add_only` when the manifest lists them in `extension_points` (the
//!   customer may add fields there, as their own layer); the fields it adds
//!   to entities it does not own are `locked`. The preview records them
//!   against its plan ([`record_pending`]) and a successful apply of that
//!   plan writes them to `metadata_lock` ([`install_locks`]), which the admin
//!   metadata routes enforce (`attome_model::guard`). A newer version
//!   arrives through a bundle apply, which those routes do not guard.
//! - T8-T3: [`three_way`] merges an upgrade (the installed version, the new
//!   one and the customer's live metadata) property by property, keeping a
//!   customer's change the package did not also make and naming each
//!   property both changed as a [`Conflict`]; [`package_drift`] names every
//!   managed property that differs live from what the package installed;
//!   [`without_package`] is the live metadata minus what a package owns,
//!   which an uninstall that removes its data plans with retiring allowed.
//!   A package's bundle is always a selection (`partial`): installing or
//!   upgrading it never retires what it does not carry.
//! - T3-T2: [`Package::files`] carries static files (a custom component's
//!   JavaScript module), base64 by path; [`check_files`] bounds them and
//!   [`signing_payload`] covers them, so a file cannot change after signing.
//!   A preview stages them against its plan ([`stage_files`]); the newest
//!   applied plan's files are what `GET /api/v1/packages/{id}/files/{path}`
//!   serves ([`installed_file`]).

use std::collections::BTreeMap;

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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
    /// T8-T2: its own entities the customer may add fields to (a managed
    /// package's other entities take no customer change). Left out of the
    /// signed form when empty, so earlier signatures still hold.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extension_points: Vec<String>,
}

/// A package document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Package {
    pub format: String,
    pub manifest: Manifest,
    pub bundle: Bundle,
    /// T3-T2: static files by path (`gauge.js`, `icons/gauge.svg`), each
    /// base64. Covered by the signature when there are any.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, String>,
    #[serde(default)]
    pub signature: Option<String>,
}

/// The most bytes one package file may hold.
pub const MAX_FILE_BYTES: usize = 2 * 1024 * 1024;
/// The most bytes a package's files may hold together.
pub const MAX_FILES_BYTES: usize = 10 * 1024 * 1024;
/// The most files a package may carry.
pub const MAX_FILES: usize = 200;

/// The extensions a package file may have, with the type it is served as.
pub const FILE_TYPES: [(&str, &str); 6] = [
    ("js", "text/javascript; charset=utf-8"),
    ("mjs", "text/javascript; charset=utf-8"),
    ("css", "text/css; charset=utf-8"),
    ("json", "application/json"),
    ("svg", "image/svg+xml"),
    ("png", "image/png"),
];

/// The type `path` is served as, when its extension is allowed. Pure.
pub fn content_type_of(path: &str) -> Option<&'static str> {
    let ext = path.rsplit_once('.')?.1.to_ascii_lowercase();
    FILE_TYPES
        .iter()
        .find(|(e, _)| *e == ext)
        .map(|(_, content_type)| *content_type)
}

/// Whether `path` is a plain relative path: segments of letters, digits,
/// `.`, `_` and `-`, none empty, `.` or `..`, at most 200 characters. Pure.
pub fn is_file_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 200
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        })
}

/// One file's digests: lowercase hex SHA-256, and the Subresource
/// Integrity value (`sha256-<base64>`) a browser checks it against. Pure.
pub fn file_digest(bytes: &[u8]) -> (String, String) {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(bytes);
    (
        hex::encode(digest),
        format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        ),
    )
}

/// T3-T2: `files` decoded, or every problem with them at once: a bad path,
/// an extension not served, content that is not base64, and the size caps.
/// Pure.
pub fn check_files(
    files: &BTreeMap<String, String>,
) -> Result<Vec<(String, Vec<u8>)>, Vec<String>> {
    let mut problems = Vec::new();
    let mut decoded = Vec::with_capacity(files.len());
    if files.len() > MAX_FILES {
        problems.push(format!("files: at most {MAX_FILES}"));
    }
    let mut total = 0usize;
    for (path, content) in files {
        if !is_file_path(path) {
            problems.push(format!("files.{path}: not a plain relative path"));
            continue;
        }
        if content_type_of(path).is_none() {
            problems.push(format!(
                "files.{path}: only .js, .mjs, .css, .json, .svg and .png files are served"
            ));
            continue;
        }
        match base64::engine::general_purpose::STANDARD.decode(content.trim()) {
            Ok(bytes) if bytes.len() > MAX_FILE_BYTES => {
                problems.push(format!("files.{path}: larger than {MAX_FILE_BYTES} bytes"));
            }
            Ok(bytes) => {
                total += bytes.len();
                decoded.push((path.clone(), bytes));
            }
            Err(_) => problems.push(format!("files.{path}: not base64")),
        }
    }
    if total > MAX_FILES_BYTES {
        problems.push(format!(
            "files: larger than {MAX_FILES_BYTES} bytes together"
        ));
    }
    if problems.is_empty() {
        Ok(decoded)
    } else {
        Err(problems)
    }
}

/// The digest of every file, by path (what the signature covers). Pure.
fn files_digest(files: &BTreeMap<String, String>) -> Value {
    let digests: serde_json::Map<String, Value> = files
        .iter()
        .map(|(path, content)| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(content.trim())
                .unwrap_or_else(|_| content.as_bytes().to_vec());
            (path.clone(), Value::String(file_digest(&bytes).0))
        })
        .collect();
    Value::Object(digests)
}

/// T3-T2: stores a previewed package's files against its plan, so the plan's
/// apply makes them the package's served files. Replaces what the plan had.
pub async fn stage_files(
    db: &attome_db::DbPool,
    plan_ref: uuid::Uuid,
    manifest: &Manifest,
    files: &[(String, Vec<u8>)],
) -> Result<(), attome_types::AppError> {
    use attome_types::AppError;
    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query("DELETE FROM package_file WHERE plan_ref = $1")
        .bind(plan_ref)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    for (path, bytes) in files {
        let (sha256, integrity) = file_digest(bytes);
        let content_type = content_type_of(path)
            .ok_or_else(|| AppError::Validation(format!("files.{path}: not served")))?;
        sqlx::query(
            "INSERT INTO package_file (plan_ref, package_id, version, path, content_type, sha256, \
                 integrity, size_bytes, body) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(plan_ref)
        .bind(&manifest.id)
        .bind(&manifest.version)
        .bind(path)
        .bind(content_type)
        .bind(&sha256)
        .bind(&integrity)
        .bind(i32::try_from(bytes.len()).unwrap_or(i32::MAX))
        .bind(bytes)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await
}

/// A package file as served.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ServedFile {
    pub content_type: String,
    pub sha256: String,
    pub integrity: String,
    pub body: Vec<u8>,
}

/// T3-T2: `path` of package `package_id` as its newest applied plan carries
/// it, unless that install was since uninstalled; `None` when there is none.
/// With `with_body` false the body is left empty (a lookup of the digest).
pub async fn installed_file(
    db: &attome_db::DbPool,
    package_id: &str,
    path: &str,
    with_body: bool,
) -> Result<Option<ServedFile>, attome_types::AppError> {
    sqlx::query_as(
        "SELECT f.content_type, f.sha256, f.integrity, \
                CASE WHEN $3 THEN f.body ELSE ''::bytea END AS body \
           FROM package_file f JOIN metadata_bundle_plan p ON p.id = f.plan_ref \
          WHERE f.package_id = $1 AND f.path = $2 AND p.status = 'succeeded' \
            AND NOT EXISTS (SELECT 1 FROM package_install i \
                             WHERE i.plan_ref = f.plan_ref AND i.uninstalled_at IS NOT NULL) \
          ORDER BY p.finished_at DESC NULLS LAST, p.created_at DESC LIMIT 1",
    )
    .bind(package_id)
    .bind(path)
    .bind(with_body)
    .fetch_optional(db)
    .await
    .map_err(attome_types::AppError::internal)
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

/// T8-T3: `candidate` is a higher `MAJOR.MINOR.PATCH` than `installed`.
/// Pure.
pub fn is_newer(candidate: &str, installed: &str) -> bool {
    matches!((semver(candidate), semver(installed)), (Some(c), Some(i)) if c > i)
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

/// One lock a managed package sets: `(object_kind, object_key, mode)`.
pub type PackageLock = (String, String, String);

/// The locks a managed package sets on install (an unmanaged one sets
/// none), given which entities the target already has. Pure.
pub fn managed_locks(
    manifest: &Manifest,
    bundle: &Bundle,
    existing: &dyn Fn(&str) -> bool,
) -> Vec<PackageLock> {
    if manifest.mode != PackageMode::Managed {
        return Vec::new();
    }
    let prefix = format!("{}_", manifest.namespace);
    let mut locks = Vec::new();
    for entity in &bundle.entities {
        if existing(&entity.logicalname) {
            for attr in &entity.attributes {
                if attr.logicalname.starts_with(&prefix) {
                    locks.push((
                        "attribute".to_owned(),
                        format!("{}.{}", entity.logicalname, attr.logicalname),
                        "locked".to_owned(),
                    ));
                }
            }
        } else if entity.logicalname.starts_with(&prefix) {
            let mode = if manifest.extension_points.contains(&entity.logicalname) {
                "add_only"
            } else {
                "locked"
            };
            locks.push((
                "entity".to_owned(),
                entity.logicalname.clone(),
                mode.to_owned(),
            ));
        }
    }
    locks
}

/// Problems with a manifest's extension points: each is an entity the
/// package adds. Pure.
pub fn check_extension_points(
    manifest: &Manifest,
    bundle: &Bundle,
    existing: &dyn Fn(&str) -> bool,
) -> Vec<String> {
    manifest
        .extension_points
        .iter()
        .filter(|point| {
            !bundle
                .entities
                .iter()
                .any(|e| &e.logicalname == *point && !existing(&e.logicalname))
        })
        .map(|point| format!("extension point {point} is not an entity this package adds"))
        .collect()
}

/// Records what a managed package will lock once `plan_id` applies, with
/// its manifest (T8-T3: upgrade, drift and uninstall read it back).
pub async fn record_pending(
    db: &attome_db::DbPool,
    plan_id: uuid::Uuid,
    manifest: &Manifest,
    locks: &[PackageLock],
) -> Result<(), attome_types::AppError> {
    sqlx::query(
        "INSERT INTO package_install (plan_ref, package_id, version, mode, locks, manifest) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (plan_ref) DO UPDATE SET locks = EXCLUDED.locks, manifest = EXCLUDED.manifest",
    )
    .bind(plan_id)
    .bind(&manifest.id)
    .bind(&manifest.version)
    .bind(match manifest.mode {
        PackageMode::Managed => "managed",
        PackageMode::Unmanaged => "unmanaged",
    })
    .bind(serde_json::to_value(locks).map_err(attome_types::AppError::internal)?)
    .bind(serde_json::to_value(manifest).map_err(attome_types::AppError::internal)?)
    .execute(db)
    .await
    .map_err(attome_types::AppError::internal)?;
    Ok(())
}

/// After `plan_id` applied: writes its package's locks, once. A plan that
/// is not a package's does nothing. T8-T3: an upgrade's apply supersedes
/// the version it replaces (`data_choice = 'upgraded'`) and drops the locks
/// that version set and this one does not.
pub async fn install_locks(
    db: &attome_db::DbPool,
    plan_id: uuid::Uuid,
) -> Result<usize, attome_types::AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let row: Option<(serde_json::Value, String)> = sqlx::query_as(
        "UPDATE package_install SET installed_at = now() \
          WHERE plan_ref = $1 AND installed_at IS NULL RETURNING locks, package_id",
    )
    .bind(plan_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(attome_types::AppError::internal)?;
    let Some((locks, package_id)) = row else {
        return Ok(0);
    };
    let locks: Vec<PackageLock> =
        serde_json::from_value(locks).map_err(attome_types::AppError::internal)?;
    let replaced: Vec<serde_json::Value> = sqlx::query_scalar(
        "UPDATE package_install SET uninstalled_at = now(), data_choice = 'upgraded' \
          WHERE package_id = $1 AND plan_ref <> $2 \
            AND installed_at IS NOT NULL AND uninstalled_at IS NULL \
          RETURNING locks",
    )
    .bind(&package_id)
    .bind(plan_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(attome_types::AppError::internal)?;
    for old in replaced {
        let old: Vec<PackageLock> =
            serde_json::from_value(old).map_err(attome_types::AppError::internal)?;
        for (kind, key, _) in old
            .iter()
            .filter(|(k, key, _)| !locks.iter().any(|(nk, nkey, _)| nk == k && nkey == key))
        {
            sqlx::query("DELETE FROM metadata_lock WHERE object_kind = $1 AND object_key = $2")
                .bind(kind)
                .bind(key)
                .execute(&mut *tx)
                .await
                .map_err(attome_types::AppError::internal)?;
        }
    }
    for (kind, key, mode) in &locks {
        sqlx::query(
            "INSERT INTO metadata_lock (object_kind, object_key, mode, set_by_layer) \
             VALUES ($1, $2, $3, 'product') \
             ON CONFLICT (object_kind, object_key) DO UPDATE SET mode = EXCLUDED.mode, \
                 set_by_layer = EXCLUDED.set_by_layer",
        )
        .bind(kind)
        .bind(key)
        .bind(mode)
        .execute(&mut *tx)
        .await
        .map_err(attome_types::AppError::internal)?;
    }
    tx.commit()
        .await
        .map_err(attome_types::AppError::internal)?;
    Ok(locks.len())
}

/// T8-T3: one property an upgrade cannot merge on its own: the package's
/// new version and the customer both changed it, differently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[schema(as = PackageConflict)]
pub struct Conflict {
    /// `entity` or `entity.attribute`.
    pub object: String,
    pub property: String,
    /// What the installed version set.
    #[schema(value_type = Object)]
    pub installed: Value,
    /// What the deployment has now.
    #[schema(value_type = Object)]
    pub customer: Value,
    /// What the new version sets.
    #[schema(value_type = Object)]
    pub package: Value,
}

/// An upgrade's merge.
#[derive(Debug, Clone)]
pub struct Merge {
    /// The new version with the customer's kept changes: a selection.
    pub bundle: Bundle,
    /// Properties both changed; the bundle carries the package's value.
    pub conflicts: Vec<Conflict>,
    /// `object.property` the customer changed and the package did not: kept.
    pub kept: Vec<String>,
    /// Objects the installed version had and the new one drops: left in
    /// place, no longer the package's.
    pub removed: Vec<String>,
}

/// T8-T3: a managed property that differs live from what the package set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct DriftItem {
    /// `entity` or `entity.attribute`.
    pub object: String,
    /// `changed`, or `missing` when the object is gone.
    pub change: String,
    pub property: Option<String>,
    #[schema(value_type = Object)]
    pub installed: Value,
    #[schema(value_type = Object)]
    pub live: Value,
}

/// The entity properties an upgrade merges and drift compares.
const ENTITY_PROPERTIES: [&str; 4] = [
    "display_name",
    "primary_name_attribute",
    "is_append_only",
    "extends",
];
/// The attribute properties an upgrade merges and drift compares: what a
/// package sets and provisioning does not fill in on its own.
const ATTRIBUTE_PROPERTIES: [&str; 7] = [
    "display_name",
    "field_type",
    "is_required",
    "is_sensitive",
    "lookup_entity",
    "options",
    "max_length",
];

fn as_value<T: Serialize>(item: &T) -> Value {
    serde_json::to_value(item).unwrap_or(Value::Null)
}

/// Merges one object's `properties` into `package` (its new definition).
fn merge_object(
    object: &str,
    properties: &[&str],
    installed: Option<&Value>,
    customer: Option<&Value>,
    package: &mut Value,
    out: &mut Merge,
) {
    let Some(customer) = customer else {
        return;
    };
    for &property in properties {
        let c = customer.get(property).cloned().unwrap_or(Value::Null);
        let p = package.get(property).cloned().unwrap_or(Value::Null);
        let i = installed.map(|i| i.get(property).cloned().unwrap_or(Value::Null));
        // A property the installed version left unset is not compared:
        // provisioning may have filled it in.
        if i.as_ref().is_some_and(Value::is_null) {
            continue;
        }
        let changed_by_customer = match &i {
            Some(i) => c != *i,
            None => c != p,
        };
        if !changed_by_customer || c == p {
            continue;
        }
        if i.as_ref() == Some(&p) {
            if let Some(slot) = package.get_mut(property) {
                *slot = c;
            }
            out.kept.push(format!("{object}.{property}"));
        } else {
            out.conflicts.push(Conflict {
                object: object.to_owned(),
                property: property.to_owned(),
                installed: i.unwrap_or(Value::Null),
                customer: c,
                package: p,
            });
        }
    }
}

/// T8-T3: the three-way merge of an upgrade: `installed` (the version the
/// deployment has), `package` (the new version) and `live` (the deployment
/// now, the customer's layer included). Pure.
pub fn three_way(installed: &Bundle, package: &Bundle, live: &Bundle) -> Result<Merge, String> {
    let mut out = Merge {
        bundle: package.clone(),
        conflicts: Vec::new(),
        kept: Vec::new(),
        removed: Vec::new(),
    };
    let mut entities = Vec::with_capacity(package.entities.len());
    for entity in &package.entities {
        let name = &entity.logicalname;
        let old = installed.entities.iter().find(|e| &e.logicalname == name);
        let now = live.entities.iter().find(|e| &e.logicalname == name);
        let mut merged = as_value(entity);
        merge_object(
            name,
            &ENTITY_PROPERTIES,
            old.map(as_value).as_ref(),
            now.map(as_value).as_ref(),
            &mut merged,
            &mut out,
        );
        let mut attributes = Vec::with_capacity(entity.attributes.len());
        for attr in &entity.attributes {
            let object = format!("{name}.{}", attr.logicalname);
            let old_attr = old.and_then(|o| {
                o.attributes
                    .iter()
                    .find(|a| a.logicalname == attr.logicalname)
            });
            let live_attr = now.and_then(|n| {
                n.attributes
                    .iter()
                    .find(|a| a.logicalname == attr.logicalname)
            });
            let mut value = as_value(attr);
            merge_object(
                &object,
                &ATTRIBUTE_PROPERTIES,
                old_attr.map(as_value).as_ref(),
                live_attr.map(as_value).as_ref(),
                &mut value,
                &mut out,
            );
            attributes.push(value);
        }
        if let Some(old) = old {
            for attr in &old.attributes {
                if !entity
                    .attributes
                    .iter()
                    .any(|a| a.logicalname == attr.logicalname)
                {
                    out.removed.push(format!("{name}.{}", attr.logicalname));
                }
            }
        }
        merged["attributes"] = Value::Array(attributes);
        entities.push(
            serde_json::from_value(merged).map_err(|e| format!("merging entity {name}: {e}"))?,
        );
    }
    for entity in &installed.entities {
        if !package
            .entities
            .iter()
            .any(|e| e.logicalname == entity.logicalname)
        {
            out.removed.push(entity.logicalname.clone());
        }
    }
    out.bundle.entities = entities;
    out.bundle.partial = true;
    Ok(out)
}

/// T8-T3: every managed property that differs live from what `installed`
/// set, and every object of it gone. Pure.
pub fn package_drift(installed: &Bundle, live: &Bundle) -> Vec<DriftItem> {
    fn compare(
        object: &str,
        properties: &[&str],
        installed: &Value,
        live: &Value,
        out: &mut Vec<DriftItem>,
    ) {
        for &property in properties {
            let i = installed.get(property).cloned().unwrap_or(Value::Null);
            let l = live.get(property).cloned().unwrap_or(Value::Null);
            if !i.is_null() && i != l {
                out.push(DriftItem {
                    object: object.to_owned(),
                    change: "changed".to_owned(),
                    property: Some(property.to_owned()),
                    installed: i,
                    live: l,
                });
            }
        }
    }
    let missing = |object: String| DriftItem {
        object,
        change: "missing".to_owned(),
        property: None,
        installed: Value::Bool(true),
        live: Value::Null,
    };
    let mut out = Vec::new();
    for entity in &installed.entities {
        let name = &entity.logicalname;
        let Some(now) = live.entities.iter().find(|e| &e.logicalname == name) else {
            out.push(missing(name.clone()));
            continue;
        };
        compare(
            name,
            &ENTITY_PROPERTIES,
            &as_value(entity),
            &as_value(now),
            &mut out,
        );
        for attr in &entity.attributes {
            let object = format!("{name}.{}", attr.logicalname);
            match now
                .attributes
                .iter()
                .find(|a| a.logicalname == attr.logicalname)
            {
                Some(live_attr) => compare(
                    &object,
                    &ATTRIBUTE_PROPERTIES,
                    &as_value(attr),
                    &as_value(live_attr),
                    &mut out,
                ),
                None => out.push(missing(object)),
            }
        }
    }
    out
}

/// The entities a package owns: those of `installed` named with its
/// namespace. Pure.
pub fn owned_entities(installed: &Bundle, namespace: &str) -> Vec<String> {
    let prefix = format!("{namespace}_");
    installed
        .entities
        .iter()
        .filter(|e| e.logicalname.starts_with(&prefix))
        .map(|e| e.logicalname.clone())
        .collect()
}

/// T8-T3: `live` without what the package owns: its entities, with their
/// views and queries, and the attributes it added to entities it does not
/// own. Planned with retiring allowed, it retires exactly those. Pure.
pub fn without_package(live: &Bundle, installed: &Bundle, namespace: &str) -> Bundle {
    let prefix = format!("{namespace}_");
    let owned = owned_entities(installed, namespace);
    let mut out = live.clone();
    out.partial = false;
    out.entities.retain(|e| !owned.contains(&e.logicalname));
    for entity in &mut out.entities {
        let added: Vec<&str> = installed
            .entities
            .iter()
            .filter(|e| e.logicalname == entity.logicalname)
            .flat_map(|e| e.attributes.iter())
            .filter(|a| a.logicalname.starts_with(&prefix))
            .map(|a| a.logicalname.as_str())
            .collect();
        entity
            .attributes
            .retain(|a| !added.contains(&a.logicalname.as_str()));
    }
    out.views.retain(|v| !owned.contains(&v.entity));
    out.queries
        .retain(|q| q.entity.as_ref().is_none_or(|e| !owned.contains(e)));
    out
}

/// The bytes a package's signature covers: the canonical JSON of its
/// format, manifest and bundle hash, and (T3-T2) each file's SHA-256 when it
/// carries files, so a package without files signs exactly as before.
pub fn signing_payload(
    format: &str,
    manifest: &Manifest,
    bundle: &Bundle,
    files: &BTreeMap<String, String>,
) -> Result<Vec<u8>, String> {
    let manifest = serde_json::to_value(manifest).map_err(|e| e.to_string())?;
    let mut doc = json!({
        "format": format,
        "manifest": manifest,
        "bundle_sha256": bundle_hash(bundle),
    });
    if !files.is_empty() {
        doc["files_sha256"] = files_digest(files);
    }
    attome_model::canonical::canonicalize(&doc).map(String::into_bytes)
}

/// Signs `package` with the publisher's key.
pub fn sign(package: &mut Package, key: &SigningKey) -> Result<(), String> {
    let payload = signing_payload(
        &package.format,
        &package.manifest,
        &package.bundle,
        &package.files,
    )?;
    let signature = key.sign(&payload);
    package.signature =
        Some(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()));
    Ok(())
}

/// T8-T4: the signing key a publisher's key file holds, a base64 32-byte
/// Ed25519 seed.
fn key_from_seed(seed_b64: &str) -> Result<SigningKey, String> {
    let seed: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(seed_b64.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("the signing key is not a 32-byte base64 Ed25519 seed")?;
    Ok(SigningKey::from_bytes(&seed))
}

/// T8-T4: signs `package` with the key in a publisher's key file.
pub fn sign_with_seed(package: &mut Package, seed_b64: &str) -> Result<(), String> {
    sign(package, &key_from_seed(seed_b64)?)
}

/// T8-T4: the base64 public key of a publisher's key file, the value a
/// target trusts the publisher by.
pub fn public_key_of(seed_b64: &str) -> Result<String, String> {
    let key = key_from_seed(seed_b64)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes()))
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
    let payload = signing_payload(
        &package.format,
        &package.manifest,
        &package.bundle,
        &package.files,
    )?;
    key.verify(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| "the signature does not match the package".to_owned())
}

/// T8-T5 (V2-D1811): the publisher the built-in modules (Sales, Service,
/// GRC, the verticals) are packaged under. Its packages keep the platform's
/// own unprefixed names (`account`, `opportunity`, `service_ticket`), so
/// the namespace rule does not apply to them, and nobody else may claim it.
pub const PLATFORM_PUBLISHER: &str = "Attome";

/// The package ids reserved to [`PLATFORM_PUBLISHER`].
pub const PLATFORM_ID_PREFIX: &str = "com.attome.";

/// The base64 Ed25519 key the platform's packages are signed with, carried
/// by the binary. `None` until the owner publishes it under the release-key
/// custody (`docs/release-signing.md`): until then no package that claims
/// the platform publisher or a reserved id is accepted, whoever a
/// deployment trusts.
pub const PLATFORM_RELEASE_KEY: Option<&str> = None;

/// Whether `manifest` claims the platform publisher or a reserved id.
pub fn claims_platform(manifest: &Manifest) -> bool {
    manifest
        .publisher
        .trim()
        .eq_ignore_ascii_case(PLATFORM_PUBLISHER)
        || manifest.id.starts_with(PLATFORM_ID_PREFIX)
}

/// Who vouches for a verified package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// A publisher the deployment trusts; the namespace rule applies.
    Publisher,
    /// The platform release key: a built-in module, exempt from the
    /// namespace rule.
    Platform,
}

/// [`verify`], but a package claiming the platform publisher or a reserved
/// id verifies only against the platform release key, never against a key
/// a deployment lists for that name.
pub fn verify_trust(package: &Package, trusted: &[(String, String)]) -> Result<Trust, String> {
    verify_trust_with(package, trusted, PLATFORM_RELEASE_KEY)
}

fn verify_trust_with(
    package: &Package,
    trusted: &[(String, String)],
    platform_key: Option<&str>,
) -> Result<Trust, String> {
    if claims_platform(&package.manifest) {
        let key = platform_key.ok_or(
            "the Attome publisher and com.attome. package ids are reserved for packages signed \
             by the platform release key, which this build does not carry",
        )?;
        verify(
            package,
            &[(package.manifest.publisher.clone(), key.to_owned())],
        )?;
        return Ok(Trust::Platform);
    }
    verify(package, trusted)?;
    Ok(Trust::Publisher)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// V2-D1811: only the platform release key admits the reserved
    /// publisher; a deployment trusting the name gains nothing.
    #[test]
    fn the_platform_publisher_needs_the_release_key() {
        let release = SigningKey::from_bytes(&[7; 32]);
        let release_pub =
            base64::engine::general_purpose::STANDARD.encode(release.verifying_key().to_bytes());
        let mut package = Package {
            format: PACKAGE_FORMAT.into(),
            manifest: Manifest {
                id: "com.attome.sales".into(),
                publisher: PLATFORM_PUBLISHER.into(),
                namespace: "sales".into(),
                ..manifest()
            },
            bundle: bundle(),
            files: BTreeMap::new(),
            signature: None,
        };
        sign(&mut package, &release).unwrap();
        // No release key in the build: refused, even when a deployment
        // lists the publisher with the very same key.
        let listed = vec![(PLATFORM_PUBLISHER.to_owned(), release_pub.clone())];
        assert!(verify_trust_with(&package, &listed, None).is_err());
        assert_eq!(
            verify_trust_with(&package, &[], Some(&release_pub)),
            Ok(Trust::Platform)
        );
        // Another key that claims the publisher is refused.
        let other = SigningKey::from_bytes(&[9; 32]);
        sign(&mut package, &other).unwrap();
        assert!(verify_trust_with(&package, &[], Some(&release_pub)).is_err());
        // A reserved id under another publisher's name is refused too.
        package.manifest.publisher = "Example Co".into();
        let example = vec![(
            "Example Co".to_owned(),
            base64::engine::general_purpose::STANDARD.encode(other.verifying_key().to_bytes()),
        )];
        assert!(verify_trust_with(&package, &example, None).is_err());
    }

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
            extension_points: Vec::new(),
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

    /// T3-T2: files are signed with the package; changing one breaks the
    /// signature, and a package without files signs as before.
    #[test]
    fn package_files_are_signed_and_checked() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let trusted = vec![(
            "Example Co".to_owned(),
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes()),
        )];
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let mut package = Package {
            format: PACKAGE_FORMAT.into(),
            manifest: manifest(),
            bundle: bundle(),
            files: BTreeMap::from([("gauge.js".to_owned(), b64("export {};"))]),
            signature: None,
        };
        sign(&mut package, &key).unwrap();
        assert_eq!(verify(&package, &trusted), Ok(()));
        package
            .files
            .insert("gauge.js".into(), b64("alert('changed')"));
        assert!(verify(&package, &trusted).is_err(), "a changed file");

        assert!(check_files(&package.files).is_ok());
        let bad = BTreeMap::from([
            ("../escape.js".to_owned(), b64("x")),
            ("run.exe".to_owned(), b64("x")),
            ("ok.js".to_owned(), "%%%".to_owned()),
        ]);
        let problems = check_files(&bad).unwrap_err();
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert_eq!(
            content_type_of("a/b.MJS"),
            Some("text/javascript; charset=utf-8")
        );
        let (hex, sri) = file_digest(b"export {};");
        assert_eq!(hex.len(), 64);
        assert!(sri.starts_with("sha256-"));
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
            files: BTreeMap::new(),
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

    #[test]
    fn a_managed_package_locks_its_own_and_opens_its_extension_points() {
        let existing = |name: &str| name == "account";
        let locks = managed_locks(&manifest(), &bundle(), &existing);
        assert_eq!(
            locks,
            vec![
                (
                    "entity".to_owned(),
                    "exf_vehicle".to_owned(),
                    "locked".to_owned()
                ),
                (
                    "attribute".to_owned(),
                    "account.exf_fleet_size".to_owned(),
                    "locked".to_owned()
                ),
            ]
        );
        let mut open = manifest();
        open.extension_points = vec!["exf_vehicle".into()];
        assert_eq!(managed_locks(&open, &bundle(), &existing)[0].2, "add_only");
        assert!(check_extension_points(&open, &bundle(), &existing).is_empty());
        open.extension_points = vec!["account".into()];
        assert_eq!(check_extension_points(&open, &bundle(), &existing).len(), 1);
        let mut unmanaged = manifest();
        unmanaged.mode = PackageMode::Unmanaged;
        assert!(managed_locks(&unmanaged, &bundle(), &existing).is_empty());
        // An empty list stays out of the signed form.
        assert!(
            serde_json::to_value(manifest())
                .unwrap()
                .get("extension_points")
                .is_none()
        );
    }

    #[test]
    fn an_upgrade_keeps_customer_changes_and_names_conflicts() {
        let installed = bundle();
        // The customer relabelled the plate and the fleet size, and added a
        // field to the vehicle.
        let mut live = bundle();
        live.entities[0].attributes[0].display_name = "Number plate".into();
        live.entities[1].attributes[0].display_name = "Fleet (vehicles)".into();
        let mut colour = live.entities[0].attributes[0].clone();
        colour.logicalname = "colour".into();
        live.entities[0].attributes.push(colour);
        // The new version relabels the fleet size too, adds a VIN and drops
        // nothing on the vehicle.
        let mut package = bundle();
        package.entities[1].attributes[0].display_name = "Fleet size".into();
        let mut vin = package.entities[0].attributes[0].clone();
        vin.logicalname = "vin".into();
        vin.display_name = "VIN".into();
        package.entities[0].attributes.push(vin);

        let merge = three_way(&installed, &package, &live).expect("merge");
        assert!(
            merge.bundle.partial,
            "a package never retires what it leaves out"
        );
        assert_eq!(
            merge.kept,
            vec!["exf_vehicle.plate.display_name".to_owned()]
        );
        assert_eq!(
            merge.bundle.entities[0].attributes[0].display_name,
            "Number plate"
        );
        assert_eq!(merge.bundle.entities[0].attributes[1].logicalname, "vin");
        assert_eq!(merge.conflicts.len(), 1, "{:?}", merge.conflicts);
        assert_eq!(merge.conflicts[0].object, "account.exf_fleet_size");
        assert_eq!(merge.conflicts[0].customer, json!("Fleet (vehicles)"));
        assert_eq!(
            merge.bundle.entities[1].attributes[0].display_name,
            "Fleet size"
        );
        assert!(merge.removed.is_empty());

        let mut smaller = bundle();
        smaller.entities.truncate(1);
        let merge = three_way(&installed, &smaller, &bundle()).expect("merge");
        assert_eq!(merge.removed, vec!["account".to_owned()]);
        assert!(merge.conflicts.is_empty() && merge.kept.is_empty());
    }

    #[test]
    fn drift_names_changed_and_missing_managed_parts() {
        assert!(package_drift(&bundle(), &bundle()).is_empty());
        let mut live = bundle();
        live.entities[0].attributes[0].field_type = "number".into();
        live.entities[1].attributes.clear();
        // Unset by the package: provisioning may fill it, so not drift.
        live.entities[0].primary_name_attribute = Some("plate".into());
        let drift = package_drift(&bundle(), &live);
        assert_eq!(drift.len(), 2, "{drift:?}");
        assert_eq!(drift[0].object, "exf_vehicle.plate");
        assert_eq!(drift[0].property.as_deref(), Some("field_type"));
        assert_eq!(drift[1].object, "account.exf_fleet_size");
        assert_eq!(drift[1].change, "missing");
    }

    #[test]
    fn uninstall_takes_out_only_what_the_package_owns() {
        let mut live = bundle();
        let mut own = live.entities[1].attributes[0].clone();
        own.logicalname = "industry".into();
        live.entities[1].attributes.push(own);
        let rest = without_package(&live, &bundle(), "exf");
        assert!(!rest.partial);
        assert_eq!(rest.entities.len(), 1);
        assert_eq!(rest.entities[0].logicalname, "account");
        assert_eq!(rest.entities[0].attributes.len(), 1);
        assert_eq!(rest.entities[0].attributes[0].logicalname, "industry");
        assert_eq!(
            owned_entities(&bundle(), "exf"),
            vec!["exf_vehicle".to_owned()]
        );
    }
}
