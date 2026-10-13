//! Closed `attome-changeset/v1` files read from `fleet.changesets_dir`
//! (design §6.4, owner answer Topic 17 Q3): the developer runs the source
//! tree, so the reviewed files are on disk. The console never builds a
//! changeset; it lists them, verifies each file's `checksum` with the same
//! JCS canonicalisation the customer's planner uses
//! (`attome_api::changeset::jcs::document_checksum`), and sends the
//! documents a target needs.
//!
//! Which files a customer gets: `platform` and `product` layers go to
//! everyone (the customer's planner answers `already_applied` for what its
//! ledger holds), a `project` layer only to the deployment whose
//! `project_code` matches its `scope` (case-insensitive), and a `customer`
//! layer never — that layer belongs to the customer's own admins.
//!
//! File reads are blocking I/O on a small directory; they run on
//! `spawn_blocking` (guidelines §10).

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use attome_types::AppError;

/// The changeset format this console sends.
const FORMAT: &str = "attome-changeset/v1";
/// Bound on how many files one listing reads.
const MAX_FILES: usize = 2_000;
/// Bound on one file's size.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Bound on directory depth (`platform/`, `product/<p>/`, `project/<code>/`).
const MAX_DEPTH: usize = 4;

/// One changeset file, as the console lists it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ChangesetFile {
    pub id: Uuid,
    pub layer: String,
    pub scope: String,
    pub seq: i64,
    pub name: String,
    pub title: String,
    pub checksum: String,
    /// Relative to `fleet.changesets_dir`, `/`-separated.
    pub path: String,
    /// The document's own checksum matches its content.
    pub checksum_ok: bool,
}

/// A reference stored on a rollout (`fleet_rollout.changesets`): never
/// the document body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize, ToSchema)]
pub struct ChangesetRef {
    pub id: Uuid,
    pub checksum: String,
    pub path: String,
}

impl From<&ChangesetFile> for ChangesetRef {
    fn from(file: &ChangesetFile) -> Self {
        Self {
            id: file.id,
            checksum: file.checksum.clone(),
            path: file.path.clone(),
        }
    }
}

/// Lists every changeset file under `dir`, sorted by layer order, scope and
/// `seq`. A file that is not a closed `attome-changeset/v1` document is
/// skipped (and logged), never fatal.
pub async fn list(dir: PathBuf) -> Result<Vec<ChangesetFile>, AppError> {
    tokio::task::spawn_blocking(move || list_blocking(&dir))
        .await
        .map_err(AppError::internal)?
}

/// Loads the documents for `refs`, re-verifying each checksum against the
/// file on disk now: a file edited after the rollout was started is refused
/// (`changeset_changed`), never sent.
pub async fn load_documents(dir: PathBuf, refs: Vec<ChangesetRef>) -> Result<Vec<Value>, AppError> {
    tokio::task::spawn_blocking(move || {
        refs.iter()
            .map(|r| load_one(&dir, r))
            .collect::<Result<Vec<_>, _>>()
    })
    .await
    .map_err(AppError::internal)?
}

/// The layers a deployment receives (module doc).
pub fn applies_to(layer: &str, scope: &str, project_code: &str) -> bool {
    match layer {
        "platform" | "product" => true,
        "project" => scope.eq_ignore_ascii_case(project_code),
        _ => false,
    }
}

fn layer_rank(layer: &str) -> u8 {
    match layer {
        "platform" => 0,
        "product" => 1,
        "project" => 2,
        _ => 3,
    }
}

fn list_blocking(dir: &Path) -> Result<Vec<ChangesetFile>, AppError> {
    let mut paths = Vec::new();
    collect(dir, 0, &mut paths)?;
    let mut files: Vec<ChangesetFile> = paths
        .iter()
        .filter_map(|path| match read_document(path) {
            Ok(document) => describe(dir, path, &document),
            Err(reason) => {
                tracing::warn!(path = %path.display(), %reason, "fleet: skipping a changeset file");
                None
            }
        })
        .collect();
    files.sort_by(|a, b| {
        layer_rank(&a.layer)
            .cmp(&layer_rank(&b.layer))
            .then_with(|| a.scope.cmp(&b.scope))
            .then_with(|| a.seq.cmp(&b.seq))
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(files)
}

fn collect(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<(), AppError> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && depth == 0 => {
            return Err(AppError::Validation(format!(
                "fleet.changesets_dir: {} does not exist",
                dir.display()
            )));
        }
        Err(e) => return Err(AppError::internal(e)),
    };
    for entry in entries {
        let entry = entry.map_err(AppError::internal)?;
        let file_type = entry.file_type().map_err(AppError::internal)?;
        let path = entry.path();
        if file_type.is_dir() {
            collect(&path, depth + 1, out)?;
        } else if file_type.is_file() && path.extension().is_some_and(|e| e == "json") {
            if out.len() >= MAX_FILES {
                return Err(AppError::Validation(format!(
                    "fleet.changesets_dir: more than {MAX_FILES} changeset files"
                )));
            }
            out.push(path);
        }
    }
    Ok(())
}

fn read_document(path: &Path) -> Result<Value, String> {
    let size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    if size > MAX_FILE_BYTES {
        return Err(format!("larger than {MAX_FILE_BYTES} bytes"));
    }
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn relative(dir: &Path, path: &Path) -> String {
    path.strip_prefix(dir)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn describe(dir: &Path, path: &Path, document: &Value) -> Option<ChangesetFile> {
    let text = |name: &str| document.get(name).and_then(Value::as_str);
    if text("format") != Some(FORMAT) || text("closed_at").is_none() {
        return None;
    }
    let id = text("id").and_then(|v| Uuid::parse_str(v).ok())?;
    let checksum = text("checksum")?.to_owned();
    let checksum_ok = attome_api::changeset::jcs::document_checksum(document)
        .is_ok_and(|computed| computed == checksum);
    Some(ChangesetFile {
        id,
        layer: text("layer")?.to_owned(),
        scope: text("scope")?.to_owned(),
        seq: document.get("seq").and_then(Value::as_i64).unwrap_or(0),
        name: text("name").unwrap_or_default().to_owned(),
        title: text("title").unwrap_or_default().to_owned(),
        checksum,
        path: relative(dir, path),
        checksum_ok,
    })
}

/// Resolves a stored relative path under `dir`, refusing any `..` or
/// absolute component (the path came from this console, but it is re-read
/// from the database).
fn resolve(dir: &Path, relative_path: &str) -> Result<PathBuf, AppError> {
    let mut path = dir.to_path_buf();
    for part in relative_path.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains(['\\', ':']) {
            return Err(AppError::Validation(format!(
                "changeset path {relative_path:?} is not a plain relative path"
            )));
        }
        path.push(part);
    }
    Ok(path)
}

fn load_one(dir: &Path, reference: &ChangesetRef) -> Result<Value, AppError> {
    let path = resolve(dir, &reference.path)?;
    let document = read_document(&path).map_err(|reason| {
        AppError::Validation(format!(
            "changeset {} ({}): cannot be read: {reason}",
            reference.id, reference.path
        ))
    })?;
    let id_matches = document
        .get("id")
        .and_then(Value::as_str)
        .and_then(|v| Uuid::parse_str(v).ok())
        == Some(reference.id);
    let computed =
        attome_api::changeset::jcs::document_checksum(&document).map_err(AppError::Validation)?;
    let stated = document.get("checksum").and_then(Value::as_str);
    if !id_matches || stated != Some(reference.checksum.as_str()) || computed != reference.checksum
    {
        return Err(AppError::Conflict(
            "changeset_changed: a changeset file no longer matches the checksum this rollout \
             recorded; start a new rollout",
        ));
    }
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closed(id: Uuid, layer: &str, scope: &str, seq: i64) -> Value {
        let mut document = serde_json::json!({
            "format": FORMAT,
            "id": id.to_string(),
            "layer": layer,
            "scope": scope,
            "seq": seq,
            "name": format!("cs-{seq}"),
            "title": "A test changeset",
            "requires": {},
            "author": "test",
            "closed_at": "2026-10-01T00:00:00Z",
            "operations": [],
        });
        let checksum = attome_api::changeset::jcs::document_checksum(&document).expect("checksum");
        document["checksum"] = Value::String(checksum);
        document
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("attome-fleet-{name}-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn write(dir: &Path, relative: &str, document: &Value) {
        let path = dir.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
        std::fs::write(path, serde_json::to_vec_pretty(document).expect("json")).expect("write");
    }

    #[test]
    fn layers_reach_the_right_customers() {
        assert!(applies_to("platform", "platform", "BMD"));
        assert!(applies_to("product", "crm", "BMD"));
        assert!(applies_to("project", "bmd", "BMD"));
        assert!(!applies_to("project", "xyz", "BMD"));
        assert!(!applies_to("customer", "bmd", "BMD"));
    }

    #[tokio::test]
    async fn listing_verifies_checksums_and_orders_by_layer_then_seq() {
        let dir = temp_dir("list");
        let (a, b, c) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        write(
            &dir,
            "project/bmd/0001.json",
            &closed(a, "project", "bmd", 1),
        );
        write(
            &dir,
            "platform/0002.json",
            &closed(b, "platform", "platform", 2),
        );
        let mut tampered = closed(c, "platform", "platform", 1);
        tampered["title"] = Value::String("edited after closing".into());
        write(&dir, "platform/0001.json", &tampered);
        write(
            &dir,
            "platform/notes.json",
            &serde_json::json!({"not": "a changeset"}),
        );

        let files = list(dir.clone()).await.expect("lists");
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(
            files.iter().map(|f| f.id).collect::<Vec<_>>(),
            vec![c, b, a],
            "platform before project, then seq"
        );
        assert!(!files[0].checksum_ok, "the edited file is flagged");
        assert!(files[1].checksum_ok);
        assert_eq!(files[2].path, "project/bmd/0001.json");
    }

    #[tokio::test]
    async fn loading_refuses_a_file_changed_after_the_rollout_recorded_it() {
        let dir = temp_dir("load");
        let id = Uuid::now_v7();
        let document = closed(id, "platform", "platform", 1);
        write(&dir, "platform/0001.json", &document);
        let reference = ChangesetRef {
            id,
            checksum: document["checksum"].as_str().expect("checksum").to_owned(),
            path: "platform/0001.json".into(),
        };
        let loaded = load_documents(dir.clone(), vec![reference.clone()])
            .await
            .expect("loads");
        assert_eq!(loaded[0]["id"], id.to_string());

        write(
            &dir,
            "platform/0001.json",
            &closed(id, "platform", "platform", 2),
        );
        let refused = load_documents(dir.clone(), vec![reference]).await;
        std::fs::remove_dir_all(&dir).ok();
        assert!(matches!(refused, Err(AppError::Conflict(_))));
    }

    #[test]
    fn stored_paths_cannot_escape_the_directory() {
        let dir = Path::new("changesets");
        assert!(resolve(dir, "platform/0001.json").is_ok());
        assert!(resolve(dir, "../secrets.json").is_err());
        assert!(resolve(dir, "platform/../../x.json").is_err());
        assert!(resolve(dir, "/etc/passwd").is_err());
        assert!(resolve(dir, "C:/x.json").is_err());
    }
}
