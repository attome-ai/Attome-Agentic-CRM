//! One readable text file per object (roadmap Y1-T10), for review in a pull
//! request and for moving metadata between deployments.
//!
//! An object is written to `<kind>/<app>/<name>.json`: pretty JSON with keys
//! in a stable (sorted) order and a trailing newline, holding the object's
//! kind, app, name, schema version and document. Reading a file upgrades a
//! document written in an older shape (Y1-T12).

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::KindRegistry;
use crate::identity::KindName;
use crate::kind::Issue;

/// An object as a file holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct FileObject {
    pub kind: KindName,
    pub app: String,
    pub name: String,
    /// The schema version of `doc` after any upgrade: the kind's current one.
    pub schema_version: u32,
    pub doc: Value,
}

/// A name usable as one path segment: letters, digits, `-`, `_` and `.`;
/// anything else becomes `_`.
fn segment(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned.starts_with('.') {
        format!("_{cleaned}")
    } else {
        cleaned
    }
}

/// The file for an object: its path relative to an export directory and its
/// text.
pub fn to_file(object: &FileObject) -> (PathBuf, String) {
    let path = Path::new(object.kind.as_str())
        .join(segment(&object.app))
        .join(format!("{}.json", segment(&object.name)));
    let body = json!({
        "kind": object.kind.as_str(),
        "app": object.app,
        "name": object.name,
        "schema_version": object.schema_version,
        "doc": object.doc,
    });
    let text = serde_json::to_string_pretty(&body).unwrap_or_default() + "\n";
    (path, text)
}

/// Reads an object file, upgrading its document to the kind's current shape.
pub fn from_file(registry: &KindRegistry, path: &Path, text: &str) -> Result<FileObject, Issue> {
    let where_ = path.display().to_string();
    let value: Value = serde_json::from_str(text)
        .map_err(|error| Issue::new(&where_, "not_json", format!("not JSON: {error}")))?;
    let kind_name = value["kind"]
        .as_str()
        .ok_or_else(|| Issue::new(&where_, "required", "the file names no kind"))?;
    let kind = registry
        .get(kind_name)
        .ok_or_else(|| Issue::new(&where_, "unknown_kind", format!("no kind `{kind_name}`")))?;
    let text_field = |key: &str| {
        value[key]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Issue::new(&where_, "required", format!("the file has no `{key}`")))
    };
    let app = text_field("app")?;
    let name = text_field("name")?;
    let from = value["schema_version"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| Issue::new(&where_, "required", "the file has no schema_version"))?;
    let doc = crate::upgrade::upgrade_to_current(kind.as_ref(), from, value["doc"].clone())
        .map_err(|error| Issue::new(&where_, "upgrade_failed", error.to_string()))?;
    Ok(FileObject {
        kind: kind.name(),
        app,
        name,
        schema_version: kind.schema_version(),
        doc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn registry() -> KindRegistry {
        let mut registry = KindRegistry::default();
        registry.register(Arc::new(crate::kinds::FormKind)).unwrap();
        registry
    }

    #[test]
    fn file_round_trip_is_identical() {
        let object = FileObject {
            kind: crate::kinds::FORM,
            app: "customer".into(),
            name: "Contact / main".into(),
            schema_version: 1,
            doc: json!({ "sections": [{ "label": "Main", "fields": [] }], "entity": "0190" }),
        };
        let (path, text) = to_file(&object);
        assert_eq!(
            path,
            Path::new("form")
                .join("customer")
                .join("Contact___main.json")
        );
        assert!(text.ends_with("}\n"));
        let back = from_file(&registry(), &path, &text).unwrap();
        assert_eq!(back, object);
        let (_, again) = to_file(&back);
        assert_eq!(again, text, "writing what was read gives the same bytes");
    }

    #[test]
    fn a_file_of_an_unknown_kind_is_an_issue() {
        let issue = from_file(&registry(), Path::new("x.json"), r#"{"kind": "nope"}"#).unwrap_err();
        assert_eq!(issue.code, "unknown_kind");
    }
}
