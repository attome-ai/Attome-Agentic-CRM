//! Three-step validation (roadmap Y1-T5).
//!
//! 1. **Edit** ([`validate_edit`]): the document's own shape, on every edit.
//!    Each kind checks its shape in Rust; `json_schema()` is only published.
//! 2. **Save** ([`validate_save`]): the shape, dangling references and the
//!    kind's own checks against what exists.
//! 3. **Publish** ([`validate_publish`]): every object of the version, every
//!    reference resolved within it, and every cross-object check registered
//!    on the [`KindRegistry`]. Any issue refuses the publish.
//!
//! Issue messages describe the document, never database state.

use std::collections::BTreeSet;
use std::sync::Arc;

use attome_db::Tx;
use attome_types::AppError;
use serde_json::{Value, json};

use crate::KindRegistry;
use crate::identity::{KindName, ObjectId, ObjectRef};
use crate::kind::{Issue, Kind, ValidationCtx};

/// Step one: the document's shape.
pub fn validate_edit(kind: &dyn Kind, doc: &Value) -> Vec<Issue> {
    kind.validate_shape(doc).err().unwrap_or_default()
}

/// A [`ValidationCtx`] over a known set of existing objects.
#[derive(Debug, Default, Clone)]
pub struct KnownObjects(pub BTreeSet<ObjectRef>);

impl ValidationCtx for KnownObjects {
    fn exists(&self, target: &ObjectRef) -> bool {
        self.0.contains(target)
    }
}

/// Step two without a database: the shape, references whose targets `ctx`
/// does not know, and the kind's own checks.
pub fn validate_save_with(kind: &dyn Kind, doc: &Value, ctx: &dyn ValidationCtx) -> Vec<Issue> {
    let mut issues = validate_edit(kind, doc);
    if !issues.is_empty() {
        return issues;
    }
    for reference in kind.references(doc) {
        if !ctx.exists(&reference.target) {
            issues.push(crate::references::dangling_issue(&reference.target));
        }
    }
    issues.extend(kind.check(doc, ctx));
    issues
}

/// Step two: as [`validate_save_with`], looking the references up in `tx`.
pub async fn validate_save(
    tx: &mut Tx<'_>,
    registry: &KindRegistry,
    kind: &dyn Kind,
    doc: &Value,
) -> Result<Vec<Issue>, AppError> {
    let refs = kind.references(doc);
    let missing = crate::references::missing_targets(tx, registry, &refs).await?;
    let known = KnownObjects(
        refs.iter()
            .map(|r| r.target)
            .filter(|target| !missing.contains(target))
            .collect(),
    );
    Ok(validate_save_with(kind, doc, &known))
}

/// One object of a version being published.
#[derive(Debug, Clone)]
pub struct VersionObject {
    pub kind: KindName,
    pub id: ObjectId,
    pub name: String,
    pub doc: Value,
    /// The kind schema version the document was written with.
    pub schema_version: u32,
}

/// Every object document of one version, plus the adapter-kind objects
/// (entities, attributes, ...) that exist outside the store.
#[derive(Debug, Clone, Default)]
pub struct VersionSet {
    pub objects: Vec<VersionObject>,
    pub external: BTreeSet<ObjectRef>,
}

impl VersionSet {
    fn known(&self) -> KnownObjects {
        let mut known = self.external.clone();
        known.extend(self.objects.iter().map(|o| ObjectRef {
            kind: o.kind,
            id: o.id,
        }));
        KnownObjects(known)
    }
}

/// A check across several objects of one version (a form naming a view that
/// must show the same entity, for example).
pub trait CrossCheck: Send + Sync + 'static {
    fn check(&self, set: &VersionSet) -> Vec<Issue>;
}

/// Cross-object checks, registered alongside the kinds.
#[derive(Default, Clone)]
pub struct CrossChecks(pub Vec<Arc<dyn CrossCheck>>);

impl std::fmt::Debug for CrossChecks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CrossChecks({})", self.0.len())
    }
}

/// Step three: every object, every reference within the version, every
/// cross check. `Err` carries every issue, each path prefixed with the
/// object it belongs to.
pub fn validate_publish(
    set: &VersionSet,
    registry: &KindRegistry,
    cross: &CrossChecks,
) -> Result<(), Vec<Issue>> {
    let known = set.known();
    let mut issues = Vec::new();
    for object in &set.objects {
        let prefix = format!("/{}/{}", object.kind, object.name);
        let Some(kind) = registry.get(object.kind.as_str()) else {
            issues.push(Issue::new(
                prefix,
                "unknown_kind",
                format!("no kind `{}`", object.kind),
            ));
            continue;
        };
        for issue in validate_save_with(kind.as_ref(), &object.doc, &known) {
            issues.push(Issue {
                path: format!("{prefix}{}", issue.path),
                ..issue
            });
        }
    }
    for check in &cross.0 {
        issues.extend(check.check(set));
    }
    if issues.is_empty() {
        Ok(())
    } else {
        Err(issues)
    }
}

/// A failed publish as a client-facing validation error: the issues as a
/// JSON list of `{path, code, message}`.
pub fn publish_error(issues: &[Issue]) -> AppError {
    let list: Vec<Value> = issues
        .iter()
        .map(|i| json!({ "path": i.path, "code": i.code, "message": i.message }))
        .collect();
    AppError::Validation(Value::Array(list).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kind::{Artefact, CookInput, RefMode, Reference};

    /// `{"title": "...", "uses": ["<uuid>"]}`; `uses` names `test_item` objects.
    struct Item;

    impl Kind for Item {
        fn name(&self) -> KindName {
            KindName("test_item")
        }
        fn schema_version(&self) -> u32 {
            1
        }
        fn json_schema(&self) -> Value {
            json!({ "type": "object" })
        }
        fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
            if doc["title"].is_string() {
                Ok(())
            } else {
                Err(vec![Issue::new(
                    "/title",
                    "required",
                    "a title is required",
                )])
            }
        }
        fn references(&self, doc: &Value) -> Vec<Reference> {
            doc["uses"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str()?.parse().ok())
                .map(|id| Reference {
                    target: ObjectRef {
                        kind: KindName("test_item"),
                        id: ObjectId(id),
                    },
                    mode: RefMode::Reads,
                })
                .collect()
        }
        fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
            Vec::new()
        }
        fn cook(&self, _docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
            Ok(Vec::new())
        }
        fn agent_tool_description(&self) -> &'static str {
            "a test item"
        }
    }

    struct NoDuplicateTitles;

    impl CrossCheck for NoDuplicateTitles {
        fn check(&self, set: &VersionSet) -> Vec<Issue> {
            let mut seen = BTreeSet::new();
            set.objects
                .iter()
                .filter(|o| !seen.insert(o.doc["title"].to_string()))
                .map(|o| {
                    Issue::new(
                        format!("/test_item/{}", o.name),
                        "duplicate_title",
                        "two items share a title",
                    )
                })
                .collect()
        }
    }

    struct Nothing;

    impl ValidationCtx for Nothing {
        fn exists(&self, _target: &ObjectRef) -> bool {
            false
        }
    }

    fn registry() -> KindRegistry {
        let mut registry = KindRegistry::default();
        registry.register(Arc::new(Item)).unwrap();
        registry
    }

    fn object(name: &str, doc: Value) -> VersionObject {
        VersionObject {
            kind: KindName("test_item"),
            id: ObjectId::new(),
            name: name.to_owned(),
            doc,
            schema_version: 1,
        }
    }

    #[test]
    fn bad_shape_rejected_at_edit() {
        assert_eq!(
            validate_edit(&Item, &json!({ "title": 1 }))[0].code,
            "required"
        );
        assert!(validate_edit(&Item, &json!({ "title": "ok" })).is_empty());
    }

    #[test]
    fn dangling_reference_reported_at_save() {
        let doc = json!({ "title": "a", "uses": [ObjectId::new().to_string()] });
        let issues = validate_save_with(&Item, &doc, &Nothing);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, "dangling_reference");
    }

    #[test]
    fn cross_object_issue_blocks_publish() {
        let first = object("first", json!({ "title": "same" }));
        let mut second = object("second", json!({ "title": "same" }));
        // A reference resolved inside the version is not dangling.
        second.doc["uses"] = json!([first.id.to_string()]);
        let set = VersionSet {
            objects: vec![first, second],
            external: BTreeSet::new(),
        };
        let cross = CrossChecks(vec![Arc::new(NoDuplicateTitles)]);
        let issues = validate_publish(&set, &registry(), &cross).unwrap_err();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, "duplicate_title");
        assert!(validate_publish(&set, &registry(), &CrossChecks::default()).is_ok());
        let error = publish_error(&issues);
        assert!(matches!(error, AppError::Validation(text) if text.contains("duplicate_title")));
    }
}
