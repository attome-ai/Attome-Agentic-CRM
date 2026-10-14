//! Kind schema converters (roadmap Y1-T12): a document written in an older
//! shape is upgraded one version step at a time when it is cooked or loaded
//! from a file. The stored row is never rewritten; the next save writes the
//! current shape.

use attome_types::AppError;
use serde_json::Value;

use crate::kind::Kind;

/// Upgrades `doc` from schema version `from` to the kind's current one, one
/// step at a time through [`Kind::upgrade`]. A document newer than the
/// running kind is refused.
pub fn upgrade_to_current(kind: &dyn Kind, from: u32, doc: Value) -> Result<Value, AppError> {
    let current = kind.schema_version();
    if from > current {
        return Err(AppError::Validation(format!(
            "unsupported kind schema version: {} documents of version {from} are newer than this server's {current}",
            kind.name()
        )));
    }
    let mut doc = doc;
    for version in from..current {
        doc = kind.upgrade(version, doc)?;
    }
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::KindName;
    use crate::kind::{Artefact, CookInput, Issue, Reference, ValidationCtx};
    use serde_json::json;

    /// Version 1 had `title`; 2 renamed it `label`; 3 added `width`.
    struct Card;

    impl Kind for Card {
        fn name(&self) -> KindName {
            KindName("test_card")
        }
        fn schema_version(&self) -> u32 {
            3
        }
        fn json_schema(&self) -> Value {
            json!({})
        }
        fn validate_shape(&self, _doc: &Value) -> Result<(), Vec<Issue>> {
            Ok(())
        }
        fn references(&self, _doc: &Value) -> Vec<Reference> {
            Vec::new()
        }
        fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
            Vec::new()
        }
        fn cook(&self, _docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
            Ok(Vec::new())
        }
        fn upgrade(&self, from_version: u32, mut doc: Value) -> Result<Value, AppError> {
            match from_version {
                1 => {
                    let title = doc["title"].take();
                    doc["label"] = title;
                    if let Some(object) = doc.as_object_mut() {
                        object.remove("title");
                    }
                    Ok(doc)
                }
                2 => {
                    doc["width"] = json!(1);
                    Ok(doc)
                }
                other => Err(AppError::Validation(format!("no step from {other}"))),
            }
        }
        fn agent_tool_description(&self) -> &'static str {
            "a test card"
        }
    }

    #[test]
    fn v1_doc_upgrades_to_v3() {
        let upgraded = upgrade_to_current(&Card, 1, json!({ "title": "Hi" })).unwrap();
        assert_eq!(upgraded, json!({ "label": "Hi", "width": 1 }));
        assert_eq!(
            upgrade_to_current(&Card, 3, json!({ "label": "x" })).unwrap(),
            json!({ "label": "x" }),
            "a current document is unchanged"
        );
        assert!(
            upgrade_to_current(&Card, 4, json!({})).is_err(),
            "newer than the server"
        );
    }
}
