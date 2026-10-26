//! The sharing rule kind (roadmap Q14-T2): records of one entity owned by a
//! unit, a team or the holders of a role are shared with another unit, team
//! or role, to read or to read and change.
//!
//! ```json
//! { "entity": "<entity id>",
//!   "source": { "type": "unit", "id": "<organization id>" },
//!   "target": { "type": "team", "id": "<team id>" },
//!   "level": "read",
//!   "description_en": "Riyadh's accounts for the Jeddah desk" }
//! ```
//!
//! A rule is a condition in the record filter, never a share row per record
//! (`attome_security::sharing_rules`): it costs nothing when records are
//! written and stops applying the moment it is unpublished. Explicit deny
//! shares still win over it. A rule whose source is a rule-language
//! condition is refused: the filter has no compiler from a condition to SQL
//! yet, and the plan says to refuse such a rule rather than approximate it.

use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::identity::{KindName, ObjectId, ObjectRef};
use crate::kind::{Artefact, CookInput, Issue, Kind, RefMode, Reference, ValidationCtx};
use crate::kinds::ENTITY;

/// The kind's name.
pub const SHARING_RULE: KindName = KindName("sharing_rule");

/// What a rule's records are picked by: their owning unit, their owning
/// team, or a user owner who holds the role.
pub const SOURCE_TYPES: [&str; 3] = ["unit", "team", "role"];

/// Who a rule shares with: members of a unit or a team, holders of a role.
pub const TARGET_TYPES: [&str; 3] = ["unit", "team", "role"];

/// What the people shared with may do.
pub const LEVELS: [&str; 2] = ["read", "write"];

const MAX_DESCRIPTION_CHARS: usize = 500;

/// One cooked rule, as the record filter reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookedSharingRule {
    pub id: Uuid,
    pub entity: Uuid,
    pub source_type: String,
    pub source_id: Uuid,
    pub target_type: String,
    pub target_id: Uuid,
    pub level: String,
}

/// The sharing rule kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct SharingRuleKind;

fn uuid_at(value: &Value) -> Option<Uuid> {
    value.as_str().and_then(|s| Uuid::parse_str(s).ok())
}

/// Checks one `{ "type", "id" }` end of a rule.
fn check_end(doc: &Value, key: &str, types: &[&str], issues: &mut Vec<Issue>) {
    let end = &doc[key];
    let Some(object) = end.as_object() else {
        issues.push(Issue::new(
            format!("/{key}"),
            "required",
            format!("{key} is an object with a type and an id"),
        ));
        return;
    };
    if key == "source" && object.contains_key("condition") {
        issues.push(Issue::new(
            "/source/condition",
            "not_compilable",
            "a sharing rule cannot pick records by a condition yet: the record filter has no \
             compiler from a condition to SQL; pick them by owning unit, team or role",
        ));
        return;
    }
    for name in object.keys() {
        if name != "type" && name != "id" {
            issues.push(Issue::new(
                format!("/{key}/{name}"),
                "unknown_property",
                format!("{key} has no `{name}`"),
            ));
        }
    }
    if !end["type"].as_str().is_some_and(|t| types.contains(&t)) {
        issues.push(Issue::new(
            format!("/{key}/type"),
            "invalid",
            format!("{key}.type is one of {}", types.join(", ")),
        ));
    }
    if uuid_at(&end["id"]).is_none() {
        issues.push(Issue::new(
            format!("/{key}/id"),
            "invalid",
            format!(
                "{key}.id is the id of the {}",
                end["type"].as_str().unwrap_or("unit")
            ),
        ));
    }
}

impl Kind for SharingRuleKind {
    fn name(&self) -> KindName {
        SHARING_RULE
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        let end = |types: &[&str]| {
            json!({
                "type": "object",
                "required": ["type", "id"],
                "additionalProperties": false,
                "properties": {
                    "type": { "enum": types },
                    "id": { "type": "string", "format": "uuid" }
                }
            })
        };
        json!({
            "type": "object",
            "required": ["entity", "source", "target", "level"],
            "additionalProperties": false,
            "properties": {
                "entity": { "type": "string", "format": "uuid" },
                "source": end(&SOURCE_TYPES),
                "target": end(&TARGET_TYPES),
                "level": { "enum": LEVELS },
                "description_en": { "type": "string", "maxLength": MAX_DESCRIPTION_CHARS },
                "description_ar": { "type": "string", "maxLength": MAX_DESCRIPTION_CHARS }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let Some(object) = doc.as_object() else {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "a sharing rule is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if ![
                "entity",
                "source",
                "target",
                "level",
                "description_en",
                "description_ar",
            ]
            .contains(&key.as_str())
            {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("a sharing rule has no `{key}`"),
                ));
            }
        }
        if uuid_at(&doc["entity"]).is_none() {
            issues.push(Issue::new(
                "/entity",
                "required",
                "entity is the id of the entity whose records are shared",
            ));
        }
        check_end(doc, "source", &SOURCE_TYPES, &mut issues);
        check_end(doc, "target", &TARGET_TYPES, &mut issues);
        if !doc["level"].as_str().is_some_and(|l| LEVELS.contains(&l)) {
            issues.push(Issue::new("/level", "invalid", "level is read or write"));
        }
        for key in ["description_en", "description_ar"] {
            if doc.get(key).is_some_and(|d| {
                d.as_str()
                    .is_none_or(|d| d.chars().count() > MAX_DESCRIPTION_CHARS)
            }) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "invalid",
                    "a description is text of at most 500 characters",
                ));
            }
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    fn references(&self, doc: &Value) -> Vec<Reference> {
        uuid_at(&doc["entity"])
            .map(|id| Reference {
                target: ObjectRef {
                    kind: ENTITY,
                    id: ObjectId(id),
                },
                mode: RefMode::Reads,
            })
            .into_iter()
            .collect()
    }

    fn check(&self, doc: &Value, ctx: &dyn ValidationCtx) -> Vec<Issue> {
        match uuid_at(&doc["entity"]) {
            Some(id)
                if !ctx.exists(&ObjectRef {
                    kind: ENTITY,
                    id: ObjectId(id),
                }) =>
            {
                vec![Issue::new("/entity", "not_found", "no such entity")]
            }
            _ => Vec::new(),
        }
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        docs.iter()
            .map(|input| {
                let doc = &input.doc;
                let field = |value: &Value, what: &str| {
                    uuid_at(value).ok_or_else(|| {
                        AppError::Validation(format!(
                            "sharing rule {}: {what} is not an id",
                            input.name
                        ))
                    })
                };
                let rule = CookedSharingRule {
                    id: input.id.0,
                    entity: field(&doc["entity"], "entity")?,
                    source_type: doc["source"]["type"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    source_id: field(&doc["source"]["id"], "source.id")?,
                    target_type: doc["target"]["type"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    target_id: field(&doc["target"]["id"], "target.id")?,
                    level: doc["level"].as_str().unwrap_or("read").to_owned(),
                };
                let text =
                    crate::canonical::canonicalize(&json!(rule)).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: SHARING_RULE,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Share one entity's records owned by a unit, a team or the holders of a role with another unit, team or role, to read or to read and change. A rule is part of the record filter (no share rows are written), an explicit deny still wins, and records cannot be picked by a condition yet."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> Value {
        json!({
            "entity": Uuid::nil().to_string(),
            "source": { "type": "unit", "id": Uuid::nil().to_string() },
            "target": { "type": "team", "id": Uuid::nil().to_string() },
            "level": "read"
        })
    }

    #[test]
    fn sharing_rule_shape_is_checked() {
        let kind = SharingRuleKind;
        assert!(kind.validate_shape(&rule()).is_ok());

        let mut bad = rule();
        bad["level"] = json!("delete");
        assert!(kind.validate_shape(&bad).is_err());

        let mut bad = rule();
        bad["target"]["type"] = json!("user");
        assert!(kind.validate_shape(&bad).is_err());

        let mut bad = rule();
        bad["source"]["id"] = json!("not-an-id");
        assert!(kind.validate_shape(&bad).is_err());
    }

    #[test]
    fn sharing_rule_with_a_condition_is_refused() {
        let mut doc = rule();
        doc["source"] = json!({ "condition": "industry == \"retail\"" });
        let issues = SharingRuleKind.validate_shape(&doc).unwrap_err();
        assert!(
            issues.iter().any(|i| i.code == "not_compilable"),
            "{issues:?}"
        );
    }

    #[test]
    fn sharing_rule_cooks_to_its_runtime_shape() {
        let id = ObjectId(Uuid::now_v7());
        let out = SharingRuleKind
            .cook(&[CookInput {
                id,
                name: "riyadh-to-jeddah".into(),
                doc: rule(),
            }])
            .unwrap();
        let cooked: CookedSharingRule = serde_json::from_slice(&out[0].payload).unwrap();
        assert_eq!(cooked.id, id.0);
        assert_eq!(cooked.source_type, "unit");
        assert_eq!(cooked.target_type, "team");
        assert_eq!(cooked.level, "read");
    }
}
