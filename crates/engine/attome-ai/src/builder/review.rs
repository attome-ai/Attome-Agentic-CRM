//! A1-T13 (part): checks on a drafted model before anyone builds it. A
//! draft (from a description or a spreadsheet) is entities with their
//! attributes and relationships; [`review`] returns findings and never
//! changes the draft:
//!
//! - `exists_already`: an entity the deployment already has;
//! - `extend_party`: a person-like entity (contact, customer, patient, ...)
//!   with name, email or phone attributes, which should extend the shared
//!   Party base instead of repeating its fields;
//! - `duplicate_attribute`: an attribute named twice on one entity;
//! - `naming`: an entity or attribute name that is not lower snake case of
//!   at most 63 characters, or a lookup not named `<target>_ref`;
//! - `unknown_target`: a relationship to an entity that is neither in the
//!   draft nor in the deployment;
//! - `relationship_direction`: a one-to-many declared on the parent; the
//!   lookup belongs on the child, as many-to-one.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// One drafted attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftAttribute {
    pub name: String,
    pub field_type: String,
}

/// One drafted relationship, from the entity that declares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftRelationship {
    pub target: String,
    /// `many_to_one` (a lookup on this entity) or `one_to_many`.
    pub kind: String,
    /// The lookup attribute, for a many-to-one.
    #[serde(default)]
    pub attribute: Option<String>,
}

/// One drafted entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftEntity {
    pub name: String,
    #[serde(default)]
    pub attributes: Vec<DraftAttribute>,
    #[serde(default)]
    pub relationships: Vec<DraftRelationship>,
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub entity: String,
    pub attribute: Option<String>,
    pub code: &'static str,
    pub message: String,
}

/// Names of entities that are people, which the Party base covers.
const PERSON_LIKE: [&str; 12] = [
    "person",
    "people",
    "contact",
    "customer",
    "client",
    "patient",
    "student",
    "employee",
    "member",
    "citizen",
    "applicant",
    "candidate",
];
const PERSON_FIELDS: [&str; 6] = [
    "name",
    "full_name",
    "first_name",
    "last_name",
    "email",
    "phone",
];

/// Whether `name` is lower snake case of at most 63 characters. Pure.
pub fn name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 63
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !name.ends_with('_')
        && !name.contains("__")
}

fn person_like(entity: &DraftEntity) -> bool {
    let name = entity.name.trim_end_matches('s');
    PERSON_LIKE
        .iter()
        .any(|p| name == *p || name.ends_with(&format!("_{p}")))
        && entity
            .attributes
            .iter()
            .any(|a| PERSON_FIELDS.contains(&a.name.as_str()))
}

/// The findings on `draft`, given the entities the deployment has. Pure.
pub fn review(draft: &[DraftEntity], existing: &HashSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let drafted: HashSet<&str> = draft.iter().map(|e| e.name.as_str()).collect();
    let finding =
        |entity: &str, attribute: Option<&str>, code: &'static str, message: String| Finding {
            entity: entity.to_owned(),
            attribute: attribute.map(str::to_owned),
            code,
            message,
        };
    for entity in draft {
        let e = entity.name.as_str();
        if existing.contains(e) {
            out.push(finding(
                e,
                None,
                "exists_already",
                format!("`{e}` exists already; extend it instead of creating it again"),
            ));
        }
        if !name_ok(e) {
            out.push(finding(
                e,
                None,
                "naming",
                format!("`{e}` is not a lower snake case name"),
            ));
        }
        if person_like(entity) {
            out.push(finding(e, None, "extend_party", format!("`{e}` describes people; extend Party instead of repeating its name, email and phone")));
        }
        let mut seen = HashSet::new();
        for attr in &entity.attributes {
            let a = attr.name.as_str();
            if !seen.insert(a) {
                out.push(finding(
                    e,
                    Some(a),
                    "duplicate_attribute",
                    format!("`{a}` is named twice on `{e}`"),
                ));
            }
            if !name_ok(a) {
                out.push(finding(
                    e,
                    Some(a),
                    "naming",
                    format!("`{a}` is not a lower snake case name"),
                ));
            }
        }
        for rel in &entity.relationships {
            let target = rel.target.as_str();
            if !drafted.contains(target) && !existing.contains(target) {
                out.push(finding(e, None, "unknown_target", format!("`{e}` relates to `{target}`, which neither the draft nor the deployment has")));
            }
            match rel.kind.as_str() {
                "one_to_many" => out.push(finding(
                    e,
                    None,
                    "relationship_direction",
                    format!("declare the lookup on `{target}` (many-to-one to `{e}`), not a one-to-many on `{e}`"),
                )),
                "many_to_one" => {
                    let want = format!("{target}_ref");
                    if rel.attribute.as_deref().is_some_and(|a| a != want) {
                        out.push(finding(
                            e,
                            rel.attribute.as_deref(),
                            "naming",
                            format!("a lookup to `{target}` is named `{want}`"),
                        ));
                    }
                }
                other => out.push(finding(e, None, "relationship_direction", format!("`{other}` is not many_to_one or one_to_many"))),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(name: &str) -> DraftAttribute {
        DraftAttribute {
            name: name.into(),
            field_type: "text".into(),
        }
    }

    #[test]
    fn review_names_existing_people_duplicates_and_directions() {
        let draft = vec![
            DraftEntity {
                name: "patients".into(),
                attributes: vec![attr("full_name"), attr("phone"), attr("phone")],
                relationships: vec![DraftRelationship {
                    target: "clinic".into(),
                    kind: "many_to_one".into(),
                    attribute: Some("clinic".into()),
                }],
            },
            DraftEntity {
                name: "clinic".into(),
                attributes: vec![attr("Name")],
                relationships: vec![
                    DraftRelationship {
                        target: "patients".into(),
                        kind: "one_to_many".into(),
                        attribute: None,
                    },
                    DraftRelationship {
                        target: "region".into(),
                        kind: "many_to_one".into(),
                        attribute: None,
                    },
                ],
            },
            DraftEntity {
                name: "account".into(),
                attributes: vec![],
                relationships: vec![],
            },
        ];
        let existing: HashSet<String> = ["account".to_owned()].into();
        let codes: Vec<(String, &str)> = review(&draft, &existing)
            .into_iter()
            .map(|f| (f.entity, f.code))
            .collect();
        for want in [
            ("patients", "extend_party"),
            ("patients", "duplicate_attribute"),
            ("patients", "naming"),
            ("clinic", "naming"),
            ("clinic", "relationship_direction"),
            ("clinic", "unknown_target"),
            ("account", "exists_already"),
        ] {
            assert!(
                codes.contains(&(want.0.to_owned(), want.1)),
                "{want:?} in {codes:?}"
            );
        }
        assert!(
            name_ok("work_order_2") && !name_ok("WorkOrder") && !name_ok("a__b") && !name_ok("_x")
        );
    }
}
