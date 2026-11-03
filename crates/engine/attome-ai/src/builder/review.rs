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
//!
//! AD7-T1: [`score_model`] scores a built entity from evidence read about it
//! (its data profile, where its attributes are used, slow statements) and
//! proposes fixes as drafts, never applying one:
//!
//! - `slow_filter`: slow statements filter on an attribute no index leads
//!   on; the fix makes it filterable, which builds the index;
//! - `rarely_filled`: an attribute filled in under 5% of profiled rows;
//! - `duplicate_values`: an identifier-like attribute (code, number, email,
//!   phone, reference) with repeated values; the fix is a duplicate rule;
//! - `few_values`: a text attribute holding a handful of values; the fix is
//!   an option set with them;
//! - `unused`: an attribute on no form and no view.
//!
//! Each issue costs points from 100 ([`ModelIssue::cost`]).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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

/// What [`score_model`] reads about one attribute.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct AttributeEvidence {
    pub name: String,
    pub id: Option<uuid::Uuid>,
    pub text: bool,
    pub filterable: bool,
    /// Profiled rows and how many had a value; `None` without a profile.
    pub rows: Option<i64>,
    pub filled: i64,
    /// Distinct values, and whether that count stopped at the profiler's cap.
    pub distinct: i64,
    pub distinct_capped: bool,
    /// The most common values, most common first.
    pub top_values: Vec<String>,
    /// Forms and views that show it.
    pub on_forms: i64,
    pub on_views: i64,
}

/// A slow statement group filtering on one attribute (the index advisor's).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SlowFilter {
    pub attribute: String,
    pub statements: i64,
    pub calls: i64,
    pub worst_mean_ms: f64,
}

/// One scored issue with its evidence and a fix to draft.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ModelIssue {
    pub code: &'static str,
    pub attribute: String,
    pub evidence: String,
    /// The change to draft in a Develop workspace; never applied here.
    pub fix: Value,
    pub cost: u32,
}

/// An entity's score, 0–100, and its issues, most costly first.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ModelScore {
    pub entity: String,
    pub score: u32,
    pub issues: Vec<ModelIssue>,
    /// Whether a data profile was read (without one, only usage and slow
    /// statements are judged).
    pub profiled: bool,
}

/// Rows a profile needs before fill and value counts are judged.
const MIN_ROWS: i64 = 50;
/// An attribute filled in under this share of rows is rarely filled.
const RARE_SHARE: f64 = 0.05;
/// A text attribute with at most this many values is an option set.
const FEW_VALUES: i64 = 12;

fn identifier_like(name: &str) -> bool {
    [
        "code",
        "number",
        "email",
        "phone",
        "reference",
        "_no",
        "_ref_no",
        "national_id",
    ]
    .iter()
    .any(|k| name == k.trim_start_matches('_') || name.ends_with(k))
}

/// Scores one entity from what was read about it. Pure.
pub fn score_model(
    entity: &str,
    entity_id: Option<uuid::Uuid>,
    attributes: &[AttributeEvidence],
    slow: &[SlowFilter],
) -> ModelScore {
    let field_route = |a: &AttributeEvidence| match (entity_id, a.id) {
        (Some(e), Some(f)) => format!("/api/v1/admin/entities/{e}/fields/{f}"),
        _ => format!("/api/v1/admin/entities ({entity}.{})", a.name),
    };
    let mut issues = Vec::new();
    for s in slow {
        let Some(a) = attributes.iter().find(|a| a.name == s.attribute) else {
            continue;
        };
        if a.filterable {
            continue;
        }
        issues.push(ModelIssue {
            code: "slow_filter",
            attribute: a.name.clone(),
            evidence: format!(
                "{} slow statement(s), {} call(s), up to {:.0} ms on average, filter on it without an index",
                s.statements, s.calls, s.worst_mean_ms
            ),
            fix: json!({ "method": "PATCH", "route": field_route(a), "body": { "is_filterable": true } }),
            cost: 10,
        });
    }
    for a in attributes {
        if let Some(rows) = a.rows.filter(|r| *r >= MIN_ROWS) {
            let share = a.filled as f64 / rows as f64;
            if share < RARE_SHARE {
                issues.push(ModelIssue {
                    code: "rarely_filled",
                    attribute: a.name.clone(),
                    evidence: format!("filled in {} of {rows} profiled rows", a.filled),
                    fix: json!({ "method": "PATCH", "route": field_route(a), "body": { "is_required": false },
                                 "note": "take it off the forms, or retire it if nobody needs it" }),
                    cost: 5,
                });
            }
            let duplicates = a.filled - a.distinct;
            if identifier_like(&a.name) && !a.distinct_capped && duplicates > 0 {
                issues.push(ModelIssue {
                    code: "duplicate_values",
                    attribute: a.name.clone(),
                    evidence: format!(
                        "{} filled value(s), {} distinct: {duplicates} repeat",
                        a.filled, a.distinct
                    ),
                    fix: json!({
                        "method": "POST",
                        "route": "/api/v1/admin/data/match-rules",
                        "body": {
                            "entity": entity,
                            "name": format!("{entity} {} repeats", a.name),
                            "fields": [{ "field": a.name, "comparator": "normalized", "weight": 1.0 }],
                            "threshold": 1.0,
                            "on_save": "warn",
                        },
                    }),
                    cost: 5,
                });
            } else if a.text
                && !a.distinct_capped
                && (2..=FEW_VALUES).contains(&a.distinct)
                && a.filled >= a.distinct * 10
            {
                issues.push(ModelIssue {
                    code: "few_values",
                    attribute: a.name.clone(),
                    evidence: format!(
                        "{} filled value(s) hold only {} distinct: {}",
                        a.filled,
                        a.distinct,
                        a.top_values.join(", ")
                    ),
                    fix: json!({
                        "method": "POST",
                        "route": entity_id.map_or_else(
                            || format!("/api/v1/admin/entities ({entity})"),
                            |e| format!("/api/v1/admin/entities/{e}/refactor/option-set-preview"),
                        ),
                        "body": { "source": a.name },
                        "note": "preview the options, then change the field's type to choice with the preview's conversion map",
                    }),
                    cost: 3,
                });
            }
        }
        if a.on_forms == 0 && a.on_views == 0 {
            issues.push(ModelIssue {
                code: "unused",
                attribute: a.name.clone(),
                evidence: "on no form and no view".to_owned(),
                fix: json!({ "method": "POST", "route": "/api/v1/actions/model.form.draft/invoke",
                             "body": { "entity": entity } }),
                cost: 2,
            });
        }
    }
    issues.sort_by(|a, b| {
        b.cost
            .cmp(&a.cost)
            .then_with(|| a.attribute.cmp(&b.attribute))
    });
    let lost: u32 = issues.iter().map(|i| i.cost).sum();
    ModelScore {
        entity: entity.to_owned(),
        score: 100u32.saturating_sub(lost),
        issues,
        profiled: attributes.iter().any(|a| a.rows.is_some()),
    }
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

    #[test]
    fn builder_review_scores_a_model_with_evidence() {
        let base = AttributeEvidence {
            rows: Some(1000),
            filled: 900,
            distinct: 900,
            on_forms: 1,
            on_views: 1,
            ..AttributeEvidence::default()
        };
        let attrs = vec![
            AttributeEvidence {
                name: "visit_date".into(),
                ..base.clone()
            },
            AttributeEvidence {
                name: "fax".into(),
                text: true,
                filled: 10,
                distinct: 10,
                ..base.clone()
            },
            AttributeEvidence {
                name: "patient_code".into(),
                text: true,
                distinct: 850,
                ..base.clone()
            },
            AttributeEvidence {
                name: "status_text".into(),
                text: true,
                distinct: 3,
                top_values: vec!["open".into(), "closed".into(), "held".into()],
                ..base.clone()
            },
            AttributeEvidence {
                name: "legacy_note".into(),
                on_forms: 0,
                on_views: 0,
                ..base.clone()
            },
        ];
        let slow = [SlowFilter {
            attribute: "visit_date".into(),
            statements: 2,
            calls: 400,
            worst_mean_ms: 250.0,
        }];
        let entity = uuid::Uuid::now_v7();
        let scored = score_model("visit", Some(entity), &attrs, &slow);
        let codes: Vec<(&str, &str)> = scored
            .issues
            .iter()
            .map(|i| (i.code, i.attribute.as_str()))
            .collect();
        assert_eq!(
            codes,
            vec![
                ("slow_filter", "visit_date"),
                ("rarely_filled", "fax"),
                ("duplicate_values", "patient_code"),
                ("few_values", "status_text"),
                ("unused", "legacy_note"),
            ]
        );
        assert_eq!(scored.score, 100 - 10 - 5 - 5 - 3 - 2);
        assert!(scored.profiled);
        assert!(scored.issues[1].evidence.contains("10 of 1000"));
        assert!(scored.issues[3].evidence.ends_with("open, closed, held"));
        assert_eq!(scored.issues[3].fix["body"]["source"], json!("status_text"));
        assert_eq!(
            scored.issues[2].fix["route"],
            json!("/api/v1/admin/data/match-rules")
        );

        // A small or missing profile judges only usage and slow statements.
        let unprofiled = AttributeEvidence {
            name: "fax".into(),
            rows: None,
            filled: 0,
            ..base
        };
        let scored = score_model("visit", None, &[unprofiled], &[]);
        assert_eq!(
            (scored.score, scored.issues.len(), scored.profiled),
            (100, 0, false)
        );
    }
}
