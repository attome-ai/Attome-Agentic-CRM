//! AD1-T1: the building agent's entity skill — what to do with each drafted
//! entity before anything is made.
//!
//! Given a draft (`model.draft`) and the deployment's entity library, each
//! drafted entity gets one decision:
//!
//! - **reuse** an entity the library already has under the same name (its
//!   new attributes are added to it);
//! - **extend** a base entity: `party` for a person-like entity (A1), or a
//!   library entity holding most of the draft's attributes;
//! - **ask** when a library entity's name or label is near the drafted one in
//!   English or Arabic (a typo, a plural, a spelling), so a person decides
//!   before a near-duplicate is made;
//! - otherwise **create** it.
//!
//! Attributes are checked the same way inside each entity: one near another
//! (or near one the reused or extended entity has) is asked about, not made.
//! The plan turns into the N12 build-tool calls ([`build_plan_calls`]), made
//! by a person's confirmation in their Develop workspace (V2-D27). Pure.

use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::actions::draft_model::DraftTable;

/// One entity of the deployment's library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryEntity {
    pub id: Uuid,
    pub name: String,
    pub label_en: String,
    pub label_ar: String,
    pub attributes: Vec<String>,
}

/// What to do with one drafted entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Create,
    Reuse {
        existing: String,
    },
    Extend {
        base: String,
        base_id: Uuid,
        why: String,
    },
    Ask {
        near: Vec<String>,
        question: String,
    },
}

/// One drafted entity's step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntityStep {
    pub entity: String,
    #[serde(flatten)]
    pub decision: Decision,
    /// Attributes to add (those not already there).
    pub add_attributes: Vec<String>,
    /// Attributes near another one, asked about instead of made.
    pub ask_attributes: Vec<AttributeQuestion>,
}

/// An attribute near another one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttributeQuestion {
    pub attribute: String,
    pub near: String,
}

/// Names of entities that are people, for which `party` is the base.
const PERSON_LIKE: [&str; 12] = [
    "person", "people", "customer", "client", "patient", "student", "member", "employee",
    "contact", "tenant", "trainee", "guest",
];

/// The share of a draft's attributes a library entity must already hold to
/// be proposed as its base.
const BASE_OVERLAP: f64 = 0.6;

/// An English name compared loosely: lower case, letters and digits only, a
/// trailing plural `s` (or `es`) dropped. Pure.
pub fn normalize_en(name: &str) -> String {
    let flat: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if let Some(stem) = flat.strip_suffix("ies").filter(|s| s.len() >= 3) {
        format!("{stem}y")
    } else if let Some(stem) = flat.strip_suffix("es").filter(|s| {
        s.len() >= 4
            && (s.ends_with("ss") || s.ends_with('x') || s.ends_with("ch") || s.ends_with("sh"))
    }) {
        stem.to_owned()
    } else if let Some(stem) = flat
        .strip_suffix('s')
        .filter(|s| s.len() >= 3 && !s.ends_with('s'))
    {
        stem.to_owned()
    } else {
        flat
    }
}

/// An Arabic label compared loosely: diacritics and tatweel dropped, alef
/// forms as bare alef, taa marbuta as haa, alef maqsura as yaa, the article
/// `ال` and spaces dropped. Pure.
pub fn normalize_ar(label: &str) -> String {
    let mut out = String::new();
    for word in label.split_whitespace() {
        let word = word
            .strip_prefix("ال")
            .filter(|w| w.chars().count() >= 2)
            .unwrap_or(word);
        for c in word.chars() {
            match c {
                '\u{064B}'..='\u{065F}' | '\u{0670}' | '\u{0640}' => {}
                'أ' | 'إ' | 'آ' | 'ٱ' => out.push('ا'),
                'ة' => out.push('ه'),
                'ى' => out.push('ي'),
                other => out.push(other),
            }
        }
    }
    out
}

/// Edit distance, bounded: `None` once it passes `max`. Pure.
fn distance_within(a: &str, b: &str, max: usize) -> Option<usize> {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > max {
        return None;
    }
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut previous = row[0];
        row[0] = i + 1;
        let mut lowest = row[0];
        for (j, cb) in b.iter().enumerate() {
            let substitute = previous + usize::from(ca != cb);
            previous = row[j + 1];
            row[j + 1] = substitute.min(row[j] + 1).min(row[j + 1] + 1);
            lowest = lowest.min(row[j + 1]);
        }
        if lowest > max {
            return None;
        }
    }
    (row[b.len()] <= max).then_some(row[b.len()])
}

/// Whether two normalised names are near but not equal: one edit apart for
/// names of five or more characters. Pure.
fn near(a: &str, b: &str) -> bool {
    a != b && a.chars().count() >= 5 && b.chars().count() >= 5 && distance_within(a, b, 1).is_some()
}

/// Whether two names, or their Arabic labels, are near. Pure.
fn names_near(a: &str, a_ar: &str, b: &str, b_ar: &str) -> bool {
    let (ea, eb) = (normalize_en(a), normalize_en(b));
    if near(&ea, &eb) || (ea == eb && a != b) {
        return true;
    }
    let (ra, rb) = (normalize_ar(a_ar), normalize_ar(b_ar));
    !ra.is_empty() && !rb.is_empty() && (ra == rb || near(&ra, &rb))
}

/// The plan for a draft against the library. Pure.
pub fn plan(draft: &[DraftTable], library: &[LibraryEntity]) -> Vec<EntityStep> {
    let party = library.iter().find(|e| e.name == "party");
    draft
        .iter()
        .map(|table| {
            let attributes: Vec<String> =
                table.attributes.iter().map(|a| a.name.clone()).collect();
            let decision = if let Some(same) = library.iter().find(|e| e.name == table.name) {
                Decision::Reuse {
                    existing: same.name.clone(),
                }
            } else {
                let close: Vec<String> = library
                    .iter()
                    .filter(|e| names_near(&table.name, &table.label_ar, &e.name, &e.label_ar))
                    .map(|e| e.name.clone())
                    .collect();
                if !close.is_empty() {
                    Decision::Ask {
                        question: format!(
                            "`{}` is close to {}; use one of those, or make it as a new entity?",
                            table.name,
                            close.iter().map(|c| format!("`{c}`")).collect::<Vec<_>>().join(", ")
                        ),
                        near: close,
                    }
                } else if let Some(party) =
                    party.filter(|_| PERSON_LIKE.contains(&normalize_en(&table.name).as_str()))
                {
                    Decision::Extend {
                        base: party.name.clone(),
                        base_id: party.id,
                        why: "a person-like entity extends party, which holds names, emails and phones"
                            .to_owned(),
                    }
                } else if let Some(base) = library.iter().find(|e| {
                    let shared = attributes.iter().filter(|a| e.attributes.contains(a)).count();
                    #[allow(
                        clippy::cast_precision_loss,
                        reason = "counts of attributes, far below f64's exact range"
                    )]
                    let share = shared as f64 / attributes.len().max(1) as f64;
                    shared >= 3 && share >= BASE_OVERLAP
                }) {
                    Decision::Extend {
                        base: base.name.clone(),
                        base_id: base.id,
                        why: format!("{} already holds most of these attributes", base.name),
                    }
                } else {
                    Decision::Create
                }
            };
            // The attributes the entity already has (reused or inherited).
            let have: Vec<String> = match &decision {
                Decision::Reuse { existing } | Decision::Extend { base: existing, .. } => library
                    .iter()
                    .find(|e| &e.name == existing)
                    .map(|e| e.attributes.clone())
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            let mut add = Vec::new();
            let mut ask = Vec::new();
            for attribute in &attributes {
                if have.contains(attribute) || add.contains(attribute) {
                    continue;
                }
                let close = have
                    .iter()
                    .chain(add.iter())
                    .find(|other| {
                        let (mine, theirs) = (normalize_en(attribute), normalize_en(other));
                        mine == theirs || near(&mine, &theirs)
                    })
                    .cloned();
                match close {
                    Some(near) => ask.push(AttributeQuestion {
                        attribute: attribute.clone(),
                        near,
                    }),
                    None => add.push(attribute.clone()),
                }
            }
            EntityStep {
                entity: table.name.clone(),
                decision,
                add_attributes: add,
                ask_attributes: ask,
            }
        })
        .collect()
}

/// The build-tool calls a plan makes: each entity to create or extend, then
/// each attribute to add; an asked entity makes nothing until answered. Pure.
pub fn build_plan_calls(draft: &[DraftTable], steps: &[EntityStep]) -> Vec<Value> {
    let mut calls = Vec::new();
    for step in steps {
        let label = draft
            .iter()
            .find(|t| t.name == step.entity)
            .map(|t| {
                if t.label_en.is_empty() {
                    t.name.clone()
                } else {
                    t.label_en.clone()
                }
            })
            .unwrap_or_else(|| step.entity.clone());
        match &step.decision {
            Decision::Create => calls.push(json!({
                "action": crate::actions::schema_build::ENTITY_CREATE,
                "args": { "logicalname": step.entity, "name": label },
            })),
            Decision::Extend { base_id, .. } => calls.push(json!({
                "action": crate::actions::schema_build::ENTITY_CREATE,
                "args": { "logicalname": step.entity, "name": label, "extends_entity_id": base_id },
            })),
            Decision::Reuse { .. } | Decision::Ask { .. } => {}
        }
    }
    for step in steps {
        let target = match &step.decision {
            Decision::Ask { .. } => continue,
            Decision::Reuse { existing } => existing.clone(),
            _ => step.entity.clone(),
        };
        let table = draft.iter().find(|t| t.name == step.entity);
        for attribute in &step.add_attributes {
            let field = table.and_then(|t| t.attributes.iter().find(|a| &a.name == attribute));
            let mut call = json!({
                "action": crate::actions::schema_build::ATTRIBUTE_CREATE,
                "args": {
                    "entity": target,
                    "logicalname": attribute,
                    "name": field.map_or(attribute.as_str(), |f| if f.label_en.is_empty() { f.name.as_str() } else { f.label_en.as_str() }),
                    "field_type": field.map_or("text", |f| f.field_type.as_str()),
                },
            });
            // A lookup names the entity it points to (AD5-T1).
            if let Some(r) = table.and_then(|t| {
                t.relationships
                    .iter()
                    .find(|r| r.kind == "many_to_one" && r.attribute.as_deref() == Some(attribute))
            }) {
                call["args"]["lookup_entity"] = json!(r.target);
            }
            calls.push(call);
        }
    }
    calls
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::draft_model::DraftField;

    fn table(name: &str, label_ar: &str, attributes: &[&str]) -> DraftTable {
        DraftTable {
            name: name.into(),
            label_en: String::new(),
            label_ar: label_ar.into(),
            attributes: attributes
                .iter()
                .map(|a| DraftField {
                    name: (*a).into(),
                    field_type: "text".into(),
                    label_en: String::new(),
                    label_ar: String::new(),
                    calendar: None,
                })
                .collect(),
            relationships: Vec::new(),
            sample_rows: Vec::new(),
        }
    }

    fn library() -> Vec<LibraryEntity> {
        let entity = |name: &str, ar: &str, attributes: &[&str]| LibraryEntity {
            id: Uuid::now_v7(),
            name: name.into(),
            label_en: name.into(),
            label_ar: ar.into(),
            attributes: attributes.iter().map(|a| (*a).into()).collect(),
        };
        vec![
            entity("party", "طرف", &["full_name", "email", "phone"]),
            entity(
                "invoice",
                "فاتورة",
                &["number", "total", "due_date", "customer"],
            ),
            entity("property", "عقار", &["address", "city"]),
        ]
    }

    #[test]
    fn names_compare_loosely_in_both_languages() {
        assert_eq!(normalize_en("Invoices"), "invoice");
        assert_eq!(normalize_en("Properties"), "property");
        assert_eq!(normalize_en("addresses"), "address");
        assert_eq!(normalize_ar("الفاتورة"), normalize_ar("فاتوره"));
        assert_eq!(normalize_ar("إدارة"), "اداره");
        assert!(near("invoice", "invoise"));
        assert!(!near("unit", "unix"), "short names are not compared");
    }

    #[test]
    fn the_library_is_searched_before_creating() {
        let steps = plan(
            &[
                table("invoice", "", &["number", "notes"]),
                table("properties", "", &["address"]),
                table("tenant", "مستأجر", &["full_name", "lease_start"]),
                table(
                    "invoice_line",
                    "",
                    &["number", "total", "due_date", "customer", "qty"],
                ),
                table("visit", "زيارة", &["visited_on"]),
            ],
            &library(),
        );
        assert_eq!(
            steps[0].decision,
            Decision::Reuse {
                existing: "invoice".into()
            }
        );
        assert_eq!(steps[0].add_attributes, vec!["notes"]);
        assert!(
            matches!(&steps[1].decision, Decision::Ask { near, .. } if near == &vec!["property".to_owned()])
        );
        assert!(matches!(&steps[2].decision, Decision::Extend { base, .. } if base == "party"));
        assert_eq!(
            steps[2].add_attributes,
            vec!["lease_start"],
            "full_name comes from party"
        );
        assert!(matches!(&steps[3].decision, Decision::Extend { base, .. } if base == "invoice"));
        assert_eq!(steps[4].decision, Decision::Create);
    }

    #[test]
    fn a_near_duplicate_attribute_is_asked_about() {
        let steps = plan(
            &[table("visit", "", &["visit_date", "visit_dates", "note"])],
            &library(),
        );
        assert_eq!(steps[0].add_attributes, vec!["visit_date", "note"]);
        assert_eq!(steps[0].ask_attributes[0].attribute, "visit_dates");
    }

    #[test]
    fn calls_make_what_the_plan_decided() {
        let draft = vec![
            table("visit", "", &["visited_on"]),
            table("properties", "", &["address"]),
        ];
        let steps = plan(&draft, &library());
        let calls = build_plan_calls(&draft, &steps);
        // The asked entity makes nothing; the new one its entity and field.
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["args"]["logicalname"], "visit");
        assert_eq!(calls[1]["args"]["entity"], "visit");
    }
}
