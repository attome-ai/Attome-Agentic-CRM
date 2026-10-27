//! A24-T3: the mapping a migration follows, from a source CRM's model
//! ([`super::migration_source::SourceModel`]) to this deployment's
//! entities. [`draft_mapping`] proposes one: each source entity is mapped
//! to an existing entity it names (directly or by a common CRM synonym:
//! `Opportunity`, `deals` and `Potentials` are `opportunity`), or created;
//! each field is mapped to an attribute of the same name, created, or
//! skipped when it is the source's own bookkeeping (ids, timestamps);
//! choice values are matched by name. The person then edits the draft as a
//! table (rename, point two fields at one attribute to merge them, skip,
//! change a created field's type), and [`validate_mapping`] says what in an
//! edited mapping cannot run. Pure: nothing here reads or writes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::migration_source::{SourceEntity, SourceField, SourceModel};

/// What happens to one source entity or field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MapAction {
    /// Into an entity or attribute that exists.
    Map,
    /// Into a new entity or attribute, created first.
    Create,
    /// Not migrated.
    Skip,
}

/// A source value and what it becomes; `target: None` for a value to add.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ValueMapping {
    pub source: String,
    pub target: Option<String>,
}

/// One source field.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AttributeMapping {
    pub source: String,
    pub source_label: String,
    /// The source's own type name.
    pub source_type: String,
    pub action: MapAction,
    /// The attribute's logical name (existing for `map`, new for `create`).
    pub target: String,
    /// The Attome field type: the attribute's own for `map`, the proposed
    /// one for `create` (which the person may change).
    pub field_type: String,
    /// A `map` whose source type does not fit the attribute's type.
    #[serde(default)]
    pub type_mismatch: bool,
    /// A lookup's target, by source entity name.
    #[serde(default)]
    pub lookup_target: Option<String>,
    #[serde(default)]
    pub choices: Vec<ValueMapping>,
}

/// One source entity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct EntityMapping {
    pub source: String,
    pub source_label: String,
    pub action: MapAction,
    /// The entity's logical name (existing for `map`, new for `create`).
    pub target: String,
    pub attributes: Vec<AttributeMapping>,
}

/// A whole migration's mapping. `users` and `roles` map the source's
/// people and roles to this deployment's; the drafts leave them empty, as
/// the source connectors do not list people yet, and the person fills them.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ModelMapping {
    pub entities: Vec<EntityMapping>,
    #[serde(default)]
    pub users: Vec<ValueMapping>,
    #[serde(default)]
    pub roles: Vec<ValueMapping>,
}

/// An entity of this deployment, as the draft sees it.
#[derive(Clone, Debug, PartialEq)]
pub struct TargetEntity {
    pub logicalname: String,
    pub attributes: Vec<TargetAttribute>,
}

/// An attribute of this deployment.
#[derive(Clone, Debug, PartialEq)]
pub struct TargetAttribute {
    pub logicalname: String,
    pub field_type: String,
    pub choices: Vec<String>,
}

/// Common CRM names for this platform's entities.
const ENTITY_SYNONYMS: &[(&str, &[&str])] = &[
    (
        "account",
        &[
            "account",
            "company",
            "organization",
            "organisation",
            "respartner",
            "customer",
        ],
    ),
    ("contact", &["contact", "person", "people"]),
    ("lead", &["lead", "crmlead", "prospect"]),
    ("opportunity", &["opportunity", "deal", "potential"]),
    ("case", &["case", "ticket", "incident", "helpdeskticket"]),
    (
        "product",
        &["product", "productproduct", "producttemplate", "item"],
    ),
    ("order", &["order", "salesorder", "saleorder"]),
    ("invoice", &["invoice", "accountmove"]),
    ("task", &["task", "projecttask", "activity"]),
    ("campaign", &["campaign"]),
];

/// The source's own bookkeeping, which is never migrated as a field.
const SKIPPED_FIELDS: &[&str] = &[
    "id",
    "systemmodstamp",
    "isdeleted",
    "createddate",
    "createdbyid",
    "lastmodifieddate",
    "lastmodifiedbyid",
    "createdon",
    "modifiedon",
    "createdby",
    "modifiedby",
    "versionnumber",
    "createtime",
    "modifiedtime",
    "writedate",
    "createdate",
    "writeuid",
    "createuid",
    "lastupdate",
    "hsobjectid",
    "hscreatedate",
    "hslastmodifieddate",
    "hsupdatedat",
];

/// Lower case, letters and digits only, a custom suffix (`__c`) and one
/// plural `s` dropped: `Account__c`, `accounts` and `ACCOUNT` meet. Pure.
pub fn normalise(name: &str) -> String {
    let base = name.strip_suffix("__c").unwrap_or(name);
    let mut out: String = base
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if out.len() > 3 && out.ends_with("ies") {
        out.truncate(out.len() - 3);
        out.push('y');
    } else if out.len() > 3 && out.ends_with('s') && !out.ends_with("ss") {
        out.pop();
    }
    out
}

/// A logical name for a created entity or attribute: lower snake case,
/// letters, digits and `_`, starting with a letter, at most 48 characters.
/// Pure.
pub fn logical_name(name: &str) -> String {
    let base = name.strip_suffix("__c").unwrap_or(name);
    let mut out = String::new();
    let mut prev_lower = false;
    for c in base.chars() {
        if c.is_ascii_uppercase() {
            if prev_lower {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
            prev_lower = false;
        } else if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        } else {
            if !out.ends_with('_') && !out.is_empty() {
                out.push('_');
            }
            prev_lower = false;
        }
    }
    let mut out = out.trim_matches('_').to_owned();
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    if !out.starts_with(|c: char| c.is_ascii_lowercase()) {
        out.insert_str(0, "x_");
    }
    out.truncate(48);
    out.trim_end_matches('_').to_owned()
}

/// Whether `name` can be an entity's or attribute's logical name.
pub fn valid_logical_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 48
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The existing entity a source entity names, directly or by synonym.
fn entity_target<'t>(
    source: &SourceEntity,
    targets: &'t [TargetEntity],
) -> Option<&'t TargetEntity> {
    let n = normalise(&source.name);
    let l = normalise(&source.label);
    let by_name = |name: &str| targets.iter().find(|t| normalise(&t.logicalname) == name);
    if let Some(t) = by_name(&n).or_else(|| by_name(&l)) {
        return Some(t);
    }
    ENTITY_SYNONYMS
        .iter()
        .find(|(_, words)| words.contains(&n.as_str()) || words.contains(&l.as_str()))
        .and_then(|(target, _)| targets.iter().find(|t| t.logicalname == *target))
}

/// Whether a source value of `source` type fits an attribute of `target` type.
fn fits(source: &str, target: &str) -> bool {
    source == target
        || matches!(
            (source, target),
            ("number" | "currency", "number" | "currency")
                | ("date", "date_time")
                | ("rich_text", "text")
                | (_, "text")
        )
}

fn map_choices(source: &SourceField, target: Option<&TargetAttribute>) -> Vec<ValueMapping> {
    source
        .choices
        .iter()
        .map(|value| ValueMapping {
            source: value.clone(),
            target: target.and_then(|t| {
                t.choices
                    .iter()
                    .find(|c| normalise(c) == normalise(value))
                    .cloned()
            }),
        })
        .collect()
}

fn draft_attribute(field: &SourceField, target: Option<&TargetEntity>) -> AttributeMapping {
    let n = normalise(&field.name);
    let existing = target.and_then(|t| {
        t.attributes.iter().find(|a| {
            normalise(&a.logicalname) == n || normalise(&a.logicalname) == normalise(&field.label)
        })
    });
    let (action, name, field_type, mismatch) = if SKIPPED_FIELDS.contains(&n.as_str()) {
        (
            MapAction::Skip,
            logical_name(&field.name),
            field.attome_type.to_owned(),
            false,
        )
    } else if let Some(a) = existing {
        (
            MapAction::Map,
            a.logicalname.clone(),
            a.field_type.clone(),
            !fits(&field.attome_type, &a.field_type),
        )
    } else {
        (
            MapAction::Create,
            logical_name(&field.name),
            field.attome_type.to_owned(),
            false,
        )
    };
    AttributeMapping {
        source: field.name.clone(),
        source_label: field.label.clone(),
        source_type: field.source_type.clone(),
        action,
        target: name,
        field_type,
        type_mismatch: mismatch,
        lookup_target: field.lookup_target.clone(),
        choices: map_choices(field, existing),
    }
}

/// The proposed mapping of `source` onto `targets`. Pure.
pub fn draft_mapping(source: &SourceModel, targets: &[TargetEntity]) -> ModelMapping {
    let mut taken: BTreeSet<String> = targets.iter().map(|t| t.logicalname.clone()).collect();
    let entities = source
        .entities
        .iter()
        .map(|e| {
            let target = entity_target(e, targets);
            let (action, name) = match target {
                Some(t) => (MapAction::Map, t.logicalname.clone()),
                None => {
                    // A created entity's name must not clash with another.
                    let base = logical_name(&e.name);
                    let mut name = base.clone();
                    let mut n = 2;
                    while taken.contains(&name) {
                        name = format!("{base}_{n}");
                        n += 1;
                    }
                    taken.insert(name.clone());
                    (MapAction::Create, name)
                }
            };
            EntityMapping {
                source: e.name.clone(),
                source_label: e.label.clone(),
                action,
                target: name,
                attributes: e
                    .fields
                    .iter()
                    .map(|f| draft_attribute(f, target))
                    .collect(),
            }
        })
        .collect();
    ModelMapping {
        entities,
        users: Vec::new(),
        roles: Vec::new(),
    }
}

/// What in `mapping` cannot run against `targets`, one sentence each; empty
/// when it can. Pure.
pub fn validate_mapping(mapping: &ModelMapping, targets: &[TargetEntity]) -> Vec<String> {
    let by_name: BTreeMap<&str, &TargetEntity> = targets
        .iter()
        .map(|t| (t.logicalname.as_str(), t))
        .collect();
    let mut problems = Vec::new();
    let mut created = BTreeSet::new();
    for e in &mapping.entities {
        let existing = by_name.get(e.target.as_str());
        match e.action {
            MapAction::Skip => continue,
            MapAction::Map if existing.is_none() => {
                problems.push(format!("{}: there is no entity {}", e.source, e.target));
            }
            MapAction::Create if !valid_logical_name(&e.target) => {
                problems.push(format!(
                    "{}: {} is not a valid entity name",
                    e.source, e.target
                ));
            }
            MapAction::Create if existing.is_some() || !created.insert(e.target.as_str()) => {
                problems.push(format!(
                    "{}: the entity {} already exists",
                    e.source, e.target
                ));
            }
            _ => {}
        }
        let mut new_fields = BTreeSet::new();
        for a in &e.attributes {
            let attr =
                existing.and_then(|t| t.attributes.iter().find(|x| x.logicalname == a.target));
            match a.action {
                MapAction::Skip => {}
                MapAction::Map if attr.is_none() => problems.push(format!(
                    "{}.{}: {} has no attribute {}",
                    e.source, a.source, e.target, a.target
                )),
                MapAction::Create if !valid_logical_name(&a.target) => problems.push(format!(
                    "{}.{}: {} is not a valid attribute name",
                    e.source, a.source, a.target
                )),
                MapAction::Create if attr.is_some() || !new_fields.insert(a.target.as_str()) => {
                    problems.push(format!(
                        "{}.{}: {} already has an attribute {}",
                        e.source, a.source, e.target, a.target
                    ));
                }
                _ => {}
            }
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, kind: &'static str, choices: &[&str]) -> SourceField {
        SourceField {
            name: name.into(),
            label: name.into(),
            source_type: kind.into(),
            attome_type: kind.into(),
            required: false,
            lookup_target: None,
            choices: choices.iter().map(|c| (*c).to_owned()).collect(),
            multi: false,
        }
    }

    fn fake_model() -> SourceModel {
        SourceModel {
            entities: vec![
                SourceEntity {
                    name: "Opportunity".into(),
                    label: "Opportunity".into(),
                    custom: false,
                    fields: vec![
                        field("Id", "text", &[]),
                        field("Name", "text", &[]),
                        field("Amount", "currency", &[]),
                        field("StageName", "choice", &["Prospecting", "Closed Won"]),
                        field("Probability", "number", &[]),
                    ],
                },
                SourceEntity {
                    name: "Vehicle__c".into(),
                    label: "Vehicles".into(),
                    custom: true,
                    fields: vec![field("PlateNumber__c", "text", &[])],
                },
            ],
        }
    }

    fn targets() -> Vec<TargetEntity> {
        vec![TargetEntity {
            logicalname: "opportunity".into(),
            attributes: vec![
                TargetAttribute {
                    logicalname: "name".into(),
                    field_type: "text".into(),
                    choices: vec![],
                },
                TargetAttribute {
                    logicalname: "amount".into(),
                    field_type: "currency".into(),
                    choices: vec![],
                },
                TargetAttribute {
                    logicalname: "stage_name".into(),
                    field_type: "choice".into(),
                    choices: vec!["prospecting".into(), "won".into()],
                },
                TargetAttribute {
                    logicalname: "probability".into(),
                    field_type: "date".into(),
                    choices: vec![],
                },
            ],
        }]
    }

    #[test]
    fn mapping_draft_maps_existing_creates_new_and_skips_bookkeeping() {
        let m = draft_mapping(&fake_model(), &targets());
        let opp = &m.entities[0];
        assert_eq!(
            (opp.action, opp.target.as_str()),
            (MapAction::Map, "opportunity")
        );
        let actions: Vec<(&str, MapAction, &str)> = opp
            .attributes
            .iter()
            .map(|a| (a.source.as_str(), a.action, a.target.as_str()))
            .collect();
        assert_eq!(
            actions,
            [
                ("Id", MapAction::Skip, "id"),
                ("Name", MapAction::Map, "name"),
                ("Amount", MapAction::Map, "amount"),
                ("StageName", MapAction::Map, "stage_name"),
                ("Probability", MapAction::Map, "probability"),
            ]
        );
        // A number into a date does not fit.
        assert!(opp.attributes[4].type_mismatch);
        assert!(!opp.attributes[2].type_mismatch);
        assert_eq!(
            opp.attributes[3].choices,
            [
                ValueMapping {
                    source: "Prospecting".into(),
                    target: Some("prospecting".into())
                },
                ValueMapping {
                    source: "Closed Won".into(),
                    target: None
                },
            ]
        );
        let vehicle = &m.entities[1];
        assert_eq!(
            (vehicle.action, vehicle.target.as_str()),
            (MapAction::Create, "vehicle")
        );
        assert_eq!(vehicle.attributes[0].target, "plate_number");
        assert_eq!(vehicle.attributes[0].action, MapAction::Create);
        assert!(validate_mapping(&m, &targets()).is_empty());
    }

    #[test]
    fn mapping_names_and_synonyms() {
        assert_eq!(logical_name("AnnualRevenue"), "annual_revenue");
        assert_eq!(logical_name("crm.lead"), "crm_lead");
        assert_eq!(logical_name("2nd Phone"), "x_2nd_phone");
        assert_eq!(normalise("Opportunities"), "opportunity");
        let deals = SourceEntity {
            name: "deals".into(),
            label: "Deals".into(),
            custom: false,
            fields: vec![],
        };
        assert_eq!(
            entity_target(&deals, &targets()).map(|t| t.logicalname.as_str()),
            Some("opportunity")
        );
    }

    #[test]
    fn mapping_validation_names_what_cannot_run() {
        let mut m = draft_mapping(&fake_model(), &targets());
        m.entities[0].attributes[1].target = "nickname".into();
        m.entities[1].target = "opportunity".into();
        m.entities[1].attributes[0].target = "Bad Name".into();
        let problems = validate_mapping(&m, &targets());
        assert_eq!(
            problems,
            [
                "Opportunity.Name: opportunity has no attribute nickname",
                "Vehicle__c: the entity opportunity already exists",
                "Vehicle__c.PlateNumber__c: Bad Name is not a valid attribute name",
            ]
        );
        // Two fields into one attribute is a merge, not an error.
        let mut merged = draft_mapping(&fake_model(), &targets());
        merged.entities[0].attributes[4].target = "amount".into();
        assert!(validate_mapping(&merged, &targets()).is_empty());
    }
}
