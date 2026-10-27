//! A24-T4 (part): what running a migration from its model mapping
//! ([`super::migration_mapping`]) does, pure. A run moves in waves: a full
//! load of every mapped entity, then catch-up loads of what changed at the
//! source since the last wave began, then a cut-over (a last catch-up while
//! the source is frozen). Each wave:
//!
//! 1. brings the metadata in line ([`metadata_steps`]): the entities and
//!    attributes the mapping creates, the choice values it adds, and on
//!    every target entity a key attribute holding the source's record id
//!    (an A29 external id, `{system}_id`), all as admin-API steps;
//! 2. loads each entity, dependencies first ([`load_order`]), through an
//!    A23 import whose mapping ([`import_mapping`]) writes each source field
//!    to its target and matches every lookup by the target's key attribute,
//!    so a link resolves whichever record arrived first;
//! 3. turns each source record into an import row ([`import_row`]): the
//!    source id in the key attribute, choice values translated.
//!
//! The job that drives the connectors through these, the history and owner
//! fields kept through migration mode, and the file copy are not here.

use std::collections::{BTreeMap, BTreeSet};

use attome_records::import_validate::{ColumnMap, ImportMapping, LookupBy, LookupMap};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::migration_mapping::{
    EntityMapping, MapAction, ModelMapping, TargetEntity, logical_name,
};
use super::migration_source::SourceRecord;

/// One wave of a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Wave {
    /// Every record.
    Full,
    /// What changed since `since` (when the previous wave began).
    CatchUp { since: DateTime<Utc> },
    /// The last catch-up, with the source frozen.
    CutOver { since: DateTime<Utc> },
}

impl Wave {
    /// The source read's `since`.
    pub fn since(self) -> Option<DateTime<Utc>> {
        match self {
            Wave::Full => None,
            Wave::CatchUp { since } | Wave::CutOver { since } => Some(since),
        }
    }
}

/// The wave after one that began at `previous_start`: a full load first,
/// catch-ups after, the cut-over when asked for. Pure.
pub fn next_wave(previous_start: Option<DateTime<Utc>>, cut_over: bool) -> Wave {
    match previous_start {
        None => Wave::Full,
        Some(since) if cut_over => Wave::CutOver { since },
        Some(since) => Wave::CatchUp { since },
    }
}

/// One metadata change, as the admin API makes it.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum MetadataStep {
    /// `POST /api/v1/admin/entities`.
    CreateEntity { logicalname: String, name: String },
    /// `POST /api/v1/admin/entities/{entity}/fields`.
    CreateAttribute {
        entity: String,
        logicalname: String,
        name: String,
        field_type: String,
        /// A lookup's target entity, by its logical name here.
        lookup_entity: Option<String>,
        options: Option<Value>,
    },
    /// `POST /api/v1/admin/entities/{entity}/fields/{field}/choices`.
    AddChoice {
        entity: String,
        attribute: String,
        value: String,
    },
}

/// The key attribute that holds a source record's id: `salesforce_id`.
pub fn key_attribute(system: &str) -> String {
    format!("{}_id", logical_name(system))
}

/// The entity a source entity's records go to, by source name.
fn targets_by_source(mapping: &ModelMapping) -> BTreeMap<&str, &str> {
    mapping
        .entities
        .iter()
        .filter(|e| e.action != MapAction::Skip)
        .map(|e| (e.source.as_str(), e.target.as_str()))
        .collect()
}

/// The metadata changes a wave needs before it loads, in order: created
/// entities, then on each target the key attribute (when missing) and the
/// created attributes, then the added choice values. A lookup whose target
/// entity the mapping does not migrate becomes a text field, holding the
/// source id. Pure.
pub fn metadata_steps(
    mapping: &ModelMapping,
    targets: &[TargetEntity],
    system: &str,
) -> Vec<MetadataStep> {
    let existing: BTreeMap<&str, &TargetEntity> = targets
        .iter()
        .map(|t| (t.logicalname.as_str(), t))
        .collect();
    let by_source = targets_by_source(mapping);
    let key = key_attribute(system);
    let live: Vec<&EntityMapping> = mapping
        .entities
        .iter()
        .filter(|e| e.action != MapAction::Skip)
        .collect();
    let mut steps: Vec<MetadataStep> = live
        .iter()
        .filter(|e| e.action == MapAction::Create)
        .map(|e| MetadataStep::CreateEntity {
            logicalname: e.target.clone(),
            name: e.source_label.clone(),
        })
        .collect();
    let mut choices = Vec::new();
    for e in &live {
        let target = existing.get(e.target.as_str());
        let has =
            |name: &str| target.is_some_and(|t| t.attributes.iter().any(|a| a.logicalname == name));
        if !has(&key) {
            steps.push(MetadataStep::CreateAttribute {
                entity: e.target.clone(),
                logicalname: key.clone(),
                name: format!("{system} id"),
                field_type: "text".into(),
                lookup_entity: None,
                options: Some(json!({ "external_id": { "system": system } })),
            });
        }
        let mut created = BTreeSet::new();
        for a in &e.attributes {
            match a.action {
                MapAction::Create if !has(&a.target) && created.insert(a.target.as_str()) => {
                    let lookup = a
                        .lookup_target
                        .as_deref()
                        .and_then(|t| by_source.get(t).copied());
                    let (field_type, lookup_entity) = match (a.field_type.as_str(), lookup) {
                        ("lookup", Some(t)) => ("lookup".to_owned(), Some(t.to_owned())),
                        ("lookup", None) => ("text".to_owned(), None),
                        (other, _) => (other.to_owned(), None),
                    };
                    let options = (field_type == "choice").then(|| {
                        json!({ "choices": a.choices.iter().map(|c| c.target.clone().unwrap_or_else(|| c.source.clone())).collect::<Vec<_>>() })
                    });
                    steps.push(MetadataStep::CreateAttribute {
                        entity: e.target.clone(),
                        logicalname: a.target.clone(),
                        name: a.source_label.clone(),
                        field_type,
                        lookup_entity,
                        options,
                    });
                }
                MapAction::Map => {
                    for c in a.choices.iter().filter(|c| c.target.is_none()) {
                        choices.push(MetadataStep::AddChoice {
                            entity: e.target.clone(),
                            attribute: a.target.clone(),
                            value: c.source.clone(),
                        });
                    }
                }
                _ => {}
            }
        }
    }
    steps.extend(choices);
    steps
}

/// The migrated source entities, each after the entities its lookups point
/// at (a cycle is broken where it closes: its links resolve by key on a
/// later wave). Pure.
pub fn load_order(mapping: &ModelMapping) -> Vec<String> {
    let live: BTreeMap<&str, &EntityMapping> = mapping
        .entities
        .iter()
        .filter(|e| e.action != MapAction::Skip)
        .map(|e| (e.source.as_str(), e))
        .collect();
    fn visit<'m>(
        name: &'m str,
        live: &BTreeMap<&'m str, &'m EntityMapping>,
        state: &mut BTreeMap<&'m str, bool>,
        out: &mut Vec<String>,
    ) {
        if state.contains_key(name) {
            return;
        }
        state.insert(name, false);
        if let Some(&e) = live.get(name) {
            for a in e.attributes.iter().filter(|a| a.action != MapAction::Skip) {
                if let Some(t) = a.lookup_target.as_deref()
                    && let Some((&dep, _)) = live.get_key_value(t)
                    && dep != name
                {
                    visit(dep, live, state, out);
                }
            }
        }
        state.insert(name, true);
        out.push(name.to_owned());
    }
    let mut state = BTreeMap::new();
    let mut out = Vec::new();
    for e in mapping
        .entities
        .iter()
        .filter(|e| e.action != MapAction::Skip)
    {
        visit(e.source.as_str(), &live, &mut state, &mut out);
    }
    out
}

/// The A23 import mapping of one entity's rows: the key attribute from the
/// row's `__source_id`, each field to its target, and each lookup to a
/// migrated entity matched by that entity's key attribute. Pure.
pub fn import_mapping(
    entity: &EntityMapping,
    mapping: &ModelMapping,
    system: &str,
) -> ImportMapping {
    let key = key_attribute(system);
    let migrated = targets_by_source(mapping);
    let mut columns = vec![ColumnMap {
        source: Some(SOURCE_ID.into()),
        target: Some(key.clone()),
        ..ColumnMap::default()
    }];
    let mut lookups = std::collections::HashMap::new();
    for a in entity
        .attributes
        .iter()
        .filter(|a| a.action != MapAction::Skip)
    {
        columns.push(ColumnMap {
            source: Some(a.source.clone()),
            target: Some(a.target.clone()),
            ..ColumnMap::default()
        });
        if a.field_type == "lookup"
            && a.lookup_target
                .as_deref()
                .is_some_and(|t| migrated.contains_key(t))
        {
            lookups.insert(
                a.target.clone(),
                LookupMap {
                    by: LookupBy::Key,
                    field: Some(key.clone()),
                },
            );
        }
    }
    ImportMapping {
        columns,
        lookups,
        create_missing: false,
    }
}

/// The import column that carries the source's record id.
pub const SOURCE_ID: &str = "__source_id";

/// One source record as an import row: its id under [`SOURCE_ID`], the
/// mapped fields (skipped ones left out), choice values translated to the
/// target's (a value to add keeps its source text). Pure.
pub fn import_row(record: &SourceRecord, entity: &EntityMapping) -> Map<String, Value> {
    let mut row = Map::new();
    row.insert(SOURCE_ID.into(), Value::String(record.id.clone()));
    for a in entity
        .attributes
        .iter()
        .filter(|a| a.action != MapAction::Skip)
    {
        let Some(value) = record.fields.get(&a.source) else {
            continue;
        };
        let translate = |v: &Value| match v.as_str() {
            Some(s) => a
                .choices
                .iter()
                .find(|c| c.source == s)
                .and_then(|c| c.target.clone())
                .map_or_else(|| v.clone(), Value::String),
            None => v.clone(),
        };
        let value = if a.choices.is_empty() {
            value.clone()
        } else {
            match value {
                // A multi-choice arrives as a list, or as `a;b` (Salesforce, Zoho).
                Value::Array(items) => Value::Array(items.iter().map(translate).collect()),
                Value::String(s) if s.contains(';') => Value::Array(
                    s.split(';')
                        .map(|p| translate(&Value::String(p.trim().to_owned())))
                        .collect(),
                ),
                other => translate(other),
            }
        };
        row.insert(a.source.clone(), value);
    }
    row
}

#[cfg(test)]
mod tests {
    use super::super::migration_mapping::{AttributeMapping, TargetAttribute, ValueMapping};
    use super::*;

    fn attr(source: &str, action: MapAction, target: &str, field_type: &str) -> AttributeMapping {
        AttributeMapping {
            source: source.into(),
            source_label: source.into(),
            source_type: field_type.into(),
            action,
            target: target.into(),
            field_type: field_type.into(),
            type_mismatch: false,
            lookup_target: None,
            choices: Vec::new(),
        }
    }

    fn mapping() -> ModelMapping {
        let mut parent = attr("AccountId", MapAction::Create, "account_ref", "lookup");
        parent.lookup_target = Some("Account".into());
        let mut stage = attr("StageName", MapAction::Map, "stage", "choice");
        stage.choices = vec![
            ValueMapping {
                source: "Closed Won".into(),
                target: Some("won".into()),
            },
            ValueMapping {
                source: "Parked".into(),
                target: None,
            },
        ];
        let mut owner = attr("OwnerId", MapAction::Create, "owner_source", "lookup");
        owner.lookup_target = Some("User".into());
        ModelMapping {
            entities: vec![
                EntityMapping {
                    source: "Opportunity".into(),
                    source_label: "Opportunity".into(),
                    action: MapAction::Map,
                    target: "opportunity".into(),
                    attributes: vec![
                        attr("Id", MapAction::Skip, "id", "text"),
                        attr("Name", MapAction::Map, "name", "text"),
                        stage,
                        parent,
                        owner,
                    ],
                },
                EntityMapping {
                    source: "Account".into(),
                    source_label: "Account".into(),
                    action: MapAction::Create,
                    target: "sf_account".into(),
                    attributes: vec![attr("Name", MapAction::Create, "name", "text")],
                },
                EntityMapping {
                    source: "Note".into(),
                    source_label: "Note".into(),
                    action: MapAction::Skip,
                    target: "note".into(),
                    attributes: vec![],
                },
            ],
            users: vec![],
            roles: vec![],
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
                    logicalname: "stage".into(),
                    field_type: "choice".into(),
                    choices: vec!["won".into()],
                },
            ],
        }]
    }

    #[test]
    fn waves_go_full_then_catch_up_then_cut_over() {
        let t = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(next_wave(None, false), Wave::Full);
        assert_eq!(next_wave(Some(t), false), Wave::CatchUp { since: t });
        assert_eq!(next_wave(Some(t), true).since(), Some(t));
        assert_eq!(Wave::Full.since(), None);
    }

    #[test]
    fn waves_metadata_creates_entities_keys_fields_and_choices() {
        let steps = metadata_steps(&mapping(), &targets(), "salesforce");
        let summary: Vec<String> = steps
            .iter()
            .map(|s| match s {
                MetadataStep::CreateEntity { logicalname, .. } => format!("entity {logicalname}"),
                MetadataStep::CreateAttribute {
                    entity,
                    logicalname,
                    field_type,
                    lookup_entity,
                    ..
                } => {
                    format!(
                        "field {entity}.{logicalname} {field_type} {}",
                        lookup_entity.as_deref().unwrap_or("-")
                    )
                }
                MetadataStep::AddChoice {
                    entity,
                    attribute,
                    value,
                } => format!("choice {entity}.{attribute} {value}"),
            })
            .collect();
        assert_eq!(
            summary,
            [
                "entity sf_account",
                "field opportunity.salesforce_id text -",
                "field opportunity.account_ref lookup sf_account",
                // The source's users are not migrated: the link keeps the source id as text.
                "field opportunity.owner_source text -",
                "field sf_account.salesforce_id text -",
                "field sf_account.name text -",
                "choice opportunity.stage Parked",
            ]
        );
        assert!(matches!(
            &steps[1],
            MetadataStep::CreateAttribute { options: Some(o), .. } if o["external_id"]["system"] == "salesforce"
        ));
    }

    #[test]
    fn waves_load_dependencies_first_and_match_links_by_key() {
        let m = mapping();
        assert_eq!(load_order(&m), ["Account", "Opportunity"]);
        let im = import_mapping(&m.entities[0], &m, "salesforce");
        let columns: Vec<(&str, &str)> = im
            .columns
            .iter()
            .map(|c| {
                (
                    c.source.as_deref().unwrap_or(""),
                    c.target.as_deref().unwrap_or(""),
                )
            })
            .collect();
        assert_eq!(
            columns,
            [
                ("__source_id", "salesforce_id"),
                ("Name", "name"),
                ("StageName", "stage"),
                ("AccountId", "account_ref"),
                ("OwnerId", "owner_source"),
            ]
        );
        assert_eq!(im.lookups["account_ref"].by, LookupBy::Key);
        assert_eq!(
            im.lookups["account_ref"].field.as_deref(),
            Some("salesforce_id")
        );
        assert!(!im.lookups.contains_key("owner_source"));
    }

    #[test]
    fn waves_rows_carry_the_source_id_and_translated_choices() {
        let m = mapping();
        let mut fields = Map::new();
        fields.insert("Name".into(), json!("Big deal"));
        fields.insert("StageName".into(), json!("Closed Won"));
        fields.insert("AccountId".into(), json!("001A"));
        fields.insert("Id".into(), json!("006X"));
        let record = SourceRecord {
            id: "006X".into(),
            modified_at: None,
            fields,
        };
        let row = import_row(&record, &m.entities[0]);
        assert_eq!(row["__source_id"], "006X");
        assert_eq!(row["StageName"], "won");
        assert_eq!(row["AccountId"], "001A");
        assert!(!row.contains_key("Id"));
        let mut multi = record.clone();
        multi
            .fields
            .insert("StageName".into(), json!("Closed Won;Parked"));
        assert_eq!(
            import_row(&multi, &m.entities[0])["StageName"],
            json!(["won", "Parked"])
        );
    }
}
