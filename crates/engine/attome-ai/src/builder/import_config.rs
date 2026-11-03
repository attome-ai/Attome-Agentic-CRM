//! AD11-T1: the building agent's import skill — a source CRM's
//! configuration (its model as the A24 connectors describe it,
//! `SourceModel`) as a draft for Attome, and what cannot be moved.
//!
//! Each source entity becomes a drafted entity named by Attome's naming
//! rules (a custom suffix such as Salesforce's `__c` dropped), each field a
//! drafted field of the connector's Attome type; [`super::entities::plan`]
//! then reuses, extends, asks or creates against the deployment's library,
//! so a source `Account` lands on Attome's `account`. Lookups whose target
//! is not in the source model, the source's system fields and its people
//! are reported, not drafted. Automations and code (workflows, validation
//! rules, triggers, plugins, scripts) are listed with the Attome
//! equivalent to rebuild them as (a flow, a rule or an extension); nothing
//! of them is migrated. Pure.

use serde::{Deserialize, Serialize};

use attome_integration::connector::adapters::migration_source::SourceModel;

use crate::actions::draft_model::{DraftField, DraftTable, field_type_of, snake};
use crate::builder::review::DraftRelationship;

/// Source fields every CRM keeps for itself, never drafted.
const SOURCE_SYSTEM_FIELDS: [&str; 14] = [
    "id",
    "createdbyid",
    "createddate",
    "lastmodifiedbyid",
    "lastmodifieddate",
    "systemmodstamp",
    "isdeleted",
    "ownerid",
    "createdby",
    "createdon",
    "modifiedby",
    "modifiedon",
    "versionnumber",
    "statecode",
];

/// One automation or piece of code of the source, as the caller lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceAutomation {
    pub name: String,
    /// The source's own kind: `workflow`, `flow`, `process_builder`,
    /// `validation_rule`, `apex_trigger`, `apex_class`, `plugin`,
    /// `business_rule`, `javascript`, ...
    pub kind: String,
    #[serde(default)]
    pub entity: Option<String>,
}

/// An automation with the Attome equivalent to rebuild it as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutomationEquivalent {
    pub name: String,
    pub kind: String,
    pub entity: Option<String>,
    /// `flow`, `rule` or `extension`.
    pub rebuild_as: &'static str,
    pub note: &'static str,
}

/// What cannot be moved, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CannotMove {
    pub entity: String,
    pub field: Option<String>,
    pub reason: String,
}

/// An Attome name for a source API name: the custom suffix dropped, then
/// the naming rules. Pure.
pub fn attome_name(source: &str) -> String {
    let trimmed = source.trim();
    let base = trimmed
        .strip_suffix("__c")
        .or_else(|| trimmed.strip_suffix("__C"))
        .unwrap_or(trimmed);
    // A Dynamics publisher prefix (`new_`, `cr123_`) is the publisher's, not the name.
    let base = match base.split_once('_') {
        Some((prefix, rest))
            if !rest.is_empty()
                && prefix.len() <= 6
                && (prefix.chars().any(|c| c.is_ascii_digit()) || prefix == "new") =>
        {
            rest
        }
        _ => base,
    };
    snake(&camel_to_snake(base))
}

/// `AccountNumber` to `account_number`. Pure.
fn camel_to_snake(text: &str) -> String {
    let mut out = String::new();
    let mut previous_lower = false;
    for c in text.chars() {
        if c.is_ascii_uppercase() && previous_lower {
            out.push('_');
        }
        previous_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        out.push(c.to_ascii_lowercase());
    }
    out
}

/// The draft of the source's model, and what was left out. Pure.
pub fn draft_from_source(source: &SourceModel) -> (Vec<DraftTable>, Vec<CannotMove>) {
    let known: Vec<String> = source.entities.iter().map(|e| e.name.clone()).collect();
    let mut cannot = Vec::new();
    let mut tables = Vec::new();
    for entity in &source.entities {
        let name = attome_name(&entity.name);
        let mut attributes = Vec::new();
        let mut relationships = Vec::new();
        for field in &entity.fields {
            if SOURCE_SYSTEM_FIELDS.contains(&field.name.to_ascii_lowercase().as_str()) {
                continue;
            }
            let field_name = attome_name(&field.name);
            if field.attome_type == "lookup" {
                match &field.lookup_target {
                    Some(target) if known.contains(target) => {
                        relationships.push(DraftRelationship {
                            target: attome_name(target),
                            kind: "many_to_one".into(),
                            attribute: Some(field_name.clone()),
                        });
                    }
                    other => {
                        cannot.push(CannotMove {
                            entity: entity.name.clone(),
                            field: Some(field.name.clone()),
                            reason: match other {
                                Some(target) => format!(
                                    "a lookup to {target}, which the source model does not include"
                                ),
                                None => "a lookup with no target".to_owned(),
                            },
                        });
                        continue;
                    }
                }
            }
            attributes.push(DraftField {
                name: field_name,
                field_type: field_type_of(&field.attome_type).to_owned(),
                label_en: field.label.clone(),
                label_ar: String::new(),
                calendar: None,
            });
        }
        tables.push(DraftTable {
            name,
            label_en: entity.label.clone(),
            label_ar: String::new(),
            attributes,
            relationships,
            sample_rows: Vec::new(),
        });
    }
    if !source.users.is_empty() {
        cannot.push(CannotMove {
            entity: "users".into(),
            field: None,
            reason: format!(
                "{} people: they become Attome users through the user import, not the model",
                source.users.len()
            ),
        });
    }
    (tables, cannot)
}

/// The Attome equivalent of each automation. Pure.
pub fn automation_equivalents(automations: &[SourceAutomation]) -> Vec<AutomationEquivalent> {
    automations
        .iter()
        .map(|a| {
            let kind = a.kind.to_ascii_lowercase();
            let (rebuild_as, note) = if kind.contains("validation")
                || kind.contains("business_rule")
            {
                (
                    "rule",
                    "rebuild as a rule on the entity; conditions keep their meaning",
                )
            } else if kind.contains("flow")
                || kind.contains("workflow")
                || kind.contains("process")
                || kind.contains("approval")
            {
                (
                    "flow",
                    "rebuild as a flow; test it with its own cases before publishing",
                )
            } else {
                (
                    "extension",
                    "code: rewrite as an extension (a hook or an action), reviewed like any code",
                )
            };
            AutomationEquivalent {
                name: a.name.clone(),
                kind: a.kind.clone(),
                entity: a.entity.clone(),
                rebuild_as,
                note,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_integration::connector::adapters::migration_source::{
        SourceEntity, SourceField, SourceUser,
    };

    fn field(name: &str, kind: &str, target: Option<&str>) -> SourceField {
        SourceField {
            name: name.into(),
            label: name.into(),
            source_type: kind.into(),
            attome_type: kind.into(),
            required: false,
            lookup_target: target.map(str::to_owned),
            choices: Vec::new(),
            multi: false,
        }
    }

    #[test]
    fn source_names_follow_attome_naming() {
        assert_eq!(attome_name("Invoice__c"), "invoice");
        assert_eq!(attome_name("AccountNumber"), "account_number");
        assert_eq!(attome_name("new_projectcode"), "projectcode");
        assert_eq!(attome_name("cr7a1_region"), "region");
        assert_eq!(attome_name("Account"), "account");
    }

    #[test]
    fn a_source_model_becomes_a_draft_and_a_report() {
        let source = SourceModel {
            entities: vec![
                SourceEntity {
                    name: "Account".into(),
                    label: "Account".into(),
                    custom: false,
                    fields: vec![
                        field("Id", "text", None),
                        field("Name", "text", None),
                        field("AnnualRevenue", "currency", None),
                    ],
                },
                SourceEntity {
                    name: "Invoice__c".into(),
                    label: "Invoice".into(),
                    custom: true,
                    fields: vec![
                        field("Account__c", "lookup", Some("Account")),
                        field("Campaign__c", "lookup", Some("Campaign")),
                        field("Paid__c", "bool", None),
                    ],
                },
            ],
            users: vec![SourceUser {
                id: "u1".into(),
                name: "Sara".into(),
                email: None,
                active: true,
            }],
        };
        let (tables, cannot) = draft_from_source(&source);
        assert_eq!(tables[0].name, "account");
        let names: Vec<&str> = tables[0]
            .attributes
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["name", "annual_revenue"],
            "system fields left out"
        );
        assert_eq!(tables[1].name, "invoice");
        assert_eq!(tables[1].relationships[0].target, "account");
        assert_eq!(
            tables[1].attributes.len(),
            2,
            "the dangling lookup is not drafted"
        );
        assert_eq!(cannot.len(), 2);
        assert!(cannot[0].reason.contains("Campaign"));
        assert_eq!(cannot[1].entity, "users");
    }

    #[test]
    fn automations_get_an_equivalent_and_are_not_migrated() {
        let found = automation_equivalents(&[
            SourceAutomation {
                name: "Require close date".into(),
                kind: "validation_rule".into(),
                entity: Some("Opportunity".into()),
            },
            SourceAutomation {
                name: "Welcome email".into(),
                kind: "Flow".into(),
                entity: None,
            },
            SourceAutomation {
                name: "InvoiceTrigger".into(),
                kind: "apex_trigger".into(),
                entity: Some("Invoice__c".into()),
            },
        ]);
        let kinds: Vec<&str> = found.iter().map(|f| f.rebuild_as).collect();
        assert_eq!(kinds, vec!["rule", "flow", "extension"]);
    }
}
