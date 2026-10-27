//! T8-T2 (part): what installing a package does, in the terms the person
//! approving it reads, from the package's bundle plan ([`super::plan`]).
//! [`install_preview`] sorts the plan's lines into:
//!
//! - **new objects** (creates) and **changed objects** (updates, with their
//!   `field: live -> desired` lines), the access objects (roles, grants,
//!   entity access, privileges, field-security profiles and their fields,
//!   permission sets) left out of both because they are listed apart;
//! - **permissions requested**: every created or changed access object, so
//!   what a package asks for is never mixed into ordinary metadata;
//! - **data effects**: what touches records already there: records the
//!   package writes, a field it adds to an entity that already exists, a
//!   field whose type, requiredness or length changes, and anything it
//!   retires (values hidden, records soft-retired);
//! - **removed** and **blocked** lines as the plan gave them.
//!
//! Pure: the caller plans the bundle; nothing is written.

use serde::Serialize;
use utoipa::ToSchema;

use super::model::{
    COMPONENT_ATTRIBUTE, COMPONENT_ATTRIBUTE_PATCH, COMPONENT_ENTITY,
    COMPONENT_FIELD_SECURITY_PROFILE, COMPONENT_PERMISSION_SET, COMPONENT_PRIVILEGE,
    COMPONENT_PROFILE_FIELD, COMPONENT_RECORD, COMPONENT_ROLE, COMPONENT_ROLE_ENTITY_ACCESS,
    COMPONENT_ROLE_GRANT,
};
use super::plan::{BundlePlan, PlanAction, PlanEntry};

/// The components that grant access.
pub const ACCESS_COMPONENTS: [&str; 7] = [
    COMPONENT_ROLE,
    COMPONENT_ROLE_GRANT,
    COMPONENT_ROLE_ENTITY_ACCESS,
    COMPONENT_PRIVILEGE,
    COMPONENT_FIELD_SECURITY_PROFILE,
    COMPONENT_PROFILE_FIELD,
    COMPONENT_PERMISSION_SET,
];

/// A change field that alters what existing values may be.
const DATA_CHANGES: [&str; 4] = ["field_type", "is_required", "max_length", "options"];

/// One effect on records already there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct DataEffect {
    pub component: &'static str,
    pub key: String,
    /// `writes_records`, `adds_field_to_existing`, `changes_field`, `retires`.
    pub effect: &'static str,
    pub detail: Option<String>,
}

/// What installing a package does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct InstallPreview {
    pub new_objects: Vec<PlanEntry>,
    pub changed_objects: Vec<PlanEntry>,
    pub permissions: Vec<PlanEntry>,
    pub data_effects: Vec<DataEffect>,
    pub removed: Vec<PlanEntry>,
    pub blocked: Vec<PlanEntry>,
    /// False while anything is blocked: the package cannot be installed as it is.
    pub installable: bool,
}

fn is_access(component: &str) -> bool {
    ACCESS_COMPONENTS.contains(&component)
}

/// The entity an attribute key (`entity.field`) belongs to.
fn entity_of(key: &str) -> &str {
    key.split_once('.').map_or(key, |(entity, _)| entity)
}

/// The preview of installing the plan's bundle. Pure.
pub fn install_preview(plan: &BundlePlan) -> InstallPreview {
    let mut preview = InstallPreview {
        new_objects: Vec::new(),
        changed_objects: Vec::new(),
        permissions: Vec::new(),
        data_effects: Vec::new(),
        removed: plan.retires.clone(),
        blocked: plan.blocked.clone(),
        installable: plan.blocked.is_empty(),
    };
    // Entities this install creates: a new field on one of them touches no existing row.
    let new_entities: Vec<&str> = plan
        .entries
        .iter()
        .filter(|e| e.component == COMPONENT_ENTITY && e.action == PlanAction::Create)
        .map(|e| e.key.as_str())
        .collect();
    for entry in &plan.entries {
        if matches!(
            entry.action,
            PlanAction::Noop | PlanAction::Blocked | PlanAction::Retire
        ) {
            continue;
        }
        if is_access(entry.component) {
            preview.permissions.push(entry.clone());
        } else if entry.action == PlanAction::Create {
            preview.new_objects.push(entry.clone());
        } else {
            preview.changed_objects.push(entry.clone());
        }
        let effect = |effect: &'static str, detail: Option<String>| DataEffect {
            component: entry.component,
            key: entry.key.clone(),
            effect,
            detail,
        };
        match (entry.component, entry.action) {
            (COMPONENT_RECORD, PlanAction::Create | PlanAction::Update) => {
                preview.data_effects.push(effect("writes_records", None));
            }
            (COMPONENT_ATTRIBUTE, PlanAction::Create)
                if !new_entities.contains(&entity_of(&entry.key)) =>
            {
                preview
                    .data_effects
                    .push(effect("adds_field_to_existing", None));
            }
            (COMPONENT_ATTRIBUTE | COMPONENT_ATTRIBUTE_PATCH, PlanAction::Update) => {
                let changed: Vec<&String> = entry
                    .changes
                    .iter()
                    .filter(|c| DATA_CHANGES.iter().any(|d| c.starts_with(&format!("{d}:"))))
                    .collect();
                if !changed.is_empty() {
                    let detail = changed
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>()
                        .join("; ");
                    preview
                        .data_effects
                        .push(effect("changes_field", Some(detail)));
                }
            }
            _ => {}
        }
    }
    for entry in &plan.retires {
        preview.data_effects.push(DataEffect {
            component: entry.component,
            key: entry.key.clone(),
            effect: "retires",
            detail: entry.reason.clone(),
        });
    }
    preview
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::plan::PlanSummary;
    use uuid::Uuid;

    fn entry(component: &'static str, key: &str, action: PlanAction) -> PlanEntry {
        PlanEntry {
            component,
            key: key.into(),
            action,
            reason: None,
            changes: Vec::new(),
        }
    }

    fn plan(
        entries: Vec<PlanEntry>,
        retires: Vec<PlanEntry>,
        blocked: Vec<PlanEntry>,
    ) -> BundlePlan {
        BundlePlan {
            plan_id: Uuid::nil(),
            basis_hash: String::new(),
            bundle_hash: String::new(),
            entries,
            retires,
            blocked,
            summary: PlanSummary::default(),
            additive_only: false,
        }
    }

    #[test]
    fn package_install_preview_sorts_the_plan() {
        let mut retyped = entry(COMPONENT_ATTRIBUTE, "account.tier", PlanAction::Update);
        retyped.changes = vec![
            "max_length: 50 -> 20".into(),
            "display_name: Tier -> Level".into(),
        ];
        let mut relabelled = entry(COMPONENT_ATTRIBUTE, "account.note", PlanAction::Update);
        relabelled.changes = vec!["display_name: Note -> Notes".into()];
        let mut retired = entry(COMPONENT_ATTRIBUTE, "account.legacy", PlanAction::Retire);
        retired.reason = Some("absent from the bundle".into());
        let p = plan(
            vec![
                entry(COMPONENT_ENTITY, "exf_vehicle", PlanAction::Create),
                entry(COMPONENT_ATTRIBUTE, "exf_vehicle.plate", PlanAction::Create),
                entry(
                    COMPONENT_ATTRIBUTE,
                    "account.exf_fleet_size",
                    PlanAction::Create,
                ),
                retyped,
                relabelled,
                entry(COMPONENT_ROLE, "Fleet Manager", PlanAction::Create),
                entry(
                    COMPONENT_ROLE_ENTITY_ACCESS,
                    "Fleet Manager:exf_vehicle",
                    PlanAction::Create,
                ),
                entry(
                    COMPONENT_RECORD,
                    "exf_vehicle_type:truck",
                    PlanAction::Create,
                ),
                entry(COMPONENT_ENTITY, "account", PlanAction::Noop),
            ],
            vec![retired],
            vec![],
        );
        let preview = install_preview(&p);
        let keys = |v: &[PlanEntry]| v.iter().map(|e| e.key.clone()).collect::<Vec<_>>();
        assert_eq!(
            keys(&preview.new_objects),
            [
                "exf_vehicle",
                "exf_vehicle.plate",
                "account.exf_fleet_size",
                "exf_vehicle_type:truck"
            ]
        );
        assert_eq!(
            keys(&preview.changed_objects),
            ["account.tier", "account.note"]
        );
        assert_eq!(
            keys(&preview.permissions),
            ["Fleet Manager", "Fleet Manager:exf_vehicle"]
        );
        let effects: Vec<(&str, &str)> = preview
            .data_effects
            .iter()
            .map(|d| (d.key.as_str(), d.effect))
            .collect();
        assert_eq!(
            effects,
            [
                ("account.exf_fleet_size", "adds_field_to_existing"),
                ("account.tier", "changes_field"),
                ("exf_vehicle_type:truck", "writes_records"),
                ("account.legacy", "retires"),
            ]
        );
        assert_eq!(
            preview.data_effects[1].detail.as_deref(),
            Some("max_length: 50 -> 20")
        );
        assert!(preview.installable);
        let blocked = install_preview(&plan(
            vec![],
            vec![],
            vec![entry(COMPONENT_ATTRIBUTE, "a.b", PlanAction::Blocked)],
        ));
        assert!(!blocked.installable);
    }
}
