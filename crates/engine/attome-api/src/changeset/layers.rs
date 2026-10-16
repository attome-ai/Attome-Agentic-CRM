//! Solution 7 Phase 1 (D-785, design `document/general/SOLUTION-7-PHASE-1-DESIGN.md`
//! §2.2 "Backfill rule") — the boot step that marks every row a compiled
//! platform definition declares as `owner_layer = 'platform'`.
//!
//! Migration 0520 set every existing row to `project` (the column default).
//! [`stamp_platform_owned`] runs after the platform definitions are applied
//! and, per metadata table, sets `owner_layer = 'platform'` on the rows whose
//! logical key a platform definition declares: every `platform-bundles/*.json`
//! ([`PLATFORM_BUNDLES`], until Phase 1.5 moves them to
//! `changesets/platform/*.json`), plus the keys the caller adds for the
//! imperative seeds (`sidebar_seed.rs`, `trd_engine::seed`,
//! `attome_dashboard::seed`, `attome_project::seed` — [`PlatformKeys`] is filled by
//! whoever owns them).
//!
//! - One `UPDATE … SET owner_layer = 'platform' WHERE owner_layer = 'project'
//!   AND <key> = ANY($n)` per table, keys bound as text arrays, one short
//!   transaction per table (no metadata lock: the column is not read by the
//!   metadata cache, and a row an admin moved to another layer is left alone
//!   by the `owner_layer = 'project'` guard).
//! - Gated by `seed_gate::run_if_stale` under [`OWNER_LAYER_STAMP_KEY`] with
//!   the sha256 of the definitions and the extra keys as its version, so it
//!   runs once per changed definition set (one indexed read otherwise).
//! - `ReconcilePolicy::Seed` stamps `platform` on insert from now on
//!   (`attome_metadata::provision::changeset`), so a fresh database needs no stamp;
//!   this step is for rows written before 0520 and for the seed paths that
//!   still insert through other writers.
//!
//! Not stamped here (no bundle representation): role bulk fields, entity
//! default shares, data domains, content templates and spaces.

use std::collections::BTreeSet;

use attome_db::DbPool;
use attome_types::AppError;
use sha2::{Digest, Sha256};

use crate::bundle::model::Bundle;

/// The `seed_gate` key of this step.
pub const OWNER_LAYER_STAMP_KEY: &str = "owner-layer-stamp";

/// Separator of a sidebar path's segments in the bound key (a control
/// character no item name carries).
const PATH_SEPARATOR: char = '\u{1f}';

/// Every compiled platform bundle, `(name, json)`. A unit test keeps this
/// equal to the `platform-bundles/` folder.
pub const PLATFORM_BUNDLES: &[(&str, &str)] = &[
    (
        "attome-ai-agent",
        include_str!("../../../../../platform-bundles/attome-ai-agent.json"),
    ),
    (
        "attome-ai-agent-data",
        include_str!("../../../../../platform-bundles/attome-ai-agent-data.json"),
    ),
    (
        "attome-ai-bot-analytics",
        include_str!("../../../../../platform-bundles/attome-ai-bot-analytics.json"),
    ),
    (
        "attome-ai-bot-analytics-data",
        include_str!("../../../../../platform-bundles/attome-ai-bot-analytics-data.json"),
    ),
    (
        "attome-ai-capability-pack",
        include_str!("../../../../../platform-bundles/attome-ai-capability-pack.json"),
    ),
    (
        "attome-ai-collections",
        include_str!("../../../../../platform-bundles/attome-ai-collections.json"),
    ),
    (
        "attome-ai-followup",
        include_str!("../../../../../platform-bundles/attome-ai-followup.json"),
    ),
    (
        "attome-ai-meeting",
        include_str!("../../../../../platform-bundles/attome-ai-meeting.json"),
    ),
    (
        "attome-ai-model-catalog",
        include_str!("../../../../../platform-bundles/attome-ai-model-catalog.json"),
    ),
    (
        "attome-ai-model-catalog-data",
        include_str!("../../../../../platform-bundles/attome-ai-model-catalog-data.json"),
    ),
    (
        "attome-ai-personality",
        include_str!("../../../../../platform-bundles/attome-ai-personality.json"),
    ),
    (
        "attome-ai-provider",
        include_str!("../../../../../platform-bundles/attome-ai-provider.json"),
    ),
    (
        "attome-ai-provider-data",
        include_str!("../../../../../platform-bundles/attome-ai-provider-data.json"),
    ),
    (
        "attome-ai-quality",
        include_str!("../../../../../platform-bundles/attome-ai-quality.json"),
    ),
    (
        "attome-ai-tone",
        include_str!("../../../../../platform-bundles/attome-ai-tone.json"),
    ),
    (
        "attome-ai-tone-data",
        include_str!("../../../../../platform-bundles/attome-ai-tone-data.json"),
    ),
    (
        "attome-ai-work-share",
        include_str!("../../../../../platform-bundles/attome-ai-work-share.json"),
    ),
    (
        "attome-ai-work-share-data",
        include_str!("../../../../../platform-bundles/attome-ai-work-share-data.json"),
    ),
    (
        "attome-api-activity",
        include_str!("../../../../../platform-bundles/attome-api-activity.json"),
    ),
    (
        "attome-api-communication",
        include_str!("../../../../../platform-bundles/attome-api-communication.json"),
    ),
    (
        "attome-api-communication-event",
        include_str!("../../../../../platform-bundles/attome-api-communication-event.json"),
    ),
    (
        "attome-api-follow",
        include_str!("../../../../../platform-bundles/attome-api-follow.json"),
    ),
    (
        "attome-api-glossary",
        include_str!("../../../../../platform-bundles/attome-api-glossary.json"),
    ),
    (
        "attome-api-license",
        include_str!("../../../../../platform-bundles/attome-api-license.json"),
    ),
    (
        "attome-api-note",
        include_str!("../../../../../platform-bundles/attome-api-note.json"),
    ),
    (
        "attome-api-profiler-finding",
        include_str!("../../../../../platform-bundles/attome-api-profiler-finding.json"),
    ),
    (
        "attome-api-relationship",
        include_str!("../../../../../platform-bundles/attome-api-relationship.json"),
    ),
    (
        "attome-api-resource",
        include_str!("../../../../../platform-bundles/attome-api-resource.json"),
    ),
    (
        "attome-api-tag",
        include_str!("../../../../../platform-bundles/attome-api-tag.json"),
    ),
    (
        "attome-audit",
        include_str!("../../../../../platform-bundles/attome-audit.json"),
    ),
    (
        "attome-callintel",
        include_str!("../../../../../platform-bundles/attome-callintel.json"),
    ),
    (
        "attome-compliance-consent",
        include_str!("../../../../../platform-bundles/attome-compliance-consent.json"),
    ),
    (
        "attome-compliance-legal-matter",
        include_str!("../../../../../platform-bundles/attome-compliance-legal-matter.json"),
    ),
    (
        "attome-contract",
        include_str!("../../../../../platform-bundles/attome-contract.json"),
    ),
    (
        "attome-contract-counterparty",
        include_str!("../../../../../platform-bundles/attome-contract-counterparty.json"),
    ),
    (
        "attome-dashboard",
        include_str!("../../../../../platform-bundles/attome-dashboard.json"),
    ),
    (
        "attome-docgen",
        include_str!("../../../../../platform-bundles/attome-docgen.json"),
    ),
    (
        "attome-document",
        include_str!("../../../../../platform-bundles/attome-document.json"),
    ),
    (
        "attome-grc",
        include_str!("../../../../../platform-bundles/attome-grc.json"),
    ),
    (
        "attome-grc-regulatory-change",
        include_str!("../../../../../platform-bundles/attome-grc-regulatory-change.json"),
    ),
    (
        "attome-integration",
        include_str!("../../../../../platform-bundles/attome-integration.json"),
    ),
    (
        "attome-metadata-autovalue",
        include_str!("../../../../../platform-bundles/attome-metadata-autovalue.json"),
    ),
    (
        "attome-metric",
        include_str!("../../../../../platform-bundles/attome-metric.json"),
    ),
    (
        "attome-metric-governance",
        include_str!("../../../../../platform-bundles/attome-metric-governance.json"),
    ),
    (
        "attome-notification",
        include_str!("../../../../../platform-bundles/attome-notification.json"),
    ),
    (
        "attome-portal",
        include_str!("../../../../../platform-bundles/attome-portal.json"),
    ),
    (
        "attome-project",
        include_str!("../../../../../platform-bundles/attome-project.json"),
    ),
    (
        "attome-report",
        include_str!("../../../../../platform-bundles/attome-report.json"),
    ),
    (
        "attome-report-reports",
        include_str!("../../../../../platform-bundles/attome-report-reports.json"),
    ),
    (
        "attome-s2s",
        include_str!("../../../../../platform-bundles/attome-s2s.json"),
    ),
    (
        "attome-scan",
        include_str!("../../../../../platform-bundles/attome-scan.json"),
    ),
    (
        "attome-search-saved-search",
        include_str!("../../../../../platform-bundles/attome-search-saved-search.json"),
    ),
    (
        "attome-security",
        include_str!("../../../../../platform-bundles/attome-security.json"),
    ),
    (
        "attome-service",
        include_str!("../../../../../platform-bundles/attome-service.json"),
    ),
    (
        "attome-service-supplier-sla",
        include_str!("../../../../../platform-bundles/attome-service-supplier-sla.json"),
    ),
    (
        "attome-task-checklist",
        include_str!("../../../../../platform-bundles/attome-task-checklist.json"),
    ),
    (
        "attome-webcrawl",
        include_str!("../../../../../platform-bundles/attome-webcrawl.json"),
    ),
    (
        "attome-workflow",
        include_str!("../../../../../platform-bundles/attome-workflow.json"),
    ),
    (
        "xrm-core-api-key",
        include_str!("../../../../../platform-bundles/xrm-core-api-key.json"),
    ),
    (
        "xrm-core-authentication-type",
        include_str!("../../../../../platform-bundles/xrm-core-authentication-type.json"),
    ),
    (
        "xrm-core-authentication-type-data",
        include_str!("../../../../../platform-bundles/xrm-core-authentication-type-data.json"),
    ),
    (
        "xrm-reminder",
        include_str!("../../../../../platform-bundles/xrm-reminder.json"),
    ),
];

/// The logical keys a platform definition declares, per metadata table.
/// Ordered sets, so the gate version and the bound arrays are deterministic.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PlatformKeys {
    pub entities: BTreeSet<String>,
    /// (entity, field)
    pub attributes: BTreeSet<(String, String)>,
    pub relationships: BTreeSet<String>,
    /// (object_kind, object_ref, locale)
    pub labels: BTreeSet<(String, String, String)>,
    pub privileges: BTreeSet<String>,
    pub roles: BTreeSet<String>,
    /// (role, privilege key) — also stamps the grant's conditions.
    pub role_grants: BTreeSet<(String, String)>,
    /// (role, entity)
    pub role_entity_access: BTreeSet<(String, String)>,
    /// (role, profile)
    pub role_profiles: BTreeSet<(String, String)>,
    pub field_profiles: BTreeSet<String>,
    /// (profile, entity, field)
    pub profile_fields: BTreeSet<(String, String, String)>,
    pub calendars: BTreeSet<String>,
    /// (calendar, date `YYYY-MM-DD`)
    pub holidays: BTreeSet<(String, String)>,
    /// (calendar, date `YYYY-MM-DD`)
    pub exceptions: BTreeSet<(String, String)>,
    /// entity logicalname (one model per entity)
    pub state_models: BTreeSet<String>,
    /// (entity, transition name)
    pub transitions: BTreeSet<(String, String)>,
    pub apps: BTreeSet<String>,
    /// (entity, rule name)
    pub rules: BTreeSet<(String, String)>,
    /// (entity, view name) — system views only
    pub views: BTreeSet<(String, String)>,
    /// (entity or `""` for an entity-less query, query name)
    pub queries: BTreeSet<(String, String)>,
    /// Sidebar name paths, root first.
    pub sidebar: BTreeSet<Vec<String>>,
}

impl PlatformKeys {
    /// Adds every key one `attome-bundle/v1` document declares.
    pub fn add_bundle(&mut self, name: &str, json: &str) -> Result<(), AppError> {
        let bundle: Bundle = serde_json::from_str(json).map_err(|e| {
            AppError::internal(format!(
                "owner-layer stamp: platform bundle {name} does not parse: {e}"
            ))
        })?;
        self.add(&bundle);
        Ok(())
    }

    /// Adds every key `bundle` declares.
    pub fn add(&mut self, bundle: &Bundle) {
        for entity in &bundle.entities {
            self.entities.insert(entity.logicalname.clone());
            for attribute in &entity.attributes {
                self.attributes
                    .insert((entity.logicalname.clone(), attribute.logicalname.clone()));
            }
        }
        for patch in &bundle.attribute_patches {
            self.attributes
                .insert((patch.entity.clone(), patch.attribute.logicalname.clone()));
        }
        for relationship in &bundle.relationships {
            self.relationships.insert(relationship.name.clone());
        }
        for label in &bundle.labels {
            self.labels.insert((
                label.object_kind.clone(),
                label.object_ref.clone(),
                label.locale.clone(),
            ));
        }
        for privilege in &bundle.privileges {
            self.privileges.insert(privilege.key.clone());
        }
        for role in &bundle.roles {
            self.roles.insert(role.name.clone());
            for grant in &role.privileges {
                self.role_grants
                    .insert((role.name.clone(), grant.privilege.clone()));
            }
            for access in &role.entity_access {
                self.role_entity_access
                    .insert((role.name.clone(), access.entity.clone()));
            }
            for profile in &role.field_security_profiles {
                self.role_profiles
                    .insert((role.name.clone(), profile.clone()));
            }
        }
        for profile in &bundle.field_security_profiles {
            self.field_profiles.insert(profile.name.clone());
            for field in &profile.fields {
                self.profile_fields.insert((
                    profile.name.clone(),
                    field.entity.clone(),
                    field.field.clone(),
                ));
            }
        }
        for calendar in &bundle.calendars {
            self.calendars.insert(calendar.name.clone());
            for holiday in &calendar.holidays {
                self.holidays
                    .insert((calendar.name.clone(), holiday.holiday_date.to_string()));
            }
            for exception in calendar.exceptions.iter().flatten() {
                self.exceptions
                    .insert((calendar.name.clone(), exception.exception_date.to_string()));
            }
        }
        for model in &bundle.state_models {
            self.state_models.insert(model.entity_logicalname.clone());
            for transition in &model.transitions {
                self.transitions
                    .insert((model.entity_logicalname.clone(), transition.name.clone()));
            }
        }
        for app in &bundle.apps {
            self.apps.insert(app.name.clone());
        }
        for rule in &bundle.rules {
            self.rules
                .insert((rule.entity_logicalname.clone(), rule.name.clone()));
        }
        for view in &bundle.views {
            self.views.insert((view.entity.clone(), view.name.clone()));
        }
        for query in &bundle.queries {
            self.queries
                .insert((query.entity.clone().unwrap_or_default(), query.name.clone()));
        }
        for item in &bundle.sidebar {
            self.sidebar.insert(item.path.clone());
        }
    }

    /// Every key of [`PLATFORM_BUNDLES`].
    pub fn from_platform_bundles() -> Result<Self, AppError> {
        let mut keys = Self::default();
        for (name, json) in PLATFORM_BUNDLES {
            keys.add_bundle(name, json)?;
        }
        Ok(keys)
    }

    /// The union of `self` and `other`.
    pub fn extend(&mut self, other: &Self) {
        self.entities.extend(other.entities.iter().cloned());
        self.attributes.extend(other.attributes.iter().cloned());
        self.relationships
            .extend(other.relationships.iter().cloned());
        self.labels.extend(other.labels.iter().cloned());
        self.privileges.extend(other.privileges.iter().cloned());
        self.roles.extend(other.roles.iter().cloned());
        self.role_grants.extend(other.role_grants.iter().cloned());
        self.role_entity_access
            .extend(other.role_entity_access.iter().cloned());
        self.role_profiles
            .extend(other.role_profiles.iter().cloned());
        self.field_profiles
            .extend(other.field_profiles.iter().cloned());
        self.profile_fields
            .extend(other.profile_fields.iter().cloned());
        self.calendars.extend(other.calendars.iter().cloned());
        self.holidays.extend(other.holidays.iter().cloned());
        self.exceptions.extend(other.exceptions.iter().cloned());
        self.state_models.extend(other.state_models.iter().cloned());
        self.transitions.extend(other.transitions.iter().cloned());
        self.apps.extend(other.apps.iter().cloned());
        self.rules.extend(other.rules.iter().cloned());
        self.views.extend(other.views.iter().cloned());
        self.queries.extend(other.queries.iter().cloned());
        self.sidebar.extend(other.sidebar.iter().cloned());
    }

    /// The gate version: sha256 over a canonical rendering of every key.
    pub fn version(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{self:?}").as_bytes());
        hex::encode(hasher.finalize())
    }

    /// One statement per table, with its key columns as bound text arrays.
    fn statements(&self) -> Vec<Stamp> {
        let one = |set: &BTreeSet<String>| vec![set.iter().cloned().collect::<Vec<_>>()];
        let two = |set: &BTreeSet<(String, String)>| {
            let (a, b): (Vec<_>, Vec<_>) = set.iter().cloned().unzip();
            vec![a, b]
        };
        let three = |set: &BTreeSet<(String, String, String)>| {
            let mut columns = vec![Vec::new(), Vec::new(), Vec::new()];
            for (a, b, c) in set {
                columns[0].push(a.clone());
                columns[1].push(b.clone());
                columns[2].push(c.clone());
            }
            columns
        };
        let (with_entity, without_entity): (BTreeSet<_>, BTreeSet<_>) = self
            .queries
            .iter()
            .cloned()
            .partition(|(entity, _)| !entity.is_empty());
        let entity_less: BTreeSet<String> =
            without_entity.into_iter().map(|(_, name)| name).collect();
        let sidebar: BTreeSet<String> = self
            .sidebar
            .iter()
            .map(|path| path.join(&PATH_SEPARATOR.to_string()))
            .collect();

        vec![
            Stamp::new("entity_info", STAMP_ENTITY, one(&self.entities)),
            Stamp::new("attribute_info", STAMP_ATTRIBUTE, two(&self.attributes)),
            Stamp::new(
                "relationship_info",
                STAMP_RELATIONSHIP,
                one(&self.relationships),
            ),
            Stamp::new("metadata_label", STAMP_LABEL, three(&self.labels)),
            Stamp::new("privilege", STAMP_PRIVILEGE, one(&self.privileges)),
            Stamp::new("role", STAMP_ROLE, one(&self.roles)),
            Stamp::new(
                "role_mm_privilege",
                STAMP_ROLE_GRANT,
                two(&self.role_grants),
            ),
            Stamp::new(
                "role_privilege_condition",
                STAMP_ROLE_GRANT_CONDITION,
                two(&self.role_grants),
            ),
            Stamp::new(
                "role_mm_entity_access",
                STAMP_ROLE_ENTITY_ACCESS,
                two(&self.role_entity_access),
            ),
            Stamp::new(
                "role_mm_field_security_profile",
                STAMP_ROLE_PROFILE,
                two(&self.role_profiles),
            ),
            Stamp::new(
                "field_security_profile",
                STAMP_PROFILE,
                one(&self.field_profiles),
            ),
            Stamp::new(
                "field_security_profile_field",
                STAMP_PROFILE_FIELD,
                three(&self.profile_fields),
            ),
            Stamp::new("calendar", STAMP_CALENDAR, one(&self.calendars)),
            Stamp::new("calendar_holiday", STAMP_HOLIDAY, two(&self.holidays)),
            Stamp::new("calendar_exception", STAMP_EXCEPTION, two(&self.exceptions)),
            Stamp::new("state_model", STAMP_STATE_MODEL, one(&self.state_models)),
            Stamp::new("state_transition", STAMP_TRANSITION, two(&self.transitions)),
            Stamp::new("app", STAMP_APP, one(&self.apps)),
            Stamp::new("rule", STAMP_RULE, two(&self.rules)),
            Stamp::new("view", STAMP_VIEW, two(&self.views)),
            Stamp::new("sql_query", STAMP_QUERY, two(&with_entity)),
            Stamp::new("sql_query", STAMP_QUERY_NO_ENTITY, one(&entity_less)),
            Stamp::new("sidebar", STAMP_SIDEBAR, one(&sidebar)),
        ]
    }
}

/// One table's stamp statement and its bound key columns.
#[derive(Debug)]
struct Stamp {
    table: &'static str,
    sql: &'static str,
    columns: Vec<Vec<String>>,
}

impl Stamp {
    fn new(table: &'static str, sql: &'static str, columns: Vec<Vec<String>>) -> Self {
        Self {
            table,
            sql,
            columns,
        }
    }

    fn is_empty(&self) -> bool {
        self.columns.first().is_none_or(Vec::is_empty)
    }
}

// Every statement: platform only over `project` rows (a row another layer
// owns is left alone), keys bound as text arrays, never interpolated.

const STAMP_ENTITY: &str = "UPDATE entity_info SET owner_layer = 'platform' \
     WHERE owner_layer = 'project' AND logicalname = ANY($1::text[])";

const STAMP_ATTRIBUTE: &str = "UPDATE attribute_info a SET owner_layer = 'platform' \
     FROM entity_info e, unnest($1::text[], $2::text[]) AS k(entity, field) \
     WHERE a.owner_layer = 'project' AND e.id = a.entity_ref \
       AND e.logicalname = k.entity AND a.logicalname = k.field";

const STAMP_RELATIONSHIP: &str = "UPDATE relationship_info SET owner_layer = 'platform' \
     WHERE owner_layer = 'project' AND name = ANY($1::text[])";

const STAMP_LABEL: &str = "UPDATE metadata_label l SET owner_layer = 'platform' \
     FROM unnest($1::text[], $2::text[], $3::text[]) AS k(object_kind, object_ref, locale) \
     WHERE l.owner_layer = 'project' AND l.object_kind = k.object_kind \
       AND l.object_ref = k.object_ref AND l.locale = k.locale";

const STAMP_PRIVILEGE: &str = "UPDATE privilege SET owner_layer = 'platform' \
     WHERE owner_layer = 'project' AND key = ANY($1::text[])";

const STAMP_ROLE: &str = "UPDATE role SET owner_layer = 'platform' \
     WHERE owner_layer = 'project' AND name = ANY($1::text[])";

const STAMP_ROLE_GRANT: &str = "UPDATE role_mm_privilege rp SET owner_layer = 'platform' \
     FROM role r, privilege p, \
          unnest($1::text[], $2::text[]) AS k(role, privilege) \
     WHERE rp.owner_layer = 'project' AND r.id = rp.role_ref AND p.id = rp.privilege_ref \
       AND r.name = k.role AND p.key = k.privilege";

const STAMP_ROLE_GRANT_CONDITION: &str = "UPDATE role_privilege_condition c \
     SET owner_layer = 'platform' \
     FROM role_mm_privilege rp, role r, privilege p, \
          unnest($1::text[], $2::text[]) AS k(role, privilege) \
     WHERE c.owner_layer = 'project' AND rp.id = c.role_privilege_ref \
       AND r.id = rp.role_ref AND p.id = rp.privilege_ref \
       AND r.name = k.role AND p.key = k.privilege";

const STAMP_ROLE_ENTITY_ACCESS: &str = "UPDATE role_mm_entity_access ea \
     SET owner_layer = 'platform' \
     FROM role r, entity_info e, \
          unnest($1::text[], $2::text[]) AS k(role, entity) \
     WHERE ea.owner_layer = 'project' AND r.id = ea.role_ref AND e.id = ea.entity_ref \
       AND r.name = k.role AND e.logicalname = k.entity";

const STAMP_ROLE_PROFILE: &str = "UPDATE role_mm_field_security_profile rp \
     SET owner_layer = 'platform' \
     FROM role r, field_security_profile p, \
          unnest($1::text[], $2::text[]) AS k(role, profile) \
     WHERE rp.owner_layer = 'project' AND r.id = rp.role_ref AND p.id = rp.profile_ref \
       AND r.name = k.role AND p.name = k.profile";

const STAMP_PROFILE: &str = "UPDATE field_security_profile SET owner_layer = 'platform' \
     WHERE owner_layer = 'project' AND name = ANY($1::text[])";

const STAMP_PROFILE_FIELD: &str = "UPDATE field_security_profile_field f \
     SET owner_layer = 'platform' \
     FROM field_security_profile p, \
          unnest($1::text[], $2::text[], $3::text[]) AS k(profile, entity, field) \
     WHERE f.owner_layer = 'project' AND p.id = f.profile_ref AND p.name = k.profile \
       AND f.entity_logicalname = k.entity AND f.field_logicalname = k.field";

const STAMP_CALENDAR: &str = "UPDATE calendar SET owner_layer = 'platform' \
     WHERE owner_layer = 'project' AND name = ANY($1::text[])";

const STAMP_HOLIDAY: &str = "UPDATE calendar_holiday h SET owner_layer = 'platform' \
     FROM calendar c, unnest($1::text[], $2::text[]) AS k(calendar, day) \
     WHERE h.owner_layer = 'project' AND c.id = h.calendar_id AND c.name = k.calendar \
       AND h.holiday_date = k.day::date";

const STAMP_EXCEPTION: &str = "UPDATE calendar_exception x SET owner_layer = 'platform' \
     FROM calendar c, unnest($1::text[], $2::text[]) AS k(calendar, day) \
     WHERE x.owner_layer = 'project' AND c.id = x.calendar_id AND c.name = k.calendar \
       AND x.exception_date = k.day::date";

const STAMP_STATE_MODEL: &str = "UPDATE state_model SET owner_layer = 'platform' \
     WHERE owner_layer = 'project' AND entity_logicalname = ANY($1::text[])";

const STAMP_TRANSITION: &str = "UPDATE state_transition t SET owner_layer = 'platform' \
     FROM state_model m, unnest($1::text[], $2::text[]) AS k(entity, name) \
     WHERE t.owner_layer = 'project' AND m.id = t.model_ref \
       AND m.entity_logicalname = k.entity AND t.name = k.name";

const STAMP_APP: &str = "UPDATE app SET owner_layer = 'platform' \
     WHERE owner_layer = 'project' AND name = ANY($1::text[])";

const STAMP_RULE: &str = "UPDATE rule r SET owner_layer = 'platform' \
     FROM unnest($1::text[], $2::text[]) AS k(entity, name) \
     WHERE r.owner_layer = 'project' AND r.entity_logicalname = k.entity AND r.name = k.name";

const STAMP_VIEW: &str = "UPDATE view v SET owner_layer = 'platform' \
     FROM entity_info e, unnest($1::text[], $2::text[]) AS k(entity, name) \
     WHERE v.owner_layer = 'project' AND v.scope = 'system' \
       AND e.id = v.entity_logical_name AND e.logicalname = k.entity AND v.name = k.name";

const STAMP_QUERY: &str = "UPDATE sql_query q SET owner_layer = 'platform' \
     FROM entity_info e, unnest($1::text[], $2::text[]) AS k(entity, name) \
     WHERE q.owner_layer = 'project' AND e.id = q.entity_logical_name \
       AND e.logicalname = k.entity AND q.record_no = k.name";

const STAMP_QUERY_NO_ENTITY: &str = "UPDATE sql_query SET owner_layer = 'platform' \
     WHERE owner_layer = 'project' AND entity_logical_name IS NULL \
       AND record_no = ANY($1::text[])";

/// Sidebar items are keyed by their name path from the root.
const STAMP_SIDEBAR: &str = "WITH RECURSIVE tree AS ( \
         SELECT id, ARRAY[name]::text[] AS path FROM sidebar \
          WHERE parent_ref IS NULL AND is_deleted = false \
         UNION ALL \
         SELECT s.id, t.path || s.name::text FROM sidebar s \
           JOIN tree t ON s.parent_ref = t.id \
          WHERE s.is_deleted = false \
     ) \
     UPDATE sidebar SET owner_layer = 'platform' \
      WHERE owner_layer = 'project' \
        AND id IN (SELECT id FROM tree WHERE array_to_string(path, chr(31)) = ANY($1::text[]))";

/// What a stamp run changed, per table (for the boot log).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StampReport {
    pub rows: Vec<(&'static str, u64)>,
}

impl StampReport {
    pub fn total(&self) -> u64 {
        self.rows.iter().map(|(_, n)| n).sum()
    }
}

/// The boot step (design §2.2): stamps `platform` on every row
/// [`PLATFORM_BUNDLES`] and `extra` (the imperative seeds' keys) declare,
/// once per changed definition set. Call after the platform definitions have
/// been applied, under the platform seed lock, on the provisioning pool.
pub async fn stamp_platform_owned(db: &DbPool, extra: &PlatformKeys) -> Result<(), AppError> {
    let mut keys = PlatformKeys::from_platform_bundles()?;
    keys.extend(extra);
    let version = keys.version();
    attome_core::seed_gate::run_if_stale(db, OWNER_LAYER_STAMP_KEY, &version, || async {
        let report = stamp_keys(db, &keys).await?;
        tracing::info!(
            rows = report.total(),
            tables = ?report.rows,
            "owner-layer stamp: platform definitions marked platform"
        );
        Ok(())
    })
    .await
}

/// The ungated stamp: one short transaction per table. Idempotent (the
/// `owner_layer = 'project'` guard), so a re-run changes nothing.
pub async fn stamp_keys(db: &DbPool, keys: &PlatformKeys) -> Result<StampReport, AppError> {
    let mut report = StampReport::default();
    for stamp in keys.statements() {
        if stamp.is_empty() {
            continue;
        }
        let mut tx = attome_db::tx::begin(db).await?;
        let mut query = sqlx::query(stamp.sql);
        for column in &stamp.columns {
            query = query.bind(column);
        }
        let n = query
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(table = stamp.table, error = %e, "owner-layer stamp failed");
                AppError::internal(e)
            })?
            .rows_affected();
        attome_db::tx::commit(tx).await?;
        if n > 0 {
            report.rows.push((stamp.table, n));
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `PLATFORM_BUNDLES` names every `platform-bundles/*.json`, once.
    #[test]
    fn the_compiled_list_equals_the_folder() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../platform-bundles");
        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .expect("platform-bundles/ is readable")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".json"))
            .map(|name| name.trim_end_matches(".json").to_owned())
            .collect();
        on_disk.sort();
        let mut compiled: Vec<String> = PLATFORM_BUNDLES
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        compiled.sort();
        assert_eq!(compiled, on_disk);
    }

    #[test]
    fn every_platform_bundle_yields_keys() {
        let keys = PlatformKeys::from_platform_bundles().expect("every platform bundle parses");
        assert!(
            keys.entities.contains("audit_header"),
            "{:?}",
            keys.entities
        );
        assert!(!keys.attributes.is_empty());
        // Every declared attribute belongs to a declared or patched entity key.
        assert!(
            keys.attributes
                .iter()
                .all(|(entity, field)| !entity.is_empty() && !field.is_empty())
        );
    }

    #[test]
    fn statements_bind_one_array_per_key_column_of_equal_length() {
        let mut keys = PlatformKeys::default();
        keys.entities.insert("account".into());
        keys.attributes.insert(("account".into(), "name".into()));
        keys.labels
            .insert(("entity".into(), "account".into(), "ar".into()));
        keys.queries.insert((String::new(), "global_q".into()));
        keys.queries.insert(("account".into(), "active".into()));
        keys.sidebar.insert(vec!["Sales".into(), "Accounts".into()]);
        let statements = keys.statements();
        for stamp in &statements {
            let placeholders = (1..=stamp.columns.len())
                .filter(|i| stamp.sql.contains(&format!("${i}::text[]")))
                .count();
            assert_eq!(placeholders, stamp.columns.len(), "{}", stamp.table);
            let lengths: BTreeSet<usize> = stamp.columns.iter().map(Vec::len).collect();
            assert!(lengths.len() <= 1, "{}: ragged key columns", stamp.table);
            assert!(
                stamp.sql.contains("owner_layer = 'project'"),
                "{}",
                stamp.table
            );
        }
        let sidebar = statements
            .iter()
            .find(|s| s.table == "sidebar")
            .expect("sidebar statement");
        assert_eq!(
            sidebar.columns,
            vec![vec!["Sales\u{1f}Accounts".to_owned()]]
        );
        let entity_less = statements
            .iter()
            .find(|s| s.sql == STAMP_QUERY_NO_ENTITY)
            .expect("entity-less query statement");
        assert_eq!(entity_less.columns, vec![vec!["global_q".to_owned()]]);
        assert!(
            statements
                .iter()
                .any(|s| s.table == "calendar" && s.is_empty())
        );
    }

    #[test]
    fn the_version_follows_the_keys() {
        let empty = PlatformKeys::default();
        let mut one = PlatformKeys::default();
        one.entities.insert("account".into());
        assert_ne!(empty.version(), one.version());
        assert_eq!(one.version(), one.clone().version());
        let mut merged = PlatformKeys::default();
        merged.extend(&one);
        assert_eq!(merged, one);
    }
}
