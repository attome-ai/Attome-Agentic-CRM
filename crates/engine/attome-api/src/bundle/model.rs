//! The `attome-bundle/v1` data model (P-environment-promotion §4, Phase 1
//! step 8).
//!
//! A bundle is the declarative desired state of one deployment's
//! configuration metadata: entities and their attributes, stored queries,
//! views, the sidebar tree, roles and their grants, privileges, and
//! field-security profiles. It is the F273 vertical pack, the whole-
//! deployment promotion artifact, and the JSON `P-solution-packaging` stores
//! — one format, three consumers.
//!
//! **Identity is logical, never UUID.** Two deployments' ids differ and
//! always will, so every reference is carried as the target's stable business
//! key: an entity by `logicalname`, an attribute by `(entity, logicalname)`,
//! a query by `(entity, name)`, a view by `(entity, name)`, a sidebar item by
//! its name path from the root, a role by `name`, a privilege by `key`, a
//! field-security profile by `name`. No id, timestamp, `created_by`,
//! `modified_by`, `organization_ref`, or `row_version` ever appears in a
//! bundle — those are environment identity, not configuration.
//!
//! **Allow-list.** The component types below are the *only* things a bundle
//! can carry. Users, user-level grants, API keys, S2S clients and secrets,
//! the license, sessions, and every other table are not representable here,
//! so they cannot leak through an export (§4 "Deliberately excluded").
//!
//! Every type is a wire type (`Serialize`/`Deserialize`/`ToSchema`) because
//! the export and plan routes return them verbatim. Field order in the
//! structs is irrelevant to identity: [`super::canonical`] is what decides
//! how a bundle is serialized for hashing.

use attome_core::business_rules::{AppliesTo, BUSINESS_KIND, ConditionTree, PolicyDef};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The one format string this binary reads and writes. A bundle declaring
/// anything else is refused by [`parse_bundle`] — see [`check_format`].
pub const BUNDLE_FORMAT: &str = "attome-bundle/v1";

/// The only format prefix any version of this binary will ever accept.
/// `attome-bundle/v2` is "newer than this binary understands", anything
/// without the prefix is "not a bundle at all" — the two are reported apart
/// so an operator on an old binary reads the right message.
const BUNDLE_FORMAT_PREFIX: &str = "attome-bundle/v";

/// The field-type vocabulary a bundle may declare: exactly what
/// `attome_metadata::provision::valid_field_type` accepts, because both read
/// `attome_core::FieldType::NAMES` (U9 checklist item 6 — this used to be
/// a third hand-copied list). A name outside it is reported as `Blocked` by
/// the planner rather than silently becoming `text`.
pub const KNOWN_FIELD_TYPES: &[&str] = attome_core::FieldType::NAMES;

/// The component-type names used in [`super::plan::PlanEntry::component`].
pub const COMPONENT_ENTITY: &str = "entity";
pub const COMPONENT_ATTRIBUTE: &str = "attribute";
/// [`AttributePatch`] — distinct from [`COMPONENT_ATTRIBUTE`] so a plan's
/// entries make clear which fields are the entity's own full definition
/// versus an additive cross-module patch.
pub const COMPONENT_ATTRIBUTE_PATCH: &str = "attribute_patch";
pub const COMPONENT_QUERY: &str = "query";
pub const COMPONENT_VIEW: &str = "view";
/// D-404 / M83 Phase 1.
pub const COMPONENT_CALENDAR: &str = "calendar";
pub const COMPONENT_SIDEBAR: &str = "sidebar";
pub const COMPONENT_ROLE: &str = "role";
pub const COMPONENT_ROLE_GRANT: &str = "role_grant";
pub const COMPONENT_ROLE_ENTITY_ACCESS: &str = "role_entity_access";
pub const COMPONENT_PRIVILEGE: &str = "privilege";
pub const COMPONENT_FIELD_SECURITY_PROFILE: &str = "field_security_profile";
pub const COMPONENT_PROFILE_FIELD: &str = "profile_field";
/// Bundle-level checks (format, `requires`) that are not about one object.
pub const COMPONENT_BUNDLE: &str = "bundle";
/// Phase 3 — one row of a [`RecordSet`], keyed `entity[k1=v1,k2=v2]`.
pub const COMPONENT_RECORD: &str = "record";
/// M02/D-412 — a deployment-scope `setting` row. This is the
/// "configuration profile" the M02 plan describes: not a separate mechanism,
/// just the deployment-scope slice of the settings store, exported the same
/// way any other component is (§4's "profile = named bundle-exportable set
/// of deployment-scope values"). **Export only today** — `export_settings`
/// (`export.rs`) populates this from live `setting` rows, but no
/// `diff_settings`/apply step exists yet (deferred; see D-412's decision
/// entry for why: the ledger-driven plan/apply pipeline is a materially
/// larger, higher-risk change than this pass's budget covers). A `settings`
/// field present in an *imported* bundle is silently ignored by `apply.rs`
/// until that follow-up lands — the allow-list model already tolerates a
/// component the wire format carries before every consumer understands it.
pub const COMPONENT_SETTING: &str = "setting";
/// M07 Phase 1 (D-405/D-406) — `state_model`, keyed by the entity
/// it governs.
pub const COMPONENT_STATE_MODEL: &str = "state_model";
/// One `state_transition` row, keyed `"{entity}:{from}->{to}"`.
pub const COMPONENT_STATE_TRANSITION: &str = "state_transition";
/// M05 Phase 1 (D-426) — one `metadata_label` row, keyed
/// `"{object_kind}:{object_ref}:{locale}"`. **Export only today**, the same
/// posture [`COMPONENT_SETTING`] documents and for the same reason: a
/// `labels` field present in an *imported* bundle is silently ignored by
/// `apply.rs` until a diff/apply step exists for it.
pub const COMPONENT_METADATA_LABEL: &str = "metadata_label";
/// M01 Core P3 gap (D-455) — one `relationship_info` row, keyed by
/// its `name` (the same key `RelationshipRegistry` uses).
pub const COMPONENT_RELATIONSHIP: &str = "relationship";
/// M65 Phase 1 (D-467) — one `app` row, keyed by its `name`.
pub const COMPONENT_APP: &str = "app";
/// M45 Phase 2 (D-472) — one `rule` row, keyed by
/// `"{entity}:{name}"` (`name` is only unique within one entity, unlike a
/// relationship's plain `name`). `rule_version`'s publish history is
/// NOT exported — a bundle carries desired configuration state, not audit
/// history, same posture every other component takes (no `id`/timestamp/
/// `row_version` — see this module's own header comment); the target
/// deployment's `rule_admin::reconcile_rule` starts a fresh `version = 1`.
pub const COMPONENT_RULE: &str = "rule";

/// A whole bundle. Component vectors are in a fixed order in the struct and
/// each is sorted by its logical key once [`Bundle::normalize`] has run —
/// which [`super::canonical::canonical_json`] always does first.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Bundle {
    /// Always [`BUNDLE_FORMAT`] for a bundle this binary wrote.
    pub format: String,
    /// M92 Phase 1 — the bundle's own identity: a stable slug an operator
    /// assigns when authoring a named, versioned artifact (a vertical pack,
    /// `bundle-tool export`'s hand-corrected output — see the verticals
    /// skill's "procedure gaps" §2). `None` for an anonymous whole-deployment
    /// export/promotion, which is the common case `export_bundle` produces
    /// and is not itself a "named bundle". Populated identity is what lets
    /// the ledger answer "which bundles are installed, at which versions"
    /// (`bundle_name`/`bundle_version` in `routes::PlanListItem`) and is what
    /// `requires.depends_on_bundles` and `POST …/bundles/{name}/rollback`
    /// key on.
    #[serde(default)]
    pub name: Option<String>,
    /// Paired with [`Bundle::name`] — `"MAJOR.MINOR.PATCH"`, the version this
    /// specific snapshot represents (not a floor; contrast
    /// [`Requires::platform_version`]/[`BundleDependency::min_version`],
    /// which are floors expressed as `">=MAJOR.MINOR.PATCH"`).
    #[serde(default)]
    pub version: Option<String>,
    pub requires: Requires,
    #[serde(default)]
    pub entities: Vec<EntityDef>,
    #[serde(default)]
    pub queries: Vec<QueryDef>,
    #[serde(default)]
    pub views: Vec<ViewDef>,
    /// D-404 / M83 Phase 1 — business calendars, holidays embedded per
    /// calendar (a holiday has no independent identity outside its
    /// calendar).
    #[serde(default)]
    pub calendars: Vec<CalendarDef>,
    #[serde(default)]
    pub sidebar: Vec<SidebarDef>,
    #[serde(default)]
    pub roles: Vec<RoleDef>,
    #[serde(default)]
    pub privileges: Vec<PrivilegeDef>,
    #[serde(default)]
    pub field_security_profiles: Vec<FieldSecurityProfileDef>,
    /// Phase 3 (reference data) — see [`RecordSet`]. Always present; empty
    /// when the bundle carries no reference data.
    #[serde(default)]
    pub record_sets: Vec<RecordSet>,
    /// M02/D-412 — deployment-scope `setting` values. Export-only;
    /// see [`COMPONENT_SETTING`].
    #[serde(default)]
    pub settings: Vec<SettingDef>,
    /// M07 Phase 1 (D-405/D-406) — see [`StateModelDef`].
    #[serde(default)]
    pub state_models: Vec<StateModelDef>,
    /// M05 Phase 1 (D-426) — deployment-scope `metadata_label`
    /// rows. Export-only; see [`COMPONENT_METADATA_LABEL`].
    #[serde(default)]
    pub labels: Vec<LabelDef>,
    /// M01 Core P3 gap (D-455) — see [`RelationshipDef`].
    #[serde(default)]
    pub relationships: Vec<RelationshipDef>,
    // No `forms`: forms are code (D-788/D-790). An older bundle's `forms`
    // key is an unknown field and deserializes to nothing.
    /// M65 Phase 1 (D-467) — see [`AppDef`].
    #[serde(default)]
    pub apps: Vec<AppDef>,
    /// M45 Phase 2 (D-472) — see [`RuleDef`].
    #[serde(default)]
    pub rules: Vec<RuleDef>,
    /// Additive cross-module field promotion — see [`AttributePatch`].
    /// Always present; empty when the bundle carries no patches. Never
    /// exported automatically, same posture as [`Bundle::record_sets`]: hand
    /// authored, since export has no way to know which fields on an entity
    /// this bundle doesn't own are "this vertical's".
    #[serde(default)]
    pub attribute_patches: Vec<AttributePatch>,
}

/// One field promoted onto an entity this bundle does not otherwise define —
/// the fix for the gap the verticals skill documents repeatedly (M77/M78/
/// M82/M74): a vertical needing e.g. `asset_ref` on `service_ticket` (owned by a
/// different module) previously had no way to add just that field without
/// including `service_ticket`'s full [`EntityDef`], which would either re-assert
/// every one of that entity's other attributes or — on a target lacking the
/// owning module — wrongly create a stub entity from scratch.
///
/// The key difference from [`EntityDef`]: [`super::plan::diff_attribute_patches`]
/// never creates `entity` if it doesn't already exist live. A patch only
/// ever augments an entity, never brings one into being — see that
/// function's own doc comment for the exact semantics.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AttributePatch {
    /// Target entity logicalname. Must already exist on the deployment this
    /// bundle is applied to, or the patch is `Blocked` at plan time.
    pub entity: String,
    pub attribute: AttributeDef,
}

/// What a bundle needs from the deployment it is applied to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Requires {
    /// A minimum server version, `">=MAJOR.MINOR.PATCH"` (a bare
    /// `MAJOR.MINOR.PATCH` is read the same way). The exporter writes the
    /// exporting binary's own version.
    pub platform_version: String,
    /// The highest applied migration ordinal the bundle was exported against
    /// — the floor the target must have reached (`attome_db::schema_state`).
    pub schema_version: i64,
    /// License module keys (`attome_modules::MODULE_MAP` names) the bundle's
    /// content references. The exporter writes the distinct
    /// `sidebar.module_key` values plus `core`.
    #[serde(default)]
    pub modules: Vec<String>,
    /// M92 Phase 1 — other named bundles ([`Bundle::name`]) this bundle
    /// assumes are already installed, and the floor version of each. Checked
    /// at plan time against the ledger's own applied-bundle history
    /// ([`super::plan::check_bundle_dependencies`]): unlike
    /// `platform_version`/`schema_version`/`modules` above (which
    /// `check_requires` verifies purely, from arguments the caller already
    /// has), this needs the ledger, so it is verified separately in
    /// [`super::plan::plan_bundle`].
    #[serde(default)]
    pub depends_on_bundles: Vec<BundleDependency>,
}

/// One entry of [`Requires::depends_on_bundles`] — M92 Phase 1.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct BundleDependency {
    /// The required bundle's [`Bundle::name`].
    pub name: String,
    /// A floor, `">=MAJOR.MINOR.PATCH"` (a bare `MAJOR.MINOR.PATCH` is read
    /// the same way) — the same convention [`Requires::platform_version`]
    /// uses.
    pub min_version: String,
}

/// `entity_info` — one entity and its attributes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct EntityDef {
    pub logicalname: String,
    /// `entity_info.name`.
    pub display_name: String,
    #[serde(default)]
    pub primary_name_attribute: Option<String>,
    #[serde(default)]
    pub is_append_only: bool,
    #[serde(default)]
    pub is_audited: bool,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub is_customized: bool,
    #[serde(default)]
    pub attributes: Vec<AttributeDef>,
}

/// `attribute_info` — one field of an entity. `entity_ref` is the
/// parent [`EntityDef`]; `lookup_entity_ref` is carried as the target's
/// logicalname. `default_value` is deliberately absent: nothing in the
/// platform reads or writes that legacy column (the backfill default of a
/// schema-change plan is not stored on the attribute), and `AttributeDesc`
/// has no slot for it, so it could never be applied.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AttributeDef {
    pub logicalname: String,
    /// `attribute_info.name`.
    pub display_name: String,
    /// One of [`KNOWN_FIELD_TYPES`].
    pub field_type: String,
    #[serde(default)]
    pub is_required: bool,
    #[serde(default)]
    pub is_sensitive: bool,
    /// D-507: writes need a field-security `can_update` grant; reads don't.
    /// `#[serde(default)]` so a bundle authored before D-507 still parses.
    #[serde(default)]
    pub is_write_restricted: bool,
    #[serde(default)]
    pub is_sortable: bool,
    #[serde(default)]
    pub is_filterable: bool,
    /// Target entity logicalname for `field_type == "lookup"`.
    #[serde(default)]
    pub lookup_entity: Option<String>,
    #[serde(default)]
    pub options: Option<serde_json::Value>,
    #[serde(default)]
    pub max_length: Option<i32>,
    /// `orphan` (the column default) unless set.
    #[serde(default = "default_on_target_delete")]
    pub on_target_delete: String,
    /// `general` (the column default) unless set.
    #[serde(default = "default_data_classification")]
    pub data_classification: String,
    /// Developer-facing note on why this field exists — locale-less, never
    /// shown to end users (distinct from the label-store `description`,
    /// D-426, which this bundle format does not carry — see `LabelDef`).
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub is_customized: bool,
}

fn default_on_target_delete() -> String {
    "orphan".to_owned()
}

fn default_data_classification() -> String {
    "general".to_owned()
}

/// `sql_query` — one stored query. The key is `(entity, name)`;
/// `entity` is `None` for a multi-entity query (`entity_logical_name IS
/// NULL`). `name` is the table's `record_no` column, which is what every
/// admin surface calls the query's name.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct QueryDef {
    #[serde(default)]
    pub entity: Option<String>,
    pub name: String,
    /// `sql_query.sql_query`.
    pub sql: String,
    /// `sql_query.table_definition` — the editor's column JSON, kept
    /// as the string the table stores.
    #[serde(default)]
    pub table_definition: Option<String>,
    #[serde(default)]
    pub required_privilege: Option<String>,
    #[serde(default)]
    pub is_report: bool,
    /// The *current* published version's entity/id-column mappings
    /// (`sql_query_entity_mapping`, D-146).
    #[serde(default)]
    pub entity_mappings: Vec<QueryEntityMapping>,
    #[serde(default)]
    pub is_customized: bool,
}

/// One `sql_query_entity_mapping` row, entity carried by logicalname.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct QueryEntityMapping {
    pub entity: String,
    pub id_column: String,
}

/// The logical key of a stored query, as referenced from a [`ViewDef`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct QueryRef {
    #[serde(default)]
    pub entity: Option<String>,
    pub name: String,
}

/// `view` — one view. `entity_logical_name` (a uuid despite its
/// name) is carried as the entity's logicalname; `sql_query_ref` as the
/// query's logical key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ViewDef {
    pub entity: String,
    pub name: String,
    pub query: QueryRef,
    #[serde(default = "default_view_icon")]
    pub icon: String,
    /// `view.table_definition` (jsonb).
    #[serde(default = "default_table_definition")]
    pub table_definition: serde_json::Value,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default)]
    pub is_customized: bool,
    /// D-429 — `list` (default) | `kanban` | `calendar` | `timeline`. Only
    /// `system`-scope views are ever bundle-exported/reconciled; `personal`/
    /// `shared` rows are per-user runtime data.
    #[serde(default = "default_view_kind")]
    pub kind: String,
    /// D-429 — kind-specific settings (`state_field`/`wip_limits` for
    /// kanban; `start_field`/`end_field`/`color_field` for calendar/timeline).
    #[serde(default = "default_view_metadata")]
    pub view_metadata: serde_json::Value,
}

fn default_view_icon() -> String {
    "las la-table".to_owned()
}

fn default_view_kind() -> String {
    "list".to_owned()
}

fn default_view_metadata() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

fn default_table_definition() -> serde_json::Value {
    serde_json::Value::Array(Vec::new())
}

/// `calendar` — one named business calendar (D-404 / M83 Phase 1).
/// Not a generic XRM entity (same posture as `ViewDef`/`view`), so
/// addressed by `name` alone rather than `(entity, name)`. `working_days` is
/// a lowercase 3-letter weekday array (`"mon"`..`"sun"`); `hours` is
/// `{"mon": [{"start_minute": 540, "end_minute": 1020}], ...}`, matching
/// `calendar.hours`'s jsonb shape exactly (round-tripped verbatim,
/// not reparsed into a typed shape here — the same posture `ViewDef.
/// table_definition` already takes for its own opaque jsonb column).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct CalendarDef {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub tz: String,
    #[serde(default)]
    pub working_days: Vec<String>,
    #[serde(default = "default_calendar_hours")]
    pub hours: serde_json::Value,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default)]
    pub is_customized: bool,
    #[serde(default)]
    pub holidays: Vec<HolidayDef>,
    /// D-592 per-date exceptions. `None` (a bundle written before they
    /// existed) leaves the target's exceptions alone; `Some` is the exact
    /// list, keyed by `exception_date`. Export always writes `Some`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exceptions: Option<Vec<CalendarExceptionDef>>,
    /// Z12-T4: the calendar this one inherits from, by name. `None` leaves
    /// the target's parent alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Z12-T3: an ISO 3166 country code, such as `SA`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_ar: Option<String>,
    /// Z12-T6: holiday rules by name. `None` leaves the target's alone;
    /// `Some` is the exact list. Export writes them when there are any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<HolidayRuleDef>>,
    /// Z12-T6: seasonal hours by name, the same way as `rules`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seasons: Option<Vec<SeasonDef>>,
}

/// One `calendar_holiday_rule` row (Z12-T6), embedded under its calendar and
/// identified by `name` within it. `rule` is an
/// `attome_calendar::rules::HolidayRule` (`{"kind": "hijri", "month": 10,
/// "day": 1, "span_days": 3}`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct HolidayRuleDef {
    pub name: String,
    #[serde(default)]
    pub name_ar: Option<String>,
    #[schema(value_type = Object)]
    pub rule: serde_json::Value,
    /// A Hijri holiday whose start moves when the moon is sighted.
    #[serde(default)]
    pub needs_sighting: bool,
}

/// One `calendar_season` row (Z12-T6), identified by `name` within its
/// calendar. `definition` is an `attome_calendar::rules::Season`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SeasonDef {
    pub name: String,
    #[serde(default)]
    pub name_ar: Option<String>,
    #[schema(value_type = Object)]
    pub definition: serde_json::Value,
}

fn default_calendar_hours() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// One `calendar_holiday` row, embedded under its calendar.
/// Identified by `holiday_date` within its calendar (D-592); `name` is a
/// label, so "Eid al-Fitr" can appear once per year.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct HolidayDef {
    pub name: String,
    /// `YYYY-MM-DD` — a specific date, not a recurring rule (M83 §5:
    /// "Holidays... stored per calendar", no recurrence in Phase 1).
    #[schema(value_type = String, format = "date")]
    pub holiday_date: chrono::NaiveDate,
}

/// One `calendar_exception` row (D-592), embedded under its
/// calendar and identified by `exception_date` within it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct CalendarExceptionDef {
    pub name: String,
    #[schema(value_type = String, format = "date")]
    pub exception_date: chrono::NaiveDate,
    /// `[{"start_minute", "end_minute"}]` on that local date; `[]` closes it.
    #[schema(value_type = Vec<Object>)]
    pub ranges: serde_json::Value,
}

/// `sidebar` — one navigation item, addressed by its name path from the
/// root (`parent_ref` is what the path replaces). `privileges` are the
/// `sidebar_mm_privilege` rows as privilege keys.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SidebarDef {
    /// Root-first name path; the last element is this item's own `name`.
    pub path: Vec<String>,
    #[serde(default)]
    pub route: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub display_order: i32,
    #[serde(default)]
    pub is_container: bool,
    /// `sidebar.entity_logical_name` (already TEXT).
    #[serde(default)]
    pub entity: Option<String>,
    #[serde(default)]
    pub module_key: Option<String>,
    #[serde(default)]
    pub is_disabled: bool,
    #[serde(default)]
    pub privileges: Vec<String>,
    #[serde(default)]
    pub is_customized: bool,
}

/// `role` — one role with its grants, entity access rows and
/// field-security profile links. `owner_ref`/`owner_type` are deliberately
/// absent: the owner is a user or team, i.e. environment identity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RoleDef {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// `role.access_level` (smallint; 3 = Global).
    #[serde(default = "default_access_level")]
    pub access_level: i16,
    #[serde(default)]
    pub position_hierarchy_enabled: bool,
    #[serde(default)]
    pub is_customized: bool,
    /// `role_mm_privilege` rows (+ their D-369 conditions).
    #[serde(default)]
    pub privileges: Vec<RoleGrant>,
    /// `role_mm_entity_access` rows, entity by logicalname.
    #[serde(default)]
    pub entity_access: Vec<RoleEntityAccess>,
    /// `role_mm_field_security_profile` rows, as profile names.
    #[serde(default)]
    pub field_security_profiles: Vec<String>,
}

fn default_access_level() -> i16 {
    3
}

/// One role ⟷ privilege grant and its bounded record conditions
/// (`role_privilege_condition`, D-369).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RoleGrant {
    /// Privilege key.
    pub privilege: String,
    #[serde(default)]
    pub conditions: Vec<GrantCondition>,
}

/// One `role_privilege_condition` row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct GrantCondition {
    /// `field_logicalname`.
    pub field: String,
    /// 0=eq 1=ne 2=gt 3=lt 4=gte 5=lte 6=in (the table's own encoding).
    pub operator: i16,
    pub value: serde_json::Value,
}

/// One `role_mm_entity_access` row (D-133 per-entity depth,
/// 0130's owner-visible flags).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RoleEntityAccess {
    pub entity: String,
    pub read_access_level: i16,
    pub write_access_level: i16,
    pub delete_access_level: i16,
    #[serde(default)]
    pub read_owner_visible: bool,
    #[serde(default)]
    pub write_owner_visible: bool,
    #[serde(default)]
    pub delete_owner_visible: bool,
}

/// `privilege` — privileges are platform-minted per entity
/// (`{entity}.read` etc. through `ensure_privilege`) and are therefore never
/// retired by a bundle; they are carried so a custom privilege key a role
/// grant or sidebar item names exists on the target before the grant does.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct PrivilegeDef {
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// One deployment-scope `setting` row (M02/D-412). No `scope`
/// field — a bundle only ever carries the deployment-scope value for a key,
/// never an organization- or user-scope override, matching D-412's ruling
/// that "profile" means "deployment-scope values", nothing more.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SettingDef {
    /// `"{module}.{name}"` — validated against the live
    /// `SettingRegistry` at apply time once that step exists; export never
    /// writes a key the registry doesn't recognize, since it only ever reads
    /// rows that a registry-checked write already validated.
    pub key: String,
    pub value: serde_json::Value,
}

/// `field_security_profile` and its `_field` members.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct FieldSecurityProfileDef {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub is_customized: bool,
    #[serde(default)]
    pub fields: Vec<ProfileField>,
}

/// One `field_security_profile_field` row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ProfileField {
    /// `entity_logicalname`.
    pub entity: String,
    /// `field_logicalname`.
    pub field: String,
    pub can_read: bool,
    pub can_update: bool,
}

/// Phase 3 reference data: rows of one entity keyed by a declared business
/// key (P-environment-promotion §5 step 24). `key_fields` name the row's
/// attributes that together form its identity (e.g. `["name"]` for a
/// notification template's unique key) — resolved to a live record's id at
/// *plan* time ([`super::plan::plan_bundle`]) and applied through the
/// ordinary entity-mutation primitives ([`super::apply`]).
///
/// A lookup field's value is either a literal id or a key reference to its
/// target — `{"key": {"name": "API Key"}}` — resolved to the one active target
/// row that key matches (D-534, [`super::record_sets`]'s module doc). Reference
/// data another bundle seeds must be named by key: its id differs between a
/// deployment that created the row and one where it predates that bundle.
///
/// **Never exported automatically.** Unlike every other component,
/// [`super::export::export_bundle`] never populates `record_sets` — `SELECT`
/// against an arbitrary metadata-defined entity table with no declared key
/// convention would have to guess what "the key" is, and a wrong guess
/// silently reference-datas the wrong rows on the next apply. A record set is
/// authored by hand (or by `bundle-tool`, given the target entity and key
/// fields explicitly) and merged into a bundle deliberately — the F273
/// vertical-pack convention this phase generalizes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RecordSet {
    pub entity: String,
    pub key_fields: Vec<String>,
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub rows: Vec<serde_json::Map<String, serde_json::Value>>,
}

/// M07 Phase 1 (D-405/D-406) — `state_model`, keyed by
/// `entity_logicalname` (one live model per entity, enforced by a partial
/// unique index — see `0155_state_lifecycle.sql`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct StateModelDef {
    pub entity_logicalname: String,
    pub name: String,
    /// A `Choice` attribute logicalname on `entity_logicalname`.
    pub state_field: String,
    pub initial_state: String,
    #[serde(default = "default_true")]
    pub is_active: bool,
    #[serde(default)]
    pub transitions: Vec<StateTransitionDef>,
}

fn default_true() -> bool {
    true
}

/// `state_transition` — set semantics inside its parent
/// [`StateModelDef`], the same convention [`ProfileField`] uses inside
/// [`FieldSecurityProfileDef`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct StateTransitionDef {
    pub from_state: String,
    pub to_state: String,
    pub name: String,
    #[serde(default)]
    pub required_privilege: Option<String>,
    /// M45 — nullable, schema-ready, unevaluated in Phase 1.
    #[serde(default)]
    pub guard_expression: Option<String>,
    #[serde(default)]
    pub entry_actions: Vec<String>,
    #[serde(default)]
    pub exit_actions: Vec<String>,
    #[serde(default)]
    pub display_order: i32,
    /// M07 Phase F (D-770): a `attome-approval` plan the transition runs before
    /// it happens; requires `pending_state`. Omitted from an export when
    /// absent, so bundles without approvals are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_plan: Option<attome_approval::ApprovalPlan>,
    /// The state the record sits in while the approval is open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_state: Option<String>,
    /// Where a rejection sends the record; absent means `from_state`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_reject_state: Option<String>,
    /// M8-T3: the condition that makes the transition happen by itself.
    /// Omitted from an export when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_condition: Option<String>,
}

/// M05 Phase 1 (D-426) — one `metadata_label` row: a per-locale
/// override of `object_ref`'s display name/description. `object_ref` is the
/// same logical-key shape the table itself uses (never a UUID — see
/// `0201_xrm_core_metadata_label.sql`'s header for the per-`object_kind`
/// shape), so a label survives round-tripping between deployments the same
/// way every other bundle component does.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct LabelDef {
    /// `entity`, `attribute`, `choice_option`, `view`, `sidebar`, or
    /// `dashboard` — see `attome_core::KNOWN_OBJECT_KINDS`.
    pub object_kind: String,
    pub object_ref: String,
    /// A BCP-47 tag, e.g. `"ar-AE"`.
    pub locale: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// M01 Core P3 gap (D-455) — `relationship_info`, keyed by `name`.
/// `join_table` is intentionally NOT part of this definition even though
/// the live row stores it: it is a derived, deterministic function of
/// `name` (`"mm_{name}"`, `reconcile_relationship`'s own convention),
/// never independently authored, so carrying it here would just be a second
/// place the same fact could drift.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RelationshipDef {
    pub name: String,
    pub entity_a: String,
    pub entity_b: String,
    pub role_a: String,
    pub role_b: String,
    /// `"restrict" | "orphan" | "cascade-deactivate"` — see
    /// `attome_core::RelationshipCascade`. C-21 (M01 §7): the underscore
    /// spelling `"cascade_deactivate"` this field wrote before the fix is
    /// still accepted on apply for one release
    /// (`RelationshipCascade::from_db_str`), but a fresh export always
    /// carries the hyphenated form.
    #[serde(default = "default_orphan_cascade")]
    pub cascade: String,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_orphan_cascade() -> String {
    "orphan".to_owned()
}

/// M65 Phase 1 (D-467) — `app`, keyed by `name`. Apps only filter
/// navigation, they never authorize — see `app_admin.rs`'s own doc comment.
///
/// `sidebar_root_ref`/`default_dashboard_ref` are deliberately NOT part of
/// this definition even though the live row stores both: each is a
/// deployment-local UUID pointing at another deployment's own
/// `sidebar`/dashboard-entity row, with no portable identity a bundle
/// could carry across deployments (same shape `RelationshipDef` already
/// excludes `join_table` for — a derived/local fact, not part of the
/// portable definition). An imported app always applies with both null; an
/// admin wires them up post-apply through the admin UI on the target
/// deployment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AppDef {
    pub name: String,
    #[serde(default = "default_app_icon")]
    pub icon: String,
    /// Entity logicalnames — portable across deployments, unlike the two
    /// excluded UUID refs above.
    #[serde(default)]
    pub entities: serde_json::Value,
    /// Privilege keys — portable across deployments.
    #[serde(default)]
    pub roles: serde_json::Value,
    #[serde(default)]
    pub display_order: i32,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_app_icon() -> String {
    "las la-th-large".to_owned()
}

/// M45 Phase 2 (D-472) — `rule`, keyed by `"{entity}:{name}"`.
/// `version` is deliberately NOT part of this definition (same posture
/// `AppDef` takes for its two excluded local UUID refs above): a bundle
/// carries the CURRENT definition, not a publish history, and the target
/// deployment always reconciles to `version = 1` on first apply — see
/// `COMPONENT_RULE`'s own doc comment.
///
/// **Business rules (D-789, D-791; `BUSINESS-RULES-DESIGN.md` §7).** A
/// `kind = "business"` definition carries `applies_to`, `roles` (staff role
/// names), `portal_roles` (`{portal, role}` natural keys), `condition` and
/// `policies` instead of `expression`/`target_field`/`message`. Every added
/// field is optional and skipped when empty, so an expression-kind definition
/// (and the canonical hash of a bundle that holds only those) is unchanged.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RuleDef {
    pub entity_logicalname: String,
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub target_field: Option<String>,
    /// Legacy kinds only; absent on a business rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default = "default_rule_severity")]
    pub severity: String,
    #[serde(default = "default_true")]
    pub is_active: bool,
    #[serde(default)]
    pub display_order: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Business rules: `all` (default) or `roles`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_to: Option<AppliesTo>,
    /// Business rules: staff role names (never UUIDs), sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    /// Business rules: web-portal roles by `{portal keyword, role name}`,
    /// sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub portal_roles: Vec<PortalRoleKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<ConditionTree>,
    /// Business rules: the ordered policies (list order is the ordinal).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<PolicyDef>,
}

/// A web-portal role's natural key: the portal's `keyword` and the role's
/// `name` (unique per portal, `webportal_role_name_unique`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct PortalRoleKey {
    pub portal: String,
    pub role: String,
}

impl RuleDef {
    pub fn key(&self) -> String {
        format!("{}:{}", self.entity_logicalname, self.name)
    }

    /// Whether this is a business-rule definition (`kind = "business"`).
    pub fn is_business(&self) -> bool {
        self.kind == BUSINESS_KIND
    }

    /// The definition in the shape the live row takes: a business rule's
    /// `applies_to` defaulted, every other definition unchanged. Compare-first
    /// planning uses it so an omitted default plans as `noop`.
    pub fn as_stored(&self) -> RuleDef {
        let mut out = self.clone();
        if self.is_business() {
            out.applies_to = Some(self.applies_to.unwrap_or_default());
        }
        out
    }
}

fn default_rule_severity() -> String {
    "error".to_owned()
}

// ── Format gate ───────────────────────────────────────────────────────────────

/// Why a bundle's `format` was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormatError {
    /// The string does not start with `attome-bundle/v` at all.
    NotABundle(String),
    /// A later major than [`BUNDLE_FORMAT`] — written by a newer binary.
    Newer(String),
    /// An older major this binary no longer reads (none exist yet; kept so
    /// the day one does, the error is already distinct).
    Unsupported(String),
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormatError::NotABundle(s) => {
                write!(
                    f,
                    "'{s}' is not an attome bundle (expected {BUNDLE_FORMAT})"
                )
            }
            FormatError::Newer(s) => write!(
                f,
                "bundle format '{s}' is newer than this server understands ({BUNDLE_FORMAT}); upgrade the server first"
            ),
            FormatError::Unsupported(s) => {
                write!(
                    f,
                    "bundle format '{s}' is not supported by this server ({BUNDLE_FORMAT})"
                )
            }
        }
    }
}

impl std::error::Error for FormatError {}

/// Accepts exactly [`BUNDLE_FORMAT`]; classifies everything else.
pub fn check_format(format: &str) -> Result<(), FormatError> {
    if format == BUNDLE_FORMAT {
        return Ok(());
    }
    let Some(rest) = format.strip_prefix(BUNDLE_FORMAT_PREFIX) else {
        return Err(FormatError::NotABundle(format.to_owned()));
    };
    let Some(ours) = BUNDLE_FORMAT.strip_prefix(BUNDLE_FORMAT_PREFIX) else {
        return Err(FormatError::Unsupported(format.to_owned()));
    };
    match (rest.parse::<u32>(), ours.parse::<u32>()) {
        (Ok(theirs), Ok(mine)) if theirs > mine => Err(FormatError::Newer(format.to_owned())),
        _ => Err(FormatError::Unsupported(format.to_owned())),
    }
}

/// Parses bundle JSON and refuses an unknown or newer `format` before
/// anything else looks at the content. The format is checked *first* on the
/// raw document so a newer bundle that added fields this binary cannot
/// deserialize still gets the "newer than this server" message rather than
/// a serde error.
pub fn parse_bundle(json: &[u8]) -> Result<Bundle, attome_types::AppError> {
    #[derive(Deserialize)]
    struct Header {
        format: String,
    }
    let header: Header = serde_json::from_slice(json).map_err(|e| {
        attome_types::AppError::Validation(format!("bundle is not valid JSON: {e}"))
    })?;
    check_format(&header.format).map_err(|e| attome_types::AppError::Validation(e.to_string()))?;
    let mut bundle: Bundle = serde_json::from_slice(json).map_err(|e| {
        attome_types::AppError::Validation(format!("bundle does not match {BUNDLE_FORMAT}: {e}"))
    })?;
    bundle.normalize();
    Ok(bundle)
}

// ── Keys and normalization ────────────────────────────────────────────────────

impl QueryDef {
    /// The logical key this query is addressed by.
    pub fn key(&self) -> QueryRef {
        QueryRef {
            entity: self.entity.clone(),
            name: self.name.clone(),
        }
    }
}

impl QueryRef {
    /// Human form, `entity.name` or `*.name` for a multi-entity query.
    pub fn display(&self) -> String {
        match &self.entity {
            Some(e) => format!("{e}.{}", self.name),
            None => format!("*.{}", self.name),
        }
    }
}

impl SidebarDef {
    /// Human form of the path, `Group/Item`.
    pub fn path_display(&self) -> String {
        self.path.join("/")
    }
}

impl Bundle {
    /// An empty bundle carrying this binary's own `requires`.
    pub fn empty(requires: Requires) -> Self {
        Bundle {
            format: BUNDLE_FORMAT.to_owned(),
            name: None,
            version: None,
            requires,
            entities: Vec::new(),
            queries: Vec::new(),
            views: Vec::new(),
            calendars: Vec::new(),
            sidebar: Vec::new(),
            roles: Vec::new(),
            privileges: Vec::new(),
            field_security_profiles: Vec::new(),
            record_sets: Vec::new(),
            settings: Vec::new(),
            state_models: Vec::new(),
            labels: Vec::new(),
            relationships: Vec::new(),
            apps: Vec::new(),
            rules: Vec::new(),
            attribute_patches: Vec::new(),
        }
    }

    /// Sorts every component vector by its logical key, recursively, and
    /// de-duplicates the plain string lists (`requires.modules`, sidebar
    /// privileges, role profile links). Two bundles with the same content in
    /// a different order normalize to equal values — this is what makes
    /// `canonical_json` order-independent.
    pub fn normalize(&mut self) {
        sort_dedup(&mut self.requires.modules);
        self.requires
            .depends_on_bundles
            .sort_by(|a, b| a.name.cmp(&b.name));

        for e in &mut self.entities {
            e.attributes
                .sort_by(|a, b| a.logicalname.cmp(&b.logicalname));
        }
        self.entities
            .sort_by(|a, b| a.logicalname.cmp(&b.logicalname));

        for q in &mut self.queries {
            q.entity_mappings.sort();
        }
        self.queries.sort_by_key(QueryDef::key);

        self.views
            .sort_by(|a, b| (&a.entity, &a.name).cmp(&(&b.entity, &b.name)));

        for c in &mut self.calendars {
            c.holidays.sort();
            if let Some(exceptions) = c.exceptions.as_mut() {
                exceptions.sort_by_key(|e| e.exception_date);
            }
        }
        self.calendars.sort_by(|a, b| a.name.cmp(&b.name));

        for s in &mut self.sidebar {
            sort_dedup(&mut s.privileges);
        }
        self.sidebar.sort_by(|a, b| a.path.cmp(&b.path));

        for r in &mut self.roles {
            for g in &mut r.privileges {
                g.conditions.sort_by(|a, b| {
                    (&a.field, a.operator, a.value.to_string()).cmp(&(
                        &b.field,
                        b.operator,
                        b.value.to_string(),
                    ))
                });
            }
            r.privileges.sort_by(|a, b| a.privilege.cmp(&b.privilege));
            r.entity_access.sort_by(|a, b| a.entity.cmp(&b.entity));
            sort_dedup(&mut r.field_security_profiles);
        }
        self.roles.sort_by(|a, b| a.name.cmp(&b.name));

        self.privileges.sort_by(|a, b| a.key.cmp(&b.key));

        for p in &mut self.field_security_profiles {
            p.fields
                .sort_by(|a, b| (&a.entity, &a.field).cmp(&(&b.entity, &b.field)));
        }
        self.field_security_profiles
            .sort_by(|a, b| a.name.cmp(&b.name));

        for rs in &mut self.record_sets {
            let keys = rs.key_fields.clone();
            rs.rows.sort_by(|a, b| {
                let ka: Vec<String> = keys
                    .iter()
                    .map(|k| a.get(k).map(ToString::to_string).unwrap_or_default())
                    .collect();
                let kb: Vec<String> = keys
                    .iter()
                    .map(|k| b.get(k).map(ToString::to_string).unwrap_or_default())
                    .collect();
                ka.cmp(&kb)
            });
        }
        self.record_sets.sort_by(|a, b| a.entity.cmp(&b.entity));

        self.settings.sort_by(|a, b| a.key.cmp(&b.key));

        for m in &mut self.state_models {
            m.transitions
                .sort_by(|a, b| (&a.from_state, &a.to_state).cmp(&(&b.from_state, &b.to_state)));
        }
        self.state_models
            .sort_by(|a, b| a.entity_logicalname.cmp(&b.entity_logicalname));

        self.labels.sort_by(|a, b| {
            (&a.object_kind, &a.object_ref, &a.locale).cmp(&(
                &b.object_kind,
                &b.object_ref,
                &b.locale,
            ))
        });

        self.relationships.sort_by(|a, b| a.name.cmp(&b.name));

        self.apps.sort_by(|a, b| a.name.cmp(&b.name));
        for r in &mut self.rules {
            sort_dedup(&mut r.roles);
            r.portal_roles.sort();
            r.portal_roles.dedup();
        }
        self.rules.sort_by_key(RuleDef::key);

        self.attribute_patches.sort_by(|a, b| {
            (&a.entity, &a.attribute.logicalname).cmp(&(&b.entity, &b.attribute.logicalname))
        });
    }
}

fn sort_dedup(v: &mut Vec<String>) {
    v.sort();
    v.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_gate_accepts_only_v1() {
        assert_eq!(check_format("attome-bundle/v1"), Ok(()));
        assert!(matches!(
            check_format("attome-bundle/v2"),
            Err(FormatError::Newer(_))
        ));
        assert!(matches!(
            check_format("attome-bundle/v99"),
            Err(FormatError::Newer(_))
        ));
        assert!(matches!(
            check_format("attome-bundle/v0"),
            Err(FormatError::Unsupported(_))
        ));
        assert!(matches!(
            check_format("attome-bundle/vx"),
            Err(FormatError::Unsupported(_))
        ));
        assert!(matches!(
            check_format("something-else"),
            Err(FormatError::NotABundle(_))
        ));
        assert!(matches!(check_format(""), Err(FormatError::NotABundle(_))));
    }

    #[test]
    fn parse_refuses_newer_format_before_deserializing_content() {
        // A newer bundle with a shape this binary cannot read — the message
        // must still be the format one.
        let err = parse_bundle(br#"{"format":"attome-bundle/v2","requires":"garbage"}"#)
            .expect_err("newer format must be refused");
        let msg = err.to_string();
        assert!(msg.contains("newer than this server"), "{msg}");
    }

    #[test]
    fn parse_fills_defaults_and_normalizes() {
        let json = br#"{
            "format": "attome-bundle/v1",
            "requires": {"platform_version": ">=0.0.0", "schema_version": 0},
            "entities": [
                {"logicalname": "b", "display_name": "B", "attributes": [
                    {"logicalname": "z", "display_name": "Z", "field_type": "text"},
                    {"logicalname": "a", "display_name": "A", "field_type": "text"}
                ]},
                {"logicalname": "a", "display_name": "A"}
            ]
        }"#;
        let b = parse_bundle(json).expect("valid v1 bundle");
        assert_eq!(b.entities[0].logicalname, "a");
        assert_eq!(b.entities[1].attributes[0].logicalname, "a");
        assert_eq!(b.entities[1].attributes[0].on_target_delete, "orphan");
        assert_eq!(b.entities[1].attributes[0].data_classification, "general");
        assert!(b.record_sets.is_empty());
        assert!(b.requires.modules.is_empty());
    }

    #[test]
    fn parse_rejects_non_json() {
        let err = parse_bundle(b"not json").expect_err("must fail");
        assert!(matches!(err, attome_types::AppError::Validation(_)));
    }
}
