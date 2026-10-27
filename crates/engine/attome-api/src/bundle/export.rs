//! Export: live metadata → [`Bundle`] (P-environment-promotion §5 step 9).
//!
//! Read-only. Every read is bound, column-enumerated SQL against the pool
//! the caller hands in, and every UUID reference is translated to the
//! target's logical key before it reaches the model:
//!
//! | table.column | carried as |
//! |---|---|
//! | `attribute_info.entity_ref` | the parent [`EntityDef`] |
//! | `attribute_info.lookup_entity_ref` | `lookup_entity` logicalname |
//! | `sql_query.entity_logical_name` (a **uuid**) | `QueryDef.entity` logicalname |
//! | `sql_query_entity_mapping.entity_ref` | `entity` logicalname |
//! | `view.entity_logical_name` (uuid) | `ViewDef.entity` logicalname |
//! | `view.sql_query_ref` | `ViewDef.query` = the query's `(entity, name)` |
//! | `sidebar.parent_ref` | the root-first name `path` |
//! | `sidebar_mm_privilege.(sidebar_ref, privilege_ref)` | `SidebarDef.privileges` keys |
//! | `role_mm_privilege.(role_ref, privilege_ref)` | `RoleDef.privileges` keys |
//! | `role_privilege_condition.role_privilege_ref` | nested under its grant |
//! | `role_mm_entity_access.(role_ref, entity_ref)` | `RoleDef.entity_access` logicalname |
//! | `role_mm_field_security_profile.(role_ref, profile_ref)` | profile names |
//! | `field_security_profile_field.profile_ref` | nested under its profile |
//!
//! **Allow-list.** Only the component types the model defines are read —
//! there is no generic "dump this table" path here, so users, user grants,
//! API keys, S2S clients, the license, sessions, and any future table cannot
//! leak into an export by omission. Adding a component means adding a type
//! to `model.rs` and a reader here, deliberately.
//!
//! Only *active* rows are exported (`is_active`, or `is_deleted = false`
//! where that is the table's liveness flag). A retired object is, by
//! definition, absent from the bundle — that is how a promoted removal is
//! expressed (§4 "Removals are promoted as soft-retire").
//!
//! Rows that have no logical identity — a stored query with an empty
//! `record_no`, a sidebar item whose parent chain is broken — are skipped
//! with a `warn` naming the row, never silently, because a bundle can only
//! address what it can name.
//!
//! **Row -> component mappings are shared.** Each reader selects into a named
//! row struct and maps it with a `pub(crate)` function (`entity_def`,
//! `attribute_def`, `view_def`, ...). The changeset close
//! (`crate::changeset::translate`, D-785) deserializes a recorded row
//! snapshot into the same struct and maps it with the same function, so an
//! exported component and a recorded operation's `definition` cannot
//! disagree about what a row means. The row structs therefore derive
//! `Deserialize` as well as `FromRow`; their field names are the column names.

use std::collections::{BTreeSet, HashMap};

use attome_db::DbPool;
use attome_types::AppError;
use serde::Deserialize;
use uuid::Uuid;

use super::model::*;

/// This binary's own version, the floor an exported bundle declares.
pub const PLATFORM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `attribute_info.type` → the `ensure_attribute` vocabulary. C-16
/// (M01 §7): the map itself (the legacy integer aliases 2/4/9/10, 8, 13
/// folding onto their canonical name) lives once on
/// `attome_core::FieldType`; this is just the `&str` adapter this
/// module's export rows need.
fn int_to_type(t: i32) -> &'static str {
    attome_core::FieldType::from_int(t)
        .unwrap_or(attome_core::FieldType::Text)
        .as_str()
}

// ── Row shapes ───────────────────────────────────────────────────────────────
// Named rather than tuples: the wide ones are unreadable as tuples, and a
// name per column is what keeps the SELECT lists honest.

// `id` and parent-ref columns carry `#[serde(default)]`: a recorded snapshot
// is keyed by its logical target, so the changeset translation does not need
// them.

#[derive(sqlx::FromRow, Deserialize)]
pub(crate) struct EntityRow {
    #[serde(default)]
    pub(crate) id: Uuid,
    pub(crate) logicalname: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) primary_name_attribute: Option<String>,
    pub(crate) is_append_only: bool,
    pub(crate) is_audited: Option<bool>,
    pub(crate) category: Option<String>,
    pub(crate) is_customized: bool,
}

/// `entity_info` row -> [`EntityDef`] without attributes; `None`
/// when the row has no logicalname (it cannot be addressed).
pub(crate) fn entity_def(r: EntityRow) -> Option<EntityDef> {
    let logicalname = r.logicalname.filter(|s| !s.is_empty())?;
    Some(EntityDef {
        display_name: r.name.unwrap_or_else(|| logicalname.clone()),
        logicalname,
        primary_name_attribute: r.primary_name_attribute,
        is_append_only: r.is_append_only,
        is_audited: r.is_audited.unwrap_or(false),
        category: r.category,
        is_customized: r.is_customized,
        attributes: Vec::new(),
    })
}

/// `lookup_entity` is the lookup target's logicalname (export joins it; the
/// changeset translation resolves `lookup_entity_ref`).
#[derive(sqlx::FromRow, Deserialize)]
pub(crate) struct AttributeRow {
    #[serde(default)]
    pub(crate) id: Uuid,
    #[serde(default)]
    pub(crate) entity_ref: Option<Uuid>,
    pub(crate) logicalname: Option<String>,
    pub(crate) name: Option<String>,
    #[sqlx(rename = "type")]
    #[serde(rename = "type")]
    pub(crate) field_type: Option<i32>,
    pub(crate) required: Option<bool>,
    pub(crate) is_sensitive: bool,
    pub(crate) is_write_restricted: bool,
    pub(crate) is_sortable: bool,
    pub(crate) is_filterable: bool,
    #[serde(default)]
    pub(crate) lookup_entity: Option<String>,
    pub(crate) options: Option<serde_json::Value>,
    pub(crate) max_length: Option<i32>,
    pub(crate) on_target_delete: String,
    pub(crate) data_classification: String,
    pub(crate) purpose: Option<String>,
    pub(crate) is_customized: bool,
}

/// `attribute_info` row -> [`AttributeDef`]; `None` when the row
/// has no logicalname.
pub(crate) fn attribute_def(a: AttributeRow) -> Option<AttributeDef> {
    let logicalname = a.logicalname.filter(|s| !s.is_empty())?;
    Some(AttributeDef {
        display_name: a.name.unwrap_or_else(|| logicalname.clone()),
        logicalname,
        field_type: int_to_type(a.field_type.unwrap_or(3)).to_owned(),
        is_required: a.required.unwrap_or(false),
        is_sensitive: a.is_sensitive,
        is_write_restricted: a.is_write_restricted,
        is_sortable: a.is_sortable,
        is_filterable: a.is_filterable,
        lookup_entity: a.lookup_entity,
        options: a.options,
        max_length: a.max_length,
        on_target_delete: a.on_target_delete,
        data_classification: a.data_classification,
        purpose: a.purpose,
        is_customized: a.is_customized,
    })
}

#[derive(sqlx::FromRow, Deserialize)]
pub(crate) struct QueryRow {
    #[serde(default)]
    pub(crate) id: Uuid,
    pub(crate) entity_logical_name: Option<Uuid>,
    pub(crate) record_no: Option<String>,
    pub(crate) sql_query: Option<String>,
    pub(crate) table_definition: Option<String>,
    pub(crate) required_privilege: Option<String>,
    pub(crate) is_report: bool,
    pub(crate) is_customized: bool,
}

/// `sql_query` row -> [`QueryDef`], its entity already translated
/// to a logicalname; `None` when the query has no name (`record_no`).
pub(crate) fn query_def(
    q: QueryRow,
    entity: Option<String>,
    entity_mappings: Vec<QueryEntityMapping>,
) -> Option<QueryDef> {
    let name = q.record_no.filter(|s| !s.is_empty())?;
    Some(QueryDef {
        entity,
        name,
        sql: q.sql_query.unwrap_or_default(),
        table_definition: q.table_definition,
        required_privilege: q.required_privilege,
        is_report: q.is_report,
        entity_mappings,
        is_customized: q.is_customized,
    })
}

/// `entity` is the view's entity logicalname (export joins it; the changeset
/// translation resolves `entity_logical_name`, a uuid).
#[derive(sqlx::FromRow, Deserialize)]
pub(crate) struct ViewRow {
    #[serde(default)]
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) entity: String,
    pub(crate) sql_query_ref: Uuid,
    pub(crate) icon: String,
    pub(crate) table_definition: serde_json::Value,
    pub(crate) is_default: bool,
    pub(crate) is_customized: bool,
    pub(crate) kind: String,
    pub(crate) view_metadata: serde_json::Value,
}

/// `view` row -> [`ViewDef`], its query already translated.
pub(crate) fn view_def(v: ViewRow, query: QueryRef) -> ViewDef {
    ViewDef {
        entity: v.entity,
        name: v.name,
        query,
        icon: v.icon,
        table_definition: v.table_definition,
        is_default: v.is_default,
        is_customized: v.is_customized,
        kind: v.kind,
        view_metadata: v.view_metadata,
    }
}

#[derive(sqlx::FromRow, Deserialize)]
pub(crate) struct SidebarRow {
    #[serde(default)]
    pub(crate) id: Uuid,
    #[serde(default)]
    pub(crate) parent_ref: Option<Uuid>,
    pub(crate) name: String,
    pub(crate) route: Option<String>,
    pub(crate) icon: Option<String>,
    pub(crate) color: Option<String>,
    pub(crate) display_order: i32,
    pub(crate) is_container: bool,
    pub(crate) entity_logical_name: Option<String>,
    pub(crate) module_key: Option<String>,
    pub(crate) is_disabled: bool,
    pub(crate) is_customized: bool,
}

/// `sidebar` row -> [`SidebarDef`], given its root-first name path and
/// its privilege keys.
pub(crate) fn sidebar_def(s: SidebarRow, path: Vec<String>, privileges: Vec<String>) -> SidebarDef {
    SidebarDef {
        path,
        route: s.route,
        icon: s.icon,
        color: s.color,
        display_order: s.display_order,
        is_container: s.is_container,
        entity: s.entity_logical_name,
        module_key: s.module_key,
        is_disabled: s.is_disabled,
        privileges,
        is_customized: s.is_customized,
    }
}

/// `entity` is the entity logicalname (export joins it; the changeset
/// translation resolves `entity_ref`).
#[derive(sqlx::FromRow, Deserialize)]
pub(crate) struct EntityAccessRow {
    #[serde(default)]
    pub(crate) role_ref: Uuid,
    pub(crate) entity: String,
    pub(crate) read_access_level: i16,
    pub(crate) write_access_level: i16,
    pub(crate) delete_access_level: i16,
    pub(crate) read_owner_visible: bool,
    pub(crate) write_owner_visible: bool,
    pub(crate) delete_owner_visible: bool,
    #[sqlx(flatten)]
    #[serde(flatten)]
    pub(crate) operations: attome_security::db::OperationLevels,
}

/// `role_mm_entity_access` row -> [`RoleEntityAccess`].
pub(crate) fn role_entity_access(a: EntityAccessRow) -> RoleEntityAccess {
    RoleEntityAccess {
        entity: a.entity,
        read_access_level: a.read_access_level,
        write_access_level: a.write_access_level,
        delete_access_level: a.delete_access_level,
        read_owner_visible: a.read_owner_visible,
        write_owner_visible: a.write_owner_visible,
        delete_owner_visible: a.delete_owner_visible,
        operations: a.operations,
    }
}

/// Exports the whole configuration of the deployment `db` points at.
///
/// `db` should be a pool that can read the metadata tables — the ordinary
/// `state.base.db` is the safe choice (the readonly role's grants cover the
/// entity tables, not every metadata table). Nothing here writes.
pub async fn export_bundle(db: &DbPool) -> Result<Bundle, AppError> {
    let mut bundle = Bundle::empty(Requires {
        platform_version: format!(">={PLATFORM_VERSION}"),
        schema_version: applied_schema_version(db).await?,
        modules: Vec::new(),
        depends_on_bundles: Vec::new(),
    });

    let entity_names = export_entities(db, &mut bundle).await?;
    let query_keys = export_queries(db, &entity_names, &mut bundle).await?;
    export_views(db, &query_keys, &mut bundle).await?;
    export_calendars(db, &mut bundle).await?;
    let modules = export_sidebar(db, &mut bundle).await?;
    export_privileges(db, &mut bundle).await?;
    export_roles(db, &mut bundle).await?;
    export_field_security_profiles(db, &mut bundle).await?;
    // Q10-T5: permission sets, without their assignments.
    bundle.permission_sets = attome_security::permission_sets::export_sets(db)
        .await?
        .into_iter()
        .map(|(desc, is_customized)| PermissionSetDef::from_desc(desc, is_customized))
        .collect();
    export_settings(db, &mut bundle).await?;
    export_state_models(db, &mut bundle).await?;
    export_labels(db, &mut bundle).await?;
    export_relationships(db, &mut bundle).await?;
    export_apps(db, &mut bundle).await?;
    export_rules(db, &mut bundle).await?;

    let mut modules: BTreeSet<String> = modules;
    modules.insert("core".to_owned());
    bundle.requires.modules = modules.into_iter().collect();

    bundle.normalize();
    Ok(bundle)
}

/// The highest successfully-applied migration ordinal, `0` on a database
/// with no bookkeeping rows yet.
pub async fn applied_schema_version(db: &DbPool) -> Result<i64, AppError> {
    let state = attome_db::schema_state(db)
        .await
        .map_err(AppError::internal)?;
    Ok(state.applied_max_version.unwrap_or(0))
}

/// Entities + attributes. Returns `entity id → logicalname` for the readers
/// that follow.
async fn export_entities(
    db: &DbPool,
    bundle: &mut Bundle,
) -> Result<HashMap<Uuid, String>, AppError> {
    let rows: Vec<EntityRow> = sqlx::query_as(
        "SELECT id, logicalname, name, primary_name_attribute, is_append_only, is_audited,
                category, is_customized
         FROM entity_info
         WHERE COALESCE(is_active, true) = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut names: HashMap<Uuid, String> = HashMap::with_capacity(rows.len());
    let mut by_id: HashMap<Uuid, EntityDef> = HashMap::with_capacity(rows.len());
    for r in rows {
        let id = r.id;
        let Some(def) = entity_def(r) else {
            tracing::warn!(entity_id = %id, "bundle export: entity without logicalname skipped");
            continue;
        };
        names.insert(id, def.logicalname.clone());
        by_id.insert(id, def);
    }

    let attrs: Vec<AttributeRow> = sqlx::query_as(
        "SELECT a.id, a.entity_ref, a.logicalname, a.name, a.type, a.required,
                a.is_sensitive, a.is_write_restricted, a.is_sortable, a.is_filterable,
                le.logicalname AS lookup_entity, a.options, a.max_length,
                a.on_target_delete, a.data_classification, a.purpose, a.is_customized
         FROM attribute_info a
         LEFT JOIN entity_info le ON le.id = a.lookup_entity_ref
         WHERE COALESCE(a.is_active, true) = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    for a in attrs {
        let Some(entity) = a.entity_ref.and_then(|e| by_id.get_mut(&e)) else {
            // Attribute of an inactive/unknown entity — it goes with its entity.
            continue;
        };
        let attribute_id = a.id;
        let Some(def) = attribute_def(a) else {
            tracing::warn!(attribute_id = %attribute_id, "bundle export: attribute without logicalname skipped");
            continue;
        };
        entity.attributes.push(def);
    }

    bundle.entities = by_id.into_values().collect();
    Ok(names)
}

/// Stored queries. Returns `query id → logical key` for the view reader.
async fn export_queries(
    db: &DbPool,
    entity_names: &HashMap<Uuid, String>,
    bundle: &mut Bundle,
) -> Result<HashMap<Uuid, QueryRef>, AppError> {
    let rows: Vec<QueryRow> = sqlx::query_as(
        "SELECT id, entity_logical_name, record_no, sql_query, table_definition,
                required_privilege, is_report, is_customized
         FROM sql_query
         WHERE COALESCE(is_active, true) = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    // Current published version's entity mappings (D-146): the newest
    // version row per query is the current one (uuidv7 is time-ordered).
    let mappings: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT v.query_id, ei.logicalname, m.id_column
         FROM sql_query_entity_mapping m
         JOIN sql_query_version v ON v.id = m.query_version_id
         JOIN entity_info ei ON ei.id = m.entity_ref
         WHERE v.id = (SELECT v2.id FROM sql_query_version v2
                       WHERE v2.query_id = v.query_id
                       ORDER BY v2.id DESC LIMIT 1)",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut mapping_by_query: HashMap<Uuid, Vec<QueryEntityMapping>> = HashMap::new();
    for (query_id, entity, id_column) in mappings {
        mapping_by_query
            .entry(query_id)
            .or_default()
            .push(QueryEntityMapping { entity, id_column });
    }

    let mut keys: HashMap<Uuid, QueryRef> = HashMap::with_capacity(rows.len());
    for q in rows {
        if q.record_no.as_deref().is_none_or(str::is_empty) {
            tracing::warn!(query_id = %q.id, "bundle export: stored query without a name (record_no) skipped");
            continue;
        }
        let entity = match q.entity_logical_name {
            Some(eid) => match entity_names.get(&eid) {
                Some(n) => Some(n.clone()),
                None => {
                    tracing::warn!(query_id = %q.id, entity_id = %eid, "bundle export: stored query bound to an inactive/unknown entity skipped");
                    continue;
                }
            },
            None => None,
        };
        let query_id = q.id;
        let mappings = mapping_by_query.remove(&query_id).unwrap_or_default();
        let Some(def) = query_def(q, entity, mappings) else {
            continue;
        };
        keys.insert(query_id, def.key());
        bundle.queries.push(def);
    }
    Ok(keys)
}

async fn export_views(
    db: &DbPool,
    query_keys: &HashMap<Uuid, QueryRef>,
    bundle: &mut Bundle,
) -> Result<(), AppError> {
    // D-429: `scope = 'system'` only -- personal/shared views are per-user
    // runtime data (an `owner_ref` from this deployment is meaningless on
    // another one), never bundle-exported.
    let rows: Vec<ViewRow> = sqlx::query_as(
        "SELECT v.id, v.name, e.logicalname AS entity, v.sql_query_ref, v.icon, v.table_definition,
                    v.is_default, v.is_customized, v.kind, v.view_metadata
             FROM view v
             JOIN entity_info e ON e.id = v.entity_logical_name
             WHERE v.is_active = true AND COALESCE(e.is_active, true) = true AND v.scope = 'system'",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    for v in rows {
        let Some(query) = query_keys.get(&v.sql_query_ref) else {
            tracing::warn!(view_id = %v.id, query_id = %v.sql_query_ref, "bundle export: view whose query is unnamed/inactive skipped");
            continue;
        };
        let query = query.clone();
        bundle.views.push(view_def(v, query));
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct CalendarRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    tz: String,
    working_days: Vec<String>,
    hours: serde_json::Value,
    is_default: bool,
    is_customized: bool,
    parent: Option<String>,
    country_code: Option<String>,
    name_ar: Option<String>,
}

#[derive(sqlx::FromRow)]
struct HolidayRow {
    calendar_id: Uuid,
    name: String,
    holiday_date: chrono::NaiveDate,
}

#[derive(sqlx::FromRow)]
struct ExceptionRow {
    calendar_id: Uuid,
    name: String,
    exception_date: chrono::NaiveDate,
    ranges: serde_json::Value,
}

/// D-404 / M83 Phase 1: business calendars + their holidays and (D-592)
/// exceptions, embedded per calendar. Not entity-scoped (`calendar` is a dedicated admin
/// object, same posture as `view`).
async fn export_calendars(db: &DbPool, bundle: &mut Bundle) -> Result<(), AppError> {
    let rows: Vec<CalendarRow> = sqlx::query_as(
        "SELECT c.id, c.name, c.description, c.tz, c.working_days, c.hours, c.is_default, \
                c.is_customized, p.name AS parent, c.country_code, c.name_ar \
           FROM calendar c LEFT JOIN calendar p ON p.id = c.parent_calendar_id \
          WHERE c.is_active = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let holiday_rows: Vec<HolidayRow> = sqlx::query_as(
        "SELECT calendar_id, name, holiday_date FROM calendar_holiday WHERE is_active = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut holidays_by_calendar: HashMap<Uuid, Vec<HolidayDef>> = HashMap::new();
    for h in holiday_rows {
        holidays_by_calendar
            .entry(h.calendar_id)
            .or_default()
            .push(HolidayDef {
                name: h.name,
                holiday_date: h.holiday_date,
            });
    }

    let exception_rows: Vec<ExceptionRow> = sqlx::query_as(
        "SELECT calendar_id, name, exception_date, ranges FROM calendar_exception WHERE is_active = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut exceptions_by_calendar: HashMap<Uuid, Vec<CalendarExceptionDef>> = HashMap::new();
    for e in exception_rows {
        exceptions_by_calendar
            .entry(e.calendar_id)
            .or_default()
            .push(CalendarExceptionDef {
                name: e.name,
                exception_date: e.exception_date,
                ranges: e.ranges,
            });
    }

    // Z12-T6: rules and seasons, written only for a calendar that has any so
    // a calendar without them exports exactly as before.
    let rule_rows: Vec<(Uuid, String, Option<String>, serde_json::Value, bool)> = sqlx::query_as(
        "SELECT calendar_id, name, name_ar, rule, needs_sighting FROM calendar_holiday_rule \
          WHERE is_active = true ORDER BY name",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut rules_by_calendar: HashMap<Uuid, Vec<HolidayRuleDef>> = HashMap::new();
    for (calendar_id, name, name_ar, rule, needs_sighting) in rule_rows {
        rules_by_calendar
            .entry(calendar_id)
            .or_default()
            .push(HolidayRuleDef {
                name,
                name_ar,
                rule,
                needs_sighting,
            });
    }
    let season_rows: Vec<(Uuid, String, Option<String>, serde_json::Value)> = sqlx::query_as(
        "SELECT calendar_id, name, name_ar, definition FROM calendar_season \
          WHERE is_active = true ORDER BY name",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut seasons_by_calendar: HashMap<Uuid, Vec<SeasonDef>> = HashMap::new();
    for (calendar_id, name, name_ar, definition) in season_rows {
        seasons_by_calendar
            .entry(calendar_id)
            .or_default()
            .push(SeasonDef {
                name,
                name_ar,
                definition,
            });
    }

    for c in rows {
        bundle.calendars.push(CalendarDef {
            name: c.name,
            description: c.description,
            tz: c.tz,
            working_days: c.working_days,
            hours: c.hours,
            is_default: c.is_default,
            is_customized: c.is_customized,
            holidays: holidays_by_calendar.remove(&c.id).unwrap_or_default(),
            exceptions: Some(exceptions_by_calendar.remove(&c.id).unwrap_or_default()),
            parent: c.parent,
            country_code: c.country_code,
            name_ar: c.name_ar,
            rules: rules_by_calendar.remove(&c.id),
            seasons: seasons_by_calendar.remove(&c.id),
        });
    }
    Ok(())
}

/// Sidebar tree as name paths. Returns the distinct `module_key`s seen.
async fn export_sidebar(db: &DbPool, bundle: &mut Bundle) -> Result<BTreeSet<String>, AppError> {
    let rows: Vec<SidebarRow> = sqlx::query_as(
        "SELECT id, parent_ref, name, route, icon, color, display_order, is_container,
                entity_logical_name, module_key, is_disabled, is_customized
         FROM sidebar
         WHERE is_active = true AND is_deleted = false",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let privs: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT sp.sidebar_ref, p.key
         FROM sidebar_mm_privilege sp
         JOIN privilege p ON p.id = sp.privilege_ref
         WHERE sp.is_deleted = false AND COALESCE(p.is_active, true) = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut privs_by_item: HashMap<Uuid, Vec<String>> = HashMap::new();
    for (sidebar_ref, key) in privs {
        privs_by_item.entry(sidebar_ref).or_default().push(key);
    }

    let parent_and_name: HashMap<Uuid, (Option<Uuid>, String)> = rows
        .iter()
        .map(|r| (r.id, (r.parent_ref, r.name.clone())))
        .collect();

    let mut modules = BTreeSet::new();
    for s in rows {
        // Walk to the root. Bounded so a cyclic parent chain (which the admin
        // API refuses, but the column has no constraint) cannot spin.
        let mut path = vec![s.name.clone()];
        let mut cursor = s.parent_ref;
        let mut broken = false;
        let mut hops = 0usize;
        while let Some(pid) = cursor {
            hops += 1;
            match parent_and_name.get(&pid) {
                Some((grand, pname)) if hops <= 64 => {
                    path.push(pname.clone());
                    cursor = *grand;
                }
                _ => {
                    broken = true;
                    break;
                }
            }
        }
        if broken {
            tracing::warn!(sidebar_id = %s.id, "bundle export: sidebar item with an inactive/missing/cyclic parent chain skipped");
            continue;
        }
        path.reverse();
        if let Some(m) = &s.module_key {
            modules.insert(m.clone());
        }
        let privileges = privs_by_item.remove(&s.id).unwrap_or_default();
        bundle.sidebar.push(sidebar_def(s, path, privileges));
    }
    Ok(modules)
}

async fn export_privileges(db: &DbPool, bundle: &mut Bundle) -> Result<(), AppError> {
    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT key, name, description FROM privilege
         WHERE COALESCE(is_active, true) = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    bundle.privileges = rows
        .into_iter()
        .map(|(key, name, description)| PrivilegeDef {
            key,
            name,
            description,
        })
        .collect();
    Ok(())
}

/// M02/D-412 — every live deployment-scope `setting` row. Only
/// `scope = 'deployment'` (`scope_ref IS NULL`) is exported: a bundle is a
/// deployment-to-deployment promotion artifact, and an organization/user
/// override is per-installation state, not shared configuration (same
/// reasoning `export.rs`'s module doc gives for excluding users/API keys).
async fn export_settings(db: &DbPool, bundle: &mut Bundle) -> Result<(), AppError> {
    let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT key, value FROM setting \
         WHERE scope = 'deployment' AND scope_ref IS NULL AND is_deleted = FALSE",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    bundle.settings = rows
        .into_iter()
        .map(|(key, value)| SettingDef { key, value })
        .collect();
    Ok(())
}

async fn export_roles(db: &DbPool, bundle: &mut Bundle) -> Result<(), AppError> {
    let rows: Vec<(Uuid, String, Option<String>, i16, bool, bool)> = sqlx::query_as(
        "SELECT id, name, description, access_level, position_hierarchy_enabled, is_customized
         FROM role
         WHERE is_deleted = false AND is_active = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut roles: HashMap<Uuid, RoleDef> = rows
        .into_iter()
        .map(
            |(id, name, description, access_level, position_hierarchy_enabled, is_customized)| {
                (
                    id,
                    RoleDef {
                        name,
                        description,
                        access_level,
                        position_hierarchy_enabled,
                        is_customized,
                        privileges: Vec::new(),
                        entity_access: Vec::new(),
                        field_security_profiles: Vec::new(),
                    },
                )
            },
        )
        .collect();

    // Grants + their conditions (D-369).
    let grants: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT rp.id, rp.role_ref, p.key
         FROM role_mm_privilege rp
         JOIN privilege p ON p.id = rp.privilege_ref
         WHERE rp.is_deleted = false AND COALESCE(p.is_active, true) = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let conditions: Vec<(Uuid, String, i16, serde_json::Value)> = sqlx::query_as(
        "SELECT role_privilege_ref, field_logicalname, operator, value
         FROM role_privilege_condition
         WHERE is_deleted = false",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut conditions_by_grant: HashMap<Uuid, Vec<GrantCondition>> = HashMap::new();
    for (grant_id, field, operator, value) in conditions {
        conditions_by_grant
            .entry(grant_id)
            .or_default()
            .push(GrantCondition {
                field,
                operator,
                value,
            });
    }
    for (grant_id, role_ref, key) in grants {
        if let Some(role) = roles.get_mut(&role_ref) {
            role.privileges.push(RoleGrant {
                privilege: key,
                conditions: conditions_by_grant.remove(&grant_id).unwrap_or_default(),
            });
        }
    }

    // Per-entity access depth (D-133 + 0130's owner-visible flags).
    let access: Vec<EntityAccessRow> = sqlx::query_as(
        "SELECT ea.role_ref, e.logicalname AS entity, ea.read_access_level, ea.write_access_level,
                ea.delete_access_level, ea.read_owner_visible, ea.write_owner_visible,
                ea.delete_owner_visible, ea.create_access_level, ea.assign_access_level,
                ea.share_access_level, ea.export_access_level, ea.bulk_access_level,
                ea.read_bu_children, ea.write_bu_children, ea.delete_bu_children,
                ea.assign_bu_children, ea.share_bu_children, ea.read_owner_subtree,
                ea.write_owner_subtree, ea.delete_owner_subtree
         FROM role_mm_entity_access ea
         JOIN entity_info e ON e.id = ea.entity_ref
         WHERE ea.is_deleted = false AND COALESCE(e.is_active, true) = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for a in access {
        if let Some(role) = roles.get_mut(&a.role_ref) {
            role.entity_access.push(role_entity_access(a));
        }
    }

    // Role → field-security profile links.
    let profiles: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT rp.role_ref, p.name
         FROM role_mm_field_security_profile rp
         JOIN field_security_profile p ON p.id = rp.profile_ref
         WHERE rp.is_deleted = false AND p.is_deleted = false",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (role_ref, profile) in profiles {
        if let Some(role) = roles.get_mut(&role_ref) {
            role.field_security_profiles.push(profile);
        }
    }

    bundle.roles = roles.into_values().collect();
    Ok(())
}

async fn export_field_security_profiles(db: &DbPool, bundle: &mut Bundle) -> Result<(), AppError> {
    let rows: Vec<(Uuid, String, Option<String>, bool)> = sqlx::query_as(
        "SELECT id, name, description, is_customized
         FROM field_security_profile
         WHERE is_deleted = false",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut profiles: HashMap<Uuid, FieldSecurityProfileDef> = rows
        .into_iter()
        .map(|(id, name, description, is_customized)| {
            (
                id,
                FieldSecurityProfileDef {
                    name,
                    description,
                    is_customized,
                    fields: Vec::new(),
                },
            )
        })
        .collect();

    let fields: Vec<(Uuid, String, String, bool, bool)> = sqlx::query_as(
        "SELECT profile_ref, entity_logicalname, field_logicalname, can_read, can_update
         FROM field_security_profile_field",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (profile_ref, entity, field, can_read, can_update) in fields {
        if let Some(p) = profiles.get_mut(&profile_ref) {
            p.fields.push(ProfileField {
                entity,
                field,
                can_read,
                can_update,
            });
        }
    }

    bundle.field_security_profiles = profiles.into_values().collect();
    Ok(())
}

/// M07 Phase 1 (D-405/D-406) — `state_model`/`state_transition`.
/// Only active, non-deleted models; only non-deleted transitions — a
/// retired model or transition is, by definition, absent from the bundle
/// (§4 "Removals are promoted as soft-retire").
/// A `state_model` row as the export reads it.
type ModelExportRow = (
    Uuid,
    String,
    String,
    String,
    String,
    bool,
    Option<serde_json::Value>,
    Option<String>,
    Option<serde_json::Value>,
);

async fn export_state_models(db: &DbPool, bundle: &mut Bundle) -> Result<(), AppError> {
    // M8-T2: a record type's own model stays out of bundles, which identify
    // a model by its entity.
    let rows: Vec<ModelExportRow> = sqlx::query_as(
        "SELECT id, entity_logicalname, name, state_field, initial_state, is_active,
                locked_states, reason_field, reasons
         FROM state_model
         WHERE is_deleted = false AND record_type IS NULL",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut models: HashMap<Uuid, StateModelDef> = rows
        .into_iter()
        .map(
            |(
                id,
                entity_logicalname,
                name,
                state_field,
                initial_state,
                is_active,
                locked_states,
                reason_field,
                reasons,
            )| {
                (
                    id,
                    StateModelDef {
                        entity_logicalname,
                        name,
                        state_field,
                        initial_state,
                        is_active,
                        transitions: Vec::new(),
                        locked_states: locked_states
                            .and_then(|v| serde_json::from_value(v).ok())
                            .unwrap_or_default(),
                        reason_field,
                        reasons: reasons
                            .and_then(|v| serde_json::from_value(v).ok())
                            .unwrap_or_default(),
                    },
                )
            },
        )
        .collect();

    #[derive(sqlx::FromRow)]
    struct TransitionRow {
        model_ref: Uuid,
        from_state: String,
        to_state: String,
        name: String,
        required_privilege: Option<String>,
        guard_expression: Option<String>,
        entry_actions: Vec<String>,
        exit_actions: Vec<String>,
        display_order: i32,
        approval_plan: Option<serde_json::Value>,
        pending_state: Option<String>,
        on_reject_state: Option<String>,
        auto_condition: Option<String>,
    }
    let transitions: Vec<TransitionRow> = sqlx::query_as(
        "SELECT model_ref, from_state, to_state, name, required_privilege, guard_expression, \
                entry_actions, exit_actions, display_order, approval_plan, pending_state, \
                on_reject_state, auto_condition
         FROM state_transition
         WHERE is_deleted = false",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for t in transitions {
        if let Some(m) = models.get_mut(&t.model_ref) {
            // M07 Phase F (D-770). A plan that does not parse was hand-edited
            // (the admin API and reconcile validate it); exporting it would
            // hand the target deployment a transition that cannot run, so the
            // export fails naming the edge instead.
            let approval_plan = t
                .approval_plan
                .map(serde_json::from_value::<attome_approval::ApprovalPlan>)
                .transpose()
                .map_err(|e| {
                    AppError::internal(format!(
                        "corrupt approval_plan on state transition {} -> {}: {e}",
                        t.from_state, t.to_state
                    ))
                })?;
            m.transitions.push(StateTransitionDef {
                from_state: t.from_state,
                to_state: t.to_state,
                name: t.name,
                required_privilege: t.required_privilege,
                guard_expression: t.guard_expression,
                entry_actions: t.entry_actions,
                exit_actions: t.exit_actions,
                display_order: t.display_order,
                approval_plan,
                pending_state: t.pending_state,
                on_reject_state: t.on_reject_state,
                auto_condition: t.auto_condition,
            });
        }
    }

    bundle.state_models = models.into_values().collect();
    Ok(())
}

/// M05 Phase 1 (D-426) — `metadata_label`, every live row verbatim.
/// `object_ref` is already the table's stable business key (never a UUID —
/// see `0201_xrm_core_metadata_label.sql`'s header), so this is a plain
/// `SELECT`, the same shape `export_settings` uses.
async fn export_labels(db: &DbPool, bundle: &mut Bundle) -> Result<(), AppError> {
    let rows: Vec<(String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT object_kind, object_ref, locale, display_name, description \
         FROM metadata_label WHERE is_deleted = FALSE",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    bundle.labels = rows
        .into_iter()
        .map(
            |(object_kind, object_ref, locale, display_name, description)| LabelDef {
                object_kind,
                object_ref,
                locale,
                display_name,
                description,
            },
        )
        .collect();
    Ok(())
}

/// M01 Core P3 gap (D-455) — `relationship_info`, every live
/// (`is_deleted = false`) row verbatim. `join_table` is deliberately not
/// selected — see `RelationshipDef`'s doc comment for why it is a derived
/// fact, not part of the definition.
async fn export_relationships(db: &DbPool, bundle: &mut Bundle) -> Result<(), AppError> {
    let rows: Vec<(String, String, String, String, String, String, bool)> = sqlx::query_as(
        "SELECT name, entity_a, entity_b, role_a, role_b, cascade, is_active \
         FROM relationship_info WHERE is_deleted = FALSE",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    bundle.relationships = rows
        .into_iter()
        .map(
            |(name, entity_a, entity_b, role_a, role_b, cascade, is_active)| RelationshipDef {
                name,
                entity_a,
                entity_b,
                role_a,
                role_b,
                cascade,
                is_active,
            },
        )
        .collect();
    Ok(())
}

/// M65 Phase 1 (D-467) — `app`, every live (`is_deleted = false`)
/// row. `sidebar_root_ref`/`default_dashboard_ref` are deliberately not
/// selected — see [`AppDef`]'s doc comment for why they are deployment-local,
/// non-portable facts.
async fn export_apps(db: &DbPool, bundle: &mut Bundle) -> Result<(), AppError> {
    let rows: Vec<(
        String,
        String,
        serde_json::Value,
        serde_json::Value,
        i32,
        bool,
    )> = sqlx::query_as(
        "SELECT name, icon, entities, roles, display_order, is_active \
             FROM app WHERE is_deleted = FALSE",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    bundle.apps = rows
        .into_iter()
        .map(
            |(name, icon, entities, roles, display_order, is_active)| AppDef {
                name,
                icon,
                entities,
                roles,
                display_order,
                is_active,
            },
        )
        .collect();
    Ok(())
}

/// M45 Phase 2 (D-472) — `rule`, every live (`is_deleted = false`)
/// row. `entity_logicalname` is already the portable form the table stores it
/// in (same convention `state_model` uses). `version`/
/// `is_customized`/`row_version`/timestamps are not exported — see
/// `RuleDef`'s own doc comment for why a bundle carries current
/// configuration, not publish history. Business rules (D-789) carry their
/// roles by name and their policies; `rule_admin::export_defs` owns the
/// row → definition mapping (shared with the changeset recorder's snapshot).
async fn export_rules(db: &DbPool, bundle: &mut Bundle) -> Result<(), AppError> {
    bundle.rules = crate::rule_admin::export_defs(db).await?;
    Ok(())
}

#[cfg(test)]
mod export_secrets {
    /// Z1-T10: a bundle or changeset never carries an integration credential.
    /// Credentials are not metadata: they live in `integration_credential`,
    /// sealed under the deployment's own key, and no exporter reads that
    /// table, so promotion cannot copy one between deployments.
    #[test]
    fn exporters_never_read_the_credential_table() {
        for (name, source) in [
            ("bundle/export.rs", include_str!("export.rs")),
            ("bundle/record_sets.rs", include_str!("record_sets.rs")),
            (
                "changeset/routes.rs",
                include_str!("../changeset/routes.rs"),
            ),
            (
                "changeset/translate.rs",
                include_str!("../changeset/translate.rs"),
            ),
        ] {
            let code: String = source
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .filter(|line| !line.contains("export_secrets") && !line.contains("\"bundle/"))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                !code.contains(concat!("integration", "_credential")),
                "{name} reads the credential table"
            );
        }
    }
}
