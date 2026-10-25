//! Close's translation (design §4.6): a recorded operation's raw row
//! `snapshot` (UUIDs allowed) → its logical `args` in the
//! `attome-changeset/v1` shape (`OPS` in `scripts/changesets/lib.mjs`).
//!
//! # The snapshot contract
//!
//! A hook records the row it just wrote as a JSON object keyed by **column
//! name** — the columns `bundle::export` selects for that table, as the table
//! stores them. Translation reads it with the *same* row struct and the
//! *same* row → component function the export uses
//! (`bundle::export::{entity_def, attribute_def, query_def, view_def,
//! sidebar_def, role_entity_access}`), or, where the bundle component's
//! fields already are the column names (rules, relationships, apps,
//! calendars, holidays, exceptions, state models and transitions,
//! privileges, roles, field profiles), deserializes the component itself.
//! `definition` is that component with the child collections that have their
//! own ops left out (`attributes`, a role's three lists, `transitions`, a
//! calendar's `holidays`/`exceptions`, a profile's `fields`).
//!
//! UUID references resolve to logical keys against live metadata in the
//! close transaction: safe because logical names are immutable (D-021) and
//! retired rows remain. Where a hook may carry the logical value itself it
//! wins over the reference:
//!
//! | kind | reference column | or logical column |
//! |---|---|---|
//! | field | `lookup_entity_ref` | `lookup_entity` |
//! | stored query | `entity_logical_name` (uuid) | — (mappings: `entity_mappings`, else read live) |
//! | view | `entity_logical_name` (uuid), `sql_query_ref` | `entity` |
//! | sidebar item | `parent_ref` (the path is walked live) | privileges: `privileges`, else read live |
//! | entity domain | `domain_ref` | `domain` |
//! | role entity access | `entity_ref` | `entity` |
//!
//! Kinds with no bundle component (workflow, case definition, default share,
//! data domain, reference record) carry the snapshot as `definition` minus
//! identity and bookkeeping columns. A remaining top-level column holding a
//! UUID is a deployment-local id that would not mean the same thing
//! elsewhere; it is left out and reported as a close warning, never silently.
//!
//! A snapshot that does not fit its row shape is a defect in the hook that
//! recorded it: close fails with a masked internal error naming the
//! operation's `seq`, op and the serde error, so the defect is fixed rather
//! than exported.

use attome_core::changeset::{Op, OperationRow};
use attome_types::AppError;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::bundle::export::{
    AttributeRow, EntityAccessRow, EntityRow, QueryRow, SidebarRow, ViewRow, attribute_def,
    entity_def, query_def, role_entity_access, sidebar_def, view_def,
};
use crate::bundle::model::{
    AppDef, CalendarDef, CalendarExceptionDef, FieldSecurityProfileDef, GrantCondition, HolidayDef,
    HolidayRuleDef, LabelDef, PrivilegeDef, QueryEntityMapping, QueryRef, RelationshipDef, RoleDef,
    RuleDef, SeasonDef, StateModelDef, StateTransitionDef,
};

/// Columns that are identity or bookkeeping, never part of a definition.
const BOOKKEEPING: &[&str] = &[
    "id",
    "row_version",
    "created_at",
    "updated_at",
    "created_at",
    "modified_at",
    "deleteon",
    "created_by",
    "modified_by",
    "created_by",
    "modified_by",
    "owner_layer",
    "is_deleted",
    "deleted_at",
    "granted_at",
    "granted_by",
];

/// Parent references an op's `target` already carries logically; dropped
/// from a generic definition without a warning.
const PARENT_REFS: &[&str] = &[
    "entity_ref",
    "role_ref",
    "privilege_ref",
    "profile_ref",
    "calendar_id",
    "model_ref",
    "workflow_ref",
    "definition_ref",
    "definition_id",
    "role_privilege_ref",
    "parent_ref",
    "sidebar_ref",
    "query_id",
];

/// How many parents a sidebar path walk follows before giving up (the
/// export's bound).
const MAX_SIDEBAR_DEPTH: usize = 64;

/// One operation's translation.
#[derive(Debug, Default)]
pub(crate) struct Translated {
    /// `None` for an op with no args (`retire_*`, `publish_*`, …).
    pub(crate) args: Option<Value>,
    /// Non-portable values left out of the definition.
    pub(crate) warnings: Vec<String>,
}

struct OpCtx<'a> {
    row: &'a OperationRow,
    snap: Map<String, Value>,
    warnings: Vec<String>,
}

impl OpCtx<'_> {
    fn defect(&self, what: impl std::fmt::Display) -> AppError {
        AppError::internal(format!(
            "changeset close: operation {} ({}) cannot be translated: {what}",
            self.row.seq, self.row.op
        ))
    }

    /// The snapshot, with `extra` members set, deserialized as `T`.
    fn parse<T: DeserializeOwned>(&self, extra: &[(&str, Value)]) -> Result<T, AppError> {
        let mut snap = self.snap.clone();
        for (key, value) in extra {
            snap.insert((*key).to_owned(), value.clone());
        }
        serde_json::from_value(Value::Object(snap)).map_err(|e| {
            self.defect(format_args!(
                "its snapshot does not match {}: {e}",
                std::any::type_name::<T>()
            ))
        })
    }

    fn get(&self, key: &str) -> Option<&Value> {
        self.snap.get(key).filter(|v| !v.is_null())
    }

    fn has(&self, key: &str) -> bool {
        self.snap.contains_key(key)
    }

    fn uuid(&self, key: &str) -> Result<Option<Uuid>, AppError> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::String(s)) => Uuid::parse_str(s)
                .map(Some)
                .map_err(|_| self.defect(format_args!("`{key}` is not a uuid"))),
            Some(_) => Err(self.defect(format_args!("`{key}` is not a uuid"))),
        }
    }

    fn required(&self, key: &str) -> Result<Value, AppError> {
        self.snap
            .get(key)
            .cloned()
            .ok_or_else(|| self.defect(format_args!("its snapshot has no `{key}`")))
    }

    /// `serde_json::to_value(def)` without `drop` members.
    fn definition<T: serde::Serialize>(&self, def: &T, drop: &[&str]) -> Result<Value, AppError> {
        let mut value = serde_json::to_value(def).map_err(|e| self.defect(e))?;
        if let Value::Object(map) = &mut value {
            for key in drop {
                map.remove(*key);
            }
        }
        Ok(value)
    }

    /// The snapshot without identity/bookkeeping columns and parent
    /// references; any other uuid-valued column is left out with a warning.
    fn portable(&mut self) -> Value {
        let mut out = Map::new();
        for (key, value) in &self.snap {
            if BOOKKEEPING.contains(&key.as_str()) || PARENT_REFS.contains(&key.as_str()) {
                continue;
            }
            if value
                .as_str()
                .is_some_and(|s| s.len() == 36 && Uuid::parse_str(s).is_ok())
            {
                self.warnings.push(format!(
                    "operation {} ({}): `{key}` holds a deployment-local id and was left out of \
                     the definition; set it on the target deployment after applying",
                    self.row.seq, self.row.op
                ));
                continue;
            }
            out.insert(key.clone(), value.clone());
        }
        Value::Object(out)
    }
}

fn args_definition(definition: Value) -> Option<Value> {
    Some(json!({ "definition": definition }))
}

/// Translates one recorded operation. Reads only.
pub(crate) async fn translate(
    conn: &mut PgConnection,
    row: &OperationRow,
) -> Result<Translated, AppError> {
    let snap = row.snapshot.as_object().cloned().ok_or_else(|| {
        AppError::internal(format!(
            "changeset close: operation {} ({}) has a non-object snapshot",
            row.seq, row.op
        ))
    })?;
    let mut c = OpCtx {
        row,
        snap,
        warnings: Vec::new(),
    };
    let op = Op::parse(&row.op).ok_or_else(|| c.defect("unknown op"))?;
    if op.stage() > attome_core::changeset::model::SUPPORTED_STAGE {
        return Err(c.defect("an operation of a later stage cannot be closed in this release"));
    }

    let args = match op {
        Op::CreateEntity | Op::UpdateEntity => {
            let r: EntityRow = c.parse(&[])?;
            let def = entity_def(r).ok_or_else(|| c.defect("the entity has no logicalname"))?;
            let mut definition = c.definition(&def, &["attributes"])?;
            with_business_key(&mut definition, &c.snap);
            args_definition(definition)
        }
        Op::SetEntityDomain => {
            let domain = if c.has("domain") {
                c.get("domain").cloned().unwrap_or(Value::Null)
            } else if c.has("domain_ref") {
                match c.uuid("domain_ref")? {
                    None => Value::Null,
                    Some(id) => Value::String(
                        domain_name(conn, id)
                            .await?
                            .ok_or_else(|| c.defect(format_args!("data domain {id} not found")))?,
                    ),
                }
            } else {
                return Err(c.defect("its snapshot has neither `domain` nor `domain_ref`"));
            };
            Some(json!({ "domain": domain }))
        }
        // L1-T1: the entity's master-data settings as they now are.
        Op::SetEntityMasterData => Some(json!({
            "is_master": c.get("is_master").cloned().unwrap_or(Value::Bool(false)),
            "hub_style": c.get("hub_style").cloned().unwrap_or(Value::Null),
        })),
        Op::AddField | Op::UpdateField => {
            let mut extra = Vec::new();
            if c.get("lookup_entity").is_none()
                && let Some(target) = c.uuid("lookup_entity_ref")?
            {
                let name = entity_name(conn, target)
                    .await?
                    .ok_or_else(|| c.defect(format_args!("lookup target {target} not found")))?;
                extra.push(("lookup_entity", Value::String(name)));
            }
            let r: AttributeRow = c.parse(&extra)?;
            let def = attribute_def(r).ok_or_else(|| c.defect("the field has no logicalname"))?;
            args_definition(c.definition(&def, &[])?)
        }
        Op::UpsertRelationship => {
            let def: RelationshipDef = c.parse(&[])?;
            args_definition(c.definition(&def, &[])?)
        }
        Op::SetLabel => {
            let label: LabelDef = c.parse(&[])?;
            let mut args = json!({ "display_name": label.display_name });
            if let (Some(description), Value::Object(map)) = (label.description, &mut args) {
                map.insert("description".into(), Value::String(description));
            }
            Some(args)
        }
        Op::UpsertQuery => {
            let r: QueryRow = c.parse(&[])?;
            let entity = match r.entity_logical_name {
                None => None,
                Some(id) => Some(
                    entity_name(conn, id)
                        .await?
                        .ok_or_else(|| c.defect(format_args!("query entity {id} not found")))?,
                ),
            };
            let mappings: Vec<QueryEntityMapping> = match c.get("entity_mappings") {
                Some(m) => serde_json::from_value(m.clone())
                    .map_err(|e| c.defect(format_args!("`entity_mappings`: {e}")))?,
                None => match row.object_ref {
                    Some(query_id) => query_mappings(conn, query_id).await?,
                    None => Vec::new(),
                },
            };
            let def = query_def(r, entity, mappings)
                .ok_or_else(|| c.defect("the stored query has no name (record_no)"))?;
            args_definition(c.definition(&def, &[])?)
        }
        Op::UpsertView => {
            let mut extra = Vec::new();
            if c.get("entity").is_none() {
                let id = c
                    .uuid("entity_logical_name")?
                    .ok_or_else(|| c.defect("its snapshot has no `entity_logical_name`"))?;
                let name = entity_name(conn, id)
                    .await?
                    .ok_or_else(|| c.defect(format_args!("view entity {id} not found")))?;
                extra.push(("entity", Value::String(name)));
            }
            let r: ViewRow = c.parse(&extra)?;
            let query = query_key(conn, r.sql_query_ref).await?.ok_or_else(|| {
                c.defect(format_args!(
                    "the view's query {} is missing or has no name",
                    r.sql_query_ref
                ))
            })?;
            args_definition(c.definition(&view_def(r, query), &[])?)
        }
        Op::UpsertRule => {
            let def: RuleDef = c.parse(&[])?;
            args_definition(c.definition(&def, &[])?)
        }
        Op::UpsertStateModel => {
            let def: StateModelDef = c.parse(&[])?;
            args_definition(c.definition(&def, &["transitions"])?)
        }
        Op::UpsertStateTransition => {
            let def: StateTransitionDef = c.parse(&[])?;
            args_definition(c.definition(&def, &[])?)
        }
        Op::SetWorkflowDraft => Some(json!({ "graph": c.required("graph")? })),
        Op::UpsertWorkflow
        | Op::UpsertCaseDef
        | Op::SetEntityDefaultShare
        | Op::UpsertDataDomain => args_definition(c.portable()),
        Op::UpsertSidebarItem => {
            let r: SidebarRow = c.parse(&[])?;
            let path = sidebar_path(conn, &r)
                .await?
                .ok_or_else(|| c.defect("the menu item's parent chain is broken"))?;
            let privileges: Vec<String> = match c.get("privileges") {
                Some(p) => serde_json::from_value(p.clone())
                    .map_err(|e| c.defect(format_args!("`privileges`: {e}")))?,
                None => match row.object_ref {
                    Some(id) => sidebar_privileges(conn, id).await?,
                    None => Vec::new(),
                },
            };
            args_definition(c.definition(&sidebar_def(r, path, privileges), &[])?)
        }
        Op::UpsertApp => {
            let def: AppDef = c.parse(&[])?;
            args_definition(c.definition(&def, &[])?)
        }
        Op::UpsertCalendar => {
            let def: CalendarDef = c.parse(&[])?;
            args_definition(c.definition(&def, &["holidays", "exceptions", "rules", "seasons"])?)
        }
        Op::AddCalendarHoliday => {
            let def: HolidayDef = c.parse(&[])?;
            args_definition(c.definition(&def, &[])?)
        }
        Op::AddCalendarException => {
            let def: CalendarExceptionDef = c.parse(&[])?;
            args_definition(c.definition(&def, &[])?)
        }
        Op::UpsertCalendarRule => {
            let def: HolidayRuleDef = c.parse(&[])?;
            args_definition(c.definition(&def, &[])?)
        }
        Op::UpsertCalendarSeason => {
            let def: SeasonDef = c.parse(&[])?;
            args_definition(c.definition(&def, &[])?)
        }
        Op::EnsurePrivilege => {
            let def: PrivilegeDef = c.parse(&[])?;
            args_definition(c.definition(&def, &[])?)
        }
        Op::UpsertRole => {
            let def: RoleDef = c.parse(&[])?;
            args_definition(c.definition(
                &def,
                &["privileges", "entity_access", "field_security_profiles"],
            )?)
        }
        // The v1 catalogue requires `depth`; a role grant row carries none
        // today (the role's own access level applies), so it is null unless
        // the hook recorded one.
        Op::GrantRolePrivilege => Some(json!({ "depth": c.get("depth").cloned() })),
        Op::AddRoleGrantCondition => {
            let field = c
                .get("field_logicalname")
                .or_else(|| c.get("field"))
                .cloned()
                .ok_or_else(|| c.defect("its snapshot has no `field_logicalname`"))?;
            let condition: GrantCondition = serde_json::from_value(json!({
                "field": field,
                "operator": c.required("operator")?,
                "value": c.required("value")?,
            }))
            .map_err(|e| c.defect(e))?;
            args_definition(c.definition(&condition, &[])?)
        }
        Op::SetRoleEntityAccess => {
            let mut extra = Vec::new();
            if c.get("entity").is_none() {
                let id = c
                    .uuid("entity_ref")?
                    .ok_or_else(|| c.defect("its snapshot has no `entity_ref`"))?;
                let name = entity_name(conn, id)
                    .await?
                    .ok_or_else(|| c.defect(format_args!("entity {id} not found")))?;
                extra.push(("entity", Value::String(name)));
            }
            let r: EntityAccessRow = c.parse(&extra)?;
            Some(json!({ "access": c.definition(&role_entity_access(r), &["entity"])? }))
        }
        Op::SetRoleBulkFields => Some(json!({ "fields": c.required("fields")? })),
        Op::UpsertFieldProfile => {
            let def: FieldSecurityProfileDef = c.parse(&[])?;
            args_definition(c.definition(&def, &["fields"])?)
        }
        Op::SetFieldProfileField => {
            let can_read = c.get("can_read").and_then(Value::as_bool);
            let can_update = c.get("can_update").and_then(Value::as_bool);
            let (Some(can_read), Some(can_update)) = (can_read, can_update) else {
                return Err(c.defect("its snapshot needs boolean `can_read` and `can_update`"));
            };
            Some(json!({ "permissions": { "can_read": can_read, "can_update": can_update } }))
        }
        Op::UpsertRecord => {
            let values = match c.get("values") {
                Some(v) => v.clone(),
                None => c.portable(),
            };
            Some(upsert_record_args(values, c.get("changed")).map_err(|e| c.defect(e))?)
        }
        Op::RetireEntity
        | Op::ReactivateEntity
        | Op::RetireField
        | Op::ReactivateField
        | Op::RetireRelationship
        | Op::ClearLabel
        | Op::RetireQuery
        | Op::RetireView
        | Op::PublishRule
        | Op::RetireRule
        | Op::RetireStateModel
        | Op::RetireStateTransition
        | Op::PublishWorkflow
        | Op::RetireWorkflow
        | Op::RetireCaseDef
        | Op::RetireSidebarItem
        | Op::RetireApp
        | Op::RetireCalendar
        | Op::RemoveCalendarHoliday
        | Op::RemoveCalendarException
        | Op::RetireCalendarRule
        | Op::RetireCalendarSeason
        | Op::RevokeRolePrivilege
        | Op::RemoveRoleGrantCondition
        | Op::ClearRoleEntityAccess
        | Op::RemoveEntityDefaultShare
        | Op::AssignFieldProfile
        | Op::UnassignFieldProfile
        | Op::DeleteField => None,
        // Phase 2 (design §4.3): the executors record `args` as the snapshot,
        // so translation is the identity. TODO(P2-E): name-at-seq for
        // snapshots of earlier ops that carry an attribute UUID resolved at
        // close (a later rename in the same changeset would show its new name).
        Op::RenameField | Op::ChangeFieldType | Op::AddChoiceValue | Op::RemoveChoiceValue => {
            Some(c.portable())
        }
        // The view admin PATCH records `{columns[, sort]}` as the snapshot
        // (design §4.2), so translation is the identity over those members.
        Op::SetViewColumns => {
            let mut args = Map::new();
            args.insert("columns".into(), c.required("columns")?);
            if let Some(sort) = c.get("sort") {
                args.insert("sort".into(), sort.clone());
            }
            Some(Value::Object(args))
        }
        Op::DataStep => {
            return Err(c.defect("a Phase 2 operation this release does not record yet"));
        }
    };

    let args = with_changed(args, &row.changed);
    Ok(Translated {
        args,
        warnings: c.warnings,
    })
}

/// D-787 rule 7: a business-key declaration records its key and flag on the
/// entity snapshot (`provision::declare_business_key_recorded`); the bundle
/// component has no slot for them, so they ride on the definition beside it.
/// Other entity snapshots lack both, so an op that did not declare a key
/// leaves the target's key alone.
fn with_business_key(definition: &mut Value, snap: &Map<String, Value>) {
    if let Value::Object(map) = definition {
        for key in ["business_key", "is_reference_data"] {
            if let Some(value) = snap.get(key) {
                map.insert(key.to_owned(), value.clone());
            }
        }
    }
}

/// An `upsert_record`'s args: `values`, plus the `changed` list a recorded
/// generic write (D-787 rule 7) carries on its snapshot (field names are not
/// `&'static`, so they cannot ride on the operation's `changed` column). The
/// apply writes only those fields on an existing record (design §3.9); a
/// created record takes all `values`.
fn upsert_record_args(values: Value, changed: Option<&Value>) -> Result<Value, &'static str> {
    match changed {
        None => Ok(json!({ "values": values })),
        Some(list)
            if list
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)) =>
        {
            Ok(json!({ "values": values, "changed": list }))
        }
        Some(_) => Err("its snapshot's `changed` is not a list of field names"),
    }
}

/// `update_*` ops carry `changed: [property…]` for the review summary.
fn with_changed(args: Option<Value>, changed: &[String]) -> Option<Value> {
    if changed.is_empty() {
        return args;
    }
    let mut args = args.unwrap_or_else(|| json!({}));
    if let Value::Object(map) = &mut args {
        map.insert("changed".into(), json!(changed));
    }
    Some(args)
}

async fn entity_name(conn: &mut PgConnection, id: Uuid) -> Result<Option<String>, AppError> {
    let name: Option<Option<String>> =
        sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(AppError::internal)?;
    Ok(name.flatten().filter(|s| !s.is_empty()))
}

async fn domain_name(conn: &mut PgConnection, id: Uuid) -> Result<Option<String>, AppError> {
    sqlx::query_scalar("SELECT name FROM data_domain WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::internal)
}

/// A stored query's logical key; `None` when it is missing or unnamed.
async fn query_key(conn: &mut PgConnection, id: Uuid) -> Result<Option<QueryRef>, AppError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT q.record_no, e.logicalname \
         FROM sql_query q \
         LEFT JOIN entity_info e ON e.id = q.entity_logical_name \
         WHERE q.id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(row.and_then(|(name, entity)| {
        name.filter(|n| !n.is_empty())
            .map(|name| QueryRef { entity, name })
    }))
}

/// The current version's entity mappings of one query (the export's rule:
/// the newest version row is the current one).
async fn query_mappings(
    conn: &mut PgConnection,
    query_id: Uuid,
) -> Result<Vec<QueryEntityMapping>, AppError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT ei.logicalname, m.id_column \
         FROM sql_query_entity_mapping m \
         JOIN entity_info ei ON ei.id = m.entity_ref \
         WHERE m.query_version_id = (SELECT v.id FROM sql_query_version v \
                                     WHERE v.query_id = $1 ORDER BY v.id DESC LIMIT 1) \
         ORDER BY ei.logicalname, m.id_column",
    )
    .bind(query_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(entity, id_column)| QueryEntityMapping { entity, id_column })
        .collect())
}

/// A menu item's root-first name path, walking `parent_ref` live; `None`
/// when a parent is missing or the chain is deeper than the export allows.
async fn sidebar_path(
    conn: &mut PgConnection,
    item: &SidebarRow,
) -> Result<Option<Vec<String>>, AppError> {
    let mut path = vec![item.name.clone()];
    let mut cursor = item.parent_ref;
    while let Some(parent) = cursor {
        if path.len() > MAX_SIDEBAR_DEPTH {
            return Ok(None);
        }
        let row: Option<(Option<Uuid>, String)> =
            sqlx::query_as("SELECT parent_ref, name FROM sidebar WHERE id = $1")
                .bind(parent)
                .fetch_optional(&mut *conn)
                .await
                .map_err(AppError::internal)?;
        let Some((grand, name)) = row else {
            return Ok(None);
        };
        path.push(name);
        cursor = grand;
    }
    path.reverse();
    Ok(Some(path))
}

async fn sidebar_privileges(conn: &mut PgConnection, item: Uuid) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        "SELECT p.key FROM sidebar_mm_privilege sp \
         JOIN privilege p ON p.id = sp.privilege_ref \
         WHERE sp.sidebar_ref = $1 AND sp.is_deleted = false \
         ORDER BY p.key",
    )
    .bind(item)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn op(name: &str, snapshot: Value, changed: &[&str]) -> OperationRow {
        OperationRow {
            id: Uuid::now_v7(),
            changeset_ref: Uuid::now_v7(),
            seq: 1,
            op: name.into(),
            phase: "expand".into(),
            object_kind: "x".into(),
            object_ref: None,
            target: json!({}),
            snapshot,
            args: None,
            changed: changed.iter().map(|s| (*s).to_owned()).collect(),
            route: "POST /x".into(),
            request_id: None,
            actor_ref: None,
            recorded_at: Utc::now(),
        }
    }

    fn ctx(row: &OperationRow) -> OpCtx<'_> {
        OpCtx {
            row,
            snap: row.snapshot.as_object().cloned().unwrap_or_default(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn a_generic_definition_drops_bookkeeping_and_warns_on_local_ids() {
        let steward = Uuid::now_v7().to_string();
        let row = op(
            "upsert_data_domain",
            json!({
                "id": Uuid::now_v7(), "row_version": 3, "created_at": "2026-09-29T00:00:00Z",
                "name": "Finance", "description": null, "steward_ref": steward,
                "entity_ref": Uuid::now_v7(), "owner_layer": "project",
            }),
            &[],
        );
        let mut c = ctx(&row);
        let def = c.portable();
        assert_eq!(def, json!({ "name": "Finance", "description": null }));
        assert_eq!(c.warnings.len(), 1);
        assert!(c.warnings[0].contains("`steward_ref`"), "{:?}", c.warnings);
    }

    #[test]
    fn a_component_definition_reuses_the_export_row_mapping() {
        let row = op(
            "create_entity",
            json!({
                "id": Uuid::now_v7(), "logicalname": "contract", "name": "Contract",
                "primary_name_attribute": "name", "is_append_only": false,
                "is_audited": null, "category": null, "is_customized": true,
            }),
            &[],
        );
        let c = ctx(&row);
        let r: EntityRow = c.parse(&[]).expect("entity row");
        let def = entity_def(r).expect("named");
        let value = c.definition(&def, &["attributes"]).expect("value");
        assert_eq!(value["logicalname"], "contract");
        assert_eq!(value["display_name"], "Contract");
        assert_eq!(value["is_audited"], false);
        assert!(value.get("attributes").is_none());
    }

    #[test]
    fn a_snapshot_that_misses_a_column_is_a_named_defect() {
        let row = op("create_entity", json!({ "logicalname": "x" }), &[]);
        let c = ctx(&row);
        let err = c.parse::<EntityRow>(&[]).err().expect("missing columns");
        let AppError::Internal(message) = err else {
            panic!("expected an internal error");
        };
        assert!(message.contains("operation 1 (create_entity)"), "{message}");
    }

    #[test]
    fn changed_properties_ride_on_the_args() {
        assert_eq!(
            with_changed(
                Some(json!({"definition": {}})),
                &["display_name".to_owned()]
            ),
            Some(json!({"definition": {}, "changed": ["display_name"]}))
        );
        assert_eq!(with_changed(None, &[]), None);
        assert_eq!(
            with_changed(None, &["x".to_owned()]),
            Some(json!({"changed": ["x"]}))
        );
    }

    #[test]
    fn a_key_declaration_rides_on_the_entity_definition() {
        let mut definition = json!({ "logicalname": "country", "display_name": "Country" });
        let snap = json!({ "business_key": ["code"], "is_reference_data": true });
        with_business_key(&mut definition, snap.as_object().expect("object"));
        assert_eq!(definition["business_key"], json!(["code"]));
        assert_eq!(definition["is_reference_data"], json!(true));

        // A snapshot without them (a rename) leaves the definition alone.
        let mut plain = json!({ "logicalname": "country" });
        with_business_key(&mut plain, json!({}).as_object().expect("object"));
        assert_eq!(plain, json!({ "logicalname": "country" }));
    }

    #[test]
    fn a_recorded_reference_write_carries_its_changed_fields() {
        let values = json!({ "code": "BH", "name": "Bahrain" });
        assert_eq!(
            upsert_record_args(values.clone(), Some(&json!(["name"]))),
            Ok(json!({ "values": values, "changed": ["name"] }))
        );
        assert_eq!(
            upsert_record_args(values.clone(), None),
            Ok(json!({ "values": values }))
        );
        assert!(upsert_record_args(values.clone(), Some(&json!("name"))).is_err());
        assert!(upsert_record_args(values, Some(&json!([1]))).is_err());
    }
}
