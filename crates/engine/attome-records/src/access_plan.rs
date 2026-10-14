//! The principal-neutral access plan (D-576 item 5): how a caller that is
//! **not** a staff `SecurityContext` (today, a web portal user) reads and
//! writes records through the shared entity engine.
//!
//! An [`AccessPlan`] is built by its owner (`attome-portal`'s `PortalContext`
//! resolver) from that principal's own grants, and carries everything the
//! engine needs:
//!
//! - which actions are allowed on one entity;
//! - the row scope, as D-369-shaped conditions whose caller-relative values
//!   are already resolved (D-574);
//! - the readable, writable and filterable field sets (D-575, default-deny);
//! - the staff team that owns what the principal creates, and the entity field
//!   that records the principal on create (D-576 item 7).
//!
//! **Zero-escalation by construction.** The row scope here is built **only**
//! from the plan's conditions. Nothing in this module reads
//! `record_share`, `entity_default_share`, teams, business
//! units, the position hierarchy or `owner_ref`, so none of them can widen
//! what a plan sees. A plan with no conditions matches nothing, and an
//! unresolvable condition matches nothing (never everything).
//!
//! **Every lookup hop is authorized on its own** (plan §9.6 I-8, G-1, G-2). A
//! lookup value is shown only when its target passes the caller's own plan
//! for the target entity ([`LookupScope`]), and a lookup value written by the
//! caller must pass the same check, inside the write transaction, or it is
//! refused exactly as a nonexistent id is. An allowlisted lookup on one
//! entity grants nothing on the next.
//!
//! Writes go through [`create_one_as`]/[`update_one_as`]/[`delete_one_as`]
//! with [`Principal::Portal`], so a portal write runs the same pipeline as a
//! staff one (validation, record validators, rules, state model, lookup
//! liveness, change events, audit). No `SecurityContext` is built anywhere on
//! this path.

use std::collections::{BTreeMap, BTreeSet};

use attome_audit::initiator::Attribution;
use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, AuditUserContext,
};
use attome_core::{AttrInfo, EngineState, EntityMetaRegistry, FieldType, quote_ident};
use attome_server::security::{ConditionOperator, GrantCondition};
use attome_types::{AppError, PageBase, PageWindow, PaginatedResponse};
use serde::Serialize;
use serde_json::{Map, Value};
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::entity_crud::{field_changes_from_obj, resolve_entity};
use crate::entity_mutation::{
    CreateStamp, MutationMode, Principal, create_one_as, delete_one_as, update_one_as,
    validate_lookup_targets,
};

/// Largest page a portal list returns (R10: below the staff `MAX_PAGE_SIZE`).
pub const PORTAL_MAX_PAGE_SIZE: i64 = 100;
pub const PORTAL_DEFAULT_PAGE_SIZE: i64 = 25;

/// One scope condition, its caller-relative value already resolved.
#[derive(Clone, Debug)]
pub enum PlanCondition {
    Match(GrantCondition),
    /// A `value_ref` that resolved to nothing (a null lookup, a missing row):
    /// the condition matches no row (D-574 item 4).
    MatchNothing,
}

/// Which values of one lookup field the principal may see or write.
#[derive(Clone, Debug)]
pub enum LookupScope {
    /// A lookup to the principal's own identity entity (`webportal_user`):
    /// only the principal's own id is ever visible.
    SelfOnly,
    /// A lookup into an application entity: the target must pass the
    /// principal's read scope on it. Empty `conditions` (no read grant on the
    /// target) matches nothing, so the value reads as `null` and can't be
    /// written.
    Target {
        entity: String,
        conditions: Vec<PlanCondition>,
    },
}

/// Everything the engine needs to serve one principal on one entity.
#[derive(Clone, Debug)]
pub struct AccessPlan {
    /// The acting `webportal_user` id (never a staff id).
    pub portal_user_id: Uuid,
    /// Display text for the audit event (not hashed).
    pub portal_user_label: String,
    pub webportal_id: Uuid,
    pub entity: String,
    pub can_read: bool,
    pub can_create: bool,
    pub can_update: bool,
    pub can_delete: bool,
    /// ANDed. Empty matches nothing.
    pub conditions: Vec<PlanCondition>,
    pub readable: BTreeSet<String>,
    pub writable: BTreeSet<String>,
    pub filterable: BTreeSet<String>,
    /// The staff team that owns what this principal creates.
    pub owner_team_ref: Uuid,
    pub owner_org_ref: Uuid,
    /// The entity's lookup to `webportal_user`, set to
    /// [`AccessPlan::portal_user_id`] on create. Never client-writable.
    pub portal_user_field: Option<String>,
    /// For every readable or writable lookup field, the scope its values must
    /// pass. A lookup field missing from this map matches nothing.
    pub lookup_scopes: BTreeMap<String, LookupScope>,
    /// The inbound request's client address and browser, written into every
    /// audit row this plan produces (G-7). Set by the router per request.
    pub request_context: AuditRequestContext,
    /// D-789 ruling 6: the portal user's one portal role (D-579), the
    /// audience of portal-role business rules on this plan's writes. `None`
    /// when the principal holds no role (its own-profile plan): then only
    /// all-users rules apply. Adds to the writable allowlist above, never
    /// replaces it (D-575).
    pub role_id: Option<Uuid>,
}

impl AccessPlan {
    /// The stamp a portal create writes: no staff id anywhere (D-579).
    fn create_stamp(&self) -> CreateStamp {
        CreateStamp {
            created_by: None,
            org_ref: self.owner_org_ref,
            owner_ref: self.owner_team_ref,
            owner_type: 1,
        }
    }

    /// True when `key = value` is the engine's own stamp of the portal user
    /// field, the one write a client never makes itself.
    pub(crate) fn is_own_stamp(&self, key: &str, value: &Value) -> bool {
        self.portal_user_field.as_deref() == Some(key)
            && value.as_str().and_then(|s| s.parse::<Uuid>().ok()) == Some(self.portal_user_id)
    }
}

/// A record as a portal sees it: only allowlisted fields, no owner,
/// organisation or staff attribution columns.
#[derive(Debug, Serialize, ToSchema)]
pub struct PortalRecord {
    pub id: Uuid,
    pub row_version: i64,
    #[schema(value_type = Option<String>, format = DateTime)]
    pub created_at: Value,
    #[schema(value_type = Option<String>, format = DateTime)]
    pub updated_at: Value,
    #[schema(value_type = std::collections::HashMap<String, serde_json::Value>)]
    pub data: Map<String, Value>,
}

/// One field as a portal may see it in metadata (web-portal plan Phase 5).
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
pub struct PortalFieldView {
    pub name: String,
    /// The field's display label, when it has one.
    pub label: Option<String>,
    /// The type a reader sees (`text`, `number`, `date`, `lookup`, …).
    pub field_type: String,
    pub required: bool,
    pub max_length: Option<i32>,
    pub readable: bool,
    pub writable: bool,
    pub filterable: bool,
    /// For a lookup the caller may pick a value for: the target entity. Set
    /// only when the caller's role reads that entity, so a form can offer its
    /// records; `None` for every other field, including the portal user field
    /// the engine stamps.
    pub lookup_entity: Option<String>,
    /// A choice field's options; `None` for every other type (a formula's
    /// expression or a masked text's settings never reach a portal).
    #[schema(value_type = Option<Object>)]
    pub options: Option<Value>,
}

/// One entity as a portal may see it in metadata.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
pub struct PortalEntityView {
    pub entity: String,
    pub label: Option<String>,
    pub can_read: bool,
    pub can_create: bool,
    pub can_update: bool,
    pub can_delete: bool,
    pub fields: Vec<PortalFieldView>,
}

/// The portal-safe description of `plan`'s entity (I-18; the web-portal
/// plan's `PortalMetadataProjector`, field half).
///
/// **Built from the plan, never filtered down from staff metadata.** Only the
/// plan's own readable and writable fields are visited, and only their type,
/// requiredness, length, choice options and label are copied, so a field,
/// flag or kind of metadata the plan doesn't name cannot appear, including
/// ones added to the platform later. `labels` holds the display labels the
/// caller loaded for exactly those fields. A named field that today's
/// metadata no longer has is left out rather than described from the grant
/// alone. A file field is never filterable; it is writable when the plan says
/// so (an upload, D-774: `plan_upload_target`).
pub fn describe(
    plan: &AccessPlan,
    registry: &EntityMetaRegistry,
    entity_label: Option<String>,
    labels: &BTreeMap<String, String>,
) -> PortalEntityView {
    let attrs: &[AttrInfo] = registry.get(&plan.entity).map_or(&[], |m| &m.attrs);
    let fields = plan
        .readable
        .union(&plan.writable)
        .filter_map(|name| {
            let attr = attrs.iter().find(|a| &a.logicalname == name)?;
            let file = attr.is_file_backed();
            let readable = plan.readable.contains(name);
            let lookup_entity = match plan.lookup_scopes.get(name) {
                Some(LookupScope::Target { entity, conditions })
                    if is_lookup(attr)
                        && !conditions.is_empty()
                        && registry.get(entity).is_some() =>
                {
                    Some(entity.clone())
                }
                _ => None,
            };
            Some(PortalFieldView {
                name: name.clone(),
                label: labels.get(name).cloned(),
                field_type: attr.presentation_type().as_str().to_owned(),
                required: attr.is_required,
                max_length: attr.max_length,
                readable,
                writable: plan.writable.contains(name),
                filterable: !file && readable && plan.filterable.contains(name),
                lookup_entity,
                options: (attr.field_type() == FieldType::Choice)
                    .then(|| attr.options.clone())
                    .flatten(),
            })
        })
        .collect();
    PortalEntityView {
        entity: plan.entity.clone(),
        label: entity_label,
        can_read: plan.can_read,
        can_create: plan.can_create,
        can_update: plan.can_update,
        can_delete: plan.can_delete,
        fields,
    }
}

#[derive(Debug, Default)]
pub struct PortalListQuery {
    /// One-based: page 1 is the first page.
    pub page: i64,
    pub page_size: i64,
    /// Equality filters; each field must be filterable in the plan.
    pub filters: Vec<(String, String)>,
    /// `(field, descending)`; the field must be filterable in the plan.
    pub order_by: Option<(String, bool)>,
}

/// Text binds for one statement. Every placeholder carries its own `::type`
/// cast, so each value binds as text (the D-369 renderer's convention).
#[derive(Default)]
struct Binds(Vec<String>);

impl Binds {
    fn next(&self) -> usize {
        self.0.len() + 1
    }

    fn push(&mut self, value: String) -> usize {
        self.0.push(value);
        self.0.len()
    }
}

/// Whether `condition` can render against `attrs` today. The request-time
/// resolver turns a condition that can't (metadata drift) into
/// [`PlanCondition::MatchNothing`] rather than failing every request (G-6).
pub fn condition_renders(condition: &GrantCondition, attrs: &[AttrInfo]) -> bool {
    if condition.field_logicalname == "id" {
        return id_condition_value(condition).is_some();
    }
    attome_security::conditions::render_condition(condition, attrs, "t", 1).is_ok()
}

/// A condition on the record's own primary key: `eq` with a UUID only. The
/// key is always indexed and never sensitive, so it needs no metadata. It is
/// what lets a portal grant "my own company record"
/// (`id = @portal_user.company_ref`).
fn id_condition_value(condition: &GrantCondition) -> Option<Uuid> {
    if condition.operator != ConditionOperator::Eq {
        return None;
    }
    condition.value.as_str().and_then(|s| s.parse().ok())
}

fn render_plan_condition(
    entity: &str,
    condition: &PlanCondition,
    attrs: &[AttrInfo],
    alias: &str,
    binds: &mut Binds,
) -> Result<String, AppError> {
    let PlanCondition::Match(grant) = condition else {
        return Ok("FALSE".to_owned());
    };
    if grant.field_logicalname == "id" {
        return Ok(match id_condition_value(grant) {
            Some(id) => format!("{alias}.id = ${}::uuid", binds.push(id.to_string())),
            None => "FALSE".to_owned(),
        });
    }
    let rendered = attome_security::conditions::render_condition(grant, attrs, alias, binds.next())
        .map_err(|e| {
            AppError::internal(format!(
                "portal scope condition on {entity}.{} cannot render: {e}",
                grant.field_logicalname
            ))
        })?;
    binds.push(rendered.bind_text);
    Ok(rendered.sql)
}

/// ANDed conditions over `alias`. Empty matches nothing.
fn scope_clause(
    entity: &str,
    conditions: &[PlanCondition],
    attrs: &[AttrInfo],
    alias: &str,
    binds: &mut Binds,
) -> Result<String, AppError> {
    if conditions.is_empty() {
        return Ok("FALSE".to_owned());
    }
    let mut parts = Vec::with_capacity(conditions.len());
    for condition in conditions {
        parts.push(render_plan_condition(
            entity, condition, attrs, alias, binds,
        )?);
    }
    Ok(format!("({})", parts.join(" AND ")))
}

fn is_lookup(attr: &AttrInfo) -> bool {
    FieldType::from_int(attr.field_type_int) == Some(FieldType::Lookup)
}

/// A boolean SQL expression: the lookup value `value_sql` (a uuid column or
/// placeholder) is one the plan may see through `field`.
fn lookup_visible_sql(
    registry: &EntityMetaRegistry,
    plan: &AccessPlan,
    field: &str,
    value_sql: &str,
    binds: &mut Binds,
) -> Result<String, AppError> {
    match plan.lookup_scopes.get(field) {
        None => Ok("FALSE".to_owned()),
        Some(LookupScope::SelfOnly) => Ok(format!(
            "{value_sql} = ${}::uuid",
            binds.push(plan.portal_user_id.to_string())
        )),
        Some(LookupScope::Target { entity, conditions }) => {
            let Some(meta) = registry.get(entity) else {
                return Ok("FALSE".to_owned());
            };
            let scope = scope_clause(entity, conditions, &meta.attrs, "lk", binds)?;
            Ok(format!(
                "EXISTS (SELECT 1 FROM {table} lk WHERE lk.id = {value_sql} \
                 AND lk.is_active IS NOT FALSE AND {scope})",
                table = quote_ident(entity),
            ))
        }
    }
}

/// The explicit projection: identity, version, timestamps, readable fields.
/// A readable lookup whose target the plan can't see projects as `null` (G-2).
fn projection(
    registry: &EntityMetaRegistry,
    plan: &AccessPlan,
    attrs: &[AttrInfo],
    binds: &mut Binds,
) -> Result<String, AppError> {
    let mut cols = vec![
        "t.id".to_owned(),
        "t.row_version".to_owned(),
        "t.created_at".to_owned(),
        "t.modified_at".to_owned(),
    ];
    for attr in attrs {
        if !plan.readable.contains(&attr.logicalname) {
            continue;
        }
        let col = format!("t.{}", quote_ident(&attr.logicalname));
        if is_lookup(attr) {
            let visible = lookup_visible_sql(registry, plan, &attr.logicalname, &col, binds)?;
            cols.push(format!(
                "CASE WHEN {visible} THEN {col} END AS {name}",
                name = quote_ident(&attr.logicalname)
            ));
        } else {
            cols.push(col);
        }
    }
    Ok(cols.join(", "))
}

fn to_record(plan: &AccessPlan, row: Value) -> Result<PortalRecord, AppError> {
    let Value::Object(mut obj) = row else {
        return Err(AppError::internal("portal projection is not an object"));
    };
    let id = obj
        .remove("id")
        .and_then(|v| v.as_str().and_then(|s| s.parse().ok()))
        .ok_or_else(|| AppError::internal("portal projection has no id"))?;
    let row_version = obj
        .remove("row_version")
        .and_then(|v| v.as_i64())
        .unwrap_or_default();
    let created_at = obj.remove("created_at").unwrap_or(Value::Null);
    let updated_at = obj.remove("modified_at").unwrap_or(Value::Null);
    // Belt and braces: only allowlisted keys survive, whatever the SQL said.
    obj.retain(|k, _| plan.readable.contains(k));
    Ok(PortalRecord {
        id,
        row_version,
        created_at,
        updated_at,
        data: obj,
    })
}

async fn attrs_for(
    state: &EngineState,
    plan: &AccessPlan,
) -> Result<(Uuid, Vec<AttrInfo>), AppError> {
    let (entity_id, entity_name, attrs, is_append_only) =
        resolve_entity(state, &plan.entity).await?;
    if entity_name != plan.entity || is_append_only {
        return Err(AppError::NotFound);
    }
    Ok((entity_id, attrs))
}

/// The statement [`fetch_in_scope`] runs: one live, in-scope record,
/// projected to the plan's readable fields.
fn record_sql(
    registry: &EntityMetaRegistry,
    plan: &AccessPlan,
    attrs: &[AttrInfo],
    id: Uuid,
    lock: bool,
) -> Result<(String, Binds), AppError> {
    let table = quote_ident(&plan.entity);
    let mut binds = Binds::default();
    let id_param = binds.push(id.to_string());
    let scope = scope_clause(&plan.entity, &plan.conditions, attrs, "t", &mut binds)?;
    let cols = projection(registry, plan, attrs, &mut binds)?;
    let lock = if lock { " FOR UPDATE OF t" } else { "" };
    let sql = format!(
        "SELECT row_to_json(x) FROM (SELECT {cols} FROM {table} t \
         WHERE t.id = ${id_param}::uuid AND t.is_active IS NOT FALSE AND {scope}{lock}) x",
    );
    Ok((sql, binds))
}

/// Reads one in-scope record, or `NotFound` (whether it doesn't exist or is
/// out of scope: the two are indistinguishable, T-7).
async fn fetch_in_scope(
    state: &EngineState,
    conn: &mut PgConnection,
    plan: &AccessPlan,
    attrs: &[AttrInfo],
    id: Uuid,
    lock: bool,
) -> Result<PortalRecord, AppError> {
    let (sql, binds) = record_sql(&state.entities.load(), plan, attrs, id, lock)?;
    let mut q = sqlx::query_scalar::<_, Value>(&sql);
    for b in binds.0 {
        q = q.bind(b);
    }
    let row = q
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;
    to_record(plan, row)
}

pub async fn plan_get(
    state: &EngineState,
    plan: &AccessPlan,
    id: Uuid,
) -> Result<PortalRecord, AppError> {
    if !plan.can_read {
        return Err(AppError::NotFound);
    }
    let (_, attrs) = attrs_for(state, plan).await?;
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    fetch_in_scope(state, &mut conn, plan, &attrs, id, false).await
}

/// Whether `field` is a file the plan may download: readable in the plan and
/// file-backed in today's metadata. Anything else is the uniform 404 (C4):
/// a field the caller can't read looks the same as one that doesn't exist.
fn file_field_check(plan: &AccessPlan, attrs: &[AttrInfo], field: &str) -> Result<(), AppError> {
    let readable_file = plan.can_read
        && plan.readable.contains(field)
        && attrs
            .iter()
            .any(|a| a.logicalname == field && a.is_file_backed());
    if readable_file {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// The statement [`plan_file_key`] runs: the file field's stored value on one
/// live, in-scope record, as JSON (a key, or an array of keys for a
/// multi-file field). Call [`file_field_check`] first.
fn file_value_sql(
    plan: &AccessPlan,
    attrs: &[AttrInfo],
    id: Uuid,
    field: &str,
) -> Result<(String, Binds), AppError> {
    let mut binds = Binds::default();
    let id_param = binds.push(id.to_string());
    let scope = scope_clause(&plan.entity, &plan.conditions, attrs, "t", &mut binds)?;
    let sql = format!(
        "SELECT to_jsonb(t.{column}) FROM {table} t \
         WHERE t.id = ${id_param}::uuid AND t.is_active IS NOT FALSE AND {scope}",
        column = quote_ident(field),
        table = quote_ident(&plan.entity),
    );
    Ok((sql, binds))
}

/// The object key a portal download of `field` on record `id` names (web
/// portal plan Phase 5). The record must be in the plan's scope and the field
/// readable and file-backed; a missing record, an out-of-scope one, an
/// unreadable field and an empty field are all the same 404. A multi-file
/// field needs `key`, which must be one of its values (else 404). The caller
/// presigns the result (`attome_document::files::record_file_download`, which
/// also checks the key sits under this record's own prefix).
pub async fn plan_file_key(
    state: &EngineState,
    plan: &AccessPlan,
    id: Uuid,
    field: &str,
    key: Option<&str>,
) -> Result<String, AppError> {
    let (_, attrs) = attrs_for(state, plan).await?;
    file_field_check(plan, &attrs, field)?;
    let (sql, binds) = file_value_sql(plan, &attrs, id, field)?;
    let mut q = sqlx::query_scalar::<_, Option<Value>>(&sql);
    for b in binds.0 {
        q = q.bind(b);
    }
    let value = q
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .flatten()
        .ok_or(AppError::NotFound)?;
    match value {
        Value::String(stored) if !stored.is_empty() && key.is_none_or(|k| k == stored) => {
            Ok(stored)
        }
        Value::Array(items) => {
            let requested = key.ok_or_else(|| {
                AppError::Validation(format!(
                    "{field} holds several files; pass ?key=<one of them>"
                ))
            })?;
            items
                .iter()
                .any(|v| v.as_str() == Some(requested))
                .then(|| requested.to_owned())
                .ok_or(AppError::NotFound)
        }
        _ => Err(AppError::NotFound),
    }
}

/// Whether the plan may upload to `field` (D-774): the plan updates the
/// entity, `field` is writable in it and file-backed in today's metadata.
/// Anything else is the uniform 404.
fn upload_field_check(plan: &AccessPlan, attrs: &[AttrInfo], field: &str) -> Result<(), AppError> {
    let writable_file = plan.can_update
        && plan.writable.contains(field)
        && attrs
            .iter()
            .any(|a| a.logicalname == field && a.is_file_backed());
    if writable_file {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// `SELECT 1` for one live, in-scope record: the scope half of an upload
/// check. Call [`upload_field_check`] first.
fn in_scope_sql(
    plan: &AccessPlan,
    attrs: &[AttrInfo],
    id: Uuid,
) -> Result<(String, Binds), AppError> {
    let mut binds = Binds::default();
    let id_param = binds.push(id.to_string());
    let scope = scope_clause(&plan.entity, &plan.conditions, attrs, "t", &mut binds)?;
    let sql = format!(
        "SELECT 1 FROM {table} t \
         WHERE t.id = ${id_param}::uuid AND t.is_active IS NOT FALSE AND {scope}",
        table = quote_ident(&plan.entity),
    );
    Ok((sql, binds))
}

/// The gate for a portal upload to `field` of record `id` (D-774): the field
/// is a file the plan may write and the record is live and in scope. Every
/// miss is the same 404. The upload itself goes through the staff pipeline
/// (`attome_document::files::start_upload` and its siblings) with a portal owner,
/// and naming the promoted file on the record is an ordinary `plan_update`,
/// whose engine check requires a clean session this portal user owns.
pub async fn plan_upload_target(
    state: &EngineState,
    plan: &AccessPlan,
    id: Uuid,
    field: &str,
) -> Result<(), AppError> {
    let (_, attrs) = attrs_for(state, plan).await?;
    upload_field_check(plan, &attrs, field)?;
    let (sql, binds) = in_scope_sql(plan, &attrs, id)?;
    let mut q = sqlx::query_scalar::<_, i32>(&sql);
    for b in binds.0 {
        q = q.bind(b);
    }
    q.fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .map(|_| ())
        .ok_or(AppError::NotFound)
}

fn filter_condition(
    plan: &AccessPlan,
    field: &str,
    value: &str,
) -> Result<GrantCondition, AppError> {
    if !plan.filterable.contains(field) {
        // One message for unknown and hidden fields alike.
        return Err(AppError::Validation(format!(
            "'{field}' cannot be filtered or sorted on"
        )));
    }
    Ok(GrantCondition {
        field_logicalname: field.to_owned(),
        operator: ConditionOperator::Eq,
        value: Value::String(value.to_owned()),
    })
}

/// The list's WHERE: liveness, scope, and the caller's equality filters. A
/// filter on a lookup field also requires the value to be one the caller may
/// see, so a filter can't probe for out-of-scope targets.
fn where_clause(
    registry: &EntityMetaRegistry,
    plan: &AccessPlan,
    attrs: &[AttrInfo],
    query: &PortalListQuery,
    binds: &mut Binds,
) -> Result<String, AppError> {
    let mut clauses = vec![
        "t.is_active IS NOT FALSE".to_owned(),
        scope_clause(&plan.entity, &plan.conditions, attrs, "t", binds)?,
    ];
    for (field, value) in &query.filters {
        let condition = filter_condition(plan, field, value)?;
        let rendered =
            attome_security::conditions::render_condition(&condition, attrs, "t", binds.next())
                .map_err(|_| {
                    AppError::Validation(format!("'{field}' cannot be filtered or sorted on"))
                })?;
        binds.push(rendered.bind_text);
        clauses.push(rendered.sql);
        if attrs
            .iter()
            .any(|a| &a.logicalname == field && is_lookup(a))
        {
            let col = format!("t.{}", quote_ident(field));
            clauses.push(lookup_visible_sql(registry, plan, field, &col, binds)?);
        }
    }
    Ok(clauses.join(" AND "))
}

pub async fn plan_list(
    state: &EngineState,
    plan: &AccessPlan,
    query: PortalListQuery,
) -> Result<PaginatedResponse<PortalRecord>, AppError> {
    if !plan.can_read {
        return Err(AppError::NotFound);
    }
    let (_, attrs) = attrs_for(state, plan).await?;
    let page_size = match query.page_size {
        n if n <= 0 => PORTAL_DEFAULT_PAGE_SIZE,
        n => n.min(PORTAL_MAX_PAGE_SIZE),
    };
    // `page_size` is already inside the portal cap (at most 100), which is
    // below `MAX_PAGE_SIZE`, so the shared window keeps it as is.
    let window = PageWindow::resolve(
        Some(query.page),
        Some(page_size),
        PageBase::One,
        PORTAL_DEFAULT_PAGE_SIZE,
    );
    let ListSql {
        count_sql,
        count_binds,
        list_sql,
        binds,
    } = list_sql(&state.entities.load(), plan, &attrs, &query)?;

    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql);
    for b in count_binds.0 {
        count_q = count_q.bind(b);
    }
    let total = count_q
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;

    let mut list_q = sqlx::query_scalar::<_, Value>(&list_sql);
    for b in binds.0 {
        list_q = list_q.bind(b);
    }
    let rows = list_q
        .bind(window.page_size)
        .bind(window.offset)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    let items = rows
        .into_iter()
        .map(|row| to_record(plan, row))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PaginatedResponse {
        items,
        total,
        page: window.page,
        page_size: window.page_size,
    })
}

/// A list's two statements. The list's last two placeholders are `LIMIT` and
/// `OFFSET`, bound by the caller.
struct ListSql {
    count_sql: String,
    count_binds: Binds,
    list_sql: String,
    binds: Binds,
}

fn list_sql(
    registry: &EntityMetaRegistry,
    plan: &AccessPlan,
    attrs: &[AttrInfo],
    query: &PortalListQuery,
) -> Result<ListSql, AppError> {
    let order = match &query.order_by {
        Some((field, desc)) => {
            filter_condition(plan, field, "")?;
            // Sorting by an opaque id tells the caller nothing useful, and it
            // orders targets they may not see.
            if attrs
                .iter()
                .any(|a| &a.logicalname == field && is_lookup(a))
            {
                return Err(AppError::Validation(format!(
                    "'{field}' cannot be filtered or sorted on"
                )));
            }
            format!(
                "t.{} {} NULLS LAST, t.id",
                quote_ident(field),
                if *desc { "DESC" } else { "ASC" }
            )
        }
        None => "t.id".to_owned(),
    };
    let table = quote_ident(&plan.entity);

    let mut count_binds = Binds::default();
    let count_where = where_clause(registry, plan, attrs, query, &mut count_binds)?;
    let count_sql = format!("SELECT count(*) FROM {table} t WHERE {count_where}");

    let mut binds = Binds::default();
    let where_sql = where_clause(registry, plan, attrs, query, &mut binds)?;
    let cols = projection(registry, plan, attrs, &mut binds)?;
    let limit_param = binds.next();
    let list_sql = format!(
        "SELECT row_to_json(x) FROM (SELECT {cols} FROM {table} t WHERE {where_sql} \
         ORDER BY {order} LIMIT ${limit_param} OFFSET ${offset_param}) x",
        offset_param = limit_param + 1,
    );
    Ok(ListSql {
        count_sql,
        count_binds,
        list_sql,
        binds,
    })
}

fn body_object(body: Value) -> Result<Map<String, Value>, AppError> {
    match body {
        Value::Object(obj) => Ok(obj),
        _ => Err(AppError::Validation(
            "request body must be a JSON object".into(),
        )),
    }
}

/// A client may only send fields on the writable allowlist (D-575).
fn check_client_fields(plan: &AccessPlan, obj: &Map<String, Value>) -> Result<(), AppError> {
    if obj.keys().any(|k| !plan.writable.contains(k)) {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// The single-value check [`check_lookup_writes`] runs: is `target` a value
/// the plan may see through `field`. `None` when no value ever is (no scope
/// for `field`, or a target entity today's metadata doesn't know): that is
/// answered without a statement, since `SELECT FALSE` would leave the target
/// bind unused and Postgres refuses the bind count, a masked 500 instead of
/// the uniform 422 (found by T-37).
fn lookup_write_sql(
    registry: &EntityMetaRegistry,
    plan: &AccessPlan,
    field: &str,
    target: Uuid,
) -> Result<Option<(String, Binds)>, AppError> {
    let mut binds = Binds::default();
    let param = format!("${}::uuid", binds.push(target.to_string()));
    let visible = lookup_visible_sql(registry, plan, field, &param, &mut binds)?;
    if visible == "FALSE" {
        return Ok(None);
    }
    Ok(Some((format!("SELECT {visible}"), binds)))
}

/// G-1: every lookup value the client sends must be a target the caller may
/// see, checked inside the write transaction. A miss is refused with the same
/// 422 `validate_lookup_targets` gives a nonexistent id, so the answer can't
/// be used to test whether an id exists.
async fn check_lookup_writes(
    state: &EngineState,
    conn: &mut PgConnection,
    plan: &AccessPlan,
    attrs: &[AttrInfo],
    client: &Map<String, Value>,
) -> Result<(), AppError> {
    for attr in attrs.iter().filter(|a| is_lookup(a)) {
        let Some(value) = client.get(&attr.logicalname) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        let refused = || {
            AppError::Validation(format!(
                "{}: lookup target does not exist or is deleted",
                attr.logicalname
            ))
        };
        let target = value
            .as_str()
            .and_then(|s| s.parse::<Uuid>().ok())
            .ok_or_else(refused)?;
        let Some((sql, binds)) =
            lookup_write_sql(&state.entities.load(), plan, &attr.logicalname, target)?
        else {
            return Err(refused());
        };
        let mut q = sqlx::query_scalar::<_, bool>(&sql);
        for b in binds.0 {
            q = q.bind(b);
        }
        if !q.fetch_one(&mut *conn).await.map_err(AppError::internal)? {
            return Err(refused());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn audit(
    state: &EngineState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &AccessPlan,
    attrs: &[AttrInfo],
    record_id: Uuid,
    operation: AuditOperation,
    changed: &Map<String, Value>,
    old_row: Option<&Value>,
) -> Result<(), AppError> {
    let changed_fields = field_changes_from_obj(tx, state, attrs, changed, old_row).await;
    let event = AuditEvent {
        organization_ref: plan.owner_org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(plan.entity.clone()),
        record_id: Some(record_id),
        operation,
        version_before: None,
        version_after: None,
        user_context: AuditUserContext {
            user_id: plan.portal_user_id,
            user_name: plan.portal_user_label.clone(),
            user_display_name: plan.portal_user_label.clone(),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: plan.request_context.clone(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(format!("portal {}", plan.entity)),
        event_comment: None,
        changed_fields,
        snapshot_json: None,
    };
    attome_audit::audit_service(state)
        .write_in_tx_attributed(tx, event, Attribution::portal_user(plan.portal_user_id))
        .await?;
    Ok(())
}

/// Creates a record. The portal user field is stamped by the engine; the new
/// row must fall inside the plan's scope (a portal user cannot create a
/// record they could not then see, e.g. one pointing at another customer).
/// The owning team gets its ordinary share, so staff see the record through
/// the existing D-133 model.
pub async fn plan_create(
    state: &EngineState,
    plan: &AccessPlan,
    body: Value,
) -> Result<PortalRecord, AppError> {
    if !plan.can_create {
        return Err(AppError::Forbidden);
    }
    let (entity_id, attrs) = attrs_for(state, plan).await?;
    let client = body_object(body)?;
    check_client_fields(plan, &client)?;
    let mut obj = client.clone();
    if let Some(field) = &plan.portal_user_field {
        obj.insert(
            field.clone(),
            Value::String(plan.portal_user_id.to_string()),
        );
    }
    validate_lookup_targets(state, &attrs, &obj).await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    check_lookup_writes(state, &mut tx, plan, &attrs, &client).await?;
    let mutation = create_one_as(
        &mut tx,
        state,
        Principal::Portal(plan),
        &plan.entity,
        &attrs,
        &obj,
        plan.create_stamp(),
        MutationMode::Strict,
    )
    .await?;
    let record_id = mutation.record_id;
    if let Err(e) = fetch_in_scope(state, &mut tx, plan, &attrs, record_id, false).await {
        tracing::warn!(entity = %plan.entity, error = ?e, "portal create: the new record is outside the caller's scope");
        return Err(AppError::Validation(
            "the record would be outside what you can access".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO record_share \
            (record_id, entity_ref, principal_type, principal_id, capability, granted_by) \
         VALUES ($1, $2, 1, $3, 1, NULL) \
         ON CONFLICT (record_id, entity_ref, principal_type, principal_id, capability) DO NOTHING",
    )
    .bind(record_id)
    .bind(entity_id)
    .bind(plan.owner_team_ref)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    audit(
        state,
        &mut tx,
        plan,
        &attrs,
        record_id,
        AuditOperation::Create,
        &obj,
        None,
    )
    .await?;
    let record = fetch_in_scope(state, &mut tx, plan, &attrs, record_id, false).await?;
    attome_db::tx::commit(tx).await?;
    Ok(record)
}

/// Updates an in-scope record. Out of scope and missing are the same 404.
/// The updated row must still be in scope (no moving a record out of reach).
pub async fn plan_update(
    state: &EngineState,
    plan: &AccessPlan,
    id: Uuid,
    expected_row_version: i64,
    body: Value,
) -> Result<PortalRecord, AppError> {
    if !plan.can_update {
        return Err(AppError::NotFound);
    }
    let (entity_id, attrs) = attrs_for(state, plan).await?;
    let obj = body_object(body)?;
    check_client_fields(plan, &obj)?;
    validate_lookup_targets(state, &attrs, &obj).await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    fetch_in_scope(state, &mut tx, plan, &attrs, id, true).await?;
    check_lookup_writes(state, &mut tx, plan, &attrs, &obj).await?;
    let mutation = update_one_as(
        &mut tx,
        state,
        Principal::Portal(plan),
        &plan.entity,
        entity_id,
        id,
        &attrs,
        &obj,
        None,
        expected_row_version,
        MutationMode::Strict,
    )
    .await?;
    if fetch_in_scope(state, &mut tx, plan, &attrs, id, false)
        .await
        .is_err()
    {
        return Err(AppError::Validation(
            "the change would move the record outside what you can access".into(),
        ));
    }
    audit(
        state,
        &mut tx,
        plan,
        &attrs,
        id,
        AuditOperation::Update,
        &obj,
        mutation.old_row.as_ref(),
    )
    .await?;
    let record = fetch_in_scope(state, &mut tx, plan, &attrs, id, false).await?;
    attome_db::tx::commit(tx).await?;
    Ok(record)
}

/// Soft-deletes an in-scope record. Refused for an entity with dependents: a
/// cascade would reach records outside the plan's scope.
pub async fn plan_delete(
    state: &EngineState,
    plan: &AccessPlan,
    id: Uuid,
    expected_row_version: Option<i64>,
) -> Result<(), AppError> {
    if !plan.can_delete {
        return Err(AppError::NotFound);
    }
    let (entity_id, attrs) = attrs_for(state, plan).await?;
    if !state.entities.load().dependents_of(entity_id).is_empty() {
        return Err(AppError::Conflict(
            "records of this entity cannot be deleted from a portal",
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    fetch_in_scope(state, &mut tx, plan, &attrs, id, true).await?;
    delete_one_as(
        &mut tx,
        &plan.entity,
        &[],
        id,
        None,
        expected_row_version,
        &crate::entity_mutation::DeleteOrigin::new(crate::entity_mutation::DeleteKind::Portal),
    )
    .await?;
    audit(
        state,
        &mut tx,
        plan,
        &attrs,
        id,
        AuditOperation::SoftDelete,
        &Map::new(),
        None,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// T-37 (web-portal plan §6.1): property tests of the access-plan compiler,
/// with no database. The engine's half of the portal trust boundary is the
/// SQL this module renders from an [`AccessPlan`]; these generate plans the
/// way `attome-portal`'s resolver hands them over (conditions that no longer
/// render are already [`PlanCondition::MatchNothing`], field sets hold only
/// live fields, `filterable ⊆ readable`, the portal user field is never
/// writable) and check two properties:
///
/// 1. **Containment.** Whatever the plan, list query or metadata, the
///    compiled statements read only the plan's entity and its lookup
///    targets, never a staff widening arm (shares, default shares, teams,
///    business units, hierarchy, owner or creator columns); every placeholder
///    has exactly one bind; nothing outside `readable` is projected, and a
///    readable lookup is projected only under its scope check; a refused
///    list query is a validation error and a refused write body `Forbidden`
///    (never an internal error, which would be a 500); and a plan with no condition, an unresolvable condition, or a
///    lookup with no live scope matches nothing.
/// 2. **Monotonicity.** Applying any restriction (drop a readable, writable
///    or filterable field; make a condition match nothing; drop a field or
///    the lookup target's field from metadata; drop a lookup's scope; empty
///    or unregister its target) never turns a refusal into an acceptance:
///    each scope conjunct stays identical or becomes `FALSE`, the projected
///    fields shrink or stay, a lookup's visibility only narrows, and a list
///    query or write body the wider plan refused stays refused.
///
/// The action flags (`can_read` …) are checked before any of this runs and
/// are covered by the DB-backed `portal_isolation` suite. Run with:
/// `cargo test -p attome-records --lib access_plan::t37_property`
#[cfg(test)]
mod t37_property {
    use super::*;
    use attome_core::EntityMeta;
    use proptest::prelude::*;

    const ENTITY: &str = "t37_case";
    const TARGET: &str = "t37_account";
    const PORTAL_USER: &str = "webportal_user";
    const ENTITY_ID: Uuid = Uuid::from_u128(0x3701);
    const TARGET_ID: Uuid = Uuid::from_u128(0x3702);
    const PORTAL_USER_ID: Uuid = Uuid::from_u128(0x3703);
    /// A lookup whose target entity is not in the registry at all.
    const GONE_ID: Uuid = Uuid::from_u128(0x3704);

    static CASE_FIELDS: [&str; 11] = [
        "title",
        "attachment",
        "status",
        "secret",
        "notes",
        "tags",
        "account_ref",
        "contact_ref",
        "gone_ref",
        "ghost",
        "id",
    ];
    static TARGET_FIELDS: [&str; 4] = ["name", "region", "ghost", "id"];
    static LOOKUP_FIELDS: [&str; 4] = ["account_ref", "contact_ref", "gone_ref", "title"];
    static SCOPE_TARGETS: [&str; 2] = [TARGET, "t37_gone"];

    /// Text that would mean the portal path reached the staff access model.
    static FORBIDDEN: [&str; 14] = [
        "record_share",
        "default_share",
        "owner_ref",
        "owner_type",
        "org_ref",
        "organization_ref",
        "team",
        "businessunit",
        "business_unit",
        "position",
        "hierarchy",
        "created_by",
        "modified_by",
        "systemuser",
    ];

    fn attr(logicalname: &str, field_type_int: i32) -> AttrInfo {
        AttrInfo {
            logicalname: logicalname.to_owned(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            options: None,
        }
    }

    fn lookup(logicalname: &str, target: Uuid) -> AttrInfo {
        AttrInfo {
            lookup_entity_ref: Some(target),
            ..attr(logicalname, 11)
        }
    }

    fn case_attrs() -> Vec<AttrInfo> {
        vec![
            attr("title", 3),
            attr("status", 1),
            AttrInfo {
                is_sensitive: true,
                ..attr("secret", 3)
            },
            // Text settings are staff metadata a portal must never see.
            AttrInfo {
                is_filterable: false,
                options: Some(serde_json::json!({"mask": "internal"})),
                ..attr("notes", 3)
            },
            // A choice's options are what a portal form needs.
            AttrInfo {
                options: Some(serde_json::json!({"options": ["open", "closed"]})),
                ..attr("tags", 7)
            },
            lookup("account_ref", TARGET_ID),
            lookup("contact_ref", PORTAL_USER_ID),
            lookup("gone_ref", GONE_ID),
            attr("attachment", 12),
        ]
    }

    fn target_attrs() -> Vec<AttrInfo> {
        vec![attr("name", 3), attr("region", 1)]
    }

    fn meta(entity_id: Uuid, logicalname: &str, attrs: Vec<AttrInfo>) -> EntityMeta {
        EntityMeta {
            entity_id,
            logicalname: logicalname.to_owned(),
            attrs,
            is_append_only: false,
            primary_name_attribute: None,
        }
    }

    /// The resolver's rule (`attome-portal` `context::render_conditions`, G-6):
    /// a condition that doesn't render against today's metadata matches
    /// nothing.
    fn gate(condition: PlanCondition, attrs: &[AttrInfo]) -> PlanCondition {
        match condition {
            PlanCondition::Match(g) if condition_renders(&g, attrs) => PlanCondition::Match(g),
            _ => PlanCondition::MatchNothing,
        }
    }

    fn plan(
        conditions: Vec<PlanCondition>,
        readable: BTreeSet<String>,
        writable: BTreeSet<String>,
        filterable: BTreeSet<String>,
        portal_user_field: Option<String>,
        lookup_scopes: BTreeMap<String, LookupScope>,
    ) -> AccessPlan {
        AccessPlan {
            portal_user_id: Uuid::from_u128(0x37ff),
            portal_user_label: "t37".to_owned(),
            webportal_id: Uuid::from_u128(0x37fe),
            entity: ENTITY.to_owned(),
            can_read: true,
            can_create: true,
            can_update: true,
            can_delete: true,
            conditions,
            readable,
            writable,
            filterable,
            owner_team_ref: Uuid::from_u128(0x37fd),
            owner_org_ref: Uuid::from_u128(0x37fc),
            portal_user_field,
            lookup_scopes,
            request_context: Default::default(),
            role_id: Some(Uuid::from_u128(0x37fb)),
        }
    }

    #[derive(Clone, Debug)]
    struct World {
        plan: AccessPlan,
        case_attrs: Vec<AttrInfo>,
        target_attrs: Vec<AttrInfo>,
        target_registered: bool,
        filters: Vec<(String, String)>,
        order_by: Option<(String, bool)>,
        body: Vec<String>,
    }

    impl World {
        fn registry(&self) -> EntityMetaRegistry {
            let mut entities = vec![
                meta(ENTITY_ID, ENTITY, self.case_attrs.clone()),
                meta(PORTAL_USER_ID, PORTAL_USER, Vec::new()),
            ];
            if self.target_registered {
                entities.push(meta(TARGET_ID, TARGET, self.target_attrs.clone()));
            }
            EntityMetaRegistry::from_entities(entities)
        }

        fn query(&self) -> PortalListQuery {
            PortalListQuery {
                page: 1,
                page_size: PORTAL_DEFAULT_PAGE_SIZE,
                filters: self.filters.clone(),
                order_by: self.order_by.clone(),
            }
        }

        /// What `attome-portal` derives from today's metadata before the engine
        /// ever sees a plan (`context::build_template`, `render_conditions`).
        fn resolve(&mut self) {
            let live: BTreeSet<String> = self
                .case_attrs
                .iter()
                .map(|a| a.logicalname.clone())
                .collect();
            let plan = &mut self.plan;
            plan.readable.retain(|f| live.contains(f));
            plan.writable.retain(|f| live.contains(f));
            let readable = plan.readable.clone();
            plan.filterable
                .retain(|f| live.contains(f) && readable.contains(f));
            if let Some(field) = &plan.portal_user_field {
                plan.writable.remove(field);
            }
            // A file is never filterable to a portal (it may be writable: an
            // upload, D-774).
            for a in self.case_attrs.iter().filter(|a| a.is_file_backed()) {
                plan.filterable.remove(&a.logicalname);
            }
            plan.lookup_scopes.retain(|f, _| live.contains(f));
            plan.conditions = std::mem::take(&mut plan.conditions)
                .into_iter()
                .map(|c| gate(c, &self.case_attrs))
                .collect();
            for scope in plan.lookup_scopes.values_mut() {
                if let LookupScope::Target { entity, conditions } = scope {
                    let target_attrs: &[AttrInfo] = if entity == TARGET && self.target_registered {
                        &self.target_attrs
                    } else {
                        &[]
                    };
                    *conditions = std::mem::take(conditions)
                        .into_iter()
                        .map(|c| gate(c, target_attrs))
                        .collect();
                }
            }
        }
    }

    fn value() -> impl Strategy<Value = Value> {
        prop_oneof![
            Just(Value::String(Uuid::from_u128(7).to_string())),
            "[a-z]{0,6}".prop_map(Value::String),
            (-5i64..5).prop_map(Value::from),
            any::<bool>().prop_map(Value::Bool),
            Just(Value::Null),
            prop::collection::vec("[a-z]{0,3}".prop_map(Value::String), 0..3)
                .prop_map(Value::Array),
        ]
    }

    fn condition(fields: &'static [&'static str]) -> impl Strategy<Value = PlanCondition> {
        prop_oneof![
            1 => Just(PlanCondition::MatchNothing),
            6 => (prop::sample::select(fields), 0i16..=6, value()).prop_map(|(f, op, value)| {
                PlanCondition::Match(GrantCondition {
                    field_logicalname: f.to_owned(),
                    operator: ConditionOperator::from_i16(op).expect("0..=6 are operators"),
                    value,
                })
            }),
        ]
    }

    fn scope() -> impl Strategy<Value = Option<LookupScope>> {
        prop_oneof![
            Just(None),
            Just(Some(LookupScope::SelfOnly)),
            (
                prop::sample::select(&SCOPE_TARGETS[..]),
                prop::collection::vec(condition(&TARGET_FIELDS), 0..3),
            )
                .prop_map(|(entity, conditions)| Some(LookupScope::Target {
                    entity: entity.to_owned(),
                    conditions,
                })),
        ]
    }

    fn fields() -> impl Strategy<Value = BTreeSet<String>> {
        prop::sample::subsequence(&CASE_FIELDS[..], 0..=CASE_FIELDS.len())
            .prop_map(|v| v.into_iter().map(str::to_owned).collect())
    }

    prop_compose! {
        fn world()(
            conditions in prop::collection::vec(condition(&CASE_FIELDS), 0..4),
            readable in fields(),
            writable in fields(),
            filterable in fields(),
            scopes in prop::collection::vec(scope(), LOOKUP_FIELDS.len()),
            stamp_contact in any::<bool>(),
            filters in prop::collection::vec(
                (prop::sample::select(&CASE_FIELDS[..]), "[a-z0-9-]{0,8}"),
                0..3,
            ),
            order_by in prop::option::of((prop::sample::select(&CASE_FIELDS[..]), any::<bool>())),
            body in fields(),
        ) -> World {
            let lookup_scopes = LOOKUP_FIELDS
                .iter()
                .zip(scopes)
                .filter_map(|(f, s)| s.map(|s| ((*f).to_owned(), s)))
                .collect();
            let mut world = World {
                plan: plan(
                    conditions,
                    readable,
                    writable,
                    filterable,
                    stamp_contact.then(|| "contact_ref".to_owned()),
                    lookup_scopes,
                ),
                case_attrs: case_attrs(),
                target_attrs: target_attrs(),
                target_registered: true,
                filters: filters.into_iter().map(|(f, v)| (f.to_owned(), v)).collect(),
                order_by: order_by.map(|(f, d)| (f.to_owned(), d)),
                body: body.into_iter().collect(),
            };
            world.resolve();
            world
        }
    }

    #[derive(Clone, Debug)]
    enum Restriction {
        DropReadable(usize),
        DropWritable(usize),
        DropFilterable(usize),
        NothingCondition(usize),
        DropCaseAttr(usize),
        DropTargetAttr(usize),
        DropLookupScope(usize),
        EmptyTargetConditions(usize),
        TargetGone,
    }

    fn restriction() -> impl Strategy<Value = Restriction> {
        prop_oneof![
            any::<usize>().prop_map(Restriction::DropReadable),
            any::<usize>().prop_map(Restriction::DropWritable),
            any::<usize>().prop_map(Restriction::DropFilterable),
            any::<usize>().prop_map(Restriction::NothingCondition),
            any::<usize>().prop_map(Restriction::DropCaseAttr),
            any::<usize>().prop_map(Restriction::DropTargetAttr),
            any::<usize>().prop_map(Restriction::DropLookupScope),
            any::<usize>().prop_map(Restriction::EmptyTargetConditions),
            Just(Restriction::TargetGone),
        ]
    }

    /// The `i`-th item, wrapping; `None` when there are none.
    fn nth<T>(mut items: impl ExactSizeIterator<Item = T>, i: usize) -> Option<T> {
        let len = items.len();
        if len == 0 { None } else { items.nth(i % len) }
    }

    impl Restriction {
        fn apply(&self, world: &World) -> World {
            let mut w = world.clone();
            let plan = &mut w.plan;
            match *self {
                Restriction::DropReadable(i) => {
                    if let Some(f) = nth(plan.readable.iter().cloned(), i) {
                        plan.readable.remove(&f);
                    }
                }
                Restriction::DropWritable(i) => {
                    if let Some(f) = nth(plan.writable.iter().cloned(), i) {
                        plan.writable.remove(&f);
                    }
                }
                Restriction::DropFilterable(i) => {
                    if let Some(f) = nth(plan.filterable.iter().cloned(), i) {
                        plan.filterable.remove(&f);
                    }
                }
                Restriction::NothingCondition(i) => {
                    if !plan.conditions.is_empty() {
                        let n = i % plan.conditions.len();
                        plan.conditions[n] = PlanCondition::MatchNothing;
                    }
                }
                Restriction::DropCaseAttr(i) => {
                    let n = i % w.case_attrs.len();
                    w.case_attrs.remove(n);
                }
                Restriction::DropTargetAttr(i) => {
                    let n = i % w.target_attrs.len();
                    w.target_attrs.remove(n);
                }
                Restriction::DropLookupScope(i) => {
                    if let Some(f) = nth(plan.lookup_scopes.keys().cloned(), i) {
                        plan.lookup_scopes.remove(&f);
                    }
                }
                Restriction::EmptyTargetConditions(i) => {
                    if let Some(f) = nth(plan.lookup_scopes.keys().cloned(), i)
                        && let Some(LookupScope::Target { conditions, .. }) =
                            plan.lookup_scopes.get_mut(&f)
                    {
                        conditions.clear();
                    }
                }
                Restriction::TargetGone => w.target_registered = false,
            }
            w.resolve();
            w
        }
    }

    /// `$12` -> `$?`: a restriction that drops a bind renumbers the rest.
    fn normalize(sql: &str) -> String {
        let mut out = String::with_capacity(sql.len());
        let mut chars = sql.chars().peekable();
        while let Some(c) = chars.next() {
            out.push(c);
            if c == '$' {
                let mut digits = false;
                while chars.next_if(char::is_ascii_digit).is_some() {
                    digits = true;
                }
                if digits {
                    out.push('?');
                }
            }
        }
        out
    }

    /// A [`scope_clause`] result as its conjuncts (`["FALSE"]` for none).
    fn conjuncts(scope: &str) -> Vec<String> {
        if scope == "FALSE" {
            return vec!["FALSE".to_owned()];
        }
        let inner = scope
            .strip_prefix('(')
            .and_then(|s| s.strip_suffix(')'))
            .expect("scope_clause parenthesises its conjuncts");
        inner.split(" AND ").map(normalize).collect()
    }

    /// Row-scope monotonicity: every conjunct is the same or became `FALSE`,
    /// so the narrower predicate implies the wider one.
    fn narrower(new: &[String], old: &[String]) -> bool {
        new == ["FALSE"]
            || (new.len() == old.len() && new.iter().zip(old).all(|(n, o)| n == o || n == "FALSE"))
    }

    #[derive(Debug, PartialEq)]
    enum LookupSight {
        Deny,
        SelfOnly,
        Scoped(Vec<String>),
    }

    fn lookup_narrower(new: &LookupSight, old: &LookupSight) -> bool {
        match (new, old) {
            (LookupSight::Deny, _) => true,
            (LookupSight::SelfOnly, LookupSight::SelfOnly) => true,
            (LookupSight::Scoped(n), LookupSight::Scoped(o)) => narrower(n, o),
            _ => false,
        }
    }

    /// Only the plan's own tables, no staff arm, and one bind per
    /// placeholder, numbered from 1 without gaps.
    fn assert_contained(sql: &str, binds: usize) {
        for token in FORBIDDEN {
            assert!(!sql.contains(token), "staff arm `{token}` in: {sql}");
        }
        let allowed = [quote_ident(ENTITY), quote_ident(TARGET)];
        for (at, _) in sql.match_indices("FROM ") {
            let rest = &sql[at + "FROM ".len()..];
            if rest.starts_with('(') {
                continue;
            }
            let table = rest.split(' ').next().unwrap_or_default();
            assert!(allowed.iter().any(|a| a == table), "reads `{table}`: {sql}");
        }
        let mut found = BTreeSet::new();
        for (at, _) in sql.match_indices('$') {
            let digits: String = sql[at + 1..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            found.insert(digits.parse::<usize>().expect("a numbered placeholder"));
        }
        assert_eq!(
            found,
            (1..=binds).collect::<BTreeSet<_>>(),
            "placeholders vs {binds} binds: {sql}"
        );
    }

    fn sight(plan: &AccessPlan, registry: &EntityMetaRegistry, field: &str) -> LookupSight {
        let Some((sql, binds)) = lookup_write_sql(registry, plan, field, Uuid::from_u128(9))
            .expect("a lookup check always compiles")
        else {
            return LookupSight::Deny;
        };
        assert_contained(&sql, binds.0.len());
        let body = sql.strip_prefix("SELECT ").expect("SELECT <predicate>");
        if let Some((_, scope)) = body.split_once("AND lk.is_active IS NOT FALSE AND ") {
            LookupSight::Scoped(conjuncts(scope.strip_suffix(')').expect("EXISTS closes")))
        } else {
            assert_eq!(
                body, "$1::uuid = $2::uuid",
                "only the self-only arm is left"
            );
            LookupSight::SelfOnly
        }
    }

    /// What one plan lets through, observed only from the compiled SQL.
    #[derive(Debug)]
    struct Sight {
        scope: Vec<String>,
        projected: BTreeSet<String>,
        lookups: Vec<LookupSight>,
        list_ok: bool,
        body_ok: bool,
        /// [`describe`]'s fields: `(readable, writable, filterable, pickable)`.
        described: BTreeMap<String, (bool, bool, bool, bool)>,
        /// The file fields [`file_field_check`] lets the plan download.
        files: BTreeSet<String>,
        /// The file fields [`upload_field_check`] lets the plan upload to.
        uploads: BTreeSet<String>,
    }

    /// The upload gate admits exactly the updatable plan's writable file
    /// fields, and its scope statement stays inside the plan.
    fn uploadable(w: &World) -> BTreeSet<String> {
        let plan = &w.plan;
        let (sql, binds) =
            in_scope_sql(plan, &w.case_attrs, Uuid::from_u128(8)).expect("the scope compiles");
        assert_contained(&sql, binds.0.len());
        let mut out = BTreeSet::new();
        for f in CASE_FIELDS {
            let expected = plan.can_update
                && plan.writable.contains(f)
                && w.case_attrs
                    .iter()
                    .any(|a| a.logicalname == f && a.is_file_backed());
            match upload_field_check(plan, &w.case_attrs, f) {
                Ok(()) => {
                    assert!(expected, "`{f}` uploadable");
                    out.insert(f.to_owned());
                }
                Err(AppError::NotFound) => assert!(!expected, "`{f}` refused"),
                Err(e) => panic!("the upload gate answered {e:?}"),
            }
        }
        out
    }

    /// The file gate admits exactly the readable file fields, and the file
    /// statement stays inside the plan like every other.
    fn downloadable(w: &World) -> BTreeSet<String> {
        let plan = &w.plan;
        let mut out = BTreeSet::new();
        for f in CASE_FIELDS {
            let is_file = w
                .case_attrs
                .iter()
                .any(|a| a.logicalname == f && a.is_file_backed());
            match file_field_check(plan, &w.case_attrs, f) {
                Ok(()) => {
                    assert!(is_file && plan.readable.contains(f), "`{f}` downloadable");
                    let (sql, binds) = file_value_sql(plan, &w.case_attrs, Uuid::from_u128(8), f)
                        .expect("a resolved file read always compiles");
                    assert_contained(&sql, binds.0.len());
                    out.insert(f.to_owned());
                }
                Err(AppError::NotFound) => {
                    assert!(!(is_file && plan.readable.contains(f)), "`{f}` refused");
                }
                Err(e) => panic!("the file gate answered {e:?}"),
            }
        }
        out
    }

    /// [`describe`] names only the plan's fields, with the plan's own flags,
    /// offers a lookup only onto a live target the role reads, and passes on
    /// options only for a choice field.
    fn described(
        w: &World,
        registry: &EntityMetaRegistry,
    ) -> BTreeMap<String, (bool, bool, bool, bool)> {
        let plan = &w.plan;
        let labels: BTreeMap<String, String> = w
            .case_attrs
            .iter()
            .map(|a| (a.logicalname.clone(), format!("L {}", a.logicalname)))
            .collect();
        let view = describe(plan, registry, None, &labels);
        assert_eq!(view.entity, ENTITY);
        let mut out = BTreeMap::new();
        for f in &view.fields {
            let attr = w
                .case_attrs
                .iter()
                .find(|a| a.logicalname == f.name)
                .unwrap_or_else(|| panic!("described `{}`, which metadata lacks", f.name));
            assert!(
                plan.readable.contains(&f.name) || plan.writable.contains(&f.name),
                "described `{}`, which the plan doesn't name",
                f.name
            );
            assert_eq!(f.readable, plan.readable.contains(&f.name));
            assert_eq!(f.writable, plan.writable.contains(&f.name));
            assert!(!f.filterable || (f.readable && plan.filterable.contains(&f.name)));
            assert_eq!(f.label.as_deref(), Some(format!("L {}", f.name).as_str()));
            if let Some(target) = &f.lookup_entity {
                assert!(
                    is_lookup(attr),
                    "`{}` offers a pick list but isn't a lookup",
                    f.name
                );
                assert_eq!(target, TARGET, "`{}` offers an unreadable target", f.name);
                assert!(w.target_registered);
                assert!(matches!(
                    plan.lookup_scopes.get(&f.name),
                    Some(LookupScope::Target { conditions, .. }) if !conditions.is_empty()
                ));
            }
            if f.options.is_some() {
                assert_eq!(f.field_type, "choice", "`{}` leaked its options", f.name);
            }
            if attr.is_file_backed() {
                assert!(!f.filterable, "file `{}` is never filterable", f.name);
            }
            out.insert(
                f.name.clone(),
                (
                    f.readable,
                    f.writable,
                    f.filterable,
                    f.lookup_entity.is_some(),
                ),
            );
        }
        out
    }

    fn observe(w: &World) -> Sight {
        let registry = w.registry();
        let attrs = &w.case_attrs;
        let plan = &w.plan;

        let scope = scope_clause(ENTITY, &plan.conditions, attrs, "t", &mut Binds::default())
            .expect("a resolved scope always renders");
        let scope = conjuncts(&scope);
        if plan.conditions.is_empty()
            || plan
                .conditions
                .iter()
                .any(|c| matches!(c, PlanCondition::MatchNothing))
        {
            assert!(
                scope.iter().any(|c| c == "FALSE"),
                "an empty or unresolvable scope matched: {scope:?}"
            );
        }

        let (sql, binds) = record_sql(&registry, plan, attrs, Uuid::from_u128(8), false)
            .expect("a resolved record read always compiles");
        assert_contained(&sql, binds.0.len());

        let cols = projection(&registry, plan, attrs, &mut Binds::default())
            .expect("a resolved projection always compiles");
        let mut projected = BTreeSet::new();
        for col in cols.split(", ") {
            for a in attrs {
                if !col.contains(&format!("t.{}", quote_ident(&a.logicalname))) {
                    continue;
                }
                assert!(
                    plan.readable.contains(&a.logicalname),
                    "projected unreadable `{}`",
                    a.logicalname
                );
                if is_lookup(a) {
                    assert!(
                        col.starts_with("CASE WHEN "),
                        "lookup `{}` projected without its scope check: {col}",
                        a.logicalname
                    );
                }
                projected.insert(a.logicalname.clone());
            }
        }

        let list_ok = match list_sql(&registry, plan, attrs, &w.query()) {
            Ok(list) => {
                assert_contained(&list.count_sql, list.count_binds.0.len());
                assert_contained(&list.list_sql, list.binds.0.len() + 2);
                true
            }
            Err(AppError::Validation(_)) => false,
            Err(e) => panic!("a list query was refused with a non-validation error: {e:?}"),
        };

        let body: Map<String, Value> = w.body.iter().map(|k| (k.clone(), Value::Null)).collect();
        let body_ok = match check_client_fields(plan, &body) {
            Ok(()) => true,
            Err(AppError::Forbidden) => false,
            Err(e) => panic!("a write body was refused with {e:?}"),
        };

        let lookups = LOOKUP_FIELDS
            .iter()
            .map(|f| {
                let seen = sight(plan, &registry, f);
                let live_scope = match plan.lookup_scopes.get(*f) {
                    None => false,
                    Some(LookupScope::SelfOnly) => true,
                    Some(LookupScope::Target { entity, .. }) => {
                        entity == TARGET && w.target_registered
                    }
                };
                if !live_scope {
                    assert_eq!(
                        seen,
                        LookupSight::Deny,
                        "`{f}` with no live scope is visible"
                    );
                }
                seen
            })
            .collect();

        Sight {
            scope,
            projected,
            lookups,
            list_ok,
            body_ok,
            described: described(w, &registry),
            files: downloadable(w),
            uploads: uploadable(w),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn t37_compiled_sql_stays_inside_the_plan(w in world()) {
            observe(&w);
        }

        #[test]
        fn t37_a_restriction_never_turns_a_deny_into_an_allow(
            w in world(),
            r in restriction(),
        ) {
            let wide = observe(&w);
            let narrow = observe(&r.apply(&w));
            prop_assert!(
                narrower(&narrow.scope, &wide.scope),
                "{:?} widened the row scope: {:?} -> {:?}", r, wide.scope, narrow.scope
            );
            prop_assert!(
                narrow.projected.is_subset(&wide.projected),
                "{:?} projected more: {:?} -> {:?}", r, wide.projected, narrow.projected
            );
            for (f, (n, o)) in LOOKUP_FIELDS.iter().zip(narrow.lookups.iter().zip(&wide.lookups)) {
                prop_assert!(lookup_narrower(n, o), "{:?} widened lookup `{}`: {:?} -> {:?}", r, f, o, n);
            }
            prop_assert!(!narrow.list_ok || wide.list_ok, "{:?} accepted a refused list query", r);
            prop_assert!(!narrow.body_ok || wide.body_ok, "{:?} accepted a refused write body", r);
            for (name, n) in &narrow.described {
                let Some(o) = wide.described.get(name) else {
                    return Err(TestCaseError::fail(format!("{r:?} described new field `{name}`")));
                };
                let only_narrower = (!n.0 || o.0) && (!n.1 || o.1) && (!n.2 || o.2) && (!n.3 || o.3);
                prop_assert!(only_narrower, "{:?} widened `{}` in metadata: {:?} -> {:?}", r, name, o, n);
            }
            prop_assert!(
                narrow.files.is_subset(&wide.files),
                "{:?} made more files downloadable: {:?} -> {:?}", r, wide.files, narrow.files
            );
            prop_assert!(
                narrow.uploads.is_subset(&wide.uploads),
                "{:?} made more fields uploadable: {:?} -> {:?}", r, wide.uploads, narrow.uploads
            );
        }
    }

    /// Keeps the properties honest: the observation parses a real allowing
    /// plan, and restrictions really move it.
    #[test]
    fn t37_observation_sees_an_allowing_plan_and_its_restriction() {
        let names = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<BTreeSet<_>>();
        let mut w = World {
            plan: plan(
                vec![PlanCondition::Match(GrantCondition {
                    field_logicalname: "title".to_owned(),
                    operator: ConditionOperator::Eq,
                    value: Value::String("mine".to_owned()),
                })],
                names(&["title", "account_ref"]),
                names(&["title"]),
                names(&["title"]),
                None,
                BTreeMap::from([(
                    "account_ref".to_owned(),
                    LookupScope::Target {
                        entity: TARGET.to_owned(),
                        conditions: vec![PlanCondition::Match(GrantCondition {
                            field_logicalname: "region".to_owned(),
                            operator: ConditionOperator::Eq,
                            value: Value::from(3),
                        })],
                    },
                )]),
            ),
            case_attrs: case_attrs(),
            target_attrs: target_attrs(),
            target_registered: true,
            filters: vec![("title".to_owned(), "x".to_owned())],
            order_by: Some(("title".to_owned(), true)),
            body: vec!["title".to_owned()],
        };
        w.resolve();
        let wide = observe(&w);
        assert_eq!(wide.scope, ["t.title = $?::TEXT"]);
        assert_eq!(wide.projected, names(&["account_ref", "title"]));
        assert_eq!(
            wide.lookups[0],
            LookupSight::Scoped(vec!["lk.region = $?::NUMERIC".to_owned()])
        );
        assert!(wide.list_ok && wide.body_ok);
        assert_eq!(wide.described["title"], (true, true, true, false));
        assert_eq!(wide.described["account_ref"], (true, false, false, true));
        assert_eq!(wide.described.len(), 2);

        // "title" is the first attribute: its condition, projection, filter
        // and write all go.
        let narrow = observe(&Restriction::DropCaseAttr(0).apply(&w));
        assert_eq!(narrow.scope, ["FALSE"]);
        assert_eq!(narrow.projected, names(&["account_ref"]));
        assert!(!narrow.list_ok && !narrow.body_ok);

        let gone = observe(&Restriction::TargetGone.apply(&w));
        assert_eq!(gone.lookups[0], LookupSight::Deny);
        assert_eq!(
            gone.described["account_ref"],
            (true, false, false, false),
            "no pick list onto a target metadata no longer has"
        );
    }
}
