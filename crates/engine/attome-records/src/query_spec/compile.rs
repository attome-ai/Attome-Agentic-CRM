//! QuerySpec to SQL (roadmap S4-T2 to S4-T5). Every value is bound; names
//! come from metadata and are quoted. The record-level predicate and the
//! field gate are part of the SQL, so a row or column the caller may not read
//! never leaves PostgreSQL.
//!
//! - Fields of the entity, and related fields through up to three lookups
//!   (`primary_contact.team.name`, S4-T3): one `LEFT JOIN` per distinct path
//!   prefix, carrying the target's live-row and record-level predicates, so a
//!   hidden related record shows as NULL and never drops the root row.
//! - `exists` / `not_exists` (S4-T4) over child rows whose lookup points at
//!   the outer row (`incident.customer`) or a many-to-many relationship by
//!   name, each a correlated subquery with the child's own predicates, nested
//!   at most three deep. Inside one, conditions name the child's own fields.
//! - Operators: the stored filters' own (`attome_core::filter::compile`),
//!   plus `between`, `not_in`, the relative dates (`operators`), `mine`,
//!   `my_team` and the Arabic-aware `text_matches` (S4-T5).
//! - Aggregates and grouping are S4-T6 and are refused until then.
//!
//! The cursor holds the last row's sort values and id, sealed
//! (`attome_types::cursor`), and names the sort it was issued for. Resuming
//! compares key by key, so sort keys may mix directions and a NULL sort value
//! is neither skipped nor repeated (PostgreSQL's order: NULLs last ascending,
//! first descending). A row-value comparison `(a, id) > (…)` would drop every
//! row whose sort value is NULL; it is used only when the sort is the id.

use std::cell::RefCell;
use std::collections::HashMap;

use attome_core::{
    AttrInfo, EntityMeta, EntityMetaRegistry, FieldCastError, FieldType, Filter, FilterSchema,
    RelationshipRegistry, cast_for_attr, data_definition::system_column_type, is_multi_choice_attr,
    live_row_predicate, parameter_cast, quote_ident,
};
use attome_security::SecurityContextExt;
use attome_security::field_gate::{self, Surface};
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::model::{Condition, QuerySpec};
use super::operators::{Clock, DATE_OPS, date_range};

/// Rows per page when the spec names none.
pub const DEFAULT_PAGE_SIZE: i64 = 50;
/// The most rows one page may ask for.
pub const MAX_PAGE_SIZE: i64 = 200;
/// The most lookups a related field may follow.
pub const MAX_HOPS: usize = 3;
/// The most `exists` conditions that may nest inside each other.
pub const MAX_EXISTS_DEPTH: usize = 3;

/// A bind value: text, cast in the SQL (`$n::uuid`, `$n::numeric`), the
/// convention `attome_core::filter::compile` and `RlsBinds::to_text_params`
/// already share.
pub type BindValue = String;

/// A compiled query: run `sql` with `binds` in order. It fetches
/// `page_size + 1` rows; a page that comes back full has a next page, whose
/// cursor [`next_cursor`] makes from the last row kept.
#[derive(Debug, Clone, PartialEq)]
pub struct Compiled {
    pub sql: String,
    pub binds: Vec<BindValue>,
    /// The result columns, in SELECT order; a related field is named by its
    /// path.
    pub columns: Vec<String>,
    /// The sort, as `field` or `-field`, ending with the id.
    pub sort: Vec<String>,
    pub page_size: i64,
}

/// The caller's record-read depth per entity id
/// (`attome_security::resolve_all_entity_access_levels`). An entity missing
/// from the map is read at `AccessLevel::None`: only what is shared.
#[derive(Debug, Clone, Default)]
pub struct Access {
    levels: HashMap<Uuid, AccessLevel>,
}

impl Access {
    pub fn new(levels: HashMap<Uuid, AccessLevel>) -> Self {
        Self { levels }
    }

    /// The same, with one entity at `level`.
    #[must_use]
    pub fn with(mut self, entity_id: Uuid, level: AccessLevel) -> Self {
        self.levels.insert(entity_id, level);
        self
    }

    fn level(&self, entity_id: Uuid) -> AccessLevel {
        self.levels
            .get(&entity_id)
            .copied()
            .unwrap_or(AccessLevel::None)
    }
}

/// What a spec compiles against.
pub struct Env<'a> {
    pub registry: &'a EntityMetaRegistry,
    pub relationships: &'a RelationshipRegistry,
    pub ctx: &'a SecurityContext,
    pub access: &'a Access,
    pub clock: Clock,
}

impl std::fmt::Debug for Env<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Env")
            .field("user_id", &self.ctx.user_id)
            .field("clock", &self.clock)
            .finish_non_exhaustive()
    }
}

/// The decoded cursor: the sort it was issued for, that row's sort values
/// (JSON as the row returned them) and its id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct CursorBody {
    #[serde(rename = "s")]
    sort: Vec<String>,
    #[serde(rename = "k")]
    keys: Vec<Value>,
    id: Uuid,
}

/// The cursor text that resumes after `row`, one of the rows `compiled`
/// returned. `CursorPage` seals it on the way out (Z14-T5); it comes back
/// sealed as the spec's `cursor`.
pub fn next_cursor(compiled: &Compiled, row: &serde_json::Map<String, Value>) -> Option<String> {
    let id = row
        .get("id")?
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())?;
    let keys = compiled.sort[..compiled.sort.len() - 1]
        .iter()
        .map(|key| {
            row.get(key.trim_start_matches('-'))
                .cloned()
                .unwrap_or(Value::Null)
        })
        .collect();
    let body = CursorBody {
        sort: compiled.sort.clone(),
        keys,
        id,
    };
    serde_json::to_string(&body).ok()
}

fn open_cursor(sealed: &str, sort: &[String]) -> Result<CursorBody, AppError> {
    let raw = attome_types::cursor::open(sealed)?;
    let body: CursorBody = serde_json::from_str(&raw).map_err(|_| AppError::InvalidCursor)?;
    // A cursor from another sort would resume at the wrong place.
    if body.sort != sort || body.keys.len() + 1 != sort.len() {
        return Err(AppError::InvalidCursor);
    }
    Ok(body)
}

/// A resolved field: its SQL expression and cast.
#[derive(Debug, Clone)]
pub(super) struct Col {
    pub(super) expr: String,
    pub(super) cast: &'static str,
    multi: bool,
    pub(super) sortable: bool,
    /// The scope's own owner column, the only one `mine` and `my_team` take.
    is_owner: bool,
}

/// Where conditions are resolved: the root (`t`, related paths allowed) or
/// the child of an `exists` (`e<n>`, its own fields only).
#[derive(Clone)]
pub(super) struct Scope<'a> {
    entity: &'a EntityMeta,
    alias: String,
    depth: usize,
}

impl<'a> Scope<'a> {
    /// The query's own entity, aliased `t`.
    pub(super) fn root(entity: &'a EntityMeta) -> Self {
        Self {
            entity,
            alias: "t".into(),
            depth: 0,
        }
    }
}

pub(super) struct Builder<'a> {
    env: &'a Env<'a>,
    binds: RefCell<Vec<BindValue>>,
    /// `(path prefix, alias, LEFT JOIN …)`, in the order made.
    joins: RefCell<Vec<(String, String, String)>>,
    subqueries: RefCell<usize>,
}

impl<'a> Builder<'a> {
    pub(super) fn new(env: &'a Env<'a>) -> Self {
        Self {
            env,
            binds: RefCell::new(Vec::new()),
            joins: RefCell::new(Vec::new()),
            subqueries: RefCell::new(0),
        }
    }

    pub(super) fn env(&self) -> &'a Env<'a> {
        self.env
    }

    /// The binds so far, in placeholder order.
    pub(super) fn into_binds(self) -> Vec<BindValue> {
        self.binds.into_inner()
    }

    /// ` LEFT JOIN …` for every related field resolved so far.
    pub(super) fn joins_sql(&self) -> String {
        self.joins
            .borrow()
            .iter()
            .map(|(_, _, join)| format!(" {join}"))
            .collect()
    }

    pub(super) fn bind(&self, value: impl Into<String>) -> usize {
        let mut binds = self.binds.borrow_mut();
        binds.push(value.into());
        binds.len()
    }

    /// The live-row and record-level predicates for `entity` aliased `alias`,
    /// each beginning with ` AND `.
    pub(super) fn row_predicates(&self, entity: &EntityMeta, alias: &str) -> String {
        self.row_predicates_in(
            entity,
            alias,
            live_row_predicate(alias, entity.is_append_only),
        )
    }

    /// [`Self::row_predicates`] over the soft-deleted rows (AA10-T3).
    pub(super) fn deleted_row_predicates(&self, entity: &EntityMeta, alias: &str) -> String {
        self.row_predicates_in(entity, alias, Some(format!("{alias}.is_active = false")))
    }

    fn row_predicates_in(&self, entity: &EntityMeta, alias: &str, rows: Option<String>) -> String {
        let mut sql = String::new();
        if let Some(rows) = rows {
            sql.push_str(" AND ");
            sql.push_str(&rows);
        }
        let ctx = self.env.ctx;
        let level = self.env.access.level(entity.entity_id);
        if ctx.is_admin || level == AccessLevel::Global {
            return sql;
        }
        let first = self.binds.borrow().len() + 1;
        if let Some(predicate) = attome_security::rls_predicate(
            ctx,
            entity.entity_id,
            alias,
            level,
            attome_security::RecordAction::Read.share_capability(),
            first,
        ) {
            sql.push(' ');
            sql.push_str(&predicate.sql);
            self.binds
                .borrow_mut()
                .extend(predicate.binds.to_text_params());
        }
        sql
    }

    fn readable_entity(&self, entity: &EntityMeta) -> bool {
        self.env.ctx.require(&entity.logicalname, "read").is_ok()
    }

    fn readable_attr(&self, entity: &'a EntityMeta, name: &str) -> Option<&'a AttrInfo> {
        let attr = entity.attrs.iter().find(|a| a.logicalname == name)?;
        field_gate::readable(
            self.env.ctx,
            &entity.logicalname,
            attr,
            entity.primary_name_attribute.as_deref(),
            Surface::Bulk,
        )
        .then_some(attr)
    }

    /// A field of `entity` itself, through the field gate (D-589: a query is
    /// a bulk surface). A field the gate refuses is reported as unknown, so
    /// its existence is not disclosed either.
    fn own_field(&self, entity: &'a EntityMeta, alias: &str, name: &str) -> Option<Col> {
        let expr = format!("{alias}.{}", quote_ident(name));
        if let Some(field_type) = system_column_type(name) {
            return Some(Col {
                expr,
                cast: parameter_cast(field_type.as_str())?,
                multi: false,
                sortable: name != "id",
                is_owner: name == "owner_ref",
            });
        }
        let attr = self.readable_attr(entity, name)?;
        Some(Col {
            expr,
            cast: cast_for_attr(attr).ok()?,
            multi: is_multi_choice_attr(attr),
            sortable: attr.is_sortable,
            is_owner: false,
        })
    }

    /// `name` in `scope`: an own field, or at the root a path through
    /// lookups, joining each target once.
    pub(super) fn resolve(&self, scope: &Scope<'a>, name: &str) -> Result<Col, AppError> {
        let unknown = || AppError::Validation(format!("unknown attribute: {name}"));
        let segments: Vec<&str> = name.split('.').collect();
        if segments.len() == 1 {
            return self
                .own_field(scope.entity, &scope.alias, name)
                .ok_or_else(unknown);
        }
        if scope.depth > 0 {
            return Err(AppError::Validation(format!(
                "related attributes are not supported inside exists: {name}"
            )));
        }
        if segments.len() - 1 > MAX_HOPS {
            return Err(AppError::Validation(format!("path too deep: {name}")));
        }
        let mut entity = scope.entity;
        let mut alias = scope.alias.clone();
        for (i, hop) in segments[..segments.len() - 1].iter().enumerate() {
            let attr = self.readable_attr(entity, hop).ok_or_else(unknown)?;
            if attr.field_type() != FieldType::Lookup {
                return Err(unknown());
            }
            // A lookup without one target (polymorphic, or created before
            // targets were stored, D-057) cannot be followed.
            let target_id = attr.lookup_entity_ref.ok_or_else(|| {
                AppError::Validation(format!("lookup has no single target: {hop}"))
            })?;
            let target = self
                .env
                .registry
                .get_by_id(target_id)
                .filter(|t| self.readable_entity(t))
                .ok_or_else(unknown)?;
            let prefix = segments[..=i].join(".");
            let existing = self
                .joins
                .borrow()
                .iter()
                .find(|(p, _, _)| *p == prefix)
                .map(|(_, a, _)| a.clone());
            alias = match existing {
                Some(a) => a,
                None => {
                    let next = format!("j{}", self.joins.borrow().len() + 1);
                    let join = format!(
                        "LEFT JOIN {} AS {next} ON {next}.id = {alias}.{}{}",
                        quote_ident(&target.logicalname),
                        quote_ident(hop),
                        self.row_predicates(target, &next),
                    );
                    self.joins.borrow_mut().push((prefix, next.clone(), join));
                    next
                }
            };
            entity = target;
        }
        let mut col = self
            .own_field(entity, &alias, segments[segments.len() - 1])
            .ok_or_else(unknown)?;
        col.is_owner = false;
        Ok(col)
    }

    pub(super) fn condition(
        &self,
        scope: &Scope<'a>,
        condition: &Condition,
        spec: &QuerySpec,
    ) -> Result<String, AppError> {
        Ok(match condition {
            Condition::And { all } if all.is_empty() => "TRUE".into(),
            Condition::Or { any } if any.is_empty() => "FALSE".into(),
            Condition::And { all } => self.join(scope, all, " AND ", spec)?,
            Condition::Or { any } => self.join(scope, any, " OR ", spec)?,
            Condition::Not { condition } => {
                format!("(NOT ({}))", self.condition(scope, condition, spec)?)
            }
            Condition::Compare { field, op, value } => {
                self.compare(scope, field, op, value.as_ref())?
            }
            Condition::Param { field, op, param } => {
                let value = spec.params.get(param).ok_or_else(|| {
                    AppError::Validation(format!("no value for parameter: {param}"))
                })?;
                self.compare(scope, field, op, Some(value))?
            }
            Condition::Exists { path, r#where } => {
                self.exists(scope, path, r#where.as_deref(), spec)?
            }
            Condition::NotExists { path, r#where } => {
                format!(
                    "(NOT {})",
                    self.exists(scope, path, r#where.as_deref(), spec)?
                )
            }
        })
    }

    fn join(
        &self,
        scope: &Scope<'a>,
        items: &[Condition],
        sep: &str,
        spec: &QuerySpec,
    ) -> Result<String, AppError> {
        let parts = items
            .iter()
            .map(|c| self.condition(scope, c, spec))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(format!("({})", parts.join(sep)))
    }

    /// `EXISTS (…)` over the child rows `path` names, correlated to
    /// `scope`'s row. A child entity the caller may not read is reported as
    /// an unknown relationship, the same as one that does not exist.
    fn exists(
        &self,
        scope: &Scope<'a>,
        path: &str,
        inner: Option<&Condition>,
        spec: &QuerySpec,
    ) -> Result<String, AppError> {
        if scope.depth >= MAX_EXISTS_DEPTH {
            return Err(AppError::Validation(format!(
                "exists nests deeper than {MAX_EXISTS_DEPTH}: {path}"
            )));
        }
        let unknown = || AppError::Validation(format!("unknown relationship: {path}"));
        let registry = self.env.registry;
        let n = {
            let mut count = self.subqueries.borrow_mut();
            *count += 1;
            *count
        };
        let child_alias = format!("e{n}");
        let outer = &scope.alias;
        let (child, from, correlate) = match path.split_once('.') {
            // Child rows whose lookup points at the outer row.
            Some((child_name, lookup)) => {
                let child = registry
                    .get(child_name)
                    .filter(|c| self.readable_entity(c))
                    .ok_or_else(unknown)?;
                let attr = self.readable_attr(child, lookup).ok_or_else(unknown)?;
                if attr.field_type() != FieldType::Lookup
                    || attr.lookup_entity_ref != Some(scope.entity.entity_id)
                {
                    return Err(unknown());
                }
                (
                    child,
                    format!("{} AS {child_alias}", quote_ident(&child.logicalname)),
                    format!("{child_alias}.{} = {outer}.id", quote_ident(lookup)),
                )
            }
            // A many-to-many relationship, through its join table.
            None => {
                let def = self
                    .env
                    .relationships
                    .get(path)
                    .filter(|d| d.is_active)
                    .ok_or_else(unknown)?;
                let side = def
                    .other_side(&scope.entity.logicalname)
                    .ok_or_else(unknown)?;
                let child = registry
                    .get(side.other_entity)
                    .filter(|c| self.readable_entity(c))
                    .ok_or_else(unknown)?;
                let link = format!("m{n}");
                (
                    child,
                    format!(
                        "{} AS {link} JOIN {} AS {child_alias} ON {child_alias}.id = {link}.{}",
                        quote_ident(&def.join_table),
                        quote_ident(&child.logicalname),
                        side.other_column,
                    ),
                    format!(
                        "{link}.{} = {outer}.id AND {link}.is_active = true",
                        side.this_column
                    ),
                )
            }
        };
        let predicates = self.row_predicates(child, &child_alias);
        let inner_scope = Scope {
            entity: child,
            alias: child_alias,
            depth: scope.depth + 1,
        };
        let filter = match inner {
            Some(c) => format!(" AND {}", self.condition(&inner_scope, c, spec)?),
            None => String::new(),
        };
        Ok(format!(
            "EXISTS (SELECT 1 FROM {from} WHERE {correlate}{predicates}{filter})"
        ))
    }

    /// One comparison: the QuerySpec operators first, then the stored
    /// filters' own through the shared filter compiler.
    fn compare(
        &self,
        scope: &Scope<'a>,
        field: &str,
        op: &str,
        value: Option<&Value>,
    ) -> Result<String, AppError> {
        let col = self.resolve(scope, field)?;
        let c = &col.expr;
        let cast = col.cast;
        if DATE_OPS.contains(&op) {
            if cast != "timestamptz" {
                return Err(AppError::Validation(format!(
                    "{op} is only valid for date fields: {field}"
                )));
            }
            let days = match value {
                None => None,
                Some(v) => Some(v.as_i64().ok_or_else(|| {
                    AppError::Validation(format!("{op} takes a whole number of days: {field}"))
                })?),
            };
            let clock = self.env.clock;
            let (start, end) = date_range(op, days, clock.now, clock.tz, clock.fiscal_start_month)?;
            let a = self.bind(start.to_rfc3339());
            let b = self.bind(end.to_rfc3339());
            return Ok(format!(
                "({c} >= ${a}::timestamptz AND {c} < ${b}::timestamptz)"
            ));
        }
        match op {
            "mine" | "my_team" if !col.is_owner => {
                return Err(AppError::Validation(format!(
                    "{op} is only valid for owner_ref: {field}"
                )));
            }
            "mine" => {
                let n = self.bind(self.env.ctx.user_id.to_string());
                return Ok(format!("{c} = ${n}::uuid"));
            }
            // Owned by one of the caller's teams or by one of their members.
            "my_team" => {
                let teams = format!(
                    "{{{}}}",
                    self.env
                        .ctx
                        .team_ids
                        .iter()
                        .map(Uuid::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                );
                let n = self.bind(teams);
                return Ok(format!(
                    "({c} = ANY(${n}::uuid[]) OR {c} IN (SELECT tm.user_ref FROM user_account_mm_team tm \
                     WHERE tm.team_ref = ANY(${n}::uuid[]) AND NOT tm.is_deleted))"
                ));
            }
            "between" => {
                let Some(pair) = value.and_then(Value::as_array).filter(|v| v.len() == 2) else {
                    return Err(AppError::Validation(format!(
                        "between takes two values: {field}"
                    )));
                };
                let low = self.bind(scalar_text(field, &pair[0])?);
                let high = self.bind(scalar_text(field, &pair[1])?);
                return Ok(format!(
                    "({c} >= ${low}::{cast} AND {c} <= ${high}::{cast})"
                ));
            }
            "text_matches" => {
                if cast != "text" || col.multi {
                    return Err(AppError::Validation(format!(
                        "text_matches is only valid for text fields: {field}"
                    )));
                }
                let text = value.and_then(Value::as_str).ok_or_else(|| {
                    AppError::Validation(format!("text_matches takes text: {field}"))
                })?;
                // The value is matched literally: LIKE's own wildcards are escaped.
                let escaped = text
                    .replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_");
                let n = self.bind(escaped);
                return Ok(format!(
                    "normalize_ar({c}) LIKE '%' || normalize_ar(${n}) || '%'"
                ));
            }
            _ => {}
        }
        let (op, negate) = match op {
            "not_in" => ("in", true),
            other => (other, false),
        };
        let filter = Filter {
            field: field.to_owned(),
            op: op.to_owned(),
            value: value.map(|v| as_filter_value(field, v)).transpose()?,
        };
        let schema = OneField {
            name: field,
            cast,
            multi: col.multi,
        };
        let first = self.binds.borrow().len() + 1;
        let (sql, new) = attome_core::compile_filter(&filter, &schema, first)?;
        // The filter compiler names the column bare; put the scope's alias on.
        let Some(rest) = sql.strip_prefix(&quote_ident(field)) else {
            return Err(AppError::Validation(format!(
                "operator {op} is not available here: {field}"
            )));
        };
        self.binds.borrow_mut().extend(new);
        let sql = format!("{c}{rest}");
        Ok(if negate {
            format!("(NOT ({sql}))")
        } else {
            sql
        })
    }
}

/// The filter compiler's view of the one field being compared.
struct OneField<'f> {
    name: &'f str,
    cast: &'static str,
    multi: bool,
}

impl FilterSchema for OneField<'_> {
    fn cast(&self, field: &str) -> Result<&'static str, FieldCastError> {
        if field == self.name {
            Ok(self.cast)
        } else {
            Err(FieldCastError::Unknown)
        }
    }

    fn is_multi_choice(&self, field: &str) -> bool {
        field == self.name && self.multi
    }
}

fn scalar_text(field: &str, v: &Value) -> Result<String, AppError> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        _ => Err(AppError::Validation(format!(
            "value must be a string, number or boolean for field: {field}"
        ))),
    }
}

/// The filter compiler takes text (and arrays of text); a QuerySpec value
/// may be a number or a boolean too.
fn as_filter_value(field: &str, value: &Value) -> Result<Value, AppError> {
    Ok(match value {
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| scalar_text(field, v).map(Value::String))
                .collect::<Result<_, _>>()?,
        ),
        other => Value::String(scalar_text(field, other)?),
    })
}

/// A sort key, resolved.
struct SortCol {
    name: String,
    col: Col,
    desc: bool,
}

/// Compiles `spec` for `env.ctx`. An entity the caller may not read is
/// `NotFound`, the same answer as one that does not exist.
pub fn compile(spec: &QuerySpec, env: &Env<'_>) -> Result<Compiled, AppError> {
    let root = env
        .registry
        .get(&spec.entity)
        .filter(|e| env.ctx.require(&e.logicalname, "read").is_ok())
        .ok_or(AppError::NotFound)?;
    if !spec.group_by.is_empty() || !spec.aggregates.is_empty() || spec.having.is_some() {
        return Err(AppError::Validation(
            "aggregates and grouping are not supported yet".into(),
        ));
    }
    let page_size = match spec.page_size {
        None => DEFAULT_PAGE_SIZE,
        Some(n) if (1..=MAX_PAGE_SIZE).contains(&n) => n,
        Some(_) => {
            return Err(AppError::Validation(format!(
                "page_size must be between 1 and {MAX_PAGE_SIZE}"
            )));
        }
    };
    let b = Builder::new(env);
    let scope = Scope::root(root);

    let mut sort: Vec<SortCol> = Vec::new();
    for key in &spec.sort {
        let col = b.resolve(&scope, &key.field)?;
        if !col.sortable {
            return Err(AppError::Validation(format!(
                "attribute is not sortable: {}",
                key.field
            )));
        }
        if !sort.iter().any(|s| s.name == key.field) {
            sort.push(SortCol {
                name: key.field.clone(),
                col,
                desc: key.desc,
            });
        }
    }
    let id_desc = sort.last().is_some_and(|s| s.desc);

    // The id first, then the selected fields, then any sort field not
    // selected (the cursor reads it from the row).
    let mut columns: Vec<(String, String)> = vec![("id".into(), "t.\"id\"".into())];
    let mut add = |name: &str, expr: &str| {
        if !columns.iter().any(|(n, _)| n == name) {
            columns.push((name.to_owned(), expr.to_owned()));
        }
    };
    for name in &spec.select {
        let col = b.resolve(&scope, name)?;
        add(name, &col.expr);
    }
    if spec.select.is_empty()
        && let Some(primary) = root.primary_name_attribute.as_deref()
        && let Ok(col) = b.resolve(&scope, primary)
    {
        add(primary, &col.expr);
    }
    for s in &sort {
        add(&s.name, &s.col.expr);
    }

    let mut conds: Vec<String> = Vec::new();
    if let Some(condition) = &spec.r#where {
        conds.push(b.condition(&scope, condition, spec)?);
    }
    let mut sort_names: Vec<String> = sort
        .iter()
        .map(|s| {
            if s.desc {
                format!("-{}", s.name)
            } else {
                s.name.clone()
            }
        })
        .collect();
    sort_names.push(if id_desc { "-id".into() } else { "id".into() });
    if let Some(cursor) = &spec.cursor {
        let body = open_cursor(cursor, &sort_names)?;
        conds.push(cursor_condition(&b, &sort, id_desc, &body)?);
    }
    // The root's own predicates last, numbered after every other bind.
    let root_predicates = b.row_predicates(root, "t");

    let mut sql = format!(
        "SELECT {} FROM {} AS t",
        columns
            .iter()
            .map(|(name, expr)| format!("{expr} AS {}", quote_ident(name)))
            .collect::<Vec<_>>()
            .join(", "),
        quote_ident(&root.logicalname),
    );
    sql.push_str(&b.joins_sql());
    sql.push_str(" WHERE TRUE");
    for cond in &conds {
        sql.push_str(" AND ");
        sql.push_str(cond);
    }
    sql.push_str(&root_predicates);
    let mut order: Vec<String> = sort
        .iter()
        .map(|s| format!("{} {}", s.col.expr, if s.desc { "DESC" } else { "ASC" }))
        .collect();
    order.push(format!("t.\"id\" {}", if id_desc { "DESC" } else { "ASC" }));
    sql.push_str(&format!(
        " ORDER BY {} LIMIT {}",
        order.join(", "),
        page_size + 1
    ));

    Ok(Compiled {
        sql,
        binds: b.into_binds(),
        columns: columns.into_iter().map(|(n, _)| n).collect(),
        sort: sort_names,
        page_size,
    })
}

/// AA10-T2: the ids of the rows `spec.where` selects that the caller may
/// reach, as `SELECT t."id" FROM ... WHERE ...` with no order and no limit
/// (the caller bounds it), compiled exactly as [`compile`] compiles the
/// filter and the row predicates. `select`, `sort`, `cursor` and the page
/// are ignored.
pub fn compile_scope(
    spec: &QuerySpec,
    env: &Env<'_>,
) -> Result<(String, Vec<BindValue>), AppError> {
    compile_scope_rows(spec, env, false)
}

/// AA10-T3: [`compile_scope`] over the soft-deleted rows instead of the live
/// ones when `deleted` (what a mass restore selects). An append-only entity
/// has no deleted rows and is refused.
pub fn compile_scope_rows(
    spec: &QuerySpec,
    env: &Env<'_>,
    deleted: bool,
) -> Result<(String, Vec<BindValue>), AppError> {
    let root = env
        .registry
        .get(&spec.entity)
        .filter(|e| env.ctx.require(&e.logicalname, "read").is_ok())
        .ok_or(AppError::NotFound)?;
    let b = Builder::new(env);
    let scope = Scope::root(root);
    let mut conds: Vec<String> = Vec::new();
    if let Some(condition) = &spec.r#where {
        conds.push(b.condition(&scope, condition, spec)?);
    }
    let root_predicates = if deleted {
        if root.is_append_only {
            return Err(AppError::Validation(
                "an append-only entity has no deleted records".into(),
            ));
        }
        b.deleted_row_predicates(root, "t")
    } else {
        b.row_predicates(root, "t")
    };
    let mut sql = format!(
        "SELECT t.\"id\" FROM {} AS t",
        quote_ident(&root.logicalname)
    );
    sql.push_str(&b.joins_sql());
    sql.push_str(" WHERE TRUE");
    for cond in &conds {
        sql.push_str(" AND ");
        sql.push_str(cond);
    }
    sql.push_str(&root_predicates);
    Ok((sql, b.into_binds()))
}

/// Rows after the cursor row in sort order. Key by key: a row is after it
/// when every earlier key is equal and this key is past it.
fn cursor_condition(
    b: &Builder<'_>,
    sort: &[SortCol],
    id_desc: bool,
    body: &CursorBody,
) -> Result<String, AppError> {
    let id_param = b.bind(body.id.to_string());
    let id_after = format!(
        "t.\"id\" {} ${id_param}::uuid",
        if id_desc { "<" } else { ">" }
    );
    if sort.is_empty() {
        return Ok(id_after);
    }
    let mut equal_so_far: Vec<String> = Vec::new();
    let mut branches: Vec<String> = Vec::new();
    for (s, value) in sort.iter().zip(&body.keys) {
        let column = &s.col.expr;
        let cast = s.col.cast;
        let (after, equal) = if value.is_null() {
            // NULLs sort last ascending and first descending.
            if s.desc {
                (format!("{column} IS NOT NULL"), format!("{column} IS NULL"))
            } else {
                ("FALSE".to_owned(), format!("{column} IS NULL"))
            }
        } else {
            let text = match value {
                Value::String(v) => v.clone(),
                Value::Number(_) | Value::Bool(_) => value.to_string(),
                _ => return Err(AppError::InvalidCursor),
            };
            let n = b.bind(text);
            if s.desc {
                (
                    format!("{column} < ${n}::{cast}"),
                    format!("{column} = ${n}::{cast}"),
                )
            } else {
                (
                    format!("({column} > ${n}::{cast} OR {column} IS NULL)"),
                    format!("{column} = ${n}::{cast}"),
                )
            }
        };
        let mut branch = equal_so_far.clone();
        branch.push(after);
        branches.push(format!("({})", branch.join(" AND ")));
        equal_so_far.push(equal);
    }
    equal_so_far.push(id_after);
    branches.push(format!("({})", equal_so_far.join(" AND ")));
    Ok(format!("({})", branches.join(" OR ")))
}

#[cfg(test)]
pub(super) mod fixtures {
    use std::collections::{HashMap, HashSet};

    use attome_core::{RelationshipCascade, RelationshipDef};
    use attome_server::security::BulkFields;

    use super::*;

    pub fn attr(name: &str, field_type: FieldType, sensitive: bool) -> AttrInfo {
        AttrInfo {
            logicalname: name.into(),
            field_type_int: field_type.to_int(),
            is_required: false,
            max_length: None,
            is_sensitive: sensitive,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            sensitivity: Default::default(),
            options: None,
        }
    }

    pub fn lookup(name: &str, target: u128) -> AttrInfo {
        AttrInfo {
            lookup_entity_ref: Some(Uuid::from_u128(target)),
            ..attr(name, FieldType::Lookup, false)
        }
    }

    pub fn entity(id: u128, name: &str, attrs: Vec<AttrInfo>) -> EntityMeta {
        EntityMeta {
            entity_id: Uuid::from_u128(id),
            logicalname: name.into(),
            attrs,
            is_append_only: false,
            primary_name_attribute: Some("name".into()),
        }
    }

    /// account (1) with a parent account and a primary contact (2), whose
    /// team is a team (3); an incident (4) points at an account and a
    /// contact; accounts and contacts are also linked many-to-many.
    pub fn registry() -> EntityMetaRegistry {
        EntityMetaRegistry::from_entities(vec![
            entity(
                1,
                "account",
                vec![
                    attr("name", FieldType::Text, false),
                    attr("revenue", FieldType::Number, false),
                    attr("tax_id", FieldType::Text, true),
                    attr("created_on", FieldType::Date, false),
                    lookup("parent", 1),
                    lookup("primary_contact", 2),
                    attr("loose_ref", FieldType::Lookup, false),
                ],
            ),
            entity(
                2,
                "contact",
                vec![
                    attr("name", FieldType::Text, false),
                    attr("ssn", FieldType::Text, true),
                    lookup("team", 3),
                    lookup("account", 1),
                ],
            ),
            entity(3, "team", vec![attr("name", FieldType::Text, false)]),
            entity(
                4,
                "incident",
                vec![
                    attr("title", FieldType::Text, false),
                    attr("statecode", FieldType::Number, false),
                    lookup("customer", 1),
                    lookup("contact", 2),
                ],
            ),
        ])
    }

    pub fn relationships() -> RelationshipRegistry {
        RelationshipRegistry::from_entries(vec![RelationshipDef {
            id: Uuid::from_u128(90),
            name: "account_contacts".into(),
            entity_a: "account".into(),
            entity_b: "contact".into(),
            role_a: "Accounts".into(),
            role_b: "Contacts".into(),
            join_table: "account_mm_contact".into(),
            cascade: RelationshipCascade::Orphan,
            is_customized: false,
            is_active: true,
            row_version: 1,
        }])
    }

    pub fn reader() -> SecurityContext {
        SecurityContext {
            user_id: Uuid::from_u128(7),
            is_admin: false,
            privileges: ["account.read", "contact.read", "team.read", "incident.read"]
                .into_iter()
                .map(str::to_owned)
                .collect::<HashSet<_>>(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            bulk_fields: BulkFields::Legacy,
            epoch: 0,
            accessible_org_ids: vec![Uuid::from_u128(8)],
            team_ids: vec![Uuid::from_u128(9)],
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            service_principal: false,
        }
    }

    pub fn global() -> Access {
        Access::new(
            (1..=4)
                .map(|i| (Uuid::from_u128(i), AccessLevel::Global))
                .collect(),
        )
    }

    pub fn clock() -> Clock {
        Clock {
            now: "2026-10-24T12:00:00Z".parse().unwrap(),
            tz: chrono_tz::Tz::UTC,
            fiscal_start_month: 1,
        }
    }

    pub fn run(doc: Value, ctx: &SecurityContext, access: &Access) -> Result<Compiled, AppError> {
        let registry = registry();
        let relationships = relationships();
        let env = Env {
            registry: &registry,
            relationships: &relationships,
            ctx,
            access,
            clock: clock(),
        };
        let spec: QuerySpec = serde_json::from_value(doc).expect("spec");
        compile(&spec, &env)
    }

    /// The record-level fragment `rls_predicate` makes for a team reader of
    /// `entity` aliased `alias`, numbered from `first`.
    pub fn team_rls(entity: u128, alias: &str, first: usize) -> String {
        attome_security::rls_predicate(
            &reader(),
            Uuid::from_u128(entity),
            alias,
            AccessLevel::Team,
            attome_security::RecordAction::Read.share_capability(),
            first,
        )
        .expect("a team reader is narrowed")
        .sql
    }

    pub fn validation(result: Result<Compiled, AppError>) -> String {
        match result {
            Err(AppError::Validation(m)) => m,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::fixtures::*;
    use super::*;

    #[test]
    fn compiles_select_and_eq_with_rls() {
        let doc = json!({
            "entity": "account",
            "select": ["name"],
            "where": {"kind": "compare", "field": "name", "op": "eq", "value": "Acme"}
        });
        let open = run(doc.clone(), &reader(), &global()).unwrap();
        assert_eq!(
            open.sql,
            "SELECT t.\"id\" AS \"id\", t.\"name\" AS \"name\" FROM \"account\" AS t \
             WHERE TRUE AND t.\"name\" = $1::text AND (t.is_active IS NULL OR t.is_active = true) \
             ORDER BY t.\"id\" ASC LIMIT 51"
        );
        assert_eq!(open.binds, vec!["Acme".to_owned()]);

        let team = global().with(Uuid::from_u128(1), AccessLevel::Team);
        let c = run(doc, &reader(), &team).unwrap();
        assert!(c.sql.contains(&team_rls(1, "t", 2)), "{}", c.sql);
        assert_eq!(c.binds.len(), 7);
        assert!(c.sql.ends_with("ORDER BY t.\"id\" ASC LIMIT 51"));
    }

    #[test]
    fn nested_and_or_not_parenthesised() {
        let c = run(
            json!({
                "entity": "account",
                "where": {"kind": "and", "all": [
                    {"kind": "or", "any": [
                        {"kind": "compare", "field": "name", "op": "starts_with", "value": "A"},
                        {"kind": "compare", "field": "revenue", "op": "gt", "value": 1000}
                    ]},
                    {"kind": "not", "condition":
                        {"kind": "compare", "field": "revenue", "op": "is_null"}},
                    {"kind": "or", "any": []},
                    {"kind": "and", "all": []}
                ]}
            }),
            &reader(),
            &global(),
        )
        .unwrap();
        assert!(
            c.sql.contains(
                "((t.\"name\" ILIKE $1 OR t.\"revenue\" > $2::numeric) \
                 AND (NOT (t.\"revenue\" IS NULL)) AND FALSE AND TRUE)"
            ),
            "{}",
            c.sql
        );
        assert_eq!(c.binds, vec!["A%".to_owned(), "1000".to_owned()]);
        // The primary name is selected when the spec selects nothing.
        assert!(
            c.sql
                .starts_with("SELECT t.\"id\" AS \"id\", t.\"name\" AS \"name\" FROM")
        );
    }

    #[test]
    fn unreadable_attribute_is_unknown() {
        let unknown = "unknown attribute: tax_id";
        assert_eq!(
            validation(run(
                json!({"entity": "account", "select": ["tax_id"]}),
                &reader(),
                &global()
            )),
            unknown
        );
        assert_eq!(
            validation(run(
                json!({"entity": "account",
                       "where": {"kind": "compare", "field": "tax_id", "op": "eq", "value": "1"}}),
                &reader(),
                &global()
            )),
            unknown
        );
        let mut granted = reader();
        granted.field_grants.insert("account.tax_id".into());
        assert!(
            run(
                json!({"entity": "account", "select": ["tax_id"]}),
                &granted,
                &global()
            )
            .is_ok()
        );

        // An entity the caller may not read is not found, like a missing one.
        let mut stranger = reader();
        stranger.privileges.clear();
        for doc in [json!({"entity": "account"}), json!({"entity": "nothing"})] {
            assert!(matches!(
                run(doc, &stranger, &global()),
                Err(AppError::NotFound)
            ));
        }
    }

    #[test]
    fn cursor_uses_row_value_comparison() {
        // Sorted by the id alone, the cursor is one comparison on the id.
        let first = json!({"entity": "account", "page_size": 2});
        let c = run(first.clone(), &reader(), &global()).unwrap();
        let row = json!({"id": Uuid::from_u128(42).to_string(), "name": "Acme"});
        let cursor =
            attome_types::cursor::seal(&next_cursor(&c, row.as_object().unwrap()).unwrap());
        let mut next = first.clone();
        next["cursor"] = json!(cursor);
        let c = run(next, &reader(), &global()).unwrap();
        assert!(c.sql.contains("AND t.\"id\" > $1::uuid AND"), "{}", c.sql);
        assert_eq!(c.binds, vec![Uuid::from_u128(42).to_string()]);
        assert!(c.sql.ends_with("LIMIT 3"));

        // Mixed directions resume key by key; a NULL value keeps its place.
        // A sort field not selected is still returned, for the cursor.
        let sorted = json!({"entity": "account", "select": ["name"], "page_size": 2,
            "sort": [{"field": "revenue", "desc": true}, {"field": "name"}]});
        let c = run(sorted.clone(), &reader(), &global()).unwrap();
        assert_eq!(c.sort, vec!["-revenue", "name", "id"]);
        assert_eq!(c.columns, vec!["id", "name", "revenue"]);
        let row = json!({"id": Uuid::from_u128(5).to_string(), "revenue": 10, "name": null});
        let cursor =
            attome_types::cursor::seal(&next_cursor(&c, row.as_object().unwrap()).unwrap());
        let mut next = sorted.clone();
        next["cursor"] = json!(cursor.clone());
        let c = run(next, &reader(), &global()).unwrap();
        assert!(
            c.sql.contains(
                "((t.\"revenue\" < $2::numeric) \
                 OR (t.\"revenue\" = $2::numeric AND FALSE) \
                 OR (t.\"revenue\" = $2::numeric AND t.\"name\" IS NULL AND t.\"id\" > $1::uuid))"
            ),
            "{}",
            c.sql
        );
        assert_eq!(
            c.binds,
            vec![Uuid::from_u128(5).to_string(), "10".to_owned()]
        );

        // A cursor issued for another sort, or not issued at all, is refused.
        for bad in [json!(cursor), json!("forged")] {
            let mut doc = first.clone();
            doc["cursor"] = bad;
            assert!(matches!(
                run(doc, &reader(), &global()),
                Err(AppError::InvalidCursor)
            ));
        }
    }

    #[test]
    fn values_are_bound_not_inlined() {
        let hostile = "x'; DROP TABLE account; --";
        let c = run(
            json!({
                "entity": "account",
                "where": {"kind": "or", "any": [
                    {"kind": "compare", "field": "name", "op": "eq", "value": hostile},
                    {"kind": "compare", "field": "name", "op": "in", "value": [hostile, "b"]},
                    {"kind": "param", "field": "name", "op": "contains", "param": "p"},
                    {"kind": "compare", "field": "name", "op": "text_matches", "value": hostile}
                ]},
                "params": {"p": hostile}
            }),
            &reader(),
            &global(),
        )
        .unwrap();
        assert!(!c.sql.contains("DROP"), "{}", c.sql);
        assert_eq!(c.binds.len(), 4);
        assert_eq!(c.binds[0], hostile);

        // A missing parameter, an unknown operator, a page past the cap and
        // aggregates (S4-T6) are refused.
        for doc in [
            json!({"entity": "account",
                   "where": {"kind": "param", "field": "name", "op": "eq", "param": "nope"}}),
            json!({"entity": "account",
                   "where": {"kind": "compare", "field": "name", "op": "like", "value": "a"}}),
            json!({"entity": "account", "page_size": 201}),
            json!({"entity": "account", "aggregates": [{"func": "count", "alias": "n"}]}),
        ] {
            validation(run(doc, &reader(), &global()));
        }
    }

    #[test]
    fn operators_compile_to_bound_ranges() {
        let c = run(
            json!({"entity": "account", "where": {"kind": "and", "all": [
                {"kind": "compare", "field": "created_on", "op": "this_month"},
                {"kind": "compare", "field": "revenue", "op": "between", "value": [10, 20]},
                {"kind": "compare", "field": "name", "op": "not_in", "value": ["a", "b"]},
                {"kind": "compare", "field": "owner_ref", "op": "my_team"}
            ]}}),
            &reader(),
            &global(),
        )
        .unwrap();
        assert!(
            c.sql.contains(
                "(t.\"created_on\" >= $1::timestamptz AND t.\"created_on\" < $2::timestamptz)"
            ),
            "{}",
            c.sql
        );
        assert!(
            c.sql
                .contains("(t.\"revenue\" >= $3::numeric AND t.\"revenue\" <= $4::numeric)")
        );
        assert!(c.sql.contains("(NOT (t.\"name\" = ANY($5::text[])))"));
        assert!(c.sql.contains(
            "(t.\"owner_ref\" = ANY($6::uuid[]) OR t.\"owner_ref\" IN (SELECT tm.user_ref FROM user_account_mm_team tm \
             WHERE tm.team_ref = ANY($6::uuid[]) AND NOT tm.is_deleted))"
        ), "{}", c.sql);
        assert_eq!(c.binds[0], "2026-10-01T00:00:00+00:00");
        assert_eq!(c.binds[1], "2026-11-01T00:00:00+00:00");
        assert_eq!(c.binds[5], format!("{{{}}}", Uuid::from_u128(9)));
        assert!(!c.sql.contains("now()"));

        // Date operators need a date, ownership operators the owner.
        validation(run(
            json!({"entity": "account", "where": {"kind": "compare", "field": "name", "op": "today"}}),
            &reader(),
            &global(),
        ));
        validation(run(
            json!({"entity": "account", "where": {"kind": "compare", "field": "created_by", "op": "mine"}}),
            &reader(),
            &global(),
        ));
    }

    #[test]
    fn mine_binds_caller_id() {
        let c = run(
            json!({"entity": "account", "where": {"kind": "compare", "field": "owner_ref", "op": "mine"}}),
            &reader(),
            &global(),
        )
        .unwrap();
        assert!(c.sql.contains("t.\"owner_ref\" = $1::uuid"), "{}", c.sql);
        assert_eq!(c.binds, vec![Uuid::from_u128(7).to_string()]);
    }

    #[test]
    fn text_matches_uses_normalize_ar() {
        let c = run(
            json!({"entity": "account", "where": {"kind": "compare", "field": "name",
                   "op": "text_matches", "value": "أحمد_50%"}}),
            &reader(),
            &global(),
        )
        .unwrap();
        assert!(
            c.sql
                .contains("normalize_ar(t.\"name\") LIKE '%' || normalize_ar($1) || '%'"),
            "{}",
            c.sql
        );
        assert_eq!(c.binds, vec!["أحمد\\_50\\%".to_owned()]);
        validation(run(
            json!({"entity": "account", "where": {"kind": "compare", "field": "revenue",
                   "op": "text_matches", "value": "1"}}),
            &reader(),
            &global(),
        ));
    }
}

#[cfg(test)]
mod related {
    use serde_json::json;

    use super::fixtures::*;
    use super::*;

    #[test]
    fn related_attribute_adds_one_join_per_prefix() {
        let c = run(
            json!({
                "entity": "account",
                "select": ["primary_contact.name", "primary_contact.team.name"],
                "where": {"kind": "compare", "field": "primary_contact.name", "op": "eq", "value": "Sara"},
                "sort": [{"field": "primary_contact.team.name"}]
            }),
            &reader(),
            &global(),
        )
        .unwrap();
        assert_eq!(c.sql.matches("LEFT JOIN").count(), 2, "{}", c.sql);
        assert!(
            c.sql.contains(
                "LEFT JOIN \"contact\" AS j1 ON j1.id = t.\"primary_contact\" \
                 AND (j1.is_active IS NULL OR j1.is_active = true) \
                 LEFT JOIN \"team\" AS j2 ON j2.id = j1.\"team\" \
                 AND (j2.is_active IS NULL OR j2.is_active = true)"
            ),
            "{}",
            c.sql
        );
        assert!(c.sql.contains("j1.\"name\" AS \"primary_contact.name\""));
        assert!(
            c.sql
                .contains("j2.\"name\" AS \"primary_contact.team.name\"")
        );
        assert!(c.sql.contains("j1.\"name\" = $1::text"));
        assert!(c.sql.contains("ORDER BY j2.\"name\" ASC, t.\"id\" ASC"));
        assert!(!c.sql.contains("INNER JOIN"));
        assert_eq!(
            c.columns,
            vec!["id", "primary_contact.name", "primary_contact.team.name"]
        );
    }

    #[test]
    fn related_join_carries_target_rls() {
        let team = global().with(Uuid::from_u128(2), AccessLevel::Team);
        let c = run(
            json!({"entity": "account", "select": ["primary_contact.name"]}),
            &reader(),
            &team,
        )
        .unwrap();
        // The contact's predicate sits in its join's ON clause, numbered first.
        let on = format!(
            "LEFT JOIN \"contact\" AS j1 ON j1.id = t.\"primary_contact\" \
             AND (j1.is_active IS NULL OR j1.is_active = true) {}",
            team_rls(2, "j1", 1)
        );
        assert!(c.sql.contains(&on), "{}", c.sql);
        assert_eq!(c.binds.len(), 6);
    }

    #[test]
    fn four_hops_is_rejected() {
        let m = validation(run(
            json!({"entity": "account", "select": ["parent.parent.parent.parent.name"]}),
            &reader(),
            &global(),
        ));
        assert!(m.starts_with("path too deep"), "{m}");
        assert!(
            run(
                json!({"entity": "account", "select": ["parent.parent.parent.name"]}),
                &reader(),
                &global()
            )
            .is_ok()
        );
        // A lookup with no single target is refused and named.
        assert_eq!(
            validation(run(
                json!({"entity": "account", "select": ["loose_ref.name"]}),
                &reader(),
                &global()
            )),
            "lookup has no single target: loose_ref"
        );
    }

    #[test]
    fn unreadable_target_is_unknown_attribute() {
        let mut no_teams = reader();
        no_teams.privileges.remove("team.read");
        let check = |field: &str, ctx: &SecurityContext| {
            let doc = json!({"entity": "account", "select": [field]});
            assert_eq!(
                validation(run(doc, ctx, &global())),
                format!("unknown attribute: {field}")
            );
        };
        check("primary_contact.team.name", &no_teams);
        // A sensitive field at the end of the path needs its grant.
        check("primary_contact.ssn", &reader());
        // A field that is not a lookup cannot be followed.
        check("name.name", &reader());
    }
}

#[cfg(test)]
mod exists {
    use serde_json::json;

    use super::fixtures::*;
    use super::*;

    #[test]
    fn exists_child_compiles_semi_join_with_rls() {
        let access = global().with(Uuid::from_u128(4), AccessLevel::Team);
        let c = run(
            json!({"entity": "account", "where": {"kind": "exists", "path": "incident.customer",
                   "where": {"kind": "compare", "field": "statecode", "op": "eq", "value": 0}}}),
            &reader(),
            &access,
        )
        .unwrap();
        let expected = format!(
            "EXISTS (SELECT 1 FROM \"incident\" AS e1 WHERE e1.\"customer\" = t.id \
             AND (e1.is_active IS NULL OR e1.is_active = true) {} AND e1.\"statecode\" = $7::numeric)",
            team_rls(4, "e1", 1)
        );
        assert!(c.sql.contains(&expected), "{}", c.sql);
        assert_eq!(c.binds.len(), 7);
        assert_eq!(c.binds[6], "0");
    }

    #[test]
    fn not_exists_wraps_not() {
        let c = run(
            json!({"entity": "account", "where": {"kind": "not_exists", "path": "incident.customer"}}),
            &reader(),
            &global(),
        )
        .unwrap();
        assert!(
            c.sql.contains(
                "AND (NOT EXISTS (SELECT 1 FROM \"incident\" AS e1 WHERE e1.\"customer\" = t.id \
                 AND (e1.is_active IS NULL OR e1.is_active = true)))"
            ),
            "{}",
            c.sql
        );
    }

    #[test]
    fn many_to_many_exists_uses_intersect_table() {
        let c = run(
            json!({"entity": "account", "where": {"kind": "exists", "path": "account_contacts",
                   "where": {"kind": "compare", "field": "name", "op": "eq", "value": "Sara"}}}),
            &reader(),
            &global(),
        )
        .unwrap();
        assert!(
            c.sql.contains(
                "EXISTS (SELECT 1 FROM \"account_mm_contact\" AS m1 JOIN \"contact\" AS e1 ON e1.id = m1.b_id \
                 WHERE m1.a_id = t.id AND m1.is_active = true \
                 AND (e1.is_active IS NULL OR e1.is_active = true) AND e1.\"name\" = $1::text)"
            ),
            "{}",
            c.sql
        );

        // Hidden means absent: an unreadable child is an unknown relationship.
        let mut no_contacts = reader();
        no_contacts.privileges.remove("contact.read");
        for path in ["account_contacts", "contact.account", "nothing"] {
            let doc = json!({"entity": "account", "where": {"kind": "exists", "path": path}});
            assert_eq!(
                validation(run(doc, &no_contacts, &global())),
                format!("unknown relationship: {path}")
            );
        }
    }

    #[test]
    fn nesting_deeper_than_three_is_rejected() {
        // Accounts whose child account has a child account, and so on.
        let nest = |depth: usize| {
            let mut node = json!({"kind": "exists", "path": "account.parent"});
            for _ in 1..depth {
                node = json!({"kind": "exists", "path": "account.parent", "where": node});
            }
            json!({"entity": "account", "where": node})
        };
        let c = run(nest(3), &reader(), &global()).unwrap();
        assert_eq!(c.sql.matches("EXISTS (").count(), 3);
        assert!(c.sql.contains("e2.\"parent\" = e1.id"), "{}", c.sql);
        let m = validation(run(nest(4), &reader(), &global()));
        assert!(m.starts_with("exists nests deeper than 3"), "{m}");
    }
}
