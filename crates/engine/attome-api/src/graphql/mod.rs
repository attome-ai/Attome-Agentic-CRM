//! S6-T1: a GraphQL read API whose schema is built from the metadata at
//! request time, for the caller.
//!
//! - `POST /api/v1/graphql` takes `{query, variables}` and answers
//!   `{data}` or `{data: null, errors: [{message}]}`. For each entity the
//!   caller may read there are two root fields: `<entity>(id: ID!)` and
//!   `<entity>_list(where, sort, first, after)` answering `{items,
//!   next_cursor}`. `where` is `{field: {op: value}}` with the record list's
//!   operators; `sort` is `"field"` or `"-field"`; `first` is 1 to 100
//!   (20 when absent); `after` is a previous answer's `next_cursor`.
//! - A record's fields are the caller's readable attributes and the system
//!   columns; a lookup with a selection resolves to the related record (one
//!   batched read per lookup and level, never one per row), without one to
//!   its id.
//! - `GET /api/v1/graphql/schema` answers the caller's schema as SDL.
//!
//! Every read runs through the query engine on the interactive surface
//! (`execute_spec_on`), so record-level security, field security and masks
//! apply exactly as on `GET /api/v1/{entity}`; each entity needs its read
//! privilege. Limits: at most [`MAX_ROOT_FIELDS`] root fields, [`MAX_DEPTH`]
//! levels, and an estimated [`MAX_COST`] records per query, checked before
//! anything runs. Built in `attome-api` rather than a crate of its own: it
//! needs no new dependency, and it is a transport over the record engine.

pub mod parse;

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;

use attome_core::{EngineState, FieldType};
use attome_records::query_spec::routes::execute_spec_on;
use attome_records::query_spec::{Condition, QuerySpec, RunResponse, SortKey};
use attome_security::SecurityContextExt;
use attome_security::field_gate::{self, Surface};
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;

use parse::Field;

/// Most root fields in one query.
pub const MAX_ROOT_FIELDS: usize = 10;
/// Deepest nesting (a root field alone is 1).
pub const MAX_DEPTH: usize = 6;
/// Most records one query may read, by the estimate in [`cost`].
pub const MAX_COST: u64 = 10_000;
/// A list's page when `first` is absent, and its most.
pub const DEFAULT_FIRST: i64 = 20;
pub const MAX_FIRST: i64 = 100;
/// Most ids one batched lookup read takes.
const LOOKUP_BATCH: usize = 200;

/// The estimated records a query reads: a list field reads `first` records,
/// each record reads one more per nested selection under it. Pure.
pub fn cost(fields: &[Field]) -> u64 {
    fn per_record(sel: &[Field]) -> u64 {
        1 + sel
            .iter()
            .filter(|f| !f.selection.is_empty())
            .map(|f| per_record(&f.selection))
            .sum::<u64>()
    }
    fields
        .iter()
        .map(|f| {
            if f.name.ends_with("_list") {
                let first = first_of(f).unwrap_or(DEFAULT_FIRST).clamp(1, MAX_FIRST) as u64;
                let items: Vec<Field> = f
                    .selection
                    .iter()
                    .filter(|s| s.name == "items")
                    .flat_map(|s| s.selection.clone())
                    .collect();
                first * per_record(&items)
            } else {
                per_record(&f.selection)
            }
        })
        .sum()
}

fn first_of(f: &Field) -> Option<i64> {
    f.arg("first").and_then(Value::as_i64)
}

/// Checks a parsed query against the limits. Pure.
pub fn check_limits(fields: &[Field]) -> Result<(), String> {
    if fields.len() > MAX_ROOT_FIELDS {
        return Err(format!("at most {MAX_ROOT_FIELDS} root fields"));
    }
    let depth = parse::depth(fields);
    if depth > MAX_DEPTH {
        return Err(format!(
            "the query nests {depth} levels; at most {MAX_DEPTH}"
        ));
    }
    let cost = cost(fields);
    if cost > MAX_COST {
        return Err(format!(
            "the query may read {cost} records; at most {MAX_COST} (ask for fewer, or fewer nested records)"
        ));
    }
    Ok(())
}

/// One field of an entity as the schema shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldShape {
    pub name: String,
    pub kind: FieldType,
    /// A lookup's target entity, when the caller may read it.
    pub target: Option<String>,
}

/// One entity as the schema shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityShape {
    pub name: String,
    pub fields: Vec<FieldShape>,
}

/// An entity's GraphQL type name: `deal_line` is `DealLine`. Pure.
pub fn type_name(entity: &str) -> String {
    entity
        .split('_')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut c = p.chars();
            c.next()
                .map(|first| first.to_ascii_uppercase().to_string() + c.as_str())
                .unwrap_or_default()
        })
        .collect()
}

/// The GraphQL type of a scalar field. Pure.
pub fn scalar_of(kind: &FieldType) -> &'static str {
    match kind {
        FieldType::Number | FieldType::Currency | FieldType::Rollup => "Float",
        FieldType::Bool => "Boolean",
        FieldType::Json | FieldType::Geolocation => "JSON",
        FieldType::Lookup => "ID",
        _ => "String",
    }
}

/// The schema as SDL, for `entities` (sorted by name). Pure.
pub fn sdl(entities: &[EntityShape]) -> String {
    let mut out = String::from("\"\"\"Any JSON value.\"\"\"\nscalar JSON\n\ntype Query {\n");
    for e in entities {
        let t = type_name(&e.name);
        out.push_str(&format!("  {}(id: ID!): {t}\n", e.name));
        out.push_str(&format!(
            "  {}_list(where: JSON, sort: String, first: Int, after: String): {t}Page!\n",
            e.name
        ));
    }
    out.push_str("}\n");
    for e in entities {
        let t = type_name(&e.name);
        out.push_str(&format!("\ntype {t} {{\n"));
        for f in &e.fields {
            let ty = if f.name == "id" {
                "ID!".to_owned()
            } else if let Some(target) = &f.target {
                type_name(target)
            } else {
                scalar_of(&f.kind).to_owned()
            };
            out.push_str(&format!("  {}: {ty}\n", f.name));
        }
        out.push_str(&format!(
            "}}\n\ntype {t}Page {{\n  items: [{t}!]!\n  next_cursor: String\n}}\n"
        ));
    }
    out
}

/// The entities and fields `ctx` may read, from the registry. A field the
/// caller may not read is not in its entity, as on the record list.
fn shapes(state: &EngineState, ctx: &SecurityContext) -> Vec<EntityShape> {
    let registry = state.entities.load();
    let readable: BTreeSet<String> = registry
        .iter()
        .filter(|m| ctx.require(&m.logicalname, "read").is_ok())
        .map(|m| m.logicalname.clone())
        .collect();
    let mut out: Vec<EntityShape> = registry
        .iter()
        .filter(|m| readable.contains(&m.logicalname))
        .filter(|m| is_graphql_name(&m.logicalname))
        .map(|meta| {
            let primary = meta.primary_name_attribute.as_deref();
            let mut fields: Vec<FieldShape> = attome_core::ALL_SYSTEM_COLS
                .iter()
                .filter_map(|c| {
                    attome_core::data_definition::system_column_type(c).map(|kind| FieldShape {
                        name: (*c).to_owned(),
                        kind,
                        target: None,
                    })
                })
                .collect();
            for attr in &meta.attrs {
                if matches!(
                    field_gate::projection(
                        ctx,
                        &meta.logicalname,
                        attr,
                        primary,
                        Surface::Interactive
                    ),
                    attome_core::field_mask::ColumnAccess::Hidden
                ) || !is_graphql_name(&attr.logicalname)
                {
                    continue;
                }
                let target = attr
                    .lookup_entity_ref
                    .and_then(|id| registry.get_by_id(id))
                    .map(|t| t.logicalname.clone())
                    .filter(|t| readable.contains(t) && is_graphql_name(t));
                fields.push(FieldShape {
                    name: attr.logicalname.clone(),
                    kind: attr.field_type(),
                    target,
                });
            }
            EntityShape {
                name: meta.logicalname.clone(),
                fields,
            }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn is_graphql_name(s: &str) -> bool {
    s.starts_with(|c: char| c == '_' || c.is_ascii_alphabetic())
        && s.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
        && !s.starts_with("__")
}

type Shapes = HashMap<String, HashMap<String, FieldShape>>;

/// A query error, as GraphQL answers it.
struct GqlError(String);

impl From<AppError> for GqlError {
    fn from(e: AppError) -> Self {
        GqlError(match e {
            AppError::Forbidden => "forbidden".to_owned(),
            AppError::NotFound => "not found".to_owned(),
            AppError::Validation(m) => m,
            other => {
                tracing::warn!(error = %other, "a graphql read failed");
                "the read failed".to_owned()
            }
        })
    }
}

type Rows = (Vec<Map<String, Value>>, Option<String>);
type Fetch<'a> = Pin<Box<dyn Future<Output = Result<Rows, GqlError>> + Send + 'a>>;

/// Reads `entity`'s records matching `where_` and projects each onto
/// `selection`, resolving nested lookups in one batch per field.
#[allow(clippy::too_many_arguments, reason = "one read's parts, all needed")]
fn fetch<'a>(
    state: &'a EngineState,
    ctx: &'a SecurityContext,
    shapes: &'a Shapes,
    entity: &'a str,
    where_: Option<Condition>,
    sort: Vec<SortKey>,
    page: (i64, Option<String>),
    selection: &'a [Field],
) -> Fetch<'a> {
    Box::pin(async move {
        let fields = shapes
            .get(entity)
            .ok_or_else(|| GqlError(format!("no entity {entity} you may read")))?;
        let mut select: BTreeSet<String> = BTreeSet::from(["id".to_owned()]);
        for f in selection {
            if f.name == "__typename" {
                continue;
            }
            if !fields.contains_key(&f.name) {
                return Err(GqlError(format!(
                    "{} has no field {}",
                    type_name(entity),
                    f.name
                )));
            }
            select.insert(f.name.clone());
        }
        let spec = QuerySpec {
            entity: entity.to_owned(),
            select: select.into_iter().collect(),
            r#where: where_,
            sort,
            page_size: Some(page.0),
            cursor: page.1,
            group_by: Vec::new(),
            aggregates: Vec::new(),
            having: None,
            explain: false,
            as_of: None,
            params: Default::default(),
            totals: None,
        };
        let RunResponse::Rows(rows) =
            execute_spec_on(state, ctx, spec, Surface::Interactive).await?
        else {
            return Err(GqlError("a record read compiled to aggregates".to_owned()));
        };
        let raw: Vec<Map<String, Value>> = rows.items.into_iter().map(|r| r.0).collect();
        let mut nested: HashMap<String, HashMap<String, Map<String, Value>>> = HashMap::new();
        for f in selection.iter().filter(|f| !f.selection.is_empty()) {
            let shape = &fields[&f.name];
            let Some(target) = shape.target.as_deref() else {
                return Err(GqlError(format!(
                    "{}.{} is not a lookup to an entity you may read",
                    type_name(entity),
                    f.name
                )));
            };
            let ids: Vec<Value> = raw
                .iter()
                .filter_map(|r| r.get(&f.name).and_then(Value::as_str))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|s| Value::String(s.to_owned()))
                .collect();
            let mut found = HashMap::new();
            for chunk in ids.chunks(LOOKUP_BATCH) {
                let condition = Condition::Compare {
                    field: "id".to_owned(),
                    op: "in".to_owned(),
                    value: Some(Value::Array(chunk.to_vec())),
                };
                let (rows, _) = fetch(
                    state,
                    ctx,
                    shapes,
                    target,
                    Some(condition),
                    Vec::new(),
                    (chunk.len() as i64, None),
                    &f.selection,
                )
                .await?;
                for row in rows {
                    if let Some(id) = row.get("__id").and_then(Value::as_str) {
                        found.insert(id.to_owned(), row.clone());
                    }
                }
            }
            nested.insert(f.key().to_owned(), found);
        }
        let projected = raw
            .iter()
            .map(|row| {
                let mut out = Map::new();
                // Kept for the parent's lookup join, removed below.
                if let Some(id) = row.get("id") {
                    out.insert("__id".to_owned(), id.clone());
                }
                for f in selection {
                    let value = if f.name == "__typename" {
                        Value::String(type_name(entity))
                    } else if !f.selection.is_empty() {
                        row.get(&f.name)
                            .and_then(Value::as_str)
                            .and_then(|id| nested.get(f.key()).and_then(|m| m.get(id)))
                            .map(|m| Value::Object(m.clone()))
                            .unwrap_or(Value::Null)
                    } else {
                        row.get(&f.name).cloned().unwrap_or(Value::Null)
                    };
                    out.insert(f.key().to_owned(), value);
                }
                out
            })
            .collect();
        Ok((projected, rows.next_cursor))
    })
}

/// Removes the `__id` join keys from an answer, at every level.
fn strip_ids(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.remove("__id");
            m.values_mut().for_each(strip_ids);
        }
        Value::Array(a) => a.iter_mut().for_each(strip_ids),
        _ => {}
    }
}

/// `{field: {op: value}}` as conditions on the query engine. Pure.
pub fn where_of(arg: Option<&Value>) -> Result<Option<Condition>, String> {
    let Some(arg) = arg.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let Some(fields) = arg.as_object() else {
        return Err("where is an object: {field: {op: value}}".to_owned());
    };
    let mut all = Vec::new();
    for (field, ops) in fields {
        let Some(ops) = ops.as_object() else {
            return Err(format!("where.{field} is an object: {{op: value}}"));
        };
        for (op, value) in ops {
            all.push(Condition::Compare {
                field: field.clone(),
                op: op.clone(),
                value: (!value.is_null()).then(|| value.clone()),
            });
        }
    }
    Ok((!all.is_empty()).then_some(Condition::And { all }))
}

/// `"field"` or `"-field"` as a sort key. Pure.
pub fn sort_of(arg: Option<&Value>) -> Result<Vec<SortKey>, String> {
    match arg.filter(|v| !v.is_null()) {
        None => Ok(Vec::new()),
        Some(Value::String(s)) if !s.trim().is_empty() => {
            let s = s.trim();
            Ok(vec![match s.strip_prefix('-') {
                Some(field) => SortKey {
                    field: field.to_owned(),
                    desc: true,
                },
                None => SortKey {
                    field: s.to_owned(),
                    desc: false,
                },
            }])
        }
        Some(_) => Err("sort is \"field\" or \"-field\"".to_owned()),
    }
}

async fn execute(
    state: &EngineState,
    ctx: &SecurityContext,
    fields: &[Field],
) -> Result<Map<String, Value>, GqlError> {
    let shapes: Shapes = shapes(state, ctx)
        .into_iter()
        .map(|e| {
            let fields = e.fields.into_iter().map(|f| (f.name.clone(), f)).collect();
            (e.name, fields)
        })
        .collect();
    let mut data = Map::new();
    for root in fields {
        let value = if root.name == "__typename" {
            Value::String("Query".to_owned())
        } else if let Some(entity) = root
            .name
            .strip_suffix("_list")
            .filter(|e| shapes.contains_key(*e))
        {
            let first = first_of(root).unwrap_or(DEFAULT_FIRST).clamp(1, MAX_FIRST);
            let after = match root.arg("after").and_then(Value::as_str) {
                Some(sealed) => Some(attome_types::cursor::open(sealed)?),
                None => None,
            };
            let items: Vec<Field> = root
                .selection
                .iter()
                .filter(|f| f.name == "items")
                .flat_map(|f| f.selection.clone())
                .collect();
            let (rows, next) = fetch(
                state,
                ctx,
                &shapes,
                entity,
                where_of(root.arg("where")).map_err(GqlError)?,
                sort_of(root.arg("sort")).map_err(GqlError)?,
                (first, after),
                &items,
            )
            .await?;
            let mut page = Map::new();
            for f in &root.selection {
                let v = match f.name.as_str() {
                    "items" => Value::Array(rows.iter().cloned().map(Value::Object).collect()),
                    "next_cursor" => next
                        .as_deref()
                        .map(|c| Value::String(attome_types::cursor::seal(c)))
                        .unwrap_or(Value::Null),
                    "__typename" => Value::String(format!("{}Page", type_name(entity))),
                    other => {
                        return Err(GqlError(format!(
                            "{}Page has no field {other}",
                            type_name(entity)
                        )));
                    }
                };
                page.insert(f.key().to_owned(), v);
            }
            Value::Object(page)
        } else if shapes.contains_key(&root.name) {
            let Some(id) = root.arg("id").and_then(Value::as_str) else {
                return Err(GqlError(format!("{} needs id", root.name)));
            };
            let condition = Condition::Compare {
                field: "id".to_owned(),
                op: "eq".to_owned(),
                value: Some(Value::String(id.to_owned())),
            };
            let (rows, _) = fetch(
                state,
                ctx,
                &shapes,
                &root.name,
                Some(condition),
                Vec::new(),
                (1, None),
                &root.selection,
            )
            .await?;
            rows.into_iter()
                .next()
                .map(Value::Object)
                .unwrap_or(Value::Null)
        } else {
            return Err(GqlError(format!(
                "no root field {}: an entity you may read, or <entity>_list",
                root.name
            )));
        };
        data.insert(root.key().to_owned(), value);
    }
    let mut out = Value::Object(data);
    strip_ids(&mut out);
    Ok(match out {
        Value::Object(m) => m,
        _ => Map::new(),
    })
}

/// A GraphQL request.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct GraphqlRequest {
    query: String,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    variables: Option<Map<String, Value>>,
}

/// Run a GraphQL query
///
/// S6-T1: reads records through a schema built from the metadata for the caller (see
/// `GET /api/v1/graphql/schema`). Answers `{data}`, or `{data: null, errors: [{message}]}` for a
/// query that does not parse, breaks a limit (10 root fields, 6 levels, 10,000 records by
/// estimate) or reads what the caller may not. Reads only; writes go through the record API.
#[utoipa::path(
    post,
    path = "/api/v1/graphql",
    operation_id = "run_graphql",
    tag = "entity",
    request_body = GraphqlRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::ReadOnly, None, "a read: queries only, no mutations; every read runs through the query engine with the caller's access")))),
    responses(
        (status = 200, description = "The answer, or its errors", body = Object),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn run_graphql(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<GraphqlRequest>,
) -> Json<Value> {
    let variables = body.variables.unwrap_or_default();
    let answer = match parse::parse_query(&body.query, &variables)
        .and_then(|fields| check_limits(&fields).map(|()| fields))
    {
        Err(message) => Err(GqlError(message)),
        Ok(fields) => execute(&state, &ctx, &fields).await,
    };
    Json(match answer {
        Ok(data) => json!({ "data": data }),
        Err(GqlError(message)) => json!({ "data": null, "errors": [{ "message": message }] }),
    })
}

/// The caller's GraphQL schema.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct GraphqlSchema {
    /// The schema in the GraphQL schema language.
    sdl: String,
}

/// The GraphQL schema
///
/// S6-T1: the schema `POST /api/v1/graphql` answers for the caller, in the GraphQL schema
/// language: the entities they may read, each with its readable fields, and lookups to readable
/// entities as their types.
#[utoipa::path(
    get,
    path = "/api/v1/graphql/schema",
    operation_id = "graphql_schema",
    tag = "entity",
    responses(
        (status = 200, description = "The schema", body = GraphqlSchema),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn graphql_schema(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Json<GraphqlSchema> {
    Json(GraphqlSchema {
        sdl: sdl(&shapes(&state, &ctx)),
    })
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/graphql", post(run_graphql))
        .route("/api/v1/graphql/schema", get(graphql_schema))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(run_graphql, graphql_schema))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(src: &str) -> Vec<Field> {
        parse::parse_query(src, &Map::new()).unwrap()
    }

    #[test]
    fn schema_sdl_names_types_scalars_and_lookups() {
        let shapes = vec![
            EntityShape {
                name: "account".into(),
                fields: vec![
                    FieldShape {
                        name: "id".into(),
                        kind: FieldType::Lookup,
                        target: None,
                    },
                    FieldShape {
                        name: "name".into(),
                        kind: FieldType::Text,
                        target: None,
                    },
                    FieldShape {
                        name: "revenue".into(),
                        kind: FieldType::Currency,
                        target: None,
                    },
                ],
            },
            EntityShape {
                name: "deal_line".into(),
                fields: vec![
                    FieldShape {
                        name: "account_ref".into(),
                        kind: FieldType::Lookup,
                        target: Some("account".into()),
                    },
                    FieldShape {
                        name: "owner_ref".into(),
                        kind: FieldType::Lookup,
                        target: None,
                    },
                    FieldShape {
                        name: "won".into(),
                        kind: FieldType::Bool,
                        target: None,
                    },
                ],
            },
        ];
        let s = sdl(&shapes);
        assert!(s.contains("  account(id: ID!): Account\n"), "{s}");
        assert!(s.contains("  deal_line_list(where: JSON, sort: String, first: Int, after: String): DealLinePage!\n"), "{s}");
        assert!(
            s.contains("  id: ID!\n  name: String\n  revenue: Float\n"),
            "{s}"
        );
        assert!(
            s.contains("  account_ref: Account\n  owner_ref: ID\n  won: Boolean\n"),
            "{s}"
        );
        assert!(
            s.contains("type DealLinePage {\n  items: [DealLine!]!\n  next_cursor: String\n}"),
            "{s}"
        );
        assert_eq!(type_name("a__b"), "AB");
    }

    #[test]
    fn schema_limits_depth_cost_and_root_fields() {
        assert!(
            check_limits(&q(
                "{ account_list(first: 100) { items { id owner_ref { name } } } }"
            ))
            .is_ok()
        );
        assert_eq!(
            cost(&q(
                "{ account_list(first: 100) { items { id owner_ref { name } } } }"
            )),
            200
        );
        assert_eq!(cost(&q("{ account(id: \"x\") { name } }")), 1);
        // Clamped to 100 a page: 100 * (1 + 1 + 1) per root, two roots.
        let wide = "{ a: deal_list(first: 500) { items { x { y } z { y } } } b: deal_list(first: 500) { items { x { y } z { y } } } }";
        assert_eq!(cost(&q(wide)), 600);
        // Ten roots of 100 records, each reading eleven more: 12,000.
        let nested = (0..11)
            .map(|i| format!("l{i} {{ id }}"))
            .collect::<Vec<_>>()
            .join(" ");
        let costly = format!(
            "{{ {} }}",
            (0..10)
                .map(|i| format!("a{i}: deal_list(first: 100) {{ items {{ {nested} }} }}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert!(check_limits(&q(&costly)).unwrap_err().contains("records"));
        let deep = "{ a { b { c { d { e { f { g } } } } } } }";
        assert!(check_limits(&q(deep)).unwrap_err().contains("levels"));
        let many = format!(
            "{{ {} }}",
            (0..11)
                .map(|i| format!("a{i}: x {{ id }}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert!(check_limits(&q(&many)).unwrap_err().contains("root fields"));
    }

    #[test]
    fn schema_arguments_become_engine_conditions() {
        let w = where_of(Some(
            &json!({ "amount": { "gte": 10 }, "stage": { "is_null": null } }),
        ))
        .unwrap()
        .unwrap();
        let Condition::And { all } = w else {
            panic!("an and")
        };
        assert_eq!(all.len(), 2);
        assert!(
            matches!(&all[0], Condition::Compare { field, op, value } if field == "amount" && op == "gte" && value == &Some(json!(10)))
        );
        assert!(matches!(&all[1], Condition::Compare { op, value: None, .. } if op == "is_null"));
        assert!(where_of(Some(&json!(["x"]))).is_err());
        assert!(where_of(None).unwrap().is_none());
        let s = sort_of(Some(&json!("-amount"))).unwrap();
        assert!(s[0].desc && s[0].field == "amount");
        assert!(sort_of(Some(&json!(3))).is_err());
    }

    #[test]
    fn schema_answer_drops_join_keys() {
        let mut v = json!({ "a": { "__id": "1", "items": [{ "__id": "2", "x": { "__id": "3", "y": 1 } }] } });
        strip_ids(&mut v);
        assert_eq!(v, json!({ "a": { "items": [{ "x": { "y": 1 } }] } }));
    }
}
