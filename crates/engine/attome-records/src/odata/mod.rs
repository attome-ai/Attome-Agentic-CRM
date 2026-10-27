//! S7-T1: a read-only OData v4 feed, so Excel and Power BI read records
//! without an export.
//!
//! - `GET /api/v1/odata` — the service document: one entity set per entity
//!   the caller may read.
//! - `GET /api/v1/odata/$metadata` — the CSDL schema of those sets
//!   ([`csdl`]): the key `id` and every attribute the caller may read,
//!   typed from its field type.
//! - `GET /api/v1/odata/{entity}` — records, with `$select`, `$filter`,
//!   `$orderby`, `$top`, `$count` and server-driven paging through
//!   `@odata.nextLink` ([`options`], [`filter`]).
//! - `GET /api/v1/odata/{entity}/$count` — the number of records, as text.
//!
//! Every request becomes a QuerySpec run by the same executor as
//! `POST /api/v1/query/run` (`crate::query_spec::routes::execute_spec`): the
//! record-level predicate and the field gate are inside the SQL, the query
//! runs on the read-only pool under the interactive time limit, and the plan
//! cost guard applies. An entity the caller may not read is a 404, as on
//! every other route; a sensitive attribute without a field-read grant is
//! neither in `$metadata` nor selectable.
//!
//! Clients authenticate like any API client: Power Query sends the API key
//! as a header, `OData.Feed(url, null, [Headers = [Authorization = "Bearer
//! <key>"]])`. Unsupported options (`$expand`, `$search`, `$apply`, a
//! non-zero `$skip`) are refused with a 422 naming them.

pub mod csdl;
pub mod filter;
pub mod options;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Map, Value, json};

use crate::query_spec::routes::{RunResponse, execute_spec};
use crate::query_spec::{AggFunc, Aggregate};

/// The JSON content type every OData answer carries.
const JSON_TYPE: &str = "application/json;odata.metadata=minimal;odata.streaming=true";

/// The feed's root URL, as clients reach it.
fn base_url(state: &EngineState) -> String {
    format!(
        "{}/api/v1/odata",
        state.base.config.frontend_url().trim_end_matches('/')
    )
}

fn odata(body: Value) -> Response {
    let mut response = axum::Json(body).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(JSON_TYPE));
    headers.insert("odata-version", HeaderValue::from_static("4.0"));
    response
}

/// Whether `ctx` may read `entity`'s attribute `attr`.
fn attribute_visible(ctx: &SecurityContext, entity: &str, attr: &attome_core::AttrInfo) -> bool {
    !attr.is_read_gated()
        || ctx.is_admin
        || ctx
            .field_grants
            .contains(&format!("{entity}.{}", attr.logicalname))
}

/// The entity sets `ctx` may read, sorted by name, with their properties.
fn readable_sets(state: &EngineState, ctx: &SecurityContext) -> Vec<csdl::EntitySet> {
    let registry = state.entities.load();
    let mut sets: Vec<csdl::EntitySet> = registry
        .iter()
        .filter(|e| ctx.require(&e.logicalname, "read").is_ok())
        .map(|e| {
            let mut properties = vec![csdl::Property {
                name: "id".into(),
                edm_type: "Edm.Guid",
                nullable: false,
            }];
            properties.extend(
                e.attrs
                    .iter()
                    .filter(|a| a.logicalname != "id")
                    .filter(|a| attribute_visible(ctx, &e.logicalname, a))
                    .map(|a| csdl::Property {
                        name: a.logicalname.clone(),
                        edm_type: csdl::edm_type(a.storage_type()),
                        nullable: !a.is_required,
                    }),
            );
            csdl::EntitySet {
                name: e.logicalname.clone(),
                properties,
            }
        })
        .collect();
    sets.sort_by(|a, b| a.name.cmp(&b.name));
    sets
}

/// The OData service document
///
/// S7-T1: one entity set per entity the caller may read.
#[utoipa::path(
    get,
    path = "/api/v1/odata",
    tag = "query",
    operation_id = "odata_service_document",
    responses(
        (status = 200, description = "The service document (OData JSON)", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn service_document(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Response {
    let base = base_url(&state);
    let value: Vec<Value> = readable_sets(&state, &ctx)
        .into_iter()
        .map(|s| json!({ "name": s.name, "kind": "EntitySet", "url": s.name }))
        .collect();
    odata(json!({ "@odata.context": format!("{base}/$metadata"), "value": value }))
}

/// The OData schema
///
/// S7-T1: the CSDL (XML) of every entity set the caller may read, with the
/// attributes they may read.
#[utoipa::path(
    get,
    path = "/api/v1/odata/$metadata",
    tag = "query",
    operation_id = "odata_metadata",
    responses(
        (status = 200, description = "The CSDL document (application/xml)", body = String),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn metadata(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Response {
    let xml = csdl::document(&readable_sets(&state, &ctx));
    let mut response = xml.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml;charset=utf-8"),
    );
    headers.insert("odata-version", HeaderValue::from_static("4.0"));
    response
}

/// The options read, with every readable attribute chosen when `$select`
/// named none.
fn prepared(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    pairs: &[(String, String)],
) -> Result<options::Options, AppError> {
    ctx.require(entity, "read")
        .map_err(|_| AppError::NotFound)?;
    let mut read = options::read(entity, pairs).map_err(AppError::Validation)?;
    if !read.selected {
        let registry = state.entities.load();
        let meta = registry.get(entity).ok_or(AppError::NotFound)?;
        read.spec.select = std::iter::once("id".to_owned())
            .chain(
                meta.attrs
                    .iter()
                    .filter(|a| a.logicalname != "id")
                    .filter(|a| attribute_visible(ctx, entity, a))
                    .map(|a| a.logicalname.clone()),
            )
            .collect();
    }
    Ok(read)
}

/// The number of records `spec`'s filter matches.
async fn count_of(
    state: &EngineState,
    ctx: &SecurityContext,
    spec: &crate::query_spec::QuerySpec,
) -> Result<i64, AppError> {
    let mut counting = spec.clone();
    counting.select.clear();
    counting.sort.clear();
    counting.cursor = None;
    counting.page_size = None;
    counting.aggregates = vec![Aggregate {
        func: AggFunc::Count,
        field: None,
        alias: "n".into(),
    }];
    match execute_spec(state, ctx, counting).await? {
        RunResponse::Aggregate(result) => Ok(result
            .groups
            .first()
            .and_then(|g| g.values.get("n"))
            .and_then(Value::as_i64)
            .unwrap_or(0)),
        _ => Err(AppError::internal("a count query answered rows")),
    }
}

/// Records of one entity set
///
/// S7-T1: `$select`, `$filter`, `$orderby`, `$top`, `$count`, and the next
/// page through `@odata.nextLink`.
#[utoipa::path(
    get,
    path = "/api/v1/odata/{entity}",
    tag = "query",
    operation_id = "odata_entity_set",
    params(("entity" = String, Path, description = "The entity's logical name")),
    responses(
        (status = 200, description = "A page of records (OData JSON)", body = serde_json::Value),
        (status = 400, description = "A $skiptoken this deployment did not issue", body = ErrorResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such entity, or one the caller may not read", body = ErrorResponse),
        (status = 422, description = "An option the feed does not support, or a $filter outside its grammar", body = ErrorResponse),
        (status = 504, description = "The query ran past the statement time limit", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn entity_set(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(entity): Path<String>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Result<Response, AppError> {
    let read = prepared(&state, &ctx, &entity, &pairs)?;
    let base = base_url(&state);
    let mut body = Map::new();
    body.insert(
        "@odata.context".into(),
        json!(format!("{base}/$metadata#{entity}")),
    );
    if read.count {
        body.insert(
            "@odata.count".into(),
            json!(count_of(&state, &ctx, &read.spec).await?),
        );
    }
    if read.top == Some(0) {
        body.insert("value".into(), json!([]));
        return Ok(odata(Value::Object(body)));
    }
    let page = match execute_spec(&state, &ctx, read.spec).await? {
        RunResponse::Rows(page) => page,
        _ => return Err(AppError::internal("an OData read answered no rows")),
    };
    let rows: Vec<Value> = page.items.into_iter().map(|r| Value::Object(r.0)).collect();
    body.insert("value".into(), Value::Array(rows));
    if read.top.is_none()
        && let Some(cursor) = page.next_cursor
    {
        let token = attome_types::cursor::seal(&cursor);
        let query: String = url_encode(&options::next_query(&pairs, &token));
        body.insert(
            "@odata.nextLink".into(),
            json!(format!("{base}/{entity}?{query}")),
        );
    }
    Ok(odata(Value::Object(body)))
}

/// The number of records of one entity set
///
/// S7-T1: honours `$filter`; the answer is plain text.
#[utoipa::path(
    get,
    path = "/api/v1/odata/{entity}/$count",
    tag = "query",
    operation_id = "odata_entity_count",
    params(("entity" = String, Path, description = "The entity's logical name")),
    responses(
        (status = 200, description = "The count, as text", body = String),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such entity, or one the caller may not read", body = ErrorResponse),
        (status = 422, description = "An option the feed does not support", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn entity_count(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(entity): Path<String>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Result<Response, AppError> {
    let read = prepared(&state, &ctx, &entity, &pairs)?;
    let n = count_of(&state, &ctx, &read.spec).await?;
    let mut response = n.to_string().into_response();
    response
        .headers_mut()
        .insert("odata-version", HeaderValue::from_static("4.0"));
    Ok(response)
}

/// `k=v&…`, each part percent-encoded.
fn url_encode(pairs: &[(String, String)]) -> String {
    fn enc(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'$') {
                out.push(char::from(b));
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The OData routes, mounted with the query routes.
pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/odata", get(service_document))
        .route("/api/v1/odata/$metadata", get(metadata))
        .route("/api/v1/odata/{entity}", get(entity_set))
        .route("/api/v1/odata/{entity}/$count", get(entity_count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn odata_next_link_query_is_encoded() {
        let q = url_encode(&[
            ("$filter".into(), "city eq 'Riyadh & Co'".into()),
            ("$skiptoken".into(), "a+b/c=".into()),
        ]);
        assert_eq!(
            q,
            "$filter=city%20eq%20%27Riyadh%20%26%20Co%27&$skiptoken=a%2Bb%2Fc%3D"
        );
    }
}
