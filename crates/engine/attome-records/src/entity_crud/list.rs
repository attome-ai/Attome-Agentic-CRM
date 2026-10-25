//! S1-T2: `GET /api/v1/{entity}`, a keyset-paged list of an entity's
//! records through `query/execute`'s engine (the entity's default view, its
//! record-level scoping and field masking unchanged).
//!
//! - `select=a,b`: the attributes to return (as `query/execute`'s `select`);
//! - `filter[<field>][<op>]=<value>`: one filter per pair, `op` one of the
//!   column-filter operators (`eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`,
//!   `contains`, `starts_with`, `ends_with`, `contains_any`, `contains_all`,
//!   `is_null`, `is_not_null`, `under`, `above`); `in`, `contains_any` and
//!   `contains_all` take a comma-separated list, `is_null`/`is_not_null`
//!   no value;
//! - `sort=field` or `sort=-field` (descending);
//! - `page_size` (1 to 200, default 50) and `cursor` (the last page's
//!   `next_cursor`).

use attome_core::EngineState;
use attome_core::filter::Filter;
use attome_security::record_action::Read;
use attome_server::authz::{Authorized, RecordScoped};
use attome_types::{AppError, CursorPage, ErrorResponse};
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::Value;
use utoipa::IntoParams;

use crate::query_exec::ExecuteQueryRequest;

/// The operators a list filter may name.
const OPERATORS: &[&str] = &[
    "eq",
    "neq",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "contains",
    "starts_with",
    "ends_with",
    "contains_any",
    "contains_all",
    "is_null",
    "is_not_null",
    "under",
    "above",
];

/// The list's paging, sort and projection. Filters are read from the raw
/// query (`filter[<field>][<op>]=<value>`).
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListParams {
    /// Comma-separated attributes to return.
    pub select: Option<String>,
    /// `field` ascending, `-field` descending.
    pub sort: Option<String>,
    /// 1 to 200; 50 when absent.
    pub page_size: Option<i64>,
    /// The previous page's `next_cursor`, verbatim (a cursor this
    /// deployment did not issue is a 400 `invalid_cursor`).
    pub cursor: Option<String>,
}

/// Every `filter[<field>][<op>]` pair among `pairs`.
pub fn parse_filters(pairs: &[(String, String)]) -> Result<Vec<Filter>, AppError> {
    let mut out = Vec::new();
    for (key, value) in pairs {
        let Some(rest) = key.strip_prefix("filter[") else {
            continue;
        };
        let parsed = rest
            .split_once("][")
            .and_then(|(field, op)| op.strip_suffix(']').map(|op| (field, op)));
        let Some((field, op)) = parsed.filter(|(f, o)| !f.is_empty() && !o.is_empty()) else {
            return Err(AppError::Validation(format!(
                "{key:?} is not filter[<field>][<op>]"
            )));
        };
        if !OPERATORS.contains(&op) {
            return Err(AppError::Validation(format!(
                "filter operator {op:?} is not one of {}",
                OPERATORS.join(", ")
            )));
        }
        let value = match op {
            "is_null" | "is_not_null" => None,
            "in" | "contains_any" | "contains_all" => Some(Value::Array(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(|v| Value::String(v.to_owned()))
                    .collect(),
            )),
            _ => Some(Value::String(value.clone())),
        };
        out.push(Filter {
            field: field.to_owned(),
            op: op.to_owned(),
            value,
        });
    }
    Ok(out)
}

/// `sort` as `(field, direction)`; none sorts by id.
pub fn parse_sort(sort: Option<&str>) -> (String, String) {
    match sort.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => match s.strip_prefix('-') {
            Some(field) => (field.to_owned(), "desc".to_owned()),
            None => (s.to_owned(), "asc".to_owned()),
        },
        None => (String::new(), "asc".to_owned()),
    }
}

/// List records
///
/// A keyset-paged list of an entity's records the caller may read, with `select`, `filter[field][op]` and `sort`, through the entity's default view with record scope and field masking applied.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name"), ListParams),
    responses(
        (status = 200, description = "One page of records; next_cursor continues it", body = CursorPage<serde_json::Value>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not read this entity", body = ErrorResponse),
        (status = 404, description = "No such entity, or it has no default view", body = ErrorResponse),
        (status = 422, description = "A malformed filter, sort or select", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_records(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path(entity_input): Path<String>,
    Query(params): Query<ListParams>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Result<Json<CursorPage<Value>>, AppError> {
    let filters = parse_filters(&pairs)?;
    let (order_by, order_dir) = parse_sort(params.sort.as_deref());
    let select = params.select.as_deref().map(|s| {
        s.split(',')
            .map(str::trim)
            .filter(|f| !f.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    });
    let page_size = params.page_size.unwrap_or(50).clamp(1, 200);
    let request = ExecuteQueryRequest::for_entity_list(
        entity_input,
        filters,
        order_by,
        order_dir,
        page_size,
        attome_types::cursor::open_uuid(params.cursor.as_deref())?,
        select,
    );
    let response =
        crate::query_exec::execute_stored_query_with_definition(&state, &ctx, request, None)
            .await?;
    Ok(Json(response.into_cursor_page()))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_records))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn parse_filters_reads_deep_object_pairs() {
        let filters = parse_filters(&pairs(&[
            ("filter[amount][gt]", "100"),
            ("filter[stage][in]", "won, lost"),
            ("filter[closed_on][is_null]", ""),
            ("page_size", "10"),
        ]))
        .unwrap();
        assert_eq!(filters.len(), 3);
        assert_eq!(
            (filters[0].field.as_str(), filters[0].op.as_str()),
            ("amount", "gt")
        );
        assert_eq!(filters[0].value, Some(Value::String("100".into())));
        assert_eq!(filters[1].value, Some(serde_json::json!(["won", "lost"])));
        assert_eq!(filters[2].value, None);
    }

    #[test]
    fn parse_filters_rejects_unknown_operator() {
        assert!(parse_filters(&pairs(&[("filter[amount][approx]", "1")])).is_err());
        assert!(parse_filters(&pairs(&[("filter[amount]", "1")])).is_err());
        assert!(parse_filters(&pairs(&[("filter[][eq]", "1")])).is_err());
    }

    #[test]
    fn sort_minus_prefix_is_descending() {
        assert_eq!(
            parse_sort(Some("-amount")),
            ("amount".into(), "desc".into())
        );
        assert_eq!(parse_sort(Some("name")), ("name".into(), "asc".into()));
        assert_eq!(parse_sort(None), (String::new(), "asc".into()));
    }
}
