//! The product picker (roadmap D6-T5): the products on a price list that a
//! line can use on a date, with their list price and quantity breaks,
//! searched by name or by SKU. Only products the caller may read are
//! listed (the product entity's record rules filter the query), and the
//! search terms are bound, never written into the SQL.

use attome_core::EngineState;
use attome_security::{
    RecordAction, bind_rls_predicate, resolve_entity_access_level, rls_predicate,
};
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// `product.read`: may read products.
#[derive(Debug)]
pub struct ProductRead;

impl PrivilegeKey for ProductRead {
    const KEY: &'static str = "product.read";
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ProductPickerQuery {
    /// Words in the product's English or Arabic name.
    pub q: Option<String>,
    /// An exact SKU or barcode.
    pub sku: Option<String>,
    /// The date the line is for; today when absent.
    pub on: Option<NaiveDate>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    pub page: Option<i64>,
    /// Rows per page.
    pub page_size: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PriceBreak {
    pub min_quantity: Option<String>,
    pub price: Option<String>,
    pub discount_percent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesProductPrice {
    pub product_id: Uuid,
    pub name: Option<String>,
    pub name_ar: Option<String>,
    pub sku: Option<String>,
    pub unit_ref: Option<Uuid>,
    pub list_price: Option<String>,
    pub breaks: Vec<PriceBreak>,
}

/// A name search as a LIKE pattern with its wildcards escaped.
pub fn like_pattern(q: &str) -> String {
    let escaped = q
        .trim()
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

#[utoipa::path(
    get,
    path = "/api/v1/sales/price-lists/{id}/products",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The price list"), ProductPickerQuery),
    responses(
        (status = 200, description = "The products a line can use on the date, with list prices and breaks", body = PaginatedResponse<SalesProductPrice>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks product.read", body = ErrorResponse),
        (status = 404, description = "No such price list", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_sales_price_list_products(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ProductRead>>,
    Path(price_list): Path<Uuid>,
    Query(q): Query<ProductPickerQuery>,
) -> Result<Json<PaginatedResponse<SalesProductPrice>>, AppError> {
    let on = q.on.unwrap_or_else(|| Utc::now().date_naive());
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(50).clamp(1, 200);
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM price_list WHERE id = $1 \
             AND (is_active IS NULL OR is_active = true))",
    )
    .bind(price_list)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let product_entity = state
        .entities
        .load()
        .get("product")
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)?;
    let level = resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        product_entity,
        "product",
        RecordAction::Read,
    )
    .await?;
    // $1 list, $2 date, $3 name pattern, $4 sku; record rules from $5.
    let predicate = rls_predicate(
        &ctx,
        product_entity,
        "p",
        level,
        RecordAction::Read.share_capability(),
        5,
    );
    let rls = predicate.as_ref().map_or("", |p| p.sql.as_str());
    let next = 5 + if predicate.is_some() {
        attome_security::RLS_BIND_COUNT
    } else {
        0
    };
    let from = format!(
        "FROM price_list_item i \
         JOIN price_list l ON l.id = i.price_list_ref \
         JOIN product p ON p.id = i.product_ref \
         WHERE i.price_list_ref = $1 \
           AND (i.is_active IS NULL OR i.is_active = true) \
           AND (p.is_active IS NULL OR p.is_active = true) \
           AND COALESCE(p.is_orderable, true) \
           AND (l.valid_from IS NULL OR l.valid_from::date <= $2) \
           AND (l.valid_to IS NULL OR l.valid_to::date >= $2) \
           AND ($3::text IS NULL OR p.name ILIKE $3 OR p.name_ar ILIKE $3) \
           AND ($4::text IS NULL OR p.sku = $4) {rls}"
    );
    let pattern =
        q.q.as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(like_pattern);
    let sku = q
        .sku
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let count_sql = format!("SELECT COUNT(*) {from}");
    let mut count = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(price_list)
        .bind(on)
        .bind(&pattern)
        .bind(&sku);
    let sql = format!(
        "SELECT row_to_json(r) FROM (SELECT p.id AS product_id, p.name, p.name_ar, p.sku, \
                COALESCE(i.unit_ref, p.default_unit_ref) AS unit_ref, \
                COALESCE(i.list_price, i.price)::text AS list_price, \
                COALESCE((SELECT json_agg(json_build_object( \
                    'min_quantity', b.min_quantity::text, 'price', b.price::text, \
                    'discount_percent', b.discount_percent::text) ORDER BY b.min_quantity) \
                  FROM price_break b WHERE b.price_list_item_ref = i.id \
                    AND (b.is_active IS NULL OR b.is_active = true)), '[]'::json) AS breaks \
         {from} ORDER BY p.name, p.id LIMIT ${next} OFFSET ${}) r",
        next + 1
    );
    let mut rows = sqlx::query_scalar::<_, serde_json::Value>(&sql)
        .bind(price_list)
        .bind(on)
        .bind(&pattern)
        .bind(&sku);
    if let Some(p) = &predicate {
        count = bind_rls_predicate(count, &p.binds);
        rows = bind_rls_predicate(rows, &p.binds);
    }
    let total = count
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let rows = rows
        .bind(page_size)
        .bind((page - 1) * page_size)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let items = rows
        .into_iter()
        .filter_map(|row| {
            let text = |k: &str| row.get(k).and_then(|v| v.as_str()).map(str::to_owned);
            let uuid = |k: &str| {
                row.get(k)
                    .and_then(|v| v.as_str())
                    .and_then(|s| Uuid::parse_str(s).ok())
            };
            Some(SalesProductPrice {
                product_id: uuid("product_id")?,
                name: text("name"),
                name_ar: text("name_ar"),
                sku: text("sku"),
                unit_ref: uuid("unit_ref"),
                list_price: text("list_price"),
                breaks: row
                    .get("breaks")
                    .cloned()
                    .and_then(|b| serde_json::from_value(b).ok())
                    .unwrap_or_default(),
            })
        })
        .collect();
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_sales_price_list_products),
    components(schemas(SalesProductPrice, PriceBreak))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_wildcards_are_escaped() {
        assert_eq!(like_pattern(" cable "), "%cable%");
        assert_eq!(like_pattern("50%_off"), "%50\\%\\_off%");
        assert_eq!(like_pattern("a\\b"), "%a\\\\b%");
    }
}
