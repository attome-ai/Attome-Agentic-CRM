//! Quote versions and pricing (roadmap D9-T2).
//!
//! - **Pricing.** A quote's lines are priced through D8's price resolution
//!   ([`crate::price_resolution::resolve`]): the account's own price, else
//!   the active price list in the quote's currency with its quantity
//!   breaks, per unit of the product's default unit. [`load_price_inputs`]
//!   is the loader D8 left to its callers. `reprice` sets each line's unit
//!   price and total and the quote's totals in one transaction, at the
//!   quote's row version; a product with no price refuses the whole reprice
//!   and names it.
//! - **Versions.** A new version copies the quote and its lines in one
//!   transaction: same quote number, the next version number, `draft`, not
//!   primary. The earlier version stays as it was.
//! - **Primary.** One primary quote per deal: making a quote primary
//!   clears the flag on the deal's others, under the deal's row lock. The
//!   deal's lines then follow the primary through D6-T7's sync
//!   (`/api/v1/sales/opportunities/{id}/sync`), which settles conflicts with the
//!   person rather than overwriting the deal behind their back.

use std::collections::HashMap;
use std::str::FromStr;

use attome_core::EngineState;
use attome_records::entity_mutation::{
    CreateStamp, MutationMode, Principal, create_one_as, update_one_as,
};
use attome_records::mutation_ring::MutationActor;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::price_resolution::{
    AccountPrice, ListItem, PriceBreak, PriceList, PriceRequest, UnitFactors, Validity, resolve,
};

fn dec(raw: Option<String>) -> Decimal {
    raw.and_then(|s| Decimal::from_str(s.trim()).ok())
        .unwrap_or(Decimal::ZERO)
}

fn opt_dec(raw: Option<String>) -> Option<Decimal> {
    raw.and_then(|s| Decimal::from_str(s.trim()).ok())
}

/// What D8 needs to price one product for one account.
#[derive(Debug, Clone, Default)]
pub struct PriceInputs {
    pub account_prices: Vec<AccountPrice>,
    pub lists: Vec<PriceList>,
    pub factors: UnitFactors,
    pub default_unit: Option<Uuid>,
}

type ListRow = (
    Uuid,
    Option<String>,
    Option<bool>,
    Option<NaiveDate>,
    Option<NaiveDate>,
    Option<Uuid>,
    Option<String>,
    Option<Uuid>,
);

/// An account price row: id, currency, price, valid from, valid to.
type AccountPriceRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<NaiveDate>,
    Option<NaiveDate>,
);

/// A price break row: id, item, minimum quantity, price, discount percent.
type PriceBreakRow = (Uuid, Uuid, Option<String>, Option<String>, Option<String>);

/// Loads the account's prices, the price lists in `currency` with their
/// item and breaks for the product, and the units' conversion factors.
pub async fn load_price_inputs(
    tx: &mut attome_db::Tx<'_>,
    account: Option<Uuid>,
    product: Uuid,
    currency: &str,
) -> Result<PriceInputs, AppError> {
    let mut inputs = PriceInputs::default();
    if let Some(account) = account {
        let rows: Vec<AccountPriceRow> =
            sqlx::query_as(
                "SELECT id, currency, price::text, valid_from::date, valid_to::date FROM account_price \
                  WHERE account_ref = $1 AND product_ref = $2 AND (is_active IS NULL OR is_active = true)",
            )
            .bind(account)
            .bind(product)
            .fetch_all(&mut **tx)
            .await
            .map_err(AppError::internal)?;
        inputs.account_prices = rows
            .into_iter()
            .map(|(id, cur, price, from, to)| AccountPrice {
                id,
                currency: cur.unwrap_or_default(),
                price: dec(price),
                valid: Validity { from, to },
            })
            .collect();
    }
    let lists: Vec<ListRow> = sqlx::query_as(
        "SELECT pl.id, pl.currency, pl.is_active_list, pl.valid_from::date, pl.valid_to::date, \
                i.id, COALESCE(i.list_price, i.price)::text, i.unit_ref \
           FROM price_list pl \
           LEFT JOIN price_list_item i ON i.price_list_ref = pl.id AND i.product_ref = $1 \
                                      AND (i.is_active IS NULL OR i.is_active = true) \
          WHERE upper(pl.currency) = upper($2) AND (pl.is_active IS NULL OR pl.is_active = true)",
    )
    .bind(product)
    .bind(currency)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let item_ids: Vec<Uuid> = lists.iter().filter_map(|l| l.5).collect();
    let breaks: Vec<PriceBreakRow> = sqlx::query_as(
        "SELECT id, price_list_item_ref, min_quantity::text, price::text, discount_percent::text \
               FROM price_break WHERE price_list_item_ref = ANY($1) \
                AND (is_active IS NULL OR is_active = true)",
    )
    .bind(&item_ids)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let mut by_item: HashMap<Uuid, Vec<PriceBreak>> = HashMap::new();
    for (id, item, min, price, pct) in breaks {
        by_item.entry(item).or_default().push(PriceBreak {
            id,
            min_quantity: dec(min),
            price: opt_dec(price),
            discount_percent: opt_dec(pct),
        });
    }
    let mut units: Vec<Uuid> = lists.iter().filter_map(|l| l.7).collect();
    inputs.default_unit =
        sqlx::query_scalar::<_, Option<Uuid>>("SELECT default_unit_ref FROM product WHERE id = $1")
            .bind(product)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?
            .flatten();
    units.extend(inputs.default_unit);
    inputs.lists = lists
        .into_iter()
        .map(|(id, cur, active, from, to, item, price, unit)| PriceList {
            id,
            currency: cur.unwrap_or_default(),
            active: active == Some(true),
            valid: Validity { from, to },
            item: item.map(|item_id| ListItem {
                id: item_id,
                list_price: dec(price.clone()),
                unit,
                breaks: by_item.remove(&item_id).unwrap_or_default(),
            }),
        })
        .collect();
    let factors: Vec<(Uuid, Option<String>)> =
        sqlx::query_as("SELECT id, conversion_factor::text FROM unit WHERE id = ANY($1)")
            .bind(&units)
            .fetch_all(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    inputs.factors = factors
        .into_iter()
        .filter_map(|(id, f)| opt_dec(f).map(|f| (id, f)))
        .collect();
    Ok(inputs)
}

/// A line's total: quantity times unit price less its discount, never
/// below zero, to the currency's two decimals. Pure.
pub fn line_total(quantity: Decimal, unit_price: Decimal, discount: Decimal) -> Decimal {
    (quantity * unit_price - discount)
        .max(Decimal::ZERO)
        .round_dp(2)
}

/// The quote's totals from its lines and its own discount percent. Pure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct QuoteTotals {
    #[schema(value_type = String)]
    pub subtotal: Decimal,
    #[schema(value_type = String)]
    pub discount_total: Decimal,
    #[schema(value_type = String)]
    pub vat_estimate: Decimal,
    #[schema(value_type = String)]
    pub grand_total: Decimal,
}

/// (quantity, unit price, line discount, tax) per line. Pure.
pub fn totals(
    lines: &[(Decimal, Decimal, Decimal, Decimal)],
    discount_percent: Decimal,
) -> QuoteTotals {
    let subtotal: Decimal = lines.iter().map(|(q, p, _, _)| q * p).sum();
    let line_discounts: Decimal = lines.iter().map(|(_, _, d, _)| *d).sum();
    let after_lines = (subtotal - line_discounts).max(Decimal::ZERO);
    let quote_discount = after_lines * discount_percent / Decimal::ONE_HUNDRED;
    let discount_total = (line_discounts + quote_discount).round_dp(2);
    let vat_estimate: Decimal = lines
        .iter()
        .map(|(_, _, _, t)| *t)
        .sum::<Decimal>()
        .round_dp(2);
    let subtotal = subtotal.round_dp(2);
    QuoteTotals {
        subtotal,
        discount_total,
        vat_estimate,
        grand_total: (subtotal - discount_total + vat_estimate)
            .max(Decimal::ZERO)
            .round_dp(2),
    }
}

fn data_uuid(data: &Value, key: &str) -> Option<Uuid> {
    data.get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

fn data_text(data: &Value, key: &str) -> Option<String> {
    match data.get(key) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

type LineRow = (
    Uuid,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
);

/// The result of a reprice.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct QuoteRepriced {
    pub quote_id: Uuid,
    pub lines: usize,
    pub totals: QuoteTotals,
    pub row_version: i64,
}

/// Prices every line of the quote through D8 and writes the totals.
pub async fn reprice(
    state: &EngineState,
    ctx: &SecurityContext,
    quote: Uuid,
    if_match: i64,
) -> Result<QuoteRepriced, AppError> {
    ctx.require("quote", "update")?;
    ctx.require("quote_line", "update")?;
    let read = attome_records::entity_crud::read_record(state, ctx, "quote", quote).await?;
    let data = read.data();
    let currency = data_text(data, "currency")
        .ok_or_else(|| AppError::Validation("the quote has no currency".into()))?;
    let account = data_uuid(data, "account_ref");
    let discount_percent = opt_dec(data_text(data, "discount_percent")).unwrap_or(Decimal::ZERO);
    let today = Utc::now().date_naive();

    let (quote_entity, _, quote_attrs, _) =
        attome_records::entity_crud::resolve_entity(state, "quote").await?;
    let (line_entity, _, line_attrs, _) =
        attome_records::entity_crud::resolve_entity(state, "quote_line").await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query("SELECT id FROM quote WHERE id = $1 FOR UPDATE")
        .bind(quote)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let lines: Vec<LineRow> = sqlx::query_as(
        "SELECT id, product_ref, quantity::text, discount_amount::text, tax_amount::text, row_version \
           FROM quote_line WHERE quote_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY created_at, id",
    )
    .bind(quote)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let mut priced = Vec::with_capacity(lines.len());
    for (id, product, quantity, discount, tax, version) in &lines {
        let product =
            product.ok_or_else(|| AppError::Validation(format!("line {id} has no product")))?;
        let quantity = dec(quantity.clone());
        let inputs = load_price_inputs(&mut tx, account, product, &currency).await?;
        let request = PriceRequest {
            currency: currency.clone(),
            date: today,
            quantity,
            unit: None,
            default_unit: inputs.default_unit,
            account_price_list: None,
        };
        let price = resolve(
            &request,
            &inputs.account_prices,
            &[],
            &inputs.lists,
            &inputs.factors,
        )
        .ok_or_else(|| {
            AppError::Validation(format!(
                "product {product} has no price in {currency} for this account"
            ))
        })?;
        let discount = dec(discount.clone());
        let total = line_total(quantity, price.price, discount);
        let mut patch = Map::new();
        patch.insert("unit_price".into(), json!(price.price.to_string()));
        patch.insert("line_total".into(), json!(total.to_string()));
        update_one_as(
            &mut tx,
            state,
            Principal::Staff(ctx),
            "quote_line",
            line_entity,
            *id,
            &line_attrs,
            &patch,
            Some(ctx.user_id),
            *version,
            MutationMode::Strict,
        )
        .await?;
        priced.push((quantity, price.price, discount, dec(tax.clone())));
    }
    let sums = totals(&priced, discount_percent);
    let mut patch = Map::new();
    patch.insert("subtotal".into(), json!(sums.subtotal.to_string()));
    patch.insert(
        "discount_total".into(),
        json!(sums.discount_total.to_string()),
    );
    patch.insert("vat_estimate".into(), json!(sums.vat_estimate.to_string()));
    patch.insert("grand_total".into(), json!(sums.grand_total.to_string()));
    let result = update_one_as(
        &mut tx,
        state,
        Principal::Staff(ctx),
        "quote",
        quote_entity,
        quote,
        &quote_attrs,
        &patch,
        Some(ctx.user_id),
        if_match,
        MutationMode::Strict,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(QuoteRepriced {
        quote_id: quote,
        lines: lines.len(),
        totals: sums,
        row_version: result
            .new_row
            .as_ref()
            .and_then(|r| r.get("row_version"))
            .and_then(Value::as_i64)
            .unwrap_or(if_match + 1),
    })
}

/// The quote fields a new version carries over.
pub const VERSION_FIELDS: &[&str] = &[
    "name",
    "currency",
    "discount_percent",
    "expires_on",
    "account_ref",
    "opportunity_ref",
    "quote_number",
    "valid_from",
    "payment_terms",
    "terms",
    "subtotal",
    "discount_total",
    "vat_estimate",
    "grand_total",
];

/// The line fields a new version carries over.
pub const LINE_FIELDS: &[&str] = &[
    "product_ref",
    "quantity",
    "unit_price",
    "line_total",
    "discount_amount",
    "tax_amount",
];

/// The new version's quote fields. Pure.
pub fn version_fields(old: &Value, version: i64) -> Map<String, Value> {
    let mut out: Map<String, Value> = VERSION_FIELDS
        .iter()
        .filter_map(|k| {
            old.get(*k)
                .filter(|v| !v.is_null())
                .map(|v| ((*k).to_owned(), v.clone()))
        })
        .collect();
    out.insert("version".into(), json!(version));
    out.insert("status".into(), json!("draft"));
    out.insert("is_primary".into(), json!(false));
    out
}

/// A new version.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct QuoteVersioned {
    pub quote_id: Uuid,
    pub version: i64,
    pub lines: usize,
}

/// Copies the quote and its lines into a new draft version.
pub async fn new_version(
    state: &EngineState,
    ctx: &SecurityContext,
    quote: Uuid,
) -> Result<QuoteVersioned, AppError> {
    ctx.require("quote", "create")?;
    ctx.require("quote_line", "create")?;
    let read = attome_records::entity_crud::read_record(state, ctx, "quote", quote).await?;
    let old = read.data().clone();
    let number = data_text(&old, "quote_number");
    let (quote_entity, _, quote_attrs, _) =
        attome_records::entity_crud::resolve_entity(state, "quote").await?;
    let (_, _, line_attrs, _) =
        attome_records::entity_crud::resolve_entity(state, "quote_line").await?;
    let actor = MutationActor::fetch(state, ctx.user_id).await;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query("SELECT id FROM quote WHERE id = $1 FOR UPDATE")
        .bind(quote)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let latest: Option<i64> = match &number {
        Some(n) => sqlx::query_scalar(
            "SELECT max(version)::int8 FROM quote WHERE quote_number = $1 \
              AND (is_active IS NULL OR is_active = true)",
        )
        .bind(n)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?,
        None => None,
    };
    let current = old.get("version").and_then(Value::as_f64).map(|v| v as i64);
    let version = latest.or(current).unwrap_or(1) + 1;
    let created = create_one_as(
        &mut tx,
        state,
        Principal::Staff(ctx),
        "quote",
        &quote_attrs,
        &version_fields(&old, version),
        CreateStamp::staff(ctx.user_id, actor.org_ref),
        MutationMode::Strict,
    )
    .await?;
    attome_records::entity_crud::grant_creator_share(
        &mut tx,
        quote_entity,
        created.record_id,
        ctx.user_id,
    )
    .await?;
    let lines: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(l) FROM quote_line l WHERE quote_ref = $1 \
          AND (is_active IS NULL OR is_active = true) ORDER BY created_at, id",
    )
    .bind(quote)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for line in &lines {
        let mut body: Map<String, Value> = LINE_FIELDS
            .iter()
            .filter_map(|k| {
                line.get(*k)
                    .filter(|v| !v.is_null())
                    .map(|v| ((*k).to_owned(), v.clone()))
            })
            .collect();
        body.insert("quote_ref".into(), json!(created.record_id.to_string()));
        create_one_as(
            &mut tx,
            state,
            Principal::Staff(ctx),
            "quote_line",
            &line_attrs,
            &body,
            CreateStamp::staff(ctx.user_id, actor.org_ref),
            MutationMode::Strict,
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(QuoteVersioned {
        quote_id: created.record_id,
        version,
        lines: lines.len(),
    })
}

/// The primary quote set.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct QuotePrimarySet {
    pub quote_id: Uuid,
    pub opportunity_id: Uuid,
    /// The deal's quotes that stopped being primary.
    pub unset: Vec<Uuid>,
    pub row_version: i64,
}

/// Makes the quote its deal's one primary quote.
pub async fn make_primary(
    state: &EngineState,
    ctx: &SecurityContext,
    quote: Uuid,
    if_match: i64,
) -> Result<QuotePrimarySet, AppError> {
    ctx.require("quote", "update")?;
    let read = attome_records::entity_crud::read_record(state, ctx, "quote", quote).await?;
    let deal = data_uuid(read.data(), "opportunity_ref")
        .ok_or_else(|| AppError::Validation("the quote is on no deal".into()))?;
    let (quote_entity, _, quote_attrs, _) =
        attome_records::entity_crud::resolve_entity(state, "quote").await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query("SELECT id FROM opportunity WHERE id = $1 FOR UPDATE")
        .bind(deal)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let others: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT id, row_version FROM quote WHERE opportunity_ref = $1 AND id <> $2 \
          AND is_primary = true AND (is_active IS NULL OR is_active = true)",
    )
    .bind(deal)
    .bind(quote)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let mut off = Map::new();
    off.insert("is_primary".into(), json!(false));
    for (id, version) in &others {
        update_one_as(
            &mut tx,
            state,
            Principal::Staff(ctx),
            "quote",
            quote_entity,
            *id,
            &quote_attrs,
            &off,
            Some(ctx.user_id),
            *version,
            MutationMode::Strict,
        )
        .await?;
    }
    let mut on = Map::new();
    on.insert("is_primary".into(), json!(true));
    let result = update_one_as(
        &mut tx,
        state,
        Principal::Staff(ctx),
        "quote",
        quote_entity,
        quote,
        &quote_attrs,
        &on,
        Some(ctx.user_id),
        if_match,
        MutationMode::Strict,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(QuotePrimarySet {
        quote_id: quote,
        opportunity_id: deal,
        unset: others.into_iter().map(|(id, _)| id).collect(),
        row_version: result
            .new_row
            .as_ref()
            .and_then(|r| r.get("row_version"))
            .and_then(Value::as_i64)
            .unwrap_or(if_match + 1),
    })
}

pub(crate) fn if_match(headers: &axum::http::HeaderMap) -> Result<i64, AppError> {
    headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().trim_matches('"'))
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| AppError::Validation("If-Match: \"<row_version>\" is required".into()))
}

/// Prices a quote's lines.
///
/// Prices every line through the account's prices and the active price
/// list in the quote's currency (with quantity breaks), then writes the
/// quote's totals. A product without a price refuses the whole reprice.
/// Send the quote's `row_version` in `If-Match`.
#[utoipa::path(
    post,
    path = "/api/v1/sales/quotes/{id}/reprice",
    operation_id = "post_sales_quote_reprice",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The quote"),
        ("If-Match" = String, Header, description = "The quote's row_version"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Repriced", body = QuoteRepriced),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not update quotes", body = attome_types::ErrorResponse),
        (status = 404, description = "No such quote the caller may read", body = attome_types::ErrorResponse),
        (status = 409, description = "The quote or a line changed since it was read", body = attome_types::ErrorResponse),
        (status = 422, description = "A product has no price, or If-Match is missing", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_sales_quote_reprice(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
    axum::extract::Path(quote): axum::extract::Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> Result<axum::Json<QuoteRepriced>, AppError> {
    let expected = if_match(&headers)?;
    Ok(axum::Json(reprice(&state, &ctx, quote, expected).await?))
}

/// Starts a new version of a quote.
///
/// Copies the quote and its lines into a new draft with the next version
/// number and the same quote number; it is not primary. The earlier
/// version stays as it was.
#[utoipa::path(
    post,
    path = "/api/v1/sales/quotes/{id}/versions",
    operation_id = "post_sales_quote_version",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The quote to copy")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "The new version", body = QuoteVersioned),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not create quotes", body = attome_types::ErrorResponse),
        (status = 404, description = "No such quote the caller may read", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_sales_quote_version(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
    axum::extract::Path(quote): axum::extract::Path<Uuid>,
) -> Result<axum::Json<QuoteVersioned>, AppError> {
    Ok(axum::Json(new_version(&state, &ctx, quote).await?))
}

/// Makes a quote its deal's primary quote.
///
/// Clears the flag on the deal's other quotes, under the deal's lock. The
/// deal's lines follow the primary through the quote sync route. Send the
/// quote's `row_version` in `If-Match`.
#[utoipa::path(
    post,
    path = "/api/v1/sales/quotes/{id}/primary",
    operation_id = "post_sales_quote_primary",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The quote"),
        ("If-Match" = String, Header, description = "The quote's row_version"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The quote is the deal's primary", body = QuotePrimarySet),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not update quotes", body = attome_types::ErrorResponse),
        (status = 404, description = "No such quote the caller may read", body = attome_types::ErrorResponse),
        (status = 409, description = "A quote changed since it was read", body = attome_types::ErrorResponse),
        (status = 422, description = "The quote is on no deal, or If-Match is missing", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_sales_quote_primary(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
    axum::extract::Path(quote): axum::extract::Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> Result<axum::Json<QuotePrimarySet>, AppError> {
    let expected = if_match(&headers)?;
    Ok(axum::Json(
        make_primary(&state, &ctx, quote, expected).await?,
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        post_sales_quote_reprice,
        post_sales_quote_version,
        post_sales_quote_primary
    ),
    components(schemas(QuoteRepriced, QuoteVersioned, QuotePrimarySet, QuoteTotals))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    #[test]
    fn quote_versions_copy_the_terms_as_a_draft() {
        let old = json!({
            "name": "Q-1", "currency": "SAR", "quote_number": "Q-0007", "version": 2,
            "status": "sent", "is_primary": true, "decided_at": "2026-10-01", "terms": null
        });
        let new = version_fields(&old, 3);
        assert_eq!(new["version"], 3);
        assert_eq!(new["status"], "draft");
        assert_eq!(new["is_primary"], false);
        assert_eq!(new["quote_number"], "Q-0007");
        assert!(
            !new.contains_key("decided_at"),
            "a decision is not carried over"
        );
        assert!(
            !new.contains_key("terms"),
            "empty values are not carried over"
        );
    }

    #[test]
    fn quote_versions_total_the_lines() {
        assert_eq!(line_total(d("3"), d("100"), d("50")), d("250"));
        assert_eq!(line_total(d("1"), d("10"), d("50")), d("0"));
        let t = totals(
            &[
                (d("3"), d("100"), d("50"), d("37.5")),
                (d("1"), d("200"), d("0"), d("30")),
            ],
            d("10"),
        );
        // 500 before discounts; 50 off the lines, then 10% of 450.
        assert_eq!(t.subtotal, d("500"));
        assert_eq!(t.discount_total, d("95"));
        assert_eq!(t.vat_estimate, d("67.5"));
        assert_eq!(t.grand_total, d("472.5"));
    }
}
