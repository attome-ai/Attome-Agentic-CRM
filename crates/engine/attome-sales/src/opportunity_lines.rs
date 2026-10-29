//! Opportunity lines (roadmap D6-T4): list, add, change and remove a deal's
//! lines and set its deal discount. Every change runs in one transaction
//! under the deal's lock and with the deal's `If-Match` row version: the
//! lines are repriced together ([`crate::pricing`]), each line's total is
//! stored, the deal's totals and amount are written (amount = one-time
//! total plus a year of recurring value), and the stored split amounts are
//! recalculated ([`crate::split_store::recalculate_in_tx`]).
//!
//! A line's product must be on the deal's price list, in the deal's
//! currency (`422 product_not_on_price_list`); its list price comes from
//! the price list, never the caller. `opportunity_line` is written only
//! here.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::pricing::{LineKind, PriceInput};
use crate::split_store::OpportunityUpdate;

/// `opportunity.read`: may read a deal's lines.
#[derive(Debug)]
pub struct OpportunityRead;

impl PrivilegeKey for OpportunityRead {
    const KEY: &'static str = "opportunity.read";
}

/// Most lines one page lists.
pub const MAX_LINES_PAGE: i64 = 500;

fn dec(text: Option<&str>) -> Option<Decimal> {
    text.and_then(|t| t.trim().parse().ok())
}

fn parse_dec(field: &str, text: &str) -> Result<Decimal, AppError> {
    text.trim()
        .parse()
        .map_err(|_| AppError::Validation(format!("{field} is not a number")))
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers.get(IF_MATCH).ok_or_else(|| {
        AppError::Validation("If-Match: \"<row_version>\" of the opportunity is required".into())
    })?;
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

fn opportunity_entity(state: &EngineState) -> Result<Uuid, AppError> {
    state
        .entities
        .load()
        .get("opportunity")
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)
}

async fn require(
    state: &EngineState,
    ctx: &SecurityContext,
    opportunity: Uuid,
    action: RecordAction,
) -> Result<(), AppError> {
    // D6-T13: lines stay hidden until their flag is on.
    if !state
        .feature_flags()
        .is_on(crate::flags::OPPORTUNITY_LINES, ctx)
        .await
    {
        return Err(AppError::NotFound);
    }
    let entity = opportunity_entity(state)?;
    attome_records::entity_crud::require_record_access(
        state,
        ctx,
        entity,
        "opportunity",
        opportunity,
        action,
    )
    .await
}

/// A recurring line's kind from its stored recurrence and term.
pub fn line_kind(kind: Option<&str>, recurrence: Option<&str>, term: Option<Decimal>) -> LineKind {
    if kind != Some("recurring") {
        return LineKind::OneTime;
    }
    let per_year_factor = if recurrence == Some("yearly") {
        Decimal::ONE
    } else {
        Decimal::from(12)
    };
    let term_months = term
        .and_then(|t| t.trunc().to_string().parse::<u32>().ok())
        .filter(|t| *t > 0)
        .unwrap_or(12);
    LineKind::Recurring {
        per_year_factor,
        term_months,
    }
}

type LineRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Reprices every live line of the deal and writes the totals, inside the
/// caller's transaction (which holds the deal's lock and row).
pub async fn reprice_in_tx(
    tx: &mut attome_db::Tx<'_>,
    opportunity: Uuid,
) -> Result<crate::pricing::Totals, AppError> {
    let discount: Option<String> =
        sqlx::query_scalar("SELECT deal_discount_percent::text FROM opportunity WHERE id = $1")
            .bind(opportunity)
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    let rows: Vec<LineRow> = sqlx::query_as(
        "SELECT id, quantity::text, list_price::text, sales_price::text, discount_percent::text, \
                discount_amount::text, line_kind, recurrence, term_months::text \
         FROM opportunity_line \
         WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true) \
         ORDER BY sort_order NULLS LAST, id",
    )
    .bind(opportunity)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let inputs: Vec<PriceInput> = rows
        .iter()
        .map(
            |(id, qty, list, sales, pct, amt, kind, rec, term)| PriceInput {
                line_id: *id,
                quantity: dec(qty.as_deref()).unwrap_or(Decimal::ONE),
                list_price: dec(list.as_deref()).unwrap_or(Decimal::ZERO),
                sales_price: dec(sales.as_deref()),
                discount_percent: dec(pct.as_deref()),
                discount_amount: dec(amt.as_deref()),
                kind: line_kind(kind.as_deref(), rec.as_deref(), dec(term.as_deref())),
            },
        )
        .collect();
    let priced = crate::pricing::price_lines(&inputs, dec(discount.as_deref()), 2);
    for line in &priced {
        sqlx::query(
            "UPDATE opportunity_line SET line_total = $2::numeric, modified_at = now(), \
                 row_version = row_version + 1 \
             WHERE id = $1 AND line_total IS DISTINCT FROM $2::numeric",
        )
        .bind(line.line_id)
        .bind(line.line_total.to_string())
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }
    let totals = crate::pricing::totals(&priced, &inputs);
    let has_lines = !priced.is_empty();
    sqlx::query(
        "UPDATE opportunity SET has_lines = $2, one_time_total = $3::numeric, \
             recurring_annual = $4::numeric, total_contract_value = $5::numeric, \
             amount = CASE WHEN $2 THEN $3::numeric + $4::numeric ELSE amount END, \
             modified_at = now(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(opportunity)
    .bind(has_lines)
    .bind(totals.one_time_total.to_string())
    .bind(totals.recurring_annual.to_string())
    .bind(totals.total_contract_value.to_string())
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    crate::split_store::recalculate_in_tx(tx, opportunity).await?;
    Ok(totals)
}

/// Opens the change: the deal's lock, its row at the expected version, and
/// its price list and currency.
async fn begin_change<'a>(
    state: &'a EngineState,
    opportunity: Uuid,
    expected: i64,
) -> Result<(attome_db::Tx<'a>, Option<Uuid>, Option<String>), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    crate::split_store::lock_deal(&mut tx, opportunity).await?;
    let row: Option<(i64, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT row_version, price_list_ref, currency FROM opportunity \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(opportunity)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((version, price_list, currency)) = row else {
        return Err(AppError::NotFound);
    };
    if version != expected {
        return Err(AppError::VersionConflict);
    }
    Ok((tx, price_list, currency))
}

/// The product's list price on the deal's price list, in its currency.
async fn list_price(
    tx: &mut attome_db::Tx<'_>,
    price_list: Option<Uuid>,
    currency: Option<&str>,
    product: Uuid,
) -> Result<Decimal, AppError> {
    let refused = || {
        AppError::Validation(
            "product_not_on_price_list: the product is not on this deal's price list in its currency"
                .into(),
        )
    };
    let Some(price_list) = price_list else {
        return Err(refused());
    };
    let price: Option<Option<String>> = sqlx::query_scalar(
        "SELECT COALESCE(i.list_price, i.price)::text FROM price_list_item i \
         JOIN price_list l ON l.id = i.price_list_ref \
         WHERE i.price_list_ref = $1 AND i.product_ref = $2 \
           AND (i.is_active IS NULL OR i.is_active = true) \
           AND (l.is_active IS NULL OR l.is_active = true) \
           AND COALESCE(l.is_active_list, true) \
           AND (l.valid_from IS NULL OR l.valid_from::date <= now()::date) \
           AND (l.valid_to IS NULL OR l.valid_to::date >= now()::date) \
           AND ($3::text IS NULL OR l.currency IS NULL OR l.currency = $3) \
         LIMIT 1",
    )
    .bind(price_list)
    .bind(product)
    .bind(currency)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    dec(price.flatten().as_deref()).ok_or_else(refused)
}

async fn event(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    record: Uuid,
    operation: AuditOperation,
    name: &str,
    actor: Uuid,
) -> Result<(), AppError> {
    attome_audit::write_business_event_in_tx(
        tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new("opportunity_line", record, operation, name, actor),
    )
    .await?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesOpportunityLine {
    pub id: Uuid,
    pub product_ref: Option<Uuid>,
    pub name: Option<String>,
    pub quantity: Option<String>,
    pub list_price: Option<String>,
    pub sales_price: Option<String>,
    pub discount_percent: Option<String>,
    pub discount_amount: Option<String>,
    pub line_total: Option<String>,
    pub line_kind: Option<String>,
    pub recurrence: Option<String>,
    pub term_months: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LinesQuery {
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    pub page: Option<i64>,
    /// Up to 500.
    pub page_size: Option<i64>,
}

type ListRow = (
    Uuid,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// List a deal's lines
///
/// The opportunity's product lines with their prices, discounts and totals. Anyone who may read the
/// opportunity.
#[utoipa::path(
    get,
    path = "/api/v1/sales/opportunities/{id}/lines",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The opportunity"), LinesQuery),
    responses(
        (status = 200, description = "The deal's lines", body = PaginatedResponse<SalesOpportunityLine>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not read this opportunity", body = ErrorResponse),
        (status = 404, description = "No such opportunity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_sales_lines(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityRead>>,
    Path(opportunity): Path<Uuid>,
    Query(q): Query<LinesQuery>,
) -> Result<Json<PaginatedResponse<SalesOpportunityLine>>, AppError> {
    require(&state, &ctx, opportunity, RecordAction::Read).await?;
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(100).clamp(1, MAX_LINES_PAGE);
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM opportunity_line \
         WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(opportunity)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<ListRow> = sqlx::query_as(
        "SELECT id, product_ref, name, quantity::text, list_price::text, sales_price::text, \
                discount_percent::text, discount_amount::text, line_total::text, line_kind, \
                recurrence, term_months::text \
         FROM opportunity_line \
         WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true) \
         ORDER BY sort_order NULLS LAST, id LIMIT $2 OFFSET $3",
    )
    .bind(opportunity)
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items = rows
        .into_iter()
        .map(
            |(id, product, name, qty, list, sales, pct, amt, total, kind, rec, term)| {
                SalesOpportunityLine {
                    id,
                    product_ref: product,
                    name,
                    quantity: qty,
                    list_price: list,
                    sales_price: sales,
                    discount_percent: pct,
                    discount_amount: amt,
                    line_total: total,
                    line_kind: kind,
                    recurrence: rec,
                    term_months: term,
                }
            },
        )
        .collect();
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SalesLineBody {
    pub product_ref: Uuid,
    /// Decimal text; 1 when absent.
    #[serde(default)]
    pub quantity: Option<String>,
    #[serde(default)]
    pub sales_price: Option<String>,
    #[serde(default)]
    pub discount_percent: Option<String>,
    #[serde(default)]
    pub discount_amount: Option<String>,
    /// `one_time` (default) or `recurring`.
    #[serde(default)]
    pub line_kind: Option<String>,
    /// `monthly` or `yearly`, for a recurring line.
    #[serde(default)]
    pub recurrence: Option<String>,
    #[serde(default)]
    pub term_months: Option<i32>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesLinesChanged {
    pub opportunity_id: Uuid,
    pub line_id: Option<Uuid>,
    #[schema(value_type = String)]
    pub one_time_total: Decimal,
    #[schema(value_type = String)]
    pub recurring_annual: Decimal,
    #[schema(value_type = String)]
    pub total_contract_value: Decimal,
    /// D6-T8: for a deal discount, the snapshot that undoes it
    /// (`POST /api/v1/sales/undo/{snapshot_id}`, 30 minutes).
    pub snapshot_id: Option<Uuid>,
}

fn changed(opportunity: Uuid, line: Option<Uuid>, t: crate::pricing::Totals) -> SalesLinesChanged {
    SalesLinesChanged {
        opportunity_id: opportunity,
        line_id: line,
        one_time_total: t.one_time_total,
        recurring_annual: t.recurring_annual,
        total_contract_value: t.total_contract_value,
        snapshot_id: None,
    }
}

/// D6-T13: a recurring line needs the recurring-lines flag.
async fn check_recurring(
    state: &EngineState,
    ctx: &SecurityContext,
    kind: Option<&str>,
) -> Result<(), AppError> {
    if kind == Some("recurring")
        && !state
            .feature_flags()
            .is_on(crate::flags::RECURRING_LINES, ctx)
            .await
    {
        return Err(AppError::Validation(
            "recurring lines are not switched on (sales.recurring_lines)".into(),
        ));
    }
    Ok(())
}

fn check_kind(kind: Option<&str>, recurrence: Option<&str>) -> Result<(), AppError> {
    if !matches!(kind, None | Some("one_time" | "recurring")) {
        return Err(AppError::Validation(
            "line_kind is one_time or recurring".into(),
        ));
    }
    if !matches!(recurrence, None | Some("monthly" | "yearly")) {
        return Err(AppError::Validation(
            "recurrence is monthly or yearly".into(),
        ));
    }
    Ok(())
}

fn optional_dec(field: &str, text: Option<&str>) -> Result<Option<String>, AppError> {
    text.map(|t| parse_dec(field, t).map(|d| d.to_string()))
        .transpose()
}

/// Add a line to a deal
///
/// Adds a product from the deal's price list; every line is repriced, and the deal's totals, amount
/// and split amounts are written again in the same transaction. Needs the deal's `If-Match` row
/// version and update rights on it. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/sales/opportunities/{id}/lines",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The opportunity"),
        ("If-Match" = String, Header, description = "The opportunity's row_version, quoted"),
    ),
    request_body = SalesLineBody,
    responses(
        (status = 201, description = "The line is added and the deal repriced", body = SalesLinesChanged),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this opportunity", body = ErrorResponse),
        (status = 404, description = "No such opportunity", body = ErrorResponse),
        (status = 409, description = "Stale row_version, or the deal is being changed", body = ErrorResponse),
        (status = 422, description = "If-Match missing, a bad number, or product_not_on_price_list", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_sales_line(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path(opportunity): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<SalesLineBody>,
) -> Result<(StatusCode, Json<SalesLinesChanged>), AppError> {
    let expected = if_match(&headers)?;
    let changed = add_line(&state, &ctx, opportunity, expected, &body).await?;
    Ok((StatusCode::CREATED, Json(changed)))
}

/// Adds a line and reprices the deal, as the caller (the route and the
/// `sales.opportunity_line.add` agent action share it).
pub async fn add_line(
    state: &EngineState,
    ctx: &SecurityContext,
    opportunity: Uuid,
    expected: i64,
    body: &SalesLineBody,
) -> Result<SalesLinesChanged, AppError> {
    check_kind(body.line_kind.as_deref(), body.recurrence.as_deref())?;
    let quantity = optional_dec("quantity", body.quantity.as_deref())?.unwrap_or("1".into());
    let sales = optional_dec("sales_price", body.sales_price.as_deref())?;
    let pct = optional_dec("discount_percent", body.discount_percent.as_deref())?;
    let amt = optional_dec("discount_amount", body.discount_amount.as_deref())?;
    require(state, ctx, opportunity, RecordAction::Update).await?;
    check_recurring(state, ctx, body.line_kind.as_deref()).await?;
    let (mut tx, price_list, currency) = begin_change(state, opportunity, expected).await?;
    let list = list_price(&mut tx, price_list, currency.as_deref(), body.product_ref).await?;
    let line: Uuid = sqlx::query_scalar(
        "INSERT INTO opportunity_line \
           (opportunity_ref, product_ref, name, quantity, list_price, sales_price, \
            discount_percent, discount_amount, line_kind, recurrence, term_months, description, \
            owner_ref) \
         SELECT $1, $2, (SELECT name FROM product WHERE id = $2), $3::numeric, $4::numeric, \
                $5::numeric, $6::numeric, $7::numeric, COALESCE($8, 'one_time'), $9, $10, $11, \
                o.owner_ref \
         FROM opportunity o WHERE o.id = $1 RETURNING id",
    )
    .bind(opportunity)
    .bind(body.product_ref)
    .bind(&quantity)
    .bind(list.to_string())
    .bind(&sales)
    .bind(&pct)
    .bind(&amt)
    .bind(&body.line_kind)
    .bind(&body.recurrence)
    .bind(body.term_months)
    .bind(&body.description)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let totals = reprice_in_tx(&mut tx, opportunity).await?;
    event(
        &mut tx,
        state,
        line,
        AuditOperation::Create,
        "sales.line_added",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(changed(opportunity, Some(line), totals))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SalesLinePatch {
    #[serde(default)]
    pub quantity: Option<String>,
    #[serde(default)]
    pub sales_price: Option<String>,
    #[serde(default)]
    pub discount_percent: Option<String>,
    #[serde(default)]
    pub discount_amount: Option<String>,
    #[serde(default)]
    pub line_kind: Option<String>,
    #[serde(default)]
    pub recurrence: Option<String>,
    #[serde(default)]
    pub term_months: Option<i32>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Change a deal line
///
/// Changes the line's quantity, price or discount, then reprices the deal as adding a line does.
/// Needs the deal's `If-Match` row version and update rights on it. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/sales/opportunities/{id}/lines/{line_id}",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The opportunity"),
        ("line_id" = Uuid, Path, description = "The line"),
        ("If-Match" = String, Header, description = "The opportunity's row_version, quoted"),
    ),
    request_body = SalesLinePatch,
    responses(
        (status = 200, description = "The line is changed and the deal repriced", body = SalesLinesChanged),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this opportunity", body = ErrorResponse),
        (status = 404, description = "No such line on this opportunity", body = ErrorResponse),
        (status = 409, description = "Stale row_version, or the deal is being changed", body = ErrorResponse),
        (status = 422, description = "If-Match missing or a bad value", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn patch_sales_line(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path((opportunity, line)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<SalesLinePatch>,
) -> Result<Json<SalesLinesChanged>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(
        change_line(&state, &ctx, opportunity, line, expected, &body).await?,
    ))
}

/// Changes a line and reprices the deal, as the caller.
pub async fn change_line(
    state: &EngineState,
    ctx: &SecurityContext,
    opportunity: Uuid,
    line: Uuid,
    expected: i64,
    body: &SalesLinePatch,
) -> Result<SalesLinesChanged, AppError> {
    check_kind(body.line_kind.as_deref(), body.recurrence.as_deref())?;
    let quantity = optional_dec("quantity", body.quantity.as_deref())?;
    let sales = optional_dec("sales_price", body.sales_price.as_deref())?;
    let pct = optional_dec("discount_percent", body.discount_percent.as_deref())?;
    let amt = optional_dec("discount_amount", body.discount_amount.as_deref())?;
    require(state, ctx, opportunity, RecordAction::Update).await?;
    check_recurring(state, ctx, body.line_kind.as_deref()).await?;
    let (mut tx, _, _) = begin_change(state, opportunity, expected).await?;
    let updated = sqlx::query(
        "UPDATE opportunity_line SET \
             quantity = COALESCE($3::numeric, quantity), \
             sales_price = COALESCE($4::numeric, sales_price), \
             discount_percent = COALESCE($5::numeric, discount_percent), \
             discount_amount = COALESCE($6::numeric, discount_amount), \
             line_kind = COALESCE($7, line_kind), recurrence = COALESCE($8, recurrence), \
             term_months = COALESCE($9, term_months), description = COALESCE($10, description), \
             modified_at = now(), row_version = row_version + 1 \
         WHERE id = $2 AND opportunity_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(opportunity)
    .bind(line)
    .bind(&quantity)
    .bind(&sales)
    .bind(&pct)
    .bind(&amt)
    .bind(&body.line_kind)
    .bind(&body.recurrence)
    .bind(body.term_months)
    .bind(&body.description)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    let totals = reprice_in_tx(&mut tx, opportunity).await?;
    event(
        &mut tx,
        state,
        line,
        AuditOperation::Update,
        "sales.line_changed",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(changed(opportunity, Some(line), totals))
}

/// Remove a deal line
///
/// Removes the line and reprices the deal as adding a line does. Needs the deal's `If-Match` row
/// version and update rights on it. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/sales/opportunities/{id}/lines/{line_id}",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The opportunity"),
        ("line_id" = Uuid, Path, description = "The line"),
        ("If-Match" = String, Header, description = "The opportunity's row_version, quoted"),
    ),
    responses(
        (status = 200, description = "The line is removed and the deal repriced", body = SalesLinesChanged),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this opportunity", body = ErrorResponse),
        (status = 404, description = "No such line on this opportunity", body = ErrorResponse),
        (status = 409, description = "Stale row_version, or the deal is being changed", body = ErrorResponse),
        (status = 422, description = "If-Match missing", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::SoftDelete)])))),
)]
pub(crate) async fn delete_sales_line(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path((opportunity, line)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<SalesLinesChanged>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(
        remove_line(&state, &ctx, opportunity, line, expected).await?,
    ))
}

/// Removes a line (and its line splits) and reprices the deal, as the caller.
pub async fn remove_line(
    state: &EngineState,
    ctx: &SecurityContext,
    opportunity: Uuid,
    line: Uuid,
    expected: i64,
) -> Result<SalesLinesChanged, AppError> {
    require(state, ctx, opportunity, RecordAction::Update).await?;
    let (mut tx, _, _) = begin_change(state, opportunity, expected).await?;
    let removed = sqlx::query(
        "UPDATE opportunity_line SET is_active = false, modified_at = now(), \
             row_version = row_version + 1 \
         WHERE id = $2 AND opportunity_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(opportunity)
    .bind(line)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if removed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    // A split of a removed line has nothing left to divide.
    sqlx::query("DELETE FROM opportunity_split WHERE line_ref = $1")
        .bind(line)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let totals = reprice_in_tx(&mut tx, opportunity).await?;
    event(
        &mut tx,
        state,
        line,
        AuditOperation::SoftDelete,
        "sales.line_removed",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(changed(opportunity, Some(line), totals))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SalesDealDiscountBody {
    /// Decimal text, 0 to 100; null removes it.
    #[serde(default)]
    pub percent: Option<String>,
}

/// Set a deal's discount
///
/// Sets the discount over the whole deal and reprices its lines, totals and splits. Needs the deal's
/// `If-Match` row version and update rights on it. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/sales/opportunities/{id}/deal-discount",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The opportunity"),
        ("If-Match" = String, Header, description = "The opportunity's row_version, quoted"),
    ),
    request_body = SalesDealDiscountBody,
    responses(
        (status = 200, description = "The deal discount is set and the deal repriced", body = SalesLinesChanged),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this opportunity", body = ErrorResponse),
        (status = 404, description = "No such opportunity", body = ErrorResponse),
        (status = 409, description = "Stale row_version, or the deal is being changed", body = ErrorResponse),
        (status = 422, description = "If-Match missing, or a percent outside 0 to 100", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_sales_deal_discount(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path(opportunity): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<SalesDealDiscountBody>,
) -> Result<Json<SalesLinesChanged>, AppError> {
    let expected = if_match(&headers)?;
    let percent = body
        .percent
        .as_deref()
        .map(|p| parse_dec("percent", p))
        .transpose()?;
    if percent.is_some_and(|p| p.is_sign_negative() || p > Decimal::ONE_HUNDRED) {
        return Err(AppError::Validation("percent is 0 to 100".into()));
    }
    require(&state, &ctx, opportunity, RecordAction::Update).await?;
    let (mut tx, _, _) = begin_change(&state, opportunity, expected).await?;
    let before = crate::undo::capture_lines(&mut tx, opportunity).await?;
    let discount_before: Option<String> =
        sqlx::query_scalar("SELECT deal_discount_percent::text FROM opportunity WHERE id = $1")
            .bind(opportunity)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    sqlx::query("UPDATE opportunity SET deal_discount_percent = $2::numeric WHERE id = $1")
        .bind(opportunity)
        .bind(percent.map(|p| p.to_string()))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let totals = reprice_in_tx(&mut tx, opportunity).await?;
    let snapshot = crate::undo::record_in_tx(&mut tx, opportunity, before, ctx.user_id).await?;
    crate::undo::record_discount_in_tx(&mut tx, snapshot, discount_before.as_deref()).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "opportunity",
            opportunity,
            AuditOperation::Update,
            "sales.deal_discount_set",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(SalesLinesChanged {
        snapshot_id: Some(snapshot),
        ..changed(opportunity, None, totals)
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        get_sales_lines,
        post_sales_line,
        patch_sales_line,
        delete_sales_line,
        post_sales_deal_discount
    ),
    components(schemas(
        SalesOpportunityLine,
        SalesLineBody,
        SalesLinePatch,
        SalesLinesChanged,
        SalesDealDiscountBody
    ))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recurring_line_reads_its_recurrence_and_term() {
        assert_eq!(line_kind(None, None, None), LineKind::OneTime);
        assert_eq!(
            line_kind(Some("recurring"), Some("yearly"), Some(Decimal::from(36))),
            LineKind::Recurring {
                per_year_factor: Decimal::ONE,
                term_months: 36
            }
        );
        assert_eq!(
            line_kind(Some("recurring"), None, None),
            LineKind::Recurring {
                per_year_factor: Decimal::from(12),
                term_months: 12
            }
        );
    }

    #[test]
    fn kinds_and_recurrences_are_checked() {
        assert!(check_kind(Some("one_time"), None).is_ok());
        assert!(check_kind(Some("lease"), None).is_err());
        assert!(check_kind(None, Some("weekly")).is_err());
        assert!(optional_dec("quantity", Some("two")).is_err());
        assert_eq!(
            optional_dec("quantity", Some(" 2.5 "))
                .ok()
                .flatten()
                .as_deref(),
            Some("2.5")
        );
    }
}
