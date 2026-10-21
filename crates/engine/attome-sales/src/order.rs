//! D10-T2: sales orders from accepted quotes and won deals, and their
//! confirmation.
//!
//! - **From a quote** (`POST /api/v1/sales/quotes/{id}/order`): an
//!   `accepted` quote becomes a `draft` order with the quote's account,
//!   currency, payment terms and totals, and one order line per quote line
//!   (product, quantity, prices, discount, tax, line total and the quote
//!   line it came from).
//! - **From a won deal** (`POST /api/v1/sales/opportunities/{id}/order`): a
//!   `closed_won` opportunity with an accepted primary quote orders that
//!   quote; without one, its own lines are copied (the sales price as the
//!   unit price) and the order names the opportunity.
//!
//! Either way the source orders once: an order already made from it is
//! returned, and the work is serialised per source by
//! `pg_try_advisory_xact_lock(ADVISORY_LOCK_NAMESPACE,
//! hashtext('attome-sales/order:{kind}:{id}'))`, a held lock being a
//! conflict, never a wait. Records are written through the generic mutation
//! path as the caller, so record rules, numbering and audit apply.
//!
//! - **Confirm** (`POST /api/v1/sales/orders/{id}/confirm`): a `draft`
//!   order with lines passes the account's credit check for its grand total
//!   (F5, `attome_billing::payment::credit::credit_check`), or is refused
//!   with the reason. Its lines are then locked (`is_locked`, which the
//!   pack's `order_line_locked_after_confirm` rule turns into fixed prices),
//!   an invoice request goes to billing (F4-T9, keyed on the order, so a
//!   retry asks once), and the order moves to `confirmed` through its state
//!   model, after which `order_locked_after_confirm` locks it. The
//!   `sales.order.confirmed` business event and the status are what
//!   fulfilment (F6) and contracts (W1-T13) read. Each step is safe to
//!   repeat, so a confirm that failed half way is simply retried.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::str::FromStr;
use utoipa::ToSchema;
use uuid::Uuid;

/// Most lines one order takes.
pub const MAX_LINES: i64 = 500;
/// The invoice request's `source_kind`.
pub const INVOICE_SOURCE: &str = "order";

/// `order.create`: may create orders.
#[derive(Debug)]
pub struct OrderCreate;

impl PrivilegeKey for OrderCreate {
    const KEY: &'static str = "order.create";
}

/// `order.update`: may change orders.
#[derive(Debug)]
pub struct OrderUpdate;

impl PrivilegeKey for OrderUpdate {
    const KEY: &'static str = "order.update";
}

/// An order made, or the one already made from the same source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct OrderMade {
    pub order_id: Uuid,
    /// False when the source had already been ordered.
    pub created: bool,
    pub lines: usize,
}

/// A confirmed order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct OrderConfirmed {
    pub order_id: Uuid,
    pub status: String,
    /// The billing invoice request it handed off.
    pub invoice_request_id: Uuid,
}

/// One line to copy onto an order.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LineCopy {
    pub product_ref: Option<Uuid>,
    pub description: Option<String>,
    pub quantity: Option<String>,
    pub unit_price: Option<String>,
    pub discount_amount: Option<String>,
    pub tax_amount: Option<String>,
    pub line_total: Option<String>,
    pub quote_line_ref: Option<Uuid>,
}

/// An order line's body for the generic create. Pure.
pub fn line_body(order: Uuid, line: &LineCopy) -> Value {
    let mut body = Map::new();
    body.insert("order_ref".into(), json!(order));
    let mut put = |key: &str, value: Option<Value>| {
        if let Some(value) = value {
            body.insert(key.into(), value);
        }
    };
    put("product_ref", line.product_ref.map(|id| json!(id)));
    put("description", line.description.clone().map(Value::String));
    for (key, value) in [
        ("quantity", &line.quantity),
        ("unit_price", &line.unit_price),
        ("discount_amount", &line.discount_amount),
        ("tax_amount", &line.tax_amount),
        ("line_total", &line.line_total),
    ] {
        put(key, value.as_deref().and_then(number));
    }
    put("quote_line_ref", line.quote_line_ref.map(|id| json!(id)));
    Value::Object(body)
}

/// A stored numeric's text as a JSON number. Pure.
pub fn number(text: &str) -> Option<Value> {
    serde_json::Number::from_str(text.trim())
        .ok()
        .map(Value::Number)
}

/// The sum of the lines' totals. Pure.
pub fn lines_total(lines: &[LineCopy]) -> Decimal {
    lines
        .iter()
        .filter_map(|l| l.line_total.as_deref())
        .filter_map(|t| Decimal::from_str(t.trim()).ok())
        .sum()
}

/// What a confirm checks before it changes anything. Pure.
pub fn confirmable(status: Option<&str>, lines: usize) -> Result<(), AppError> {
    match status {
        Some("draft") | None => {}
        Some(_) => return Err(AppError::Conflict("only a draft order can be confirmed")),
    }
    if lines == 0 {
        return Err(AppError::Validation("an order needs at least one line".into()));
    }
    Ok(())
}

fn lock_key(kind: &str, id: Uuid) -> String {
    format!("attome-sales/order:{kind}:{id}")
}

/// Takes the source's lock in `tx`; a held lock is a conflict.
async fn lock(tx: &mut attome_db::Tx<'_>, key: &str) -> Result<(), AppError> {
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(key)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if got {
        Ok(())
    } else {
        Err(AppError::Conflict("this order is being made or confirmed"))
    }
}

type QuoteRow = (
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

type LineRow = (
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
);

fn line_copy(row: LineRow) -> LineCopy {
    let (product_ref, description, quantity, unit_price, discount, tax, total, quote_line) = row;
    LineCopy {
        product_ref,
        description,
        quantity,
        unit_price,
        discount_amount: discount,
        tax_amount: tax,
        line_total: total,
        quote_line_ref: quote_line,
    }
}

/// The order already made from a source, if any.
async fn existing(state: &EngineState, column: &str, id: Uuid) -> Result<Option<Uuid>, AppError> {
    let sql = format!(
        "SELECT id FROM \"order\" WHERE {} = $1 AND (is_active IS NULL OR is_active = true) \
         ORDER BY created_at LIMIT 1",
        attome_core::quote_ident(column)
    );
    sqlx::query_scalar(&sql)
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)
}

/// Writes the order and its lines as the caller.
async fn write_order(
    state: &EngineState,
    ctx: &SecurityContext,
    head: Value,
    lines: &[LineCopy],
) -> Result<Uuid, AppError> {
    let (order, _) =
        attome_records::entity_crud::create_record_for(state, ctx, ctx.user_id, "order", head)
            .await?;
    for line in lines {
        attome_records::entity_crud::create_record_for(
            state,
            ctx,
            ctx.user_id,
            "order_line",
            line_body(order, line),
        )
        .await?;
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "order",
            order,
            AuditOperation::Create,
            "sales.order.created",
            ctx.user_id,
        )
        .comment(format!("{} line(s)", lines.len())),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(order)
}

/// Makes the order for an accepted quote, once.
pub async fn order_from_quote(
    state: &EngineState,
    ctx: &SecurityContext,
    quote: Uuid,
) -> Result<OrderMade, AppError> {
    attome_records::entity_crud::read_record_bulk(state, ctx, "quote", quote).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, &lock_key("quote", quote)).await?;
    let made = order_quote_locked(state, ctx, quote, None).await;
    attome_db::tx::commit(tx).await?;
    made
}

/// The body of [`order_from_quote`], under the source's lock.
async fn order_quote_locked(
    state: &EngineState,
    ctx: &SecurityContext,
    quote: Uuid,
    opportunity: Option<Uuid>,
) -> Result<OrderMade, AppError> {
    if let Some(order) = existing(state, "quote_ref", quote).await? {
        return Ok(OrderMade {
            order_id: order,
            created: false,
            lines: 0,
        });
    }
    let row: Option<QuoteRow> = sqlx::query_as(
        "SELECT status::text, account_ref, currency, name, payment_terms, subtotal::text, \
                discount_total::text, vat_estimate::text, grand_total::text \
           FROM quote WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(quote)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (status, account, currency, name, terms, subtotal, discount, vat, grand) =
        row.ok_or(AppError::NotFound)?;
    if status.as_deref() != Some("accepted") {
        return Err(AppError::Conflict("only an accepted quote can be ordered"));
    }
    let lines: Vec<LineCopy> = sqlx::query_as::<_, LineRow>(
        "SELECT product_ref, NULL::text, quantity::text, unit_price::text, \
                discount_amount::text, tax_amount::text, line_total::text, id \
           FROM quote_line WHERE quote_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY created_at, id LIMIT $2",
    )
    .bind(quote)
    .bind(MAX_LINES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .map(line_copy)
    .collect();
    let mut head = json!({
        "name": name.unwrap_or_else(|| "Order".to_owned()),
        "status": "draft",
        "ordered_on": chrono::Utc::now().date_naive(),
        "account_ref": account,
        "quote_ref": quote,
        "currency": currency,
        "payment_terms": terms,
    });
    if let Some(opportunity) = opportunity {
        head["opportunity_ref"] = json!(opportunity);
    }
    for (key, value) in [
        ("subtotal", subtotal),
        ("discount_total", discount),
        ("tax_total", vat),
        ("grand_total", grand),
    ] {
        if let Some(n) = value.as_deref().and_then(number) {
            head[key] = n;
        }
    }
    let order = write_order(state, ctx, head, &lines).await?;
    tracing::info!(%order, %quote, lines = lines.len(), "order made from a quote");
    Ok(OrderMade {
        order_id: order,
        created: true,
        lines: lines.len(),
    })
}

/// Makes the order for a won opportunity, once.
pub async fn order_from_opportunity(
    state: &EngineState,
    ctx: &SecurityContext,
    opportunity: Uuid,
) -> Result<OrderMade, AppError> {
    attome_records::entity_crud::read_record_bulk(state, ctx, "opportunity", opportunity).await?;
    let row: Option<(Option<String>, Option<Uuid>, Option<String>, Option<String>)> =
        sqlx::query_as(
            "SELECT stage::text, account_ref, currency, name FROM opportunity \
              WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(opportunity)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let (stage, account, currency, name) = row.ok_or(AppError::NotFound)?;
    if stage.as_deref() != Some("closed_won") {
        return Err(AppError::Conflict("only a won opportunity can be ordered"));
    }
    let quote: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM quote WHERE opportunity_ref = $1 AND status::text = 'accepted' \
           AND (is_active IS NULL OR is_active = true) \
         ORDER BY is_primary DESC NULLS LAST, created_at DESC LIMIT 1",
    )
    .bind(opportunity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, &lock_key("opportunity", opportunity)).await?;
    let made = match quote {
        Some(quote) => {
            let mut quote_tx = attome_db::tx::begin(&state.base.db).await?;
            lock(&mut quote_tx, &lock_key("quote", quote)).await?;
            let made = order_quote_locked(state, ctx, quote, Some(opportunity)).await;
            attome_db::tx::commit(quote_tx).await?;
            made
        }
        None => order_lines_locked(state, ctx, opportunity, account, currency, name).await,
    };
    attome_db::tx::commit(tx).await?;
    made
}

/// A won deal without an accepted quote: its own lines become the order.
async fn order_lines_locked(
    state: &EngineState,
    ctx: &SecurityContext,
    opportunity: Uuid,
    account: Option<Uuid>,
    currency: Option<String>,
    name: Option<String>,
) -> Result<OrderMade, AppError> {
    if let Some(order) = existing(state, "opportunity_ref", opportunity).await? {
        return Ok(OrderMade {
            order_id: order,
            created: false,
            lines: 0,
        });
    }
    let lines: Vec<LineCopy> = sqlx::query_as::<_, LineRow>(
        "SELECT product_ref, COALESCE(description, name), quantity::text, sales_price::text, \
                discount_amount::text, NULL::text, line_total::text, NULL::uuid \
           FROM opportunity_line \
          WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY sort_order NULLS LAST, created_at, id LIMIT $2",
    )
    .bind(opportunity)
    .bind(MAX_LINES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .map(line_copy)
    .collect();
    if lines.is_empty() {
        return Err(AppError::Validation(
            "the opportunity has no lines and no accepted quote to order".into(),
        ));
    }
    let total = lines_total(&lines).to_string();
    let mut head = json!({
        "name": name.unwrap_or_else(|| "Order".to_owned()),
        "status": "draft",
        "ordered_on": chrono::Utc::now().date_naive(),
        "account_ref": account,
        "opportunity_ref": opportunity,
        "currency": currency,
    });
    if let Some(n) = number(&total) {
        head["subtotal"] = n.clone();
        head["grand_total"] = n;
    }
    let order = write_order(state, ctx, head, &lines).await?;
    tracing::info!(%order, %opportunity, lines = lines.len(), "order made from a won deal");
    Ok(OrderMade {
        order_id: order,
        created: true,
        lines: lines.len(),
    })
}

/// Confirms a draft order: credit check, price lock, invoice request, then
/// the status.
pub async fn confirm(
    state: &EngineState,
    ctx: &SecurityContext,
    order: Uuid,
) -> Result<OrderConfirmed, AppError> {
    attome_records::entity_crud::read_record_bulk(state, ctx, "order", order).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, &lock_key("confirm", order)).await?;
    let confirmed = confirm_locked(state, ctx, order).await;
    attome_db::tx::commit(tx).await?;
    confirmed
}

type OrderRow = (
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
);

/// An order line as confirm reads it: id, version, lock, then a [`LineRow`].
type ConfirmLineRow = (
    Uuid,
    i64,
    Option<bool>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
);

async fn confirm_locked(
    state: &EngineState,
    ctx: &SecurityContext,
    order: Uuid,
) -> Result<OrderConfirmed, AppError> {
    let db = &state.base.db;
    let row: Option<OrderRow> = sqlx::query_as(
        "SELECT status::text, account_ref, currency, grand_total::text, order_number, \
                row_version::bigint \
           FROM \"order\" WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(order)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (status, account, currency, grand, number_text, version) = row.ok_or(AppError::NotFound)?;
    let lines: Vec<(Uuid, i64, Option<bool>, LineRow)> = sqlx::query_as::<_, ConfirmLineRow>(
        "SELECT l.id, l.row_version::bigint, l.is_locked, l.product_ref, \
                COALESCE(l.description, p.name), l.quantity::text, l.unit_price::text, \
                l.discount_amount::text, l.tax_amount::text, l.line_total::text, l.quote_line_ref \
           FROM order_line l LEFT JOIN product p ON p.id = l.product_ref \
          WHERE l.order_ref = $1 AND (l.is_active IS NULL OR l.is_active = true) \
          ORDER BY l.created_at, l.id LIMIT $2",
    )
    .bind(order)
    .bind(MAX_LINES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .map(|(id, v, locked, p, d, q, u, disc, tax, total, ql)| {
        (id, v, locked, (p, d, q, u, disc, tax, total, ql))
    })
    .collect();
    confirmable(status.as_deref(), lines.len())?;
    let account = account.ok_or_else(|| AppError::Validation("the order has no account".into()))?;
    let currency =
        currency.ok_or_else(|| AppError::Validation("the order has no currency".into()))?;
    let copies: Vec<LineCopy> = lines
        .iter()
        .map(|(_, _, _, row)| line_copy(row.clone()))
        .collect();
    let amount = grand
        .as_deref()
        .and_then(|g| Decimal::from_str(g.trim()).ok())
        .unwrap_or_else(|| lines_total(&copies));
    let credit = attome_billing::payment::credit::credit_check(state, account, amount).await?;
    if !credit.allowed {
        return Err(AppError::Validation(format!(
            "credit check: {}",
            credit.reason.as_deref().unwrap_or("refused")
        )));
    }
    for (id, line_version, locked, _) in &lines {
        if *locked != Some(true) {
            attome_records::entity_crud::update_record_for(
                state,
                ctx,
                ctx.user_id,
                "order_line",
                *id,
                *line_version,
                json!({ "is_locked": true }),
            )
            .await?;
        }
    }
    let label = number_text.unwrap_or_else(|| order.to_string());
    let request = attome_billing::requests::InvoiceRequest {
        source_kind: INVOICE_SOURCE.to_owned(),
        source_ref: order.to_string(),
        idempotency_key: order.to_string(),
        account_ref: account,
        currency,
        request_date: None,
        lines: copies
            .iter()
            .enumerate()
            .map(|(i, line)| request_line(&label, i, line))
            .collect::<Result<_, _>>()?,
    };
    let requested = attome_billing::requests::submit_request(state, ctx, &request).await?;
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        "order",
        order,
        version,
        json!({ "status": "confirmed" }),
    )
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "order",
            order,
            AuditOperation::Update,
            "sales.order.confirmed",
            ctx.user_id,
        )
        .comment(format!("invoice request {}", requested.request_id)),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    tracing::info!(%order, request = %requested.request_id, "order confirmed");
    Ok(OrderConfirmed {
        order_id: order,
        status: "confirmed".to_owned(),
        invoice_request_id: requested.request_id,
    })
}

/// One order line as an invoice request line. A line's net unit price is
/// its total over its quantity when it carries a discount.
fn request_line(
    label: &str,
    index: usize,
    line: &LineCopy,
) -> Result<attome_billing::requests::RequestLine, AppError> {
    let quantity = line
        .quantity
        .as_deref()
        .and_then(|q| Decimal::from_str(q.trim()).ok())
        .filter(|q| !q.is_zero())
        .unwrap_or(Decimal::ONE);
    let unit = match (line.line_total.as_deref(), line.unit_price.as_deref()) {
        (Some(total), _) => Decimal::from_str(total.trim()).ok().map(|t| t / quantity),
        (None, Some(price)) => Decimal::from_str(price.trim()).ok(),
        (None, None) => None,
    }
    .ok_or_else(|| AppError::Validation(format!("line {} has no price", index + 1)))?;
    let as_number = |d: Decimal| {
        serde_json::Number::from_str(&d.round_dp(6).normalize().to_string())
            .map_err(|_| AppError::Validation(format!("line {} has a bad amount", index + 1)))
    };
    Ok(attome_billing::requests::RequestLine {
        description: line
            .description
            .clone()
            .filter(|d| !d.trim().is_empty())
            .unwrap_or_else(|| format!("{label} line {}", index + 1)),
        quantity: as_number(quantity)?,
        unit_price: as_number(unit)?,
        vat_category: None,
        product_ref: line.product_ref,
        period_from: None,
        period_to: None,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/quotes/{id}/order",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The accepted quote")),
    responses(
        (status = 201, description = "The order is made, or the one already made from this quote is returned", body = OrderMade),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not create orders or read the quote", body = ErrorResponse),
        (status = 404, description = "No such quote", body = ErrorResponse),
        (status = 409, description = "The quote is not accepted, or it is being ordered", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_sales_quote_order(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OrderCreate>>,
    Path(quote): Path<Uuid>,
) -> Result<(StatusCode, Json<OrderMade>), AppError> {
    Ok((
        StatusCode::CREATED,
        Json(order_from_quote(&state, &ctx, quote).await?),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/opportunities/{id}/order",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The won opportunity")),
    responses(
        (status = 201, description = "The order is made from the accepted quote or the deal's lines, or the one already made is returned", body = OrderMade),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not create orders or read the opportunity", body = ErrorResponse),
        (status = 404, description = "No such opportunity", body = ErrorResponse),
        (status = 409, description = "The opportunity is not won, or it is being ordered", body = ErrorResponse),
        (status = 422, description = "No lines and no accepted quote to order", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_sales_opportunity_order(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OrderCreate>>,
    Path(opportunity): Path<Uuid>,
) -> Result<(StatusCode, Json<OrderMade>), AppError> {
    Ok((
        StatusCode::CREATED,
        Json(order_from_opportunity(&state, &ctx, opportunity).await?),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/orders/{id}/confirm",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The draft order")),
    responses(
        (status = 200, description = "The order passed the credit check, its prices are locked, billing has its invoice request and it is confirmed", body = OrderConfirmed),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not change this order", body = ErrorResponse),
        (status = 404, description = "No such order", body = ErrorResponse),
        (status = 409, description = "The order is not a draft, or it is being confirmed", body = ErrorResponse),
        (status = 422, description = "No lines, no account or currency, a line without a price, or the credit check refused (the reason is given)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_sales_order_confirm(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OrderUpdate>>,
    Path(order): Path<Uuid>,
) -> Result<Json<OrderConfirmed>, AppError> {
    Ok(Json(confirm(&state, &ctx, order).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        post_sales_quote_order,
        post_sales_opportunity_order,
        post_sales_order_confirm
    ),
    components(schemas(OrderMade, OrderConfirmed))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn line(total: Option<&str>, quantity: Option<&str>, price: Option<&str>) -> LineCopy {
        LineCopy {
            quantity: quantity.map(str::to_owned),
            unit_price: price.map(str::to_owned),
            line_total: total.map(str::to_owned),
            ..LineCopy::default()
        }
    }

    #[test]
    fn order_from_quote_copies_each_line() {
        let order = Uuid::now_v7();
        let quote_line = Uuid::now_v7();
        let body = line_body(
            order,
            &LineCopy {
                product_ref: Some(quote_line),
                quantity: Some("2".into()),
                unit_price: Some("150.50".into()),
                discount_amount: Some("1".into()),
                line_total: Some("300.00".into()),
                quote_line_ref: Some(quote_line),
                ..LineCopy::default()
            },
        );
        assert_eq!(body["order_ref"], json!(order));
        assert_eq!(body["quantity"], json!(2));
        assert_eq!(body["unit_price"].as_f64(), Some(150.5));
        assert_eq!(body["quote_line_ref"], json!(quote_line));
        assert!(
            body.get("tax_amount").is_none(),
            "absent values stay absent"
        );
    }

    #[test]
    fn order_from_quote_totals_and_numbers() {
        let lines = [
            line(Some("10.5"), None, None),
            line(Some("4.5"), None, None),
            line(None, None, None),
        ];
        assert_eq!(lines_total(&lines), Decimal::from(15));
        assert_eq!(number("12.30").and_then(|n| n.as_f64()), Some(12.3));
        assert_eq!(number("not a number"), None);
    }

    #[test]
    fn order_from_quote_confirm_needs_a_draft_with_lines() {
        assert!(confirmable(Some("draft"), 1).is_ok());
        let confirmed = confirmable(Some("confirmed"), 1);
        assert!(matches!(confirmed, Err(AppError::Conflict(_))));
        let empty = confirmable(Some("draft"), 0);
        assert!(matches!(empty, Err(AppError::Validation(_))));
    }

    #[test]
    fn order_from_quote_invoice_lines_use_the_net_price() {
        let net = line(Some("90"), Some("3"), Some("40"));
        let l = request_line("SO-1", 0, &net).unwrap();
        assert_eq!(l.unit_price.as_f64(), Some(30.0));
        assert_eq!(l.quantity.as_f64(), Some(3.0));
        assert_eq!(l.description, "SO-1 line 1");
        let priced = line(None, Some("2"), Some("7.25"));
        let l = request_line("SO-1", 1, &priced).unwrap();
        assert_eq!(l.unit_price.as_f64(), Some(7.25));
        let unpriced = line(None, Some("1"), None);
        assert!(request_line("SO-1", 2, &unpriced).is_err());
    }
}
