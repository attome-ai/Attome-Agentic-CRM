//! Reads for people and agents (roadmap F4-T14): finding invoices under the
//! caller's record scope on `invoice`, an account's balance, and why a line
//! carries the tax it does. Nothing here writes.

use std::str::FromStr;

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::scope::{bind_scope, read_scope, scope_binds};
use crate::tax::{TaxContext, determine};

/// Most invoices one search returns.
pub const MAX_FOUND: i64 = 50;

/// What to look for; every field narrows.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct InvoiceFilter {
    pub account_id: Option<Uuid>,
    /// `draft`, `issued`, `sent`, `paid`, `overdue` or `void`.
    pub status: Option<String>,
    /// `open`, `partly_paid`, `paid`, `overdue` or `written_off`.
    pub payment_status: Option<String>,
    /// An invoice number, or the start of one.
    pub number: Option<String>,
    pub limit: Option<i64>,
}

/// One invoice found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InvoiceSummary {
    pub id: Uuid,
    pub invoice_number: Option<String>,
    pub kind: Option<String>,
    pub status: Option<String>,
    pub payment_status: Option<String>,
    pub account_id: Option<Uuid>,
    pub currency: Option<String>,
    pub issued_date: Option<NaiveDate>,
    pub due_date: Option<NaiveDate>,
    pub grand_total: Option<String>,
    pub open_total: Option<String>,
}

type SummaryRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<NaiveDate>,
    Option<NaiveDate>,
    Option<String>,
    Option<String>,
);

/// Invoices the caller may read that match `filter`, newest first.
pub async fn find_invoices(
    state: &EngineState,
    ctx: &SecurityContext,
    filter: &InvoiceFilter,
) -> Result<Vec<InvoiceSummary>, AppError> {
    let scope = read_scope(state, ctx, "invoice", "i", 1).await?;
    let rls = scope.as_ref().map_or("", |p| p.sql.as_str());
    let n = scope_binds(&scope);
    let (p_account, p_status, p_payment, p_number) = (n + 1, n + 2, n + 3, n + 4);
    let limit = filter.limit.unwrap_or(20).clamp(1, MAX_FOUND);
    let sql = format!(
        "SELECT i.id, i.invoice_number, i.kind, i.status, i.payment_status, i.account_ref, \
                i.currency, i.issued_date::date, i.due_date::date, i.grand_total::text, \
                i.open_total::text \
         FROM invoice i \
         WHERE (i.is_active IS NULL OR i.is_active = true) {rls} \
           AND (${p_account}::uuid IS NULL OR i.account_ref = ${p_account}::uuid) \
           AND (${p_status}::text IS NULL OR i.status = ${p_status}::text) \
           AND (${p_payment}::text IS NULL OR i.payment_status = ${p_payment}::text) \
           AND (${p_number}::text IS NULL OR i.invoice_number LIKE ${p_number}::text || '%') \
         ORDER BY i.issued_date DESC NULLS FIRST, i.id DESC LIMIT {limit}"
    );
    let number = filter
        .number
        .as_deref()
        .map(|n| n.trim().replace(['%', '_'], ""))
        .filter(|n| !n.is_empty());
    let rows: Vec<SummaryRow> = bind_scope(sqlx::query_as(&sql), &scope)
        .bind(filter.account_id)
        .bind(filter.status.as_deref())
        .bind(filter.payment_status.as_deref())
        .bind(number)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(id, number, kind, status, payment, account, currency, issued, due, grand, open)| {
                InvoiceSummary {
                    id,
                    invoice_number: number,
                    kind,
                    status,
                    payment_status: payment,
                    account_id: account,
                    currency,
                    issued_date: issued,
                    due_date: due,
                    grand_total: grand,
                    open_total: open,
                }
            },
        )
        .collect())
}

/// What to look for in payments; every field narrows (F5-T13).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PaymentFilter {
    pub account_id: Option<Uuid>,
    /// `pending`, `succeeded`, `failed`, `refunded`, `partially_refunded`,
    /// `disputed` or `reversed`.
    pub status: Option<String>,
    /// A bank or cheque reference, or the start of one.
    pub reference: Option<String>,
    pub limit: Option<i64>,
}

/// One payment found. The gateway's reference and fee are finance fields
/// and are not shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaymentSummary {
    pub id: Uuid,
    pub name: Option<String>,
    pub account_id: Option<Uuid>,
    pub amount: Option<String>,
    pub currency: Option<String>,
    pub method: Option<String>,
    pub status: Option<String>,
    pub received_on: Option<NaiveDate>,
    pub reference: Option<String>,
    pub unallocated: Option<String>,
}

type PaymentRow = (
    Uuid,
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<NaiveDate>,
    Option<String>,
    Option<String>,
);

/// Payments the caller may read that match `filter`, newest first.
pub async fn find_payments(
    state: &EngineState,
    ctx: &SecurityContext,
    filter: &PaymentFilter,
) -> Result<Vec<PaymentSummary>, AppError> {
    let scope = read_scope(state, ctx, "customer_payment", "p", 1).await?;
    let rls = scope.as_ref().map_or("", |p| p.sql.as_str());
    let n = scope_binds(&scope);
    let (p_account, p_status, p_reference) = (n + 1, n + 2, n + 3);
    let limit = filter.limit.unwrap_or(20).clamp(1, MAX_FOUND);
    let sql = format!(
        "SELECT p.id, p.name, p.payer_account_ref, p.amount::text, p.currency, p.method, \
                p.status, p.received_on::date, p.reference, p.unallocated::text \
         FROM customer_payment p \
         WHERE (p.is_active IS NULL OR p.is_active = true) {rls} \
           AND (${p_account}::uuid IS NULL OR p.payer_account_ref = ${p_account}::uuid) \
           AND (${p_status}::text IS NULL OR p.status = ${p_status}::text) \
           AND (${p_reference}::text IS NULL OR p.reference LIKE ${p_reference}::text || '%') \
         ORDER BY p.received_on DESC NULLS FIRST, p.id DESC LIMIT {limit}"
    );
    let reference = filter
        .reference
        .as_deref()
        .map(|r| r.trim().replace(['%', '_'], ""))
        .filter(|r| !r.is_empty());
    let rows: Vec<PaymentRow> = bind_scope(sqlx::query_as(&sql), &scope)
        .bind(filter.account_id)
        .bind(filter.status.as_deref())
        .bind(reference)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                name,
                account,
                amount,
                currency,
                method,
                status,
                received,
                reference,
                unallocated,
            )| {
                PaymentSummary {
                    id,
                    name,
                    account_id: account,
                    amount,
                    currency,
                    method,
                    status,
                    received_on: received,
                    reference,
                    unallocated,
                }
            },
        )
        .collect())
}

/// What an account owes today, per currency (the statement's closing
/// balance over all time).
pub async fn account_balance(
    state: &EngineState,
    ctx: &SecurityContext,
    account: Uuid,
) -> Result<Vec<(String, String)>, AppError> {
    let today = Utc::now().date_naive();
    let statement = crate::statements::statement(
        state,
        ctx,
        account,
        NaiveDate::from_ymd_opt(1900, 1, 1).unwrap_or(today),
        today,
    )
    .await?;
    Ok(statement
        .currencies
        .into_iter()
        .map(|c| (c.currency, c.closing_balance))
        .collect())
}

/// Why a line carries the tax it does: the facts the tax engine decided on
/// and what it decided, in both languages. No model is involved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaxExplanation {
    pub line_id: Uuid,
    pub invoice_id: Uuid,
    pub category: String,
    pub seller_country: String,
    pub buyer_country: String,
    pub buyer_vat_registered: bool,
    /// The supply date, else the issue date, else today.
    pub on_date: NaiveDate,
    pub rate_pct: String,
    pub reverse_charge: bool,
    pub reason_code: Option<String>,
    pub reason_en: Option<String>,
    pub reason_ar: Option<String>,
    /// What the line stores now (a draft may not be recomputed yet).
    pub stored_vat_rate: Option<String>,
    pub stored_vat_amount: Option<String>,
}

type ExplainRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<NaiveDate>,
    Option<NaiveDate>,
);

/// Explains one line's tax, if the caller may read its invoice.
pub async fn explain_line(
    state: &EngineState,
    ctx: &SecurityContext,
    line_id: Uuid,
) -> Result<TaxExplanation, AppError> {
    let scope = read_scope(state, ctx, "invoice", "i", 2).await?;
    let rls = scope.as_ref().map_or("", |p| p.sql.as_str());
    let sql = format!(
        "SELECT i.id, l.vat_category, l.vat_rate::text, l.vat_amount::text, \
                i.buyer_vat_number, i.supply_date::date, i.issued_date::date \
         FROM invoice_line l JOIN invoice i ON i.id = l.invoice_ref \
         WHERE l.id = $1 AND (l.is_active IS NULL OR l.is_active = true) \
           AND (i.is_active IS NULL OR i.is_active = true) {rls}"
    );
    let row: Option<ExplainRow> = bind_scope(sqlx::query_as(&sql).bind(line_id), &scope)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let Some((invoice_id, category, rate, amount, buyer_vat, supply, issued)) = row else {
        return Err(AppError::NotFound);
    };
    let seller = crate::invoice::seller_country(state);
    let on_date = supply.or(issued).unwrap_or_else(|| Utc::now().date_naive());
    let category_code = category.unwrap_or_else(|| "standard".into());
    let ctx_tax = TaxContext {
        seller_country: seller.clone(),
        buyer_country: seller.clone(),
        buyer_vat_registered: buyer_vat.as_deref().is_some_and(|v| !v.trim().is_empty()),
        category: crate::invoice::category_of(Some(&category_code)),
        on_date,
    };
    let rates = crate::invoice::load_rates(state).await?;
    let decision = determine(&ctx_tax, &rates).map_err(|e| match e {
        crate::tax::TaxError::NoRate { country, on_date } => AppError::Validation(format!(
            "no VAT rate for {country} on {on_date}; add one to the region tax rates"
        )),
    })?;
    let trim = |t: Option<String>| {
        t.map(|v| Decimal::from_str(&v).map_or(v, |d| d.normalize().to_string()))
    };
    Ok(TaxExplanation {
        line_id,
        invoice_id,
        category: category_code,
        seller_country: ctx_tax.seller_country,
        buyer_country: ctx_tax.buyer_country,
        buyer_vat_registered: ctx_tax.buyer_vat_registered,
        on_date,
        rate_pct: decision.rate_pct.normalize().to_string(),
        reverse_charge: decision.reverse_charge,
        reason_code: decision.reason.as_ref().map(|r| r.code.to_owned()),
        reason_en: decision.reason.as_ref().map(|r| r.en.to_owned()),
        reason_ar: decision.reason.as_ref().map(|r| r.ar.to_owned()),
        stored_vat_rate: trim(rate),
        stored_vat_amount: trim(amount),
    })
}
