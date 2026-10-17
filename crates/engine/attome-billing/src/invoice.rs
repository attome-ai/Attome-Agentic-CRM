//! Draft invoice totals (roadmap F4-T5): each line priced by the tax engine
//! ([`crate::tax`]) and the invoice's stored totals summed from the rounded
//! lines, so a draft always shows what issuing it would charge.
//!
//! - Only a draft is recomputed; an issued invoice keeps its lines and totals
//!   for life (corrections are credit and debit notes), so any other status
//!   answers `409`.
//! - Lines and the invoice are written through the generic record update
//!   (`attome_records::entity_crud::update_record_for`) with their current
//!   `row_version`, so field rules, audit and change events apply as for any
//!   edit, and a line changed meanwhile surfaces as a version conflict.
//!   Nothing is written when a value already matches.
//! - Rates come from the regions pack's `region_tax_rate` records through the
//!   process-wide [`TaxRateCache`]. The seller is the deployment's country
//!   (`billing.seller_country`, default `SA`). The buyer is treated as in the
//!   same country until accounts record one, so reverse charge is not applied
//!   yet; the buyer's VAT number only marks them as registered.

use std::str::FromStr;
use std::sync::OnceLock;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::tax::{
    TaxContext, TaxRateCache, TaxRateRow, VatCategory, determine, invoice_totals, line_amounts,
    minor_units,
};

/// The deployment's country, for the seller side of tax.
pub const SELLER_COUNTRY_SETTING: &str = "billing.seller_country";

/// The seller country when the setting is unset.
pub const DEFAULT_SELLER_COUNTRY: &str = "SA";

/// The process-wide tax-rate cache (see [`TaxRateCache`]'s doc for its
/// source, TTL and invalidation).
pub fn tax_rates() -> &'static TaxRateCache {
    static CACHE: OnceLock<TaxRateCache> = OnceLock::new();
    CACHE.get_or_init(TaxRateCache::default)
}

/// A draft's recomputed totals.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct InvoiceTotals {
    pub invoice_id: Uuid,
    pub currency: String,
    /// Decimal amounts, as text.
    pub net_total: String,
    pub vat_total: String,
    pub grand_total: String,
    pub lines: usize,
}

/// A line category as the regions pack and the invoice line store it.
pub fn category_of(code: Option<&str>) -> VatCategory {
    match code.unwrap_or("standard") {
        "reduced" => VatCategory::Reduced,
        "zero_rated" => VatCategory::ZeroRated,
        "exempt" => VatCategory::Exempt,
        "out_of_scope" => VatCategory::OutOfScope,
        _ => VatCategory::Standard,
    }
}

fn decimal(text: Option<&str>) -> Decimal {
    text.and_then(|t| Decimal::from_str(t.trim()).ok())
        .unwrap_or(Decimal::ZERO)
}

/// The seller country: the setting, else [`DEFAULT_SELLER_COUNTRY`].
pub fn seller_country(state: &EngineState) -> String {
    attome_core::setting_registry()
        .get(SELLER_COUNTRY_SETTING)
        .and_then(|descriptor| {
            let (value, _) = state.settings.load().resolve(descriptor, None, None);
            value
                .as_str()
                .map(str::trim)
                .filter(|s| s.len() == 2)
                .map(str::to_ascii_uppercase)
        })
        .unwrap_or_else(|| DEFAULT_SELLER_COUNTRY.to_owned())
}

type RateRow = (String, Option<String>, String, NaiveDate, Option<NaiveDate>);

async fn load_rates(state: &EngineState) -> Result<std::sync::Arc<Vec<TaxRateRow>>, AppError> {
    let db = state.base.db.clone();
    tax_rates()
        .get_or_load(|| async move {
            let installed: bool =
                sqlx::query_scalar("SELECT to_regclass('region_tax_rate') IS NOT NULL")
                    .fetch_one(&db)
                    .await?;
            if !installed {
                return Ok::<_, sqlx::Error>(Vec::new());
            }
            let rows: Vec<RateRow> = sqlx::query_as(
                "SELECT country_code, category, rate::text, effective_from::date, \
                        effective_to::date \
                 FROM region_tax_rate \
                 WHERE (is_active IS NULL OR is_active = true) \
                   AND country_code IS NOT NULL AND rate IS NOT NULL \
                   AND effective_from IS NOT NULL",
            )
            .fetch_all(&db)
            .await?;
            Ok(rows
                .into_iter()
                .map(|(country, category, rate, from, to)| TaxRateRow {
                    country,
                    category: category_of(category.as_deref()),
                    rate_pct: decimal(Some(&rate)),
                    effective_from: from,
                    effective_to: to,
                })
                .collect())
        })
        .await
        .map_err(|e| AppError::internal(e.to_string()))
}

type DraftRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<NaiveDate>,
    Option<NaiveDate>,
    i64,
);

type LineRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
);

/// A decimal as the JSON number the record write path expects for a
/// number or currency field.
fn number(value: Decimal) -> Value {
    use rust_decimal::prelude::ToPrimitive;
    value
        .to_f64()
        .and_then(serde_json::Number::from_f64)
        .map_or(Value::Null, Value::Number)
}

/// An invoice's stored net, VAT, grand and open totals and the finance
/// pack's amount, as text.
type TotalsRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn changed(old: Option<&str>, new: Decimal) -> bool {
    old.and_then(|o| Decimal::from_str(o.trim()).ok()) != Some(new)
}

/// Recomputes a draft invoice's lines and totals as `ctx`.
pub async fn recompute_draft(
    state: &EngineState,
    ctx: &SecurityContext,
    invoice_id: Uuid,
) -> Result<InvoiceTotals, AppError> {
    let db = &state.base.db;
    let row: Option<DraftRow> = sqlx::query_as(
        "SELECT status, currency, buyer_vat_number, supply_date::date, issued_date::date, \
                row_version \
         FROM invoice WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(invoice_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((status, currency, buyer_vat, supply_date, issued_date, invoice_version)) = row else {
        return Err(AppError::NotFound);
    };
    ctx.require("invoice", "update")?;
    ctx.require("invoice_line", "update")?;
    if status.as_deref().unwrap_or("draft") != "draft" {
        return Err(AppError::Conflict("only a draft invoice is recomputed"));
    }
    let currency = currency
        .filter(|c| !c.trim().is_empty())
        .unwrap_or_else(|| "SAR".to_owned());
    let units = minor_units(&currency);
    let on_date = supply_date
        .or(issued_date)
        .unwrap_or_else(|| Utc::now().date_naive());
    let seller = seller_country(state);
    let rates = load_rates(state).await?;

    let lines: Vec<LineRow> = sqlx::query_as(
        "SELECT id, quantity::text, unit_price::text, discount::text, vat_category, \
                vat_rate::text, vat_amount::text, line_total::text, row_version \
         FROM invoice_line \
         WHERE invoice_ref = $1 AND (is_active IS NULL OR is_active = true) \
         ORDER BY id",
    )
    .bind(invoice_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut amounts = Vec::with_capacity(lines.len());
    for (id, qty, price, discount, category, old_rate, old_vat, old_total, version) in lines {
        let tax_ctx = TaxContext {
            seller_country: seller.clone(),
            buyer_country: seller.clone(),
            buyer_vat_registered: buyer_vat.as_deref().is_some_and(|v| !v.trim().is_empty()),
            category: category_of(category.as_deref()),
            on_date,
        };
        let decision = determine(&tax_ctx, &rates).map_err(|e| match e {
            crate::tax::TaxError::NoRate { country, on_date } => AppError::Validation(format!(
                "no VAT rate for {country} on {on_date}; add one to the region tax rates"
            )),
        })?;
        let line = line_amounts(
            decimal(qty.as_deref()),
            decimal(price.as_deref()),
            decimal(discount.as_deref()),
            decision.rate_pct,
            units,
        );
        amounts.push(line);
        let mut patch = Map::new();
        if changed(old_rate.as_deref(), decision.rate_pct) {
            patch.insert("vat_rate".into(), number(decision.rate_pct));
        }
        if changed(old_vat.as_deref(), line.vat) {
            patch.insert("vat_amount".into(), number(line.vat));
        }
        if changed(old_total.as_deref(), line.total) {
            patch.insert("line_total".into(), number(line.total));
        }
        if !patch.is_empty() {
            attome_records::entity_crud::update_record_for(
                state,
                ctx,
                ctx.user_id,
                "invoice_line",
                id,
                version,
                Value::Object(patch),
            )
            .await?;
        }
    }

    let totals = invoice_totals(&amounts);
    let current: Option<TotalsRow> = sqlx::query_as(
        "SELECT net_total::text, vat_total::text, grand_total::text, open_total::text, \
                amount::text \
             FROM invoice WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (old_net, old_vat, old_grand, old_open, old_amount) = current.unwrap_or_default();
    let mut patch = Map::new();
    if changed(old_net.as_deref(), totals.net) {
        patch.insert("net_total".into(), number(totals.net));
    }
    if changed(old_vat.as_deref(), totals.vat) {
        patch.insert("vat_total".into(), number(totals.vat));
    }
    if changed(old_grand.as_deref(), totals.total) {
        patch.insert("grand_total".into(), number(totals.total));
    }
    // Nothing is paid on a draft: what is open is the whole amount.
    if changed(old_open.as_deref(), totals.total) {
        patch.insert("open_total".into(), number(totals.total));
    }
    // The finance pack's amount is what finance-only views show.
    if changed(old_amount.as_deref(), totals.total) {
        patch.insert("amount".into(), number(totals.total));
    }
    if !patch.is_empty() {
        attome_records::entity_crud::update_record_for(
            state,
            ctx,
            ctx.user_id,
            "invoice",
            invoice_id,
            invoice_version,
            Value::Object(patch),
        )
        .await?;
    }
    Ok(InvoiceTotals {
        invoice_id,
        currency,
        net_total: totals.net.to_string(),
        vat_total: totals.vat.to_string(),
        grand_total: totals.total.to_string(),
        lines: amounts.len(),
    })
}

/// `invoice.update`: may change invoices.
#[derive(Debug)]
pub struct InvoiceUpdate;

impl attome_server::authz::PrivilegeKey for InvoiceUpdate {
    const KEY: &'static str = "invoice.update";
}

#[utoipa::path(
    post,
    path = "/api/v1/billing/invoices/{id}/recompute",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The draft invoice")),
    responses(
        (status = 200, description = "The draft's lines and totals, recomputed", body = InvoiceTotals),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not update invoices", body = attome_types::ErrorResponse),
        (status = 404, description = "No such invoice", body = attome_types::ErrorResponse),
        (status = 409, description = "The invoice is not a draft, or a line changed meanwhile", body = attome_types::ErrorResponse),
        (status = 422, description = "No VAT rate applies to a line", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_recompute(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<InvoiceUpdate>>,
    axum::extract::Path(invoice_id): axum::extract::Path<Uuid>,
) -> Result<axum::Json<InvoiceTotals>, AppError> {
    Ok(axum::Json(recompute_draft(&state, &ctx, invoice_id).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_recompute), components(schemas(InvoiceTotals)))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_categories_map_onto_the_tax_engine() {
        assert_eq!(category_of(Some("zero_rated")), VatCategory::ZeroRated);
        assert_eq!(category_of(Some("exempt")), VatCategory::Exempt);
        assert_eq!(category_of(Some("out_of_scope")), VatCategory::OutOfScope);
        assert_eq!(category_of(Some("reduced")), VatCategory::Reduced);
        assert_eq!(category_of(None), VatCategory::Standard);
    }

    #[test]
    fn only_a_different_amount_is_a_change() {
        assert!(!changed(Some("15.00"), Decimal::from_str("15").unwrap()));
        assert!(changed(Some("14.99"), Decimal::from_str("15").unwrap()));
        assert!(changed(None, Decimal::ZERO));
    }
}
