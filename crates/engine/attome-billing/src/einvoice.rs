//! E-invoicing inside the issue step (roadmap AG2-T3): the first issue hook.
//!
//! When `einvoice.enabled` is on, every issued invoice, credit note, debit
//! note and deposit invoice (never a pro forma) is written as ZATCA's UBL
//! invoice from the invoice, its lines, its account and the seller settings,
//! stamped on an onboarded device ([`attome_einvoice::document::create`])
//! and sent at once: cleared when the buyer has a VAT number (standard,
//! B2B), reported otherwise (simplified, B2C). `invoice.einvoice_status`
//! follows the document: `pending`, `cleared`, `reported` or `rejected`.
//!
//! A pending document (ZATCA unreachable, rate limited) is tried again by
//! the `BillingEinvoiceSweep` job every five minutes, which re-runs the
//! after-issue hooks once it clears or reports, so the document and sending
//! follow. The send hook never shares a standard invoice before clearance.
//!
//! Mapping notes: credit notes go to ZATCA with positive amounts (the type
//! code says it is a credit); zero-rated, exempt and out-of-scope lines carry
//! ZATCA's default exemption reason for their category; amounts not in SAR
//! carry their VAT in SAR at the invoice's exchange rate.

use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use attome_core::EngineState;
use attome_einvoice::document::DocumentState;
use attome_einvoice::zatca::api::Transport;
use attome_einvoice::zatca::xml::{
    Address, DocumentKind, Line, Party, Profile, TaxCategory, ZatcaInvoice,
};
use attome_types::AppError;
use chrono::{NaiveDate, Timelike as _, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::issue::IssueHook;

/// Documents tried per sweep.
const SWEEP_BATCH: i64 = 50;

/// How long one ZATCA call may take.
pub const ZATCA_TIMEOUT: Duration = Duration::from_secs(30);

fn decimal(text: Option<&str>) -> Decimal {
    text.and_then(|t| Decimal::from_str(t.trim()).ok())
        .unwrap_or(Decimal::ZERO)
}

/// ZATCA's category for a billing VAT category, with the default reason.
pub fn category(code: Option<&str>) -> TaxCategory {
    let reason = |code: &str, text: &str| (code.to_owned(), text.to_owned());
    match code.unwrap_or("standard") {
        "zero_rated" => {
            let (reason_code, reason) = reason("VATEX-SA-32", "Export of goods");
            TaxCategory::ZeroRated {
                reason_code,
                reason,
            }
        }
        "exempt" => {
            let (reason_code, reason) = reason(
                "VATEX-SA-29",
                "Financial services mentioned in Article 29 of the VAT Regulations",
            );
            TaxCategory::Exempt {
                reason_code,
                reason,
            }
        }
        "out_of_scope" => {
            let (reason_code, reason) = reason("VATEX-SA-OOS", "Not subject to VAT");
            TaxCategory::OutOfScope {
                reason_code,
                reason,
            }
        }
        _ => TaxCategory::Standard,
    }
}

type HeadRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<NaiveDate>,
    Option<NaiveDate>,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
);

type BuyerRow = (
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

type LineRow = (
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

/// Everything the e-invoice says, read before stamping.
struct Source {
    profile: Profile,
    kind: DocumentKind,
    number: String,
    currency: String,
    fx_rate: Decimal,
    issued: NaiveDate,
    supply: Option<NaiveDate>,
    buyer: Option<Party>,
    original_number: Option<String>,
    reason: Option<String>,
    lines: Vec<Line>,
}

/// Reads an issued invoice for e-invoicing; `None` when it needs none.
async fn source(state: &EngineState, invoice_id: Uuid) -> Result<Option<Source>, AppError> {
    let db = &state.base.db;
    let head: Option<HeadRow> = sqlx::query_as(
        "SELECT kind, status, invoice_number, currency, fx_rate::text, issued_date::date, \
                supply_date::date, account_ref, original_invoice_ref, einvoice_status \
         FROM invoice WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((kind, status, number, currency, fx, issued, supply, account, original, einvoice)) =
        head
    else {
        return Err(AppError::NotFound);
    };
    let kind = match kind.as_deref().unwrap_or("invoice") {
        "credit_note" => DocumentKind::CreditNote,
        "debit_note" => DocumentKind::DebitNote,
        "deposit" => DocumentKind::Prepayment,
        "invoice" => DocumentKind::Invoice,
        _ => return Ok(None),
    };
    if matches!(status.as_deref(), None | Some("draft" | "void"))
        || matches!(
            einvoice.as_deref(),
            Some("cleared" | "reported" | "rejected")
        )
    {
        return Ok(None);
    }
    let buyer: Option<BuyerRow> = match account {
        Some(account) => sqlx::query_as(
            "SELECT COALESCE(NULLIF(legal_name_ar, ''), NULLIF(legal_name_en, ''), name), \
                    vat_number, cr_number, billing_street, billing_building_number, \
                    billing_district, billing_city, billing_postal_zone, billing_country_code \
             FROM account WHERE id = $1",
        )
        .bind(account)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?,
        None => None,
    };
    let buyer = buyer.map(
        |(name, vat, crn, street, building, district, city, postal, country)| {
            let vat = vat.map(|v| v.trim().to_owned()).filter(|v| v.len() == 15);
            let address = match (street, building, district, city, postal) {
                (Some(street), Some(building), Some(district), Some(city), Some(postal)) => {
                    Some(Address {
                        street,
                        building_number: building,
                        city_subdivision: district,
                        city,
                        postal_zone: postal,
                        country: country
                            .filter(|c| c.len() == 2)
                            .unwrap_or_else(|| "SA".to_owned()),
                    })
                }
                _ => None,
            };
            Party {
                registration_name: name.unwrap_or_default(),
                vat_number: vat,
                other_id: crn
                    .filter(|c| !c.trim().is_empty())
                    .map(|c| ("CRN".to_owned(), c)),
                address,
            }
        },
    );
    let profile = if buyer.as_ref().is_some_and(|b| b.vat_number.is_some()) {
        Profile::Standard
    } else {
        Profile::Simplified
    };
    let original_number: Option<String> = match original {
        Some(original) => sqlx::query_scalar("SELECT invoice_number FROM invoice WHERE id = $1")
            .bind(original)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .flatten(),
        None => None,
    };
    let reason: Option<String> = sqlx::query_scalar("SELECT reason FROM invoice WHERE id = $1")
        .bind(invoice_id)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    let rows: Vec<LineRow> = sqlx::query_as(
        "SELECT description, unit, quantity::text, unit_price::text, discount::text, \
                vat_category, vat_rate::text, vat_amount::text, line_total::text \
         FROM invoice_line \
         WHERE invoice_ref = $1 AND (is_active IS NULL OR is_active = true) ORDER BY id",
    )
    .bind(invoice_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let credit = kind == DocumentKind::CreditNote;
    let lines = rows
        .into_iter()
        .map(
            |(description, unit, qty, price, discount, category_code, rate, vat, total)| {
                let mut quantity = decimal(qty.as_deref());
                let mut discount = decimal(discount.as_deref());
                let mut vat = decimal(vat.as_deref());
                let mut net = decimal(total.as_deref()) - vat;
                if credit {
                    quantity = quantity.abs();
                    discount = discount.abs();
                    vat = vat.abs();
                    net = net.abs();
                }
                Line {
                    name: description.unwrap_or_default(),
                    quantity,
                    unit_code: unit
                        .filter(|u| u.len() <= 3 && !u.is_empty())
                        .map(|u| u.to_ascii_uppercase())
                        .unwrap_or_else(|| "PCE".to_owned()),
                    unit_price: decimal(price.as_deref()),
                    discount,
                    net,
                    category: category(category_code.as_deref()),
                    percent: decimal(rate.as_deref()),
                    vat,
                }
            },
        )
        .collect();
    Ok(Some(Source {
        profile,
        kind,
        number: number.unwrap_or_default(),
        currency: currency.unwrap_or_else(|| "SAR".to_owned()),
        fx_rate: fx.as_deref().map_or(Decimal::ONE, |f| decimal(Some(f))),
        issued: issued.unwrap_or_else(|| Utc::now().date_naive()),
        supply,
        buyer,
        original_number,
        reason: reason.filter(|r| !r.trim().is_empty()),
        lines,
    }))
}

fn zatca_invoice(source: Source, seller: Party, icv: u64, pih: String) -> ZatcaInvoice {
    let vat: Decimal = source.lines.iter().map(|l| l.vat).sum();
    let vat_in_sar = (source.currency != "SAR").then(|| (vat * source.fx_rate).round_dp(2));
    ZatcaInvoice {
        profile: source.profile,
        kind: source.kind,
        number: source.number,
        uuid: Uuid::new_v4().to_string(),
        issue_date: source.issued,
        issue_time: Utc::now().time().with_nanosecond(0).unwrap_or_default(),
        currency: source.currency,
        icv,
        pih,
        seller,
        buyer: source.buyer,
        supply_date: source.supply.or(Some(source.issued)),
        payment_means: "1".into(),
        original_number: source.original_number,
        reason: source.reason,
        vat_in_sar,
        lines: source.lines,
    }
}

async fn set_status(state: &EngineState, invoice_id: Uuid, status: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE invoice SET einvoice_status = $2, modified_at = now(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND einvoice_status IS DISTINCT FROM $2",
    )
    .bind(invoice_id)
    .bind(status)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Stamps and sends one issued invoice; its e-invoice state, or `None` when
/// it needs none.
pub async fn einvoice_invoice(
    state: &EngineState,
    invoice_id: Uuid,
    transport: &dyn Transport,
) -> Result<Option<DocumentState>, AppError> {
    if !state.base.config.einvoice.enabled {
        return Ok(None);
    }
    if let Some(existing) = attome_einvoice::document::for_invoice(state, invoice_id).await? {
        if existing.status != "pending" {
            return Ok(Some(existing));
        }
    } else {
        let Some(source) = source(state, invoice_id).await? else {
            return Ok(None);
        };
        let seller = attome_einvoice::device::seller(state)?;
        attome_einvoice::document::create(state, invoice_id, |icv, pih| {
            zatca_invoice(source, seller, icv, pih)
        })
        .await?;
        set_status(state, invoice_id, "pending").await?;
    }
    let document = attome_einvoice::document::for_invoice(state, invoice_id)
        .await?
        .ok_or_else(|| AppError::internal("a stamped document went missing"))?;
    let after = attome_einvoice::document::submit(state, document.id, transport).await?;
    set_status(state, invoice_id, &after.status).await?;
    Ok(Some(after))
}

/// The first issue hook: e-invoicing.
pub struct EinvoiceHook {
    pub transport: Arc<dyn Transport>,
}

impl std::fmt::Debug for EinvoiceHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EinvoiceHook").finish_non_exhaustive()
    }
}

impl IssueHook for EinvoiceHook {
    fn name(&self) -> &'static str {
        "einvoice"
    }

    fn order(&self) -> u16 {
        10
    }

    fn after_issue<'a>(
        &'a self,
        state: &'a EngineState,
        invoice_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>> {
        Box::pin(async move {
            einvoice_invoice(state, invoice_id, self.transport.as_ref())
                .await
                .map(|_| ())
        })
    }
}

/// Tries the pending documents that are due again; re-runs the after-issue
/// hooks of each that cleared or reported. Returns how many settled.
pub async fn sweep(state: &EngineState, transport: &dyn Transport) -> Result<u64, AppError> {
    if !state.base.config.einvoice.enabled {
        return Ok(0);
    }
    let mut settled = 0;
    for document in attome_einvoice::document::due(state, SWEEP_BATCH).await? {
        let after = match attome_einvoice::document::submit(state, document, transport).await {
            Ok(after) => after,
            Err(e) => {
                tracing::warn!(%document, error = %e, "billing e-invoicing sweep: a document could not be sent");
                continue;
            }
        };
        set_status(state, after.invoice_id, &after.status).await?;
        if after.status != "pending" {
            settled += 1;
        }
        if matches!(after.status.as_str(), "cleared" | "reported") {
            attome_jobs::enqueue_on_pool(
                &state.base.db,
                attome_core::jobs::EngineJob::BillingAfterIssue {
                    invoice_id: after.invoice_id,
                },
            )
            .await
            .map_err(AppError::internal)?;
        }
    }
    Ok(settled)
}

#[utoipa::path(
    get,
    path = "/api/v1/billing/invoices/{id}/einvoice",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The invoice")),
    responses(
        (status = 200, description = "The invoice's e-invoice: status, ZATCA's validation results and the QR code", body = DocumentState),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not read invoices", body = attome_types::ErrorResponse),
        (status = 404, description = "The invoice has no e-invoice", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_einvoice(
    axum::extract::State(state): axum::extract::State<EngineState>,
    _ctx: attome_server::authz::Authorized<
        attome_server::authz::Privilege<crate::statements::InvoiceRead>,
    >,
    axum::extract::Path(invoice_id): axum::extract::Path<Uuid>,
) -> Result<axum::Json<DocumentState>, AppError> {
    attome_einvoice::document::for_invoice(&state, invoice_id)
        .await?
        .map(axum::Json)
        .ok_or(AppError::NotFound)
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_einvoice), components(schemas(DocumentState)))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_carry_zatcas_default_reasons() {
        assert_eq!(category(Some("standard")), TaxCategory::Standard);
        assert_eq!(category(None), TaxCategory::Standard);
        assert!(
            matches!(category(Some("exempt")), TaxCategory::Exempt { reason_code, .. } if reason_code == "VATEX-SA-29")
        );
        assert!(matches!(
            category(Some("zero_rated")),
            TaxCategory::ZeroRated { .. }
        ));
        assert!(matches!(
            category(Some("out_of_scope")),
            TaxCategory::OutOfScope { .. }
        ));
    }
}
