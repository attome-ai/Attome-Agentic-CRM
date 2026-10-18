//! The issued invoice's document and its sending (roadmap F4-T13), as two
//! issue hooks run by the `BillingAfterIssue` job.
//!
//! - [`DocumentHook`] (order 50) writes the bilingual invoice: Arabic and
//!   English side by side, seller and buyer with their VAT numbers, the
//!   issue date in Gregorian and Hijri, the lines and the totals. Billing
//!   writes the HTML (every value escaped) and attome-docgen renders it and
//!   attaches the PDF to the invoice's `document` field as the person who
//!   issued it. An invoice that already has its document is left alone, so
//!   a retried job does not render twice.
//! - [`SendHook`] (order 90) emails the PDF to the invoice's contact and
//!   moves the invoice from `issued` to `sent` in the same transaction as
//!   the queued email. It waits for e-invoicing: while `einvoice_status` is
//!   `pending` or `submitted` it fails, so the job retries later; a
//!   `rejected` or `failed` invoice is never sent. Without a contact email
//!   it leaves the invoice issued for a person to send.
//!
//! The e-invoicing hook (AG2) registers before both with a lower order, and
//! adds the QR code and the XML these hooks then carry.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use attome_core::EngineState;
use attome_docgen::generate::PdfRenderer;
use attome_html::escape_html;
use attome_types::AppError;
use chrono::NaiveDate;
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use uuid::Uuid;

use crate::issue::IssueHook;

/// The deployment's legal name, printed as the seller.
pub const SELLER_NAME_SETTING: &str = "billing.seller_name";
/// The deployment's VAT registration number, printed as the seller's.
pub const SELLER_VAT_SETTING: &str = "billing.seller_vat_number";

/// Registers the document and send hooks (at boot).
pub fn register_hooks(renderer: Arc<dyn PdfRenderer>) {
    crate::issue::register_issue_hook(Arc::new(DocumentHook { renderer }));
    crate::issue::register_issue_hook(Arc::new(SendHook));
}

fn setting_text(state: &EngineState, key: &str) -> Option<String> {
    attome_core::setting_registry().get(key).and_then(|d| {
        let (value, _) = state.settings.load().resolve(d, None, None);
        value
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    })
}

type HeadRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<NaiveDate>,
    Option<NaiveDate>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<String>,
);

type LineRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// What the document shows.
struct Invoice {
    number: String,
    kind: String,
    currency: String,
    buyer: String,
    issued: Option<NaiveDate>,
    due: Option<NaiveDate>,
    buyer_vat: Option<String>,
    address: Option<String>,
    net: String,
    vat: String,
    grand: String,
    document: Option<String>,
    issuer: Option<Uuid>,
    language: String,
}

async fn load(state: &EngineState, id: Uuid) -> Result<Invoice, AppError> {
    let row: Option<HeadRow> = sqlx::query_as(
        "SELECT i.invoice_number, COALESCE(i.kind, 'invoice'), i.currency, a.name, \
                i.issued_date::date, i.due_date::date, i.buyer_vat_number, i.billing_address, \
                i.net_total::text, i.vat_total::text, i.grand_total::text, i.document, \
                i.modified_by, COALESCE(i.language, 'ar_en') \
         FROM invoice i LEFT JOIN account a ON a.id = i.account_ref \
         WHERE i.id = $1",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((
        number,
        kind,
        currency,
        buyer,
        issued,
        due,
        vat_no,
        address,
        net,
        vat,
        grand,
        document,
        issuer,
        language,
    )) = row
    else {
        return Err(AppError::NotFound);
    };
    Ok(Invoice {
        number: number.unwrap_or_default(),
        kind: kind.unwrap_or_else(|| "invoice".into()),
        currency: currency.unwrap_or_default(),
        buyer: buyer.unwrap_or_default(),
        issued,
        due,
        buyer_vat: vat_no,
        address,
        net: net.unwrap_or_default(),
        vat: vat.unwrap_or_default(),
        grand: grand.unwrap_or_default(),
        document: document.filter(|d| !d.is_empty()),
        issuer,
        language: language.unwrap_or_else(|| "ar_en".into()),
    })
}

fn title(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "credit_note" => ("Credit Note", "إشعار دائن"),
        "debit_note" => ("Debit Note", "إشعار مدين"),
        "deposit" => ("Deposit Invoice", "فاتورة دفعة مقدمة"),
        _ => ("Tax Invoice", "فاتورة ضريبية"),
    }
}

/// The bilingual invoice as one HTML document. Every value is escaped.
fn html(
    inv: &Invoice,
    lines: &[LineRow],
    seller: &str,
    seller_vat: &str,
    hijri: Option<String>,
) -> String {
    let e = |s: &str| escape_html(s);
    let (en_title, ar_title) = title(&inv.kind);
    let issued = inv.issued.map(|d| d.to_string()).unwrap_or_default();
    let due = inv.due.map(|d| d.to_string()).unwrap_or_default();
    let mut rows = String::new();
    for (description, quantity, price, rate, vat, total) in lines {
        let cell = |v: &Option<String>| e(v.as_deref().unwrap_or(""));
        rows.push_str(&format!(
            "<tr><td>{}</td><td class=\"n\">{}</td><td class=\"n\">{}</td><td class=\"n\">{}%</td>\
             <td class=\"n\">{}</td><td class=\"n\">{}</td></tr>",
            cell(description),
            cell(quantity),
            cell(price),
            cell(rate),
            cell(vat),
            cell(total)
        ));
    }
    let both = |en: &str, ar: &str| {
        format!("<span class=\"en\">{en}</span> <span class=\"ar\" dir=\"rtl\">{ar}</span>")
    };
    format!(
        "<!doctype html><html lang=\"ar\"><head><meta charset=\"utf-8\"><style>\
         body{{font-family:'Noto Naskh Arabic','Noto Sans',sans-serif;font-size:11pt;color:#111}}\
         h1{{font-size:16pt;display:flex;justify-content:space-between}}\
         table{{width:100%;border-collapse:collapse;margin-top:12px}}\
         th,td{{border:1px solid #999;padding:4px 6px;text-align:start}}\
         td.n{{text-align:end;direction:ltr;unicode-bidi:isolate}}\
         .ar{{direction:rtl;unicode-bidi:isolate}}\
         .parties{{display:flex;justify-content:space-between;gap:24px}}\
         .totals td:first-child{{font-weight:bold}}</style></head><body>\
         <h1>{title}</h1>\
         <p>{number_label}: <b dir=\"ltr\">{number}</b></p>\
         <p>{issued_label}: <span dir=\"ltr\">{issued}</span>{hijri}</p>\
         <p>{due_label}: <span dir=\"ltr\">{due}</span></p>\
         <div class=\"parties\"><div><h3>{seller_label}</h3><p>{seller}</p><p>{vat_label}: <span dir=\"ltr\">{seller_vat}</span></p></div>\
         <div><h3>{buyer_label}</h3><p>{buyer}</p><p>{address}</p><p>{vat_label}: <span dir=\"ltr\">{buyer_vat}</span></p></div></div>\
         <table><thead><tr><th>{description}</th><th>{quantity}</th><th>{price}</th><th>{rate}</th><th>{vat}</th><th>{total}</th></tr></thead>\
         <tbody>{rows}</tbody></table>\
         <table class=\"totals\"><tr><td>{net_label}</td><td class=\"n\">{net} {currency}</td></tr>\
         <tr><td>{vat_total_label}</td><td class=\"n\">{vat_total} {currency}</td></tr>\
         <tr><td>{grand_label}</td><td class=\"n\">{grand} {currency}</td></tr></table>\
         </body></html>",
        title = both(en_title, ar_title),
        number_label = both("Invoice number", "رقم الفاتورة"),
        number = e(&inv.number),
        issued_label = both("Issue date", "تاريخ الإصدار"),
        issued = e(&issued),
        hijri = hijri
            .map(|h| format!(" <span dir=\"ltr\">({})</span>", e(&h)))
            .unwrap_or_default(),
        due_label = both("Due date", "تاريخ الاستحقاق"),
        due = e(&due),
        seller_label = both("Seller", "البائع"),
        seller = e(seller),
        vat_label = both("VAT number", "الرقم الضريبي"),
        seller_vat = e(seller_vat),
        buyer_label = both("Buyer", "المشتري"),
        buyer = e(&inv.buyer),
        address = e(inv.address.as_deref().unwrap_or("")),
        buyer_vat = e(inv.buyer_vat.as_deref().unwrap_or("")),
        description = both("Description", "الوصف"),
        quantity = both("Qty", "الكمية"),
        price = both("Unit price", "سعر الوحدة"),
        rate = both("VAT rate", "نسبة الضريبة"),
        vat = both("VAT", "الضريبة"),
        total = both("Total", "الإجمالي"),
        rows = rows,
        net_label = both("Total excluding VAT", "الإجمالي غير شامل الضريبة"),
        net = e(&inv.net),
        currency = e(&inv.currency),
        vat_total_label = both("VAT total", "مجموع الضريبة"),
        vat_total = e(&inv.vat),
        grand_label = both("Total including VAT", "الإجمالي شامل الضريبة"),
        grand = e(&inv.grand),
    )
}

/// Renders and attaches the issued invoice's PDF.
pub struct DocumentHook {
    pub renderer: Arc<dyn PdfRenderer>,
}

impl std::fmt::Debug for DocumentHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentHook").finish_non_exhaustive()
    }
}

impl IssueHook for DocumentHook {
    fn name(&self) -> &'static str {
        "document"
    }

    fn order(&self) -> u16 {
        50
    }

    fn after_issue<'a>(
        &'a self,
        state: &'a EngineState,
        invoice_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>> {
        Box::pin(async move {
            let inv = load(state, invoice_id).await?;
            if inv.document.is_some() {
                return Ok(());
            }
            let issuer = inv
                .issuer
                .ok_or_else(|| AppError::internal("an issued invoice has no issuer"))?;
            let ctx = state.base.security.resolve_strict(issuer).await?;
            let lines: Vec<LineRow> = sqlx::query_as(
                "SELECT description, quantity::text, unit_price::text, vat_rate::text, \
                        vat_amount::text, line_total::text \
                 FROM invoice_line \
                 WHERE invoice_ref = $1 AND (is_active IS NULL OR is_active = true) \
                 ORDER BY id",
            )
            .bind(invoice_id)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let hijri = inv.issued.and_then(|d| {
                state
                    .hijri
                    .load()
                    .to_hijri(d)
                    .ok()
                    .map(|h| format!("{}-{:02}-{:02} AH", h.year, h.month, h.day))
            });
            let seller = setting_text(state, SELLER_NAME_SETTING).unwrap_or_default();
            let seller_vat = setting_text(state, SELLER_VAT_SETTING).unwrap_or_default();
            let document = html(&inv, &lines, &seller, &seller_vat, hijri);
            let label = if inv.number.is_empty() {
                "invoice".to_owned()
            } else {
                inv.number.clone()
            };
            attome_docgen::generate::render_to_field(
                state,
                &ctx,
                self.renderer.as_ref(),
                "invoice",
                invoice_id,
                "document",
                &label,
                &document,
                "A4",
            )
            .await?;
            tracing::info!(%invoice_id, language = %inv.language, "billing: invoice document attached");
            Ok(())
        })
    }
}

type SendRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<bool>,
    Option<Uuid>,
);

/// Emails the issued invoice to its contact and marks it sent.
#[derive(Debug)]
pub struct SendHook;

impl IssueHook for SendHook {
    fn name(&self) -> &'static str {
        "send"
    }

    fn order(&self) -> u16 {
        90
    }

    fn after_issue<'a>(
        &'a self,
        state: &'a EngineState,
        invoice_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>> {
        Box::pin(async move {
            let row: Option<SendRow> = sqlx::query_as(
                "SELECT i.status, i.einvoice_status, i.invoice_number, i.document, c.email, \
                        c.do_not_email, i.modified_by \
                 FROM invoice i LEFT JOIN contact c ON c.id = i.contact_ref \
                 WHERE i.id = $1",
            )
            .bind(invoice_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let Some((status, einvoice, number, document, email, do_not_email, issuer)) = row
            else {
                return Err(AppError::NotFound);
            };
            if status.as_deref() != Some("issued") {
                // Sent already, or no longer sendable.
                return Ok(());
            }
            match einvoice.as_deref() {
                Some("pending" | "submitted") => {
                    return Err(AppError::Conflict(
                        "the invoice waits for e-invoicing clearance before it is sent",
                    ));
                }
                Some("rejected" | "failed") => {
                    tracing::warn!(%invoice_id, "billing: an invoice e-invoicing refused is not sent");
                    return Ok(());
                }
                _ => {}
            }
            let Some(email) = email.filter(|e| e.contains('@')) else {
                tracing::info!(%invoice_id, "billing: no contact email; the invoice stays issued for a person to send");
                return Ok(());
            };
            if do_not_email == Some(true) {
                tracing::info!(%invoice_id, "billing: the contact asked not to be emailed");
                return Ok(());
            }
            let Some(key) = document.filter(|d| !d.is_empty()) else {
                return Err(AppError::Conflict(
                    "the invoice document is not attached yet",
                ));
            };
            let path = ObjectPath::parse(&key)
                .map_err(|e| AppError::internal(format!("invalid invoice document key: {e}")))?;
            let bytes = state
                .base
                .storage
                .store()
                .get(&path)
                .await
                .map_err(|e| {
                    AppError::internal(format!("reading the invoice document failed: {e}"))
                })?
                .bytes()
                .await
                .map_err(|e| {
                    AppError::internal(format!("reading the invoice document failed: {e}"))
                })?;
            if bytes.len() > attome_email::MAX_ATTACHMENT_BYTES {
                return Err(AppError::internal(
                    "the invoice document is too large to email",
                ));
            }
            let number = number.unwrap_or_default();
            let message = attome_email::EmailMessage {
                to: email,
                subject: format!("Invoice {number} | فاتورة {number}"),
                text_body: format!(
                    "Please find attached invoice {number}.\n\nمرفق الفاتورة رقم {number}."
                ),
                html_body: None,
                delivery_id: None,
                from_override: None,
                message_id: None,
                in_reply_to: None,
                references: None,
                communication_id: None,
                attachments: vec![attome_email::EmailAttachment {
                    filename: format!("{number}.pdf"),
                    content_type: "application/pdf".into(),
                    content_base64: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &bytes,
                    ),
                }],
            };
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let moved = sqlx::query(
                "UPDATE invoice SET status = 'sent', modified_at = now(), \
                     row_version = row_version + 1 \
                 WHERE id = $1 AND status = 'issued'",
            )
            .bind(invoice_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
            if moved == 0 {
                return Ok(());
            }
            attome_jobs::enqueue_in_tx(
                &mut tx,
                attome_core::jobs::EngineJob::SendEmail(Box::new(message)),
            )
            .await
            .map_err(AppError::internal)?;
            attome_audit::write_business_event_in_tx(
                &mut tx,
                &attome_audit::audit_service(state),
                attome_audit::BusinessEvent::new(
                    "invoice",
                    invoice_id,
                    attome_audit::AuditOperation::Execute,
                    "billing.invoice_sent",
                    issuer.unwrap_or(Uuid::nil()),
                )
                .source(attome_audit::AuditSource::BackgroundJob),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invoice() -> Invoice {
        Invoice {
            number: "INV-2026-000001".into(),
            kind: "invoice".into(),
            currency: "SAR".into(),
            buyer: "<script>alert(1)</script> Co".into(),
            issued: NaiveDate::from_ymd_opt(2026, 10, 18),
            due: NaiveDate::from_ymd_opt(2026, 11, 17),
            buyer_vat: Some("300000000000003".into()),
            address: None,
            net: "100".into(),
            vat: "15".into(),
            grand: "115".into(),
            document: None,
            issuer: None,
            language: "ar_en".into(),
        }
    }

    #[test]
    fn the_document_is_bilingual_and_escapes_every_value() {
        let lines = vec![(
            Some("Setup & support".into()),
            Some("1".into()),
            Some("100".into()),
            Some("15".into()),
            Some("15".into()),
            Some("115".into()),
        )];
        let doc = html(
            &invoice(),
            &lines,
            "Attome Co",
            "310000000000003",
            Some("1448-04-26 AH".into()),
        );
        assert!(doc.contains("Tax Invoice") && doc.contains("فاتورة ضريبية"));
        assert!(doc.contains("INV-2026-000001"));
        assert!(doc.contains("1448-04-26 AH"));
        assert!(doc.contains("310000000000003") && doc.contains("300000000000003"));
        assert!(!doc.contains("<script>"), "the buyer name was not escaped");
        assert!(doc.contains("Setup &amp; support"));
        assert_eq!(title("credit_note").1, "إشعار دائن");
    }
}
