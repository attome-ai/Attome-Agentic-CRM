//! The UBL 2.1 invoice ZATCA receives (Fatoora phase 2), written from an
//! invoice's data per ZATCA's data dictionary, for standard (B2B,
//! cleared) and simplified (B2C, reported) invoices, credit notes, debit
//! notes and prepayment invoices.
//!
//! The document always carries the three parts the signature fills in
//! later (`ext:UBLExtensions`, the QR `cac:AdditionalDocumentReference` and
//! `cac:Signature`), placeholders until [`super::sign`] stamps it. The
//! invoice hash leaves those three out ([`super::hash::invoice_hash`]), so
//! stamping never changes the hash the stamp signs.
//!
//! Amounts are written with two decimals (ZATCA's rule for SAR and for
//! every document currency), the unit price and quantity with up to six.
//! The totals are the sums of the lines' rounded amounts, the same rule
//! attome-billing uses, and a line's net must equal its quantity times its
//! price less its discount.

use chrono::{NaiveDate, NaiveTime};
use rust_decimal::{Decimal, RoundingStrategy};
use serde::{Deserialize, Serialize};

/// Which clearance path the invoice takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Profile {
    /// Business to business: cleared by ZATCA before it is sent.
    Standard,
    /// Business to consumer: reported to ZATCA within 24 hours.
    Simplified,
}

/// The kind of document (`cbc:InvoiceTypeCode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentKind {
    Invoice,
    CreditNote,
    DebitNote,
    Prepayment,
}

impl DocumentKind {
    pub fn type_code(self) -> &'static str {
        match self {
            Self::Invoice => "388",
            Self::CreditNote => "381",
            Self::DebitNote => "383",
            Self::Prepayment => "386",
        }
    }
}

/// A VAT category (UN/ECE 5305) with, when no VAT is charged, ZATCA's
/// exemption reason code and text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaxCategory {
    /// `S`: the standard (or a reduced) rate.
    Standard,
    /// `Z`: zero rated, e.g. `VATEX-SA-32` exports of goods.
    ZeroRated { reason_code: String, reason: String },
    /// `E`: exempt, e.g. `VATEX-SA-29` financial services.
    Exempt { reason_code: String, reason: String },
    /// `O`: outside the scope of VAT, e.g. `VATEX-SA-OOS`.
    OutOfScope { reason_code: String, reason: String },
}

impl TaxCategory {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Standard => "S",
            Self::ZeroRated { .. } => "Z",
            Self::Exempt { .. } => "E",
            Self::OutOfScope { .. } => "O",
        }
    }

    fn exemption(&self) -> Option<(&str, &str)> {
        match self {
            Self::Standard => None,
            Self::ZeroRated {
                reason_code,
                reason,
            }
            | Self::Exempt {
                reason_code,
                reason,
            }
            | Self::OutOfScope {
                reason_code,
                reason,
            } => Some((reason_code, reason)),
        }
    }
}

/// A postal address (KSA national address fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    pub street: String,
    /// Four digits.
    pub building_number: String,
    pub city_subdivision: String,
    pub city: String,
    /// Five digits.
    pub postal_zone: String,
    /// ISO 3166-1 alpha-2.
    pub country: String,
}

/// The seller or the buyer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Party {
    pub registration_name: String,
    /// Fifteen digits, starting and ending with 3, for a VAT-registered party.
    pub vat_number: Option<String>,
    /// Another identifier with its scheme (`CRN`, `MOM`, `MLS`, `700`, `SAG`,
    /// `NAT`, `GCC`, `IQA`, `PAS`, `OTH`), required where there is no VAT
    /// number (the seller's commercial registration, a buyer's national ID).
    pub other_id: Option<(String, String)>,
    pub address: Option<Address>,
}

/// One invoice line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Line {
    pub name: String,
    pub quantity: Decimal,
    /// UN/ECE recommendation 20 unit code, e.g. `PCE`.
    pub unit_code: String,
    pub unit_price: Decimal,
    /// The line's discount, an amount.
    pub discount: Decimal,
    /// Quantity times price less the discount, rounded.
    pub net: Decimal,
    pub category: TaxCategory,
    /// The rate, a percent (15 for 15%).
    pub percent: Decimal,
    /// The line's VAT, rounded.
    pub vat: Decimal,
}

/// Everything the invoice XML says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZatcaInvoice {
    pub profile: Profile,
    pub kind: DocumentKind,
    /// The invoice number (attome-billing's `invoice_number`).
    pub number: String,
    /// A UUID, kept for the invoice's life.
    pub uuid: String,
    pub issue_date: NaiveDate,
    pub issue_time: NaiveTime,
    /// ISO 4217.
    pub currency: String,
    /// The invoice counter value: this device's count of documents.
    pub icv: u64,
    /// The previous invoice's hash on this device (base64).
    pub pih: String,
    pub seller: Party,
    /// Required for a standard invoice.
    pub buyer: Option<Party>,
    /// The supply date (`cac:Delivery`), required for a standard invoice.
    pub supply_date: Option<NaiveDate>,
    /// UN/ECE 4461: `10` cash, `30` credit transfer, `42` bank account,
    /// `48` card, `1` not defined.
    pub payment_means: String,
    /// For a credit or debit note: the original invoice's number.
    pub original_number: Option<String>,
    /// For a credit or debit note: why it was issued.
    pub reason: Option<String>,
    /// For a document not in SAR: its VAT total converted to SAR.
    pub vat_in_sar: Option<Decimal>,
    pub lines: Vec<Line>,
}

/// What stamping fills in; placeholders until then.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stamp {
    /// The whole `ext:UBLExtensions` element.
    pub extensions: Option<String>,
    /// The QR code, base64 TLV.
    pub qr: Option<String>,
}

/// Why an invoice cannot be written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XmlError {
    #[error("{0}")]
    Invalid(String),
}

fn invalid(message: impl Into<String>) -> XmlError {
    XmlError::Invalid(message.into())
}

/// Rounds half away from zero, as attome-billing does.
fn round(value: Decimal, dp: u32) -> Decimal {
    value.round_dp_with_strategy(dp, RoundingStrategy::MidpointAwayFromZero)
}

/// Two decimals, as ZATCA writes amounts.
pub fn amount(value: Decimal) -> String {
    format!("{:.2}", round(value, 2))
}

/// A quantity or unit price, up to six decimals, no trailing zeros.
fn measure(value: Decimal) -> String {
    let v = round(value, 6).normalize();
    if v.scale() == 0 {
        format!("{v}.00")
    } else {
        v.to_string()
    }
}

fn percent(value: Decimal) -> String {
    format!("{:.2}", round(value, 2))
}

fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// A writer with four-space indentation.
struct W {
    out: String,
    depth: usize,
}

impl W {
    fn line(&mut self, text: &str) {
        self.out.push('\n');
        for _ in 0..self.depth {
            self.out.push_str("    ");
        }
        self.out.push_str(text);
    }
    fn open(&mut self, tag: &str) {
        self.line(&format!("<{tag}>"));
        self.depth += 1;
    }
    fn close(&mut self, tag: &str) {
        self.depth -= 1;
        self.line(&format!("</{tag}>"));
    }
    fn leaf(&mut self, tag: &str, text: &str) {
        self.line(&format!("<{tag}>{}</{tag}>", esc(text)));
    }
    fn leaf_attr(&mut self, tag: &str, attrs: &str, text: &str) {
        self.line(&format!("<{tag} {attrs}>{}</{tag}>", esc(text)));
    }
    fn money(&mut self, tag: &str, currency: &str, value: Decimal) {
        self.leaf_attr(
            tag,
            &format!("currencyID=\"{}\"", esc(currency)),
            &amount(value),
        );
    }
}

fn is_vat_number(v: &str) -> bool {
    v.len() == 15 && v.bytes().all(|b| b.is_ascii_digit()) && v.starts_with('3') && v.ends_with('3')
}

/// Checks what ZATCA rejects before anything is written.
fn validate(inv: &ZatcaInvoice) -> Result<(), XmlError> {
    if inv.lines.is_empty() {
        return Err(invalid("an invoice has at least one line"));
    }
    if inv.currency.len() != 3 {
        return Err(invalid("the currency is a three-letter ISO code"));
    }
    match &inv.seller.vat_number {
        Some(v) if is_vat_number(v) => {}
        _ => {
            return Err(invalid(
                "the seller's VAT number is fifteen digits starting and ending with 3",
            ));
        }
    }
    if inv.seller.address.is_none() {
        return Err(invalid("the seller's address is required"));
    }
    if inv.profile == Profile::Standard {
        let buyer = inv
            .buyer
            .as_ref()
            .ok_or_else(|| invalid("a standard invoice names its buyer"))?;
        if buyer.address.is_none() {
            return Err(invalid("a standard invoice carries the buyer's address"));
        }
        if buyer.vat_number.is_none() && buyer.other_id.is_none() {
            return Err(invalid(
                "a standard invoice carries the buyer's VAT number or another identifier",
            ));
        }
        if inv.supply_date.is_none() {
            return Err(invalid("a standard invoice carries the supply date"));
        }
    }
    if let Some(v) = inv.buyer.as_ref().and_then(|b| b.vat_number.as_deref())
        && !is_vat_number(v)
    {
        return Err(invalid(
            "the buyer's VAT number is fifteen digits starting and ending with 3",
        ));
    }
    if matches!(inv.kind, DocumentKind::CreditNote | DocumentKind::DebitNote)
        && (inv.original_number.is_none() || inv.reason.as_deref().is_none_or(str::is_empty))
    {
        return Err(invalid(
            "a credit or debit note names the original invoice and the reason",
        ));
    }
    if inv.currency != "SAR" && inv.vat_in_sar.is_none() {
        return Err(invalid("a document not in SAR carries its VAT in SAR"));
    }
    for (i, line) in inv.lines.iter().enumerate() {
        let expected = round(line.quantity * line.unit_price - line.discount, 2);
        if expected != round(line.net, 2) {
            return Err(invalid(format!(
                "line {}: the net {} is not quantity times price less discount ({expected})",
                i + 1,
                line.net
            )));
        }
        if line.category != TaxCategory::Standard && !line.vat.is_zero() {
            return Err(invalid(format!(
                "line {}: a zero-rated, exempt or out-of-scope line carries no VAT",
                i + 1
            )));
        }
    }
    Ok(())
}

/// One VAT subtotal: the category, the rate, and its sums.
struct Subtotal<'a> {
    category: &'a TaxCategory,
    percent: Decimal,
    taxable: Decimal,
    vat: Decimal,
}

fn subtotals(lines: &[Line]) -> Vec<Subtotal<'_>> {
    let mut out: Vec<Subtotal<'_>> = Vec::new();
    for line in lines {
        match out
            .iter_mut()
            .find(|s| s.category == &line.category && s.percent == line.percent)
        {
            Some(s) => {
                s.taxable += line.net;
                s.vat += line.vat;
            }
            None => out.push(Subtotal {
                category: &line.category,
                percent: line.percent,
                taxable: line.net,
                vat: line.vat,
            }),
        }
    }
    out
}

fn party(w: &mut W, tag: &str, p: &Party) {
    w.open(tag);
    w.open("cac:Party");
    if let Some((scheme, id)) = &p.other_id {
        w.open("cac:PartyIdentification");
        w.leaf_attr("cbc:ID", &format!("schemeID=\"{}\"", esc(scheme)), id);
        w.close("cac:PartyIdentification");
    }
    if let Some(a) = &p.address {
        w.open("cac:PostalAddress");
        w.leaf("cbc:StreetName", &a.street);
        w.leaf("cbc:BuildingNumber", &a.building_number);
        w.leaf("cbc:CitySubdivisionName", &a.city_subdivision);
        w.leaf("cbc:CityName", &a.city);
        w.leaf("cbc:PostalZone", &a.postal_zone);
        w.open("cac:Country");
        w.leaf("cbc:IdentificationCode", &a.country);
        w.close("cac:Country");
        w.close("cac:PostalAddress");
    }
    if let Some(vat) = &p.vat_number {
        w.open("cac:PartyTaxScheme");
        w.leaf("cbc:CompanyID", vat);
        w.open("cac:TaxScheme");
        w.leaf("cbc:ID", "VAT");
        w.close("cac:TaxScheme");
        w.close("cac:PartyTaxScheme");
    }
    w.open("cac:PartyLegalEntity");
    w.leaf("cbc:RegistrationName", &p.registration_name);
    w.close("cac:PartyLegalEntity");
    w.close("cac:Party");
    w.close(tag);
}

fn tax_category(w: &mut W, tag: &str, category: &TaxCategory, rate: Decimal) {
    w.open(tag);
    w.leaf_attr(
        "cbc:ID",
        "schemeID=\"UN/ECE 5305\" schemeAgencyID=\"6\"",
        category.code(),
    );
    w.leaf("cbc:Percent", &percent(rate));
    if let Some((code, reason)) = category.exemption() {
        w.leaf("cbc:TaxExemptionReasonCode", code);
        w.leaf("cbc:TaxExemptionReason", reason);
    }
    w.open("cac:TaxScheme");
    w.leaf_attr(
        "cbc:ID",
        "schemeID=\"UN/ECE 5153\" schemeAgencyID=\"6\"",
        "VAT",
    );
    w.close("cac:TaxScheme");
    w.close(tag);
}

/// The invoice's net and VAT totals: the sums of its lines.
pub fn totals(inv: &ZatcaInvoice) -> (Decimal, Decimal) {
    (
        inv.lines.iter().map(|l| l.net).sum(),
        inv.lines.iter().map(|l| l.vat).sum(),
    )
}

/// The placeholder extensions block, replaced when the invoice is stamped.
pub const EXTENSIONS_PLACEHOLDER: &str = "<ext:UBLExtensions></ext:UBLExtensions>";

/// Writes the invoice XML, with `stamp`'s parts or placeholders.
pub fn invoice_xml(inv: &ZatcaInvoice, stamp: &Stamp) -> Result<String, XmlError> {
    validate(inv)?;
    let currency = inv.currency.as_str();
    let mut w = W {
        out: String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Invoice xmlns=\"urn:oasis:names:specification:ubl:schema:xsd:Invoice-2\" xmlns:cac=\"urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2\" xmlns:cbc=\"urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2\" xmlns:ext=\"urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2\">",
        ),
        depth: 1,
    };
    w.line(
        stamp
            .extensions
            .as_deref()
            .unwrap_or(EXTENSIONS_PLACEHOLDER),
    );
    w.leaf("cbc:ProfileID", "reporting:1.0");
    w.leaf("cbc:ID", &inv.number);
    w.leaf("cbc:UUID", &inv.uuid);
    w.leaf(
        "cbc:IssueDate",
        &inv.issue_date.format("%Y-%m-%d").to_string(),
    );
    w.leaf(
        "cbc:IssueTime",
        &inv.issue_time.format("%H:%M:%S").to_string(),
    );
    let subtype = match inv.profile {
        Profile::Standard => "0100000",
        Profile::Simplified => "0200000",
    };
    w.leaf_attr(
        "cbc:InvoiceTypeCode",
        &format!("name=\"{subtype}\""),
        inv.kind.type_code(),
    );
    w.leaf("cbc:DocumentCurrencyCode", currency);
    w.leaf("cbc:TaxCurrencyCode", "SAR");
    if let Some(original) = &inv.original_number {
        w.open("cac:BillingReference");
        w.open("cac:InvoiceDocumentReference");
        w.leaf("cbc:ID", original);
        w.close("cac:InvoiceDocumentReference");
        w.close("cac:BillingReference");
    }
    w.open("cac:AdditionalDocumentReference");
    w.leaf("cbc:ID", "ICV");
    w.leaf("cbc:UUID", &inv.icv.to_string());
    w.close("cac:AdditionalDocumentReference");
    w.open("cac:AdditionalDocumentReference");
    w.leaf("cbc:ID", "PIH");
    w.open("cac:Attachment");
    w.leaf_attr(
        "cbc:EmbeddedDocumentBinaryObject",
        "mimeCode=\"text/plain\"",
        &inv.pih,
    );
    w.close("cac:Attachment");
    w.close("cac:AdditionalDocumentReference");
    w.open("cac:AdditionalDocumentReference");
    w.leaf("cbc:ID", "QR");
    w.open("cac:Attachment");
    w.leaf_attr(
        "cbc:EmbeddedDocumentBinaryObject",
        "mimeCode=\"text/plain\"",
        stamp.qr.as_deref().unwrap_or(""),
    );
    w.close("cac:Attachment");
    w.close("cac:AdditionalDocumentReference");
    w.open("cac:Signature");
    w.leaf(
        "cbc:ID",
        "urn:oasis:names:specification:ubl:signature:Invoice",
    );
    w.leaf(
        "cbc:SignatureMethod",
        "urn:oasis:names:specification:ubl:dsig:enveloped:xades",
    );
    w.close("cac:Signature");
    party(&mut w, "cac:AccountingSupplierParty", &inv.seller);
    match &inv.buyer {
        Some(buyer) => party(&mut w, "cac:AccountingCustomerParty", buyer),
        None => {
            w.open("cac:AccountingCustomerParty");
            w.line("<cac:Party></cac:Party>");
            w.close("cac:AccountingCustomerParty");
        }
    }
    if let Some(day) = inv.supply_date {
        w.open("cac:Delivery");
        w.leaf(
            "cbc:ActualDeliveryDate",
            &day.format("%Y-%m-%d").to_string(),
        );
        w.close("cac:Delivery");
    }
    w.open("cac:PaymentMeans");
    w.leaf("cbc:PaymentMeansCode", &inv.payment_means);
    if let Some(reason) = &inv.reason {
        w.leaf("cbc:InstructionNote", reason);
    }
    w.close("cac:PaymentMeans");

    let subs = subtotals(&inv.lines);
    let (net, vat) = totals(inv);
    // The VAT total in SAR, then the document-currency total with its subtotals.
    w.open("cac:TaxTotal");
    w.money("cbc:TaxAmount", "SAR", inv.vat_in_sar.unwrap_or(vat));
    w.close("cac:TaxTotal");
    w.open("cac:TaxTotal");
    w.money("cbc:TaxAmount", currency, vat);
    for s in &subs {
        w.open("cac:TaxSubtotal");
        w.money("cbc:TaxableAmount", currency, s.taxable);
        w.money("cbc:TaxAmount", currency, s.vat);
        tax_category(&mut w, "cac:TaxCategory", s.category, s.percent);
        w.close("cac:TaxSubtotal");
    }
    w.close("cac:TaxTotal");
    w.open("cac:LegalMonetaryTotal");
    w.money("cbc:LineExtensionAmount", currency, net);
    w.money("cbc:TaxExclusiveAmount", currency, net);
    w.money("cbc:TaxInclusiveAmount", currency, net + vat);
    w.money("cbc:AllowanceTotalAmount", currency, Decimal::ZERO);
    w.money("cbc:PrepaidAmount", currency, Decimal::ZERO);
    w.money("cbc:PayableAmount", currency, net + vat);
    w.close("cac:LegalMonetaryTotal");

    for (i, line) in inv.lines.iter().enumerate() {
        w.open("cac:InvoiceLine");
        w.leaf("cbc:ID", &(i + 1).to_string());
        w.leaf_attr(
            "cbc:InvoicedQuantity",
            &format!("unitCode=\"{}\"", esc(&line.unit_code)),
            &measure(line.quantity),
        );
        w.money("cbc:LineExtensionAmount", currency, line.net);
        if !line.discount.is_zero() {
            w.open("cac:AllowanceCharge");
            w.leaf("cbc:ChargeIndicator", "false");
            w.leaf("cbc:AllowanceChargeReason", "discount");
            w.money("cbc:Amount", currency, line.discount);
            w.close("cac:AllowanceCharge");
        }
        w.open("cac:TaxTotal");
        w.money("cbc:TaxAmount", currency, line.vat);
        w.money("cbc:RoundingAmount", currency, line.net + line.vat);
        w.close("cac:TaxTotal");
        w.open("cac:Item");
        w.leaf("cbc:Name", &line.name);
        w.open("cac:ClassifiedTaxCategory");
        w.leaf("cbc:ID", line.category.code());
        w.leaf("cbc:Percent", &percent(line.percent));
        w.open("cac:TaxScheme");
        w.leaf("cbc:ID", "VAT");
        w.close("cac:TaxScheme");
        w.close("cac:ClassifiedTaxCategory");
        w.close("cac:Item");
        w.open("cac:Price");
        w.leaf_attr(
            "cbc:PriceAmount",
            &format!("currencyID=\"{}\"", esc(currency)),
            &measure(line.unit_price),
        );
        w.close("cac:Price");
        w.close("cac:InvoiceLine");
    }
    w.depth = 0;
    w.line("</Invoice>");
    w.out.push('\n');
    Ok(w.out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::str::FromStr;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    pub(crate) fn sample() -> ZatcaInvoice {
        let address = |street: &str| Address {
            street: street.into(),
            building_number: "2322".into(),
            city_subdivision: "Al-Murabba".into(),
            city: "Riyadh".into(),
            postal_zone: "23333".into(),
            country: "SA".into(),
        };
        ZatcaInvoice {
            profile: Profile::Standard,
            kind: DocumentKind::Invoice,
            number: "INV-2026-000001".into(),
            uuid: "3cf5ee18-ee25-44ea-a444-2c37ba7f28be".into(),
            issue_date: NaiveDate::from_ymd_opt(2026, 10, 18).unwrap(),
            issue_time: NaiveTime::from_hms_opt(9, 30, 0).unwrap(),
            currency: "SAR".into(),
            icv: 1,
            pih: super::super::hash::FIRST_PIH.into(),
            seller: Party {
                registration_name: "شركة أتوم & شركاه".into(),
                vat_number: Some("399999999900003".into()),
                other_id: Some(("CRN".into(), "1010010000".into())),
                address: Some(address("Prince Sultan")),
            },
            buyer: Some(Party {
                registration_name: "Fatoora Samples".into(),
                vat_number: Some("399999999800003".into()),
                other_id: None,
                address: Some(address("Salah Al-Din")),
            }),
            supply_date: NaiveDate::from_ymd_opt(2026, 10, 18),
            payment_means: "30".into(),
            original_number: None,
            reason: None,
            vat_in_sar: None,
            lines: vec![
                Line {
                    name: "Setup".into(),
                    quantity: d("2"),
                    unit_code: "PCE".into(),
                    unit_price: d("100"),
                    discount: d("10"),
                    net: d("190"),
                    category: TaxCategory::Standard,
                    percent: d("15"),
                    vat: d("28.50"),
                },
                Line {
                    name: "Training (exempt)".into(),
                    quantity: d("1"),
                    unit_code: "PCE".into(),
                    unit_price: d("50"),
                    discount: Decimal::ZERO,
                    net: d("50"),
                    category: TaxCategory::Exempt {
                        reason_code: "VATEX-SA-29".into(),
                        reason: "Financial services mentioned in Article 29 of the VAT Regulations"
                            .into(),
                    },
                    percent: Decimal::ZERO,
                    vat: Decimal::ZERO,
                },
            ],
        }
    }

    #[test]
    fn zatca_xml_writes_a_well_formed_standard_invoice() {
        let xml = invoice_xml(&sample(), &Stamp::default()).unwrap();
        // Well formed, and the parts ZATCA reads are there.
        super::super::c14n::canonicalize(&xml, super::super::c14n::Removal::None).unwrap();
        assert!(xml.contains("<cbc:InvoiceTypeCode name=\"0100000\">388</cbc:InvoiceTypeCode>"));
        assert!(xml.contains("شركة أتوم &amp; شركاه"));
        assert!(xml.contains("<cbc:TaxableAmount currencyID=\"SAR\">190.00</cbc:TaxableAmount>"));
        assert!(
            xml.contains("<cbc:TaxExemptionReasonCode>VATEX-SA-29</cbc:TaxExemptionReasonCode>")
        );
        assert!(xml.contains("<cbc:PayableAmount currencyID=\"SAR\">268.50</cbc:PayableAmount>"));
        assert!(xml.contains("<cbc:InvoicedQuantity unitCode=\"PCE\">2.00</cbc:InvoicedQuantity>"));
        assert!(xml.contains("<cbc:ID>QR</cbc:ID>"));
    }

    #[test]
    fn zatca_xml_refuses_what_zatca_rejects() {
        let mut inv = sample();
        inv.seller.vat_number = Some("123".into());
        assert!(invoice_xml(&inv, &Stamp::default()).is_err());
        let mut inv = sample();
        inv.buyer = None;
        assert!(invoice_xml(&inv, &Stamp::default()).is_err());
        inv.profile = Profile::Simplified;
        assert!(invoice_xml(&inv, &Stamp::default()).is_ok());
        let mut inv = sample();
        inv.kind = DocumentKind::CreditNote;
        assert!(invoice_xml(&inv, &Stamp::default()).is_err());
        inv.original_number = Some("INV-2026-000001".into());
        inv.reason = Some("Returned goods".into());
        assert!(invoice_xml(&inv, &Stamp::default()).is_ok());
        let mut inv = sample();
        inv.lines[0].net = d("200");
        assert!(invoice_xml(&inv, &Stamp::default()).is_err());
    }

    #[test]
    fn zatca_xml_amounts_have_two_decimals() {
        assert_eq!(amount(d("4")), "4.00");
        assert_eq!(amount(d("0.605")), "0.61");
        assert_eq!(measure(d("2")), "2.00");
        assert_eq!(measure(d("2.5000")), "2.5");
    }
}
