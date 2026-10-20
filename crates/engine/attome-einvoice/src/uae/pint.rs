//! The PINT AE invoice (roadmap AG3-T2): the Peppol International invoice
//! with the UAE specialisation, as UBL 2.1. An invoice is `Invoice` with
//! type code 380; a credit note is `CreditNote` with 381 and positive
//! amounts. The customisation is `urn:peppol:pint:billing-1@ae-1` and the
//! profile `urn:peppol:bis:billing`. Parties are identified by their
//! Peppol endpoint (scheme `0235`, the UAE TIN) and their VAT registration
//! (TRN). Amounts carry two decimals; a line's net is its quantity times
//! its price, and the totals are the sums of the lines' rounded amounts.
//! VAT categories are UNCL5305 codes (`S` standard, `Z` zero rated, `E`
//! exempt, `O` outside scope); an exempt or out-of-scope subtotal carries
//! its reason. When the document currency is not AED, the VAT total is
//! also given in AED at the invoice's rate.

use std::fmt::Write as _;

use chrono::NaiveDate;
use rust_decimal::Decimal;

pub const CUSTOMIZATION_ID: &str = "urn:peppol:pint:billing-1@ae-1";
pub const PROFILE_ID: &str = "urn:peppol:bis:billing";
/// The Peppol endpoint scheme for a UAE TIN.
pub const ENDPOINT_SCHEME: &str = "0235";

/// Invoice or credit note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PintKind {
    Invoice,
    CreditNote,
}

/// A VAT category (UNCL5305).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PintTax {
    Standard,
    ZeroRated,
    Exempt { reason: String },
    OutOfScope { reason: String },
}

impl PintTax {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Standard => "S",
            Self::ZeroRated => "Z",
            Self::Exempt { .. } => "E",
            Self::OutOfScope { .. } => "O",
        }
    }

    fn reason(&self) -> Option<&str> {
        match self {
            Self::Exempt { reason } | Self::OutOfScope { reason } => Some(reason),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PintParty {
    pub name: String,
    /// The UAE TIN, the Peppol endpoint.
    pub tin: String,
    /// The VAT registration number (TRN), when registered.
    pub trn: Option<String>,
    pub street: Option<String>,
    pub city: Option<String>,
    /// ISO 3166-1 alpha-2, `AE` for a UAE party.
    pub country: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PintLine {
    pub id: String,
    pub name: String,
    pub quantity: Decimal,
    /// UN/ECE recommendation 20 code (`C62` for one, `HUR` for an hour).
    pub unit: String,
    pub price: Decimal,
    pub tax: PintTax,
    /// Percent, 5 for standard-rated lines.
    pub rate: Decimal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PintInvoice {
    pub kind: PintKind,
    pub number: String,
    pub issue_date: NaiveDate,
    pub currency: String,
    /// AED per unit of `currency`, when it is not AED.
    pub aed_rate: Option<Decimal>,
    /// The invoice a credit note corrects.
    pub billing_reference: Option<String>,
    pub supplier: PintParty,
    pub customer: PintParty,
    pub lines: Vec<PintLine>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PintError {
    #[error("the PINT AE invoice is not valid: {0}")]
    Invalid(String),
}

fn r2(v: Decimal) -> Decimal {
    v.round_dp_with_strategy(2, rust_decimal::RoundingStrategy::MidpointAwayFromZero)
}

fn money(v: Decimal) -> String {
    format!("{:.2}", r2(v))
}

fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// A line's net amount. Pure.
pub fn line_net(line: &PintLine) -> Decimal {
    r2(line.quantity * line.price)
}

/// The VAT of the lines in one category at one rate. Pure.
fn subtotals(lines: &[PintLine]) -> Vec<(&PintTax, Decimal, Decimal, Decimal)> {
    let mut out: Vec<(&PintTax, Decimal, Decimal, Decimal)> = Vec::new();
    for line in lines {
        let net = line_net(line);
        match out
            .iter_mut()
            .find(|(t, rate, _, _)| *t == &line.tax && *rate == line.rate)
        {
            Some(s) => s.2 += net,
            None => out.push((&line.tax, line.rate, net, Decimal::ZERO)),
        }
    }
    for s in &mut out {
        s.3 = r2(s.2 * s.1 / Decimal::ONE_HUNDRED);
    }
    out
}

/// The document's net and VAT totals. Pure.
pub fn totals(inv: &PintInvoice) -> (Decimal, Decimal) {
    let net: Decimal = inv.lines.iter().map(line_net).sum();
    let vat: Decimal = subtotals(&inv.lines).iter().map(|s| s.3).sum();
    (net, vat)
}

fn validate(inv: &PintInvoice) -> Result<(), PintError> {
    let bad = |m: &str| Err(PintError::Invalid(m.to_owned()));
    if inv.number.trim().is_empty() {
        return bad("the invoice number is required");
    }
    if inv.currency.len() != 3 {
        return bad("the currency is a three-letter code");
    }
    if inv.currency != "AED" && inv.aed_rate.is_none_or(|r| r <= Decimal::ZERO) {
        return bad("an invoice not in AED needs its AED rate");
    }
    if inv
        .supplier
        .trn
        .as_deref()
        .is_none_or(|t| t.trim().is_empty())
    {
        return bad("the supplier's TRN is required");
    }
    for p in [&inv.supplier, &inv.customer] {
        if p.tin.trim().is_empty() || p.name.trim().is_empty() {
            return bad("each party needs a name and a TIN");
        }
    }
    if inv.kind == PintKind::CreditNote && inv.billing_reference.is_none() {
        return bad("a credit note names the invoice it corrects");
    }
    if inv.lines.is_empty() {
        return bad("an invoice has at least one line");
    }
    for line in &inv.lines {
        if line.quantity <= Decimal::ZERO || line.price < Decimal::ZERO {
            return bad("a line has a positive quantity and a price of zero or more");
        }
        if matches!(line.tax, PintTax::Exempt { ref reason } | PintTax::OutOfScope { ref reason } if reason.trim().is_empty())
        {
            return bad("an exempt or out-of-scope line needs its reason");
        }
    }
    Ok(())
}

fn party(out: &mut String, tag: &str, p: &PintParty) {
    let _ = write!(out, "<cac:{tag}><cac:Party>");
    let _ = write!(
        out,
        "<cbc:EndpointID schemeID=\"{ENDPOINT_SCHEME}\">{}</cbc:EndpointID>",
        esc(&p.tin)
    );
    out.push_str("<cac:PostalAddress>");
    if let Some(street) = &p.street {
        let _ = write!(out, "<cbc:StreetName>{}</cbc:StreetName>", esc(street));
    }
    if let Some(city) = &p.city {
        let _ = write!(out, "<cbc:CityName>{}</cbc:CityName>", esc(city));
    }
    let _ = write!(
        out,
        "<cac:Country><cbc:IdentificationCode>{}</cbc:IdentificationCode></cac:Country></cac:PostalAddress>",
        esc(&p.country)
    );
    if let Some(trn) = &p.trn {
        let _ = write!(
            out,
            "<cac:PartyTaxScheme><cbc:CompanyID>{}</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme>",
            esc(trn)
        );
    }
    let _ = write!(
        out,
        "<cac:PartyLegalEntity><cbc:RegistrationName>{}</cbc:RegistrationName></cac:PartyLegalEntity>",
        esc(&p.name)
    );
    let _ = write!(out, "</cac:Party></cac:{tag}>");
}

fn category(out: &mut String, tag: &str, tax: &PintTax, rate: Decimal) {
    let _ = write!(out, "<cac:{tag}><cbc:ID>{}</cbc:ID>", tax.code());
    if tax.code() != "O" {
        let _ = write!(out, "<cbc:Percent>{}</cbc:Percent>", money(rate));
    }
    if let Some(reason) = tax.reason() {
        let _ = write!(
            out,
            "<cbc:TaxExemptionReason>{}</cbc:TaxExemptionReason>",
            esc(reason)
        );
    }
    let _ = write!(
        out,
        "<cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:{tag}>"
    );
}

/// The PINT AE document as UBL 2.1 XML.
pub fn invoice_xml(inv: &PintInvoice) -> Result<String, PintError> {
    validate(inv)?;
    let (root, line_tag, qty_tag, type_tag, type_code) = match inv.kind {
        PintKind::Invoice => (
            "Invoice",
            "InvoiceLine",
            "InvoicedQuantity",
            "InvoiceTypeCode",
            "380",
        ),
        PintKind::CreditNote => (
            "CreditNote",
            "CreditNoteLine",
            "CreditedQuantity",
            "CreditNoteTypeCode",
            "381",
        ),
    };
    let ns = format!("urn:oasis:names:specification:ubl:schema:xsd:{root}-2");
    let cur = esc(&inv.currency);
    let mut out = String::new();
    let _ = write!(
        out,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><{root} xmlns=\"{ns}\" \
         xmlns:cac=\"urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2\" \
         xmlns:cbc=\"urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2\">"
    );
    let _ = write!(
        out,
        "<cbc:CustomizationID>{CUSTOMIZATION_ID}</cbc:CustomizationID>"
    );
    let _ = write!(out, "<cbc:ProfileID>{PROFILE_ID}</cbc:ProfileID>");
    let _ = write!(out, "<cbc:ID>{}</cbc:ID>", esc(&inv.number));
    let _ = write!(out, "<cbc:IssueDate>{}</cbc:IssueDate>", inv.issue_date);
    let _ = write!(out, "<cbc:{type_tag}>{type_code}</cbc:{type_tag}>");
    let _ = write!(
        out,
        "<cbc:DocumentCurrencyCode>{cur}</cbc:DocumentCurrencyCode>"
    );
    if inv.currency != "AED" {
        out.push_str("<cbc:TaxCurrencyCode>AED</cbc:TaxCurrencyCode>");
    }
    if let Some(reference) = &inv.billing_reference {
        let _ = write!(
            out,
            "<cac:BillingReference><cac:InvoiceDocumentReference><cbc:ID>{}</cbc:ID></cac:InvoiceDocumentReference></cac:BillingReference>",
            esc(reference)
        );
    }
    party(&mut out, "AccountingSupplierParty", &inv.supplier);
    party(&mut out, "AccountingCustomerParty", &inv.customer);

    let subs = subtotals(&inv.lines);
    let (net, vat) = totals(inv);
    let _ = write!(
        out,
        "<cac:TaxTotal><cbc:TaxAmount currencyID=\"{cur}\">{}</cbc:TaxAmount>",
        money(vat)
    );
    for (tax, rate, taxable, amount) in &subs {
        let _ = write!(
            out,
            "<cac:TaxSubtotal><cbc:TaxableAmount currencyID=\"{cur}\">{}</cbc:TaxableAmount>\
             <cbc:TaxAmount currencyID=\"{cur}\">{}</cbc:TaxAmount>",
            money(*taxable),
            money(*amount)
        );
        category(&mut out, "TaxCategory", tax, *rate);
        out.push_str("</cac:TaxSubtotal>");
    }
    out.push_str("</cac:TaxTotal>");
    if let Some(rate) = inv.aed_rate.filter(|_| inv.currency != "AED") {
        let _ = write!(
            out,
            "<cac:TaxTotal><cbc:TaxAmount currencyID=\"AED\">{}</cbc:TaxAmount></cac:TaxTotal>",
            money(vat * rate)
        );
    }
    let _ = write!(
        out,
        "<cac:LegalMonetaryTotal>\
         <cbc:LineExtensionAmount currencyID=\"{cur}\">{n}</cbc:LineExtensionAmount>\
         <cbc:TaxExclusiveAmount currencyID=\"{cur}\">{n}</cbc:TaxExclusiveAmount>\
         <cbc:TaxInclusiveAmount currencyID=\"{cur}\">{g}</cbc:TaxInclusiveAmount>\
         <cbc:PayableAmount currencyID=\"{cur}\">{g}</cbc:PayableAmount>\
         </cac:LegalMonetaryTotal>",
        n = money(net),
        g = money(net + vat)
    );
    for line in &inv.lines {
        let _ = write!(out, "<cac:{line_tag}><cbc:ID>{}</cbc:ID>", esc(&line.id));
        let _ = write!(
            out,
            "<cbc:{qty_tag} unitCode=\"{}\">{}</cbc:{qty_tag}>",
            esc(&line.unit),
            line.quantity.normalize()
        );
        let _ = write!(
            out,
            "<cbc:LineExtensionAmount currencyID=\"{cur}\">{}</cbc:LineExtensionAmount>",
            money(line_net(line))
        );
        let _ = write!(out, "<cac:Item><cbc:Name>{}</cbc:Name>", esc(&line.name));
        category(&mut out, "ClassifiedTaxCategory", &line.tax, line.rate);
        out.push_str("</cac:Item>");
        let _ = write!(
            out,
            "<cac:Price><cbc:PriceAmount currencyID=\"{cur}\">{}</cbc:PriceAmount></cac:Price>",
            line.price.normalize()
        );
        let _ = write!(out, "</cac:{line_tag}>");
    }
    let _ = write!(out, "</{root}>");
    Ok(out)
}

#[cfg(test)]
mod uae_pint {
    use super::*;

    fn party(name: &str, tin: &str, trn: Option<&str>) -> PintParty {
        PintParty {
            name: name.into(),
            tin: tin.into(),
            trn: trn.map(str::to_owned),
            street: Some("Sheikh Zayed Road".into()),
            city: Some("Dubai".into()),
            country: "AE".into(),
        }
    }

    fn fixture() -> PintInvoice {
        PintInvoice {
            kind: PintKind::Invoice,
            number: "INV-2027-0001".into(),
            issue_date: NaiveDate::from_ymd_opt(2027, 1, 15).unwrap(),
            currency: "AED".into(),
            aed_rate: None,
            billing_reference: None,
            supplier: party("Attome Trading LLC", "1000000001", Some("100000000100003")),
            customer: party("Gulf & Co", "1000000002", Some("100000000200003")),
            lines: vec![
                PintLine {
                    id: "1".into(),
                    name: "Licences".into(),
                    quantity: Decimal::from(10),
                    unit: "C62".into(),
                    price: Decimal::new(9999, 2),
                    tax: PintTax::Standard,
                    rate: Decimal::from(5),
                },
                PintLine {
                    id: "2".into(),
                    name: "Training (education)".into(),
                    quantity: Decimal::from(2),
                    unit: "HUR".into(),
                    price: Decimal::from(300),
                    tax: PintTax::Exempt {
                        reason: "Exempt supply".into(),
                    },
                    rate: Decimal::ZERO,
                },
            ],
        }
    }

    #[test]
    fn writes_the_pint_ae_invoice() {
        let xml = invoice_xml(&fixture()).unwrap();
        assert!(
            xml.contains(
                "<cbc:CustomizationID>urn:peppol:pint:billing-1@ae-1</cbc:CustomizationID>"
            )
        );
        assert!(xml.contains("<cbc:ProfileID>urn:peppol:bis:billing</cbc:ProfileID>"));
        assert!(xml.contains("<cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>"));
        assert!(xml.contains("<cbc:EndpointID schemeID=\"0235\">1000000001</cbc:EndpointID>"));
        assert!(xml.contains("<cbc:RegistrationName>Gulf &amp; Co</cbc:RegistrationName>"));
        // 10 x 99.99 = 999.90 at 5% = 50.00 (49.995 rounds away from zero); 600 exempt.
        assert!(xml.contains(
            "<cbc:LineExtensionAmount currencyID=\"AED\">1599.90</cbc:LineExtensionAmount>"
        ));
        assert!(xml.contains("<cbc:TaxAmount currencyID=\"AED\">50.00</cbc:TaxAmount>"));
        assert!(xml.contains("<cbc:PayableAmount currencyID=\"AED\">1649.90</cbc:PayableAmount>"));
        assert!(xml.contains("<cbc:TaxExemptionReason>Exempt supply</cbc:TaxExemptionReason>"));
        assert!(
            !xml.contains("TaxCurrencyCode"),
            "an AED invoice has no tax currency"
        );
    }

    #[test]
    fn a_credit_note_in_another_currency_reports_aed_vat() {
        let mut inv = fixture();
        inv.kind = PintKind::CreditNote;
        inv.currency = "USD".into();
        inv.aed_rate = Some(Decimal::new(36725, 4));
        inv.billing_reference = Some("INV-2027-0001".into());
        inv.lines.truncate(1);
        let xml = invoice_xml(&inv).unwrap();
        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains(
            "<CreditNote xmlns=\"urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2\""
        ));
        assert!(xml.contains("<cbc:CreditNoteTypeCode>381</cbc:CreditNoteTypeCode>"));
        assert!(xml.contains("<cbc:TaxCurrencyCode>AED</cbc:TaxCurrencyCode>"));
        // 50.00 USD of VAT at 3.6725 = 183.63 AED.
        assert!(xml.contains("<cbc:TaxAmount currencyID=\"AED\">183.63</cbc:TaxAmount>"));
        assert!(xml.contains("<cbc:CreditedQuantity unitCode=\"C62\">10</cbc:CreditedQuantity>"));
    }

    #[test]
    fn refuses_what_the_fta_would() {
        let mut inv = fixture();
        inv.supplier.trn = None;
        assert!(invoice_xml(&inv).is_err());
        let mut inv = fixture();
        inv.kind = PintKind::CreditNote;
        assert!(
            invoice_xml(&inv).is_err(),
            "a credit note names its invoice"
        );
        let mut inv = fixture();
        inv.currency = "USD".into();
        assert!(
            invoice_xml(&inv).is_err(),
            "a foreign currency needs its AED rate"
        );
    }
}
