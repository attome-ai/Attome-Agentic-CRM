//! The ETA document (roadmap AG3-T1): Egypt's e-invoice, JSON version 1.0.
//!
//! An invoice is document type `I`, a credit note `C` and a debit note `D`
//! (a note names the documents it corrects in `references`, by their ETA
//! UUID). Parties are a business (`B`, its tax registration number), a
//! person (`P`, national ID, needed above the threshold) or a foreigner
//! (`F`). Each line carries its item code (`EGS` internal or `GS1`), unit
//! type, quantity and unit value in EGP, and its taxable items (`T1` VAT at
//! 14 with sub-type `V009`, for example).
//!
//! The line math is ETA's: sales total = quantity × unit value; net total =
//! sales total − discount; each rate tax = (net total + taxable fees + value
//! difference) × rate ÷ 100; line total = net total + taxes − items
//! discount. Amounts carry five decimals. The document totals are the sums
//! of the lines, with taxes summed per tax type.
//!
//! Numbers are written as JSON numbers in the shortest form that keeps the
//! five-decimal value (an integral one without a fraction), and
//! [`super::serialize`] reads the same values, so what is signed is what
//! is sent.

use chrono::{DateTime, SecondsFormat, Utc};
use rust_decimal::Decimal;
use serde_json::{Map, Number, Value, json};

/// Invoice, credit note or debit note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtaKind {
    Invoice,
    CreditNote,
    DebitNote,
}

impl EtaKind {
    pub fn code(self) -> &'static str {
        match self {
            Self::Invoice => "I",
            Self::CreditNote => "C",
            Self::DebitNote => "D",
        }
    }
}

/// A party's address as ETA records it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EtaAddress {
    /// The issuer's branch code (`0` for the head office); issuer only.
    pub branch_id: Option<String>,
    /// ISO 3166-1 alpha-2, `EG` at home.
    pub country: String,
    pub governate: String,
    pub region_city: String,
    pub street: String,
    pub building_number: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtaParty {
    /// `B` business, `P` person, `F` foreigner.
    pub kind: String,
    /// The registration number, national ID or foreign ID.
    pub id: String,
    pub name: String,
    pub address: EtaAddress,
}

/// One taxable item on a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtaTax {
    /// `T1` VAT, `T2` table tax and so on (ETA's tax types).
    pub tax_type: String,
    /// ETA's sub-type, `V009` for general VAT.
    pub sub_type: String,
    /// Percent.
    pub rate: Decimal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtaLine {
    pub description: String,
    /// `EGS` (the taxpayer's coded item) or `GS1`.
    pub item_type: String,
    pub item_code: String,
    /// The taxpayer's own code for the item.
    pub internal_code: String,
    /// ETA unit type (`EA` each, `KGM` kilogram ...).
    pub unit_type: String,
    pub quantity: Decimal,
    /// The unit value in EGP.
    pub unit_value: Decimal,
    /// The currency the item was sold in, and its value and rate when not EGP.
    pub currency_sold: String,
    pub amount_sold: Option<Decimal>,
    pub exchange_rate: Option<Decimal>,
    /// The discount before tax, as an amount.
    pub discount: Decimal,
    /// The discount after tax.
    pub items_discount: Decimal,
    pub taxes: Vec<EtaTax>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtaInvoice {
    pub kind: EtaKind,
    pub internal_id: String,
    pub issued_at: DateTime<Utc>,
    /// The issuer's activity code (ETA's list, `4620` for example).
    pub activity_code: String,
    pub issuer: EtaParty,
    pub receiver: EtaParty,
    /// The ETA UUIDs a credit or debit note corrects.
    pub references: Vec<String>,
    pub lines: Vec<EtaLine>,
    /// A discount on the whole document, after tax.
    pub extra_discount: Decimal,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EtaError {
    #[error("the ETA document is not valid: {0}")]
    Invalid(String),
}

fn r5(v: Decimal) -> Decimal {
    v.round_dp_with_strategy(5, rust_decimal::RoundingStrategy::MidpointAwayFromZero)
}

/// `v` (rounded to five decimals) as a JSON number in its shortest form.
/// Pure.
pub fn number(v: Decimal) -> Value {
    let v = r5(v).normalize();
    if v.fract().is_zero()
        && let Ok(i) = i64::try_from(v)
    {
        return Value::Number(i.into());
    }
    v.to_string()
        .parse::<f64>()
        .ok()
        .and_then(Number::from_f64)
        .map_or(Value::Null, Value::Number)
}

/// A line's figures: sales total, net total, each tax's amount, and total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineFigures {
    pub sales_total: Decimal,
    pub net_total: Decimal,
    pub taxes: Vec<Decimal>,
    pub total: Decimal,
}

/// A line's figures by ETA's math. Pure.
pub fn line_figures(line: &EtaLine) -> LineFigures {
    let sales_total = r5(line.quantity * line.unit_value);
    let net_total = r5(sales_total - line.discount);
    let taxes: Vec<Decimal> = line
        .taxes
        .iter()
        .map(|t| r5(net_total * t.rate / Decimal::ONE_HUNDRED))
        .collect();
    let total = r5(net_total + taxes.iter().sum::<Decimal>() - line.items_discount);
    LineFigures {
        sales_total,
        net_total,
        taxes,
        total,
    }
}

fn validate(inv: &EtaInvoice) -> Result<(), EtaError> {
    let bad = |m: &str| Err(EtaError::Invalid(m.to_owned()));
    if inv.internal_id.trim().is_empty() {
        return bad("the internal id (the invoice number) is required");
    }
    if inv.issuer.kind != "B" || inv.issuer.id.trim().is_empty() {
        return bad("the issuer is a business with its tax registration number");
    }
    if inv.issuer.address.branch_id.is_none() {
        return bad("the issuer's address names its branch (0 for the head office)");
    }
    if !matches!(inv.receiver.kind.as_str(), "B" | "P" | "F") {
        return bad("the receiver is B, P or F");
    }
    if inv.activity_code.trim().is_empty() {
        return bad("the issuer's activity code is required");
    }
    if inv.lines.is_empty() {
        return bad("a document has at least one line");
    }
    if inv.kind != EtaKind::Invoice && inv.references.is_empty() {
        return bad("a credit or debit note names the documents it corrects");
    }
    for line in &inv.lines {
        if line.quantity <= Decimal::ZERO || line.unit_value < Decimal::ZERO {
            return bad("a line has a positive quantity and a unit value");
        }
        if line.currency_sold != "EGP"
            && (line.amount_sold.is_none() || line.exchange_rate.is_none())
        {
            return bad("a line sold in another currency carries its amount and rate");
        }
        if !matches!(line.item_type.as_str(), "EGS" | "GS1") {
            return bad("a line's item type is EGS or GS1");
        }
    }
    Ok(())
}

fn address(a: &EtaAddress) -> Value {
    let mut out = Map::new();
    if let Some(branch) = &a.branch_id {
        out.insert("branchID".into(), json!(branch));
    }
    out.insert("country".into(), json!(a.country));
    out.insert("governate".into(), json!(a.governate));
    out.insert("regionCity".into(), json!(a.region_city));
    out.insert("street".into(), json!(a.street));
    out.insert("buildingNumber".into(), json!(a.building_number));
    Value::Object(out)
}

fn party(p: &EtaParty) -> Value {
    json!({ "address": address(&p.address), "type": p.kind, "id": p.id, "name": p.name })
}

/// The document as ETA takes it, without its signatures. Pure.
pub fn document(inv: &EtaInvoice) -> Result<Value, EtaError> {
    validate(inv)?;
    let mut lines = Vec::new();
    let mut tax_totals: Vec<(String, Decimal)> = Vec::new();
    let (mut sales, mut discounts, mut net, mut items_discount) =
        (Decimal::ZERO, Decimal::ZERO, Decimal::ZERO, Decimal::ZERO);
    for line in &inv.lines {
        let f = line_figures(line);
        sales += f.sales_total;
        discounts += line.discount;
        net += f.net_total;
        items_discount += line.items_discount;
        let mut taxable = Vec::new();
        for (tax, amount) in line.taxes.iter().zip(&f.taxes) {
            taxable.push(json!({
                "taxType": tax.tax_type,
                "amount": number(*amount),
                "subType": tax.sub_type,
                "rate": number(tax.rate),
            }));
            match tax_totals.iter_mut().find(|(t, _)| *t == tax.tax_type) {
                Some(t) => t.1 += *amount,
                None => tax_totals.push((tax.tax_type.clone(), *amount)),
            }
        }
        let mut unit_value = Map::new();
        unit_value.insert("currencySold".into(), json!(line.currency_sold));
        unit_value.insert("amountEGP".into(), number(line.unit_value));
        if let (Some(sold), Some(rate)) = (line.amount_sold, line.exchange_rate) {
            unit_value.insert("amountSold".into(), number(sold));
            unit_value.insert("currencyExchangeRate".into(), number(rate));
        }
        let rate = if f.sales_total.is_zero() {
            Decimal::ZERO
        } else {
            line.discount * Decimal::ONE_HUNDRED / f.sales_total
        };
        lines.push(json!({
            "description": line.description,
            "itemType": line.item_type,
            "itemCode": line.item_code,
            "unitType": line.unit_type,
            "quantity": number(line.quantity),
            "internalCode": line.internal_code,
            "salesTotal": number(f.sales_total),
            "total": number(f.total),
            "valueDifference": 0,
            "totalTaxableFees": 0,
            "netTotal": number(f.net_total),
            "itemsDiscount": number(line.items_discount),
            "unitValue": Value::Object(unit_value),
            "discount": { "rate": number(rate), "amount": number(line.discount) },
            "taxableItems": taxable,
        }));
    }
    let taxes: Decimal = tax_totals.iter().map(|t| t.1).sum();
    let mut doc = Map::new();
    doc.insert("issuer".into(), party(&inv.issuer));
    doc.insert("receiver".into(), party(&inv.receiver));
    doc.insert("documentType".into(), json!(inv.kind.code()));
    doc.insert("documentTypeVersion".into(), json!("1.0"));
    doc.insert(
        "dateTimeIssued".into(),
        json!(inv.issued_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
    );
    doc.insert("taxpayerActivityCode".into(), json!(inv.activity_code));
    doc.insert("internalID".into(), json!(inv.internal_id));
    if !inv.references.is_empty() {
        doc.insert("references".into(), json!(inv.references));
    }
    doc.insert("invoiceLines".into(), Value::Array(lines));
    doc.insert("totalDiscountAmount".into(), number(discounts));
    doc.insert("totalSalesAmount".into(), number(sales));
    doc.insert("netAmount".into(), number(net));
    doc.insert(
        "taxTotals".into(),
        Value::Array(
            tax_totals
                .iter()
                .map(|(t, amount)| json!({ "taxType": t, "amount": number(*amount) }))
                .collect(),
        ),
    );
    doc.insert(
        "totalAmount".into(),
        number(net + taxes - inv.extra_discount - items_discount),
    );
    doc.insert("extraDiscountAmount".into(), number(inv.extra_discount));
    doc.insert("totalItemsDiscountAmount".into(), number(items_discount));
    Ok(Value::Object(doc))
}

#[cfg(test)]
mod eta_document {
    use super::*;
    use chrono::TimeZone;

    fn dec(text: &str) -> Decimal {
        text.parse().unwrap()
    }

    pub(crate) fn invoice() -> EtaInvoice {
        let address = |branch: Option<&str>| EtaAddress {
            branch_id: branch.map(str::to_owned),
            country: "EG".into(),
            governate: "Cairo".into(),
            region_city: "Nasr City".into(),
            street: "Abbas El Akkad".into(),
            building_number: "12".into(),
        };
        EtaInvoice {
            kind: EtaKind::Invoice,
            internal_id: "INV-2026-001".into(),
            issued_at: Utc.with_ymd_and_hms(2026, 11, 3, 8, 30, 0).unwrap(),
            activity_code: "4620".into(),
            issuer: EtaParty {
                kind: "B".into(),
                id: "100324932".into(),
                name: "Attome Egypt".into(),
                address: address(Some("0")),
            },
            receiver: EtaParty {
                kind: "B".into(),
                id: "313717919".into(),
                name: "Nile Trading".into(),
                address: address(None),
            },
            references: vec![],
            lines: vec![
                EtaLine {
                    description: "Consulting hours".into(),
                    item_type: "EGS".into(),
                    item_code: "EG-100324932-1".into(),
                    internal_code: "SRV-1".into(),
                    unit_type: "EA".into(),
                    quantity: dec("3"),
                    unit_value: dec("1000"),
                    currency_sold: "EGP".into(),
                    amount_sold: None,
                    exchange_rate: None,
                    discount: dec("300"),
                    items_discount: dec("0"),
                    taxes: vec![EtaTax {
                        tax_type: "T1".into(),
                        sub_type: "V009".into(),
                        rate: dec("14"),
                    }],
                },
                EtaLine {
                    description: "Licence".into(),
                    item_type: "EGS".into(),
                    item_code: "EG-100324932-2".into(),
                    internal_code: "LIC-1".into(),
                    unit_type: "EA".into(),
                    quantity: dec("1"),
                    unit_value: dec("2499.99"),
                    currency_sold: "EGP".into(),
                    amount_sold: None,
                    exchange_rate: None,
                    discount: dec("0"),
                    items_discount: dec("0"),
                    taxes: vec![EtaTax {
                        tax_type: "T1".into(),
                        sub_type: "V009".into(),
                        rate: dec("14"),
                    }],
                },
            ],
            extra_discount: dec("0"),
        }
    }

    #[test]
    fn line_math_and_totals_follow_eta() {
        let doc = document(&invoice()).unwrap();
        let first = &doc["invoiceLines"][0];
        assert_eq!(first["salesTotal"], json!(3000));
        assert_eq!(first["netTotal"], json!(2700));
        assert_eq!(first["discount"], json!({ "rate": 10, "amount": 300 }));
        assert_eq!(first["taxableItems"][0]["amount"], json!(378));
        assert_eq!(first["total"], json!(3078));
        let second = &doc["invoiceLines"][1];
        assert_eq!(second["taxableItems"][0]["amount"], json!(349.9986));
        assert_eq!(doc["netAmount"], json!(5199.99));
        assert_eq!(
            doc["taxTotals"],
            json!([{ "taxType": "T1", "amount": 727.9986 }])
        );
        assert_eq!(doc["totalAmount"], json!(5927.9886));
        assert_eq!(doc["dateTimeIssued"], "2026-11-03T08:30:00Z");
        assert_eq!(doc["issuer"]["address"]["branchID"], "0");
        assert!(doc["receiver"]["address"].get("branchID").is_none());
        assert!(doc.get("signatures").is_none());
    }

    #[test]
    fn notes_name_what_they_correct_and_bad_input_is_refused() {
        let mut note = invoice();
        note.kind = EtaKind::CreditNote;
        assert!(document(&note).is_err());
        note.references = vec!["ABCD1234".into()];
        assert_eq!(document(&note).unwrap()["references"], json!(["ABCD1234"]));
        let mut foreign = invoice();
        foreign.lines[0].currency_sold = "USD".into();
        assert!(document(&foreign).is_err());
        assert_eq!(number(dec("1.000004")), json!(1));
        assert_eq!(number(dec("0.123456")), json!(0.12346));
    }
}
