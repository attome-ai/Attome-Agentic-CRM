//! Three-way match (roadmap W3-T3), pure: a vendor bill is checked against
//! its purchase order (what was agreed) and its goods receipts (what
//! arrived and was accepted) before it may be posted.
//!
//! Per order line, the quantity billed so far may not exceed the accepted
//! received quantity by more than the quantity tolerance, and the billed
//! unit price may not exceed the ordered one by more than the price
//! tolerance. A bill without lines is checked on its net total against the
//! value of what was received and not yet billed. A quantity problem wins
//! over a price problem; either sends the bill to a person
//! (`vendor_bill.match_status` = `quantity_variance` or `price_variance`).
//!
//! The vendor's ZATCA QR code (base64 TLV: seller, VAT number, time, total
//! with VAT, VAT) is read by [`decode_zatca_qr`] and compared with the bill
//! by [`check_zatca_qr`].

use base64::Engine;
use rust_decimal::Decimal;
use serde::Serialize;
use uuid::Uuid;

/// How far a bill may stray before a person looks at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tolerances {
    /// Percent over the ordered unit price.
    pub price_percent: Decimal,
    /// Percent over the accepted received quantity.
    pub quantity_percent: Decimal,
    /// An absolute amount a header-only bill may be over (rounding).
    pub amount: Decimal,
}

impl Default for Tolerances {
    fn default() -> Self {
        Self {
            price_percent: Decimal::from(2),
            quantity_percent: Decimal::ZERO,
            amount: Decimal::new(1, 2),
        }
    }
}

/// One purchase order line with what arrived and what was billed before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderLine {
    pub id: Uuid,
    pub ordered: Decimal,
    pub unit_price: Decimal,
    /// Received less rejected, over every receipt.
    pub accepted: Decimal,
    /// Billed on earlier bills.
    pub billed_before: Decimal,
}

/// One line of the bill being matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillLine {
    pub order_line: Uuid,
    pub quantity: Decimal,
    pub unit_price: Decimal,
}

/// The stored match status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchStatus {
    Matched,
    PriceVariance,
    QuantityVariance,
}

impl MatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::PriceVariance => "price_variance",
            Self::QuantityVariance => "quantity_variance",
        }
    }
}

/// Why a line (or the whole bill) is out of tolerance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Variance {
    /// `None` for a header-only bill.
    pub order_line: Option<Uuid>,
    pub kind: MatchStatus,
    pub expected: Decimal,
    pub billed: Decimal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatchResult {
    pub status: MatchStatus,
    pub variances: Vec<Variance>,
}

fn over(value: Decimal, base: Decimal, percent: Decimal) -> bool {
    value > base + base * percent / Decimal::ONE_HUNDRED
}

/// Matches a bill with lines.
pub fn match_lines(order: &[OrderLine], bill: &[BillLine], tol: Tolerances) -> MatchResult {
    let mut variances = Vec::new();
    for line in bill {
        let Some(ordered) = order.iter().find(|o| o.id == line.order_line) else {
            // Billing a line that is not on the order: nothing was agreed.
            variances.push(Variance {
                order_line: Some(line.order_line),
                kind: MatchStatus::QuantityVariance,
                expected: Decimal::ZERO,
                billed: line.quantity,
            });
            continue;
        };
        let billed_total: Decimal = bill
            .iter()
            .filter(|b| b.order_line == line.order_line)
            .map(|b| b.quantity)
            .sum::<Decimal>()
            + ordered.billed_before;
        if over(billed_total, ordered.accepted, tol.quantity_percent)
            && !variances.iter().any(|v: &Variance| {
                v.order_line == Some(line.order_line) && v.kind == MatchStatus::QuantityVariance
            })
        {
            variances.push(Variance {
                order_line: Some(line.order_line),
                kind: MatchStatus::QuantityVariance,
                expected: ordered.accepted,
                billed: billed_total,
            });
        }
        if over(line.unit_price, ordered.unit_price, tol.price_percent) {
            variances.push(Variance {
                order_line: Some(line.order_line),
                kind: MatchStatus::PriceVariance,
                expected: ordered.unit_price,
                billed: line.unit_price,
            });
        }
    }
    result(variances)
}

/// Matches a bill that carries only its net total.
pub fn match_header(order: &[OrderLine], net_total: Decimal, tol: Tolerances) -> MatchResult {
    let open_received: Decimal = order
        .iter()
        .map(|l| (l.accepted - l.billed_before).max(Decimal::ZERO) * l.unit_price)
        .sum();
    let open_ordered: Decimal = order
        .iter()
        .map(|l| (l.ordered - l.billed_before).max(Decimal::ZERO) * l.unit_price)
        .sum();
    let limit =
        open_received + open_received * tol.price_percent / Decimal::ONE_HUNDRED + tol.amount;
    if net_total <= limit {
        return result(vec![]);
    }
    // Within what was ordered but more than arrived: billing ahead of
    // delivery. Beyond what was ordered: the price is off.
    let kind = if net_total <= open_ordered + tol.amount {
        MatchStatus::QuantityVariance
    } else {
        MatchStatus::PriceVariance
    };
    result(vec![Variance {
        order_line: None,
        kind,
        expected: open_received,
        billed: net_total,
    }])
}

fn result(variances: Vec<Variance>) -> MatchResult {
    let status = if variances
        .iter()
        .any(|v| v.kind == MatchStatus::QuantityVariance)
    {
        MatchStatus::QuantityVariance
    } else if variances.is_empty() {
        MatchStatus::Matched
    } else {
        MatchStatus::PriceVariance
    };
    MatchResult { status, variances }
}

/// The five fields of a ZATCA (phase 1) QR code.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZatcaQr {
    pub seller_name: String,
    pub vat_number: String,
    pub timestamp: String,
    pub total_with_vat: String,
    pub vat_total: String,
}

/// Reads a base64 TLV QR payload; `None` when it is not one.
pub fn decode_zatca_qr(payload: &str) -> Option<ZatcaQr> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(payload.trim())
        .ok()?;
    let mut qr = ZatcaQr::default();
    let mut i = 0;
    while i < bytes.len() {
        let tag = *bytes.get(i)?;
        let len = usize::from(*bytes.get(i + 1)?);
        let value = std::str::from_utf8(bytes.get(i + 2..i + 2 + len)?)
            .ok()?
            .to_owned();
        match tag {
            1 => qr.seller_name = value,
            2 => qr.vat_number = value,
            3 => qr.timestamp = value,
            4 => qr.total_with_vat = value,
            5 => qr.vat_total = value,
            _ => {}
        }
        i += 2 + len;
    }
    (!qr.vat_number.is_empty()).then_some(qr)
}

/// What disagrees between a QR code and the bill.
pub fn check_zatca_qr(
    qr: &ZatcaQr,
    vendor_vat_number: &str,
    grand_total: Decimal,
    vat_total: Decimal,
) -> Vec<&'static str> {
    let mut issues = Vec::new();
    if qr.vat_number.trim() != vendor_vat_number.trim() {
        issues.push("vat_number");
    }
    let amount = |s: &str| s.trim().parse::<Decimal>().ok();
    if amount(&qr.total_with_vat) != Some(grand_total) {
        issues.push("total_with_vat");
    }
    if amount(&qr.vat_total) != Some(vat_total) {
        issues.push("vat_total");
    }
    issues
}

#[cfg(test)]
mod three_way_match {
    use super::*;
    use std::str::FromStr;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap_or_default()
    }

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn order() -> Vec<OrderLine> {
        vec![
            OrderLine {
                id: u(1),
                ordered: d("10"),
                unit_price: d("100"),
                accepted: d("8"),
                billed_before: d("0"),
            },
            OrderLine {
                id: u(2),
                ordered: d("5"),
                unit_price: d("20"),
                accepted: d("5"),
                billed_before: d("2"),
            },
        ]
    }

    #[test]
    fn a_bill_for_what_arrived_at_the_agreed_price_matches() {
        let bill = vec![
            BillLine {
                order_line: u(1),
                quantity: d("8"),
                unit_price: d("101"),
            },
            BillLine {
                order_line: u(2),
                quantity: d("3"),
                unit_price: d("20"),
            },
        ];
        let r = match_lines(&order(), &bill, Tolerances::default());
        assert_eq!(r.status, MatchStatus::Matched, "1% over is within 2%");
    }

    #[test]
    fn billing_more_than_arrived_is_a_quantity_variance() {
        let bill = vec![
            BillLine {
                order_line: u(1),
                quantity: d("9"),
                unit_price: d("130"),
            },
            BillLine {
                order_line: u(2),
                quantity: d("4"),
                unit_price: d("20"),
            },
        ];
        let r = match_lines(&order(), &bill, Tolerances::default());
        assert_eq!(r.status, MatchStatus::QuantityVariance);
        assert_eq!(r.variances.len(), 3, "two quantity problems and one price");
    }

    #[test]
    fn a_higher_price_is_a_price_variance() {
        let bill = vec![BillLine {
            order_line: u(1),
            quantity: d("8"),
            unit_price: d("103"),
        }];
        let r = match_lines(&order(), &bill, Tolerances::default());
        assert_eq!(r.status, MatchStatus::PriceVariance);
        assert_eq!(r.variances[0].expected, d("100"));
    }

    #[test]
    fn a_line_not_on_the_order_is_refused() {
        let bill = vec![BillLine {
            order_line: u(9),
            quantity: d("1"),
            unit_price: d("1"),
        }];
        let r = match_lines(&order(), &bill, Tolerances::default());
        assert_eq!(r.status, MatchStatus::QuantityVariance);
    }

    #[test]
    fn header_only_bills_compare_with_the_received_value() {
        // Received and unbilled: 8 x 100 + 3 x 20 = 860.
        let tol = Tolerances::default();
        assert_eq!(
            match_header(&order(), d("860"), tol).status,
            MatchStatus::Matched
        );
        assert_eq!(
            match_header(&order(), d("870"), tol).status,
            MatchStatus::Matched,
            "within 2%"
        );
        // Ordered and unbilled: 10 x 100 + 3 x 20 = 1060.
        assert_eq!(
            match_header(&order(), d("1000"), tol).status,
            MatchStatus::QuantityVariance
        );
        assert_eq!(
            match_header(&order(), d("1200"), tol).status,
            MatchStatus::PriceVariance
        );
    }

    fn tlv(fields: &[(u8, &str)]) -> String {
        let mut bytes = Vec::new();
        for (tag, value) in fields {
            bytes.push(*tag);
            bytes.push(u8::try_from(value.len()).unwrap_or(0));
            bytes.extend_from_slice(value.as_bytes());
        }
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn zatca_qr_is_read_and_checked() {
        let payload = tlv(&[
            (1, "شركة المورد"),
            (2, "310122393500003"),
            (3, "2026-10-16T10:00:00Z"),
            (4, "1150.00"),
            (5, "150.00"),
        ]);
        let qr = decode_zatca_qr(&payload).unwrap_or_default();
        assert_eq!(qr.seller_name, "شركة المورد");
        assert!(check_zatca_qr(&qr, "310122393500003", d("1150"), d("150")).is_empty());
        assert_eq!(
            check_zatca_qr(&qr, "310122393500003", d("1200"), d("150")),
            vec!["total_with_vat"]
        );
        assert!(decode_zatca_qr("not base64!").is_none());
    }
}
