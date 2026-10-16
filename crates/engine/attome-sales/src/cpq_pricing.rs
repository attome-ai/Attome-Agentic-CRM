//! The CPQ pricing waterfall (roadmap F1-T2), pure: how a configured line
//! goes from its list price to what the customer pays, one step at a time,
//! so the quote shows each step and the agreed price can be explained.
//!
//! The order is fixed: list price; the account or contracted price when
//! [`crate::price_resolution`] found one; the volume break from the list;
//! the line's own discount (percent, then amount); promotions that apply on
//! the date and quantity, in the order given, each at most once; a step
//! never takes the unit price below zero. The finished line total is the
//! net unit price times the quantity, rounded once to the currency's minor
//! units. [`Waterfall`] serialises to the JSON the line stores beside its
//! price.

use chrono::NaiveDate;
use rust_decimal::{Decimal, RoundingStrategy};
use serde::Serialize;

use crate::price_resolution::{PriceSource, ResolvedPrice, Validity};

/// A promotion a quote line may take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Promotion {
    pub code: String,
    pub valid: Validity,
    /// The least quantity it needs.
    pub min_quantity: Decimal,
    pub reduction: Reduction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reduction {
    Percent(Decimal),
    /// Off each unit.
    AmountPerUnit(Decimal),
}

/// What prices one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaterfallInput {
    pub quantity: Decimal,
    /// The product's price-list price, before any break.
    pub list_price: Decimal,
    /// The result of price resolution, when it found a price.
    pub resolved: Option<ResolvedPrice>,
    pub discount_percent: Option<Decimal>,
    pub discount_amount: Option<Decimal>,
    pub promotions: Vec<Promotion>,
    pub date: NaiveDate,
    pub minor_units: u8,
}

/// One step of the waterfall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WaterfallStep {
    /// `list_price`, `account_price`, `contract_price`, `volume_break`,
    /// `line_discount_percent`, `line_discount_amount` or `promotion`.
    pub step: &'static str,
    /// The unit price after this step.
    pub unit_price: Decimal,
    /// What this step changed it by (negative is a reduction).
    pub change: Decimal,
    /// The promotion code, for a promotion step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Waterfall {
    pub steps: Vec<WaterfallStep>,
    pub net_unit: Decimal,
    pub line_total: Decimal,
}

/// Prices one line through the waterfall.
pub fn price(input: &WaterfallInput) -> Waterfall {
    let mut steps = vec![WaterfallStep {
        step: "list_price",
        unit_price: input.list_price,
        change: Decimal::ZERO,
        code: None,
    }];
    let mut unit = input.list_price;
    let mut push = |step: &'static str, next: Decimal, code: Option<String>, unit: &mut Decimal| {
        let next = next.max(Decimal::ZERO);
        if next != *unit || code.is_some() {
            steps.push(WaterfallStep {
                step,
                unit_price: next,
                change: next - *unit,
                code,
            });
        }
        *unit = next;
    };
    if let Some(resolved) = &input.resolved {
        let step = match resolved.source {
            PriceSource::AccountPrice { .. } => "account_price",
            PriceSource::Contract { .. } => "contract_price",
            PriceSource::PriceList { .. } => "volume_break",
        };
        push(step, resolved.price, None, &mut unit);
    }
    if let Some(pct) = input.discount_percent.filter(|p| !p.is_zero()) {
        push(
            "line_discount_percent",
            unit - unit * pct / Decimal::ONE_HUNDRED,
            None,
            &mut unit,
        );
    }
    if let Some(amount) = input.discount_amount.filter(|a| !a.is_zero()) {
        push("line_discount_amount", unit - amount, None, &mut unit);
    }
    let mut taken: Vec<&str> = Vec::new();
    for promo in &input.promotions {
        if taken.contains(&promo.code.as_str())
            || !promo.valid.contains(input.date)
            || input.quantity < promo.min_quantity
        {
            continue;
        }
        taken.push(&promo.code);
        let next = match promo.reduction {
            Reduction::Percent(pct) => unit - unit * pct / Decimal::ONE_HUNDRED,
            Reduction::AmountPerUnit(amount) => unit - amount,
        };
        push("promotion", next, Some(promo.code.clone()), &mut unit);
    }
    let line_total = (unit * input.quantity).round_dp_with_strategy(
        u32::from(input.minor_units),
        RoundingStrategy::MidpointAwayFromZero,
    );
    Waterfall {
        steps,
        net_unit: unit,
        line_total,
    }
}

#[cfg(test)]
mod cpq_pricing {
    use super::*;
    use std::str::FromStr;
    use uuid::Uuid;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap_or_default()
    }

    fn day(m: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, m, 1).unwrap_or_default()
    }

    fn input() -> WaterfallInput {
        WaterfallInput {
            quantity: d("10"),
            list_price: d("100"),
            resolved: None,
            discount_percent: None,
            discount_amount: None,
            promotions: vec![],
            date: day(6),
            minor_units: 2,
        }
    }

    fn names(w: &Waterfall) -> Vec<&'static str> {
        w.steps.iter().map(|s| s.step).collect()
    }

    #[test]
    fn every_step_is_shown_in_order() {
        let mut i = input();
        i.resolved = Some(ResolvedPrice {
            price: d("90"),
            source: PriceSource::PriceList {
                list: Uuid::from_u128(1),
                item: Uuid::from_u128(2),
                price_break: Some(Uuid::from_u128(3)),
            },
        });
        i.discount_percent = Some(d("10"));
        i.discount_amount = Some(d("1"));
        i.promotions = vec![Promotion {
            code: "SPRING".into(),
            valid: Validity::default(),
            min_quantity: d("5"),
            reduction: Reduction::Percent(d("5")),
        }];
        let w = price(&i);
        assert_eq!(
            names(&w),
            [
                "list_price",
                "volume_break",
                "line_discount_percent",
                "line_discount_amount",
                "promotion"
            ]
        );
        // 100 -> 90 -> 81 -> 80 -> 76.
        assert_eq!(w.net_unit, d("76"));
        assert_eq!(w.line_total, d("760.00"));
        assert_eq!(w.steps[2].change, d("-9"));
        assert_eq!(w.steps[4].code.as_deref(), Some("SPRING"));
    }

    #[test]
    fn account_price_step_is_named_by_its_source() {
        let mut i = input();
        i.resolved = Some(ResolvedPrice {
            price: d("85"),
            source: PriceSource::AccountPrice {
                id: Uuid::from_u128(9),
            },
        });
        assert_eq!(names(&price(&i)), ["list_price", "account_price"]);
    }

    #[test]
    fn promotions_need_their_date_and_quantity_and_apply_once() {
        let mut i = input();
        let promo = |code: &str, min: &str, to: Option<NaiveDate>| Promotion {
            code: code.into(),
            valid: Validity { from: None, to },
            min_quantity: d(min),
            reduction: Reduction::AmountPerUnit(d("10")),
        };
        i.promotions = vec![
            promo("EXPIRED", "1", Some(day(5))),
            promo("BULK", "50", None),
            promo("ONCE", "1", None),
            promo("ONCE", "1", None),
        ];
        let w = price(&i);
        assert_eq!(names(&w), ["list_price", "promotion"]);
        assert_eq!(w.net_unit, d("90"));
    }

    #[test]
    fn a_step_never_goes_below_zero_and_the_total_rounds_once() {
        let mut i = input();
        i.discount_amount = Some(d("150"));
        assert_eq!(price(&i).net_unit, Decimal::ZERO);
        let mut i = input();
        i.quantity = d("3");
        i.list_price = d("0.335");
        i.minor_units = 3;
        assert_eq!(price(&i).line_total, d("1.005"));
        i.minor_units = 2;
        assert_eq!(price(&i).line_total, d("1.01"));
    }

    #[test]
    fn the_waterfall_serialises_for_the_line() {
        let mut i = input();
        i.discount_percent = Some(d("10"));
        let json = serde_json::to_value(price(&i)).unwrap_or_default();
        assert_eq!(json["steps"][1]["step"], "line_discount_percent");
        assert_eq!(json["steps"][1]["unit_price"], "90");
        assert!(json["steps"][1].get("code").is_none());
    }
}
