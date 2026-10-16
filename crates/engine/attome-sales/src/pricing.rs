//! Opportunity line pricing (roadmap D6-T3), pure. The order is fixed: list
//! price, sales price override, line discount (percent, then amount), deal
//! discount. Full precision throughout; each line total is rounded once, to
//! the currency's minor units, half away from zero.

use rust_decimal::{Decimal, RoundingStrategy};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One-time or recurring value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LineKind {
    OneTime,
    /// A price per billing period: `per_year_factor` periods a year (12 for
    /// monthly), over `term_months`.
    Recurring {
        per_year_factor: Decimal,
        term_months: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceInput {
    pub line_id: Uuid,
    pub quantity: Decimal,
    pub list_price: Decimal,
    pub sales_price: Option<Decimal>,
    pub discount_percent: Option<Decimal>,
    pub discount_amount: Option<Decimal>,
    pub kind: LineKind,
}

/// One stage of a line's price, for the explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PriceStep {
    pub name: &'static str,
    pub value: Decimal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PricedLine {
    pub line_id: Uuid,
    /// The unit price after every discount, unrounded.
    pub net_unit: Decimal,
    /// Quantity times the net unit price, rounded once.
    pub line_total: Decimal,
    pub steps: Vec<PriceStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    pub one_time_total: Decimal,
    /// Recurring lines' value over a year.
    pub recurring_annual: Decimal,
    /// One-time value plus recurring value over each line's term.
    pub total_contract_value: Decimal,
}

const HUNDRED: Decimal = Decimal::ONE_HUNDRED;

fn round_once(value: Decimal, minor_units: u8) -> Decimal {
    value.round_dp_with_strategy(
        u32::from(minor_units),
        RoundingStrategy::MidpointAwayFromZero,
    )
}

/// Prices every line; `deal_discount_percent` applies after each line's own
/// discount.
pub fn price_lines(
    inputs: &[PriceInput],
    deal_discount_percent: Option<Decimal>,
    minor_units: u8,
) -> Vec<PricedLine> {
    inputs
        .iter()
        .map(|input| {
            let mut steps = vec![PriceStep {
                name: "list_price",
                value: input.list_price,
            }];
            let mut unit = input.list_price;
            if let Some(sales) = input.sales_price {
                unit = sales;
                steps.push(PriceStep {
                    name: "sales_price",
                    value: unit,
                });
            }
            if let Some(percent) = input.discount_percent.filter(|p| !p.is_zero()) {
                unit -= unit * percent / HUNDRED;
                steps.push(PriceStep {
                    name: "line_discount_percent",
                    value: unit,
                });
            }
            if let Some(amount) = input.discount_amount.filter(|a| !a.is_zero()) {
                unit = (unit - amount).max(Decimal::ZERO);
                steps.push(PriceStep {
                    name: "line_discount_amount",
                    value: unit,
                });
            }
            if let Some(percent) = deal_discount_percent.filter(|p| !p.is_zero()) {
                unit -= unit * percent / HUNDRED;
                steps.push(PriceStep {
                    name: "deal_discount",
                    value: unit,
                });
            }
            let line_total = round_once(unit * input.quantity, minor_units);
            steps.push(PriceStep {
                name: "line_total",
                value: line_total,
            });
            PricedLine {
                line_id: input.line_id,
                net_unit: unit,
                line_total,
                steps,
            }
        })
        .collect()
}

/// The deal's totals from its priced lines.
pub fn totals(priced: &[PricedLine], inputs: &[PriceInput]) -> Totals {
    let mut one_time_total = Decimal::ZERO;
    let mut recurring_annual = Decimal::ZERO;
    let mut recurring_term = Decimal::ZERO;
    for line in priced {
        let Some(input) = inputs.iter().find(|i| i.line_id == line.line_id) else {
            continue;
        };
        match input.kind {
            LineKind::OneTime => one_time_total += line.line_total,
            LineKind::Recurring {
                per_year_factor,
                term_months,
            } => {
                let annual = line.line_total * per_year_factor;
                recurring_annual += annual;
                recurring_term += annual * Decimal::from(term_months) / Decimal::from(12);
            }
        }
    }
    Totals {
        one_time_total,
        recurring_annual,
        total_contract_value: one_time_total + recurring_term,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).expect("decimal")
    }

    fn line(quantity: &str, list: &str) -> PriceInput {
        PriceInput {
            line_id: Uuid::now_v7(),
            quantity: dec(quantity),
            list_price: dec(list),
            sales_price: None,
            discount_percent: None,
            discount_amount: None,
            kind: LineKind::OneTime,
        }
    }

    #[test]
    fn list_times_quantity() {
        let priced = price_lines(&[line("3", "19.99")], None, 2);
        assert_eq!(priced[0].line_total, dec("59.97"));
    }

    #[test]
    fn sales_price_overrides_list() {
        let mut input = line("2", "100");
        input.sales_price = Some(dec("80"));
        let priced = price_lines(&[input], None, 2);
        assert_eq!(priced[0].net_unit, dec("80"));
        assert_eq!(priced[0].line_total, dec("160"));
    }

    #[test]
    fn deal_discount_after_line_discount() {
        let mut input = line("1", "100");
        input.discount_percent = Some(dec("10"));
        input.discount_amount = Some(dec("5"));
        let priced = price_lines(&[input], Some(dec("10")), 2);
        // 100 -> 90 (10%) -> 85 (-5) -> 76.5 (deal 10%).
        assert_eq!(priced[0].net_unit, dec("76.5"));
        assert_eq!(priced[0].line_total, dec("76.50"));
    }

    #[test]
    fn kwd_three_decimals_rounded_once() {
        let mut input = line("3", "0.3335");
        input.discount_percent = Some(dec("0"));
        let priced = price_lines(&[input], None, 3);
        // 1.0005 rounds once to 1.001; rounding the unit first would give 1.002.
        assert_eq!(priced[0].line_total, dec("1.001"));
    }

    #[test]
    fn recurring_annual_and_tcv() {
        let mut monthly = line("2", "50");
        monthly.kind = LineKind::Recurring {
            per_year_factor: dec("12"),
            term_months: 24,
        };
        let setup = line("1", "500");
        let inputs = vec![monthly, setup];
        let priced = price_lines(&inputs, None, 2);
        let t = totals(&priced, &inputs);
        assert_eq!(t.one_time_total, dec("500"));
        assert_eq!(t.recurring_annual, dec("1200"));
        assert_eq!(t.total_contract_value, dec("2900"));
    }

    #[test]
    fn steps_record_each_stage() {
        let mut input = line("1", "100");
        input.sales_price = Some(dec("90"));
        input.discount_percent = Some(dec("10"));
        let priced = price_lines(&[input], Some(dec("5")), 2);
        let names: Vec<&str> = priced[0].steps.iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            vec![
                "list_price",
                "sales_price",
                "line_discount_percent",
                "deal_discount",
                "line_total"
            ]
        );
    }
}
