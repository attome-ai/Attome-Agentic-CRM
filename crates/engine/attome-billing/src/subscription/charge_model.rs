//! Charge models (roadmap F3-T3): what one period of a subscription line
//! costs for a quantity and a unit price. Pure; the caller decides which
//! periods a model charges (a setup fee once, the rest every period).

use std::str::FromStr;

use rust_decimal::{Decimal, RoundingStrategy};
use serde_json::Value;

/// One price band: quantities from `from` up to (not including) `to`;
/// `None` is open-ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier {
    pub from: Decimal,
    pub to: Option<Decimal>,
    pub price: Decimal,
}

/// How a line's period amount is worked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChargeModel {
    /// The unit price, whatever the quantity.
    Flat,
    /// Quantity times unit price.
    PerUnit,
    /// Each band's share of the quantity at that band's price, summed.
    Tiered(Vec<Tier>),
    /// The whole quantity at the price of the band it falls in.
    Volume(Vec<Tier>),
    /// The unit price, charged once.
    SetupFee,
    /// Quantity times unit price, but never less than the commitment.
    MinimumCommitment(Decimal),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChargeError {
    #[error("tiers must be a JSON array of {{from, to, price}}")]
    Shape,
    #[error("tier {0} has a value that is not a number")]
    NotANumber(usize),
    #[error("tiers must start at 0")]
    NotFromZero,
    #[error("tier {0} does not start where the one before it ends")]
    Gap(usize),
    #[error("only the last tier may be open-ended")]
    OpenBeforeLast,
    #[error("tier {0} ends before it starts")]
    Reversed(usize),
}

/// The amount one period of the line costs, unrounded.
pub fn period_amount(model: &ChargeModel, quantity: Decimal, unit_price: Decimal) -> Decimal {
    match model {
        ChargeModel::Flat | ChargeModel::SetupFee => unit_price,
        ChargeModel::PerUnit => quantity * unit_price,
        ChargeModel::Tiered(tiers) => tiers
            .iter()
            .map(|t| {
                let upper = t.to.map_or(quantity, |to| quantity.min(to));
                let inside = (upper - t.from).max(Decimal::ZERO);
                inside * t.price
            })
            .sum(),
        ChargeModel::Volume(tiers) => {
            let band = tiers
                .iter()
                .find(|t| quantity >= t.from && t.to.is_none_or(|to| quantity < to))
                .or_else(|| tiers.last());
            band.map_or(Decimal::ZERO, |t| quantity * t.price)
        }
        ChargeModel::MinimumCommitment(min) => (quantity * unit_price).max(*min),
    }
}

fn number(value: Option<&Value>, index: usize) -> Result<Option<Decimal>, ChargeError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => Decimal::from_str(&n.to_string())
            .map(Some)
            .map_err(|_| ChargeError::NotANumber(index)),
        Some(Value::String(s)) => Decimal::from_str(s.trim())
            .map(Some)
            .map_err(|_| ChargeError::NotANumber(index)),
        Some(_) => Err(ChargeError::NotANumber(index)),
    }
}

/// Reads `subscription_line.tiers_json`: bands that start at 0, each where
/// the one before ends, only the last open-ended.
pub fn parse_tiers(json: &str) -> Result<Vec<Tier>, ChargeError> {
    let value: Value = serde_json::from_str(json).map_err(|_| ChargeError::Shape)?;
    let items = value.as_array().ok_or(ChargeError::Shape)?;
    let mut tiers = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        if !item.is_object() {
            return Err(ChargeError::Shape);
        }
        let from = number(item.get("from"), i)?.ok_or(ChargeError::Shape)?;
        let to = number(item.get("to"), i)?;
        let price = number(item.get("price"), i)?.ok_or(ChargeError::Shape)?;
        if to.is_some_and(|to| to <= from) {
            return Err(ChargeError::Reversed(i));
        }
        tiers.push(Tier { from, to, price });
    }
    let Some(first) = tiers.first() else {
        return Err(ChargeError::Shape);
    };
    if first.from != Decimal::ZERO {
        return Err(ChargeError::NotFromZero);
    }
    for (i, pair) in tiers.windows(2).enumerate() {
        match pair[0].to {
            None => return Err(ChargeError::OpenBeforeLast),
            Some(end) if end != pair[1].from => return Err(ChargeError::Gap(i + 1)),
            Some(_) => {}
        }
    }
    Ok(tiers)
}

/// Rounds to the currency's minor units, half away from zero (the rule
/// invoicing uses per line).
pub fn round_minor(amount: Decimal, decimals: u32) -> Decimal {
    amount.round_dp_with_strategy(decimals, RoundingStrategy::MidpointAwayFromZero)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).expect("decimal")
    }

    fn bands() -> Vec<Tier> {
        parse_tiers(
            r#"[{"from": 0, "to": 10, "price": "5"},
                {"from": 10, "to": 100, "price": "4"},
                {"from": 100, "price": "3"}]"#,
        )
        .expect("tiers")
    }

    #[test]
    fn flat_ignores_quantity() {
        assert_eq!(
            period_amount(&ChargeModel::Flat, dec("7"), dec("99")),
            dec("99")
        );
        assert_eq!(
            period_amount(&ChargeModel::PerUnit, dec("7"), dec("2.5")),
            dec("17.5")
        );
    }

    #[test]
    fn tiered_sums_each_band() {
        // 10 at 5 + 90 at 4 + 20 at 3.
        assert_eq!(
            period_amount(&ChargeModel::Tiered(bands()), dec("120"), Decimal::ZERO),
            dec("470")
        );
        assert_eq!(
            period_amount(&ChargeModel::Tiered(bands()), dec("4"), Decimal::ZERO),
            dec("20")
        );
    }

    #[test]
    fn volume_uses_single_band() {
        assert_eq!(
            period_amount(&ChargeModel::Volume(bands()), dec("120"), Decimal::ZERO),
            dec("360")
        );
        assert_eq!(
            period_amount(&ChargeModel::Volume(bands()), dec("10"), Decimal::ZERO),
            dec("40"),
            "a band's upper bound belongs to the next band"
        );
    }

    #[test]
    fn minimum_commitment_floors() {
        let model = ChargeModel::MinimumCommitment(dec("100"));
        assert_eq!(period_amount(&model, dec("3"), dec("10")), dec("100"));
        assert_eq!(period_amount(&model, dec("30"), dec("10")), dec("300"));
        assert_eq!(round_minor(dec("2.345"), 2), dec("2.35"));
        assert_eq!(round_minor(dec("-2.345"), 2), dec("-2.35"));
        assert_eq!(round_minor(dec("1.2345"), 3), dec("1.235"));
    }

    #[test]
    fn tiers_with_gap_rejected() {
        assert_eq!(
            parse_tiers(r#"[{"from":0,"to":10,"price":1},{"from":12,"price":1}]"#),
            Err(ChargeError::Gap(1))
        );
        assert_eq!(
            parse_tiers(r#"[{"from":0,"price":1},{"from":10,"price":1}]"#),
            Err(ChargeError::OpenBeforeLast)
        );
        assert_eq!(
            parse_tiers(r#"[{"from":5,"price":1}]"#),
            Err(ChargeError::NotFromZero)
        );
        assert_eq!(parse_tiers("[]"), Err(ChargeError::Shape));
    }
}
