//! A19-T1: money amounts and the currency each is in.
//!
//! A `currency` attribute `x` stores its amount in `x` (`NUMERIC(20,6)` for a
//! column provisioned since A19-T1) and its ISO 4217 code in the companion
//! attribute `x_currency`, which provisioning adds beside it. On write the
//! amount is rounded to the decimals of its currency (the `currency` table,
//! migration 0335: KWD, BHD and OMR 3, JPY 0); a write that names no currency
//! gets the deployment's base currency ([`BASE_CURRENCY_SETTING`]).

use std::str::FromStr;

use rust_decimal::{Decimal, RoundingStrategy};
use serde_json::Value;

/// The suffix of the companion attribute holding an amount's currency code.
pub const CURRENCY_SUFFIX: &str = "_currency";

/// The deployment setting naming the currency an amount without one is in.
pub const BASE_CURRENCY_SETTING: &str = "core.base_currency";

/// The base currency when the setting is unset.
pub const DEFAULT_BASE_CURRENCY: &str = "USD";

/// The column type of a money amount provisioned since A19-T1: 14 integer
/// digits and 6 decimals, enough for every currency's minor unit and for a
/// unit price kept finer than one.
pub const AMOUNT_COLUMN_TYPE: &str = "NUMERIC(20,6)";

/// The companion attribute of the money attribute `field`.
pub fn companion(field: &str) -> String {
    format!("{field}{CURRENCY_SUFFIX}")
}

/// Whether `code` is shaped like an ISO 4217 code: three ASCII capitals.
pub fn is_code(code: &str) -> bool {
    code.len() == 3 && code.bytes().all(|b| b.is_ascii_uppercase())
}

/// `value` (a JSON number) rounded half away from zero to `decimals` places,
/// as a JSON number; `None` when it is not a number. Pure.
pub fn round(value: &Value, decimals: u32) -> Option<Value> {
    let Value::Number(n) = value else {
        return None;
    };
    let text = n.to_string();
    let amount = Decimal::from_str(&text)
        .or_else(|_| Decimal::from_scientific(&text))
        .ok()?;
    let rounded = amount
        .round_dp_with_strategy(decimals, RoundingStrategy::MidpointAwayFromZero)
        .normalize();
    if rounded.scale() == 0
        && let Ok(whole) = i64::try_from(rounded.mantissa())
    {
        return Some(Value::from(whole));
    }
    let as_f64: f64 = rounded.to_string().parse().ok()?;
    serde_json::Number::from_f64(as_f64).map(Value::Number)
}

#[cfg(test)]
mod money_currency {
    use super::*;
    use serde_json::json;

    #[test]
    fn money_currency_rounds_to_three_decimals_for_the_gulf_dinars() {
        assert_eq!(round(&json!(12.34567), 3), Some(json!(12.346)));
        assert_eq!(round(&json!(0.0005), 3), Some(json!(0.001)));
    }

    #[test]
    fn money_currency_rounds_yen_to_whole_units() {
        assert_eq!(round(&json!(1234.5), 0), Some(json!(1235)));
        assert_eq!(round(&json!(1234.49), 0), Some(json!(1234)));
    }

    #[test]
    fn money_currency_rounds_half_away_from_zero_at_two_decimals() {
        assert_eq!(round(&json!(19.995), 2), Some(json!(20)));
        assert_eq!(round(&json!(-2.345), 2), Some(json!(-2.35)));
        assert_eq!(round(&json!(10.1), 2), Some(json!(10.1)));
    }

    #[test]
    fn money_currency_leaves_a_non_number_alone() {
        assert_eq!(round(&json!("12.5"), 2), None);
        assert_eq!(round(&Value::Null, 2), None);
    }

    #[test]
    fn money_currency_names_the_companion_and_checks_codes() {
        assert_eq!(companion("amount"), "amount_currency");
        assert!(is_code("KWD"));
        assert!(!is_code("kwd"));
        assert!(!is_code("US"));
        assert!(!is_code("USDT"));
    }
}
