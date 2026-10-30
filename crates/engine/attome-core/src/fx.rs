//! A19-T2: dated exchange rates.
//!
//! A rate converts one unit of `from` into `to` on a day (`exchange_rate`,
//! migration 0337), from a named source: `manual` for a rate an
//! administrator entered, or the feed that imported it. The rate for a day is
//! the newest one on or before it, so a weekend or a holiday uses the last
//! published rate. When a deployment names a preferred source
//! ([`SOURCE_SETTING`]), a rate from it wins over another source's rate for
//! the same day; another source's newer rate still wins over an older
//! preferred one. When only the opposite direction is stored, its inverse is
//! used. A currency converts to itself at 1.
//!
//! A19-T3: a money attribute whose options carry [`OPTIONS_KEY`] converts
//! its amount into the base currency on every write ([`Conversion`]):
//! `<name>_base` holds the converted amount and `<name>_rate` the rate,
//! taken on the record's day, another attribute's date or today; at a named
//! stage the rate stops changing, and a missing rate warns or refuses.

use chrono::NaiveDate;
use rust_decimal::Decimal;
use rust_decimal::prelude::Zero;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::money::is_code;

/// The deployment setting naming the preferred rate source.
pub const SOURCE_SETTING: &str = "core.fx_source";

/// The source of a rate an administrator entered.
pub const MANUAL_SOURCE: &str = "manual";

/// Decimal places a stored rate keeps (`numeric(20,10)`).
pub const RATE_SCALE: u32 = 10;

/// One stored rate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExchangeRate {
    pub from_currency: String,
    pub to_currency: String,
    pub rate: Decimal,
    pub rate_date: NaiveDate,
    pub source: String,
}

/// The rate that applies to a conversion and where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedRate {
    pub rate: Decimal,
    /// The day of the stored rate used (on or before the day asked for).
    pub rate_date: NaiveDate,
    pub source: String,
    /// The stored rate was the opposite direction, inverted.
    pub inverted: bool,
}

/// Whether `source` is a usable source name: 1 to 64 lowercase letters,
/// digits, `_`, `-` or `.`. Pure.
pub fn is_source(source: &str) -> bool {
    !source.is_empty()
        && source.len() <= 64
        && source.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.')
        })
}

/// Checks one rate before it is stored: two different well-formed codes, a
/// positive rate that fits `numeric(20,10)`, and a source name. The rate is
/// returned rounded to [`RATE_SCALE`] places. Pure.
pub fn validate(rate: &ExchangeRate) -> Result<Decimal, String> {
    if !is_code(&rate.from_currency) || !is_code(&rate.to_currency) {
        return Err("from_currency and to_currency are ISO 4217 codes (three capitals)".into());
    }
    if rate.from_currency == rate.to_currency {
        return Err("from_currency and to_currency differ".into());
    }
    if rate.rate <= Decimal::zero() {
        return Err("rate is above zero".into());
    }
    let rounded = rate.rate.round_dp(RATE_SCALE);
    if rounded.is_zero() {
        return Err("rate is too small to store".into());
    }
    // numeric(20,10): ten digits before the point.
    if rounded >= Decimal::from(10_000_000_000_i64) {
        return Err("rate is too large to store".into());
    }
    if !is_source(&rate.source) {
        return Err("source is 1 to 64 lowercase letters, digits, _, - or .".into());
    }
    Ok(rounded)
}

/// The rate from `from` to `to` on `day`, chosen from `rates` (any order, any
/// pairs): the newest on or before `day` in either direction, the preferred
/// source first on a tie of days, the stored direction before the inverse.
/// `None` when nothing applies. Pure: [`rate_on`] feeds it the candidates.
pub fn pick(
    rates: &[ExchangeRate],
    from: &str,
    to: &str,
    day: NaiveDate,
    preferred_source: Option<&str>,
) -> Option<AppliedRate> {
    if from == to {
        return Some(AppliedRate {
            rate: Decimal::ONE,
            rate_date: day,
            source: "identity".into(),
            inverted: false,
        });
    }
    rates
        .iter()
        .filter(|r| r.rate_date <= day && r.rate > Decimal::zero())
        .filter_map(|r| {
            if r.from_currency == from && r.to_currency == to {
                Some((r, false))
            } else if r.from_currency == to && r.to_currency == from {
                Some((r, true))
            } else {
                None
            }
        })
        .max_by_key(|(r, inverted)| {
            (
                r.rate_date,
                preferred_source == Some(r.source.as_str()),
                !inverted,
            )
        })
        .map(|(r, inverted)| AppliedRate {
            rate: if inverted {
                (Decimal::ONE / r.rate).round_dp(RATE_SCALE)
            } else {
                r.rate
            },
            rate_date: r.rate_date,
            source: r.source.clone(),
            inverted,
        })
}

/// The rate from `from` to `to` on `day`, read from `exchange_rate`: the
/// newest stored rate on or before the day in each direction and, for that
/// day, from each source, then [`pick`].
pub async fn rate_on<'e, E>(
    executor: E,
    from: &str,
    to: &str,
    day: NaiveDate,
    preferred_source: Option<&str>,
) -> Result<Option<AppliedRate>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    if from == to {
        return Ok(pick(&[], from, to, day, preferred_source));
    }
    // Per direction, every source's rate on the newest day on or before
    // `day`: the candidates `pick` chooses among.
    // The rate is read as text: sqlx is built without its decimal feature.
    let rows: Vec<(String, String, String, NaiveDate, String)> = sqlx::query_as(
        "WITH newest AS ( \
             SELECT from_currency, to_currency, max(rate_date) AS rate_date \
               FROM exchange_rate \
              WHERE ((from_currency = $1 AND to_currency = $2) \
                  OR (from_currency = $2 AND to_currency = $1)) \
                AND rate_date <= $3 \
              GROUP BY from_currency, to_currency) \
         SELECT r.from_currency::text, r.to_currency::text, r.rate::text, r.rate_date, r.source \
           FROM exchange_rate r \
           JOIN newest n USING (from_currency, to_currency, rate_date)",
    )
    .bind(from)
    .bind(to)
    .bind(day)
    .fetch_all(executor)
    .await?;
    let rates: Vec<ExchangeRate> = rows
        .into_iter()
        .filter_map(|(from_currency, to_currency, rate, rate_date, source)| {
            Some(ExchangeRate {
                from_currency,
                to_currency,
                rate: rate.parse().ok()?,
                rate_date,
                source,
            })
        })
        .collect();
    Ok(pick(&rates, from, to, day, preferred_source))
}

/// A19-T3: the attribute option of a money attribute that converts its
/// amount into the base currency.
pub const OPTIONS_KEY: &str = "fx";

/// The suffix of the attribute holding the amount in the base currency.
pub const BASE_SUFFIX: &str = "_base";

/// The suffix of the attribute holding the rate the base amount used.
pub const RATE_SUFFIX: &str = "_rate";

/// The attribute holding the base amount of the money attribute `field`.
pub fn base_field(field: &str) -> String {
    format!("{field}{BASE_SUFFIX}")
}

/// The attribute holding the rate of the money attribute `field`.
pub fn rate_field(field: &str) -> String {
    format!("{field}{RATE_SUFFIX}")
}

/// Which day's rate converts an amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateDate {
    /// The day the record was created (today on create).
    RecordDate,
    /// The date in another attribute of the record (today while it is
    /// empty), such as an approval or invoice date.
    Attribute(String),
    /// The day of the write.
    Today,
}

/// What a write does when no rate applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MissingRate {
    /// Store the amount without a base amount, and log it.
    #[default]
    Warn,
    /// Refuse the write.
    Block,
}

/// The stage at which a record's rate stops changing: once the stored
/// value of `attribute` is one of `values`, later writes keep the stored
/// rate (a changed amount is converted with it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageLock {
    pub attribute: String,
    pub values: Vec<String>,
}

/// A money attribute's conversion, from `options.fx`:
/// `{"rate_date": "record_date" | "today" | "attribute:<name>",
///   "lock_at_stage": {"attribute": "<name>", "values": ["won"]},
///   "missing_rate": "warn" | "block"}`, every key optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversion {
    pub rate_date: RateDate,
    pub lock_at_stage: Option<StageLock>,
    pub missing_rate: MissingRate,
}

/// Whether `name` can be an attribute name: lowercase letters, digits and
/// `_`, starting with a letter, at most 63 bytes.
fn is_attribute_name(name: &str) -> bool {
    name.len() <= 63
        && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

impl Conversion {
    /// The conversion `options` asks for: `Ok(None)` when it names none,
    /// `Err` with the reason when `options.fx` is malformed. Pure.
    pub fn from_options(options: Option<&Value>) -> Result<Option<Self>, String> {
        let Some(fx) = options.and_then(|o| o.get(OPTIONS_KEY)) else {
            return Ok(None);
        };
        if fx.is_null() {
            return Ok(None);
        }
        let Some(fx) = fx.as_object() else {
            return Err("options.fx is an object".into());
        };
        if let Some(key) = fx
            .keys()
            .find(|k| !matches!(k.as_str(), "rate_date" | "lock_at_stage" | "missing_rate"))
        {
            return Err(format!("options.fx.{key} is not a conversion option"));
        }
        let rate_date = match fx.get("rate_date").map(|v| v.as_str()) {
            None | Some(Some("record_date")) => RateDate::RecordDate,
            Some(Some("today")) => RateDate::Today,
            Some(Some(other)) => match other.strip_prefix("attribute:") {
                Some(name) if is_attribute_name(name) => RateDate::Attribute(name.to_owned()),
                _ => {
                    return Err(
                        "options.fx.rate_date is record_date, today or attribute:<name>".into(),
                    );
                }
            },
            Some(None) => return Err("options.fx.rate_date is a string".into()),
        };
        let lock_at_stage = match fx.get("lock_at_stage") {
            None | Some(Value::Null) => None,
            Some(lock) => {
                let attribute = lock
                    .get("attribute")
                    .and_then(Value::as_str)
                    .filter(|a| is_attribute_name(a));
                let values: Option<Vec<String>> = lock
                    .get("values")
                    .and_then(Value::as_array)
                    .and_then(|vs| vs.iter().map(|v| v.as_str().map(str::to_owned)).collect());
                match (attribute, values) {
                    (Some(attribute), Some(values)) if !values.is_empty() => Some(StageLock {
                        attribute: attribute.to_owned(),
                        values,
                    }),
                    _ => {
                        return Err("options.fx.lock_at_stage is {\"attribute\": \"<name>\", \
                                    \"values\": [\"<stage>\", ...]}"
                            .into());
                    }
                }
            }
        };
        let missing_rate = match fx.get("missing_rate").map(|v| v.as_str()) {
            None | Some(Some("warn")) => MissingRate::Warn,
            Some(Some("block")) => MissingRate::Block,
            _ => return Err("options.fx.missing_rate is warn or block".into()),
        };
        Ok(Some(Self {
            rate_date,
            lock_at_stage,
            missing_rate,
        }))
    }

    /// Whether a record whose stored stage is `stored_stage` keeps its
    /// stored rate. Pure.
    pub fn is_locked(&self, stored_stage: Option<&str>) -> bool {
        match (&self.lock_at_stage, stored_stage) {
            (Some(lock), Some(stage)) => lock.values.iter().any(|v| v == stage),
            _ => false,
        }
    }
}

/// `amount` in the base currency at `rate`, rounded half away from zero to
/// the base currency's `decimals`. Pure.
pub fn convert(amount: Decimal, rate: Decimal, decimals: u32) -> Decimal {
    (amount * rate).round_dp_with_strategy(
        decimals,
        rust_decimal::RoundingStrategy::MidpointAwayFromZero,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn day(s: &str) -> NaiveDate {
        NaiveDate::from_str(s).unwrap()
    }

    fn rate(from: &str, to: &str, value: &str, on: &str, source: &str) -> ExchangeRate {
        ExchangeRate {
            from_currency: from.into(),
            to_currency: to.into(),
            rate: Decimal::from_str(value).unwrap(),
            rate_date: day(on),
            source: source.into(),
        }
    }

    #[test]
    fn fx_rates_newest_on_or_before_the_day() {
        let rates = [
            rate("USD", "SAR", "3.7500", "2026-10-01", "manual"),
            rate("USD", "SAR", "3.7510", "2026-10-15", "manual"),
            rate("USD", "SAR", "3.7600", "2026-11-01", "manual"),
        ];
        let applied = pick(&rates, "USD", "SAR", day("2026-10-20"), None).unwrap();
        assert_eq!(applied.rate, Decimal::from_str("3.7510").unwrap());
        assert_eq!(applied.rate_date, day("2026-10-15"));
        assert!(!applied.inverted);
        let exact = pick(&rates, "USD", "SAR", day("2026-10-15"), None).unwrap();
        assert_eq!(exact.rate_date, day("2026-10-15"));
        assert!(
            pick(&rates, "USD", "SAR", day("2026-09-30"), None).is_none(),
            "nothing before the first rate"
        );
    }

    #[test]
    fn fx_rates_inverse_when_only_the_other_direction_is_stored() {
        let rates = [rate("SAR", "KWD", "0.0820", "2026-10-01", "sama")];
        let applied = pick(&rates, "KWD", "SAR", day("2026-10-02"), None).unwrap();
        assert!(applied.inverted);
        assert_eq!(
            applied.rate,
            (Decimal::ONE / Decimal::from_str("0.0820").unwrap()).round_dp(10)
        );
        assert!(pick(&rates, "KWD", "USD", day("2026-10-02"), None).is_none());
    }

    #[test]
    fn fx_rates_preferred_source_wins_a_tie_but_not_a_newer_day() {
        let rates = [
            rate("EUR", "AED", "4.30", "2026-10-10", "manual"),
            rate("EUR", "AED", "4.31", "2026-10-10", "cbuae"),
            rate("EUR", "AED", "4.32", "2026-10-12", "manual"),
        ];
        let tie = pick(&rates, "EUR", "AED", day("2026-10-11"), Some("cbuae")).unwrap();
        assert_eq!(tie.source, "cbuae");
        let newer = pick(&rates, "EUR", "AED", day("2026-10-12"), Some("cbuae")).unwrap();
        assert_eq!(
            newer.source, "manual",
            "a newer day beats the preferred source"
        );
        assert_eq!(newer.rate, Decimal::from_str("4.32").unwrap());
    }

    #[test]
    fn fx_rates_stored_direction_beats_the_inverse_on_a_tie() {
        let rates = [
            rate("USD", "QAR", "3.64", "2026-10-10", "manual"),
            rate("QAR", "USD", "0.2740", "2026-10-10", "manual"),
        ];
        let applied = pick(&rates, "USD", "QAR", day("2026-10-10"), None).unwrap();
        assert!(!applied.inverted);
        assert_eq!(applied.rate, Decimal::from_str("3.64").unwrap());
    }

    #[test]
    fn fx_rates_same_currency_is_one() {
        let applied = pick(&[], "BHD", "BHD", day("2026-10-10"), None).unwrap();
        assert_eq!(applied.rate, Decimal::ONE);
    }

    #[test]
    fn fx_convert_reads_the_options() {
        use serde_json::json;
        assert_eq!(Conversion::from_options(None), Ok(None));
        assert_eq!(
            Conversion::from_options(Some(&json!({"precision": 2}))),
            Ok(None)
        );
        let all = Conversion::from_options(Some(&json!({"fx": {
            "rate_date": "attribute:approved_on",
            "lock_at_stage": {"attribute": "stage", "values": ["won", "lost"]},
            "missing_rate": "block"
        }})))
        .unwrap()
        .unwrap();
        assert_eq!(all.rate_date, RateDate::Attribute("approved_on".into()));
        assert_eq!(all.missing_rate, MissingRate::Block);
        assert!(all.is_locked(Some("won")));
        assert!(!all.is_locked(Some("open")));
        assert!(!all.is_locked(None));
        let defaults = Conversion::from_options(Some(&json!({"fx": {}})))
            .unwrap()
            .unwrap();
        assert_eq!(defaults.rate_date, RateDate::RecordDate);
        assert_eq!(defaults.missing_rate, MissingRate::Warn);
        assert!(!defaults.is_locked(Some("won")));
        for bad in [
            json!({"fx": "today"}),
            json!({"fx": {"rate_date": "yesterday"}}),
            json!({"fx": {"rate_date": "attribute:Bad Name"}}),
            json!({"fx": {"missing_rate": "ignore"}}),
            json!({"fx": {"lock_at_stage": {"attribute": "stage", "values": []}}}),
            json!({"fx": {"lock_at_stage": {"values": ["won"]}}}),
            json!({"fx": {"source": "sama"}}),
        ] {
            assert!(Conversion::from_options(Some(&bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn fx_convert_rounds_to_the_base_decimals() {
        let d = |s: &str| Decimal::from_str(s).unwrap();
        assert_eq!(convert(d("100"), d("3.75"), 2), d("375.00"));
        assert_eq!(convert(d("10.005"), d("1"), 2), d("10.01"));
        assert_eq!(convert(d("1"), d("3.2520325203"), 3), d("3.252"));
        assert_eq!(convert(d("-2.5"), d("1"), 0), d("-3"));
        assert_eq!(base_field("total"), "total_base");
        assert_eq!(rate_field("total"), "total_rate");
    }

    #[test]
    fn fx_rates_validate_refuses_bad_rows() {
        let good = rate("USD", "SAR", "3.75000000004", "2026-10-10", "manual");
        assert_eq!(
            validate(&good).unwrap(),
            Decimal::from_str("3.7500000000").unwrap()
        );
        assert!(validate(&rate("USD", "USD", "1", "2026-10-10", "manual")).is_err());
        assert!(validate(&rate("usd", "SAR", "1", "2026-10-10", "manual")).is_err());
        assert!(validate(&rate("USD", "SAR", "0", "2026-10-10", "manual")).is_err());
        assert!(validate(&rate("USD", "SAR", "-1", "2026-10-10", "manual")).is_err());
        assert!(validate(&rate("USD", "SAR", "0.00000000001", "2026-10-10", "manual")).is_err());
        assert!(validate(&rate("USD", "SAR", "10000000000", "2026-10-10", "manual")).is_err());
        assert!(validate(&rate("USD", "SAR", "1", "2026-10-10", "Bad Source")).is_err());
    }
}
