//! A19-T1: a money amount written through generic CRUD carries its currency
//! and is rounded to that currency's decimals.
//!
//! A `currency` attribute `x` keeps its ISO 4217 code in the companion
//! attribute `x_currency` (provisioned beside it by `attome-metadata`). On a
//! write that sets `x`: the code is the one sent, else (an update) the one
//! stored, else the deployment's base currency (`core.base_currency`), and
//! is written with the amount when it was not already; the amount is rounded
//! half away from zero to the code's decimals from the `currency` table
//! (migration 0335). A code the table does not hold is refused.
//!
//! A19-T3: a money attribute whose options carry `fx`
//! ([`attome_core::fx::Conversion`]) and that has its number attributes
//! `x_base` and `x_rate` also stores, on every write that sets its amount,
//! its currency or the date attribute its rate is taken on, the amount in
//! the base currency and the rate used ([`attome_core::fx::rate_on`]): on
//! the record's creation day, another date attribute's day (today while
//! empty) or today. Once the record's stored stage is one of
//! `lock_at_stage.values`, the stored rate is kept. When no rate applies,
//! `missing_rate: block` refuses the write and `warn` (the default) stores
//! no base amount.

use std::collections::{BTreeSet, HashMap};

use std::str::FromStr;

use attome_core::fx::{self, Conversion, MissingRate, RateDate};
use attome_core::money::{BASE_CURRENCY_SETTING, DEFAULT_BASE_CURRENCY, companion, is_code, round};
use attome_core::{AttrInfo, EngineState, FieldType, quote_ident};
use attome_types::AppError;
use attome_types::types::FieldError;
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde_json::{Map, Value};
use sqlx::PgConnection;
use uuid::Uuid;

/// A money amount being written: (amount attribute, companion, code).
pub type CodedAmount = (String, String, String);

/// The money attributes of `attrs` that have their companion: (amount,
/// companion). A formula or rollup over money is not one: it is computed.
pub fn money_fields(attrs: &[AttrInfo]) -> Vec<(String, String)> {
    attrs
        .iter()
        .filter(|a| a.field_type() == FieldType::Currency)
        .filter_map(|a| {
            let name = companion(&a.logicalname);
            attrs
                .iter()
                .any(|c| c.logicalname == name && c.field_type() == FieldType::Text)
                .then(|| (a.logicalname.clone(), name))
        })
        .collect()
}

/// The deployment's base currency.
pub fn base_currency(state: &EngineState) -> String {
    attome_core::setting_registry()
        .get(BASE_CURRENCY_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_str().map(str::to_owned))
        .filter(|c| is_code(c))
        .unwrap_or_else(|| DEFAULT_BASE_CURRENCY.to_owned())
}

/// The body with each money amount's currency filled in and the amount
/// rounded; `None` when it sets no money amount or currency. `record` is the
/// record an update changes (its stored currency is kept when the body names
/// none); `None` on create.
pub async fn apply(
    conn: &mut PgConnection,
    state: &EngineState,
    entity: &str,
    record: Option<Uuid>,
    attrs: &[AttrInfo],
    obj: &Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AppError> {
    let fields: Vec<(String, String)> = money_fields(attrs)
        .into_iter()
        .filter(|(amount, code)| obj.contains_key(amount) || obj.contains_key(code))
        .collect();
    let converting: Vec<Converting> = converting(attrs)
        .into_iter()
        .filter(|c| {
            obj.contains_key(&c.amount)
                || obj.contains_key(&c.code)
                || c.date_attribute
                    .as_ref()
                    .is_some_and(|d| obj.contains_key(d))
        })
        .collect();
    if fields.is_empty() && converting.is_empty() {
        return Ok(None);
    }
    let base = base_currency(state);
    let mut out = obj.clone();
    let mut codes: Vec<CodedAmount> = Vec::new();
    for (amount, code_field) in &fields {
        let sent = obj
            .get(code_field)
            .and_then(Value::as_str)
            .map(str::to_owned);
        let has_amount = obj.get(amount).is_some_and(|v| !v.is_null());
        let code = match sent {
            Some(code) => code,
            None if !has_amount => continue,
            None => {
                let stored = match record {
                    Some(id) => stored_code(conn, entity, id, code_field).await?,
                    None => None,
                };
                let code = stored.unwrap_or_else(|| base.clone());
                out.insert(code_field.clone(), Value::String(code.clone()));
                code
            }
        };
        codes.push((amount.clone(), code_field.clone(), code));
    }
    let wanted: BTreeSet<&str> = codes.iter().map(|(_, _, c)| c.as_str()).collect();
    let decimals = currency_decimals(conn, &wanted.into_iter().collect::<Vec<_>>()).await?;
    let failures = round_amounts(&mut out, &codes, &decimals);
    if !failures.is_empty() {
        return Err(AppError::FieldValidation(failures));
    }
    if !converting.is_empty() {
        let failures =
            convert_amounts(conn, state, entity, record, &base, &converting, &mut out).await?;
        if !failures.is_empty() {
            return Err(AppError::FieldValidation(failures));
        }
    }
    Ok(Some(out))
}

/// A19-T3: a money attribute that converts into the base currency.
#[derive(Debug)]
struct Converting {
    amount: String,
    code: String,
    conversion: Conversion,
    /// The date attribute the rate is taken on, when the record has it.
    date_attribute: Option<String>,
    /// The stage attribute that locks the rate, when the record has it.
    stage_attribute: Option<String>,
}

/// The money attributes of `attrs` that convert: `options.fx` set, and the
/// number attributes `<name>_base` and `<name>_rate` present.
fn converting(attrs: &[AttrInfo]) -> Vec<Converting> {
    let has = |name: &str, ok: &dyn Fn(FieldType) -> bool| {
        attrs
            .iter()
            .any(|a| a.logicalname == name && ok(a.field_type()))
    };
    money_fields(attrs)
        .into_iter()
        .filter_map(|(amount, code)| {
            let attr = attrs.iter().find(|a| a.logicalname == amount)?;
            let conversion = Conversion::from_options(attr.options.as_ref())
                .ok()
                .flatten()?;
            let number = |t: FieldType| t == FieldType::Number;
            if !has(&fx::base_field(&amount), &number) || !has(&fx::rate_field(&amount), &number) {
                return None;
            }
            let date_attribute = match &conversion.rate_date {
                RateDate::Attribute(name) if has(name, &|t: FieldType| t.is_temporal()) => {
                    Some(name.clone())
                }
                _ => None,
            };
            let stage_attribute = conversion
                .lock_at_stage
                .as_ref()
                .map(|l| l.attribute.clone())
                .filter(|name| has(name, &|_: FieldType| true));
            Some(Converting {
                amount,
                code,
                conversion,
                date_attribute,
                stage_attribute,
            })
        })
        .collect()
}

/// What a converting write needs from the stored record.
#[derive(Debug, Default)]
struct Stored {
    amount: Option<Decimal>,
    code: Option<String>,
    rate: Option<Decimal>,
    created: Option<NaiveDate>,
    stage: Option<String>,
    day: Option<NaiveDate>,
}

async fn stored_for(
    conn: &mut PgConnection,
    entity: &str,
    record: Uuid,
    c: &Converting,
) -> Result<Stored, AppError> {
    let stage = c
        .stage_attribute
        .as_deref()
        .map_or("NULL::text".to_owned(), |s| {
            format!("{}::text", quote_ident(s))
        });
    let day = c
        .date_attribute
        .as_deref()
        .map_or("NULL::date".to_owned(), |d| {
            format!("{}::date", quote_ident(d))
        });
    let sql = format!(
        "SELECT {}::text, {}::text, {}::text, created_at::date, {stage}, {day} \
           FROM {} WHERE id = $1",
        quote_ident(&c.amount),
        quote_ident(&c.code),
        quote_ident(&fx::rate_field(&c.amount)),
        quote_ident(entity)
    );
    type Row = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<NaiveDate>,
        Option<String>,
        Option<NaiveDate>,
    );
    let row: Option<Row> = sqlx::query_as(&attome_db::tag_dynamic("records.money_fx", &sql))
        .bind(record)
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    let decimal = |s: Option<String>| s.and_then(|s| Decimal::from_str(s.trim()).ok());
    Ok(row
        .map(|(amount, code, rate, created, stage, day)| Stored {
            amount: decimal(amount),
            code: code.map(|c| c.trim().to_owned()).filter(|c| is_code(c)),
            rate: decimal(rate),
            created,
            stage,
            day,
        })
        .unwrap_or_default())
}

/// A JSON amount as a decimal: a number, or a string holding one.
fn decimal_of(value: &Value) -> Option<Decimal> {
    match value {
        Value::Number(n) => Decimal::from_str(&n.to_string())
            .or_else(|_| Decimal::from_scientific(&n.to_string()))
            .ok(),
        Value::String(s) => Decimal::from_str(s.trim()).ok(),
        _ => None,
    }
}

/// A decimal as a JSON number.
fn number_of(value: Decimal) -> Value {
    serde_json::Number::from_str(&value.normalize().to_string())
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

/// The day a date or date-time JSON value falls on.
fn day_of(value: &Value) -> Option<NaiveDate> {
    let s = value.as_str()?;
    NaiveDate::parse_from_str(s.get(..10)?, "%Y-%m-%d").ok()
}

/// The deployment's preferred rate source, when set.
fn preferred_source(state: &EngineState) -> Option<String> {
    attome_core::setting_registry()
        .get(fx::SOURCE_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_str().map(str::to_owned))
        .filter(|s| fx::is_source(s))
}

/// Writes `<name>_base` and `<name>_rate` for each of `converting` into
/// `out`; answers a failure for each amount whose rate is missing under
/// `missing_rate: block`.
async fn convert_amounts(
    conn: &mut PgConnection,
    state: &EngineState,
    entity: &str,
    record: Option<Uuid>,
    base: &str,
    converting: &[Converting],
    out: &mut Map<String, Value>,
) -> Result<Vec<FieldError>, AppError> {
    let today = chrono::Utc::now().date_naive();
    let preferred = preferred_source(state);
    let places = currency_decimals(conn, &[base])
        .await?
        .get(base)
        .copied()
        .unwrap_or(2);
    let mut failures = Vec::new();
    for c in converting {
        let stored = match record {
            Some(id) => stored_for(conn, entity, id, c).await?,
            None => Stored::default(),
        };
        let (base_name, rate_name) = (fx::base_field(&c.amount), fx::rate_field(&c.amount));
        let amount = match out.get(&c.amount) {
            Some(value) => decimal_of(value),
            None => stored.amount,
        };
        let Some(amount) = amount else {
            out.insert(base_name, Value::Null);
            out.insert(rate_name, Value::Null);
            continue;
        };
        let code = out
            .get(&c.code)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or(stored.code)
            .unwrap_or_else(|| base.to_owned());
        let locked = c
            .conversion
            .is_locked(stored.stage.as_deref())
            .then_some(stored.rate)
            .flatten();
        let day = match &c.conversion.rate_date {
            RateDate::RecordDate => stored.created.unwrap_or(today),
            RateDate::Today => today,
            RateDate::Attribute(_) => match c.date_attribute.as_ref().and_then(|d| out.get(d)) {
                Some(value) => day_of(value),
                None => stored.day,
            }
            .unwrap_or(today),
        };
        let rate = match locked {
            Some(rate) => Some(rate),
            None => fx::rate_on(&mut *conn, &code, base, day, preferred.as_deref())
                .await
                .map_err(AppError::internal)?
                .map(|applied| applied.rate),
        };
        match rate {
            Some(rate) => {
                out.insert(base_name, number_of(fx::convert(amount, rate, places)));
                out.insert(rate_name, number_of(rate));
            }
            None if c.conversion.missing_rate == MissingRate::Block => {
                failures.push(FieldError {
                    field: c.amount.clone(),
                    code: "missing_rate".to_owned(),
                    message: format!(
                        "{}: no {code} to {base} exchange rate on or before {day}",
                        c.amount
                    ),
                });
            }
            None => {
                tracing::warn!(
                    %entity, field = %c.amount, %code, %base, %day,
                    "no exchange rate applies; the amount is stored without a base amount"
                );
                out.insert(base_name, Value::Null);
                out.insert(rate_name, Value::Null);
            }
        }
    }
    Ok(failures)
}

/// Rounds each `(amount, companion, code)` amount in `body` to its code's
/// `decimals`, and answers a failure for each code not among them. Pure.
pub fn round_amounts(
    body: &mut Map<String, Value>,
    codes: &[CodedAmount],
    decimals: &HashMap<String, u32>,
) -> Vec<FieldError> {
    let mut failures = Vec::new();
    for (amount, code_field, code) in codes {
        let Some(places) = decimals.get(code) else {
            failures.push(FieldError {
                field: code_field.clone(),
                code: "invalid".to_owned(),
                message: format!("{code_field}: unknown currency {code}"),
            });
            continue;
        };
        if let Some(rounded) = body.get(amount).and_then(|v| round(v, *places)) {
            body.insert(amount.clone(), rounded);
        }
    }
    failures
}

/// The currency stored on `record` in `code_field`.
async fn stored_code(
    conn: &mut PgConnection,
    entity: &str,
    record: Uuid,
    code_field: &str,
) -> Result<Option<String>, AppError> {
    let sql = format!(
        "SELECT {}::text FROM {} WHERE id = $1",
        quote_ident(code_field),
        quote_ident(entity)
    );
    let code: Option<Option<String>> =
        sqlx::query_scalar(&attome_db::tag_dynamic("records.money", &sql))
            .bind(record)
            .fetch_optional(&mut *conn)
            .await
            .map_err(AppError::internal)?;
    Ok(code
        .flatten()
        .map(|c| c.trim().to_owned())
        .filter(|c| is_code(c)))
}

/// The decimals of each of `codes` the `currency` table holds.
async fn currency_decimals(
    conn: &mut PgConnection,
    codes: &[&str],
) -> Result<HashMap<String, u32>, AppError> {
    let rows: Vec<(String, i16)> =
        sqlx::query_as("SELECT code::text, decimals FROM currency WHERE code::text = ANY($1)")
            .bind(codes)
            .fetch_all(&mut *conn)
            .await
            .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(code, places)| (code, u32::try_from(places).unwrap_or(2)))
        .collect())
}

#[cfg(test)]
mod money_currency {
    use super::*;
    use serde_json::json;

    fn attr(name: &str, ft: FieldType) -> AttrInfo {
        serde_json::from_value(json!({
            "logicalname": name,
            "field_type_int": ft.to_int(),
            "is_sensitive": false,
            "is_sortable": false,
            "is_filterable": false,
        }))
        .expect("attr")
    }

    #[test]
    fn money_currency_pairs_an_amount_with_its_companion() {
        let attrs = [
            attr("total", FieldType::Currency),
            attr("total_currency", FieldType::Text),
            attr("fee", FieldType::Currency),
            attr("count", FieldType::Number),
        ];
        assert_eq!(
            money_fields(&attrs),
            vec![("total".to_owned(), "total_currency".to_owned())]
        );
    }

    #[test]
    fn money_currency_rounds_each_amount_to_its_currency() {
        let mut body: Map<String, Value> = serde_json::from_value(json!({
            "total": 10.12345, "total_currency": "KWD",
            "fee": 99.5, "fee_currency": "JPY",
            "net": 7.45678, "net_currency": "SAR",
        }))
        .expect("body");
        let codes: [CodedAmount; 3] = [
            ("total".into(), "total_currency".into(), "KWD".into()),
            ("fee".into(), "fee_currency".into(), "JPY".into()),
            ("net".into(), "net_currency".into(), "SAR".into()),
        ];
        let decimals = HashMap::from([
            ("KWD".to_owned(), 3),
            ("JPY".to_owned(), 0),
            ("SAR".to_owned(), 2),
        ]);
        assert!(round_amounts(&mut body, &codes, &decimals).is_empty());
        assert_eq!(body["total"], json!(10.123));
        assert_eq!(body["fee"], json!(100));
        assert_eq!(body["net"], json!(7.46));
    }

    #[test]
    fn fx_convert_finds_the_converting_attributes() {
        let mut total = attr("total", FieldType::Currency);
        total.options = Some(json!({"fx": {"rate_date": "attribute:closed_on",
            "lock_at_stage": {"attribute": "stage", "values": ["won"]}}}));
        let mut fee = attr("fee", FieldType::Currency);
        fee.options = Some(json!({"fx": {}}));
        let attrs = [
            total,
            attr("total_currency", FieldType::Text),
            attr("total_base", FieldType::Number),
            attr("total_rate", FieldType::Number),
            attr("closed_on", FieldType::Date),
            attr("stage", FieldType::Choice),
            // No `fee_base`/`fee_rate`: not converted.
            fee,
            attr("fee_currency", FieldType::Text),
        ];
        let found = converting(&attrs);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].amount, "total");
        assert_eq!(found[0].date_attribute.as_deref(), Some("closed_on"));
        assert_eq!(found[0].stage_attribute.as_deref(), Some("stage"));
    }

    #[test]
    fn fx_convert_reads_amounts_and_days() {
        assert_eq!(decimal_of(&json!(10.5)), Decimal::from_str("10.5").ok());
        assert_eq!(decimal_of(&json!("3.75")), Decimal::from_str("3.75").ok());
        assert_eq!(decimal_of(&json!(null)), None);
        assert_eq!(number_of(Decimal::from_str("375.00").unwrap()), json!(375));
        assert_eq!(
            number_of(Decimal::from_str("3.7510000000").unwrap()),
            json!(3.751)
        );
        assert_eq!(
            day_of(&json!("2026-10-05T23:00:00Z")),
            NaiveDate::from_ymd_opt(2026, 10, 5)
        );
        assert_eq!(
            day_of(&json!("2026-10-05")),
            NaiveDate::from_ymd_opt(2026, 10, 5)
        );
        assert_eq!(day_of(&json!("soon")), None);
    }

    #[test]
    fn money_currency_refuses_an_unknown_currency() {
        let mut body: Map<String, Value> =
            serde_json::from_value(json!({"total": 1.5, "total_currency": "XXX"})).expect("body");
        let codes: [CodedAmount; 1] = [("total".into(), "total_currency".into(), "XXX".into())];
        let failures = round_amounts(&mut body, &codes, &HashMap::new());
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].field, "total_currency");
        assert_eq!(body["total"], json!(1.5));
    }
}
