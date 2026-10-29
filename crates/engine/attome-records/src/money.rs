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

use std::collections::{BTreeSet, HashMap};

use attome_core::money::{BASE_CURRENCY_SETTING, DEFAULT_BASE_CURRENCY, companion, is_code, round};
use attome_core::{AttrInfo, EngineState, FieldType, quote_ident};
use attome_types::AppError;
use attome_types::types::FieldError;
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
    if fields.is_empty() {
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
    Ok(Some(out))
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
