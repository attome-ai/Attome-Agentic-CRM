//! Saved QuerySpecs with typed parameters (roadmap S4-T9). A stored query
//! (`sql_query`) may hold a QuerySpec beside, or instead of, its SQL text,
//! with the parameters its `param` conditions name: `{name, type, required}`,
//! `type` one of `text`, `number`, `date`, `uuid`, `bool`. Both are versioned
//! with the query's `sql_query_version` row. A caller runs it by id through
//! `POST /api/v1/query/run` with `query_id` and values only; the query's
//! `required_privilege` gates the run as it gates `query/execute`, and a
//! share with one of the caller's roles or teams admits it too (A14-T2,
//! [`super::share`]). A parameter may carry a `default` of its type, used
//! when a run leaves it out (A14-T2).

use std::collections::{BTreeMap, BTreeSet};

use attome_db::DbPool;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use super::model::{Condition, QuerySpec};

/// The most parameters one saved query declares.
pub const MAX_PARAMS: usize = 32;

/// A parameter's type; a supplied value must already be of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ParamType {
    Text,
    Number,
    /// An RFC 3339 timestamp or a `YYYY-MM-DD` date.
    Date,
    Uuid,
    Bool,
}

/// One declared parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ParamDecl {
    /// `^[a-z][a-z0-9_]*$`.
    pub name: String,
    #[serde(rename = "type")]
    pub ty: ParamType,
    #[serde(default)]
    pub required: bool,
    /// A14-T2: the value a run that leaves the parameter out gets; of the
    /// parameter's type. A required parameter with a default never fails
    /// for being left out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub default: Option<Value>,
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && name.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Every parameter name `condition` reads.
fn param_names(condition: &Condition, out: &mut BTreeSet<String>) {
    match condition {
        Condition::And { all } => all.iter().for_each(|c| param_names(c, out)),
        Condition::Or { any } => any.iter().for_each(|c| param_names(c, out)),
        Condition::Not { condition } => param_names(condition, out),
        Condition::Compare { .. } => {}
        Condition::Exists { r#where, .. } | Condition::NotExists { r#where, .. } => {
            if let Some(c) = r#where {
                param_names(c, out);
            }
        }
        Condition::Param { param, .. } => {
            out.insert(param.clone());
        }
    }
}

/// Checks a spec and its parameters on save: names are well formed and
/// unique, and every `param` condition names a declared parameter. A saved
/// spec carries no values of its own (`params`), no cursor and no `explain`.
pub fn validate(spec: &QuerySpec, params: &[ParamDecl]) -> Result<(), AppError> {
    if params.len() > MAX_PARAMS {
        return Err(AppError::Validation(format!(
            "a saved query declares at most {MAX_PARAMS} parameters"
        )));
    }
    let mut declared = BTreeSet::new();
    for p in params {
        if !valid_name(&p.name) {
            return Err(AppError::Validation(format!(
                "parameter name {:?} must match ^[a-z][a-z0-9_]*$",
                p.name
            )));
        }
        if !declared.insert(p.name.clone()) {
            return Err(AppError::Validation(format!(
                "parameter {} is declared twice",
                p.name
            )));
        }
        if let Some(default) = &p.default {
            coerce_one(&p.name, p.ty, default)?;
        }
    }
    if !spec.params.is_empty() || spec.cursor.is_some() || spec.explain {
        return Err(AppError::Validation(
            "a saved query_spec holds no params, cursor or explain; they are sent with each run"
                .into(),
        ));
    }
    let mut used = BTreeSet::new();
    for condition in spec.r#where.iter().chain(spec.having.iter()) {
        param_names(condition, &mut used);
    }
    if let Some(missing) = used.iter().find(|name| !declared.contains(*name)) {
        return Err(AppError::Validation(format!(
            "query_spec reads parameter {missing}, which parameters does not declare"
        )));
    }
    Ok(())
}

fn type_error(name: &str, ty: ParamType) -> AppError {
    let ty = match ty {
        ParamType::Text => "text",
        ParamType::Number => "a number",
        ParamType::Date => "a date (YYYY-MM-DD or RFC 3339)",
        ParamType::Uuid => "a UUID",
        ParamType::Bool => "true or false",
    };
    AppError::Validation(format!("parameter {name} must be {ty}"))
}

/// The value `raw` for a parameter of type `ty`, or a 422. Only the type's
/// own JSON form is taken: `"1"` is not a number.
fn coerce_one(name: &str, ty: ParamType, raw: &Value) -> Result<Value, AppError> {
    let ok = match (ty, raw) {
        (ParamType::Text, Value::String(_)) | (ParamType::Bool, Value::Bool(_)) => true,
        (ParamType::Number, Value::Number(n)) => n.as_f64().is_some_and(f64::is_finite),
        (ParamType::Uuid, Value::String(s)) => Uuid::parse_str(s).is_ok(),
        (ParamType::Date, Value::String(s)) => {
            chrono::DateTime::parse_from_rfc3339(s).is_ok()
                || chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
        }
        _ => false,
    };
    if ok {
        Ok(raw.clone())
    } else {
        Err(type_error(name, ty))
    }
}

/// The values a run supplies, checked against the declarations: each one
/// declared and of its type, every required one present.
pub fn coerce(
    params: &[ParamDecl],
    supplied: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>, AppError> {
    if let Some(unknown) = supplied
        .keys()
        .find(|name| !params.iter().any(|p| &p.name == *name))
    {
        return Err(AppError::Validation(format!(
            "parameter {unknown} is not declared by this query"
        )));
    }
    let mut out = BTreeMap::new();
    for p in params {
        match supplied.get(&p.name) {
            Some(raw) => {
                out.insert(p.name.clone(), coerce_one(&p.name, p.ty, raw)?);
            }
            None if p.default.is_some() => {
                out.insert(p.name.clone(), p.default.clone().unwrap_or(Value::Null));
            }
            None if p.required => {
                return Err(AppError::Validation(format!(
                    "parameter {} is required",
                    p.name
                )));
            }
            None => {}
        }
    }
    Ok(out)
}

/// A saved query's current QuerySpec, parameters and privilege.
#[derive(Debug, Clone)]
pub struct SavedSpec {
    pub spec: QuerySpec,
    pub params: Vec<ParamDecl>,
    pub required_privilege: Option<String>,
}

/// Loads the live query `id`'s current version. A missing or retired query
/// is a 404; one with no QuerySpec is a 422.
pub async fn load(db: &DbPool, id: Uuid) -> Result<SavedSpec, AppError> {
    let row: Option<(Option<Value>, Option<Value>, Option<String>)> = sqlx::query_as(
        "SELECT v.query_spec, v.parameters, q.required_privilege \
           FROM sql_query q \
           LEFT JOIN LATERAL ( \
               SELECT query_spec, parameters FROM sql_query_version \
                WHERE query_id = q.id ORDER BY id DESC LIMIT 1) v ON true \
          WHERE q.id = $1 AND (q.is_active IS NULL OR q.is_active = true)",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (spec, params, required_privilege) = row.ok_or(AppError::NotFound)?;
    let spec = spec.ok_or_else(|| {
        AppError::Validation(
            "this stored query has no query_spec; run it through query/execute".into(),
        )
    })?;
    let spec: QuerySpec = serde_json::from_value(spec)
        .map_err(|e| AppError::internal(format!("stored query_spec of {id}: {e}")))?;
    let params: Vec<ParamDecl> = match params {
        Some(p) => serde_json::from_value(p)
            .map_err(|e| AppError::internal(format!("stored parameters of {id}: {e}")))?,
        None => Vec::new(),
    };
    Ok(SavedSpec {
        spec,
        params,
        required_privilege,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn spec(doc: Value) -> QuerySpec {
        serde_json::from_value(doc).unwrap()
    }

    fn decl(name: &str, ty: ParamType, required: bool) -> ParamDecl {
        ParamDecl {
            name: name.into(),
            ty,
            required,
            default: None,
        }
    }

    #[test]
    fn a_left_out_parameter_takes_its_default() {
        let mut status = decl("status", ParamType::Number, true);
        status.default = Some(json!(1));
        let params = [status.clone()];
        let ran = coerce(&params, &BTreeMap::new()).unwrap();
        assert_eq!(ran.get("status"), Some(&json!(1)));
        let sent = coerce(&params, &BTreeMap::from([("status".into(), json!(2))])).unwrap();
        assert_eq!(sent.get("status"), Some(&json!(2)));

        let s = spec(json!({"entity": "account", "where":
            {"kind": "param", "field": "statecode", "op": "eq", "param": "status"}}));
        assert!(validate(&s, &params).is_ok());
        status.default = Some(json!("open"));
        assert!(
            validate(&s, &[status]).is_err(),
            "a default must be of its parameter's type"
        );
    }

    #[test]
    fn every_param_condition_must_be_declared() {
        let s = spec(
            json!({"entity": "account", "where": {"kind": "and", "all": [
                {"kind": "param", "field": "statecode", "op": "eq", "param": "status"},
                {"kind": "exists", "path": "contacts",
                 "where": {"kind": "param", "field": "city", "op": "eq", "param": "city"}}
            ]}}),
        );
        assert!(validate(&s, &[decl("status", ParamType::Number, true)]).is_err());
        assert!(
            validate(
                &s,
                &[
                    decl("status", ParamType::Number, true),
                    decl("city", ParamType::Text, false)
                ]
            )
            .is_ok()
        );
        assert!(validate(&s, &[decl("Status", ParamType::Number, true)]).is_err());
        let twice = [
            decl("status", ParamType::Number, true),
            decl("status", ParamType::Text, true),
        ];
        assert!(validate(&s, &twice).is_err());
    }

    #[test]
    fn a_saved_spec_holds_no_values() {
        let s = spec(json!({"entity": "account", "params": {"x": 1}}));
        assert!(validate(&s, &[]).is_err());
    }

    #[test]
    fn values_must_be_of_their_declared_type() {
        let params = [
            decl("status", ParamType::Number, true),
            decl("since", ParamType::Date, false),
            decl("owner", ParamType::Uuid, false),
        ];
        let ok = coerce(&params, &BTreeMap::from([("status".into(), json!(1))])).unwrap();
        assert_eq!(ok.get("status"), Some(&json!(1)));
        for bad in [json!("x"), json!("1"), json!(true)] {
            assert!(coerce(&params, &BTreeMap::from([("status".into(), bad)])).is_err());
        }
        assert!(
            coerce(&params, &BTreeMap::new()).is_err(),
            "status is required"
        );
        let dated = BTreeMap::from([
            ("status".into(), json!(1)),
            ("since".into(), json!("2026-10-01")),
            ("owner".into(), json!(Uuid::nil().to_string())),
        ]);
        assert!(coerce(&params, &dated).is_ok());
        let unknown = BTreeMap::from([("status".into(), json!(1)), ("nope".into(), json!(1))]);
        assert!(coerce(&params, &unknown).is_err());
    }
}
