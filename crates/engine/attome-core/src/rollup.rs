//! Rollup fields (roadmap A10-T1): a field whose value is computed from
//! related records (count, distinct count, sum, min, max, average, first,
//! last), stored in a native column of its result type.
//!
//! A rollup's `options` are its definition:
//!
//! ```json
//! { "function": "sum",
//!   "path": [{ "entity": "opportunity", "via": "account_ref" }],
//!   "attribute": "amount",
//!   "filter": "status == \"won\"",
//!   "window": { "days": 90, "date_attribute": "close_date" },
//!   "mode": "fast",
//!   "result_type": "currency" }
//! ```
//!
//! - `path` walks from the rollup's entity to the records it aggregates, one
//!   to [`MAX_ROLLUP_HOPS`] steps: each step names an entity and its lookup
//!   (`via`) to the step before (the first step's lookup points at the
//!   rollup's own entity). `account <- opportunity <- opportunity_line` is
//!   two steps.
//! - `attribute` is a field of the last step's entity; `count` needs none,
//!   every other function one whose type fits it ([`fits`]).
//! - `filter` is a rule-language condition on the last step's records that
//!   must run in the database (`attome_core::rules_sql`), since the rollup is
//!   computed by a query.
//! - `window` keeps only records whose date field falls in the last `days`.
//! - `first` and `last` order by `order_by` (a date or number field of the
//!   last step's entity; `created_at` when absent).
//! - `mode` is `fast` (recomputed shortly after a related record changes,
//!   A10-T2) or `exact` (in the related record's own write, A10-T3).
//! - `result_type` is what the column holds; it must be the one the function
//!   and attribute give ([`expected_result_type`]), so the column type is
//!   known from the options alone (`FieldType::storage`).
//!
//! This module defines and checks the definition; reconcile calls
//! [`validate`] before the field is saved. Computing the value is A10-T2/T3.

use std::collections::HashMap;

use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AttrInfo, EntityMetaRegistry, FieldType};

/// How many lookups a rollup's path may cross.
pub const MAX_ROLLUP_HOPS: usize = 3;
/// The longest window, in days (ten years).
pub const MAX_ROLLUP_WINDOW_DAYS: u32 = 3660;
/// The column types a rollup may hold.
pub const ROLLUP_RESULT_TYPES: &[&str] = &["number", "currency", "date", "date_time"];
/// The field `first` and `last` order by when the definition names none.
pub const DEFAULT_ORDER_BY: &str = "created_at";

/// What a rollup computes over its related records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollupFunction {
    Count,
    DistinctCount,
    Sum,
    Min,
    Max,
    Avg,
    First,
    Last,
}

impl RollupFunction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::DistinctCount => "distinct_count",
            Self::Sum => "sum",
            Self::Min => "min",
            Self::Max => "max",
            Self::Avg => "avg",
            Self::First => "first",
            Self::Last => "last",
        }
    }
}

/// When a rollup is recomputed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollupMode {
    /// Shortly after a related record changes (A10-T2).
    #[default]
    Fast,
    /// In the related record's own write (A10-T3).
    Exact,
}

/// One step of a rollup's path: an entity and its lookup to the step before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollupStep {
    pub entity: String,
    pub via: String,
}

/// Keep only the related records dated in the last `days`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollupWindow {
    pub days: u32,
    pub date_attribute: String,
}

/// A rollup field's `options`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollupOptions {
    pub function: RollupFunction,
    pub path: Vec<RollupStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<RollupWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_by: Option<String>,
    #[serde(default)]
    pub mode: RollupMode,
    pub result_type: String,
}

/// The definition's shape, without the entities it names. A failure is
/// `AppError::Validation`.
pub fn parse_options(options: Option<&Value>) -> Result<RollupOptions, AppError> {
    let value = options.ok_or_else(|| {
        AppError::Validation(
            "a rollup field requires options {\"function\", \"path\", \"result_type\", ...}".into(),
        )
    })?;
    let opts: RollupOptions = serde_json::from_value(value.clone())
        .map_err(|e| AppError::Validation(format!("invalid rollup options: {e}")))?;
    if opts.path.is_empty() || opts.path.len() > MAX_ROLLUP_HOPS {
        return Err(AppError::Validation(format!(
            "a rollup's path has 1 to {MAX_ROLLUP_HOPS} steps, not {}",
            opts.path.len()
        )));
    }
    if !ROLLUP_RESULT_TYPES.contains(&opts.result_type.as_str()) {
        return Err(AppError::Validation(format!(
            "a rollup's result_type is one of {}, not '{}'",
            ROLLUP_RESULT_TYPES.join(", "),
            opts.result_type
        )));
    }
    if let Some(window) = &opts.window
        && (window.days == 0 || window.days > MAX_ROLLUP_WINDOW_DAYS)
    {
        return Err(AppError::Validation(format!(
            "a rollup's window is 1 to {MAX_ROLLUP_WINDOW_DAYS} days, not {}",
            window.days
        )));
    }
    if opts.order_by.is_some()
        && !matches!(opts.function, RollupFunction::First | RollupFunction::Last)
    {
        return Err(AppError::Validation(
            "order_by applies only to the first and last functions".into(),
        ));
    }
    Ok(opts)
}

/// Whether `function` can aggregate a field stored as `storage`. Pure.
pub fn fits(function: RollupFunction, storage: &FieldType) -> bool {
    match function {
        RollupFunction::Count => true,
        RollupFunction::DistinctCount => matches!(
            storage,
            FieldType::Text
                | FieldType::Number
                | FieldType::Currency
                | FieldType::Date
                | FieldType::DateTime
                | FieldType::Bool
                | FieldType::Choice
                | FieldType::Lookup
                | FieldType::Icon
                | FieldType::Color
        ),
        RollupFunction::Sum | RollupFunction::Avg => {
            matches!(storage, FieldType::Number | FieldType::Currency)
        }
        RollupFunction::Min
        | RollupFunction::Max
        | RollupFunction::First
        | RollupFunction::Last => matches!(
            storage,
            FieldType::Number | FieldType::Currency | FieldType::Date | FieldType::DateTime
        ),
    }
}

/// The result type `function` over a field stored as `storage` gives: a
/// count is a number, every other function keeps the field's type. Pure.
pub fn expected_result_type(function: RollupFunction, storage: Option<&FieldType>) -> &'static str {
    match (function, storage) {
        (RollupFunction::Count | RollupFunction::DistinctCount, _) | (_, None) => "number",
        (_, Some(ft)) => ft.as_str(),
    }
}

/// A10-T1: checks a rollup on `entity` against the entities in `registry`:
/// every step's lookup points at the step before, the attribute exists, is
/// not read-gated and fits the function, the result type is the one they
/// give, the window's field is a date, `order_by` is a date or number, and
/// the filter is a condition on the last entity that runs in the database.
/// Returns the parsed definition. A failure is `AppError::Validation`.
pub fn validate(
    entity: &str,
    options: Option<&Value>,
    registry: &EntityMetaRegistry,
) -> Result<RollupOptions, AppError> {
    let opts = parse_options(options)?;
    let mut parent = registry
        .get(entity)
        .ok_or_else(|| AppError::Validation(format!("unknown entity '{entity}'")))?;
    for (i, step) in opts.path.iter().enumerate() {
        let child = registry.get(&step.entity).ok_or_else(|| {
            AppError::Validation(format!(
                "path step {}: unknown entity '{}'",
                i + 1,
                step.entity
            ))
        })?;
        let via = child.attrs.iter().find(|a| a.logicalname == step.via);
        let points_back = via.is_some_and(|a| {
            a.field_type() == FieldType::Lookup && a.lookup_entity_ref == Some(parent.entity_id)
        });
        if !points_back {
            return Err(AppError::Validation(format!(
                "path step {}: '{}.{}' is not a lookup to '{}'",
                i + 1,
                step.entity,
                step.via,
                parent.logicalname
            )));
        }
        parent = child;
    }
    let last = parent;
    let field = |name: &str| readable_field(last, name);

    let storage = match (&opts.attribute, opts.function) {
        (None, RollupFunction::Count) => None,
        (None, function) => {
            return Err(AppError::Validation(format!(
                "a {} rollup needs an attribute",
                function.as_str()
            )));
        }
        (Some(name), function) => {
            let attr = field(name)?;
            let storage = attr.storage_type();
            let multi = attr
                .options
                .as_ref()
                .is_some_and(|o| attr.field_type().is_multi_valued(o));
            if !fits(function, &storage) || multi {
                return Err(AppError::Validation(format!(
                    "{} cannot aggregate '{name}', a {} field",
                    function.as_str(),
                    attr.field_type()
                )));
            }
            Some(storage)
        }
    };
    let expected = expected_result_type(opts.function, storage.as_ref());
    if opts.result_type != expected {
        return Err(AppError::Validation(format!(
            "this rollup gives a {expected} value; set result_type to '{expected}'"
        )));
    }

    if let Some(window) = &opts.window
        && !field(&window.date_attribute)?.storage_type().is_temporal()
    {
        return Err(AppError::Validation(format!(
            "the window's field '{}' is not a date",
            window.date_attribute
        )));
    }
    if let Some(order_by) = &opts.order_by
        && order_by != DEFAULT_ORDER_BY
        && !matches!(
            field(order_by)?.storage_type(),
            FieldType::Number | FieldType::Currency | FieldType::Date | FieldType::DateTime
        )
    {
        return Err(AppError::Validation(format!(
            "first and last order by a date or number field, not '{order_by}'"
        )));
    }

    if let Some(filter) = opts.filter.as_deref().filter(|f| !f.trim().is_empty()) {
        check_filter(filter, &last.attrs)?;
    }
    Ok(opts)
}

/// The field `name` of `entity`, when it exists and is not read-gated.
fn readable_field<'a>(entity: &'a crate::EntityMeta, name: &str) -> Result<&'a AttrInfo, AppError> {
    entity
        .attrs
        .iter()
        .find(|a| a.logicalname == name && !a.is_read_gated())
        .ok_or_else(|| {
            AppError::Validation(format!(
                "'{}' has no readable field '{name}'",
                entity.logicalname
            ))
        })
}

/// The filter compiles to a condition on `attrs` (stored fields only:
/// formulas are left out, as in a formula's own schema) and translates to
/// SQL.
fn check_filter(filter: &str, attrs: &[AttrInfo]) -> Result<(), AppError> {
    let readable: Vec<AttrInfo> = attrs
        .iter()
        .filter(|a| !a.is_read_gated())
        .cloned()
        .collect();
    let schema = crate::formula::formula_input_schema(&readable);
    let compiled = attome_rules::compile(filter, &schema)
        .map_err(|e| AppError::Validation(format!("the rollup's filter does not compile: {e}")))?;
    if compiled
        .result_type()
        .unify(&attome_rules::Type::Bool)
        .is_none()
    {
        return Err(AppError::Validation(format!(
            "the rollup's filter gives '{}', not a condition",
            compiled.result_type()
        )));
    }
    let expr = attome_rules::parse(filter)
        .map_err(|e| AppError::Validation(format!("the rollup's filter does not parse: {e}")))?;
    let by_name: HashMap<String, AttrInfo> = readable
        .into_iter()
        .filter(|a| !a.is_formula())
        .map(|a| (a.logicalname.clone(), a))
        .collect();
    crate::rules_sql::translatable(&expr, &by_name).map_err(|e| {
        AppError::Validation(format!(
            "the rollup's filter must run in the database: {}",
            e.reason
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    fn attr(name: &str, ft: FieldType, lookup: Option<Uuid>) -> AttrInfo {
        AttrInfo {
            logicalname: name.into(),
            field_type_int: ft.to_int(),
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity_ref: lookup,
            on_target_delete: crate::OnTargetDelete::default(),
            data_classification: crate::DataClassification::default(),
            sensitivity: Default::default(),
            sensitivity_confirmed: false,
            options: None,
        }
    }

    /// account <- opportunity (account_ref) <- opportunity_line (opportunity_ref).
    fn registry() -> EntityMetaRegistry {
        let (account, opportunity, line) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let meta = |id: Uuid, name: &str, attrs: Vec<AttrInfo>| crate::EntityMeta {
            entity_id: id,
            logicalname: name.into(),
            attrs,
            is_append_only: false,
            primary_name_attribute: None,
        };
        EntityMetaRegistry::from_entities(vec![
            meta(
                account,
                "account",
                vec![attr("name", FieldType::Text, None)],
            ),
            meta(
                opportunity,
                "opportunity",
                vec![
                    attr("account_ref", FieldType::Lookup, Some(account)),
                    attr("amount", FieldType::Currency, None),
                    attr("status", FieldType::Text, None),
                    attr("close_date", FieldType::Date, None),
                    attr("title", FieldType::Text, None),
                ],
            ),
            meta(
                line,
                "opportunity_line",
                vec![
                    attr("opportunity_ref", FieldType::Lookup, Some(opportunity)),
                    attr("quantity", FieldType::Number, None),
                ],
            ),
        ])
    }

    fn check(options: Value) -> Result<RollupOptions, AppError> {
        validate("account", Some(&options), &registry())
    }

    fn message(r: Result<RollupOptions, AppError>) -> String {
        match r {
            Err(AppError::Validation(m)) => m,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn rollup_definition_accepts_a_windowed_filtered_sum() {
        let opts = check(json!({
            "function": "sum",
            "path": [{ "entity": "opportunity", "via": "account_ref" }],
            "attribute": "amount",
            "filter": "status == \"won\"",
            "window": { "days": 90, "date_attribute": "close_date" },
            "result_type": "currency",
        }))
        .expect("valid");
        assert_eq!(opts.mode, RollupMode::Fast);
        assert_eq!(opts.function, RollupFunction::Sum);
    }

    #[test]
    fn rollup_definition_follows_two_hops_and_counts_without_attribute() {
        check(json!({
            "function": "count",
            "path": [
                { "entity": "opportunity", "via": "account_ref" },
                { "entity": "opportunity_line", "via": "opportunity_ref" },
            ],
            "mode": "exact",
            "result_type": "number",
        }))
        .expect("valid");
    }

    #[test]
    fn rollup_definition_refuses_a_path_that_does_not_point_back() {
        let m = message(check(json!({
            "function": "count",
            "path": [{ "entity": "opportunity_line", "via": "opportunity_ref" }],
            "result_type": "number",
        })));
        assert!(m.contains("is not a lookup to 'account'"), "{m}");
        let m = message(check(json!({
            "function": "count", "path": [], "result_type": "number",
        })));
        assert!(m.contains("1 to 3 steps"), "{m}");
    }

    #[test]
    fn rollup_definition_refuses_a_function_that_does_not_fit() {
        let m = message(check(json!({
            "function": "sum",
            "path": [{ "entity": "opportunity", "via": "account_ref" }],
            "attribute": "title",
            "result_type": "number",
        })));
        assert!(m.contains("sum cannot aggregate 'title'"), "{m}");
        let m = message(check(json!({
            "function": "avg",
            "path": [{ "entity": "opportunity", "via": "account_ref" }],
            "result_type": "number",
        })));
        assert!(m.contains("needs an attribute"), "{m}");
    }

    #[test]
    fn rollup_definition_names_the_result_type_it_gives() {
        let m = message(check(json!({
            "function": "max",
            "path": [{ "entity": "opportunity", "via": "account_ref" }],
            "attribute": "close_date",
            "result_type": "number",
        })));
        assert!(m.contains("set result_type to 'date'"), "{m}");
        let m = message(check(json!({
            "function": "distinct_count",
            "path": [{ "entity": "opportunity", "via": "account_ref" }],
            "attribute": "status",
            "result_type": "currency",
        })));
        assert!(m.contains("set result_type to 'number'"), "{m}");
    }

    #[test]
    fn rollup_definition_checks_window_order_and_filter() {
        let base = |extra: Value| {
            let mut o = json!({
                "function": "last",
                "path": [{ "entity": "opportunity", "via": "account_ref" }],
                "attribute": "amount",
                "result_type": "currency",
            });
            for (k, v) in extra.as_object().expect("an object") {
                o[k] = v.clone();
            }
            check(o)
        };
        let m = message(base(
            json!({ "window": { "days": 30, "date_attribute": "status" } }),
        ));
        assert!(m.contains("is not a date"), "{m}");
        let m = message(base(
            json!({ "window": { "days": 0, "date_attribute": "close_date" } }),
        ));
        assert!(m.contains("1 to 3660 days"), "{m}");
        let m = message(base(json!({ "order_by": "status" })));
        assert!(m.contains("order by a date or number"), "{m}");
        base(json!({ "order_by": "close_date" })).expect("a date orders");
        let m = message(base(json!({ "filter": "amount + 1" })));
        assert!(m.contains("not a condition"), "{m}");
        let m = message(base(json!({ "filter": "missing == 1" })));
        assert!(m.contains("does not compile"), "{m}");
        let m = message(check(json!({
            "function": "count",
            "path": [{ "entity": "opportunity", "via": "account_ref" }],
            "order_by": "close_date",
            "result_type": "number",
        })));
        assert!(m.contains("only to the first and last"), "{m}");
    }

    #[test]
    fn rollup_definition_refuses_unknown_options() {
        let m = message(check(json!({
            "function": "count",
            "path": [{ "entity": "opportunity", "via": "account_ref" }],
            "result_type": "number",
            "colour": "red",
        })));
        assert!(m.contains("invalid rollup options"), "{m}");
    }
}
