//! The QuerySpec types (roadmap S4-T1). Deserializing checks the shape (an
//! unknown condition kind or aggregate is refused); what the names mean is
//! checked against the entity's metadata when the spec is compiled.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Every comparison operator a condition may use: the stored filters' own,
/// then the ranges and relative dates QuerySpec adds.
pub const OPERATORS: &[&str] = &[
    "eq",
    "neq",
    "gt",
    "gte",
    "lt",
    "lte",
    "contains",
    "starts_with",
    "ends_with",
    "in",
    "is_null",
    "is_not_null",
    "contains_any",
    "contains_all",
    "under",
    "above",
    "tagged",
    "between",
    "not_in",
    "today",
    "last_n_days",
    "next_n_days",
    "this_month",
    "last_month",
    "this_quarter",
    "this_year",
    "mine",
    "my_team",
    "text_matches",
];

/// A structured query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuerySpec {
    pub entity: String,
    #[serde(default)]
    pub select: Vec<String>,
    #[serde(default, rename = "where", skip_serializing_if = "Option::is_none")]
    pub r#where: Option<Condition>,
    #[serde(default)]
    pub sort: Vec<SortKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default)]
    pub group_by: Vec<GroupKey>,
    #[serde(default)]
    pub aggregates: Vec<Aggregate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub having: Option<Condition>,
    #[serde(default)]
    pub explain: bool,
    /// Read the records as they were at this time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_of: Option<DateTime<Utc>>,
    /// Values for `param` conditions, by name.
    #[serde(default)]
    pub params: BTreeMap<String, Value>,
    /// P1-T2: total rows an aggregate query adds (`rollup` or `cube`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totals: Option<Totals>,
}

/// P1-T2: the total rows of an aggregate query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Totals {
    /// Subtotals along the group fields in order, then the grand total
    /// (`GROUP BY ROLLUP`): a summary's subtotals.
    Rollup,
    /// A total for every combination of the group fields (`GROUP BY CUBE`):
    /// a matrix's row totals, column totals and grand total.
    Cube,
}

/// One node of the condition tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Condition {
    And {
        all: Vec<Condition>,
    },
    Or {
        any: Vec<Condition>,
    },
    Not {
        condition: Box<Condition>,
    },
    Compare {
        field: String,
        op: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<Value>,
    },
    /// A related record exists (through a lookup or relationship path).
    Exists {
        path: String,
        #[serde(default, rename = "where", skip_serializing_if = "Option::is_none")]
        r#where: Option<Box<Condition>>,
    },
    NotExists {
        path: String,
        #[serde(default, rename = "where", skip_serializing_if = "Option::is_none")]
        r#where: Option<Box<Condition>>,
    },
    /// A comparison whose value comes from `params`.
    Param {
        field: String,
        op: String,
        param: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SortKey {
    pub field: String,
    #[serde(default)]
    pub desc: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DateBucket {
    Day,
    Week,
    Month,
    Quarter,
    Year,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupKey {
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<DateBucket>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggFunc {
    Count,
    Sum,
    Avg,
    Min,
    Max,
    CountDistinct,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Aggregate {
    pub func: AggFunc,
    /// None only for `count` (every row).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub alias: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn query_spec_round_trips_json() {
        let doc = json!({
            "entity": "opportunity",
            "select": ["name", "amount"],
            "where": {"kind": "and", "all": [
                {"kind": "compare", "field": "stage", "op": "in", "value": ["won", "open"]},
                {"kind": "not", "condition": {"kind": "compare", "field": "amount", "op": "is_null"}},
                {"kind": "exists", "path": "account.contacts",
                 "where": {"kind": "param", "field": "city", "op": "eq", "param": "city"}}
            ]},
            "sort": [{"field": "amount", "desc": true}],
            "page_size": 50,
            "group_by": [{"field": "closedate", "bucket": "month"}],
            "aggregates": [{"func": "sum", "field": "amount", "alias": "total"},
                           {"func": "count", "alias": "n"}],
            "having": {"kind": "compare", "field": "total", "op": "gt", "value": 1000},
            "explain": false,
            "params": {"city": "Riyadh"}
        });
        let spec: QuerySpec = serde_json::from_value(doc.clone()).expect("parses");
        assert_eq!(spec.entity, "opportunity");
        assert_eq!(spec.aggregates[0].func, AggFunc::Sum);
        let back = serde_json::to_value(&spec).expect("serializes");
        let again: QuerySpec = serde_json::from_value(back).expect("parses again");
        assert_eq!(spec, again);
        for op in ["between", "in", "mine", "text_matches"] {
            assert!(OPERATORS.contains(&op), "{op}");
        }
    }

    #[test]
    fn unknown_condition_kind_is_rejected() {
        let doc = json!({
            "entity": "account",
            "where": {"kind": "xor", "all": []}
        });
        assert!(serde_json::from_value::<QuerySpec>(doc).is_err());
        let unknown_field = json!({"entity": "account", "limit": 5});
        assert!(serde_json::from_value::<QuerySpec>(unknown_field).is_err());
    }
}
