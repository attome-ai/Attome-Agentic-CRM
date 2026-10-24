//! Text and JSON forms of the same queries (roadmap S4-T8): each text must
//! parse to exactly its JSON spec. S4-T14's contract tests run both forms
//! from this list.

#[cfg(test)]
pub(crate) fn cases() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        (
            "SELECT name FROM account",
            json!({"entity": "account", "select": ["name"]}),
        ),
        (
            "SELECT name FROM account WHERE EXISTS(incident.customerid WHERE statecode = 0)",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "exists", "path": "incident.customerid",
                             "where": {"kind": "compare", "field": "statecode", "op": "eq", "value": 0}}}),
        ),
        (
            "SELECT name FROM account WHERE name = 'Acme'",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "compare", "field": "name", "op": "eq", "value": "Acme"}}),
        ),
        (
            "SELECT name FROM account WHERE revenue <> 0",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "compare", "field": "revenue", "op": "neq", "value": 0}}),
        ),
        (
            "SELECT name FROM account WHERE revenue > 1.5 AND revenue <= 99",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "and", "all": [
                       {"kind": "compare", "field": "revenue", "op": "gt", "value": 1.5},
                       {"kind": "compare", "field": "revenue", "op": "lte", "value": 99}]}}),
        ),
        (
            "SELECT name FROM account WHERE revenue < -3 OR revenue >= 10",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "or", "any": [
                       {"kind": "compare", "field": "revenue", "op": "lt", "value": -3},
                       {"kind": "compare", "field": "revenue", "op": "gte", "value": 10}]}}),
        ),
        (
            "SELECT name FROM account WHERE a = 1 OR b = 2 AND c = 3",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "or", "any": [
                       {"kind": "compare", "field": "a", "op": "eq", "value": 1},
                       {"kind": "and", "all": [
                           {"kind": "compare", "field": "b", "op": "eq", "value": 2},
                           {"kind": "compare", "field": "c", "op": "eq", "value": 3}]}]}}),
        ),
        (
            "SELECT name FROM account WHERE (a = 1 OR b = 2) AND c = 3",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "and", "all": [
                       {"kind": "or", "any": [
                           {"kind": "compare", "field": "a", "op": "eq", "value": 1},
                           {"kind": "compare", "field": "b", "op": "eq", "value": 2}]},
                       {"kind": "compare", "field": "c", "op": "eq", "value": 3}]}}),
        ),
        (
            "SELECT name FROM account WHERE NOT active = true",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "not", "condition":
                       {"kind": "compare", "field": "active", "op": "eq", "value": true}}}),
        ),
        (
            "SELECT name FROM account WHERE stage IN ('won', 'lost')",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "compare", "field": "stage", "op": "in", "value": ["won", "lost"]}}),
        ),
        (
            "SELECT name FROM account WHERE stage NOT IN ('won')",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "compare", "field": "stage", "op": "not_in", "value": ["won"]}}),
        ),
        (
            "SELECT name FROM account WHERE revenue BETWEEN 10 AND 20",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "compare", "field": "revenue", "op": "between", "value": [10, 20]}}),
        ),
        (
            "SELECT name FROM account WHERE parent IS NULL",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "compare", "field": "parent", "op": "is_null"}}),
        ),
        (
            "SELECT name FROM account WHERE parent IS NOT NULL",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "compare", "field": "parent", "op": "is_not_null"}}),
        ),
        (
            "SELECT name FROM account WHERE name starts_with 'Al'",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "compare", "field": "name", "op": "starts_with", "value": "Al"}}),
        ),
        (
            "SELECT name FROM account WHERE name contains 'co'",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "compare", "field": "name", "op": "contains", "value": "co"}}),
        ),
        (
            "SELECT name FROM account WHERE created_at last_n_days(30)",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "compare", "field": "created_at", "op": "last_n_days", "value": 30}}),
        ),
        (
            "SELECT name FROM account WHERE owner_ref mine",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "compare", "field": "owner_ref", "op": "mine"}}),
        ),
        (
            "SELECT name FROM account WHERE tags contains_any ('a', 'b')",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "compare", "field": "tags", "op": "contains_any", "value": ["a", "b"]}}),
        ),
        (
            "SELECT name FROM account WHERE city = :city",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "param", "field": "city", "op": "eq", "param": "city"}}),
        ),
        (
            "SELECT name FROM account WHERE NOT EXISTS(contact.parentcustomerid)",
            json!({"entity": "account", "select": ["name"],
                   "where": {"kind": "not_exists", "path": "contact.parentcustomerid"}}),
        ),
        (
            "SELECT name, revenue FROM account ORDER BY revenue DESC, name ASC LIMIT 10",
            json!({"entity": "account", "select": ["name", "revenue"],
                   "sort": [{"field": "revenue", "desc": true}, {"field": "name", "desc": false}],
                   "page_size": 10}),
        ),
        (
            "SELECT count_distinct(owner_ref) AS owners, avg(revenue) AS mean FROM account GROUP BY bucket(created_at, month)",
            json!({"entity": "account",
                   "aggregates": [
                       {"func": "count_distinct", "field": "owner_ref", "alias": "owners"},
                       {"func": "avg", "field": "revenue", "alias": "mean"}],
                   "group_by": [{"field": "created_at", "bucket": "month"}]}),
        ),
        (
            "SELECT industry, min(revenue) AS low, max(revenue) AS high FROM account GROUP BY industry HAVING low > 0 ORDER BY industry",
            json!({"entity": "account", "select": ["industry"],
                   "aggregates": [
                       {"func": "min", "field": "revenue", "alias": "low"},
                       {"func": "max", "field": "revenue", "alias": "high"}],
                   "group_by": [{"field": "industry"}],
                   "having": {"kind": "compare", "field": "low", "op": "gt", "value": 0},
                   "sort": [{"field": "industry", "desc": false}]}),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::cases;
    use crate::query_spec::{QuerySpec, text};

    #[test]
    fn text_and_json_forms_parse_to_equal_specs() {
        let cases = cases();
        assert!(cases.len() >= 20);
        for (text_form, json_form) in cases {
            let from_json: QuerySpec =
                serde_json::from_value(json_form).unwrap_or_else(|e| panic!("{text_form}: {e}"));
            let from_text = text::parse(text_form).unwrap_or_else(|e| panic!("{text_form}: {e:?}"));
            assert_eq!(from_text, from_json, "{text_form}");
        }
    }
}
