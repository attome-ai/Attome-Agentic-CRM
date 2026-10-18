//! Z11-T9: decision tables — first and all hit policies, and the gap,
//! overlap and unchecked-cell report.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::ops::Bound;

use attome_rules::{
    Budgets, Context, DecisionRow, DecisionTable, HitPolicy, TableIssue, Type, Value,
};
use chrono::Utc;

fn row(cells: &[Option<&str>], result: &str) -> DecisionRow {
    DecisionRow {
        cells: cells.iter().map(|c| c.map(str::to_owned)).collect(),
        result: result.to_owned(),
    }
}

/// Discount by order amount and tier.
fn discounts(hit: HitPolicy) -> DecisionTable {
    DecisionTable {
        inputs: vec![("amount".into(), Type::Number), ("tier".into(), Type::Text)],
        output: Type::Number,
        hit,
        rows: vec![
            row(&[Some("it < 100"), None], "0"),
            row(
                &[Some("it >= 100 and it < 500"), Some("it == \"gold\"")],
                "10",
            ),
            row(&[Some("it >= 100"), None], "5"),
        ],
    }
}

fn ctx(amount: f64, tier: &str) -> Context {
    Context::new(Utc::now())
        .with_field("amount", Value::Number(amount))
        .with_field("tier", Value::Text(tier.into()))
}

#[test]
fn first_match_returns_first_row() {
    let table = discounts(HitPolicy::First)
        .compile(Budgets::default())
        .unwrap();
    assert_eq!(table.eval(&ctx(50.0, "gold")).unwrap(), Value::Number(0.0));
    assert_eq!(
        table.eval(&ctx(200.0, "gold")).unwrap(),
        Value::Number(10.0)
    );
    assert_eq!(
        table.eval(&ctx(200.0, "silver")).unwrap(),
        Value::Number(5.0)
    );

    let mut none = discounts(HitPolicy::First);
    none.rows.remove(0);
    let none = none.compile(Budgets::default()).unwrap();
    assert_eq!(
        none.eval(&ctx(50.0, "gold")).unwrap(),
        Value::Null,
        "no row matches"
    );
}

#[test]
fn all_matches_returns_list() {
    let table = discounts(HitPolicy::All)
        .compile(Budgets::default())
        .unwrap();
    assert_eq!(
        table.eval(&ctx(200.0, "gold")).unwrap(),
        Value::List(vec![Value::Number(10.0), Value::Number(5.0)])
    );
    assert_eq!(
        table.eval(&ctx(50.0, "x")).unwrap(),
        Value::List(vec![Value::Number(0.0)])
    );
}

#[test]
fn numeric_gap_reported() {
    let table = DecisionTable {
        inputs: vec![("amount".into(), Type::Number)],
        output: Type::Text,
        hit: HitPolicy::First,
        rows: vec![
            row(&[Some("it < 100")], "\"small\""),
            row(&[Some("it >= 200")], "\"large\""),
        ],
    }
    .compile(Budgets::default())
    .unwrap();
    assert_eq!(
        table.check(),
        vec![TableIssue::Gap {
            input: "amount".into(),
            from: Bound::Included(100.0),
            to: Bound::Excluded(200.0),
        }]
    );
    // A row for the middle closes it.
    let closed = DecisionTable {
        inputs: vec![("amount".into(), Type::Number)],
        output: Type::Text,
        hit: HitPolicy::First,
        rows: vec![
            row(&[Some("it < 100")], "\"small\""),
            row(&[Some("it >= 100 and it < 200")], "\"medium\""),
            row(&[Some("it >= 200")], "\"large\""),
        ],
    }
    .compile(Budgets::default())
    .unwrap();
    assert!(closed.check().is_empty(), "{:?}", closed.check());
}

#[test]
fn overlap_reported() {
    let table = discounts(HitPolicy::First)
        .compile(Budgets::default())
        .unwrap();
    // Row 2 (100..500, gold) and row 3 (>= 100, any tier) both match 200/gold.
    assert_eq!(table.check(), vec![TableIssue::Overlap { rows: (1, 2) }]);
    let distinct = DecisionTable {
        inputs: vec![("tier".into(), Type::Text)],
        output: Type::Number,
        hit: HitPolicy::All,
        rows: vec![
            row(&[Some("it == \"gold\"")], "10"),
            row(&[Some("in(it, [\"silver\", \"bronze\"])")], "5"),
        ],
    }
    .compile(Budgets::default())
    .unwrap();
    assert!(distinct.check().is_empty(), "{:?}", distinct.check());
}

#[test]
fn free_form_cell_unchecked() {
    let table = DecisionTable {
        inputs: vec![("amount".into(), Type::Number)],
        output: Type::Number,
        hit: HitPolicy::First,
        rows: vec![
            row(&[Some("it * 2 > 100")], "1"),
            row(&[Some("it < 0")], "2"),
        ],
    }
    .compile(Budgets::default())
    .unwrap();
    let issues = table.check();
    assert!(
        issues.contains(&TableIssue::Unchecked {
            row: 0,
            input: "amount".into()
        }),
        "{issues:?}"
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, TableIssue::Gap { .. } | TableIssue::Overlap { .. })),
        "no gap or overlap is claimed past an unchecked cell: {issues:?}"
    );
    assert_eq!(table.eval(&ctx(60.0, "")).unwrap(), Value::Number(1.0));
}

#[test]
fn bad_tables_are_refused() {
    let mut wide = discounts(HitPolicy::First);
    wide.rows[0].cells.pop();
    assert!(
        wide.compile(Budgets::default()).is_err(),
        "a row with too few cells"
    );
    let mut not_a_condition = discounts(HitPolicy::First);
    not_a_condition.rows[0].cells[0] = Some("it + 1".into());
    assert!(not_a_condition.compile(Budgets::default()).is_err());
    let mut wrong_result = discounts(HitPolicy::First);
    wrong_result.rows[0].result = "\"zero\"".into();
    assert!(wrong_result.compile(Budgets::default()).is_err());
    let mut big = discounts(HitPolicy::First);
    big.rows = (0..=attome_rules::decision_table::MAX_ROWS)
        .map(|_| row(&[None, None], "0"))
        .collect();
    let err = big.compile(Budgets::default()).unwrap_err();
    assert_eq!(err.code(), "rules.budget.table_size");
}
