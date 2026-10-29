//! Z11-T7: multi-hop paths (two or three hops), read from data the caller
//! loaded after checking read access at every hop.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_rules::{
    Budgets, Context, LanguageVersion, RulesError, Schema, Type, Value, compile_versioned,
};
use chrono::Utc;

fn schema() -> Schema {
    Schema::new()
        .with_field("amount", Type::Number)
        .with_path(&["deal", "account", "tier"], Type::Text)
        .with_optional_path(&["deal", "account", "owner", "region"], Type::Text)
}

fn v2(src: &str) -> Result<attome_rules::Compiled, RulesError> {
    compile_versioned(src, &schema(), LanguageVersion::V2, Budgets::default())
}

#[test]
fn two_hop_path_reads_context() {
    let rule = v2("deal.account.tier == \"gold\" and amount > 10").unwrap();
    let ctx = Context::new(Utc::now())
        .with_field("amount", Value::Number(20.0))
        .with_path(&["deal", "account", "tier"], Value::Text("gold".into()));
    assert_eq!(rule.eval(&ctx).unwrap(), Value::Bool(true));
    // Not loaded: a required path is unknown, an optional one reads as null.
    let bare = Context::new(Utc::now()).with_field("amount", Value::Number(20.0));
    assert_eq!(rule.eval(&bare).unwrap_err().code(), "rules.field.unknown");
    let optional = v2("is_null(deal.account.owner.region)").unwrap();
    assert_eq!(optional.eval(&bare).unwrap(), Value::Bool(true));
}

#[test]
fn six_hop_path_rejected() {
    // A9-T2 allows up to five lookups after the first field.
    let err = v2("deal.account.owner.region.country.zone.name == \"x\"").unwrap_err();
    assert_eq!(err.code(), "rules.lookup.multi_hop");
    // A path the schema does not declare is an unknown field.
    assert_eq!(
        v2("deal.account.name").unwrap_err().code(),
        "rules.field.unknown"
    );
}

#[test]
fn compiled_lists_paths() {
    let rule = v2(
        "if(is_null(deal.account.owner.region), deal.account.tier, deal.account.owner.region) == deal.account.tier",
    )
    .unwrap();
    assert_eq!(
        rule.paths(),
        vec![
            vec![
                "deal".to_owned(),
                "account".into(),
                "owner".into(),
                "region".into()
            ],
            vec!["deal".to_owned(), "account".into(), "tier".into()],
        ]
    );
    assert!(v2("amount + 1").unwrap().paths().is_empty());
}

#[test]
fn v1_rejects_path() {
    let err = compile_versioned(
        "deal.account.tier == \"gold\"",
        &schema(),
        LanguageVersion::V1,
        Budgets::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), "rules.lookup.multi_hop");
}
