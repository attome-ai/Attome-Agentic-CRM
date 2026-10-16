//! Z11-T1: language versions — a V2 function is unknown to V1 text, V2
//! accepts every V1 expression, and upgrading V1 text to V2 keeps it.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_rules::{
    Budgets, Context, LanguageVersion, RulesError, Schema, Type, Value, compile, compile_versioned,
    upgrade,
};

fn schema() -> Schema {
    Schema::new().with_field("name", Type::Text)
}

#[test]
fn v1_rejects_v2_function() {
    let Err(err) = compile_versioned(
        r#"endswith(name, "Ltd")"#,
        &schema(),
        LanguageVersion::V1,
        Budgets::default(),
    ) else {
        panic!("V1 does not know endswith");
    };
    assert!(
        matches!(err, RulesError::UnknownFunction(ref f) if f == "endswith"),
        "{err:?}"
    );
    assert!(
        compile(r#"endswith(name, "Ltd")"#, &schema()).is_err(),
        "compile() is V1"
    );

    let v2 = compile_versioned(
        r#"endswith(name, "Ltd")"#,
        &schema(),
        LanguageVersion::V2,
        Budgets::default(),
    )
    .expect("V2 knows endswith");
    let ctx = Context::new(chrono::Utc::now()).with_field("name", Value::Text("Acme Ltd".into()));
    assert_eq!(v2.eval(&ctx).unwrap(), Value::Bool(true));
}

#[test]
fn v2_accepts_v1_expression() {
    let src = r#"if(startswith(name, "A"), len(name), 0)"#;
    assert!(compile(src, &schema()).is_ok());
    assert!(compile_versioned(src, &schema(), LanguageVersion::LATEST, Budgets::default()).is_ok());
    assert_eq!(LanguageVersion::parse("v2"), Some(LanguageVersion::V2));
    assert_eq!(LanguageVersion::V1.as_str(), "v1");
    assert_eq!(LanguageVersion::parse("v9"), None);
}

#[test]
fn upgrade_v1_to_v2_keeps_text() {
    let src = r#"lower(name) == "acme""#;
    assert_eq!(
        upgrade(src, LanguageVersion::V1, LanguageVersion::V2).unwrap(),
        src
    );
    assert!(
        upgrade(
            r#"endswith(name, "x")"#,
            LanguageVersion::V2,
            LanguageVersion::V1
        )
        .is_err(),
        "V2 text using a V2 function cannot go back to V1"
    );
}
