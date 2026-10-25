//! Z11-T12: the `expression.validate` agent tool returns the check the
//! admin validate route returns: an error's code and byte span, or the
//! result type and whether the expression runs in the database.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_ai::execute::ActionOutcome;
use attome_testkit::skip_if_no_db;
use serde_json::{Value, json};

use common::fixture;

fn completed(outcome: ActionOutcome) -> Value {
    match outcome {
        ActionOutcome::Completed { result, .. } => result,
        other => panic!("expected the read to execute, got {other:?}"),
    }
}

#[tokio::test]
async fn expression_validate_tool_returns_diagnostics() {
    let f = skip_if_no_db!(fixture().await);
    let ctx = f.agent_ctx("expr-1").await;

    // `statuz` is not a field: the error points at it.
    let expression = r#"lower(statuz) == "open""#;
    let result = completed(
        f.dispatch(
            &ctx,
            "expression.validate",
            json!({ "expression": expression, "entity": f.entity }),
        )
        .await
        .expect("dispatch"),
    );
    assert_eq!(result["ok"], false, "{result}");
    let diagnostic = &result["diagnostics"][0];
    assert_eq!(diagnostic["code"], "rules.field.unknown", "{result}");
    let start = diagnostic["start"].as_u64().unwrap() as usize;
    let end = diagnostic["end"].as_u64().unwrap() as usize;
    assert_eq!(&expression[start..end], "statuz", "{result}");

    // A good expression: its type, and it runs in the database.
    let result = completed(
        f.dispatch(
            &ctx,
            "expression.validate",
            json!({ "expression": r#"lower(status) == "open""#, "entity": f.entity }),
        )
        .await
        .expect("dispatch"),
    );
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["result_type"], "bool", "{result}");
    assert_eq!(result["sql_translatable"], true, "{result}");

    // The spec tool lists the V2 functions.
    let spec = completed(
        f.dispatch(&ctx, "expression.spec", json!({}))
            .await
            .expect("dispatch"),
    );
    assert!(
        spec["functions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["name"] == "normalize_ar"),
        "{spec}"
    );
}
