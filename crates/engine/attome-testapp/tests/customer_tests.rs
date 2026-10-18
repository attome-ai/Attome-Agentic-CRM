//! Z15-T12: a customer test runs its given/when/expect inside a transaction
//! that is always rolled back: a passing test leaves no rows, a mismatch is
//! reported with the attribute and both values, a role's missing privilege
//! is an expected `forbidden`, and a stored test's run is recorded.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_records::customer_tests::{TestDefinition, run_and_record, run_test};
use attome_testapp::TestApp;
use serde_json::{Value, json};
use uuid::Uuid;

async fn install(app: &TestApp) {
    for pack in ["crm"] {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs")
            .join(pack)
            .join("changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
}

fn definition(value: Value) -> TestDefinition {
    serde_json::from_value(value).unwrap()
}

async fn accounts_named(app: &TestApp, name: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM account WHERE name = $1 OR name = $1 || ' renamed'")
        .bind(name)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: Z15
#[test]
fn passing_test_leaves_no_rows() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let ctx = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let name = format!("ct-{}", Uuid::now_v7().simple());
        let outcome = run_test(
            &app.state,
            &ctx,
            &definition(json!({
                "given": [{ "entity": "account", "ref": "a", "record": { "name": name } }],
                "when": [{ "op": "update", "entity": "account", "ref": "a",
                           "values": { "name": format!("{name} renamed") } }],
                "expect": [{ "entity": "account", "ref": "a", "attribute": "name",
                             "equals": format!("{name} renamed") }]
            })),
        )
        .await;
        assert!(outcome.passed, "{:?}", outcome.failures);
        assert_eq!(accounts_named(&app, &name).await, 0, "rolled back");

        // A role without the privilege meets an expected forbidden.
        let role = format!("ct-role-{}", Uuid::now_v7().simple());
        sqlx::query("INSERT INTO role (name, owner_layer) VALUES ($1, 'customer')")
            .bind(&role)
            .execute(app.db())
            .await
            .unwrap();
        let outcome = run_test(
            &app.state,
            &ctx,
            &definition(json!({
                "as_role": role,
                "given": [{ "entity": "account", "ref": "a", "record": { "name": name } }],
                "when": [{ "op": "delete", "entity": "account", "ref": "a" }],
                "expect": [{ "error": "forbidden" }]
            })),
        )
        .await;
        assert!(outcome.passed, "{:?}", outcome.failures);
        assert_eq!(accounts_named(&app, &name).await, 0, "rolled back");
    });
}

// feature: Z15
#[test]
fn expectation_mismatch_is_reported() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let ctx = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let name = format!("ct-{}", Uuid::now_v7().simple());
        let wrong = definition(json!({
            "given": [{ "entity": "account", "ref": "a", "record": { "name": name } }],
            "expect": [
                { "entity": "account", "ref": "a", "attribute": "name", "equals": "Someone else" },
                { "error": "conflict" }
            ]
        }));
        let outcome = run_test(&app.state, &ctx, &wrong).await;
        assert!(!outcome.passed);
        assert!(
            outcome
                .failures
                .iter()
                .any(|f| f.contains("a.name") && f.contains("Someone else")),
            "{:?}",
            outcome.failures
        );
        assert!(
            outcome.failures.iter().any(|f| f.contains("Conflict")),
            "{:?}",
            outcome.failures
        );
        assert_eq!(accounts_named(&app, &name).await, 0, "rolled back");

        // A stored test: its run is recorded with the failures.
        let test = Uuid::now_v7();
        sqlx::query("INSERT INTO customer_test (id, name, definition) VALUES ($1, 'mismatch', $2)")
            .bind(test)
            .bind(serde_json::to_value(&wrong).unwrap())
            .execute(app.db())
            .await
            .unwrap();
        let (run, outcome) = run_and_record(&app.state, &ctx, test).await.unwrap();
        assert!(!outcome.passed);
        let (passed, failures): (Option<bool>, Option<Value>) =
            sqlx::query_as("SELECT passed, failures FROM customer_test_run WHERE id = $1")
                .bind(run)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(passed, Some(false));
        assert_eq!(
            failures.unwrap().as_array().unwrap().len(),
            outcome.failures.len()
        );
    });
}
