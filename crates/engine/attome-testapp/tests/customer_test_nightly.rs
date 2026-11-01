//! T7-T3: the nightly run of live-safe customer tests reports the ones that
//! fail and flags a test whose runs on one test and configuration version
//! both passed and failed.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use serde_json::{Value, json};
use uuid::Uuid;

async fn live_test(app: &TestApp, name: &str, author: Uuid, definition: Value) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO customer_test (id, name, definition, created_by, live_safe) \
         VALUES ($1, $2, $3, $4, true)",
    )
    .bind(id)
    .bind(name)
    .bind(definition)
    .bind(author)
    .execute(app.db())
    .await
    .unwrap();
    id
}

// feature: T7
#[test]
fn nightly_reports_failures_and_flags_flaky_tests() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        // An author with no privileges: deleting notes is refused to them.
        let author = attome_testapp::seed_user(app.db(), "nightly-author").await;
        let suffix = Uuid::now_v7().simple().to_string();
        let holds = format!("refused-{suffix}");
        let breaks = format!("allowed-{suffix}");
        let steady = live_test(
            &app,
            &holds,
            author.id,
            json!({ "expect": [{ "entity": "note", "action": "delete", "allowed": false }] }),
        )
        .await;
        live_test(
            &app,
            &breaks,
            author.id,
            json!({ "expect": [{ "entity": "note", "action": "delete", "allowed": true }] }),
        )
        .await;
        // An earlier failed run of the steady test on the same versions.
        sqlx::query(
            "INSERT INTO customer_test_run \
                 (id, test_id, finished_at, passed, failures, test_version, config_version) \
             VALUES ($1, $2, now(), false, '[]', \
                     (SELECT row_version FROM customer_test WHERE id = $2), \
                     (SELECT COALESCE(MAX(id), 0) FROM metadata_change_log))",
        )
        .bind(Uuid::now_v7())
        .bind(steady)
        .execute(app.db())
        .await
        .unwrap();

        let report = attome_records::customer_tests::run_live_safe(&app.state)
            .await
            .unwrap();
        assert!(report.failed.contains(&breaks), "{report:?}");
        assert!(!report.failed.contains(&holds), "{report:?}");
        assert!(report.flaky.contains(&holds), "{report:?}");
        let flagged: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT flaky_since FROM customer_test WHERE id = $1")
                .bind(steady)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert!(flagged.is_some());
        let scheduled: bool = sqlx::query_scalar(
            "SELECT scheduled FROM customer_test_run WHERE test_id = $1 \
              ORDER BY started_at DESC, id DESC LIMIT 1",
        )
        .bind(steady)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(scheduled);

        // Flagged once: the next night does not report it again.
        let again = attome_records::customer_tests::run_live_safe(&app.state)
            .await
            .unwrap();
        assert!(!again.flaky.contains(&holds), "{again:?}");
    });
}
