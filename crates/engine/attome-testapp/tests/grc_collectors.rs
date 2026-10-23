//! R11-T1: the evidence collectors write one evidence record each, and a
//! failing collector opens one finding however often it fails.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_grc::collectors::{Collector, Inputs, collect};
use attome_testapp::TestApp;
use chrono::{Duration, Utc};

async fn count(app: &TestApp, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(app.db()).await.unwrap()
}

// feature: R11
#[test]
fn collectors_write_evidence_and_one_finding_per_failure() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let evidence_before = count(
            &app,
            "SELECT count(*) FROM grc_evidence WHERE reference_value LIKE 'collector:%'",
        )
        .await;
        // No restore drill recorded: backup_drill fails.
        let inputs = Inputs {
            last_drill: None,
            release_version: "0.0.0-test".into(),
        };
        let first = collect(&app.state, &inputs).await.expect("collect");
        assert_eq!(first.collected, Collector::ALL.len());
        assert!(first.failed >= 1, "{first:?}");
        let evidence_after = count(
            &app,
            "SELECT count(*) FROM grc_evidence WHERE reference_value LIKE 'collector:%'",
        )
        .await;
        assert_eq!(
            evidence_after - evidence_before,
            i64::try_from(Collector::ALL.len()).unwrap()
        );
        let drill_findings = "SELECT count(*) FROM grc_finding \
                               WHERE title = 'Evidence check failed: backup_drill' \
                                 AND status::text = 'open'";
        assert_eq!(count(&app, drill_findings).await, 1);

        // Failing again opens no second finding.
        collect(&app.state, &inputs).await.expect("collect again");
        assert_eq!(count(&app, drill_findings).await, 1);

        // A recent passing drill passes.
        let passing = Inputs {
            last_drill: Some((Utc::now() - Duration::days(2), true, "ok".into())),
            release_version: "0.0.0-test".into(),
        };
        collect(&app.state, &passing)
            .await
            .expect("collect with a drill");
        let passed: bool = sqlx::query_scalar(
            "SELECT (notes::jsonb ->> 'passed')::boolean FROM grc_evidence \
              WHERE reference_value = 'collector:backup_drill' \
              ORDER BY collected_at DESC, id DESC LIMIT 1",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(passed);
    });
}
