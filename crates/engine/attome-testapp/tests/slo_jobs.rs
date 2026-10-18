//! AA13-T9: the monthly SLO report is written once per month, and a class
//! burning its error budget fast notifies the administrators once per hour.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::slo_admin::{burn_check, monthly_report, report_period};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::json;
use uuid::Uuid;

/// A past day no other run uses (the Redis dedupe key and the samples are
/// keyed by time).
fn unique_day() -> NaiveDate {
    let offset = (Uuid::now_v7().as_u128() % 7_000) as i64;
    NaiveDate::from_ymd_opt(2003, 1, 1).unwrap() + Duration::days(offset)
}

// feature: AA13
#[test]
fn monthly_report_is_idempotent() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let day = unique_day();
        let now: DateTime<Utc> = day.and_hms_opt(12, 0, 0).unwrap().and_utc();
        let period = report_period(now);

        assert!(
            monthly_report(&app.state, now).await.unwrap(),
            "first run writes"
        );
        assert!(
            !monthly_report(&app.state, now).await.unwrap(),
            "a repeat is a no-op"
        );
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM ops_slo_report WHERE period_start = $1")
                .bind(period)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(rows, 1);

        let path = format!("/api/v1/admin/slo/reports/{}", period.format("%Y-%m"));
        let (status, report) = app.request(Method::GET, &path, None).await;
        assert_eq!(status, StatusCode::OK, "{report}");
        let classes = report["report"]["classes"].as_array().unwrap();
        let s1 = classes.iter().find(|c| c["id"] == "S1").unwrap();
        assert_eq!(
            s1["status"], "ok",
            "no traffic leaves the whole budget: {s1}"
        );
        let (status, list) = app
            .request(Method::GET, "/api/v1/admin/slo/reports", None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(list["total"].as_i64().unwrap() >= 1, "{list}");
    });
}

// feature: AA13
#[test]
fn burn_check_notifies_once_per_hour() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let day = unique_day();
        attome_server::metrics_store::ensure_partitions(app.db(), day)
            .await
            .unwrap();
        let now: DateTime<Utc> = day.and_hms_opt(10, 30, 0).unwrap().and_utc();
        // S1 (GET whoami, 0.1% objective): half the last four minutes' requests failed.
        let series = |status: &str| {
            json!({ "method": "GET", "endpoint": "/api/v1/admin/security/whoami", "status": status,
                    "node": format!("burn-{day}") })
        };
        for (status, at, value) in [
            ("200", now - Duration::minutes(4), 0.0),
            ("200", now - Duration::minutes(1), 100.0),
            ("500", now - Duration::minutes(4), 0.0),
            ("500", now - Duration::minutes(1), 100.0),
        ] {
            sqlx::query(
                "INSERT INTO ops_metric_sample (ts, name, labels, value) \
                 VALUES ($1, 'axum_http_requests_total', $2, $3)",
            )
            .bind(at)
            .bind(series(status))
            .bind(value)
            .execute(app.db())
            .await
            .unwrap();
        }
        let notification = app.state.base.config.notification.clone();

        let first = burn_check(&app.state, &notification, now).await.unwrap();
        assert!(first.iter().any(|c| c == "S1"), "{first:?}");
        let again = burn_check(&app.state, &notification, now + Duration::minutes(5))
            .await
            .unwrap();
        assert!(!again.iter().any(|c| c == "S1"), "once per hour: {again:?}");
        // The administrator was told.
        let told: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM notification_dispatch WHERE recipient_user_ref = $1 \
             AND subject LIKE '%burning its error budget fast%'",
        )
        .bind(app.admin.id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(told >= 1);
    });
}

/// Stores one minute of S5's (POST query/execute) request-duration buckets:
/// `n` requests, `slow` of them in the 0.1-0.12 s bucket.
async fn store_s5_buckets(app: &TestApp, node: &str, at: DateTime<Utc>, n: f64, slow: f64) {
    for (le, value) in [
        ("0.03", n - slow),
        ("0.1", n - slow),
        ("0.12", n),
        ("+Inf", n),
    ] {
        sqlx::query(
            "INSERT INTO ops_metric_sample (ts, name, labels, value) VALUES ($1, $2, $3, $4)",
        )
        .bind(at)
        .bind(attome_server::metrics_store::SLO_LATENCY_BUCKETS)
        .bind(
            json!({ "method": "POST", "endpoint": "/api/v1/query/execute", "le": le,
                      "node": node }),
        )
        .bind(value)
        .execute(app.db())
        .await
        .unwrap();
    }
}

// feature: AA14
#[test]
fn perf_regression_check_alerts_once_on_a_slower_upgrade() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let day = unique_day();
        let upgraded: DateTime<Utc> = day.and_hms_opt(12, 0, 0).unwrap().and_utc();
        let now = upgraded + Duration::days(2);
        for offset in [-3, -2, 0, 1] {
            attome_server::metrics_store::ensure_partitions(app.db(), day + Duration::days(offset))
                .await
                .unwrap();
        }
        let node = format!("perf-{day}");
        for (version, started_at) in [
            ("1.0.0-perf", upgraded - Duration::days(10)),
            ("1.1.0-perf", upgraded),
        ] {
            sqlx::query(
                "INSERT INTO deploy_event (node, version, kind, started_at, finished_at) \
                 VALUES ($1, $2, 'start', $3, $3)",
            )
            .bind(&node)
            .bind(version)
            .bind(started_at)
            .execute(app.db())
            .await
            .unwrap();
        }
        // The week before: 5,000 requests, 2% slow. Since: 5,000, 10% slow.
        let before = upgraded - Duration::days(2);
        store_s5_buckets(&app, &node, before, 0.0, 0.0).await;
        store_s5_buckets(&app, &node, before + Duration::minutes(1), 5_000.0, 100.0).await;
        let after = upgraded + Duration::days(1);
        store_s5_buckets(&app, &node, after, 0.0, 0.0).await;
        store_s5_buckets(&app, &node, after + Duration::minutes(1), 5_000.0, 500.0).await;

        assert_eq!(
            attome_server::slo::last_upgrade(app.db()).await.unwrap(),
            Some(upgraded)
        );
        let findings = attome_server::slo::perf_regression_check(app.db(), now)
            .await
            .unwrap();
        let s5 = findings.iter().find(|f| f.class == "S5").unwrap();
        assert!(s5.regressed, "{s5:?}");
        assert_eq!((s5.before_requests, s5.after_requests), (5_000, 5_000));
        let s1 = findings.iter().find(|f| f.class == "S1").unwrap();
        assert!(!s1.regressed, "no traffic is not a regression: {s1:?}");

        let state: String =
            sqlx::query_scalar("SELECT state FROM ops_alert WHERE name = 'PerfRegression:S5'")
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(state, "firing");
        // A second day of the same regression keeps it firing without a
        // second notification.
        attome_server::slo::perf_regression_check(app.db(), now + Duration::hours(1))
            .await
            .unwrap();
        let fired: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM ops_alert_event WHERE name = 'PerfRegression:S5' \
             AND event = 'firing'",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(fired, 1);
        let s1_alert: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM ops_alert WHERE name = 'PerfRegression:S1' AND state = 'firing'",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(s1_alert, 0);
    });
}
