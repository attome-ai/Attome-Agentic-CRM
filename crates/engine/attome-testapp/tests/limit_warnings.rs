//! AA9-T7: a limit whose seven-day peak reaches the warning level tells the
//! administrators once per day, and the limits list flags it.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::limits_admin::limit_warning_check;
use attome_testapp::TestApp;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use uuid::Uuid;

/// A past day no other run uses (the Redis dedupe key is keyed by day).
fn unique_day() -> NaiveDate {
    let offset = (Uuid::now_v7().as_u128() % 7_000) as i64;
    NaiveDate::from_ymd_opt(2003, 1, 1).unwrap() + Duration::days(offset)
}

// feature: AA9
#[test]
fn warning_created_once_per_day() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let day = unique_day();
        let now: DateTime<Utc> = day.and_hms_opt(3, 0, 0).unwrap().and_utc();
        // The bulk cap (500 records by default) reached 425 records, 85%,
        // two days before, and nobody was refused.
        sqlx::query(
            "INSERT INTO limit_usage_daily (day, limit_key, principal_kind, principal_id, hits, peak) \
             VALUES ($1, 'bulk.max_records_per_request', 'user', $2, 0, 425)",
        )
        .bind(day - Duration::days(2))
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();
        let notification = app.state.base.config.notification.clone();

        let first = limit_warning_check(&app.state, &notification, now)
            .await
            .unwrap();
        assert!(
            first.iter().any(|k| k == "bulk.max_records_per_request"),
            "{first:?}"
        );
        let again = limit_warning_check(&app.state, &notification, now + Duration::hours(2))
            .await
            .unwrap();
        assert!(
            !again.iter().any(|k| k == "bulk.max_records_per_request"),
            "once per day: {again:?}"
        );
        let told: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM notification_dispatch WHERE recipient_user_ref = $1 \
             AND subject = 'Limit bulk.max_records_per_request is close to its value'",
        )
        .bind(app.admin.id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(told, 1);
        // The next day it warns again while the peak is in the window.
        let next = limit_warning_check(&app.state, &notification, now + Duration::days(1))
            .await
            .unwrap();
        assert!(
            next.iter().any(|k| k == "bulk.max_records_per_request"),
            "{next:?}"
        );
    });
}
