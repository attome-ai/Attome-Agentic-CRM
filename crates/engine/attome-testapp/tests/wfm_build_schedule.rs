//! G17-T16: a schedule from build to publish (G17-T6, G17-T7, G17-T11). The
//! build job turns a day's forecast and a shift template into one draft
//! schedule, and a retry of the same run replaces its own draft; the planner
//! reads it, publishes it under its row version (each shift booked), and the
//! people scheduled see their shifts; a what-if with one person fewer
//! leaves at least as many intervals short. A backwards period is refused.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_user};
use attome_workforce::build_job::{BuildJob, run};
use axum::http::{Method, StatusCode};
use chrono::NaiveDate;
use serde_json::json;
use uuid::Uuid;

// feature: G17
// negative: POST /api/v1/workforce/groups/{id}/schedules/build, POST /api/v1/workforce/schedules/{id}/publish
#[test]
fn build_publish_and_what_if() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        app.install_packs(&["workforce"]).await;
        let people = [
            seed_user(app.db(), "wfm-build-a").await,
            seed_user(app.db(), "wfm-build-b").await,
            seed_user(app.db(), "wfm-build-c").await,
        ];
        let day = NaiveDate::from_ymd_opt(2027, 3, 7).unwrap();
        let midnight = day.and_hms_opt(0, 0, 0).unwrap().and_utc();

        let group: Uuid = sqlx::query_scalar(
            "INSERT INTO wfm_planning_group (id, name, channel, interval_minutes, aht_seconds, \
                 service_level_target_pct, service_level_seconds, is_active, row_version) \
             VALUES (uuidv7(), 'Voice', 'voice', '30', 180, 80, 20, true, 0) RETURNING id",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        for person in &people {
            sqlx::query(
                "INSERT INTO wfm_group_member (id, planning_group_ref, user_ref, is_active, \
                     row_version) VALUES (uuidv7(), $1, $2, true, 0)",
            )
            .bind(group)
            .bind(person.id)
            .execute(app.db())
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO wfm_shift_template (id, name, planning_group_ref, start_window_from, \
                 start_window_to, length_minutes, is_active, row_version) \
             VALUES (uuidv7(), 'Day', $1, '08:00', '09:00', 480, true, 0)",
        )
        .bind(group)
        .execute(app.db())
        .await
        .unwrap();
        // Ten contacts a half hour from 08:00 to 17:00.
        sqlx::query(
            "INSERT INTO wfm_forecast_interval (id, planning_group_ref, interval_start, volume, \
                 digital_share, is_active, row_version) \
             SELECT uuidv7(), $1, $2 + make_interval(mins => 30 * g), 10, 0, true, 0 \
               FROM generate_series(16, 33) AS g",
        )
        .bind(group)
        .bind(midnight)
        .execute(app.db())
        .await
        .unwrap();

        // The route refuses a backwards period before anything is queued.
        let build = format!("/api/v1/workforce/groups/{group}/schedules/build");
        let (status, body) = app
            .request(
                Method::POST,
                &build,
                Some(json!({ "from": "2027-03-08", "to": "2027-03-07" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        // The job itself, run here: the binary registers the job type at
        // start-up (`crates/apps/attome/src/jobs.rs`), which this app does
        // not run, so the route's enqueue is not exercised here.
        let job = BuildJob {
            run_id: Uuid::now_v7(),
            group_id: group,
            from: day,
            to: day,
            requested_by: app.admin.id,
            deadline_secs: Some(30),
        };
        let built = run(&app.state, &job).await.unwrap();
        assert!(built.assignments >= 1, "{built:?}");
        let again = run(&app.state, &job).await.unwrap();
        assert_eq!(again.schedule_id, built.schedule_id, "a retry keeps its draft");
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM wfm_shift_assignment WHERE schedule_ref = $1 \
               AND (is_active IS NULL OR is_active = true)",
        )
        .bind(built.schedule_id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(
            rows as usize, again.assignments,
            "a retry replaces its assignments"
        );

        let detail_path = format!("/api/v1/workforce/schedules/{}", built.schedule_id);
        let (status, detail) = app.request(Method::GET, &detail_path, None).await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        assert_eq!(detail["status"], "draft", "{detail}");
        let version = detail["row_version"].as_i64().unwrap();

        // Publishing needs the current row version.
        let publish = format!("{detail_path}/publish");
        let stale = format!("\"{}\"", version + 7);
        let (status, body) = app
            .request_with(Method::POST, &publish, &[("if-match", stale.as_str())], None)
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let current = format!("\"{version}\"");
        let (status, published) = app
            .request_with(Method::POST, &publish, &[("if-match", current.as_str())], None)
            .await;
        assert_eq!(status, StatusCode::OK, "{published}");
        assert_eq!(
            published["bookings"].as_u64().unwrap() as usize,
            rows as usize,
            "every shift is booked: {published}"
        );

        // Each person scheduled sees their own shifts, now published.
        let mut seen: i64 = 0;
        for person in &people {
            let (status, mine) = app
                .request_as(
                    &person.cookie,
                    Method::GET,
                    "/api/v1/workforce/me/schedule?from=2027-03-07&to=2027-03-07",
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{mine}");
            for shift in mine.as_array().unwrap() {
                assert_eq!(shift["user_id"], person.id.to_string());
                assert!(shift["booking_id"].is_string(), "{shift}");
                seen += 1;
            }
        }
        assert_eq!(seen, rows, "every published shift reaches its person");

        // One person fewer never helps.
        let what_if = format!("{detail_path}/what-if");
        let (status, base) = app.request(Method::POST, &what_if, Some(json!({}))).await;
        assert_eq!(status, StatusCode::OK, "{base}");
        assert_eq!(base["days"].as_array().unwrap().len(), 1, "{base}");
        let (status, fewer) = app
            .request(
                Method::POST,
                &what_if,
                Some(json!({ "headcount_delta": -1 })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{fewer}");
        assert!(
            fewer["under"].as_u64().unwrap() >= base["under"].as_u64().unwrap(),
            "{base} / {fewer}"
        );
    });
}
